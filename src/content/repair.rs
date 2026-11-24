//! Repairs of damaged content (always on a copy — the input slice is never modified):
//! - JPEG: cut before garbage / at the truncation point (on a restart marker when one is close)
//!   and append EOI.
//! - PNG: keep chunks up to the first bad CRC / truncation and append IEND; if that doesn't decode,
//!   re-encode the rows that inflate, padding the missing ones (non-interlaced only).
//! - ZIP family: rebuild the central directory + EOCD from local headers (data descriptors
//!   handled; truncated or CRC-failing entries dropped; no zip64).
//! - PDF: append a missing `%%EOF`, or rebuild a classic xref table from `n g obj` offsets.
//! - MP4/MOV: set an `mdat` size of 0 or past the end to the real length.
//! - WAV/AVI: set RIFF / data / movi sizes to the real length.
//! Every result must pass `validate` (not Partial) or None is returned.

use super::bmff;
use super::exif::jpeg_info;
use super::util::*;
use super::validate::{self, validate_with};
use super::zipscan::{scan_local, LocalEntry};
use crate::model::Condition;
use std::io::Write;

pub fn repair(type_id: &str, d: &[u8]) -> Option<Vec<u8>> {
    let k = kind(type_id);
    let out = match k {
        Kind::Jpeg => jpeg(d)?,
        Kind::Png => png(d)?,
        Kind::Ooxml | Kind::Odf | Kind::Epub | Kind::Zip => zip(d)?,
        Kind::Pdf => pdf(d)?,
        Kind::Mp4 => mp4(d)?,
        Kind::Wav | Kind::Avi => riff(d, k)?,
        _ => return None,
    };
    if out.as_slice() == d {
        return None;
    }
    let v = validate_with(type_id, &out.as_slice(), &out, None);
    if v.condition == Condition::Partial {
        return None;
    }
    Some(out)
}

// ------------------------------------------------------------------------------------- JPEG

fn jpeg(d: &[u8]) -> Option<Vec<u8>> {
    let j = jpeg_info(d)?;
    let scan = j.scan_start?;
    if j.eoi_end.is_some() && j.first_bad.is_none() {
        return None;
    }
    let mut cut = match j.first_bad {
        Some(bad) => match j.last_good_cut {
            Some(c) if c > scan && c <= bad && bad - c < 64 * 1024 => c,
            _ => bad,
        },
        None => {
            // Truncated: drop trailing zero fill (unallocated / trimmed space).
            let mut e = d.len();
            while e > scan && d[e - 1] == 0 {
                e -= 1;
            }
            e
        }
    };
    while cut > scan && d[cut - 1] == 0xFF {
        cut -= 1;
    }
    if cut <= scan {
        return None;
    }
    let mut out = d[..cut].to_vec();
    out.extend_from_slice(&[0xFF, 0xD9]);
    validate::decode(Kind::Jpeg, &out).ok()?;
    Some(out)
}

// -------------------------------------------------------------------------------------- PNG

fn chunk(t: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut c = (body.len() as u32).to_be_bytes().to_vec();
    c.extend_from_slice(t);
    c.extend_from_slice(body);
    let mut h = crc32fast::Hasher::new();
    h.update(t);
    h.update(body);
    c.extend_from_slice(&h.finalize().to_be_bytes());
    c
}

fn png(d: &[u8]) -> Option<Vec<u8>> {
    if !d.starts_with(b"\x89PNG\r\n\x1a\n") {
        return None;
    }
    // (type, start, body range)
    let mut good: Vec<([u8; 4], usize, usize, usize)> = Vec::new();
    let mut partial_idat: Option<(usize, usize)> = None;
    let mut p = 8;
    let mut ended = false;
    while p + 12 <= d.len() && good.len() < 100_000 {
        let len = be32(d, p)? as usize;
        let mut t = [0u8; 4];
        t.copy_from_slice(&d[p + 4..p + 8]);
        if !t.iter().all(|c| c.is_ascii_alphabetic()) {
            break;
        }
        let bs = p + 8;
        let be = bs.saturating_add(len);
        if be + 4 > d.len() {
            if &t == b"IDAT" {
                partial_idat = Some((bs, d.len().min(be)));
            }
            break;
        }
        if be32(d, be) != Some(crc32fast::hash(&d[p + 4..be])) {
            if &t == b"IDAT" {
                partial_idat = Some((bs, be));
            }
            break;
        }
        if &t == b"IEND" {
            ended = true;
            break;
        }
        good.push((t, p, bs, be));
        p = be + 4;
    }
    if ended {
        return None;
    }
    let ihdr = good.first().filter(|c| &c.0 == b"IHDR")?;
    let ih = &d[ihdr.2..ihdr.3];
    // Phase 1: keep the good chunks, close the file.
    let mut out = d[..8].to_vec();
    for c in &good {
        out.extend_from_slice(&d[c.1..c.3 + 4]);
    }
    out.extend_from_slice(&chunk(b"IEND", &[]));
    if good.iter().any(|c| &c.0 == b"IDAT") && validate::decode(Kind::Png, &out).is_ok() {
        return Some(out);
    }
    // Phase 2: inflate what's there and pad the missing rows.
    let (w, h, depth, color, interlace) = (be32(ih, 0)? as u64, be32(ih, 4)? as u64, *ih.get(8)? as u64, *ih.get(9)?, *ih.get(12)?);
    if interlace != 0 {
        return None;
    }
    let channels = match color {
        0 | 3 => 1,
        2 => 3,
        4 => 2,
        6 => 4,
        _ => return None,
    };
    let row = (w * channels * depth).div_ceil(8) + 1;
    let expected = row.checked_mul(h)?;
    if expected == 0 || expected > 512 << 20 {
        return None;
    }
    let mut z = Vec::new();
    for c in good.iter().filter(|c| &c.0 == b"IDAT") {
        z.extend_from_slice(&d[c.2..c.3]);
    }
    if let Some((s, e)) = partial_idat {
        z.extend_from_slice(&d[s..e]);
    }
    if z.len() < 2 {
        return None;
    }
    // zlib header (2 bytes), then raw deflate.
    let mut raw = Vec::new();
    super::zipscan::inflate(&z[2..], expected, Some((&mut raw, expected as usize)));
    if raw.len() < row as usize {
        return None;
    }
    raw.resize(expected as usize, 0);
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&raw).ok()?;
    let idat = enc.finish().ok()?;
    let mut out = d[..8].to_vec();
    for c in good.iter().take_while(|c| &c.0 != b"IDAT") {
        out.extend_from_slice(&d[c.1..c.3 + 4]);
    }
    for part in idat.chunks(1 << 20) {
        out.extend_from_slice(&chunk(b"IDAT", part));
    }
    out.extend_from_slice(&chunk(b"IEND", &[]));
    validate::decode(Kind::Png, &out).ok()?;
    Some(out)
}

// -------------------------------------------------------------------------------------- ZIP

fn zip(d: &[u8]) -> Option<Vec<u8>> {
    if validate::validate_zip(&mut std::io::Cursor::new(d), validate::ZIP_BUDGET).condition == Condition::Good {
        return None;
    }
    let entries: Vec<LocalEntry> = scan_local(d, true, validate::ZIP_BUDGET, 65_000)
        .into_iter()
        .filter(|e| e.ok && !e.truncated && !e.name.is_empty() && e.csize < 0xFFFF_FFFF && e.usize < 0xFFFF_FFFF)
        .collect();
    if entries.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    let mut placed = Vec::new();
    for e in &entries {
        let rel = out.len();
        if rel > 0xFFFF_FFF0 {
            break;
        }
        out.extend_from_slice(&d[e.header_at..e.data_end + e.desc_len]);
        placed.push((e, rel));
    }
    let cd_at = out.len();
    for (e, rel) in &placed {
        let h = e.header_at;
        let nlen = le16(d, h + 26)? as usize;
        let name = &d[h + 30..h + 30 + nlen];
        let mut c = b"PK\x01\x02".to_vec();
        c.extend_from_slice(&20u16.to_le_bytes()); // made by
        c.extend_from_slice(&d[h + 4..h + 6]); // needed
        c.extend_from_slice(&d[h + 6..h + 8]); // flags
        c.extend_from_slice(&d[h + 8..h + 10]); // method
        c.extend_from_slice(&d[h + 10..h + 14]); // time, date
        c.extend_from_slice(&e.crc.to_le_bytes());
        c.extend_from_slice(&(e.csize as u32).to_le_bytes());
        c.extend_from_slice(&(e.usize as u32).to_le_bytes());
        c.extend_from_slice(&(nlen as u16).to_le_bytes());
        c.extend_from_slice(&[0; 2]); // extra
        c.extend_from_slice(&[0; 2]); // comment
        c.extend_from_slice(&[0; 2]); // disk
        c.extend_from_slice(&[0; 2]); // internal attrs
        let ext: u32 = if e.name.ends_with('/') { 0x10 } else { 0 };
        c.extend_from_slice(&ext.to_le_bytes());
        c.extend_from_slice(&(*rel as u32).to_le_bytes());
        c.extend_from_slice(name);
        out.extend_from_slice(&c);
    }
    let cd_len = out.len() - cd_at;
    let n = placed.len() as u16;
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&(cd_len as u32).to_le_bytes());
    out.extend_from_slice(&(cd_at as u32).to_le_bytes());
    out.extend_from_slice(&[0; 2]);
    if validate::validate_zip(&mut std::io::Cursor::new(&out[..]), validate::ZIP_BUDGET).condition != Condition::Good {
        return None;
    }
    Some(out)
}

// -------------------------------------------------------------------------------------- PDF

/// Offsets of `n g obj` definitions (last one wins), by object number.
pub fn pdf_objects(d: &[u8]) -> std::collections::BTreeMap<u32, (u32, usize)> {
    let mut objs = std::collections::BTreeMap::new();
    let mut p = 0;
    while let Some(i) = find_from(d, b"obj", p) {
        p = i + 3;
        if objs.len() > 1_000_000 {
            break;
        }
        // Must be followed by a delimiter and preceded by "<num> <gen> ".
        if d.get(i + 3).is_some_and(|c| c.is_ascii_alphanumeric()) {
            continue;
        }
        let mut j = i;
        let ws = |c: u8| matches!(c, b' ' | b'\r' | b'\n' | b'\t' | 0 | 12);
        let s1 = j;
        while j > 0 && ws(d[j - 1]) {
            j -= 1;
        }
        if j == s1 {
            continue;
        }
        let ge = j;
        while j > 0 && d[j - 1].is_ascii_digit() && ge - j < 5 {
            j -= 1;
        }
        if j == ge {
            continue;
        }
        let gs = j;
        let s2 = j;
        while j > 0 && ws(d[j - 1]) {
            j -= 1;
        }
        if j == s2 {
            continue;
        }
        let ne = j;
        while j > 0 && d[j - 1].is_ascii_digit() && ne - j < 10 {
            j -= 1;
        }
        if j == ne || (j > 0 && !ws(d[j - 1]) && d[j - 1] != b'>' && d[j - 1] != b']' && d[j - 1] != b')') {
            continue;
        }
        let num: Option<u32> = std::str::from_utf8(&d[j..ne]).ok().and_then(|s| s.parse().ok());
        let gen: Option<u32> = std::str::from_utf8(&d[gs..ge]).ok().and_then(|s| s.parse().ok());
        if let (Some(n), Some(g)) = (num, gen) {
            if n > 0 && n < 10_000_000 && g < 65535 {
                objs.insert(n, (g, j));
            }
        }
    }
    objs
}

fn pdf(d: &[u8]) -> Option<Vec<u8>> {
    find(&d[..d.len().min(1024)], b"%PDF-")?;
    let v = validate::validate_pdf(&d);
    if v.condition == Condition::Good {
        return None;
    }
    // Only %%EOF missing?
    let mut tail_fixed = d.to_vec();
    tail_fixed.extend_from_slice(b"\n%%EOF\n");
    if validate::validate_pdf(&tail_fixed.as_slice()).condition == Condition::Good {
        return Some(tail_fixed);
    }
    let objs = pdf_objects(d);
    if objs.is_empty() {
        return None;
    }
    let ref_after = |key: &[u8]| -> Option<(u32, u32)> {
        let i = rfind(d, key)?;
        let s = String::from_utf8_lossy(&d[i + key.len()..d.len().min(i + key.len() + 32)]).into_owned();
        let mut it = s.split_whitespace();
        let n: u32 = it.next()?.parse().ok()?;
        let g: u32 = it.next()?.parse().ok()?;
        (it.next()?.starts_with('R')).then_some((n, g))
    };
    let root = ref_after(b"/Root").filter(|(n, _)| objs.contains_key(n)).or_else(|| {
        let i = find(d, b"/Type /Catalog").or_else(|| find(d, b"/Type/Catalog"))?;
        objs.iter().filter(|(_, (_, o))| *o < i).max_by_key(|(_, (_, o))| *o).map(|(n, (g, _))| (*n, *g))
    })?;
    let info = ref_after(b"/Info").filter(|(n, _)| objs.contains_key(n));
    let size = objs.keys().next_back().copied()? + 1;
    let mut out = d.to_vec();
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    let xref_at = out.len();
    out.extend_from_slice(format!("xref\n0 {size}\n").as_bytes());
    for n in 0..size {
        match objs.get(&n) {
            Some((g, o)) => out.extend_from_slice(format!("{o:010} {g:05} n\r\n").as_bytes()),
            None => out.extend_from_slice(b"0000000000 65535 f\r\n"),
        }
    }
    let info_s = info.map(|(n, g)| format!(" /Info {n} {g} R")).unwrap_or_default();
    out.extend_from_slice(format!("trailer\n<< /Size {size} /Root {} {} R{info_s} >>\nstartxref\n{xref_at}\n%%EOF\n", root.0, root.1).as_bytes());
    Some(out)
}

// -------------------------------------------------------------------------------------- MP4

fn mp4(d: &[u8]) -> Option<Vec<u8>> {
    let len = d.len() as u64;
    let (boxes, _) = bmff::top_level(&d);
    let last = boxes.last()?;
    if &last.typ != b"mdat" || !(last.declared_zero || last.end() > len) {
        return None;
    }
    let real = len - last.start;
    let mut out = d.to_vec();
    let s = last.start as usize;
    if last.large {
        out[s + 8..s + 16].copy_from_slice(&real.to_be_bytes());
    } else if real <= u32::MAX as u64 {
        out[s..s + 4].copy_from_slice(&(real as u32).to_be_bytes());
    } else {
        return None;
    }
    Some(out)
}

// ------------------------------------------------------------------------------------- RIFF

fn riff(d: &[u8], k: Kind) -> Option<Vec<u8>> {
    if d.len() < 12 || &d[..4] != b"RIFF" {
        return None;
    }
    let len = d.len();
    let mut out = d.to_vec();
    let declared = le32(d, 4)? as usize;
    if declared + 8 > len {
        out[4..8].copy_from_slice(&((len - 8) as u32).to_le_bytes());
    }
    let mut p = 12;
    let mut n = 0;
    while p + 8 <= len && n < 100_000 {
        n += 1;
        let id = &d[p..p + 4];
        let clen = le32(d, p + 4)? as usize;
        let is_data = (k == Kind::Wav && id == b"data") || (k == Kind::Avi && id == b"LIST" && d.get(p + 8..p + 12) == Some(b"movi"));
        if p + 8 + clen > len {
            if !is_data {
                return None;
            }
            let mut real = len - p - 8;
            if k == Kind::Wav {
                // Whole sample frames only.
                let align = find(&d[..p], b"fmt ").and_then(|f| le16(d, f + 20)).filter(|&a| a > 0).unwrap_or(1) as usize;
                real -= real % align;
            }
            out[p + 4..p + 8].copy_from_slice(&(real as u32).to_le_bytes());
            break;
        }
        p += 8 + clen + (clen & 1);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::super::validate::tests::{jpeg_bytes, png_bytes, val, wav};
    use super::*;

    #[test]
    fn jpeg_truncated_and_garbage() {
        let j = jpeg_bytes(200, 150);
        assert!(repair("jpg", &j).is_none());
        let cut = &j[..j.len() * 3 / 5];
        let r = repair("jpg", cut).expect("repaired");
        assert!(r.ends_with(&[0xFF, 0xD9]));
        assert_eq!(val("jpg", &r).condition, Condition::Good);
        // Overwrite the second half with noise.
        let mut g = j.clone();
        let half = g.len() / 2;
        let mut x = 12345u32;
        for b in g[half..].iter_mut() {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            *b = (x >> 16) as u8;
        }
        let r = repair("jpg", &g).expect("repaired");
        assert_eq!(val("jpg", &r).condition, Condition::Good);
        assert!(r.len() <= g.len());
    }

    #[test]
    fn png_truncated() {
        let p = png_bytes(300, 200);
        assert!(repair("png", &p).is_none());
        let cut = &p[..p.len() / 2];
        let r = repair("png", cut).expect("repaired");
        let img = super::super::validate::decode(Kind::Png, &r).unwrap();
        assert_eq!((img.width(), img.height()), (300, 200));
    }

    #[test]
    fn zip_without_directory_or_truncated() {
        let z = super::super::zipscan::tests::make_zip(&[("a.txt", b"alpha alpha"), ("dir/", b""), ("b.txt", &[3u8; 9000]), ("c.txt", b"gamma")], true);
        assert!(repair("zip", &z).is_none());
        let cd = find(&z, b"PK\x01\x02").unwrap();
        let r = repair("zip", &z[..cd]).expect("repaired");
        let a = zip::ZipArchive::new(std::io::Cursor::new(&r)).unwrap();
        assert_eq!(a.len(), 4);
        // Cut inside c.txt's data: the first three survive.
        let es = scan_local(&z, false, 0, 10);
        let r2 = repair("docx", &z[..es[3].data_at + 2]).expect("repaired");
        assert_eq!(zip::ZipArchive::new(std::io::Cursor::new(&r2)).unwrap().len(), 3);
    }

    #[test]
    fn pdf_rebuilds_xref() {
        let d = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n4 0 obj\n(x)\nendobj\n";
        let r = repair("pdf", d).expect("repaired");
        assert_eq!(val("pdf", &r).condition, Condition::Good);
        let s = String::from_utf8_lossy(&r);
        assert!(s.contains("/Root 1 0 R"));
        assert!(s.contains("0000000009 00000 n\r\n"));
        assert!(s.contains("0000000000 65535 f\r\n0000000000 65535 f\r\n") || s.contains("xref\n0 5\n"));
        // Only %%EOF missing.
        let ok = format!("%PDF-1.4\n1 0 obj << >> endobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer << /Root 1 0 R /Size 2 >>\nstartxref\n31\n");
        let r = repair("pdf", ok.as_bytes()).expect("repaired");
        assert!(r.ends_with(b"%%EOF\n"));
    }

    #[test]
    fn mp4_and_wav_sizes() {
        let v = super::super::bmff::tests::sample_mp4(5000);
        assert!(repair("mp4", &v).is_none());
        let cut = &v[..v.len() - 1000];
        let r = repair("mp4", cut).expect("repaired");
        assert_eq!(val("mp4", &r).condition, Condition::Good);
        assert_eq!(r.len(), cut.len());

        let w = wav(8000, 4000);
        let cut = &w[..w.len() - 101];
        let r = repair("wav", cut).expect("repaired");
        assert_eq!(val("wav", &r).condition, Condition::Good);
        assert_eq!(le32(&r, 4), Some((r.len() - 8) as u32));
    }
}
