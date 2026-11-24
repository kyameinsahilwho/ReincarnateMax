//! PDF, RTF, EML, PST, OLE compound files (DOC/XLS/PPT/MSG), SQLite, PE (EXE/DLL).

use super::parse::{clip, clean, dmg, est, or_dmg, sized, typed, Env, Parsed};
use super::rd::Rd;
use crate::formats::sniff;

const MB: u64 = 1 << 20;

/// From `%PDF` to the last `%%EOF`, following incremental updates: after an `%%EOF` the scan goes
/// on only while PDF syntax shows up within the next MiB, and never past the next file header.
/// The search never runs past another PDF's header on a sector: a PDF whose own `%%EOF` is gone
/// must not end at the next PDF's.
pub(crate) fn pdf(rd: &mut Rd, env: &Env) -> Option<Parsed> {
    const CAP: u64 = 512 * MB;
    const SYNTAX: [&[u8]; 4] = [b"endobj", b" 0 obj", b"xref", b"trailer"];
    let limit = CAP.min(rd.avail());
    let mut pos = 5u64;
    let mut last_eof: Option<u64> = None;
    let mut other: Option<u64> = None;
    loop {
        let mut to = limit;
        if let Some(le) = last_eof {
            let win = (le + MB).min(limit);
            let mut syntax = false;
            for t in SYNTAX {
                if let Ok(Some(_)) = rd.find(le, win, t) {
                    syntax = true;
                    break;
                }
            }
            if !syntax {
                break;
            }
            if let Some(h) = env.next_hit(rd.start + le - 1) {
                to = to.min(h - rd.start);
            }
        }
        let found = loop {
            match rd.find_any(pos, to, &[b"%%EOF", b"%PDF-"]) {
                Ok(Some((q, 1))) if (rd.start + q) % 512 == 0 => {
                    other = Some(q);
                    break Ok(None);
                }
                // A "%PDF-" inside the file (not a file start): keep looking.
                Ok(Some((q, 1))) => pos = q + 5,
                Ok(r) => break Ok(r.map(|(q, _)| q)),
                Err(e) => break Err(e),
            }
        };
        match found {
            Ok(Some(q)) => {
                let mut e = q + 5;
                if rd.u8(e).ok() == Some(b'\r') {
                    e += 1;
                }
                if rd.u8(e).ok() == Some(b'\n') {
                    e += 1;
                }
                last_eof = Some(e);
                pos = e;
            }
            Ok(None) => break,
            Err(_) => return dmg(last_eof.unwrap_or(pos).max(pos)),
        }
    }
    match last_eof {
        Some(e) => clean(e),
        None => {
            let to_next = env.next_hit(rd.start).map(|h| h - rd.start).unwrap_or(limit);
            dmg(to_next.min(limit).min(other.unwrap_or(u64::MAX)))
        }
    }
}

/// Brace balance to the final `}`.
pub(crate) fn rtf(rd: &mut Rd) -> Option<Parsed> {
    const CAP: u64 = 512 * MB;
    let mut depth = 0i64;
    let mut esc = false;
    let mut pos = 0u64;
    while pos < CAP {
        let c = or_dmg!(rd.chunk(pos), pos);
        for (i, &b) in c.iter().enumerate() {
            if esc {
                esc = false;
                continue;
            }
            match b {
                b'\\' => esc = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return clean(pos + i as u64 + 1);
                    }
                }
                0 => return dmg(pos + i as u64),
                _ => {}
            }
        }
        pos += c.len() as u64;
    }
    dmg(pos)
}

/// Text up to the first NUL byte (estimated).
pub(crate) fn eml(rd: &mut Rd) -> Option<Parsed> {
    const CAP: u64 = 64 * MB;
    let mut pos = 0u64;
    while pos < CAP {
        let Ok(c) = rd.chunk(pos) else { break };
        if let Some(i) = c.iter().position(|&b| b == 0 || (b < 0x09)) {
            return est(pos + i as u64);
        }
        pos += c.len() as u64;
    }
    est(pos.min(CAP))
}

pub(crate) fn pst(rd: &mut Rd) -> Option<Parsed> {
    let ver = rd.u16le(10).ok()?;
    let len = match ver {
        14 | 15 => rd.u32le(0xA8).ok()? as u64,
        v if v >= 23 => rd.u64le(0xB8).ok()?,
        _ => return None,
    };
    sized(rd, len, 512, 100 << 30)
}

/// OLE compound file: highest sector the FAT marks as used.
pub(crate) fn ole(rd: &mut Rd) -> Option<Parsed> {
    const FREE: u32 = 0xFFFF_FFFF;
    let h = rd.bytes(0, 512).ok()?.to_vec();
    let major = sniff::le16(&h, 0x1A)?;
    let shift = sniff::le16(&h, 0x1E)?;
    if !((major == 3 && shift == 9) || (major == 4 && shift == 12)) {
        return None;
    }
    let ss = 1u64 << shift;
    let per = (ss / 4) as usize;
    let nfat = sniff::le32(&h, 0x2C)? as usize;
    let dir_first = sniff::le32(&h, 0x30)?;
    let mut difat_next = sniff::le32(&h, 0x44)?;
    let ndifat = sniff::le32(&h, 0x48)?;
    // The FAT sectors are part of the file, which is at most 64 GiB.
    if nfat == 0 || nfat > 1 << 20 || nfat as u64 * ss > 64 << 30 {
        return None;
    }
    let mut fat_sects: Vec<u32> = (0..109).filter_map(|i| sniff::le32(&h, 0x4C + 4 * i)).filter(|&s| s < 0xFFFF_FFFA).collect();
    // The DIFAT chain: only as many sectors as nfat needs (a looping chain can't grow it).
    let difat_needed = nfat.saturating_sub(109).div_ceil(per - 1) as u32;
    for _ in 0..ndifat.min(difat_needed) {
        if difat_next >= 0xFFFF_FFFA || fat_sects.len() >= nfat {
            break;
        }
        let off = (difat_next as u64 + 1) * ss;
        let s = or_dmg!(rd.bytes(off, ss as usize), off).to_vec();
        for i in 0..per - 1 {
            let v = sniff::le32(&s, 4 * i)?;
            if v < 0xFFFF_FFFA {
                fat_sects.push(v);
            }
        }
        difat_next = sniff::le32(&s, ss as usize - 4)?;
    }
    fat_sects.truncate(nfat);
    // A FAT sector listed twice: not a real compound file.
    let mut seen = std::collections::HashSet::with_capacity(fat_sects.len());
    if !fat_sects.iter().all(|&s| seen.insert(s)) {
        return None;
    }
    drop(seen);
    // Highest used sector, one FAT sector at a time (the FAT itself is never held in memory).
    let mut max_used = 0u64;
    let mut damaged = false;
    for (k, &fs) in fat_sects.iter().enumerate() {
        max_used = max_used.max(fs as u64);
        let off = (fs as u64 + 1) * ss;
        match rd.bytes(off, ss as usize) {
            Ok(s) => {
                if let Some(j) = (0..per).rev().find(|&i| s[4 * i..4 * i + 4] != FREE.to_le_bytes()) {
                    max_used = max_used.max((k * per + j) as u64);
                }
            }
            Err(_) => damaged = true,
        }
    }
    let size = (max_used + 2) * ss;
    if size > 64 << 30 {
        return None;
    }
    // Directory names (first few sectors of the directory chain) decide the type.
    let mut names = Vec::new();
    let mut s = dir_first;
    for _ in 0..8 {
        if s >= 0xFFFF_FFFA {
            break;
        }
        if let Ok(d) = rd.bytes((s as u64 + 1) * ss, ss as usize) {
            names.extend(sniff::ole_dir_names(d));
        }
        // The FAT entry for sector s.
        s = match fat_sects.get(s as usize / per) {
            Some(&fs) => rd.u32le((fs as u64 + 1) * ss + 4 * (s as u64 % per as u64)).unwrap_or(FREE),
            None => FREE,
        };
    }
    let ty = sniff::ole_kind_from_names(&names);
    let avail = rd.avail();
    if size > avail {
        return typed(clip(avail), ty);
    }
    typed(if damaged { dmg(size) } else { clean(size) }, ty)
}

pub(crate) fn sqlite(rd: &mut Rd, env: &Env) -> Option<Parsed> {
    let h = rd.bytes(0, 100).ok()?.to_vec();
    if !sniff::sqlite_ok(&h) {
        return None;
    }
    let ps = sniff::be16(&h, 16)? as u64;
    let ps = if ps == 1 { 65536 } else { ps };
    let count = sniff::be32(&h, 28)? as u64;
    let valid = sniff::be32(&h, 24)? == sniff::be32(&h, 92)?;
    if count > 0 && valid {
        return sized(rd, ps * count, ps, 256 << 30);
    }
    let to_next = env.next_hit(rd.start).map(|n| n - rd.start).unwrap_or(rd.avail());
    est(to_next.min(1 << 30).min(rd.avail()) / ps * ps)
}

pub(crate) fn pe(rd: &mut Rd) -> Option<Parsed> {
    let h = rd.bytes(0, 0x40).ok()?.to_vec();
    let e = sniff::le32(&h, 0x3C)? as u64;
    let coff = rd.bytes(e, 24).ok()?.to_vec();
    if &coff[..4] != b"PE\0\0" {
        return None;
    }
    let nsec = sniff::le16(&coff, 6)? as u64;
    let optsz = sniff::le16(&coff, 20)? as u64;
    let chars = sniff::le16(&coff, 22)?;
    let opt = e + 24;
    let magic = rd.u16le(opt).ok()?;
    if !(1..=96).contains(&nsec) || !(magic == 0x10B || magic == 0x20B) {
        return None;
    }
    let mut end = rd.u32le(opt + 60).ok()? as u64;
    let secs = rd.bytes(opt + optsz, (40 * nsec) as usize).ok()?.to_vec();
    for s in secs.chunks_exact(40) {
        let raw_size = sniff::le32(s, 16)? as u64;
        let raw_ptr = sniff::le32(s, 20)? as u64;
        if raw_ptr > 0 && raw_size > 0 {
            end = end.max(raw_ptr + raw_size);
        }
    }
    let (nrva_at, dirs) = if magic == 0x10B { (opt + 92, opt + 96) } else { (opt + 108, opt + 112) };
    if rd.u32le(nrva_at).unwrap_or(0) > 4 {
        let off = rd.u32le(dirs + 32).unwrap_or(0) as u64;
        let size = rd.u32le(dirs + 36).unwrap_or(0) as u64;
        if off > 0 && size > 0 && size < 64 * MB {
            end = end.max(off + size);
        }
    }
    let ty = if chars & 0x2000 != 0 { "dll" } else { "exe" };
    typed(sized(rd, end, 512, 4 << 30), ty)
}
