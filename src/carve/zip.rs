//! ZIP family (ZIP, OOXML, ODF, EPUB, JAR, APK): local headers -> central directory -> end of
//! central directory (+ comment), ZIP64 aware. When a local header is missing where the previous
//! entry ends, the next structure is searched 1..=64 clusters later and the split point inside
//! the previous entry is found by its CRC; the central directory's offsets must agree.

use super::parse::{clip, clean, dmg, End, Env, Parsed};
use super::rd::Rd;
use crate::formats::sniff;

const LOCAL: u32 = 0x0403_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const EOCD: u32 = 0x0605_4b50;
const Z64_EOCD: u32 = 0x0606_4b50;
const Z64_LOC: u32 = 0x0706_4b50;
const DD: u32 = 0x0807_4b50;
const CAP: u64 = 64 << 30;

#[derive(Clone, Copy)]
struct Entry {
    data: u64,
    csize: u64,
    method: u16,
    crc: u32,
    dd: bool,
}

struct Facts {
    names: Vec<String>,
    mimetype: Option<String>,
    content_types: Option<String>,
}

pub(crate) fn parse(rd: &mut Rd, env: &Env) -> Option<Parsed> {
    let cs = env.cluster.max(512);
    let mut f = Facts { names: Vec::new(), mimetype: None, content_types: None };
    let mut pos = 0u64;
    let mut gap: Option<(u64, u64)> = None;
    let mut last: Option<Entry> = None;
    let mut nlocal = 0u32;
    let mut cd_start: Option<u64> = None;
    let mut ncentral = 0u32;
    let finish = |p: Option<Parsed>, f: &Facts| {
        p.map(|mut p| {
            p.ty = Some(sniff::zip_kind(&f.names, f.mimetype.as_deref(), f.content_types.as_deref()));
            p
        })
    };
    loop {
        if pos > CAP {
            return finish(dmg(pos), &f);
        }
        let sig = match rd.u32le(pos) {
            Ok(s) => s,
            Err(_) => return if nlocal == 0 { None } else { finish(clip(pos.min(rd.avail())), &f) },
        };
        let step = match sig {
            LOCAL if cd_start.is_none() => local(rd, pos, &mut f),
            CENTRAL => central(rd, pos),
            Z64_EOCD => rd.u64le(pos + 4).ok().filter(|&s| s >= 44 && s < 1 << 20).map(|s| (12 + s, None)),
            Z64_LOC => Some((20, None)),
            DD if pos == 0 => Some((4, None)),
            EOCD if nlocal > 0 || ncentral > 0 => {
                let Ok(clen) = rd.u16le(pos + 20) else { return finish(dmg(pos), &f) };
                let end = pos + 22 + clen as u64;
                if end > rd.avail() {
                    return finish(clip(rd.avail()), &f);
                }
                let cd_off = rd.u32le(pos + 16).unwrap_or(0) as u64;
                let shift = gap.map_or(0, |g| g.1);
                if let (Some((split, g)), Some(c)) = (gap, cd_start) {
                    // The central directory must say the same thing as the rebuilt layout.
                    if cd_off != 0xFFFF_FFFF && cd_off + g != c {
                        return finish(dmg(split), &f);
                    }
                    let p = Parsed { ty: None, len: end - g, end: End::Clean, frags: vec![(0, split), (split + g, end - split - g)], soft: false };
                    return finish(Some(p), &f);
                }
                let _ = shift;
                return finish(clean(end), &f);
            }
            _ => None,
        };
        match step {
            Some((adv, entry)) => {
                if sig == LOCAL {
                    nlocal += 1;
                    last = entry;
                }
                if sig == CENTRAL {
                    ncentral += 1;
                    cd_start.get_or_insert(pos);
                }
                pos += adv;
            }
            None => {
                if nlocal == 0 && ncentral == 0 {
                    return None;
                }
                if gap.is_none() && cd_start.is_none() {
                    if let Some(le) = last {
                        if let Some(g) = find_gap(rd, pos, le, cs) {
                            gap = Some(g);
                            pos += g.1;
                            continue;
                        }
                    }
                }
                // Damaged: still try to find a consistent end of central directory ahead.
                if gap.is_none() {
                    if let Some(end) = eocd_ahead(rd, pos) {
                        return finish(dmg(end), &f);
                    }
                }
                return finish(dmg(gap.map_or(pos, |g| g.0.max(pos.saturating_sub(g.1)))), &f);
            }
        }
    }
}

/// A local file header at `pos`: (bytes to the next structure, entry).
fn local(rd: &mut Rd, pos: u64, f: &mut Facts) -> Option<(u64, Option<Entry>)> {
    let h = rd.bytes(pos, 30).ok()?.to_vec();
    let ver = sniff::le16(&h, 4)?;
    let flags = sniff::le16(&h, 6)?;
    let method = sniff::le16(&h, 8)?;
    let crc = sniff::le32(&h, 14)?;
    let mut csize = sniff::le32(&h, 18)? as u64;
    let usize_ = sniff::le32(&h, 22)? as u64;
    let nlen = sniff::le16(&h, 26)? as u64;
    let xlen = sniff::le16(&h, 28)? as u64;
    if ver >= 100 || nlen == 0 || nlen > 1024 || method > 100 {
        return None;
    }
    let name = String::from_utf8_lossy(rd.bytes(pos + 30, nlen as usize).ok()?).into_owned();
    if xlen > 0 && (csize == 0xFFFF_FFFF || usize_ == 0xFFFF_FFFF) {
        let x = rd.bytes(pos + 30 + nlen, xlen as usize).ok()?.to_vec();
        let mut i = 0;
        while i + 4 <= x.len() {
            let id = sniff::le16(&x, i)?;
            let sz = sniff::le16(&x, i + 2)? as usize;
            if id == 1 {
                let mut o = i + 4;
                if usize_ == 0xFFFF_FFFF {
                    o += 8;
                }
                if csize == 0xFFFF_FFFF {
                    csize = sniff::le64(&x, o)?;
                }
                break;
            }
            i += 4 + sz;
        }
    }
    let data = pos + 30 + nlen + xlen;
    let dd = flags & 8 != 0;
    let mut next_rel = data.saturating_add(csize);
    if dd && csize == 0 {
        let comp = if method == 8 { inflate_len(rd, data)? } else { stored_dd_len(rd, data)? };
        let mut d = data + comp;
        if rd.u32le(d).ok()? == DD {
            d += 4;
        }
        next_rel = if rd.u32le(d + 4).ok()? as u64 == comp { d + 12 } else if rd.u64le(d + 4).ok()? == comp { d + 20 } else { d + 12 };
        csize = comp;
    }
    if f.names.len() < 256 {
        if name == "mimetype" && method == 0 && csize < 128 {
            f.mimetype = rd.bytes(data, csize as usize).ok().map(|b| String::from_utf8_lossy(b).into_owned());
        }
        if name == "[Content_Types].xml" && f.content_types.is_none() {
            let n = csize.min(64 << 10) as usize;
            let mut buf = vec![0u8; n];
            let (got, _) = rd.read(data, &mut buf);
            buf.truncate(got);
            let text = if method == 8 { sniff::inflate_prefix(&buf, 256 << 10) } else { buf };
            f.content_types = Some(String::from_utf8_lossy(&text).into_owned());
        }
        f.names.push(name);
    }
    Some((next_rel - pos, Some(Entry { data, csize, method, crc, dd })))
}

fn central(rd: &mut Rd, pos: u64) -> Option<(u64, Option<Entry>)> {
    let h = rd.bytes(pos, 46).ok()?;
    let (n, x, c) = (sniff::le16(h, 28)? as u64, sniff::le16(h, 30)? as u64, sniff::le16(h, 32)? as u64);
    if n > 4096 {
        return None;
    }
    Some((46 + n + x + c, None))
}

/// Length of the raw deflate stream starting at `data`.
fn inflate_len(rd: &mut Rd, data: u64) -> Option<u64> {
    let mut d = flate2::Decompress::new(false);
    let mut out = vec![0u8; 256 << 10];
    let mut pos = data;
    loop {
        if pos - data > 4 << 30 {
            return None;
        }
        let c = rd.chunk(pos).ok()?;
        let (before, before_out) = (d.total_in(), d.total_out());
        let st = d.decompress(c, &mut out, flate2::FlushDecompress::None).ok()?;
        let used = d.total_in() - before;
        pos += used;
        if st == flate2::Status::StreamEnd {
            return Some(d.total_in());
        }
        if used == 0 && d.total_out() == before_out {
            return None;
        }
    }
}

/// Stored entry with a data descriptor: the descriptor signature whose size field matches.
fn stored_dd_len(rd: &mut Rd, data: u64) -> Option<u64> {
    let mut from = data;
    while let Ok(Some(q)) = rd.find(from, data + (256 << 20), &DD.to_le_bytes()) {
        if rd.u32le(q + 8).ok()? as u64 == q - data {
            return Some(q - data);
        }
        from = q + 1;
    }
    None
}

/// A consistent end-of-central-directory record within 64 MiB after `from`.
fn eocd_ahead(rd: &mut Rd, from: u64) -> Option<u64> {
    let mut p = from;
    let to = from + (64 << 20);
    while let Ok(Some(q)) = rd.find(p, to, &EOCD.to_le_bytes()) {
        let size = rd.u32le(q + 12).ok()? as u64;
        let off = rd.u32le(q + 16).ok()? as u64;
        if off + size == q {
            let clen = rd.u16le(q + 20).ok()? as u64;
            return Some(q + 22 + clen);
        }
        p = q + 1;
    }
    None
}

fn plausible(rd: &mut Rd, q: u64) -> bool {
    match rd.u32le(q) {
        Ok(LOCAL) => rd.bytes(q, 30).ok().is_some_and(|h| sniff::le16(h, 4).unwrap_or(999) < 100 && (1..=1024).contains(&sniff::le16(h, 26).unwrap_or(0))),
        Ok(CENTRAL) => rd.bytes(q, 46).ok().is_some_and(|h| sniff::le16(h, 28).unwrap_or(0) <= 4096),
        _ => false,
    }
}

/// The next structure should be at `pos` but isn't: find (split, gap).
fn find_gap(rd: &mut Rd, pos: u64, e: Entry, cs: u64) -> Option<(u64, u64)> {
    if e.dd || e.csize > 64 << 20 || !(e.method == 0 || e.method == 8) {
        return None;
    }
    let mut budget: u64 = 512 << 20;
    for g in 1..=64u64 {
        let gap = g * cs;
        if pos + gap + 4 > rd.avail() {
            return None;
        }
        if !plausible(rd, pos + gap) {
            continue;
        }
        // Split candidates: cluster boundaries inside the entry's data, last first.
        let first = e.data.div_ceil(cs) * cs;
        let mut s = pos / cs * cs;
        while s >= first && s > 0 {
            if crc_with_gap(rd, e, s, gap, &mut budget) == Some(e.crc) {
                return Some((s, gap));
            }
            if budget == 0 {
                return None;
            }
            s -= cs;
        }
    }
    None
}

/// CRC-32 of the entry's uncompressed content when its data is split at `split` with `gap`.
fn crc_with_gap(rd: &mut Rd, e: Entry, split: u64, gap: u64, budget: &mut u64) -> Option<u32> {
    let end = e.data + e.csize;
    let mut h = crc32fast::Hasher::new();
    let mut inf = (e.method == 8).then(|| flate2::Decompress::new(false));
    let mut out = vec![0u8; 256 << 10];
    let mut v = e.data;
    let mut buf = vec![0u8; 64 << 10];
    while v < end {
        let piece_end = if v < split { split.min(end) } else { end };
        let n = ((piece_end - v) as usize).min(buf.len());
        let phys = if v < split { v } else { v + gap };
        let (got, bad) = rd.read(phys, &mut buf[..n]);
        if bad || got < n {
            return None;
        }
        *budget = budget.saturating_sub(n as u64);
        match inf.as_mut() {
            None => h.update(&buf[..n]),
            Some(d) => {
                let mut input = &buf[..n];
                loop {
                    let before_in = d.total_in();
                    let before_out = d.total_out();
                    let st = d.decompress(input, &mut out, flate2::FlushDecompress::None).ok()?;
                    let used = (d.total_in() - before_in) as usize;
                    let made = (d.total_out() - before_out) as usize;
                    h.update(&out[..made]);
                    input = &input[used..];
                    if st == flate2::Status::StreamEnd {
                        return Some(h.finalize());
                    }
                    if (input.is_empty() && made < out.len()) || (used == 0 && made == 0) {
                        break;
                    }
                }
            }
        }
        v += n as u64;
    }
    Some(h.finalize())
}
