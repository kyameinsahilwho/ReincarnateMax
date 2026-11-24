//! PNG, GIF, BMP, TIFF/RAW, RAF, X3F, PSD, ICO.

use super::parse::{clip, clean, dmg, est, or_dmg, sized, typed, Env, Parsed};
use super::rd::{Rd, R};
use crate::formats::sniff;

const MB: u64 = 1 << 20;

pub(crate) fn png(rd: &mut Rd) -> Option<Parsed> {
    let mut pos = 8u64;
    let mut n = 0u32;
    loop {
        let len = or_dmg!(rd.u32be(pos), pos) as u64;
        let ty: [u8; 4] = or_dmg!(rd.bytes(pos + 4, 4), pos).try_into().unwrap();
        if len > 0x7FFF_FFFF || !ty.iter().all(u8::is_ascii_alphabetic) || (n == 0 && &ty != b"IHDR") {
            return if n == 0 { None } else { dmg(pos) };
        }
        if (n < 4 || &ty == b"IEND") && len <= MB {
            let mut buf = vec![0u8; 4 + len as usize + 4];
            let (got, bad) = rd.read(pos + 4, &mut buf);
            if bad || got < buf.len() {
                return if n == 0 { None } else { dmg(pos) };
            }
            let crc = crc32fast::hash(&buf[..4 + len as usize]);
            if crc.to_be_bytes() != buf[4 + len as usize..] {
                return if n == 0 { None } else { dmg(pos) };
            }
        }
        let next = pos + 12 + len;
        if &ty == b"IEND" {
            return clean(next);
        }
        if next > rd.avail() {
            return clip(rd.avail());
        }
        if next > 1 << 30 {
            return dmg(pos);
        }
        pos = next;
        n += 1;
    }
}

pub(crate) fn gif(rd: &mut Rd) -> Option<Parsed> {
    let h = rd.bytes(0, 13).ok()?;
    if h[6..10].iter().all(|&b| b == 0) {
        return None;
    }
    let flags = h[10];
    let mut pos = 13u64;
    if flags & 0x80 != 0 {
        pos += 3 << ((flags & 7) + 1);
    }
    let mut frames = 0u32;
    loop {
        if pos > 512 * MB {
            return dmg(pos);
        }
        let b = or_dmg!(rd.u8(pos), pos);
        match b {
            0x3B => return if frames > 0 { clean(pos + 1) } else { dmg(pos + 1) },
            0x21 => {
                pos += 2;
            }
            0x2C => {
                let f = or_dmg!(rd.u8(pos + 9), pos);
                pos += 10;
                if f & 0x80 != 0 {
                    pos += 3 << ((f & 7) + 1);
                }
                let lzw = or_dmg!(rd.u8(pos), pos);
                if !(1..=12).contains(&lzw) {
                    return dmg(pos);
                }
                pos += 1;
                frames += 1;
            }
            _ => return if pos < 64 { None } else { dmg(pos) },
        }
        // Data sub-blocks.
        loop {
            let n = or_dmg!(rd.u8(pos), pos);
            pos += 1 + n as u64;
            if n == 0 {
                break;
            }
        }
    }
}

pub(crate) fn bmp(rd: &mut Rd) -> Option<Parsed> {
    let h = rd.bytes(0, 54).ok()?.to_vec();
    if !sniff::bmp_ok(&h) {
        return None;
    }
    let declared = sniff::le32(&h, 2)? as u64;
    let off = sniff::le32(&h, 10)? as u64;
    let dib = sniff::le32(&h, 14)?;
    let mut len = declared;
    if dib >= 40 {
        let w = sniff::le32(&h, 18)? as i32 as i64;
        let hh = (sniff::le32(&h, 22)? as i32 as i64).abs();
        let bpp = sniff::le16(&h, 28)? as i64;
        let comp = sniff::le32(&h, 30)?;
        if comp == 0 || comp == 3 || comp == 6 {
            let row = ((w * bpp + 31) / 32) * 4;
            let need = off + (row * hh) as u64;
            len = if declared >= need && declared - need <= 1024 { declared } else { need };
        }
    }
    sized(rd, len, 26, 1 << 30)
}

/// Byte-order aware reads for TIFF structures.
struct Tf<'r, 'a> {
    rd: &'r mut Rd<'a>,
    le: bool,
}
impl Tf<'_, '_> {
    fn u16(&mut self, p: u64) -> R<u16> {
        if self.le {
            self.rd.u16le(p)
        } else {
            self.rd.u16be(p)
        }
    }
    fn u32(&mut self, p: u64) -> R<u32> {
        if self.le {
            self.rd.u32le(p)
        } else {
            self.rd.u32be(p)
        }
    }
    /// Values of a SHORT/LONG/IFD array entry (inline or at its offset), at most 65536.
    fn arr(&mut self, typ: u16, cnt: u32, val: [u8; 4]) -> Vec<u64> {
        let cnt = cnt.min(65536) as u64;
        let w = match typ {
            3 => 2,
            4 | 13 => 4,
            _ => return Vec::new(),
        };
        let inline = cnt * w <= 4;
        let base = if inline { 0 } else { self.u32_of(val) as u64 };
        let mut out = Vec::with_capacity(cnt as usize);
        for i in 0..cnt {
            let v = if inline {
                let b = &val[(i * w) as usize..];
                if w == 2 {
                    (if self.le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) }) as u64
                } else {
                    self.u32_of(val) as u64
                }
            } else if w == 2 {
                match self.u16(base + i * 2) {
                    Ok(v) => v as u64,
                    Err(_) => break,
                }
            } else {
                match self.u32(base + i * 4) {
                    Ok(v) => v as u64,
                    Err(_) => break,
                }
            };
            out.push(v);
        }
        out
    }
    fn u32_of(&self, v: [u8; 4]) -> u32 {
        if self.le {
            u32::from_le_bytes(v)
        } else {
            u32::from_be_bytes(v)
        }
    }
}

/// TIFF and TIFF-based camera RAW: the furthest byte referenced by the IFD chain, SubIFDs, EXIF
/// IFD, strips/tiles and JPEG previews (capped at 200 MB).
pub(crate) fn tiff(rd: &mut Rd, env: &Env) -> Option<Parsed> {
    const CAP: u64 = 200 * MB;
    const TSIZE: [u64; 14] = [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8, 4];
    let head = rd.bytes(0, 16).ok()?.to_vec();
    let le = head[0] == b'I';
    let rw2 = head.starts_with(b"IIU\0");
    let mut t = Tf { rd, le };
    let ifd0 = t.u32(4).ok()? as u64;
    let mut queue = vec![ifd0];
    let mut seen = std::collections::HashSet::new();
    let mut maxend = 16u64;
    let mut make: Option<String> = None;
    let mut dng = false;
    let mut raw_unbounded = false;
    let mut nifd = 0;
    let mut damaged = false;
    while let Some(off) = queue.pop() {
        if off < 8 || off >= CAP || !seen.insert(off) || nifd >= 64 {
            continue;
        }
        nifd += 1;
        let first = nifd == 1;
        let n = match t.u16(off) {
            Ok(n) if (1..=1000).contains(&n) => n as u64,
            _ if first => return None,
            _ => {
                damaged = true;
                continue;
            }
        };
        let ents = match t.rd.bytes(off + 2, (12 * n) as usize) {
            Ok(b) => b.to_vec(),
            Err(_) if first => return None,
            Err(_) => {
                damaged = true;
                continue;
            }
        };
        maxend = maxend.max(off + 2 + 12 * n + 4);
        let mut bad_types = 0;
        let mut pairs: [(Option<(u16, u32, [u8; 4])>, Option<(u16, u32, [u8; 4])>); 2] = [(None, None), (None, None)];
        let mut jpeg = (0u64, 0u64);
        for e in ents.chunks_exact(12) {
            let r16 = |b: &[u8]| if le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) };
            let tag = r16(&e[0..2]);
            let typ = r16(&e[2..4]);
            let cnt = t.u32_of(e[4..8].try_into().unwrap());
            let val: [u8; 4] = e[8..12].try_into().unwrap();
            if typ == 0 || typ > 13 {
                bad_types += 1;
                continue;
            }
            let size = cnt as u64 * TSIZE[typ as usize];
            let v = t.u32_of(val) as u64;
            if size > 4 && v + size <= CAP {
                maxend = maxend.max(v + size);
            }
            match tag {
                273 => pairs[0].0 = Some((typ, cnt, val)),
                279 => pairs[0].1 = Some((typ, cnt, val)),
                324 => pairs[1].0 = Some((typ, cnt, val)),
                325 => pairs[1].1 = Some((typ, cnt, val)),
                513 => jpeg.0 = v,
                514 => jpeg.1 = v,
                330 => queue.extend(t.arr(typ, cnt.min(64), val)),
                34665 | 34853 | 40965 => queue.push(v),
                50706 => dng = true,
                271 if make.is_none() => {
                    let n = (cnt as usize).min(64);
                    let s: Vec<u8> = if cnt <= 4 { val[..n.min(4)].to_vec() } else { t.rd.bytes(v, n).map(|b| b.to_vec()).unwrap_or_default() };
                    make = Some(s.iter().take_while(|&&c| c != 0).map(|&c| c as char).collect());
                }
                280 if rw2 => {
                    raw_unbounded = true;
                    if v < CAP {
                        maxend = maxend.max(v);
                    }
                }
                _ => {}
            }
        }
        if first && bad_types * 2 > n {
            return None;
        }
        for (o, c) in pairs {
            if let (Some(o), Some(c)) = (o, c) {
                let offs = t.arr(o.0, o.1, o.2);
                let cnts = t.arr(c.0, c.1, c.2);
                for (a, b) in offs.iter().zip(cnts.iter()) {
                    if a + b <= CAP {
                        maxend = maxend.max(a + b);
                    } else {
                        damaged = true;
                    }
                }
            }
        }
        if jpeg.0 > 0 && jpeg.0 + jpeg.1 <= CAP {
            maxend = maxend.max(jpeg.0 + jpeg.1);
        }
        if let Ok(next) = t.u32(off + 2 + 12 * n) {
            if next != 0 {
                queue.push(next as u64);
            }
        }
    }
    let ty = sniff::raw_kind(&head, make.as_deref(), dng);
    let avail = rd.avail();
    if raw_unbounded {
        let to_next = env.next_hit(rd.start).map(|h| h - rd.start).unwrap_or(avail);
        return typed(est(maxend.max(to_next.min(CAP)).min(avail)), ty);
    }
    if maxend > avail {
        return typed(clip(avail), ty);
    }
    if rd.bytes(maxend - 1, 1).is_err() {
        damaged = true;
    }
    typed(if damaged { dmg(maxend) } else { clean(maxend) }, ty)
}

pub(crate) fn raf(rd: &mut Rd) -> Option<Parsed> {
    let h = rd.bytes(0, 108).ok()?.to_vec();
    let mut end = 108u64;
    for o in [84usize, 92, 100] {
        let off = sniff::be32(&h, o)? as u64;
        let len = sniff::be32(&h, o + 4)? as u64;
        if off > 0 && len > 0 {
            if off + len > 512 * MB {
                return None;
            }
            end = end.max(off + len);
        }
    }
    sized(rd, end, 109, 512 * MB)
}

/// Sigma X3F: the directory section ("SECd") near the end, pointed to by the file's last 4 bytes.
pub(crate) fn x3f(rd: &mut Rd, env: &Env) -> Option<Parsed> {
    const CAP: u64 = 200 * MB;
    let mut pos = 40u64;
    let limit = CAP.min(rd.avail());
    while let Ok(Some(q)) = rd.find(pos, limit, b"SECd") {
        if let Ok(count) = rd.u32le(q + 8) {
            if (1..=1000).contains(&count) {
                let dir_end = q + 12 + count as u64 * 12;
                for end in [dir_end + 4, dir_end] {
                    if rd.u32le(end - 4).ok() == Some(q as u32) {
                        return clean(end);
                    }
                }
            }
        }
        pos = q + 4;
    }
    let to_next = env.next_hit(rd.start).map(|h| h - rd.start).unwrap_or(rd.avail());
    est(to_next.min(CAP).min(rd.avail()))
}

pub(crate) fn psd(rd: &mut Rd) -> Option<Parsed> {
    let h = rd.bytes(0, 26).ok()?.to_vec();
    let psb = sniff::be16(&h, 4)? == 2;
    let ch = sniff::be16(&h, 12)? as u64;
    let height = sniff::be32(&h, 14)? as u64;
    let width = sniff::be32(&h, 18)? as u64;
    let depth = sniff::be16(&h, 22)? as u64;
    let maxdim = if psb { 300_000 } else { 30_000 };
    if !(1..=56).contains(&ch) || height == 0 || width == 0 || height > maxdim || width > maxdim || !matches!(depth, 1 | 8 | 16 | 32) || sniff::be16(&h, 24)? > 9 {
        return None;
    }
    let cap = if psb { 64 << 30 } else { 2u64 << 30 };
    let mut pos = 26u64;
    for i in 0..3 {
        let l = if i == 2 && psb { rd.u64be(pos).ok()? } else { rd.u32be(pos).ok()? as u64 };
        pos = pos.saturating_add(if i == 2 && psb { 8 } else { 4 } + l.min(1 << 50));
        if pos > cap {
            return None;
        }
    }
    let comp = or_dmg!(rd.u16be(pos), pos);
    pos += 2;
    let rows = ch * height;
    match comp {
        0 => pos += rows * (width * depth).div_ceil(8),
        1 => {
            let w = if psb { 4 } else { 2 };
            let mut sum = 0u64;
            let mut p = pos;
            for _ in 0..rows {
                sum += if psb { or_dmg!(rd.u32be(p), p) as u64 } else { or_dmg!(rd.u16be(p), p) as u64 };
                p += w;
            }
            pos = p + sum;
        }
        _ => return dmg(pos),
    }
    sized(rd, pos, 30, cap)
}

pub(crate) fn ico(rd: &mut Rd) -> Option<Parsed> {
    let n = rd.u16le(4).ok()? as u64;
    if n == 0 || n > 64 {
        return None;
    }
    let ents = rd.bytes(6, (16 * n) as usize).ok()?.to_vec();
    if !sniff::ico_ok(&[&rd.bytes(0, 6).ok()?.to_vec()[..], &ents].concat()) {
        return None;
    }
    let mut end = 6 + 16 * n;
    for e in ents.chunks_exact(16) {
        let size = sniff::le32(e, 8)? as u64;
        let off = sniff::le32(e, 12)? as u64;
        end = end.max(off + size);
    }
    sized(rd, end, 22, 64 * MB)
}
