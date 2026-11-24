//! 7z, RAR4/RAR5, GZIP, BZIP2, XZ, TAR, CAB, ISO 9660.

use super::parse::{clip, clean, dmg, est, or_dmg, sized, Env, Parsed};
use super::rd::Rd;
use crate::formats::sniff;

const GB: u64 = 1 << 30;

pub(crate) fn sevenz(rd: &mut Rd) -> Option<Parsed> {
    let h = rd.bytes(0, 32).ok()?.to_vec();
    if crc32fast::hash(&h[12..32]) != sniff::le32(&h, 8)? {
        return None;
    }
    let off = sniff::le64(&h, 12)?;
    let size = sniff::le64(&h, 20)?;
    if size == 0 || off > 1 << 40 || size > 1 << 30 {
        return None;
    }
    let end = 32 + off + size;
    if end > rd.avail() {
        return clip(rd.avail());
    }
    if size <= 16 << 20 {
        let mut buf = vec![0u8; size as usize];
        let (got, bad) = rd.read(32 + off, &mut buf);
        if bad || got < buf.len() || crc32fast::hash(&buf) != sniff::le32(&h, 28)? {
            return dmg(end);
        }
    }
    sized(rd, end, 33, 1 << 40)
}

fn vint(rd: &mut Rd, p: u64) -> Option<(u64, u64)> {
    let mut v = 0u64;
    for i in 0..10u64 {
        let b = rd.u8(p + i).ok()?;
        v |= ((b & 0x7F) as u64) << (7 * i);
        if b & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

pub(crate) fn rar(rd: &mut Rd) -> Option<Parsed> {
    if rd.bytes(0, 8).ok()? == b"Rar!\x1a\x07\x01\x00" {
        return rar5(rd);
    }
    let mut pos = 7u64;
    let mut files = 0u32;
    loop {
        let Ok(h) = rd.bytes(pos, 7) else { break };
        let (crc, ty, flags, size) = (sniff::le16(h, 0)?, h[2], sniff::le16(h, 3)?, sniff::le16(h, 5)? as u64);
        if !(0x72..=0x7B).contains(&ty) || size < 7 {
            break;
        }
        let Ok(hb) = rd.bytes(pos + 2, size as usize - 2) else { break };
        if ty != 0x72 && (crc32fast::hash(hb) & 0xFFFF) as u16 != crc {
            break;
        }
        let mut add = 0u64;
        if flags & 0x8000 != 0 || ty == 0x74 || ty == 0x7A {
            add = rd.u32le(pos + 7).ok()? as u64;
            if (ty == 0x74 || ty == 0x7A) && flags & 0x100 != 0 {
                add |= (rd.u32le(pos + 32).ok()? as u64) << 32;
            }
        }
        if ty == 0x74 {
            files += 1;
        }
        if ty == 0x7B {
            return sized(rd, pos.saturating_add(size + add.min(1 << 50)), 20, 1 << 40);
        }
        pos = pos.saturating_add(size + add.min(1 << 50));
        if pos > 1 << 40 {
            break;
        }
    }
    if files == 0 {
        return None;
    }
    est(pos.min(rd.avail()))
}

fn rar5(rd: &mut Rd) -> Option<Parsed> {
    let mut pos = 8u64;
    let mut blocks = 0u32;
    loop {
        let Ok(crc) = rd.u32le(pos) else { break };
        let Some((hsize, l1)) = vint(rd, pos + 4) else { break };
        if hsize == 0 || hsize > 2 << 20 {
            break;
        }
        let mut hb = vec![0u8; (l1 + hsize) as usize];
        let (got, bad) = rd.read(pos + 4, &mut hb);
        if bad || got < hb.len() || crc32fast::hash(&hb) != crc {
            break;
        }
        let mut q = pos + 4 + l1;
        let Some((ty, l)) = vint(rd, q) else { break };
        q += l;
        let Some((flags, l)) = vint(rd, q) else { break };
        q += l;
        if flags & 1 != 0 {
            let Some((_, l)) = vint(rd, q) else { break };
            q += l;
        }
        let data = if flags & 2 != 0 { vint(rd, q).map(|v| v.0).unwrap_or(0) } else { 0 };
        if !(1..=5).contains(&ty) {
            break;
        }
        let end = (pos + 4 + l1 + hsize).saturating_add(data);
        blocks += 1;
        if ty == 5 {
            return sized(rd, end, 20, 1 << 40);
        }
        pos = end;
        if pos > 1 << 40 {
            break;
        }
    }
    if blocks < 2 {
        return None;
    }
    est(pos.min(rd.avail()))
}

pub(crate) fn gzip(rd: &mut Rd) -> Option<Parsed> {
    const CAP: u64 = 4 * GB;
    let mut pos = 0u64;
    let mut members = 0u32;
    loop {
        let Ok(h) = rd.bytes(pos, 10) else { break };
        if h[..3] != [0x1F, 0x8B, 8] || h[3] & 0xE0 != 0 {
            break;
        }
        let flags = h[3];
        let mut p = pos + 10;
        if flags & 4 != 0 {
            p += 2 + or_dmg!(rd.u16le(p), p) as u64;
        }
        for bit in [8u8, 16] {
            if flags & bit != 0 {
                match rd.find(p, p + 65536, &[0]) {
                    Ok(Some(z)) => p = z + 1,
                    _ => return if members == 0 { None } else { dmg(p) },
                }
            }
        }
        if flags & 2 != 0 {
            p += 2;
        }
        // Inflate the member.
        let mut d = flate2::Decompress::new(false);
        let mut out = vec![0u8; 256 << 10];
        let mut crc = crc32fast::Hasher::new();
        let mut q = p;
        loop {
            if q - p > CAP {
                return est(q);
            }
            let c = match rd.chunk(q) {
                Ok(c) => c,
                Err(_) => return if members == 0 && q - p < 64 { None } else { dmg(q) },
            };
            let (bi, bo) = (d.total_in(), d.total_out());
            let st = match d.decompress(c, &mut out, flate2::FlushDecompress::None) {
                Ok(s) => s,
                Err(_) => return if members == 0 && q - p < 64 { None } else { dmg(q) },
            };
            let used = d.total_in() - bi;
            let made = (d.total_out() - bo) as usize;
            crc.update(&out[..made]);
            q += used;
            if st == flate2::Status::StreamEnd {
                break;
            }
            if used == 0 && made == 0 {
                return dmg(q);
            }
        }
        let crc = crc.finalize();
        let (tc, ts) = (or_dmg!(rd.u32le(q), q), or_dmg!(rd.u32le(q + 4), q));
        if tc != crc || ts != d.total_out() as u32 {
            return dmg(q + 8);
        }
        pos = q + 8;
        members += 1;
    }
    if members == 0 {
        None
    } else {
        clean(pos)
    }
}

pub(crate) fn bz2(rd: &mut Rd, env: &Env) -> Option<Parsed> {
    const MAGIC: u64 = 0x1772_4538_5090;
    const CAP: u64 = 512 << 20;
    let mut start = 0u64;
    loop {
        // Bit-aligned search for the end-of-stream magic, then 32 bits of CRC.
        let mut reg = 0u64;
        let mut pos = start + 4;
        let mut found = None;
        'scan: while pos - start < CAP {
            let Ok(c) = rd.chunk(pos) else { break };
            for (i, &b) in c.iter().enumerate() {
                for k in (0..8).rev() {
                    reg = (reg << 1) | ((b >> k) & 1) as u64;
                    if reg & 0xFFFF_FFFF_FFFF == MAGIC {
                        // Bit index just after the magic.
                        let bit = (pos + i as u64) * 8 + (8 - k as u64);
                        found = Some(bit);
                        break 'scan;
                    }
                }
            }
            pos += c.len() as u64;
        }
        let Some(bit) = found else {
            if start > 0 {
                return clean(start);
            }
            let to_next = env.next_hit(rd.start).map(|h| h - rd.start).unwrap_or(rd.avail());
            return est(to_next.min(CAP).min(rd.avail()));
        };
        let end = (bit + 32).div_ceil(8);
        if end > rd.avail() {
            return clip(rd.avail());
        }
        // Another stream right after (parallel bzip2)?
        match rd.bytes(end, 10) {
            Ok(n) if n.starts_with(b"BZh") && (b'1'..=b'9').contains(&n[3]) && n[4..10] == [0x31, 0x41, 0x59, 0x26, 0x53, 0x59] => start = end,
            _ => return clean(end),
        }
    }
}

pub(crate) fn xz(rd: &mut Rd) -> Option<Parsed> {
    const CAP: u64 = 16 * GB;
    let h = rd.bytes(0, 12).ok()?.to_vec();
    if crc32fast::hash(&h[6..8]) != sniff::le32(&h, 8)? {
        return None;
    }
    let mut stream = 0u64;
    let mut from = 12u64;
    let mut end = None;
    while let Ok(Some(q)) = rd.find(from, CAP.min(rd.avail()), b"YZ") {
        from = q + 1;
        if (q + 2 - stream) % 4 != 0 || q < stream + 22 {
            continue;
        }
        let Ok(f) = rd.bytes(q - 10, 12) else { continue };
        let f = f.to_vec();
        if f[8..10] != h[6..8] || crc32fast::hash(&f[4..10]) != sniff::le32(&f, 0)? {
            continue;
        }
        let mut e = q + 2;
        end = Some(e);
        // Stream padding, then maybe another stream.
        while rd.u32le(e).ok() == Some(0) {
            e += 4;
        }
        if rd.bytes(e, 6).ok() == Some(&[0xFD, b'7', b'z', b'X', b'Z', 0][..]) {
            stream = e;
            from = e + 12;
            continue;
        }
        break;
    }
    match end {
        Some(e) => clean(e),
        None => dmg(12),
    }
}

pub(crate) fn tar(rd: &mut Rd) -> Option<Parsed> {
    const CAP: u64 = 64 * GB;
    let mut pos = 0u64;
    loop {
        let blk = or_dmg!(rd.bytes(pos, 512), pos).to_vec();
        if blk.iter().all(|&b| b == 0) {
            if pos == 0 {
                return None;
            }
            let mut end = pos + 512;
            if rd.bytes(end, 512).is_ok_and(|b| b.iter().all(|&x| x == 0)) {
                end += 512;
                // Zero blocks up to the next record boundary (10240 bytes) belong to the archive.
                while end % 10240 != 0 && rd.bytes(end, 512).is_ok_and(|b| b.iter().all(|&x| x == 0)) {
                    end += 512;
                }
            }
            return clean(end);
        }
        if !sniff::tar_ok(&blk) {
            return if pos == 0 { None } else { dmg(pos) };
        }
        let f = &blk[124..136];
        let size = if f[0] & 0x80 != 0 {
            f[1..].iter().fold(0u64, |a, &b| a.saturating_mul(256).saturating_add(b as u64))
        } else {
            f.iter().take_while(|&&c| c != 0 && c != b' ').fold(0u64, |a, &c| if (b'0'..=b'7').contains(&c) { a * 8 + (c - b'0') as u64 } else { a })
        };
        pos = pos.saturating_add(512).saturating_add(size.div_ceil(512).saturating_mul(512));
        if pos > CAP {
            return dmg(pos);
        }
        if pos > rd.avail() {
            return clip(rd.avail());
        }
    }
}

pub(crate) fn cab(rd: &mut Rd) -> Option<Parsed> {
    let h = rd.bytes(0, 36).ok()?.to_vec();
    let cb = sniff::le32(&h, 8)? as u64;
    let coff = sniff::le32(&h, 16)? as u64;
    if coff >= cb || sniff::le32(&h, 12)? != 0 {
        return None;
    }
    sized(rd, cb, 36, 2 * GB)
}

pub(crate) fn iso(rd: &mut Rd) -> Option<Parsed> {
    let pvd = rd.bytes(0x8000, 136).ok()?.to_vec();
    if !pvd.starts_with(b"\x01CD001\x01") {
        return None;
    }
    let vss = sniff::le32(&pvd, 80)? as u64;
    let lbs = sniff::le16(&pvd, 128)? as u64;
    if !matches!(lbs, 512 | 1024 | 2048) {
        return None;
    }
    sized(rd, vss * lbs, 0x8800, 256 * GB)
}
