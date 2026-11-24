//! RIFF (AVI/WAV/WebP), AIFF, ISO-BMFF (MP4/MOV/M4A/3GP/HEIC/AVIF/CR3), Matroska/WebM, ASF,
//! FLV, MPEG-PS, MPEG-TS/M2TS, MP3, FLAC, Ogg, AAC ADTS, AMR, MIDI.

use super::parse::{clip, clean, dmg, est, or_dmg, typed, Env, Parsed};
use super::rd::Rd;
use crate::formats::sniff;

const GB: u64 = 1 << 30;

fn printable4(b: &[u8]) -> bool {
    b.len() >= 4 && b[..4].iter().all(|&c| (0x20..0x7F).contains(&c))
}

fn finish_sized(rd: &mut Rd, end: u64, damaged: bool) -> Option<Parsed> {
    let avail = rd.avail();
    if end > avail {
        return clip(avail);
    }
    if damaged || rd.bytes(end - 1, 1).is_err() {
        return dmg(end);
    }
    clean(end)
}

/// Placeholder sizes left by recordings that were never finalized (streamed or interrupted).
fn riff_placeholder(size: u64) -> bool {
    size == 0 || size == 0xFFFF_FFFF
}

/// The end of a file whose size field is a placeholder: estimated up to the next header (at
/// most 4 GiB, the most a RIFF size can say), never before `min`.
fn est_to_next(rd: &mut Rd, env: &Env, min: u64) -> Option<Parsed> {
    let avail = rd.avail();
    let to = env.next_hit(rd.start).map_or(avail, |h| h - rd.start).min(4 * GB + 8);
    est(to.max(min).min(avail))
}

pub(crate) fn riff(rd: &mut Rd, env: &Env) -> Option<Parsed> {
    let h = rd.bytes(0, 12).ok()?.to_vec();
    let ty = match &h[8..12] {
        b"AVI " => "avi",
        b"WAVE" => "wav",
        b"WEBP" => "webp",
        _ => return None,
    };
    let rf64 = h.starts_with(b"RF64");
    let size = if rf64 {
        if rd.bytes(12, 4).ok()? != b"ds64" {
            return None;
        }
        rd.u64le(20).ok()?
    } else {
        sniff::le32(&h, 4)? as u64
    };
    if size < 4 || (ty == "webp" && size > 256 << 20) {
        return None;
    }
    // 0xFFFFFFFF: the recording was never finalized; the data chunk may still say how long it is.
    let riff_unknown = !rf64 && size == 0xFFFF_FFFF && ty != "webp";
    // Walk the chunks inside: they must look like chunks.
    let mut end = if riff_unknown { 4 * GB + 8 } else { size.saturating_add(8 + (size & 1)) };
    let mut pos = 12u64;
    let mut n = 0;
    while pos + 8 <= end && n < 256 {
        let Ok(c) = rd.bytes(pos, 8) else { break };
        if !printable4(c) {
            // The chunk chain is broken: what's before the break is all we can vouch for.
            return if n == 0 { None } else { typed(dmg(pos), ty) };
        }
        let id: [u8; 4] = c[..4].try_into().unwrap();
        let cs = sniff::le32(c, 4)? as u64;
        let media = (ty == "wav" && &id == b"data") || (ty == "avi" && &id == b"LIST" && rd.bytes(pos + 8, 4).ok() == Some(b"movi"));
        if media && !rf64 && (riff_placeholder(cs) || (ty == "avi" && cs <= 4)) {
            // Placeholder size: the samples run on to wherever the recording stopped.
            return typed(est_to_next(rd, env, pos + 8), ty);
        }
        pos += 8 + cs + (cs & 1);
        n += 1;
        if media && riff_unknown {
            // Only the RIFF size is a placeholder: the media chunk's own size ends the file.
            end = pos;
            break;
        }
    }
    if n == 0 {
        return None;
    }
    if riff_unknown && end > 4 * GB {
        // No media chunk with a real size: the end is unknown.
        return typed(est_to_next(rd, env, pos.min(end)), ty);
    }
    if ty == "avi" {
        // OpenDML: "RIFF....AVIX" extensions follow the first RIFF.
        while let Ok(x) = rd.bytes(end, 12) {
            if !(x.starts_with(b"RIFF") && &x[8..12] == b"AVIX") || end > 64 * GB {
                break;
            }
            let s = sniff::le32(x, 4)? as u64;
            end += 8 + s + (s & 1);
        }
    }
    typed(finish_sized(rd, end, false), ty)
}

pub(crate) fn aiff(rd: &mut Rd) -> Option<Parsed> {
    let size = rd.u32be(4).ok()? as u64;
    if size < 4 || !printable4(rd.bytes(12, 4).ok()?) {
        return None;
    }
    finish_sized(rd, 8 + size + (size & 1), false)
}

const BMFF_TOP: [&[u8; 4]; 20] = [
    b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid", b"meta", b"moof", b"mfra", b"pdin", b"styp", b"sidx", b"ssix", b"prft", b"emsg", b"pnot", b"udta",
    b"jumb", b"junk",
];

pub(crate) fn bmff(rd: &mut Rd, env: &Env) -> Option<Parsed> {
    const CAP: u64 = 256 * GB;
    let avail = rd.avail();
    let (mut moov, mut mdat, mut meta, mut moof) = (false, false, false, false);
    let mut pos = 0u64;
    while pos < avail {
        let Ok(h) = rd.bytes(pos, 8) else { break };
        let size32 = sniff::be32(h, 0)? as u64;
        let typ: [u8; 4] = h[4..8].try_into().unwrap();
        if !BMFF_TOP.contains(&&typ) || (pos > 0 && &typ == b"ftyp") {
            break;
        }
        let len = match size32 {
            1 => match rd.u64be(pos + 8) {
                Ok(l) if l >= 16 => l,
                _ => break,
            },
            0 => {
                // Extends to the end of the file: estimate it.
                let to = env.next_hit(rd.start + pos).map(|h| h - rd.start).unwrap_or(avail);
                return est(to.max(pos + 8));
            }
            n if n < 8 => break,
            n => n,
        };
        match &typ {
            b"moov" => moov = true,
            b"mdat" => mdat = true,
            b"meta" => meta = true,
            b"moof" => moof = true,
            _ => {}
        }
        if pos.saturating_add(len) > avail {
            return clip(avail);
        }
        pos += len;
        if pos > CAP {
            return dmg(pos);
        }
    }
    if pos < 16 {
        return None;
    }
    if (moov && (mdat || moof)) || meta {
        if rd.bytes(pos - 1, 1).is_err() {
            return dmg(pos);
        }
        clean(pos)
    } else {
        dmg(pos)
    }
}

fn ebml_id(rd: &mut Rd, p: u64) -> Option<(u32, u64)> {
    let b = rd.u8(p).ok()?;
    if b == 0 {
        return None;
    }
    let l = b.leading_zeros() as u64 + 1;
    if l > 4 {
        return None;
    }
    let bytes = rd.bytes(p, l as usize).ok()?;
    Some((bytes.iter().fold(0u32, |a, &x| (a << 8) | x as u32), l))
}

/// (size, None when "unknown"), length of the size field.
fn ebml_size(rd: &mut Rd, p: u64) -> Option<(Option<u64>, u64)> {
    let b = rd.u8(p).ok()?;
    if b == 0 {
        return None;
    }
    let l = b.leading_zeros() as u64 + 1;
    let bytes = rd.bytes(p, l as usize).ok()?;
    let mut v = (b & (0xFFu16 >> l) as u8) as u64;
    for &x in &bytes[1..] {
        v = (v << 8) | x as u64;
    }
    let all = (1u64 << (7 * l)) - 1;
    Some((if v == all { None } else { Some(v) }, l))
}

pub(crate) fn ebml(rd: &mut Rd) -> Option<Parsed> {
    const SEGMENT: u32 = 0x1853_8067;
    const CLUSTER: u32 = 0x1F43_B675;
    const TOP: [u32; 10] = [0x114D_9B74, 0x1549_A966, 0x1654_AE6B, CLUSTER, 0x1C53_BB6B, 0x1941_A469, 0x1043_A770, 0x1254_C367, 0xEC, 0xBF];
    const CHILD: [u32; 9] = [0xE7, 0x5854, 0xA7, 0xAB, 0xA3, 0xA0, 0xAF, 0xEC, 0xBF];
    let (id, il) = ebml_id(rd, 0)?;
    if id != 0x1A45_DFA3 {
        return None;
    }
    let (hs, hl) = ebml_size(rd, il)?;
    let hs = hs.filter(|&s| s <= 4096)?;
    let seg = il + hl + hs;
    let (id, sl) = ebml_id(rd, seg)?;
    if id != SEGMENT {
        return None;
    }
    let (ss, szl) = ebml_size(rd, seg + sl)?;
    let data = seg + sl + szl;
    if let Some(s) = ss {
        if s > 1 << 40 {
            return None;
        }
        return finish_sized(rd, data + s, false);
    }
    let mut p = data;
    let mut clusters = 0u32;
    'top: loop {
        let Some((id, il)) = ebml_id(rd, p) else { break };
        if !TOP.contains(&id) {
            break;
        }
        let Some((sz, zl)) = ebml_size(rd, p + il) else { break };
        match sz {
            Some(s) => p += il + zl + s,
            None if id == CLUSTER => {
                p += il + zl;
                loop {
                    let Some((cid, cl)) = ebml_id(rd, p) else { break 'top };
                    if !CHILD.contains(&cid) {
                        break;
                    }
                    let Some((Some(s), zl)) = ebml_size(rd, p + cl) else { break 'top };
                    p += cl + zl + s;
                }
            }
            None => break,
        }
        if id == CLUSTER {
            clusters += 1;
        }
        if p > 64 * GB {
            break;
        }
    }
    let p = p.min(rd.avail());
    if clusters > 0 {
        clean(p)
    } else {
        dmg(p)
    }
}

pub(crate) fn asf(rd: &mut Rd) -> Option<Parsed> {
    let hsize = rd.u64le(16).ok()?;
    if !(30..=64 << 20).contains(&hsize) {
        return None;
    }
    let head_n = hsize.min(128 << 10) as usize;
    let mut head = vec![0u8; head_n];
    let (got, _) = rd.read(0, &mut head);
    head.truncate(got);
    let ty = sniff::asf_kind(&head);
    // File Properties object -> declared file size.
    let mut file_size = 0u64;
    let mut o = 30usize;
    while o + 24 <= head.len() {
        let sz = sniff::le64(&head, o + 16)?;
        if head[o..o + 16] == sniff::ASF_FILE_PROPS {
            file_size = sniff::le64(&head, o + 40).unwrap_or(0);
            break;
        }
        // Every object moves forward and stays inside the header buffer (no wrap-around).
        if sz < 24 || sz > (head.len() - o) as u64 {
            break;
        }
        o += sz as usize;
    }
    let mut pos = hsize;
    let d = or_dmg!(rd.bytes(pos, 24), pos).to_vec();
    if d[..16] != sniff::ASF_DATA {
        return typed(dmg(pos), ty);
    }
    pos = pos.saturating_add(sniff::le64(&d, 16)?);
    while let Ok(x) = rd.bytes(pos, 24) {
        if x[..16] != sniff::ASF_SIMPLE_INDEX && x[..16] != sniff::ASF_INDEX {
            break;
        }
        let s = sniff::le64(x, 16)?;
        if s < 24 {
            break;
        }
        pos = pos.saturating_add(s);
    }
    let end = if file_size >= pos && file_size - pos < 64 << 20 { file_size } else { pos };
    typed(finish_sized(rd, end, false), ty)
}

pub(crate) fn flv(rd: &mut Rd) -> Option<Parsed> {
    let off = rd.u32be(5).ok()? as u64;
    let mut pos = off + 4;
    let mut tags = 0u32;
    while let Ok(t) = rd.bytes(pos, 11) {
        let ty = t[0] & 0x1F;
        let ds = ((t[1] as u64) << 16) | ((t[2] as u64) << 8) | t[3] as u64;
        if !matches!(ty, 8 | 9 | 18) || t[8..11] != [0, 0, 0] {
            break;
        }
        match rd.u32be(pos + 11 + ds) {
            Ok(prev) if prev as u64 == 11 + ds => {}
            _ => break,
        }
        pos += 15 + ds;
        tags += 1;
    }
    if tags == 0 {
        None
    } else {
        clean(pos)
    }
}

pub(crate) fn mpeg_ps(rd: &mut Rd) -> Option<Parsed> {
    let mut pos = 0u64;
    let mut packs = 0u32;
    loop {
        let Ok(h) = rd.bytes(pos, 6) else { break };
        if h[..3] != [0, 0, 1] {
            break;
        }
        match h[3] {
            0xBA => {
                if h[4] & 0xC0 == 0x40 {
                    let Ok(s) = rd.u8(pos + 13) else { break };
                    pos += 14 + (s & 7) as u64;
                } else if h[4] & 0xF0 == 0x20 {
                    pos += 12;
                } else {
                    break;
                }
                packs += 1;
            }
            0xB9 => return clean(pos + 4),
            0xBB..=0xFF => pos += 6 + u16::from_be_bytes([h[4], h[5]]) as u64,
            _ => break,
        }
        if pos > 64 * GB {
            break;
        }
    }
    if packs < 2 {
        return None;
    }
    if pos > rd.avail() {
        // The last packet runs past the end of the source.
        return clip(rd.avail());
    }
    est(pos)
}

pub(crate) fn ts(rd: &mut Rd, first: u64, pkt: u64) -> Option<Parsed> {
    let mut n = 0u64;
    while rd.u8(first + n * pkt).ok() == Some(0x47) && n * pkt < 64 * GB {
        n += 1;
    }
    if n < 4 {
        return None;
    }
    // The last packet must be complete.
    while n > 0 && (n * pkt) > rd.avail() {
        n -= 1;
    }
    clean(n * pkt)
}

fn mp3_at(rd: &mut Rd, p: u64) -> Option<sniff::Mp3Hdr> {
    rd.bytes(p, 4).ok().and_then(sniff::mp3_header)
}

pub(crate) fn mp3(rd: &mut Rd) -> Option<Parsed> {
    let mut pos = 0u64;
    if let Some(n) = rd.bytes(0, 10).ok().and_then(sniff::id3_len) {
        pos = n;
        // The first frame may follow some padding.
        let mut q = pos;
        let lim = pos + 65536;
        loop {
            if q >= lim {
                return None;
            }
            let ok = mp3_at(rd, q).is_some_and(|h| {
                let mut buf = vec![0u8; 3 * 1441 + 4];
                let (got, _) = rd.read(q, &mut buf);
                let _ = h;
                sniff::mp3_frames(&buf[..got], 3)
            });
            if ok {
                break;
            }
            q += 1;
        }
        pos = q;
    }
    let first = mp3_at(rd, pos)?;
    let mut frames = 0u32;
    let avail = rd.avail();
    while let Some(h) = mp3_at(rd, pos) {
        if h.ver != first.ver || h.layer != first.layer || h.sample_rate != first.sample_rate {
            break;
        }
        if pos + h.len as u64 > avail {
            return if frames >= 4 { clip(avail) } else { None };
        }
        pos += h.len as u64;
        frames += 1;
    }
    if frames < 4 {
        return None;
    }
    if rd.bytes(pos, 8).ok() == Some(b"APETAGEX") {
        if let Ok(s) = rd.u32le(pos + 12) {
            pos += 32 + s as u64;
        }
    }
    if rd.bytes(pos, 3).ok() == Some(b"TAG") {
        pos += 128;
    }
    clean(pos.min(avail))
}

pub(crate) fn aac(rd: &mut Rd) -> Option<Parsed> {
    let mut pos = 0u64;
    let mut frames = 0u32;
    let mut sr = None;
    let avail = rd.avail();
    while let Some((len, s)) = rd.bytes(pos, 7).ok().and_then(sniff::adts_header) {
        if *sr.get_or_insert(s) != s {
            break;
        }
        if pos + len as u64 > avail {
            break;
        }
        pos += len as u64;
        frames += 1;
    }
    if frames < 4 {
        return None;
    }
    if rd.bytes(pos, 3).ok() == Some(b"TAG") {
        pos += 128;
    }
    clean(pos.min(avail))
}

pub(crate) fn amr(rd: &mut Rd) -> Option<Parsed> {
    const NB: [u8; 16] = [12, 13, 15, 17, 19, 20, 26, 31, 5, 6, 5, 5, 0, 0, 0, 0];
    const WB: [u8; 16] = [17, 23, 32, 36, 40, 46, 50, 58, 60, 5, 0, 0, 0, 0, 0, 0];
    let wb = rd.bytes(0, 9).ok() == Some(b"#!AMR-WB\n");
    let mut pos = if wb { 9 } else { 6 };
    let mut frames = 0u32;
    while let Ok(t) = rd.u8(pos) {
        let ft = (t >> 3) & 15;
        let size = if wb { WB[ft as usize] } else { NB[ft as usize] };
        let nodata = ft == 15 || (wb && ft == 14);
        if t & 0x83 != 0 || t & 0x04 == 0 || (size == 0 && !nodata) {
            break;
        }
        if pos + 1 + size as u64 > rd.avail() {
            break;
        }
        pos += 1 + size as u64;
        frames += 1;
    }
    if frames == 0 {
        None
    } else {
        clean(pos)
    }
}

pub(crate) fn midi(rd: &mut Rd) -> Option<Parsed> {
    let ntrks = rd.u16be(10).ok()?;
    if ntrks == 0 {
        return None;
    }
    let mut pos = 14u64;
    let mut seen = 0u16;
    while seen < ntrks {
        let c = or_dmg!(rd.bytes(pos, 8), pos).to_vec();
        if !printable4(&c) {
            return dmg(pos);
        }
        if &c[..4] == b"MTrk" {
            seen += 1;
        }
        pos += 8 + sniff::be32(&c, 4)? as u64;
        if pos > 256 << 20 {
            return dmg(pos);
        }
    }
    finish_sized(rd, pos, false)
}

// ---------------------------------------------------------------------------------------- FLAC

const fn crc8_table() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u8;
        let mut k = 0;
        while k < 8 {
            c = if c & 0x80 != 0 { (c << 1) ^ 0x07 } else { c << 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}
const fn crc16_table() -> [u16; 256] {
    let mut t = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = (i as u16) << 8;
        let mut k = 0;
        while k < 8 {
            c = if c & 0x8000 != 0 { (c << 1) ^ 0x8005 } else { c << 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}
static CRC8: [u8; 256] = crc8_table();
static CRC16: [u16; 256] = crc16_table();

/// A FLAC frame header at `p` (sync + CRC-8): (header length, samples in the frame).
fn flac_frame(rd: &mut Rd, p: u64) -> Option<(u64, u64)> {
    let mut b = [0u8; 16];
    let (got, bad) = rd.read(p, &mut b);
    if bad || got < 6 {
        return None;
    }
    let b = &b[..got];
    if b[0] != 0xFF || b[1] & 0xFE != 0xF8 {
        return None;
    }
    let (bs, sr, ch, ss) = (b[2] >> 4, b[2] & 15, b[3] >> 4, (b[3] >> 1) & 7);
    if bs == 0 || sr == 15 || ch >= 11 || ss == 3 || b[3] & 1 != 0 {
        return None;
    }
    let lead = b[4].leading_ones() as usize;
    let nlen = match lead {
        0 => 1,
        2..=7 => lead,
        _ => return None,
    };
    let mut i = 4 + nlen;
    if i > got || b[5..4 + nlen].iter().any(|&x| x & 0xC0 != 0x80) {
        return None;
    }
    let samples = match bs {
        1 => 192,
        2..=5 => 576u64 << (bs - 2),
        6 => {
            i += 1;
            *b.get(i - 1)? as u64 + 1
        }
        7 => {
            i += 2;
            u16::from_be_bytes([*b.get(i - 2)?, *b.get(i - 1)?]) as u64 + 1
        }
        _ => 256u64 << (bs - 8),
    };
    i += match sr {
        12 => 1,
        13 | 14 => 2,
        _ => 0,
    };
    if i >= got {
        return None;
    }
    let crc = b[..i].iter().fold(0u8, |c, &x| CRC8[(c ^ x) as usize]);
    (crc == b[i]).then_some((i as u64 + 1, samples))
}

pub(crate) fn flac(rd: &mut Rd) -> Option<Parsed> {
    let mut pos = 4u64;
    let (mut min_frame, mut max_frame) = (0u64, 0u64);
    let mut total_samples = 1u64;
    for i in 0..1024 {
        let h = rd.u32be(pos).ok()?;
        let (last, ty, len) = (h >> 31 == 1, (h >> 24) & 0x7F, (h & 0xFF_FFFF) as u64);
        if ty > 6 || (i == 0 && (ty != 0 || len != 34)) || (i > 0 && ty == 0) {
            return if i == 0 { None } else { clip(pos) };
        }
        if ty == 0 {
            let si = rd.bytes(pos + 4, 18).ok()?;
            min_frame = ((si[4] as u64) << 16) | ((si[5] as u64) << 8) | si[6] as u64;
            max_frame = ((si[7] as u64) << 16) | ((si[8] as u64) << 8) | si[9] as u64;
            total_samples = (((si[13] & 15) as u64) << 32) | sniff::be32(si, 14)? as u64;
        }
        pos += 4 + len;
        if last {
            break;
        }
    }
    if min_frame > max_frame {
        (min_frame, max_frame) = (0, 0);
    }
    let maxf = if max_frame > 0 { max_frame + 64 } else { 1 << 20 };
    let first = pos;
    let mut f = pos;
    let mut samples_done = 0u64;
    if flac_frame(rd, f).is_none() {
        return if total_samples == 0 { clean(f) } else { clip(f.min(rd.avail())) };
    }
    loop {
        let Some((hl, ns)) = flac_frame(rd, f) else { return dmg(f) };
        let mut crc = 0u16;
        let mut q = f;
        // Where the running CRC-16 becomes zero: the frame may end there. Zero bytes after a zero
        // keep it zero, so a run (padding after the end) counts once, at its start.
        let mut zeros: Vec<u64> = Vec::new();
        let mut last_zero = 0u64;
        let mut next = None;
        'scan: while q - f <= maxf {
            let c = match rd.chunk(q) {
                Ok(c) => c.to_vec(),
                Err(_) => break,
            };
            let mut i = 0;
            while i < c.len() {
                crc = (crc << 8) ^ CRC16[((crc >> 8) as u8 ^ c[i]) as usize];
                i += 1;
                let at = q + i as u64;
                if crc == 0 && at >= f + hl + 2 {
                    if last_zero + 1 != at && zeros.len() < 64 {
                        zeros.push(at);
                    }
                    last_zero = at;
                    let sync = if i + 1 < c.len() { c[i] == 0xFF && c[i + 1] & 0xFE == 0xF8 } else { true };
                    if sync && flac_frame(rd, at).is_some() {
                        next = Some(at);
                        break 'scan;
                    }
                }
                if at - f > maxf {
                    break 'scan;
                }
            }
            q += c.len() as u64;
        }
        if let Some(n) = next {
            f = n;
            samples_done += ns;
            if f > 8 * GB {
                return dmg(f);
            }
            continue;
        }
        // The last frame: no frame header follows, and a CRC-16 zero can also happen by chance
        // (about once per 64 KiB) before or after its true end. Keep the zeros its size bounds
        // from STREAMINFO allow; one left is the end, several leave the end estimated.
        let fits = |z: &u64| (min_frame == 0 || z - f >= min_frame) && (max_frame == 0 || z - f <= max_frame);
        let cands: Vec<u64> = if zeros.iter().any(fits) { zeros.iter().copied().filter(fits).collect() } else { zeros };
        return match cands.len() {
            0 => dmg(f),
            1 if cands.iter().all(fits) => clean(cands[0]),
            _ => {
                // The zero nearest to the length the stream's average bitrate predicts.
                let pick = if samples_done > 0 {
                    let guess = ((f - first) as u128 * ns as u128 / samples_done as u128) as u64;
                    cands.iter().copied().min_by_key(|&z| (z - f).abs_diff(guess)).unwrap_or(cands[0])
                } else {
                    cands[0]
                };
                est(pick)
            }
        };
    }
}

// ----------------------------------------------------------------------------------------- Ogg

const fn ogg_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = (i as u32) << 24;
        let mut k = 0;
        while k < 8 {
            c = if c & 0x8000_0000 != 0 { (c << 1) ^ 0x04C1_1DB7 } else { c << 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}
static OGG_CRC: [u32; 256] = ogg_table();

pub(crate) fn ogg(rd: &mut Rd) -> Option<Parsed> {
    let mut pos = 0u64;
    let mut open: Vec<u32> = Vec::new();
    let mut pages = 0u64;
    loop {
        let Ok(h) = rd.bytes(pos, 27) else { break };
        if &h[..4] != b"OggS" || h[4] != 0 {
            break;
        }
        let (htype, serial, nseg) = (h[5], sniff::le32(h, 14)?, h[26] as usize);
        let Ok(segs) = rd.bytes(pos + 27, nseg) else { break };
        let body: u64 = segs.iter().map(|&s| s as u64).sum();
        let plen = 27 + nseg as u64 + body;
        let mut page = vec![0u8; plen as usize];
        let (got, bad) = rd.read(pos, &mut page);
        if bad || got < page.len() {
            break;
        }
        let stored = sniff::le32(&page, 22)?;
        page[22..26].fill(0);
        let crc = page.iter().fold(0u32, |c, &b| (c << 8) ^ OGG_CRC[((c >> 24) as u8 ^ b) as usize]);
        if crc != stored {
            break;
        }
        if htype & 2 != 0 {
            if pages > 0 && open.is_empty() {
                break;
            }
            open.push(serial);
        } else if !open.contains(&serial) {
            break;
        }
        if htype & 4 != 0 {
            open.retain(|&s| s != serial);
        }
        pages += 1;
        pos += plen;
        if pos > 64 * GB {
            break;
        }
    }
    if pages == 0 {
        None
    } else if open.is_empty() {
        clean(pos)
    } else {
        dmg(pos)
    }
}
