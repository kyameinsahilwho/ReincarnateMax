//! ISO base media (MP4/MOV/M4A/HEIC/CR3) box walking: top level through random reads (so a 4 GB
//! video's `moov` can be found without reading `mdat`), children over in-memory slices.

use super::util::{be16, be32, be64, fmt_secs, fmt_unix, put, RandomRead};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BoxHdr {
    pub typ: [u8; 4],
    pub start: u64,
    /// Header length (8 or 16).
    pub hdr: u64,
    /// Total size as declared (size 0 = "to the end", resolved to the end of the container).
    pub size: u64,
    pub declared_zero: bool,
    pub large: bool,
}

impl BoxHdr {
    pub fn end(&self) -> u64 {
        self.start.saturating_add(self.size)
    }
    #[allow(dead_code)]
    pub fn name(&self) -> String {
        self.typ.iter().map(|&c| if c.is_ascii_graphic() || c == b' ' { c as char } else { '?' }).collect()
    }
}

/// Plausible box type: four printable ASCII characters (QuickTime allows ©).
pub fn plausible_type(t: &[u8]) -> bool {
    t.len() == 4 && t.iter().all(|&c| c.is_ascii_alphanumeric() || c == b' ' || c == 0xA9 || c == b'-' || c == b'_')
}

/// Read one box header at `pos` inside a container ending at `end`.
pub fn read_box(rr: &dyn RandomRead, pos: u64, end: u64) -> Option<BoxHdr> {
    if pos + 8 > end {
        return None;
    }
    let mut h = [0u8; 16];
    let n = rr.read_at(pos, &mut h);
    if n < 8 {
        return None;
    }
    let size32 = be32(&h, 0)? as u64;
    let mut typ = [0u8; 4];
    typ.copy_from_slice(&h[4..8]);
    let (size, hdr, large, zero) = match size32 {
        0 => (end - pos, 8, false, true),
        1 => {
            if n < 16 {
                return None;
            }
            (be64(&h, 8)?, 16, true, false)
        }
        s => (s, 8, false, false),
    };
    if size < hdr {
        return None;
    }
    Some(BoxHdr { typ, start: pos, hdr, size, declared_zero: zero, large })
}

/// Top-level boxes. Stops at the first implausible header; the last box may extend beyond
/// `rr.size()` (truncated file). At most 10 000 boxes.
pub fn top_level(rr: &dyn RandomRead) -> (Vec<BoxHdr>, bool) {
    let len = rr.size();
    let mut out = Vec::new();
    let mut pos = 0u64;
    let mut clean = true;
    while pos < len && out.len() < 10_000 {
        match read_box(rr, pos, len) {
            Some(b) if plausible_type(&b.typ) => {
                out.push(b);
                pos = b.end();
            }
            _ => {
                clean = false;
                break;
            }
        }
    }
    (out, clean)
}

/// Child boxes of an in-memory container's content: (type, content slice).
pub fn children(d: &[u8]) -> Vec<([u8; 4], &[u8])> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + 8 <= d.len() && out.len() < 4096 {
        let Some(b) = read_box(&d, p as u64, d.len() as u64) else { break };
        if !plausible_type(&b.typ) {
            break;
        }
        let s = (p as u64 + b.hdr) as usize;
        let e = (b.end().min(d.len() as u64)) as usize;
        out.push((b.typ, &d[s.min(e)..e]));
        p = e;
        if b.end() > d.len() as u64 {
            break;
        }
    }
    out
}

pub fn child<'a>(d: &'a [u8], t: &[u8; 4]) -> Option<&'a [u8]> {
    children(d).into_iter().find(|(ty, _)| ty == t).map(|(_, c)| c)
}

/// Seconds since 1904-01-01 (QuickTime epoch) -> text.
fn mac_time(secs: u64) -> Option<String> {
    fmt_unix(secs as i64 - 2_082_844_800)
}

/// Brand from an `ftyp` content.
pub fn brand(ftyp: &[u8]) -> Option<String> {
    let b = ftyp.get(..4)?;
    Some(String::from_utf8_lossy(b).trim().to_string())
}

#[derive(Default, Debug)]
pub struct MoovInfo {
    pub created: Option<String>,
    pub duration: Option<f64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub has_video: bool,
    pub has_audio: bool,
    pub title: Option<String>,
    pub artist: Option<String>,
    pub album: Option<String>,
    pub year: Option<String>,
    pub software: Option<String>,
}

/// Parse a `moov` box content.
pub fn moov_info(moov: &[u8]) -> MoovInfo {
    let mut i = MoovInfo::default();
    for (t, c) in children(moov) {
        match &t {
            b"mvhd" => {
                let v = c.first().copied().unwrap_or(0);
                let (ct, ts, dur) = if v == 1 {
                    (be64(c, 4), be32(c, 20).map(|x| x as u64), be64(c, 24))
                } else {
                    (be32(c, 4).map(|x| x as u64), be32(c, 12).map(|x| x as u64), be32(c, 16).map(|x| x as u64))
                };
                if let Some(ct) = ct.filter(|&x| x > 0) {
                    i.created = mac_time(ct);
                }
                if let (Some(ts), Some(d)) = (ts, dur) {
                    if ts > 0 && d > 0 && d != u32::MAX as u64 && d != u64::MAX {
                        i.duration = Some(d as f64 / ts as f64);
                    }
                }
            }
            b"trak" => {
                let mut handler = [0u8; 4];
                if let Some(h) = child(c, b"mdia").and_then(|m| child(m, b"hdlr")) {
                    if h.len() >= 12 {
                        handler.copy_from_slice(&h[8..12]);
                    }
                }
                match &handler {
                    b"vide" => i.has_video = true,
                    b"soun" => i.has_audio = true,
                    _ => {}
                }
                if let Some(tk) = child(c, b"tkhd") {
                    let off = if tk.first() == Some(&1) { 88 } else { 76 };
                    let w = be32(tk, off).map(|x| x >> 16).unwrap_or(0);
                    let h = be32(tk, off + 4).map(|x| x >> 16).unwrap_or(0);
                    if w > 0 && h > 0 && i.width.is_none() && &handler != b"soun" {
                        i.width = Some(w);
                        i.height = Some(h);
                    }
                }
            }
            b"udta" => udta(c, &mut i),
            b"meta" => meta_box(c, &mut i),
            _ => {}
        }
    }
    i
}

fn udta(c: &[u8], i: &mut MoovInfo) {
    for (t, v) in children(c) {
        match &t {
            b"meta" => meta_box(v, i),
            // QuickTime user data text: size(2) language(2) text.
            [0xA9, a, b, cc] => {
                let len = be16(v, 0).unwrap_or(0) as usize;
                let txt = v.get(4..4 + len).map(|s| String::from_utf8_lossy(s).into_owned());
                set_tag(i, &[*a, *b, *cc], txt);
            }
            _ => {}
        }
    }
}

fn meta_box(c: &[u8], i: &mut MoovInfo) {
    // ISO `meta` is a full box (4 bytes version/flags); QuickTime's isn't.
    let body = if c.get(4..8) == Some(b"hdlr") { c } else { c.get(4..).unwrap_or(&[]) };
    if let Some(ilst) = child(body, b"ilst") {
        for (t, item) in children(ilst) {
            let txt = child(item, b"data").and_then(|d| d.get(8..)).map(|s| String::from_utf8_lossy(s).into_owned());
            match &t {
                [0xA9, a, b, cc] => set_tag(i, &[*a, *b, *cc], txt),
                b"aART" if i.artist.is_none() => i.artist = txt,
                _ => {}
            }
        }
    }
}

fn set_tag(i: &mut MoovInfo, t: &[u8; 3], v: Option<String>) {
    let Some(v) = v.map(|s| s.trim_matches(char::from(0)).trim().to_string()).filter(|s| !s.is_empty()) else { return };
    let slot = match t {
        b"nam" => &mut i.title,
        b"ART" => &mut i.artist,
        b"alb" => &mut i.album,
        b"day" => &mut i.year,
        b"too" | b"swr" => &mut i.software,
        _ => return,
    };
    if slot.is_none() {
        *slot = Some(v);
    }
}

impl MoovInfo {
    pub fn fill(&self, m: &mut BTreeMap<String, String>) {
        if let Some(t) = &self.title {
            put(m, "title", t);
        }
        if let Some(a) = &self.artist {
            put(m, "artist", a);
        }
        if let Some(a) = &self.album {
            put(m, "album", a);
        }
        if let Some(y) = &self.year {
            put(m, "year", y.get(..4).unwrap_or(y));
        }
        if let Some(c) = &self.created {
            put(m, "created", c);
        }
        if let Some(d) = self.duration.and_then(fmt_secs) {
            put(m, "duration", &d);
        }
        if let (Some(w), Some(h)) = (self.width, self.height) {
            put(m, "width", &w.to_string());
            put(m, "height", &h.to_string());
        }
        if let Some(s) = &self.software {
            put(m, "software", s);
        }
    }
}

/// Locate `moov` (content range) through random reads; None if absent. Caps the read at 64 MiB.
pub fn find_moov(rr: &dyn RandomRead) -> Option<Vec<u8>> {
    let (boxes, _) = top_level(rr);
    let b = boxes.iter().find(|b| &b.typ == b"moov")?;
    let len = (b.size - b.hdr).min(64 << 20) as usize;
    Some(rr.read_vec(b.start + b.hdr, len))
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn bx(t: &[u8; 4], content: &[u8]) -> Vec<u8> {
        let mut v = ((content.len() + 8) as u32).to_be_bytes().to_vec();
        v.extend_from_slice(t);
        v.extend_from_slice(content);
        v
    }

    /// ftyp + moov(mvhd 10 s, trak(tkhd 1920x1080, mdia/hdlr vide), udta/meta/ilst ©nam) + mdat.
    pub fn sample_mp4(mdat_len: usize) -> Vec<u8> {
        let mut mvhd = vec![0u8; 100];
        mvhd[4..8].copy_from_slice(&(1_714_573_330u32.wrapping_add(2_082_844_800)).to_be_bytes());
        mvhd[12..16].copy_from_slice(&1000u32.to_be_bytes());
        mvhd[16..20].copy_from_slice(&10_000u32.to_be_bytes());
        let mut tkhd = vec![0u8; 84];
        tkhd[76..80].copy_from_slice(&(1920u32 << 16).to_be_bytes());
        tkhd[80..84].copy_from_slice(&(1080u32 << 16).to_be_bytes());
        let mut hdlr = vec![0u8; 24];
        hdlr[8..12].copy_from_slice(b"vide");
        let trak = bx(b"trak", &[bx(b"tkhd", &tkhd), bx(b"mdia", &bx(b"hdlr", &hdlr))].concat());
        let mut data = vec![0, 0, 0, 1, 0, 0, 0, 0];
        data.extend_from_slice(b"Holiday clip");
        let ilst = bx(b"ilst", &bx(&[0xA9, b'n', b'a', b'm'], &bx(b"data", &data)));
        let mut meta = vec![0u8; 4];
        meta.extend_from_slice(&ilst);
        let udta = bx(b"udta", &bx(b"meta", &meta));
        let moov = bx(b"moov", &[bx(b"mvhd", &mvhd), trak, udta].concat());
        [bx(b"ftyp", b"isom\0\0\x02\0isomiso2mp41"), moov, bx(b"mdat", &vec![0x55u8; mdat_len])].concat()
    }

    #[test]
    fn walks_mp4() {
        let v = sample_mp4(1000);
        let (top, clean) = top_level(&v.as_slice());
        assert!(clean);
        assert_eq!(top.iter().map(|b| b.name()).collect::<Vec<_>>(), vec!["ftyp", "moov", "mdat"]);
        let moov = find_moov(&v.as_slice()).unwrap();
        let i = moov_info(&moov);
        assert_eq!(i.duration, Some(10.0));
        assert_eq!((i.width, i.height), (Some(1920), Some(1080)));
        assert_eq!(i.title.as_deref(), Some("Holiday clip"));
        assert_eq!(i.created.as_deref(), Some("2024-05-01 14:22:10"));
        assert!(i.has_video);
    }
}
