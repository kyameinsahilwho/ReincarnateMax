//! TIFF / EXIF IFD parsing (JPEG APP1, TIFF, TIFF-based camera RAW) and JPEG marker structure.
//! Every offset is bounds-checked; loops are capped so hostile input stays cheap.

use super::util::{be16, fmt_secs, norm_date};
use std::collections::{BTreeMap, HashSet};

#[derive(Default, Debug, Clone)]
pub struct ExifInfo {
    pub make: Option<String>,
    pub model: Option<String>,
    pub software: Option<String>,
    pub datetime: Option<String>,
    pub taken: Option<String>,
    pub orientation: Option<u32>,
    /// IFD0 ImageWidth / ImageLength.
    pub ifd0_dims: Option<(u32, u32)>,
    /// Exif PixelXDimension / PixelYDimension.
    pub pixel_dims: Option<(u32, u32)>,
    pub gps: Option<(f64, f64)>,
    pub artist: Option<String>,
    pub description: Option<String>,
    pub exposure: Option<String>,
    pub fnumber: Option<f64>,
    pub iso: Option<u32>,
    pub focal: Option<f64>,
    /// (offset, length) of JPEG streams inside the TIFF data (thumbnails, previews), relative to
    /// the TIFF header.
    pub jpegs: Vec<(usize, usize)>,
}

impl ExifInfo {
    pub fn camera(&self) -> Option<String> {
        let make = self.make.as_deref().map(str::trim).filter(|s| !s.is_empty());
        let model = self.model.as_deref().map(str::trim).filter(|s| !s.is_empty());
        match (make, model) {
            (Some(ma), Some(mo)) => {
                let first = ma.split_whitespace().next().unwrap_or(ma).to_ascii_lowercase();
                if mo.to_ascii_lowercase().starts_with(&first) {
                    Some(mo.to_string())
                } else {
                    let short = match first.as_str() {
                        "nikon" => "Nikon",
                        "olympus" => "Olympus",
                        "samsung" => "Samsung",
                        _ => ma,
                    };
                    Some(format!("{short} {mo}"))
                }
            }
            (Some(ma), None) => Some(ma.to_string()),
            (None, Some(mo)) => Some(mo.to_string()),
            _ => None,
        }
    }

    /// Put the standard meta keys.
    pub fn fill(&self, m: &mut BTreeMap<String, String>, dims_from_ifd0: bool) {
        use super::util::put;
        if let Some(c) = self.camera() {
            put(m, "camera", &c);
        }
        if let Some(t) = self.taken.as_ref().or(self.datetime.as_ref()) {
            put(m, "taken", t);
        }
        let dims = self.pixel_dims.or(if dims_from_ifd0 { self.ifd0_dims } else { None });
        if let Some((w, h)) = dims {
            if w > 0 && h > 0 {
                put(m, "width", &w.to_string());
                put(m, "height", &h.to_string());
            }
        }
        if let Some(o) = self.orientation {
            if (1..=8).contains(&o) {
                put(m, "orientation", &o.to_string());
            }
        }
        if let Some((la, lo)) = self.gps {
            put(m, "gps", &format!("{la:.6}, {lo:.6}"));
        }
        if let Some(s) = &self.software {
            put(m, "software", s);
        }
        if let Some(a) = &self.artist {
            put(m, "author", a);
        }
        if let Some(d) = &self.description {
            let d = d.trim();
            // Cameras often write placeholder descriptions.
            if !d.is_empty() && !d.eq_ignore_ascii_case("OLYMPUS DIGITAL CAMERA") && !d.starts_with("SAMSUNG") {
                put(m, "title", d);
            }
        }
        if let Some(e) = &self.exposure {
            put(m, "exposure", e);
        }
        if let Some(f) = self.fnumber {
            put(m, "fNumber", &format!("f/{}", fmt_secs(f).unwrap_or_default()));
        }
        if let Some(i) = self.iso {
            put(m, "iso", &i.to_string());
        }
        if let Some(f) = self.focal {
            put(m, "focalLength", &format!("{} mm", fmt_secs(f).unwrap_or_default()));
        }
    }
}

pub struct Tiff<'a> {
    pub d: &'a [u8],
    pub le: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Entry {
    pub tag: u16,
    pub typ: u16,
    pub count: u32,
    /// Absolute offset (in `d`) of the value bytes.
    pub at: usize,
}

fn type_size(t: u16) -> usize {
    match t {
        1 | 2 | 6 | 7 => 1,
        3 | 8 => 2,
        4 | 9 | 11 | 13 => 4,
        5 | 10 | 12 => 8,
        _ => 0,
    }
}

impl<'a> Tiff<'a> {
    /// Accepts "II"/"MM" with any magic (42 for TIFF, 0x55 for RW2, "RO"/"RS" for ORF).
    pub fn new(d: &'a [u8]) -> Option<Self> {
        if d.len() < 8 {
            return None;
        }
        let le = match &d[..2] {
            b"II" => true,
            b"MM" => false,
            _ => return None,
        };
        Some(Tiff { d, le })
    }
    pub fn u16(&self, o: usize) -> Option<u16> {
        let b = self.d.get(o..o + 2)?;
        Some(if self.le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) })
    }
    pub fn u32(&self, o: usize) -> Option<u32> {
        let b = self.d.get(o..o + 4)?;
        let a = [b[0], b[1], b[2], b[3]];
        Some(if self.le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) })
    }
    pub fn first_ifd(&self) -> Option<usize> {
        self.u32(4).map(|v| v as usize)
    }
    /// Entries of the IFD at `off` and the next IFD offset (0 = none).
    pub fn ifd(&self, off: usize) -> (Vec<Entry>, usize) {
        let Some(n) = self.u16(off) else { return (Vec::new(), 0) };
        let n = (n as usize).min(1000);
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let e = off + 2 + i * 12;
            let (Some(tag), Some(typ), Some(count)) = (self.u16(e), self.u16(e + 2), self.u32(e + 4)) else { break };
            let size = type_size(typ).saturating_mul(count as usize);
            let at = if size <= 4 { e + 8 } else { self.u32(e + 8).unwrap_or(u32::MAX) as usize };
            out.push(Entry { tag, typ, count, at });
        }
        let next = self.u32(off + 2 + n * 12).unwrap_or(0) as usize;
        (out, next)
    }
    pub fn uint(&self, e: &Entry, i: usize) -> Option<u32> {
        if i >= e.count as usize {
            return None;
        }
        match e.typ {
            3 | 8 => self.u16(e.at + i * 2).map(|v| v as u32),
            4 | 9 | 13 => self.u32(e.at + i * 4),
            1 | 7 => self.d.get(e.at + i).map(|&v| v as u32),
            _ => None,
        }
    }
    pub fn rational(&self, e: &Entry, i: usize) -> Option<f64> {
        if !matches!(e.typ, 5 | 10) || i >= e.count as usize {
            return None;
        }
        let n = self.u32(e.at + i * 8)?;
        let d = self.u32(e.at + i * 8 + 4)?;
        if d == 0 {
            return None;
        }
        if e.typ == 10 {
            Some(n as i32 as f64 / d as i32 as f64)
        } else {
            Some(n as f64 / d as f64)
        }
    }
    pub fn ascii(&self, e: &Entry) -> Option<String> {
        if !matches!(e.typ, 2 | 7 | 1) {
            return None;
        }
        let n = (e.count as usize).min(512);
        let b = self.d.get(e.at..e.at.checked_add(n)?)?;
        let b = &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())];
        let s = super::util::utf8_or_1252(b).trim().to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
}

/// Parse a TIFF structure (the bytes after "Exif\0\0", a .tif, or a TIFF-based RAW).
pub fn parse_tiff(d: &[u8]) -> Option<ExifInfo> {
    let t = Tiff::new(d)?;
    let mut info = ExifInfo::default();
    let mut seen = HashSet::new();
    // (offset, kind): 0 = main chain IFD, 1 = sub IFD (no chain), 2 = Exif, 3 = GPS
    let mut queue: Vec<(usize, u8, bool)> = vec![(t.first_ifd()?, 0, true)];
    let mut visited = 0;
    while let Some((off, kind, is_ifd0)) = queue.pop() {
        if off < 8 || off >= d.len() || !seen.insert(off) || visited > 32 {
            continue;
        }
        visited += 1;
        let (entries, next) = t.ifd(off);
        let get = |tag: u16| entries.iter().find(|e| e.tag == tag);
        match kind {
            0 | 1 => {
                if is_ifd0 {
                    for (tag, slot) in [(0x010F, &mut info.make), (0x0110, &mut info.model), (0x0131, &mut info.software), (0x013B, &mut info.artist)] {
                        if slot.is_none() {
                            *slot = get(tag).and_then(|e| t.ascii(e));
                        }
                    }
                    if info.description.is_none() {
                        info.description = get(0x010E).and_then(|e| t.ascii(e));
                    }
                    if info.datetime.is_none() {
                        info.datetime = get(0x0132).and_then(|e| t.ascii(e)).and_then(|s| norm_date(&s));
                    }
                    if info.orientation.is_none() {
                        info.orientation = get(0x0112).and_then(|e| t.uint(e, 0));
                    }
                    if let (Some(w), Some(h)) = (get(0x0100).and_then(|e| t.uint(e, 0)), get(0x0101).and_then(|e| t.uint(e, 0))) {
                        info.ifd0_dims = Some((w, h));
                    }
                }
                // Embedded JPEGs: thumbnail / preview pointers, JPEG-compressed strips, JpgFromRaw.
                if let (Some(o), Some(l)) = (get(0x0201).and_then(|e| t.uint(e, 0)), get(0x0202).and_then(|e| t.uint(e, 0))) {
                    info.jpegs.push((o as usize, l as usize));
                }
                let comp = get(0x0103).and_then(|e| t.uint(e, 0));
                if matches!(comp, Some(6) | Some(7)) {
                    if let (Some(so), Some(sc)) = (get(0x0111), get(0x0117)) {
                        if so.count == 1 {
                            if let (Some(o), Some(l)) = (t.uint(so, 0), t.uint(sc, 0)) {
                                info.jpegs.push((o as usize, l as usize));
                            }
                        }
                    }
                }
                if let Some(e) = get(0x002E) {
                    if matches!(e.typ, 7 | 1) {
                        info.jpegs.push((e.at, e.count as usize));
                    }
                }
                if let Some(e) = get(0x8769).and_then(|e| t.uint(e, 0)) {
                    queue.push((e as usize, 2, false));
                }
                if let Some(e) = get(0x8825).and_then(|e| t.uint(e, 0)) {
                    queue.push((e as usize, 3, false));
                }
                if let Some(e) = get(0x014A) {
                    for i in 0..(e.count as usize).min(8) {
                        if let Some(o) = t.uint(e, i) {
                            queue.push((o as usize, 1, false));
                        }
                    }
                }
                if kind == 0 && next != 0 {
                    queue.push((next, 0, false));
                }
            }
            2 => {
                if let Some(s) = get(0x9003).and_then(|e| t.ascii(e)).and_then(|s| norm_date(&s)) {
                    info.taken = Some(s);
                } else if info.taken.is_none() {
                    info.taken = get(0x9004).and_then(|e| t.ascii(e)).and_then(|s| norm_date(&s));
                }
                if let (Some(w), Some(h)) = (get(0xA002).and_then(|e| t.uint(e, 0)), get(0xA003).and_then(|e| t.uint(e, 0))) {
                    if w > 0 && h > 0 {
                        info.pixel_dims = Some((w, h));
                    }
                }
                if let Some(v) = get(0x829A).and_then(|e| t.rational(e, 0)) {
                    if v > 0.0 && v < 3600.0 {
                        info.exposure = Some(if v < 1.0 { format!("1/{} s", (1.0 / v).round()) } else { format!("{} s", fmt_secs(v).unwrap_or_default()) });
                    }
                }
                info.fnumber = get(0x829D).and_then(|e| t.rational(e, 0)).filter(|v| *v > 0.0 && *v < 100.0);
                info.iso = get(0x8827).and_then(|e| t.uint(e, 0)).filter(|v| *v > 0);
                info.focal = get(0x920A).and_then(|e| t.rational(e, 0)).filter(|v| *v > 0.0 && *v < 5000.0);
            }
            3 => {
                let coord = |tag: u16| -> Option<f64> {
                    let e = get(tag)?;
                    let v = t.rational(e, 0)? + t.rational(e, 1).unwrap_or(0.0) / 60.0 + t.rational(e, 2).unwrap_or(0.0) / 3600.0;
                    Some(v)
                };
                let reff = |tag: u16| get(tag).and_then(|e| t.d.get(e.at).copied());
                if let (Some(mut la), Some(mut lo)) = (coord(2), coord(4)) {
                    if reff(1) == Some(b'S') {
                        la = -la;
                    }
                    if reff(3) == Some(b'W') {
                        lo = -lo;
                    }
                    if la.abs() <= 90.0 && lo.abs() <= 180.0 && (la != 0.0 || lo != 0.0) {
                        info.gps = Some((la, lo));
                    }
                }
            }
            _ => {}
        }
    }
    Some(info)
}

// ------------------------------------------------------------------------------------ JPEG

pub fn is_sof(m: u8) -> bool {
    matches!(m, 0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF)
}

#[derive(Default, Debug, Clone)]
pub struct JpegInfo {
    pub sof: Option<u8>,
    pub width: u32,
    pub height: u32,
    pub components: u8,
    /// Byte offset of the APP1 Exif TIFF header.
    pub exif_at: Option<(usize, usize)>,
    /// Offset of the first entropy-coded byte (after the first SOS header).
    pub scan_start: Option<usize>,
    /// Offset just past the EOI marker.
    pub eoi_end: Option<usize>,
    /// First position where the entropy data holds a marker that can't be there (garbage).
    pub first_bad: Option<usize>,
    /// Offset just past the last RSTn marker or the last complete inter-scan segment before the end
    /// or the first bad byte (a safe cut point).
    pub last_good_cut: Option<usize>,
}

impl JpegInfo {
    pub fn progressive(&self) -> bool {
        matches!(self.sof, Some(0xC2) | Some(0xC6) | Some(0xCA) | Some(0xCE))
    }
}

/// Walk a JPEG's markers and entropy data. Bounded by the data length.
pub fn jpeg_info(d: &[u8]) -> Option<JpegInfo> {
    if d.len() < 4 || d[0] != 0xFF || d[1] != 0xD8 {
        return None;
    }
    let mut info = JpegInfo::default();
    let mut i = 2;
    // Header segments up to the first SOS.
    loop {
        while i < d.len() && d[i] == 0xFF && d.get(i + 1) == Some(&0xFF) {
            i += 1;
        }
        if i + 4 > d.len() || d[i] != 0xFF {
            if i < d.len() && d[i] != 0xFF {
                info.first_bad = Some(i);
            }
            return Some(info);
        }
        let m = d[i + 1];
        if m == 0xD9 {
            info.eoi_end = Some(i + 2);
            return Some(info);
        }
        if (0xD0..=0xD7).contains(&m) || m == 0x01 {
            i += 2;
            continue;
        }
        let len = be16(d, i + 2)? as usize;
        if len < 2 {
            info.first_bad = Some(i);
            return Some(info);
        }
        let seg = i + 4;
        if is_sof(m) && info.sof.is_none() && seg + 6 <= d.len() {
            info.sof = Some(m);
            info.height = be16(d, seg + 1).unwrap_or(0) as u32;
            info.width = be16(d, seg + 3).unwrap_or(0) as u32;
            info.components = d[seg + 5];
        }
        if m == 0xE1 && info.exif_at.is_none() && d.len() >= seg + 6 && &d[seg..seg + 6] == b"Exif\0\0" {
            let end = (i + 2 + len).min(d.len());
            if end > seg + 6 {
                info.exif_at = Some((seg + 6, end - seg - 6));
            }
        }
        i += 2 + len;
        if m == 0xDA {
            break;
        }
    }
    if i > d.len() {
        return Some(info);
    }
    info.scan_start = Some(i);
    info.last_good_cut = Some(i);
    // Entropy-coded data and the segments between progressive scans.
    while i + 1 < d.len() {
        if d[i] != 0xFF {
            i += 1;
            continue;
        }
        let m = d[i + 1];
        match m {
            0x00 | 0xFF => i += if m == 0xFF { 1 } else { 2 },
            0xD0..=0xD7 => {
                i += 2;
                info.last_good_cut = Some(i);
            }
            0xD9 => {
                info.eoi_end = Some(i + 2);
                return Some(info);
            }
            0xC4 | 0xDA | 0xDB | 0xDD | 0xCC | 0xFE | 0xE0..=0xEF => {
                info.last_good_cut = Some(i);
                let Some(len) = be16(d, i + 2) else { break };
                if len < 2 {
                    info.first_bad = Some(i);
                    return Some(info);
                }
                i += 2 + len as usize;
                if i <= d.len() && m == 0xDA {
                    info.last_good_cut = Some(i);
                }
            }
            _ => {
                info.first_bad = Some(i);
                return Some(info);
            }
        }
    }
    Some(info)
}

/// EXIF from a JPEG (APP1).
pub fn jpeg_exif(d: &[u8]) -> Option<ExifInfo> {
    let j = jpeg_info(d)?;
    let (o, l) = j.exif_at?;
    parse_tiff(&d[o..o + l])
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A minimal big-endian EXIF TIFF block: Make, Model, Orientation, ExifIFD{DateTimeOriginal,
    /// PixelX, PixelY}, GPS{N 48°51'30", E 2°17'40"}.
    pub fn sample_tiff() -> Vec<u8> {
        let mut d = b"MM\0*\0\0\0\x08".to_vec();
        // IFD0 at 8 with 5 entries: 2 + 5*12 + 4 = 66 -> data from 74.
        let data0 = 8 + 2 + 5 * 12 + 4;
        let make = b"Canon\0";
        let model = b"Canon EOS R6\0";
        let mut heap: Vec<u8> = Vec::new();
        let make_at = data0 + heap.len();
        heap.extend_from_slice(make);
        let model_at = data0 + heap.len();
        heap.extend_from_slice(model);
        // Exif IFD position after the heap.
        let exif_at = data0 + heap.len();
        let exif_len = 2 + 3 * 12 + 4;
        let date_at = exif_at + exif_len;
        let gps_at = date_at + 20;
        let gps_len = 2 + 4 * 12 + 4;
        let rat_at = gps_at + gps_len;
        let ent = |d: &mut Vec<u8>, tag: u16, typ: u16, count: u32, val: u32| {
            d.extend_from_slice(&tag.to_be_bytes());
            d.extend_from_slice(&typ.to_be_bytes());
            d.extend_from_slice(&count.to_be_bytes());
            d.extend_from_slice(&val.to_be_bytes());
        };
        d.extend_from_slice(&5u16.to_be_bytes());
        ent(&mut d, 0x010F, 2, make.len() as u32, make_at as u32);
        ent(&mut d, 0x0110, 2, model.len() as u32, model_at as u32);
        ent(&mut d, 0x0112, 3, 1, 6 << 16);
        ent(&mut d, 0x8769, 4, 1, exif_at as u32);
        ent(&mut d, 0x8825, 4, 1, gps_at as u32);
        d.extend_from_slice(&0u32.to_be_bytes());
        d.extend_from_slice(&heap);
        assert_eq!(d.len(), exif_at);
        d.extend_from_slice(&3u16.to_be_bytes());
        ent(&mut d, 0x9003, 2, 20, date_at as u32);
        ent(&mut d, 0xA002, 4, 1, 6000);
        ent(&mut d, 0xA003, 4, 1, 4000);
        d.extend_from_slice(&0u32.to_be_bytes());
        d.extend_from_slice(b"2024:05:01 14:22:10\0");
        assert_eq!(d.len(), gps_at);
        d.extend_from_slice(&4u16.to_be_bytes());
        ent(&mut d, 1, 2, 2, u32::from_be_bytes(*b"N\0\0\0"));
        ent(&mut d, 2, 5, 3, rat_at as u32);
        ent(&mut d, 3, 2, 2, u32::from_be_bytes(*b"E\0\0\0"));
        ent(&mut d, 4, 5, 3, (rat_at + 24) as u32);
        d.extend_from_slice(&0u32.to_be_bytes());
        for (n, den) in [(48u32, 1u32), (51, 1), (30, 1), (2, 1), (17, 1), (40, 1)] {
            d.extend_from_slice(&n.to_be_bytes());
            d.extend_from_slice(&den.to_be_bytes());
        }
        d
    }

    #[test]
    fn parses_exif_block() {
        let e = parse_tiff(&sample_tiff()).unwrap();
        assert_eq!(e.camera().as_deref(), Some("Canon EOS R6"));
        assert_eq!(e.taken.as_deref(), Some("2024-05-01 14:22:10"));
        assert_eq!(e.pixel_dims, Some((6000, 4000)));
        assert_eq!(e.orientation, Some(6));
        let (la, lo) = e.gps.unwrap();
        assert!((la - 48.858333).abs() < 1e-4 && (lo - 2.294444).abs() < 1e-4);
    }

    #[test]
    fn hostile_tiff_is_bounded() {
        // IFD pointing at itself with a huge count.
        let mut d = b"II*\0\x08\0\0\0".to_vec();
        d.extend_from_slice(&[0xFF, 0xFF]);
        d.extend_from_slice(&[0u8; 64]);
        assert!(parse_tiff(&d).is_some());
        assert!(parse_tiff(b"II").is_none());
    }
}
