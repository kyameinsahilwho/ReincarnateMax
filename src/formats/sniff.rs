//! Byte-level validators shared by `detect` and the carver's per-sector dispatch. Every function
//! takes a slice that may be short and never panics.

#[inline]
pub(crate) fn le16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
#[inline]
pub(crate) fn le32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
#[inline]
pub(crate) fn le64(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}
#[inline]
pub(crate) fn be16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
#[inline]
pub(crate) fn be32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
#[inline]
pub(crate) fn at(b: &[u8], o: usize, pat: &[u8]) -> bool {
    b.get(o..o + pat.len()) == Some(pat)
}

/// First occurrence of `pat` in `hay`.
pub(crate) fn find(hay: &[u8], pat: &[u8]) -> Option<usize> {
    if pat.is_empty() || hay.len() < pat.len() {
        return None;
    }
    let first = pat[0];
    let last = hay.len() - pat.len();
    let mut i = 0;
    while i <= last {
        match hay[i..=last].iter().position(|&b| b == first) {
            None => return None,
            Some(p) => {
                i += p;
                if &hay[i..i + pat.len()] == pat {
                    return Some(i);
                }
                i += 1;
            }
        }
    }
    None
}

// ------------------------------------------------------------------------------------- MPEG audio

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Mp3Hdr {
    /// 3 = MPEG-1, 2 = MPEG-2, 0 = MPEG-2.5
    pub ver: u8,
    /// 1..=3
    pub layer: u8,
    pub sample_rate: u32,
    pub len: usize,
}

/// An MPEG-1/2/2.5 audio frame header (layer I-III) and its frame length.
pub(crate) fn mp3_header(h: &[u8]) -> Option<Mp3Hdr> {
    if h.len() < 4 || h[0] != 0xFF || h[1] & 0xE0 != 0xE0 {
        return None;
    }
    let ver = (h[1] >> 3) & 3;
    let lb = (h[1] >> 1) & 3;
    if ver == 1 || lb == 0 {
        return None;
    }
    let layer = 4 - lb;
    let bri = (h[2] >> 4) as usize;
    let sri = ((h[2] >> 2) & 3) as usize;
    if bri == 0 || bri == 15 || sri == 3 || h[3] & 3 == 2 {
        return None;
    }
    const V1: [[u32; 15]; 3] = [
        [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448],
        [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384],
        [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320],
    ];
    const V2: [[u32; 15]; 2] = [[0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256], [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160]];
    let br = if ver == 3 { V1[layer as usize - 1][bri] } else { V2[if layer == 1 { 0 } else { 1 }][bri] } * 1000;
    let sr = [[11025, 12000, 8000], [0, 0, 0], [22050, 24000, 16000], [44100, 48000, 32000]][ver as usize][sri];
    let pad = ((h[2] >> 1) & 1) as u32;
    let len = match layer {
        1 => (12 * br / sr + pad) * 4,
        2 => 144 * br / sr + pad,
        _ => {
            if ver == 3 {
                144 * br / sr + pad
            } else {
                72 * br / sr + pad
            }
        }
    } as usize;
    if len < 21 {
        return None;
    }
    Some(Mp3Hdr { ver, layer, sample_rate: sr, len })
}

/// `n` consecutive MPEG audio frames with the same version, layer and sample rate start at 0.
pub(crate) fn mp3_frames(b: &[u8], n: usize) -> bool {
    let Some(first) = mp3_header(b) else { return false };
    let mut pos = first.len;
    for _ in 1..n {
        match b.get(pos..).and_then(mp3_header) {
            Some(h) if h.ver == first.ver && h.layer == first.layer && h.sample_rate == first.sample_rate => pos += h.len,
            _ => return false,
        }
    }
    true
}

/// ID3v2 tag header: total tag length (header + body + footer).
pub(crate) fn id3_len(h: &[u8]) -> Option<u64> {
    if h.len() < 10 || !h.starts_with(b"ID3") || !(2..=4).contains(&h[3]) || h[4] == 0xFF {
        return None;
    }
    if h[6..10].iter().any(|&b| b & 0x80 != 0) {
        return None;
    }
    let flags_ok = match h[3] {
        2 => h[5] & 0x3F == 0,
        3 => h[5] & 0x1F == 0,
        _ => h[5] & 0x0F == 0,
    };
    if !flags_ok {
        return None;
    }
    let size = h[6..10].iter().fold(0u64, |a, &b| (a << 7) | b as u64);
    Some(10 + size + if h[3] == 4 && h[5] & 0x10 != 0 { 10 } else { 0 })
}

/// AAC ADTS frame header: frame length (incl. header) and sample-rate index.
pub(crate) fn adts_header(h: &[u8]) -> Option<(usize, u8)> {
    if h.len() < 7 || h[0] != 0xFF || h[1] & 0xF6 != 0xF0 {
        return None;
    }
    let sri = (h[2] >> 2) & 0xF;
    if sri > 12 {
        return None;
    }
    let len = (((h[3] & 3) as usize) << 11) | ((h[4] as usize) << 3) | ((h[5] >> 5) as usize);
    let hl = if h[1] & 1 == 0 { 9 } else { 7 };
    if len <= hl {
        return None;
    }
    Some((len, sri))
}

pub(crate) fn adts_frames(b: &[u8], n: usize) -> bool {
    let Some((l0, sr0)) = adts_header(b) else { return false };
    let mut pos = l0;
    for _ in 1..n {
        match b.get(pos..).and_then(adts_header) {
            Some((l, sr)) if sr == sr0 => pos += l,
            _ => return false,
        }
    }
    true
}

// ------------------------------------------------------------------------------- small checks

pub(crate) fn bmp_ok(h: &[u8]) -> bool {
    if !h.starts_with(b"BM") {
        return false;
    }
    let (Some(size), Some(res), Some(off), Some(dib)) = (le32(h, 2), le32(h, 6), le32(h, 10), le32(h, 14)) else { return false };
    if res != 0 || !matches!(dib, 12 | 40 | 52 | 56 | 64 | 108 | 124) || size < 26 || off < 26 || off > size || size > 1 << 30 {
        return false;
    }
    if dib >= 40 {
        let (Some(w), Some(hh), Some(planes), Some(bpp)) = (le32(h, 18), le32(h, 22), le16(h, 26), le16(h, 28)) else { return false };
        let w = w as i32;
        let hh = hh as i32;
        if w <= 0 || w > 1 << 16 || hh == 0 || hh.unsigned_abs() > 1 << 16 || planes != 1 || !matches!(bpp, 1 | 2 | 4 | 8 | 16 | 24 | 32 | 64) {
            return false;
        }
    }
    true
}

pub(crate) fn ico_ok(h: &[u8]) -> bool {
    if !(h.starts_with(&[0, 0, 1, 0]) || h.starts_with(&[0, 0, 2, 0])) {
        return false;
    }
    let n = le16(h, 4).unwrap_or(0) as usize;
    if n == 0 || n > 64 {
        return false;
    }
    let first = 6 + 16 * n as u32;
    for i in 0..n.min(8) {
        let e = 6 + 16 * i;
        let (Some(res), Some(planes), Some(bpp), Some(size), Some(off)) = (h.get(e + 3), le16(h, e + 4), le16(h, e + 6), le32(h, e + 8), le32(h, e + 12))
        else {
            return i > 0;
        };
        if *res != 0 && *res != 0xFF {
            return false;
        }
        if h[2] == 1 && (planes > 1 || !matches!(bpp, 0 | 1 | 2 | 4 | 8 | 16 | 24 | 32)) {
            return false;
        }
        if size < 40 || size > 4 << 20 || off < first || off > 16 << 20 {
            return false;
        }
        if i == 0 && off != first {
            return false;
        }
    }
    true
}

pub(crate) fn tar_ok(h: &[u8]) -> bool {
    if h.len() < 512 || !(at(h, 257, b"ustar\0") || at(h, 257, b"ustar ")) {
        return false;
    }
    let stored = h[148..156].iter().take_while(|&&c| c != 0 && c != b' ').try_fold(0u32, |a, &c| if (b'0'..=b'7').contains(&c) { Some(a * 8 + (c - b'0') as u32) } else { None });
    let Some(stored) = stored else { return false };
    let sum: u32 = h[..512].iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { 32 } else { b as u32 }).sum();
    sum == stored && h[0] != 0
}

pub(crate) fn pe_ok(h: &[u8]) -> Option<bool> {
    if !h.starts_with(b"MZ") {
        return None;
    }
    let e = le32(h, 0x3C)? as usize;
    if !(0x40..0x10000).contains(&e) {
        return None;
    }
    if !at(h, e, b"PE\0\0") {
        return None;
    }
    let nsec = le16(h, e + 6)?;
    let magic = le16(h, e + 24)?;
    if nsec == 0 || nsec > 96 || !(magic == 0x10B || magic == 0x20B) {
        return None;
    }
    Some(le16(h, e + 22)? & 0x2000 != 0)
}

pub(crate) fn ts_ok(h: &[u8], first: usize, pkt: usize, n: usize) -> bool {
    (0..n).all(|i| h.get(first + i * pkt) == Some(&0x47)) && h.get(first + 1).is_some_and(|b| b & 0x80 == 0)
}

pub(crate) fn mpeg_ps_ok(h: &[u8]) -> bool {
    h.starts_with(&[0, 0, 1, 0xBA]) && h.len() > 4 && (h[4] & 0xC4 == 0x44 || h[4] & 0xF1 == 0x21)
}

pub(crate) fn sqlite_ok(h: &[u8]) -> bool {
    if !h.starts_with(b"SQLite format 3\0") || h.len() < 100 {
        return false;
    }
    let ps = be16(h, 16).unwrap_or(0) as u32;
    let ps = if ps == 1 { 65536 } else { ps };
    ps >= 512 && ps.is_power_of_two() && (1..=2).contains(&h[18]) && (1..=2).contains(&h[19]) && h[21] == 64 && h[22] == 32 && h[23] == 32
}

pub(crate) const OLE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
pub(crate) const ASF_HEADER: [u8; 16] = [0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C];
pub(crate) const ASF_DATA: [u8; 16] = [0x36, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C];
pub(crate) const ASF_FILE_PROPS: [u8; 16] = [0xA1, 0xDC, 0xAB, 0x8C, 0x47, 0xA9, 0xCF, 0x11, 0x8E, 0xE4, 0x00, 0xC0, 0x0C, 0x20, 0x53, 0x65];
pub(crate) const ASF_SIMPLE_INDEX: [u8; 16] = [0x90, 0x08, 0x00, 0x33, 0xB1, 0xE5, 0xCF, 0x11, 0x89, 0xF4, 0x00, 0xA0, 0xC9, 0x03, 0x49, 0xCB];
pub(crate) const ASF_INDEX: [u8; 16] = [0xD3, 0x29, 0xE2, 0xD6, 0xDA, 0x35, 0xD1, 0x11, 0x90, 0x34, 0x00, 0xA0, 0xC9, 0x03, 0x49, 0xBE];
const ASF_AUDIO: [u8; 16] = [0x40, 0x9E, 0x69, 0xF8, 0x4D, 0x5B, 0xCF, 0x11, 0xA8, 0xFD, 0x00, 0x80, 0x5F, 0x5C, 0x44, 0x2B];
const ASF_VIDEO: [u8; 16] = [0xC0, 0xEF, 0x19, 0xBC, 0x4D, 0x5B, 0xCF, 0x11, 0xA8, 0xFD, 0x00, 0x80, 0x5F, 0x5C, 0x44, 0x2B];

/// wmv or wma, from the stream types visible in the header bytes.
pub(crate) fn asf_kind(h: &[u8]) -> &'static str {
    let hl = (le64(h, 16).unwrap_or(0) as usize).min(h.len());
    let head = &h[..hl.max(30.min(h.len()))];
    if find(head, &ASF_VIDEO).is_some() {
        "wmv"
    } else if find(head, &ASF_AUDIO).is_some() {
        "wma"
    } else {
        "wmv"
    }
}

/// Specific type of an ISO-BMFF file from its `ftyp` box (`h` starts at the box).
pub(crate) fn ftyp_kind(h: &[u8]) -> Option<&'static str> {
    if !at(h, 4, b"ftyp") {
        return None;
    }
    let size = be32(h, 0)? as usize;
    if !(16..=4096).contains(&size) || size % 4 != 0 {
        return None;
    }
    let major: [u8; 4] = h.get(8..12)?.try_into().ok()?;
    if !major.iter().all(|&c| c.is_ascii_graphic() || c == b' ') {
        return None;
    }
    let compat: Vec<[u8; 4]> = h.get(16..size.min(h.len())).unwrap_or(&[]).chunks_exact(4).filter_map(|c| c.try_into().ok()).collect();
    let has = |b: &[u8; 4]| major == *b || compat.contains(b);
    Some(match &major {
        b"avif" | b"avis" => "avif",
        b"heic" | b"heix" | b"heim" | b"heis" | b"hevc" | b"hevx" | b"mif1" | b"msf1" | b"MiHE" => {
            if has(b"avif") || has(b"avis") {
                "avif"
            } else {
                "heic"
            }
        }
        b"crx " => "cr3",
        b"qt  " => "mov",
        b"M4A " | b"M4B " | b"M4P " | b"F4A " | b"F4B " => "m4a",
        b"M4V " | b"M4VH" | b"M4VP" => "m4v",
        m if m.starts_with(b"3g") => "3gp",
        _ => "mp4",
    })
}

/// Specific type of an OOXML/ODF/EPUB/plain ZIP from entry names, the `mimetype` entry and the
/// (partial) text of `[Content_Types].xml`.
pub(crate) fn zip_kind(names: &[String], mimetype: Option<&str>, content_types: Option<&str>) -> &'static str {
    if let Some(m) = mimetype {
        let m = m.trim();
        match m {
            "application/vnd.oasis.opendocument.text" => return "odt",
            "application/vnd.oasis.opendocument.spreadsheet" => return "ods",
            "application/vnd.oasis.opendocument.presentation" => return "odp",
            "application/epub+zip" => return "epub",
            _ => {}
        }
    }
    let any = |p: &str| names.iter().any(|n| n.starts_with(p));
    if any("word/") {
        return "docx";
    }
    if any("xl/") {
        return "xlsx";
    }
    if any("ppt/") {
        return "pptx";
    }
    if names.iter().any(|n| n == "[Content_Types].xml") {
        if let Some(ct) = content_types {
            if ct.contains("wordprocessingml") {
                return "docx";
            }
            if ct.contains("spreadsheetml") {
                return "xlsx";
            }
            if ct.contains("presentationml") {
                return "pptx";
            }
        }
    }
    "zip"
}

/// Inflate up to `max_out` bytes of a raw deflate stream (partial input is fine).
pub(crate) fn inflate_prefix(data: &[u8], max_out: usize) -> Vec<u8> {
    let mut d = flate2::Decompress::new(false);
    let mut out = vec![0u8; max_out];
    let _ = d.decompress(data, &mut out, flate2::FlushDecompress::None);
    out.truncate(d.total_out() as usize);
    out
}

/// Camera RAW type of a TIFF-structured file from its header, Make and DNGVersion.
pub(crate) fn raw_kind(h: &[u8], make: Option<&str>, dng: bool) -> &'static str {
    if h.starts_with(b"IIRO") || h.starts_with(b"IIRS") || h.starts_with(b"MMOR") {
        return "orf";
    }
    if h.starts_with(b"IIU\0") {
        return "rw2";
    }
    if h.starts_with(b"II*\0") && at(h, 8, b"CR") {
        return "cr2";
    }
    if dng {
        return "dng";
    }
    let m = make.unwrap_or("").trim().to_ascii_uppercase();
    if m.starts_with("NIKON") {
        "nef"
    } else if m.starts_with("SONY") {
        "arw"
    } else if m.starts_with("PENTAX") || m.starts_with("RICOH") || m.starts_with("ASAHI") {
        "pef"
    } else if m.starts_with("OLYMPUS") || m.starts_with("OM DIGITAL") {
        "orf"
    } else {
        "tiff"
    }
}

/// Make / DNGVersion from IFD0 when it lies inside `h` (a TIFF header at 0).
pub(crate) fn tiff_ifd0_facts(h: &[u8]) -> (Option<String>, bool) {
    let le = h.starts_with(b"II");
    let r16 = |o: usize| if le { le16(h, o) } else { be16(h, o) };
    let r32 = |o: usize| if le { le32(h, o) } else { be32(h, o) };
    let Some(ifd) = r32(4) else { return (None, false) };
    let ifd = ifd as usize;
    let Some(n) = r16(ifd) else { return (None, false) };
    let mut make = None;
    let mut dng = false;
    for i in 0..(n as usize).min(400) {
        let e = ifd + 2 + 12 * i;
        let (Some(tag), Some(cnt)) = (r16(e), r32(e + 4)) else { break };
        match tag {
            271 => {
                let cnt = cnt as usize;
                let off = if cnt <= 4 { Some(e + 8) } else { r32(e + 8).map(|v| v as usize) };
                if let Some(s) = off.and_then(|o| h.get(o..o + cnt.min(64))) {
                    let s: String = s.iter().take_while(|&&c| c != 0).map(|&c| c as char).collect();
                    make = Some(s);
                }
            }
            50706 => dng = true,
            _ => {}
        }
    }
    (make, dng)
}

/// OLE compound file specific type from the directory entry names visible in `h`.
pub(crate) fn ole_kind_from_names(names: &[String]) -> &'static str {
    for n in names {
        match n.as_str() {
            "WordDocument" => return "doc",
            "Workbook" | "Book" => return "xls",
            "PowerPoint Document" => return "ppt",
            _ => {}
        }
        if n.starts_with("__substg1.0_") || n.starts_with("__properties_version1.0") || n.starts_with("__nameid_version1.0") {
            return "msg";
        }
    }
    "doc"
}

/// Names of the 128-byte OLE directory entries in `dir`.
pub(crate) fn ole_dir_names(dir: &[u8]) -> Vec<String> {
    dir.chunks_exact(128)
        .filter_map(|e| {
            let nl = le16(e, 64)? as usize;
            if nl < 2 || nl > 64 || e[66] == 0 {
                return None;
            }
            let u: Vec<u16> = e[..nl - 2].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            Some(String::from_utf16_lossy(&u))
        })
        .collect()
}
