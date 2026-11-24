//! Structural checks: "does it decode / is it complete?". Images are decoded with the `image`
//! crate; containers are walked (ZIP entries CRC-checked, MP4 boxes, RIFF sizes, PDF xref, OGG
//! page CRCs, FLAC frame CRCs, MP3 frame sync, SQLite page count).

use super::bmff;
use super::exif::jpeg_info;
use super::util::*;
use super::Validation;
use crate::model::Condition;
use std::io::{Cursor, Read, Seek};

pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

pub const NOTE_DECODES: &str = "It opens and decodes completely.";
pub const NOTE_DAMAGED_PART: &str = "It's damaged — only part of it can be shown.";
pub const NOTE_UNCHECKABLE: &str = "MAX can't check this file type.";
pub const NOTE_STRUCTURE_OK: &str = "Its structure is complete.";
pub const NOTE_CUT_SHORT: &str = "It's cut short — its end is missing.";
pub const NOTE_NO_MOOV: &str = "Its index (moov) is missing, so most players won't open it.";

fn v(condition: Condition, note: &str, complete: bool) -> Validation {
    Validation { condition, note: note.to_string(), complete }
}
fn good(note: &str) -> Validation {
    v(Condition::Good, note, true)
}
fn partial(note: &str) -> Validation {
    v(Condition::Partial, note, false)
}
fn unknown(note: &str) -> Validation {
    v(Condition::Unknown, note, true)
}

/// Total decompressed bytes a ZIP check may inflate.
pub const ZIP_BUDGET: u64 = 512 << 20;

/// Validate a file. `rr` gives random access to the whole file; `prefix` holds its first bytes
/// (all of them when `prefix.len() == rr.size()`); `zip` optionally streams the whole file for ZIP
/// checks of files larger than the prefix.
pub fn validate_with(type_id: &str, rr: &dyn RandomRead, prefix: &[u8], zip: Option<&mut dyn ReadSeek>) -> Validation {
    let full = prefix.len() as u64 >= rr.size();
    let k = kind(type_id);
    let label = crate::formats::by_id(type_id).map(|t| t.label).unwrap_or("file");
    if rr.size() == 0 {
        return partial("It's empty.");
    }
    match k {
        Kind::Jpeg | Kind::Png | Kind::Gif | Kind::Webp | Kind::Bmp | Kind::Tiff | Kind::Ico => {
            if !full {
                return unknown("It's too large to check here.");
            }
            validate_image(k, prefix, label)
        }
        Kind::Ooxml | Kind::Odf | Kind::Epub | Kind::Zip => match zip {
            Some(z) => validate_zip(z, ZIP_BUDGET),
            None if full => validate_zip(&mut Cursor::new(prefix), ZIP_BUDGET),
            None => unknown("It's too large to check here."),
        },
        Kind::Pdf => validate_pdf(rr),
        Kind::Mp4 | Kind::Cr3 | Kind::Heic | Kind::Avif => {
            if k == Kind::Mp4 {
                validate_mp4(rr)
            } else {
                // Same box structure; a missing moov is normal for HEIF ('meta' instead).
                let (boxes, _) = bmff::top_level(rr);
                match boxes.last() {
                    None => partial("Its start doesn't look right any more."),
                    Some(b) if b.end() > rr.size() => partial(NOTE_CUT_SHORT),
                    _ => good(NOTE_STRUCTURE_OK),
                }
            }
        }
        Kind::Wav | Kind::Avi => validate_riff(rr, k),
        Kind::Mp3 => with_prefix_note(validate_mp3(prefix), full),
        Kind::Flac => with_prefix_note(validate_flac(prefix, full), full),
        Kind::Ogg => with_prefix_note(validate_ogg(prefix, full), full),
        Kind::Sqlite => validate_sqlite(rr),
        _ => unknown(NOTE_UNCHECKABLE),
    }
}

fn with_prefix_note(mut v: Validation, full: bool) -> Validation {
    if !full && v.condition == Condition::Good {
        v.note = "The part MAX checked (its first 64 MB) is intact.".into();
    }
    v
}

// ---------------------------------------------------------------------------------- images

pub fn image_format(k: Kind) -> Option<image::ImageFormat> {
    Some(match k {
        Kind::Jpeg => image::ImageFormat::Jpeg,
        Kind::Png => image::ImageFormat::Png,
        Kind::Gif => image::ImageFormat::Gif,
        Kind::Webp => image::ImageFormat::WebP,
        Kind::Bmp => image::ImageFormat::Bmp,
        Kind::Tiff | Kind::Raw => image::ImageFormat::Tiff,
        Kind::Ico => image::ImageFormat::Ico,
        _ => return None,
    })
}

/// The most one decode may allocate.
pub const MAX_DECODE_ALLOC: u64 = 1 << 30;
/// Decoded pixels held at once by every decode together (thumbnails, checks, repairs).
const DECODE_BUDGET: u64 = 1536 << 20;

struct Budget {
    used: std::sync::Mutex<u64>,
    cv: std::sync::Condvar,
}

fn budget() -> &'static Budget {
    static B: std::sync::OnceLock<Budget> = std::sync::OnceLock::new();
    B.get_or_init(|| Budget { used: std::sync::Mutex::new(0), cv: std::sync::Condvar::new() })
}

/// Room for `n` decoded bytes in the shared budget, held until dropped. Waits while other
/// decodes hold the room; a decode on its own always gets it.
struct Reservation(u64);

impl Reservation {
    fn take(n: u64) -> Reservation {
        let b = budget();
        let mut used = b.used.lock().unwrap_or_else(|e| e.into_inner());
        while *used > 0 && *used + n > DECODE_BUDGET {
            used = b.cv.wait(used).unwrap_or_else(|e| e.into_inner());
        }
        *used += n;
        Reservation(n)
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let b = budget();
        let mut used = b.used.lock().unwrap_or_else(|e| e.into_inner());
        *used = used.saturating_sub(self.0);
        b.cv.notify_all();
    }
}

pub fn decode(k: Kind, d: &[u8]) -> Result<image::DynamicImage, String> {
    decode_limited(k, d, MAX_DECODE_ALLOC)
}

/// Decode with at most `max_alloc` bytes for the pixels. The decoded size is read from the header
/// first and reserved in a budget shared by every decode, so parallel decodes of huge images wait
/// for each other instead of exhausting memory.
pub fn decode_limited(k: Kind, d: &[u8], max_alloc: u64) -> Result<image::DynamicImage, String> {
    use image::ImageDecoder;
    let fmt = image_format(k).ok_or("not an image")?;
    let reader = || {
        let mut r = image::ImageReader::new(Cursor::new(d));
        r.set_format(fmt);
        let mut lim = image::Limits::default();
        lim.max_alloc = Some(max_alloc);
        lim.max_image_width = Some(40_000);
        lim.max_image_height = Some(40_000);
        r.limits(lim);
        r
    };
    let need = reader().into_decoder().map_err(|e| e.to_string())?.total_bytes();
    if need > max_alloc {
        return Err("The image is too large to decode.".into());
    }
    let _room = Reservation::take(need);
    reader().decode().map_err(|e| e.to_string())
}

fn validate_image(k: Kind, d: &[u8], label: &str) -> Validation {
    if sig_matches(k, d) == Some(false) {
        return partial(&format!("Its start doesn't look like a {label} any more, so it can't be shown."));
    }
    let decoded = decode(k, d);
    if k == Kind::Jpeg {
        let j = jpeg_info(d).unwrap_or_default();
        let intact = j.eoi_end.is_some() && j.first_bad.is_none();
        return match (decoded.is_ok(), intact) {
            (true, true) => good(NOTE_DECODES),
            (true, false) => partial(NOTE_DAMAGED_PART),
            (false, _) if j.scan_start.is_some() => partial(NOTE_DAMAGED_PART),
            (false, _) => partial("It's damaged and can't be shown."),
        };
    }
    match decoded {
        Ok(_) => good(NOTE_DECODES),
        Err(_) => {
            // Something decodable at the start (a valid header) means a viewer shows part of it.
            let header_ok = match k {
                Kind::Png => d.len() > 33 && &d[12..16] == b"IHDR",
                Kind::Gif => d.len() > 13,
                _ => d.len() > 64,
            };
            partial(if header_ok { NOTE_DAMAGED_PART } else { "It's damaged and can't be shown." })
        }
    }
}

// -------------------------------------------------------------------------------------- ZIP

pub fn validate_zip(r: &mut dyn ReadSeek, budget: u64) -> Validation {
    let mut z = match zip::ZipArchive::new(r) {
        Ok(z) => z,
        Err(_) => return partial("Its table of contents is missing or damaged, so it won't open as is."),
    };
    let n = z.len();
    let mut bad = 0usize;
    let mut checked = 0usize;
    let mut left = budget;
    let mut stopped = false;
    for i in 0..n.min(100_000) {
        if left == 0 {
            stopped = true;
            break;
        }
        match z.by_index(i) {
            Ok(f) => {
                if f.is_dir() {
                    checked += 1;
                    continue;
                }
                let size = f.size();
                if size > left {
                    stopped = true;
                    break;
                }
                // Read one byte past the declared size: honest entries hit EOF there (and the
                // zip crate checks the CRC); a lying header can't inflate without bound.
                let mut f = f.take(size + 1);
                match std::io::copy(&mut f, &mut std::io::sink()) {
                    Ok(c) if c <= size => left = left.saturating_sub(c),
                    _ => bad += 1,
                }
                checked += 1;
            }
            Err(zip::result::ZipError::UnsupportedArchive(_)) => checked += 1, // encrypted / unknown method
            Err(_) => {
                bad += 1;
                checked += 1;
            }
        }
    }
    if bad > 0 {
        let item = if n == 1 { "item" } else { "items" };
        return partial(&format!("{bad} of {n} {item} in it are damaged."));
    }
    if stopped || checked < n {
        return good(&format!("The first {checked} of its {n} items check out."));
    }
    good(&format!("All {n} items in it check out."))
}

// -------------------------------------------------------------------------------------- PDF

pub fn validate_pdf(rr: &dyn RandomRead) -> Validation {
    let size = rr.size();
    let head = rr.read_vec(0, 1024);
    if find(&head, b"%PDF-").is_none() {
        return partial("Its start doesn't look like a PDF any more.");
    }
    let tail_at = size.saturating_sub(4096);
    let tail = rr.read_vec(tail_at, 4096);
    if rfind(&tail, b"%%EOF").is_none() {
        return partial("Its end is missing, so some pages may not open.");
    }
    let Some(sx) = rfind(&tail, b"startxref") else {
        return partial("Its index is missing; most PDF readers can still rebuild it.");
    };
    let num: String = tail[sx + 9..].iter().map(|&c| c as char).skip_while(|c| c.is_whitespace()).take_while(|c| c.is_ascii_digit()).collect();
    let Ok(off) = num.parse::<u64>() else {
        return partial("Its index is damaged; most PDF readers can still rebuild it.");
    };
    if off >= size {
        return partial("Its index points past its end; most PDF readers can still rebuild it.");
    }
    let at = rr.read_vec(off, 64);
    let s = String::from_utf8_lossy(&at);
    let t = s.trim_start();
    let is_obj = {
        let mut it = t.split_whitespace();
        matches!((it.next(), it.next(), it.next()), (Some(a), Some(b), Some(c)) if a.chars().all(|x| x.is_ascii_digit()) && b.chars().all(|x| x.is_ascii_digit()) && c.starts_with("obj"))
    };
    if t.starts_with("xref") || is_obj {
        good(NOTE_STRUCTURE_OK)
    } else {
        partial("Its index points to the wrong place; most PDF readers can still rebuild it.")
    }
}

// -------------------------------------------------------------------------------------- MP4

pub fn validate_mp4(rr: &dyn RandomRead) -> Validation {
    let size = rr.size();
    let (boxes, clean) = bmff::top_level(rr);
    if boxes.is_empty() {
        return partial("Its start doesn't look like a video any more.");
    }
    let moov = boxes.iter().find(|b| &b.typ == b"moov");
    let last = boxes.last().unwrap();
    if moov.is_none() {
        return partial(NOTE_NO_MOOV);
    }
    if last.end() > size {
        return partial(if &last.typ == b"moov" { "Its index (moov) is cut short, so most players won't open it." } else { NOTE_CUT_SHORT });
    }
    if !clean {
        // Trailing zeros (cluster slack) are fine; anything else is damage.
        let rest = rr.read_vec(last.end(), 65536);
        if rest.iter().any(|&b| b != 0) {
            return v(Condition::Partial, "Part of it after the video data is damaged.", true);
        }
    }
    let m = moov.unwrap();
    let content = rr.read_vec(m.start + m.hdr, (m.size - m.hdr).min(64 << 20) as usize);
    if bmff::child(&content, b"mvhd").is_none() {
        return partial("Its index (moov) is damaged, so most players won't open it.");
    }
    good(NOTE_STRUCTURE_OK)
}

// ------------------------------------------------------------------------------------- RIFF

pub fn validate_riff(rr: &dyn RandomRead, k: Kind) -> Validation {
    let size = rr.size();
    let h = rr.read_vec(0, 12);
    let form: &[u8] = if k == Kind::Wav { b"WAVE" } else { b"AVI " };
    if h.len() < 12 || (&h[..4] != b"RIFF" && &h[..4] != b"RF64") || &h[8..12] != form {
        return partial("Its start doesn't look right any more.");
    }
    let declared = le32(&h, 4).unwrap_or(0) as u64;
    if &h[..4] == b"RF64" || declared == 0xFFFF_FFFF {
        return unknown("Its size fields can't be checked.");
    }
    // Walk this RIFF's chunks (and AVI's RIFF AVIX continuations).
    let riff_end = 8 + declared;
    let mut p = 12u64;
    let mut seen_fmt = false;
    let mut seen_data = false;
    let mut n = 0;
    while p + 8 <= riff_end.min(size) && n < 100_000 {
        n += 1;
        let c = rr.read_vec(p, 12);
        if c.len() < 8 {
            break;
        }
        let len = le32(&c, 4).unwrap_or(0) as u64;
        match &c[..4] {
            b"fmt " => seen_fmt = true,
            b"data" => seen_data = true,
            b"LIST" if c.len() >= 12 && (&c[8..12] == b"hdrl") => seen_fmt = true,
            b"LIST" if c.len() >= 12 && (&c[8..12] == b"movi") => seen_data = true,
            _ => {}
        }
        if p + 8 + len > size {
            return partial(NOTE_CUT_SHORT);
        }
        p += 8 + len + (len & 1);
    }
    if !seen_fmt {
        return partial("Its format header is missing.");
    }
    if !seen_data {
        return partial(if riff_end > size { NOTE_CUT_SHORT } else { "Its audio/video data is missing." });
    }
    if riff_end > size + 1 {
        return partial(NOTE_CUT_SHORT);
    }
    good(NOTE_STRUCTURE_OK)
}

// -------------------------------------------------------------------------------------- MP3

#[derive(Clone, Copy, Debug)]
pub struct MpegHeader {
    /// 1, 2 or 25 (MPEG 2.5)
    pub version: u8,
    pub layer: u8,
    pub bitrate: u32,
    pub sample_rate: u32,
    pub channels: u8,
    pub len: usize,
    pub samples: u32,
}

pub fn mpeg_header(b: &[u8]) -> Option<MpegHeader> {
    if b.len() < 4 || b[0] != 0xFF || b[1] & 0xE0 != 0xE0 {
        return None;
    }
    let version = match (b[1] >> 3) & 3 {
        0 => 25,
        2 => 2,
        3 => 1,
        _ => return None,
    };
    let layer = match (b[1] >> 1) & 3 {
        1 => 3,
        2 => 2,
        3 => 1,
        _ => return None,
    };
    let bi = (b[2] >> 4) as usize;
    let si = ((b[2] >> 2) & 3) as usize;
    if bi == 0 || bi == 15 || si == 3 || b[3] & 3 == 2 {
        return None;
    }
    const V1L1: [u32; 15] = [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448];
    const V1L2: [u32; 15] = [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384];
    const V1L3: [u32; 15] = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320];
    const V2L1: [u32; 15] = [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256];
    const V2L23: [u32; 15] = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160];
    let bitrate = match (version, layer) {
        (1, 1) => V1L1[bi],
        (1, 2) => V1L2[bi],
        (1, 3) => V1L3[bi],
        (_, 1) => V2L1[bi],
        _ => V2L23[bi],
    };
    let sample_rate = [44100, 48000, 32000][si] / if version == 1 { 1 } else if version == 2 { 2 } else { 4 };
    let pad = ((b[2] >> 1) & 1) as usize;
    let samples = match (layer, version) {
        (1, _) => 384,
        (2, _) => 1152,
        (3, 1) => 1152,
        _ => 576,
    };
    let len = if layer == 1 { (12 * bitrate as usize * 1000 / sample_rate as usize + pad) * 4 } else { samples as usize / 8 * bitrate as usize * 1000 / sample_rate as usize + pad };
    if len < 21 {
        return None;
    }
    Some(MpegHeader { version, layer, bitrate, sample_rate, channels: if b[3] >> 6 == 3 { 1 } else { 2 }, len, samples })
}

/// (frames, bytes in valid frames, audio bytes, first header)
pub fn mp3_scan(d: &[u8]) -> (usize, usize, usize, Option<MpegHeader>) {
    let start = id3_skip(d).unwrap_or(0).min(d.len());
    let mut end = d.len();
    if end >= start + 128 && &d[end - 128..end - 125] == b"TAG" {
        end -= 128;
    }
    if end >= start + 32 && &d[end - 32..end - 24] == b"APETAGEX" {
        let sz = le32(d, end - 20).unwrap_or(0) as usize;
        let hdr = if le32(d, end - 12).unwrap_or(0) & 0x8000_0000 != 0 { 32 } else { 0 };
        end = end.saturating_sub(sz + hdr).max(start);
    }
    let mut p = start;
    let mut frames = 0;
    let mut good_bytes = 0;
    let mut first = None;
    while p + 4 <= end {
        if d[p] != 0xFF {
            match d[p..end].iter().position(|&b| b == 0xFF) {
                Some(k) => p += k,
                None => break,
            }
            continue;
        }
        if let Some(h) = mpeg_header(&d[p..]) {
            let next = p + h.len;
            let chained = next >= end || (next + 4 <= end && mpeg_header(&d[next..]).is_some_and(|n| n.sample_rate == h.sample_rate && n.layer == h.layer));
            if chained {
                first.get_or_insert(h);
                frames += 1;
                good_bytes += h.len.min(end - p);
                p = next;
                continue;
            }
        }
        p += 1;
    }
    (frames, good_bytes, end - start, first)
}

pub fn validate_mp3(d: &[u8]) -> Validation {
    let (frames, good_bytes, total, _) = mp3_scan(d);
    if frames < 3 {
        return partial("It doesn't contain playable MP3 audio any more.");
    }
    let ratio = good_bytes as f64 / total.max(1) as f64;
    if ratio >= 0.97 {
        good("Its audio frames check out.")
    } else {
        v(Condition::Partial, "Parts of it are damaged and will sound broken or be skipped.", false)
    }
}

// ------------------------------------------------------------------------------------- FLAC

fn crc8(d: &[u8]) -> u8 {
    let mut c = 0u8;
    for &b in d {
        c ^= b;
        for _ in 0..8 {
            c = if c & 0x80 != 0 { (c << 1) ^ 0x07 } else { c << 1 };
        }
    }
    c
}

fn crc16_table() -> &'static [u16; 256] {
    static T: std::sync::OnceLock<[u16; 256]> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let mut t = [0u16; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = (i as u16) << 8;
            for _ in 0..8 {
                c = if c & 0x8000 != 0 { (c << 1) ^ 0x8005 } else { c << 1 };
            }
            *e = c;
        }
        t
    })
}

fn crc16(d: &[u8]) -> u16 {
    let t = crc16_table();
    d.iter().fold(0u16, |c, &b| (c << 8) ^ t[((c >> 8) as u8 ^ b) as usize])
}

/// Length of a valid FLAC frame header at `p` (CRC-8 checked), or None.
pub fn flac_frame_header(d: &[u8], p: usize) -> Option<usize> {
    let b = d.get(p..p + 16.min(d.len() - p.min(d.len())))?;
    if b.len() < 6 || b[0] != 0xFF || (b[1] & 0xFE) != 0xF8 {
        return None;
    }
    let bs = b[2] >> 4;
    let sr = b[2] & 0x0F;
    if bs == 0 || sr == 15 || (b[3] >> 4) > 10 || (b[3] >> 1) & 7 == 3 || (b[3] >> 1) & 7 == 7 {
        return None;
    }
    let mut i = 4;
    let lead = b[i].leading_ones() as usize;
    if lead == 1 || lead > 7 {
        return None;
    }
    i += if lead == 0 { 1 } else { lead };
    i += match bs {
        6 => 1,
        7 => 2,
        _ => 0,
    };
    i += match sr {
        12 => 1,
        13 | 14 => 2,
        _ => 0,
    };
    if i >= b.len() {
        return None;
    }
    if crc8(&b[..i]) == b[i] {
        Some(i + 1)
    } else {
        None
    }
}

pub fn validate_flac(d: &[u8], full: bool) -> Validation {
    let mut p = id3_skip(d).unwrap_or(0);
    if d.get(p..p + 4) != Some(b"fLaC") {
        return partial("Its start doesn't look like FLAC audio any more.");
    }
    p += 4;
    let mut blocks = 0;
    loop {
        let Some(&h) = d.get(p) else { return partial(NOTE_CUT_SHORT) };
        let len = (be32(d, p).unwrap_or(0) & 0x00FF_FFFF) as usize;
        p += 4 + len;
        blocks += 1;
        if h & 0x80 != 0 || blocks > 256 {
            break;
        }
    }
    if p >= d.len() {
        return partial(NOTE_CUT_SHORT);
    }
    if flac_frame_header(d, p).is_none() {
        return partial("Its audio starts with damaged data.");
    }
    // CRC-16 the first frames: a frame runs to the next valid header whose CRC matches.
    let candidates = |from: usize, max: usize| -> Vec<usize> {
        let mut out = Vec::new();
        let mut q = from;
        while out.len() < max && q + 2 <= d.len() {
            match d[q..].iter().position(|&b| b == 0xFF) {
                Some(k) => {
                    q += k;
                    if flac_frame_header(d, q).is_some() {
                        out.push(q);
                    }
                    q += 1;
                }
                None => break,
            }
        }
        out
    };
    let mut s = p;
    let mut bad = 0;
    for _ in 0..64 {
        let next = candidates(s + 1, 4);
        let ok = next.iter().find(|&&c| c >= s + 2 && be16(d, c - 2) == Some(crc16(&d[s..c - 2])));
        match ok {
            Some(&c) => s = c,
            None => {
                if next.is_empty() {
                    // Last frame: runs to the end of the file.
                    if full && d.len() >= s + 2 && be16(d, d.len() - 2) != Some(crc16(&d[s..d.len() - 2])) {
                        return partial(NOTE_CUT_SHORT);
                    }
                    break;
                }
                bad += 1;
                s = next[0];
            }
        }
    }
    if bad > 0 {
        return partial("Parts of it are damaged and will sound broken or be skipped.");
    }
    if full {
        // The last frame (found in the tail) must end exactly at the end of the file.
        let tail = d.len().saturating_sub(1 << 20).max(s);
        let mut last = None;
        let mut q = tail;
        while let Some(k) = d[q..].iter().position(|&b| b == 0xFF) {
            q += k;
            if flac_frame_header(d, q).is_some() && d.len() >= q + 2 && be16(d, d.len() - 2) == Some(crc16(&d[q..d.len() - 2])) {
                last = Some(q);
            }
            q += 1;
            if q + 2 > d.len() {
                break;
            }
        }
        if last.is_none() && d.len() - s > 2 {
            return partial(NOTE_CUT_SHORT);
        }
    }
    good("Its audio frames check out.")
}

// -------------------------------------------------------------------------------------- OGG

fn ogg_crc_table() -> &'static [u32; 256] {
    static T: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = (i as u32) << 24;
            for _ in 0..8 {
                c = if c & 0x8000_0000 != 0 { (c << 1) ^ 0x04C1_1DB7 } else { c << 1 };
            }
            *e = c;
        }
        t
    })
}

pub fn ogg_crc(page: &[u8]) -> u32 {
    let t = ogg_crc_table();
    let mut c = 0u32;
    for (i, &b) in page.iter().enumerate() {
        let b = if (22..26).contains(&i) { 0 } else { b };
        c = (c << 8) ^ t[((c >> 24) as u8 ^ b) as usize];
    }
    c
}

pub fn validate_ogg(d: &[u8], full: bool) -> Validation {
    if !d.starts_with(b"OggS") {
        return partial("Its start doesn't look like OGG audio any more.");
    }
    let mut p = 0;
    let mut pages = 0;
    let mut bad = 0;
    let mut eos = false;
    while p + 27 <= d.len() {
        if &d[p..p + 4] != b"OggS" {
            // Lost sync: damage. Resync at the next page.
            bad += 1;
            match find_from(d, b"OggS", p + 1) {
                Some(n) => {
                    p = n;
                    continue;
                }
                None => break,
            }
        }
        let segs = d[p + 26] as usize;
        let body: usize = d.get(p + 27..p + 27 + segs).map_or(0, |s| s.iter().map(|&x| x as usize).sum());
        let end = p + 27 + segs + body;
        if end > d.len() {
            if full {
                return partial(NOTE_CUT_SHORT);
            }
            break;
        }
        if pages < 4096 && le32(d, p + 22) != Some(ogg_crc(&d[p..end])) {
            bad += 1;
        }
        if d[p + 5] & 4 != 0 {
            eos = true;
        }
        pages += 1;
        p = end;
    }
    if bad > 0 {
        return partial("Parts of it are damaged and will sound broken or be skipped.");
    }
    if full && !eos {
        return partial(NOTE_CUT_SHORT);
    }
    good("Its audio pages check out.")
}

// ----------------------------------------------------------------------------------- SQLite

pub fn validate_sqlite(rr: &dyn RandomRead) -> Validation {
    let h = rr.read_vec(0, 100);
    if h.len() < 100 || !h.starts_with(b"SQLite format 3\0") {
        return partial("Its start doesn't look like a database any more.");
    }
    let ps = match be16(&h, 16).unwrap_or(0) {
        1 => 65536u64,
        p if p >= 512 && p.is_power_of_two() => p as u64,
        _ => return partial("Its header is damaged."),
    };
    let size = rr.size();
    let pages = be32(&h, 28).unwrap_or(0) as u64;
    let valid = be32(&h, 24) == be32(&h, 92) && pages > 0;
    if valid {
        let expected = pages * ps;
        if size < expected {
            return partial(NOTE_CUT_SHORT);
        }
        return good(NOTE_STRUCTURE_OK);
    }
    if size % ps == 0 {
        good(NOTE_STRUCTURE_OK)
    } else {
        partial(NOTE_CUT_SHORT)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn jpeg_bytes(w: u32, h: u32) -> Vec<u8> {
        let img = image::RgbImage::from_fn(w, h, |x, y| image::Rgb([(x * 5) as u8, (y * 3) as u8, ((x + y) * 7) as u8]));
        let mut j = Vec::new();
        image::codecs::jpeg::JpegEncoder::new_with_quality(&mut j, 85).encode_image(&img).unwrap();
        j
    }

    pub fn png_bytes(w: u32, h: u32) -> Vec<u8> {
        let img = image::RgbImage::from_fn(w, h, |x, y| image::Rgb([(x * 5) as u8, (y * 3) as u8, ((x * y) % 251) as u8]));
        let mut p = Vec::new();
        img.write_to(&mut Cursor::new(&mut p), image::ImageFormat::Png).unwrap();
        p
    }

    pub fn wav(rate: u32, data_len: usize) -> Vec<u8> {
        let mut w = b"RIFF".to_vec();
        w.extend_from_slice(&((36 + data_len) as u32).to_le_bytes());
        w.extend_from_slice(b"WAVEfmt ");
        w.extend_from_slice(&16u32.to_le_bytes());
        w.extend_from_slice(&1u16.to_le_bytes());
        w.extend_from_slice(&2u16.to_le_bytes());
        w.extend_from_slice(&rate.to_le_bytes());
        w.extend_from_slice(&(rate * 4).to_le_bytes());
        w.extend_from_slice(&4u16.to_le_bytes());
        w.extend_from_slice(&16u16.to_le_bytes());
        w.extend_from_slice(b"data");
        w.extend_from_slice(&(data_len as u32).to_le_bytes());
        w.extend((0..data_len).map(|i| (i % 7) as u8));
        w
    }

    pub fn val(t: &str, d: &[u8]) -> Validation {
        validate_with(t, &d, d, None)
    }

    #[test]
    fn images() {
        let j = jpeg_bytes(64, 48);
        assert_eq!(val("jpg", &j).condition, Condition::Good);
        let cut = val("jpg", &j[..j.len() * 2 / 3]);
        assert_eq!((cut.condition, cut.complete), (Condition::Partial, false));
        assert_eq!(cut.note, NOTE_DAMAGED_PART);
        let p = png_bytes(40, 30);
        assert_eq!(val("png", &p).condition, Condition::Good);
        assert_eq!(val("png", &p[..p.len() - 30]).condition, Condition::Partial);
        let mut zeroed = p.clone();
        zeroed[..16].fill(0);
        assert!(val("png", &zeroed).note.contains("doesn't look like"));
    }

    #[test]
    fn decodes_are_capped_and_share_a_budget() {
        let p = png_bytes(50, 100);
        // 50 x 100 RGB needs 15000 bytes.
        assert!(decode_limited(Kind::Png, &p, 1000).is_err());
        assert!(decode_limited(Kind::Png, &p, 1 << 20).is_ok());
        // Parallel decodes all finish (each gives its room back when done).
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| assert!(decode(Kind::Png, &p).is_ok()));
            }
        });
        // A reservation larger than the whole budget still goes through on its own.
        drop(Reservation::take(DECODE_BUDGET + 1));
    }

    #[test]
    fn zips() {
        let z = super::super::zipscan::tests::make_zip(&[("a.txt", b"hello world hello world"), ("b.txt", &[7u8; 5000])], true);
        let ok = val("zip", &z);
        assert_eq!(ok.condition, Condition::Good, "{}", ok.note);
        // Corrupt b.txt's data.
        let mut bad = z.clone();
        let e = super::super::zipscan::scan_local(&z, false, 0, 10);
        bad[e[1].data_at + 3] ^= 0x55;
        let r = val("zip", &bad);
        assert_eq!(r.condition, Condition::Partial);
        assert!(r.note.starts_with("1 of 2"), "{}", r.note);
        assert_eq!(val("docx", &z[..z.len() - 30]).condition, Condition::Partial);
    }

    #[test]
    fn pdfs() {
        let body = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n";
        let x = body.len();
        let ok = [&body[..], format!("xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer << /Root 1 0 R /Size 2 >>\nstartxref\n{x}\n%%EOF\n").as_bytes()].concat();
        assert_eq!(val("pdf", &ok).condition, Condition::Good);
        assert_eq!(val("pdf", &ok[..ok.len() - 7]).condition, Condition::Partial);
        let wrong = [&body[..], b"trailer << >>\nstartxref\n3\n%%EOF\n"].concat();
        assert_eq!(val("pdf", &wrong).condition, Condition::Partial);
    }

    #[test]
    fn mp4s() {
        let v = super::super::bmff::tests::sample_mp4(5000);
        assert_eq!(val("mp4", &v).condition, Condition::Good);
        let cut = val("mp4", &v[..v.len() - 100]);
        assert_eq!(cut.note, NOTE_CUT_SHORT);
        // mdat first and moov lost at the end.
        let moov_at = find(&v, b"moov").unwrap() - 4;
        let only = [&v[..moov_at], &v[find(&v, b"mdat").unwrap() - 4..]].concat();
        assert_eq!(val("mov", &only).note, NOTE_NO_MOOV);
    }

    #[test]
    fn riff_and_sqlite() {
        let w = wav(8000, 4000);
        assert_eq!(val("wav", &w).condition, Condition::Good);
        assert_eq!(val("wav", &w[..w.len() - 100]).note, NOTE_CUT_SHORT);
        let mut db = vec![0u8; 4096 * 3];
        db[..16].copy_from_slice(b"SQLite format 3\0");
        db[16..18].copy_from_slice(&4096u16.to_be_bytes());
        db[28..32].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(val("sqlite", &db).condition, Condition::Good);
        assert_eq!(val("sqlite", &db[..8192]).condition, Condition::Partial);
    }

    #[test]
    fn mp3_frames() {
        // MPEG1 layer III 128 kbps 44.1 kHz: 417-byte frames.
        let mut f = vec![0u8; 417];
        f[..4].copy_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
        for (i, b) in f[4..].iter_mut().enumerate() {
            *b = (i % 200) as u8;
        }
        let ok: Vec<u8> = (0..50).flat_map(|_| f.clone()).collect();
        assert_eq!(val("mp3", &ok).condition, Condition::Good);
        let mut dam = ok.clone();
        dam[417 * 10..417 * 20].fill(0);
        assert_eq!(val("mp3", &dam).condition, Condition::Partial);
        let h = mpeg_header(&f).unwrap();
        assert_eq!((h.bitrate, h.sample_rate, h.len), (128, 44100, 417));
    }

    #[test]
    fn ogg_pages() {
        let mk = |seq: u32, flags: u8, body: &[u8]| {
            let mut p = b"OggS\0".to_vec();
            p.push(flags);
            p.extend_from_slice(&(seq as u64 * 1000).to_le_bytes());
            p.extend_from_slice(&1u32.to_le_bytes());
            p.extend_from_slice(&seq.to_le_bytes());
            p.extend_from_slice(&[0; 4]);
            p.push(1);
            p.push(body.len() as u8);
            p.extend_from_slice(body);
            let c = ogg_crc(&p);
            p[22..26].copy_from_slice(&c.to_le_bytes());
            p
        };
        let o = [mk(0, 2, b"\x01vorbis-ish"), mk(1, 0, &[9; 100]), mk(2, 4, &[8; 50])].concat();
        assert_eq!(val("ogg", &o).condition, Condition::Good);
        let mut bad = o.clone();
        bad[60] ^= 1;
        assert_eq!(val("ogg", &bad).condition, Condition::Partial);
        assert_eq!(val("ogg", &o[..o.len() - 10]).note, NOTE_CUT_SHORT);
    }

    #[test]
    fn unknown_types() {
        assert_eq!(val("txt", b"hello").condition, Condition::Unknown);
        assert_eq!(val("txt", b"hello").note, NOTE_UNCHECKABLE);
    }
}
