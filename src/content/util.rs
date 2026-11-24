//! Small shared helpers for the content module: type families, byte readers, signatures, text
//! decoding, dates, and random access over either a byte slice or a found file.

use crate::device::source::BlockSource;
use crate::model::FoundFile;
use std::cell::Cell;

/// Format families the content code dispatches on. Several registry ids map to one kind
/// ("mov", "m4a" -> Mp4; "cr2", "nef", "dng" -> Raw).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Jpeg,
    Png,
    Gif,
    Webp,
    Bmp,
    Tiff,
    /// TIFF-based camera RAW (CR2, NEF, ARW, DNG, ORF, RW2, PEF, SRW…).
    Raw,
    Cr3,
    Raf,
    Heic,
    Avif,
    Psd,
    Ico,
    Svg,
    Pdf,
    Ooxml,
    Odf,
    Epub,
    Zip,
    SevenZ,
    Rar,
    Gz,
    Mp4,
    Mp3,
    Aac,
    Wav,
    Avi,
    Flac,
    Ogg,
    Mkv,
    Sqlite,
    Pe,
    Rtf,
    Ole,
    Text,
    Html,
    Csv,
    Other,
}

pub fn kind(type_id: &str) -> Kind {
    let id = type_id.trim().trim_start_matches('.').to_ascii_lowercase();
    match id.as_str() {
        "jpg" | "jpeg" | "jpe" | "jfif" => Kind::Jpeg,
        "png" => Kind::Png,
        "gif" => Kind::Gif,
        "webp" => Kind::Webp,
        "bmp" | "dib" => Kind::Bmp,
        "tif" | "tiff" => Kind::Tiff,
        "cr2" | "nef" | "nrw" | "arw" | "srf" | "sr2" | "dng" | "orf" | "rw2" | "pef" | "srw" | "rwl" | "3fr" | "erf" | "kdc" | "dcr" | "mef"
        | "mos" | "iiq" => Kind::Raw,
        "cr3" => Kind::Cr3,
        "raf" => Kind::Raf,
        "heic" | "heif" | "hif" => Kind::Heic,
        "avif" => Kind::Avif,
        "psd" | "psb" => Kind::Psd,
        "ico" | "cur" => Kind::Ico,
        "svg" => Kind::Svg,
        "pdf" => Kind::Pdf,
        "docx" | "docm" | "dotx" | "dotm" | "xlsx" | "xlsm" | "xltx" | "xltm" | "pptx" | "pptm" | "potx" | "ppsx" | "vsdx" => Kind::Ooxml,
        "odt" | "ods" | "odp" | "odg" | "ott" | "ots" | "otp" => Kind::Odf,
        "epub" => Kind::Epub,
        "zip" | "jar" | "apk" | "xpi" | "kmz" | "cbz" | "aab" => Kind::Zip,
        "7z" => Kind::SevenZ,
        "rar" => Kind::Rar,
        "gz" | "tgz" | "gzip" => Kind::Gz,
        "mp4" | "m4v" | "mov" | "qt" | "m4a" | "m4b" | "m4p" | "3gp" | "3g2" | "f4v" => Kind::Mp4,
        "mp3" => Kind::Mp3,
        "aac" => Kind::Aac,
        "wav" | "wave" => Kind::Wav,
        "avi" => Kind::Avi,
        "flac" => Kind::Flac,
        "ogg" | "oga" | "ogv" | "opus" => Kind::Ogg,
        "mkv" | "mka" | "mk3d" | "webm" => Kind::Mkv,
        "sqlite" | "sqlite3" | "db3" | "sqlitedb" => Kind::Sqlite,
        "exe" | "dll" | "sys" | "ocx" | "scr" | "cpl" | "efi" => Kind::Pe,
        "rtf" => Kind::Rtf,
        "doc" | "dot" | "xls" | "xlt" | "ppt" | "pps" | "pot" | "msg" | "pub" | "vsd" | "msi" | "ole" => Kind::Ole,
        "txt" | "text" | "log" | "md" | "markdown" | "json" | "xml" | "ini" | "cfg" | "conf" | "yaml" | "yml" | "tsv" | "srt" | "vtt" | "bat"
        | "cmd" | "ps1" | "py" | "js" | "css" | "c" | "h" | "cpp" | "hpp" | "rs" | "java" | "cs" | "sql" | "reg" | "nfo" | "sh" | "tex"
        | "eml" | "ics" | "vcf" => Kind::Text,
        "html" | "htm" | "xhtml" => Kind::Html,
        "csv" => Kind::Csv,
        _ => Kind::Other,
    }
}

/// Container family: two ids in one family are not a real mismatch (a .docx detected as ZIP, a
/// .cr2 detected as TIFF, a .mov detected as MP4).
pub fn family(type_id: &str) -> String {
    match kind(type_id) {
        Kind::Tiff | Kind::Raw => "tiff".into(),
        Kind::Ooxml | Kind::Odf | Kind::Epub | Kind::Zip => "zip".into(),
        Kind::Mp4 | Kind::Cr3 | Kind::Heic | Kind::Avif => "isobmff".into(),
        Kind::Text | Kind::Html | Kind::Csv => "text".into(),
        Kind::Other => type_id.to_ascii_lowercase(),
        k => format!("{k:?}"),
    }
}

/// Does `p` (the file's first bytes) carry `k`'s signature? None = the kind has no fixed signature.
pub fn sig_matches(k: Kind, p: &[u8]) -> Option<bool> {
    let at = |off: usize, s: &[u8]| p.len() >= off + s.len() && &p[off..off + s.len()] == s;
    let tiff = at(0, b"II*\0") || at(0, b"MM\0*");
    Some(match k {
        Kind::Jpeg => at(0, &[0xFF, 0xD8, 0xFF]),
        Kind::Png => at(0, b"\x89PNG\r\n\x1a\n"),
        Kind::Gif => at(0, b"GIF87a") || at(0, b"GIF89a"),
        Kind::Webp => at(0, b"RIFF") && at(8, b"WEBP"),
        Kind::Bmp => at(0, b"BM"),
        Kind::Tiff => tiff,
        Kind::Raw => tiff || at(0, b"IIRO") || at(0, b"IIRS") || at(0, b"IIU\0") || at(0, b"MMOR") || at(0, b"FOVb"),
        Kind::Cr3 => at(4, b"ftypcrx "),
        Kind::Raf => at(0, b"FUJIFILMCCD-RAW"),
        Kind::Heic | Kind::Avif => at(4, b"ftyp"),
        Kind::Psd => at(0, b"8BPS"),
        Kind::Ico => at(0, &[0, 0, 1, 0]) || at(0, &[0, 0, 2, 0]),
        Kind::Pdf => find(&p[..p.len().min(1024)], b"%PDF-").is_some(),
        Kind::Ooxml | Kind::Odf | Kind::Epub | Kind::Zip => at(0, b"PK\x03\x04") || at(0, b"PK\x05\x06") || at(0, b"PK\x07\x08"),
        Kind::SevenZ => at(0, &[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C]),
        Kind::Rar => at(0, b"Rar!\x1a\x07"),
        Kind::Gz => at(0, &[0x1F, 0x8B]),
        Kind::Mp4 => {
            p.len() >= 8 && matches!(&p[4..8], b"ftyp" | b"moov" | b"mdat" | b"wide" | b"free" | b"skip" | b"pnot" | b"uuid" | b"junk" | b"PICT")
        }
        Kind::Mp3 => at(0, b"ID3") || mp3_sync_near_start(p),
        Kind::Aac => at(0, b"ID3") || (p.len() >= 2 && p[0] == 0xFF && p[1] & 0xF6 == 0xF0) || at(0, b"ADIF"),
        Kind::Wav => at(0, b"RIFF") && at(8, b"WAVE") || at(0, b"RF64") && at(8, b"WAVE"),
        Kind::Avi => at(0, b"RIFF") && at(8, b"AVI "),
        Kind::Flac => at(0, b"fLaC") || (at(0, b"ID3") && id3_skip(p).map_or(false, |s| p.len() < s + 4 || at(s, b"fLaC"))),
        Kind::Ogg => at(0, b"OggS"),
        Kind::Mkv => at(0, &[0x1A, 0x45, 0xDF, 0xA3]),
        Kind::Sqlite => at(0, b"SQLite format 3\0"),
        Kind::Pe => at(0, b"MZ"),
        Kind::Rtf => at(0, b"{\\rtf"),
        Kind::Ole => at(0, &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
        Kind::Svg | Kind::Text | Kind::Html | Kind::Csv | Kind::Other => return None,
    })
}

/// Size of a leading ID3v2 tag (header + body + footer), if present.
pub fn id3_skip(p: &[u8]) -> Option<usize> {
    if p.len() < 10 || &p[..3] != b"ID3" {
        return None;
    }
    let sz = syncsafe(&p[6..10]) as usize;
    Some(10 + sz + if p[5] & 0x10 != 0 { 10 } else { 0 })
}

pub fn syncsafe(b: &[u8]) -> u32 {
    b.iter().take(4).fold(0u32, |a, &x| (a << 7) | (x & 0x7F) as u32)
}

/// Two valid MPEG audio frame headers in a row within the first bytes.
fn mp3_sync_near_start(p: &[u8]) -> bool {
    let lim = p.len().min(4096);
    let mut i = 0;
    while i + 4 <= lim {
        if let Some(h) = crate::content::validate::mpeg_header(&p[i..]) {
            let next = i + h.len;
            if next + 4 <= p.len() && crate::content::validate::mpeg_header(&p[next..]).is_some() {
                return true;
            }
            if next + 4 > p.len() && i == 0 {
                return true;
            }
        }
        i += 1;
    }
    false
}

// ------------------------------------------------------------------------------------ bytes

pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    find_from(hay, needle, 0)
}

pub fn find_from(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= hay.len() || hay.len() - from < needle.len() {
        return None;
    }
    let first = needle[0];
    let last_start = hay.len() - needle.len();
    let mut i = from;
    while i <= last_start {
        match hay[i..=last_start].iter().position(|&b| b == first) {
            None => return None,
            Some(k) => {
                i += k;
                if &hay[i..i + needle.len()] == needle {
                    return Some(i);
                }
                i += 1;
            }
        }
    }
    None
}

pub fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let first = needle[0];
    let mut end = hay.len() - needle.len() + 1; // candidates are < end
    while let Some(i) = hay[..end].iter().rposition(|&b| b == first) {
        if &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
        end = i;
    }
    None
}

pub fn be16(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}
pub fn be32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}
pub fn be64(d: &[u8], o: usize) -> Option<u64> {
    d.get(o..o + 8).map(|b| u64::from_be_bytes(b.try_into().unwrap()))
}
pub fn le16(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
pub fn le32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
pub fn le64(d: &[u8], o: usize) -> Option<u64> {
    d.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

pub fn hex_spaced(d: &[u8]) -> String {
    let mut s = String::with_capacity(d.len() * 3);
    for (i, b) in d.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02X}"));
    }
    s
}

// ------------------------------------------------------------------------------------- text

pub fn latin1(d: &[u8]) -> String {
    d.iter().map(|&b| b as char).collect()
}

const CP1252_HIGH: [u16; 32] = [
    0x20AC, 0x81, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x8D, 0x017D, 0x8F, 0x90, 0x2018,
    0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x9D, 0x017E, 0x0178,
];

pub fn cp1252_char(b: u8) -> char {
    if (0x80..0xA0).contains(&b) {
        char::from_u32(CP1252_HIGH[(b - 0x80) as usize] as u32).unwrap_or('?')
    } else {
        b as char
    }
}

pub fn utf16(d: &[u8], le: bool) -> String {
    let units: Vec<u16> = d.chunks_exact(2).map(|c| if le { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) }).collect();
    String::from_utf16_lossy(&units)
}

/// UTF-8 when valid, else Windows-1252.
pub fn utf8_or_1252(d: &[u8]) -> String {
    match std::str::from_utf8(d) {
        Ok(s) => s.to_string(),
        Err(_) => d.iter().map(|&b| cp1252_char(b)).collect(),
    }
}

/// Trim, drop NULs and control characters, collapse inner whitespace, cap the length.
pub fn clean(s: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut space = false;
    for c in s.chars() {
        if c == '\0' {
            continue;
        }
        if c.is_whitespace() || c.is_control() {
            space = !out.is_empty();
            continue;
        }
        if space {
            out.push(' ');
            space = false;
        }
        out.push(c);
        if out.chars().count() >= max_chars {
            break;
        }
    }
    out
}

pub fn put(m: &mut std::collections::BTreeMap<String, String>, k: &str, v: &str) {
    let v = clean(v, 200);
    if !v.is_empty() && !m.contains_key(k) {
        m.insert(k.to_string(), v);
    }
}

// -------------------------------------------------------------------------------------- dates

/// Days since 1970-01-01 -> (y, m, d).
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Unix seconds -> "YYYY-MM-DD HH:MM:SS" (UTC). None when implausible (before 1971 or after 2100).
pub fn fmt_unix(secs: i64) -> Option<String> {
    if !(31_536_000..4_102_444_800).contains(&secs) {
        return None;
    }
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let t = secs.rem_euclid(86_400);
    Some(format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", t / 3600, t / 60 % 60, t % 60))
}

/// Normalise "2024:05:01 14:22:10", "2024-05-01T14:22:10Z", "D:20240501142210+02'00'",
/// "20240501T142210" to "2024-05-01 14:22:10" (or just the date when that's all there is).
pub fn norm_date(s: &str) -> Option<String> {
    let s = s.trim().trim_start_matches("D:");
    let digits: Vec<u32> = s.chars().filter(|c| c.is_ascii_digit()).map(|c| c.to_digit(10).unwrap()).collect();
    let num = |a: usize, b: usize| -> Option<u32> {
        if digits.len() >= b {
            Some(digits[a..b].iter().fold(0, |x, &d| x * 10 + d))
        } else {
            None
        }
    };
    let y = num(0, 4)?;
    if !(1900..=2100).contains(&y) {
        return None;
    }
    let (mo, d) = (num(4, 6), num(6, 8));
    let (mo, d) = match (mo, d) {
        (Some(mo), Some(d)) if (1..=12).contains(&mo) && (1..=31).contains(&d) => (mo, d),
        (Some(mo), None) if (1..=12).contains(&mo) => return Some(format!("{y:04}-{mo:02}")),
        (None, None) => return Some(format!("{y:04}")),
        _ => return None,
    };
    match (num(8, 10), num(10, 12), num(12, 14)) {
        (Some(h), Some(mi), sec) if h < 24 && mi < 60 => Some(format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{:02}", sec.unwrap_or(0).min(59))),
        _ => Some(format!("{y:04}-{mo:02}-{d:02}")),
    }
}

pub fn fmt_secs(s: f64) -> Option<String> {
    if !s.is_finite() || s <= 0.0 || s > 1.0e7 {
        return None;
    }
    Some(format!("{:.1}", s).trim_end_matches(".0").to_string())
}

// ------------------------------------------------------------------------------ random access

/// Random access to a file's bytes, either in memory or on the scan source.
pub trait RandomRead {
    fn size(&self) -> u64;
    /// Read at `pos`; returns bytes read (short at the end, 0 on error).
    fn read_at(&self, pos: u64, buf: &mut [u8]) -> usize;
    fn read_vec(&self, pos: u64, len: usize) -> Vec<u8> {
        let n = (len as u64).min(self.size().saturating_sub(pos)) as usize;
        let mut v = vec![0u8; n];
        let got = self.read_at(pos, &mut v);
        v.truncate(got);
        v
    }
}

/// In-memory bytes (`&data` where `data: &[u8]`, or `&vec.as_slice()`).
impl RandomRead for &[u8] {
    fn size(&self) -> u64 {
        self.len() as u64
    }
    fn read_at(&self, pos: u64, buf: &mut [u8]) -> usize {
        if pos >= self.len() as u64 {
            return 0;
        }
        let p = pos as usize;
        let n = buf.len().min(self.len() - p);
        buf[..n].copy_from_slice(&self[p..p + n]);
        n
    }
}

/// A found file read through `fileread` (extents, resident data, live path).
pub struct FileRead<'a> {
    pub src: Option<&'a dyn BlockSource>,
    pub file: &'a FoundFile,
    /// Set when any byte came from an unreadable sector.
    pub bad: Cell<bool>,
}

impl<'a> FileRead<'a> {
    pub fn new(src: Option<&'a dyn BlockSource>, file: &'a FoundFile) -> Self {
        FileRead { src, file, bad: Cell::new(false) }
    }
}

impl RandomRead for FileRead<'_> {
    fn size(&self) -> u64 {
        self.file.size
    }
    fn read_at(&self, pos: u64, buf: &mut [u8]) -> usize {
        let mut got = 0;
        while got < buf.len() {
            match crate::fileread::read_at(self.src, self.file, pos + got as u64, &mut buf[got..]) {
                Ok((0, _)) | Err(_) => break,
                Ok((n, bad)) => {
                    if bad {
                        self.bad.set(true);
                    }
                    got += n;
                }
            }
        }
        got
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_normalise() {
        assert_eq!(norm_date("2024:05:01 14:22:10").as_deref(), Some("2024-05-01 14:22:10"));
        assert_eq!(norm_date("D:20240501142210+02'00'").as_deref(), Some("2024-05-01 14:22:10"));
        assert_eq!(norm_date("2024-05-01T14:22:10Z").as_deref(), Some("2024-05-01 14:22:10"));
        assert_eq!(norm_date("2019").as_deref(), Some("2019"));
        assert_eq!(norm_date("0000:00:00 00:00:00"), None);
        assert_eq!(fmt_unix(1_714_573_330).as_deref(), Some("2024-05-01 14:22:10"));
    }

    #[test]
    fn families_and_signatures() {
        assert_eq!(family("docx"), family("zip"));
        assert_eq!(family("cr2"), family("tif"));
        assert_ne!(family("wav"), family("avi"));
        assert_eq!(sig_matches(Kind::Jpeg, &[0xFF, 0xD8, 0xFF, 0xE0]), Some(true));
        assert_eq!(sig_matches(Kind::Jpeg, b"hello"), Some(false));
        assert_eq!(sig_matches(Kind::Text, b"hello"), None);
        assert_eq!(find(b"abcabd", b"abd"), Some(3));
        assert_eq!(rfind(b"abcabc", b"abc"), Some(3));
    }
}
