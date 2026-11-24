//! Signature families and the per-sector dispatch that runs on every 512-byte boundary.

use crate::formats::sniff::*;

/// A signature family: one header check, one structure parser, possibly several specific types
/// (decided from the content when the file is rebuilt).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub(crate) enum Fam {
    Jpeg,
    Png,
    Gif,
    Bmp,
    Riff,
    Tiff,
    Raf,
    X3f,
    Psd,
    Ico,
    Bmff,
    Ebml,
    Asf,
    Flv,
    MpegPs,
    MpegTs,
    Mts,
    Mp3,
    Flac,
    Ogg,
    Aac,
    Amr,
    Aiff,
    Midi,
    Pdf,
    Rtf,
    Eml,
    Pst,
    Ole,
    Zip,
    SevenZ,
    Rar,
    Gzip,
    Bz2,
    Xz,
    Tar,
    Cab,
    Iso,
    Sqlite,
    Pe,
}

pub(crate) const NFAM: usize = Fam::Pe as usize + 1;

pub(crate) const ALL: [Fam; NFAM] = [
    Fam::Jpeg,
    Fam::Png,
    Fam::Gif,
    Fam::Bmp,
    Fam::Riff,
    Fam::Tiff,
    Fam::Raf,
    Fam::X3f,
    Fam::Psd,
    Fam::Ico,
    Fam::Bmff,
    Fam::Ebml,
    Fam::Asf,
    Fam::Flv,
    Fam::MpegPs,
    Fam::MpegTs,
    Fam::Mts,
    Fam::Mp3,
    Fam::Flac,
    Fam::Ogg,
    Fam::Aac,
    Fam::Amr,
    Fam::Aiff,
    Fam::Midi,
    Fam::Pdf,
    Fam::Rtf,
    Fam::Eml,
    Fam::Pst,
    Fam::Ole,
    Fam::Zip,
    Fam::SevenZ,
    Fam::Rar,
    Fam::Gzip,
    Fam::Bz2,
    Fam::Xz,
    Fam::Tar,
    Fam::Cab,
    Fam::Iso,
    Fam::Sqlite,
    Fam::Pe,
];

impl Fam {
    /// Formats that commonly hold other files at sector-aligned offsets.
    pub fn is_container(self) -> bool {
        use Fam::*;
        matches!(self, Zip | Tar | Iso | Pdf | Ole | Pst | Rar | Bmff | Riff | Ebml | Asf | Tiff | Pe | Cab | SevenZ)
    }

    /// Stream formats whose signature also matches on many sectors inside one file (every TS
    /// packet or MPEG-PS pack, MP3/AAC frames that happen to start on a sector).
    pub fn is_stream(self) -> bool {
        use Fam::*;
        matches!(self, MpegPs | MpegTs | Mts | Mp3 | Aac)
    }

    pub fn from_u8(v: u8) -> Option<Fam> {
        ALL.get(v as usize).copied()
    }

    /// The type ids this family can produce; the first is the default.
    pub fn types(self) -> &'static [&'static str] {
        use Fam::*;
        match self {
            Jpeg => &["jpg"],
            Png => &["png"],
            Gif => &["gif"],
            Bmp => &["bmp"],
            Riff => &["avi", "wav", "webp"],
            Tiff => &["tiff", "cr2", "nef", "nrw", "arw", "srf", "sr2", "dng", "orf", "rw2", "pef"],
            Raf => &["raf"],
            X3f => &["x3f"],
            Psd => &["psd"],
            Ico => &["ico"],
            Bmff => &["mp4", "m4v", "mov", "3gp", "m4a", "heic", "avif", "cr3"],
            Ebml => &["mkv", "webm"],
            Asf => &["wmv", "wma"],
            Flv => &["flv"],
            MpegPs => &["mpg"],
            MpegTs => &["ts"],
            Mts => &["mts"],
            Mp3 => &["mp3"],
            Flac => &["flac"],
            Ogg => &["ogg", "opus"],
            Aac => &["aac"],
            Amr => &["amr"],
            Aiff => &["aiff"],
            Midi => &["mid"],
            Pdf => &["pdf"],
            Rtf => &["rtf"],
            Eml => &["eml"],
            Pst => &["pst"],
            Ole => &["doc", "xls", "ppt", "msg"],
            Zip => &["zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub"],
            SevenZ => &["7z"],
            Rar => &["rar"],
            Gzip => &["gz"],
            Bz2 => &["bz2"],
            Xz => &["xz"],
            Tar => &["tar"],
            Cab => &["cab"],
            Iso => &["iso"],
            Sqlite => &["sqlite"],
            Pe => &["exe", "dll"],
        }
    }
}

/// Bytes past a sector start the dispatch may look at (TS packets, MP3/AAC frames, PE headers).
pub(crate) const LOOK: usize = 20 * 1024;

/// Is there a first byte worth a closer look? (Position-independent checks are separate.)
static FIRST: [bool; 256] = {
    let mut t = [false; 256];
    let s: &[u8] = b"\xFF\x89GBRIMF\x00\x1A\x30\x47fO#%{!\xD0P7\x1F\xFDS8DX\x01Cs";
    let mut i = 0;
    while i < s.len() {
        t[s[i] as usize] = true;
        i += 1;
    }
    t
};

/// What starts at `p[0]` (a sector boundary)? Returns the family and the offset of the file start
/// relative to `p` (ISO images are recognised by their volume descriptor at 0x8000).
#[inline]
pub(crate) fn sniff(p: &[u8]) -> Option<(Fam, i64)> {
    if p.len() < 16 {
        return None;
    }
    // Position-independent checks first (cheap loads).
    if &p[4..8] == b"ftyp" {
        if ftyp_kind(p).is_some() {
            return Some((Fam::Bmff, 0));
        }
    }
    if p.len() > 263 && p[257] == b'u' && tar_ok(p) {
        return Some((Fam::Tar, 0));
    }
    if p[4] == 0x47 && ts_ok(p, 4, 192, 4) {
        return Some((Fam::Mts, 0));
    }
    if !FIRST[p[0] as usize] {
        return None;
    }
    let f = match p[0] {
        0xFF => {
            if p[1] == 0xD8 && p[2] == 0xFF && p[3] >= 0xC0 && p[3] != 0xFF {
                Fam::Jpeg
            } else if p[1] & 0xF6 == 0xF0 {
                if adts_frames(p, 2) {
                    Fam::Aac
                } else {
                    return None;
                }
            } else if p[1] & 0xE0 == 0xE0 && mp3_frames(p, 3) {
                Fam::Mp3
            } else {
                return None;
            }
        }
        0x89 if p.starts_with(b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR") => Fam::Png,
        b'G' if (p.starts_with(b"GIF89a") || p.starts_with(b"GIF87a")) => Fam::Gif,
        b'B' => {
            if bmp_ok(p) {
                Fam::Bmp
            } else if p.starts_with(b"BZh") && (b'1'..=b'9').contains(&p[3]) && (at(p, 4, &[0x31, 0x41, 0x59, 0x26, 0x53, 0x59]) || at(p, 4, &[0x17, 0x72, 0x45, 0x38, 0x50, 0x90])) {
                Fam::Bz2
            } else {
                return None;
            }
        }
        b'R' => {
            if (p.starts_with(b"RIFF") || p.starts_with(b"RF64")) && matches!(&p[8..12], b"AVI " | b"WAVE" | b"WEBP") {
                Fam::Riff
            } else if p.starts_with(b"Rar!\x1a\x07\x00") || p.starts_with(b"Rar!\x1a\x07\x01\x00") {
                Fam::Rar
            } else if p.starts_with(b"Return-Path:") || p.starts_with(b"Received:") {
                eml(p)?
            } else {
                return None;
            }
        }
        b'I' => {
            if p.starts_with(b"II*\0") || p.starts_with(b"IIRO") || p.starts_with(b"IIRS") || p.starts_with(b"IIU\0") {
                tiff(p, true)?
            } else if id3_len(p).is_some() {
                Fam::Mp3
            } else {
                return None;
            }
        }
        b'M' => {
            if p.starts_with(b"MM\0*") || p.starts_with(b"MMOR") {
                tiff(p, false)?
            } else if p.starts_with(b"MThd\0\0\0\x06") && p[8] == 0 && p[9] <= 2 {
                Fam::Midi
            } else if p.starts_with(b"MSCF\0\0\0\0") && p[24] == 3 && p[25] == 1 {
                Fam::Cab
            } else if p.starts_with(b"MZ") && pe_ok(p).is_some() {
                Fam::Pe
            } else if p.starts_with(b"Message-ID:") || p.starts_with(b"MIME-Version:") {
                eml(p)?
            } else {
                return None;
            }
        }
        b'F' => {
            if p.starts_with(b"FUJIFILMCCD-RAW ") {
                Fam::Raf
            } else if p.starts_with(b"FOVb") && p[4] <= 4 && p[6] <= 4 {
                Fam::X3f
            } else if p.starts_with(b"FLV\x01") && p[4] & 0xFA == 0 && be32(p, 5) == Some(9) && be32(p, 9) == Some(0) {
                Fam::Flv
            } else if p.starts_with(b"FORM") && (at(p, 8, b"AIFF") || at(p, 8, b"AIFC")) {
                Fam::Aiff
            } else if p.starts_with(b"From: ") {
                eml(p)?
            } else {
                return None;
            }
        }
        0x00 => {
            if p[1] != 0 || p[2] > 2 {
                return None;
            }
            if mpeg_ps_ok(p) {
                Fam::MpegPs
            } else if ico_ok(p) {
                Fam::Ico
            } else {
                return None;
            }
        }
        0x1A if p.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) && (p[4] & 0xF0) != 0 => Fam::Ebml,
        0x30 if p.starts_with(&ASF_HEADER) => Fam::Asf,
        0x47 if ts_ok(p, 0, 188, 4) => Fam::MpegTs,
        b'f' if p.starts_with(b"fLaC") && p[4] & 0x7F == 0 && p[5..8] == [0, 0, 34] => Fam::Flac,
        b'O' if p.starts_with(b"OggS\0\x02") => Fam::Ogg,
        b'#' if p.starts_with(b"#!AMR\n") || p.starts_with(b"#!AMR-WB\n") => Fam::Amr,
        b'%' if p.starts_with(b"%PDF-") && p[5].is_ascii_digit() => Fam::Pdf,
        b'{' if p.starts_with(b"{\\rtf") => Fam::Rtf,
        b'!' if p.starts_with(b"!BDN") && at(p, 8, b"SM") => Fam::Pst,
        0xD0 if p.starts_with(&OLE) && p[0x1C] == 0xFE && p[0x1D] == 0xFF && matches!(p[0x1E], 9 | 12) => Fam::Ole,
        b'P' => {
            if p.starts_with(b"PK\x03\x04") && p[5] == 0 && p[4] < 100 && le16(p, 26).is_some_and(|n| (1..=1024).contains(&n)) {
                Fam::Zip
            } else {
                return None;
            }
        }
        b'7' if p.starts_with(&[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C]) && p[6] == 0 => Fam::SevenZ,
        0x1F if p[1] == 0x8B && p[2] == 8 && p[3] & 0xE0 == 0 => Fam::Gzip,
        0xFD if p.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0, 0]) && p[7] & 0xF0 == 0 => Fam::Xz,
        b'S' if sqlite_ok(p) => Fam::Sqlite,
        b'8' if p.starts_with(b"8BPS") && matches!(p[5], 1 | 2) && p[4] == 0 && p[6..12] == [0; 6] => Fam::Psd,
        b'D' | b'X' if p.starts_with(b"Delivered-To:") || p.starts_with(b"X-") || p.starts_with(b"DKIM-Signature:") => eml(p)?,
        0x01 if p.starts_with(b"\x01CD001\x01") => return Some((Fam::Iso, -0x8000)),
        _ => return None,
    };
    Some((f, 0))
}

fn tiff(p: &[u8], le: bool) -> Option<Fam> {
    let off = if le { le32(p, 4)? } else { be32(p, 4)? };
    if off < 8 || off > 256 << 20 {
        return None;
    }
    Some(Fam::Tiff)
}

fn eml(p: &[u8]) -> Option<Fam> {
    let n = p.len().min(4096);
    let n = p[..n].iter().position(|&b| b == 0).unwrap_or(n);
    (crate::formats::detect(&p[..n]).map(|t| t.id) == Some("eml")).then_some(Fam::Eml)
}
