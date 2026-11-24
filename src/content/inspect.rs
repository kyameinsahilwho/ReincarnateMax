//! `inspect_file` logic as a pure function over a found file and its source: detected vs
//! extension type, header hex, parsed header facts, validation, metadata, preview kind.

use super::exif::jpeg_info;
use super::meta;
use super::util::*;
use super::validate::{self, mpeg_header};
use super::{Inspection, Validation};
use crate::device::source::{BlockSource, Source};
use crate::model::{flags, Condition, FoundFile};
use std::collections::BTreeMap;

/// How much of a file inspection reads.
pub const READ_CAP: u64 = 64 << 20;

pub fn preview_kind(type_id: &str) -> (&'static str, bool) {
    let id = type_id.to_ascii_lowercase();
    match kind(&id) {
        Kind::Jpeg | Kind::Png | Kind::Gif | Kind::Webp | Kind::Bmp | Kind::Ico | Kind::Svg | Kind::Avif => ("image", false),
        // WebView2 can't show these; the UI uses ?thumb=512.
        Kind::Tiff | Kind::Raw | Kind::Cr3 | Kind::Raf => ("image", true),
        Kind::Mp4 if matches!(id.as_str(), "m4a" | "m4b" | "m4p") => ("audio", false),
        Kind::Mp4 if matches!(id.as_str(), "mp4" | "m4v" | "mov" | "qt" | "3gp") => ("video", false),
        Kind::Mkv if id == "webm" => ("video", false),
        Kind::Ogg if id == "ogv" => ("video", false),
        Kind::Mp3 | Kind::Wav | Kind::Flac | Kind::Ogg | Kind::Aac => ("audio", false),
        Kind::Pdf => ("pdf", false),
        Kind::Ooxml | Kind::Odf | Kind::Epub | Kind::Rtf | Kind::Ole | Kind::Csv => ("document", false),
        Kind::Text | Kind::Html => ("text", false),
        _ => ("hex", false),
    }
}

fn hms(secs: f64) -> String {
    let s = secs.round() as u64;
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
    } else {
        format!("{}:{:02}", s / 60, s % 60)
    }
}

/// The type the content analysis should use.
pub fn effective_type(f: &FoundFile, head: &[u8]) -> (Option<&'static crate::formats::FileType>, Option<&'static crate::formats::FileType>, bool, String) {
    let detected = crate::formats::detect(head);
    let ext_type = crate::formats::by_ext(&f.ext());
    let claimed = ext_type.map(|t| t.id.to_string()).unwrap_or_else(|| f.type_id.clone());
    let own_ok = sig_matches(kind(&claimed), head) == Some(true);
    let mismatch = match (detected, ext_type) {
        (Some(d), Some(e)) => !own_ok && family(d.id) != family(e.id),
        _ => false,
    };
    let eff = if mismatch {
        detected.map(|d| d.id.to_string()).unwrap_or_default()
    } else if !f.type_id.is_empty() {
        f.type_id.clone()
    } else if let Some(e) = ext_type {
        e.id.to_string()
    } else {
        detected.map(|d| d.id.to_string()).unwrap_or_default()
    };
    (detected, ext_type, mismatch, eff)
}

/// Inspect a file. `arc` (the same source as `src`) lets ZIP validation stream files larger than
/// the read cap.
pub fn inspect(src: Option<&dyn BlockSource>, arc: Option<Source>, f: &FoundFile) -> Inspection {
    let rr = FileRead::new(src, f);
    let data = rr.read_vec(0, f.size.min(READ_CAP) as usize);
    let complete = data.len() as u64 >= f.size;
    let head = &data[..data.len().min(4096)];
    let (detected, ext_type, mismatch, eff) = effective_type(f, head);

    let mut m = super::extract_meta(&eff, &data);
    let k = kind(&eff);
    if !complete {
        match k {
            Kind::Mp4 if !m.contains_key("duration") => {
                if let Some(moov) = super::bmff::find_moov(&rr) {
                    super::bmff::moov_info(&moov).fill(&mut m);
                }
            }
            Kind::Pdf => {
                let tail = rr.read_vec(f.size.saturating_sub(1 << 20), 1 << 20);
                for (key, v) in meta::extract("pdf", &tail) {
                    m.entry(key).or_insert(v);
                }
            }
            Kind::Mp3 => {
                let tail = rr.read_vec(f.size.saturating_sub(128), 128);
                for (key, v) in meta::extract("mp3", &tail) {
                    m.entry(key).or_insert(v);
                }
            }
            _ => {}
        }
    }

    let streams = arc.is_some() || f.live_path.is_some() || f.resident.is_some();
    let validation = if matches!(k, Kind::Ooxml | Kind::Odf | Kind::Epub | Kind::Zip) && !complete && streams {
        let mut reader = crate::fileread::FileReader::new(arc, f.clone());
        let v = validate::validate_with(&eff, &rr, &data, Some(&mut reader));
        if reader.hit_bad_sectors {
            rr.bad.set(true);
        }
        v
    } else {
        validate::validate_with(&eff, &rr, &data, None)
    };

    let fields = header_fields(k, &data, &m, f.size);
    let (pk, thumb_only) = preview_kind(&eff);
    Inspection {
        detected_type: detected.map(|t| t.id.to_string()),
        detected_label: detected.map(|t| t.label.to_string()),
        ext_type: ext_type.map(|t| t.id.to_string()),
        mismatch,
        header_hex: hex_spaced(&data[..data.len().min(64)]),
        fields,
        validation,
        meta: m,
        preview_kind: pk.to_string(),
        bad_sectors: rr.bad.get() || f.flags & flags::BAD_SECTORS != 0,
        thumb_only,
    }
}

/// The verdict to store after an inspection, if it changes anything: Good when it decodes,
/// Partial when it's damaged.
pub fn verdict_change(current: Condition, v: &Validation) -> Option<Condition> {
    match v.condition {
        Condition::Good if !matches!(current, Condition::Excellent | Condition::Good) => Some(Condition::Good),
        Condition::Partial if current != Condition::Partial => Some(Condition::Partial),
        _ => None,
    }
}

fn add(fields: &mut Vec<(String, String)>, k: &str, v: impl Into<String>) {
    let v = v.into();
    if !v.is_empty() && !fields.iter().any(|(x, _)| x == k) {
        fields.push((k.to_string(), v));
    }
}

fn from_meta(fields: &mut Vec<(String, String)>, m: &BTreeMap<String, String>, keys: &[(&str, &str)]) {
    for (mk, label) in keys {
        if let Some(v) = m.get(*mk) {
            add(fields, label, v.clone());
        }
    }
}

fn dims(fields: &mut Vec<(String, String)>, m: &BTreeMap<String, String>) {
    if let (Some(w), Some(h)) = (m.get("width"), m.get("height")) {
        add(fields, "Dimensions", format!("{w} × {h}"));
    }
}

fn duration(fields: &mut Vec<(String, String)>, m: &BTreeMap<String, String>) {
    if let Some(d) = m.get("duration").and_then(|d| d.parse::<f64>().ok()) {
        add(fields, "Duration", hms(d));
    }
}

pub fn header_fields(k: Kind, d: &[u8], m: &BTreeMap<String, String>, size: u64) -> Vec<(String, String)> {
    let mut f = Vec::new();
    match k {
        Kind::Jpeg => {
            dims(&mut f, m);
            if let Some(j) = jpeg_info(d) {
                add(&mut f, "Progressive", if j.progressive() { "Yes" } else { "No" });
                add(&mut f, "End marker", if j.eoi_end.is_some() { "Present" } else { "Missing" });
            }
            from_meta(&mut f, m, &[("camera", "Camera"), ("taken", "Taken"), ("orientation", "Orientation"), ("exposure", "Exposure"), ("fNumber", "Aperture"), ("iso", "ISO"), ("focalLength", "Focal length"), ("gps", "Location"), ("software", "Software")]);
        }
        Kind::Png => {
            dims(&mut f, m);
            if d.len() >= 29 && &d[12..16] == b"IHDR" {
                add(&mut f, "Bit depth", d[24].to_string());
                let ct = match d[25] {
                    0 => "Grayscale",
                    2 => "RGB",
                    3 => "Palette",
                    4 => "Grayscale + alpha",
                    6 => "RGBA",
                    _ => "Unknown",
                };
                add(&mut f, "Color type", ct);
                add(&mut f, "Interlaced", if d[28] == 1 { "Yes" } else { "No" });
            }
            from_meta(&mut f, m, &[("title", "Title"), ("author", "Author"), ("software", "Software"), ("created", "Created")]);
        }
        Kind::Gif | Kind::Bmp | Kind::Webp | Kind::Psd | Kind::Ico | Kind::Tiff | Kind::Raw | Kind::Cr3 | Kind::Raf | Kind::Heic | Kind::Avif => {
            dims(&mut f, m);
            from_meta(&mut f, m, &[("camera", "Camera"), ("taken", "Taken"), ("exposure", "Exposure"), ("fNumber", "Aperture"), ("iso", "ISO"), ("gps", "Location")]);
        }
        Kind::Pdf => {
            if let Some(i) = find(&d[..d.len().min(1024)], b"%PDF-") {
                let v: String = d[i + 5..].iter().take(4).take_while(|c| c.is_ascii_digit() || **c == b'.').map(|&c| c as char).collect();
                add(&mut f, "PDF version", v);
            }
            from_meta(&mut f, m, &[("pages", "Pages"), ("title", "Title"), ("author", "Author"), ("software", "Made with"), ("created", "Created"), ("modified", "Modified")]);
            if find(&d[d.len().saturating_sub(1 << 20)..], b"/Encrypt").is_some() {
                add(&mut f, "Encrypted", "Yes");
            }
        }
        Kind::Mp4 => {
            if let Some(ftyp) = super::bmff::child(d, b"ftyp") {
                add(&mut f, "Brand", super::bmff::brand(ftyp).unwrap_or_default());
            }
            duration(&mut f, m);
            dims(&mut f, m);
            from_meta(&mut f, m, &[("created", "Created"), ("title", "Title"), ("artist", "Artist"), ("album", "Album")]);
        }
        Kind::Mkv => {
            duration(&mut f, m);
            dims(&mut f, m);
            from_meta(&mut f, m, &[("title", "Title"), ("created", "Created"), ("software", "Made with")]);
        }
        Kind::Ooxml | Kind::Odf | Kind::Epub | Kind::Zip => {
            if let Some(c) = super::zipscan::Container::open(d) {
                add(&mut f, "Entries", c.len().to_string());
                if let super::zipscan::Container::Local(..) = c {
                    add(&mut f, "Central directory", "Missing");
                }
            }
            from_meta(&mut f, m, &[("title", "Title"), ("author", "Author"), ("pages", "Pages"), ("slides", "Slides"), ("words", "Words"), ("created", "Created"), ("modified", "Modified"), ("software", "Made with")]);
        }
        Kind::Mp3 => {
            let (frames, _, audio, first) = validate::mp3_scan(&d[..d.len().min(8 << 20)]);
            if let Some(h) = first {
                let vbr = meta::mp3_vbr_duration(d);
                add(&mut f, "Bitrate", if vbr.is_some() { format!("{} kbps (variable)", h.bitrate) } else { format!("{} kbps", h.bitrate) });
                add(&mut f, "Sample rate", format!("{:.1} kHz", h.sample_rate as f64 / 1000.0).replace(".0 ", " "));
                add(&mut f, "Channels", if h.channels == 1 { "Mono" } else { "Stereo" });
                let layer = ["", "I", "II", "III"][h.layer as usize];
                let ver = if h.version == 25 { "2.5".to_string() } else { h.version.to_string() };
                add(&mut f, "Format", format!("MPEG-{ver} Layer {layer}"));
                if let Some(s) = vbr {
                    add(&mut f, "Duration", hms(s));
                } else if h.bitrate > 0 && frames > 0 {
                    let audio_bytes = size.saturating_sub((d.len() - audio.min(d.len())) as u64);
                    add(&mut f, "Duration", format!("about {}", hms(audio_bytes as f64 * 8.0 / (h.bitrate as f64 * 1000.0))));
                }
            }
            if d.starts_with(b"ID3") && d.len() > 4 {
                add(&mut f, "ID3 tag", format!("v2.{}", d[3]));
            }
            duration(&mut f, m);
            from_meta(&mut f, m, &[("title", "Title"), ("artist", "Artist"), ("album", "Album"), ("year", "Year")]);
        }
        Kind::Wav => {
            if let Some(p) = find(&d[..d.len().min(65536)], b"fmt ") {
                let ch = le16(d, p + 10).unwrap_or(0);
                add(&mut f, "Sample rate", format!("{} Hz", le32(d, p + 12).unwrap_or(0)));
                add(&mut f, "Channels", ch.to_string());
                add(&mut f, "Bits per sample", le16(d, p + 22).unwrap_or(0).to_string());
            }
            duration(&mut f, m);
            from_meta(&mut f, m, &[("title", "Title"), ("artist", "Artist")]);
        }
        Kind::Flac => {
            let p = id3_skip(d).unwrap_or(0) + 4;
            if d.get(p + 4..p + 4 + 18).is_some() && d[p] & 0x7F == 0 {
                let b = &d[p + 4..];
                let v = be64(b, 10).unwrap_or(0);
                add(&mut f, "Sample rate", format!("{} Hz", v >> 44));
                add(&mut f, "Channels", (((v >> 41) & 7) + 1).to_string());
                add(&mut f, "Bits per sample", (((v >> 36) & 31) + 1).to_string());
            }
            duration(&mut f, m);
            from_meta(&mut f, m, &[("title", "Title"), ("artist", "Artist"), ("album", "Album"), ("year", "Year")]);
        }
        Kind::Ogg | Kind::Avi | Kind::Aac => {
            duration(&mut f, m);
            dims(&mut f, m);
            from_meta(&mut f, m, &[("title", "Title"), ("artist", "Artist"), ("album", "Album")]);
        }
        Kind::Sqlite => from_meta(&mut f, m, &[("pageSize", "Page size"), ("dbPages", "Pages")]),
        Kind::Pe => from_meta(&mut f, m, &[("company", "Company"), ("product", "Product"), ("title", "Description"), ("version", "Version")]),
        Kind::Ole => from_meta(&mut f, m, &[("title", "Title"), ("author", "Author"), ("software", "Made with")]),
        _ => from_meta(&mut f, m, &[("title", "Title"), ("author", "Author"), ("duration", "Duration (s)")]),
    }
    if let Some(mp) = mpeg_header(d).filter(|_| k == Kind::Aac) {
        add(&mut f, "Sample rate", format!("{} Hz", mp.sample_rate));
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::source::MemSource;
    use crate::model::Extent;

    #[test]
    fn inspects_a_jpeg_on_a_source() {
        let j = super::super::validate::tests::jpeg_bytes(64, 32);
        let mut disk = vec![0u8; 4096];
        disk.extend_from_slice(&j);
        let m = MemSource::new(disk);
        let f = FoundFile { name: "x.jpg".into(), size: j.len() as u64, type_id: "jpg".into(), extents: vec![Extent { offset: 4096, len: j.len() as u64 }], ..Default::default() };
        let ins = inspect(Some(&m), None, &f);
        assert_eq!(ins.detected_type.as_deref(), Some("jpg"));
        assert!(!ins.mismatch);
        assert!(ins.header_hex.starts_with("FF D8 FF"));
        assert_eq!(ins.validation.condition, Condition::Good);
        assert_eq!(ins.preview_kind, "image");
        assert!(ins.fields.iter().any(|(k, v)| k == "Dimensions" && v == "64 × 32"));
        assert!(!ins.bad_sectors);
        assert_eq!(verdict_change(Condition::Unknown, &ins.validation), Some(Condition::Good));
        assert_eq!(verdict_change(Condition::Excellent, &ins.validation), None);

        // Same bytes named .pdf: mismatch, analysed as JPEG.
        let f2 = FoundFile { name: "x.pdf".into(), type_id: String::new(), ..f.clone() };
        let ins = inspect(Some(&m), None, &f2);
        assert!(ins.mismatch);
        assert_eq!(ins.ext_type.as_deref(), Some("pdf"));
        assert_eq!(ins.preview_kind, "image");

        // Unreadable sectors inside it.
        let mut m2 = MemSource::new(m.data.clone());
        m2.bad = vec![(4096 + 512, 4096 + 1024)];
        let ins = inspect(Some(&m2), None, &f);
        assert!(ins.bad_sectors);
        assert_eq!(verdict_change(Condition::Good, &ins.validation), if ins.validation.condition == Condition::Partial { Some(Condition::Partial) } else { None });
    }

    #[test]
    fn kinds() {
        assert_eq!(preview_kind("mov").0, "video");
        assert_eq!(preview_kind("m4a").0, "audio");
        assert_eq!(preview_kind("cr2"), ("image", true));
        assert_eq!(preview_kind("docx").0, "document");
        assert_eq!(preview_kind("log").0, "text");
        assert_eq!(preview_kind("heic").0, "hex");
        assert_eq!(hms(3725.0), "1:02:05");
    }
}
