//! Preview engine and content intelligence: quick condition assessment, format validation
//! ("does it decode?"), embedded metadata (EXIF, ID3, Office, PDF, MP4), suggested names for carved
//! files, repair attempts, document text, thumbnails, hex reads, and the `maxfile://` protocol
//! that streams found files to the WebView (with Range support for audio/video).
//! OWNER: content agent.
//!
//! Layout: `assess` (post-scan check), `meta` (+ `exif`, `bmff`, `zipscan`, `xml`), `validate`,
//! `repair`, `docs` (document text), `thumb` (thumbnails + cache), `protocol`, `inspect`.
//! Everything below the commands is pure (byte slices / `BlockSource` + `FoundFile`).

mod assess;
mod bmff;
mod docs;
mod exif;
mod inspect;
mod meta;
mod protocol;
mod repair;
mod thumb;
mod util;
mod validate;
mod xml;
mod zipscan;

use crate::device::source::{BlockSource, Source};
use crate::model::{flags, Condition, FoundFile};
use serde::Serialize;
use std::collections::BTreeMap;

/// Cheap check after a scan (one small read): header vs type, all-zero (TRIM) first sector,
/// overlap with live data. Updates condition, note, type_id (when the content says otherwise) and
/// flags (EXT_MISMATCH, ZEROED, BAD_SECTORS). Must not take more than one ~4 KiB read per file.
/// The decision table is documented in `content/assess.rs`.
pub fn assess(src: &dyn BlockSource, f: &mut FoundFile) {
    assess::assess(Some(src), f)
}

/// Same as [`assess`] for files that don't need the scan source (resident / live path), or when
/// the source is unavailable.
#[allow(dead_code)] // public API for other modules
pub fn assess_opt(src: Option<&dyn BlockSource>, f: &mut FoundFile) {
    assess::assess(src, f)
}

fn guarded<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(fallback)
}

/// Metadata from content (`data` = the first bytes of the file, up to 1 MiB, or all of it).
/// Keys: camera, taken, width, height, orientation, gps, title, author, artist, album, year,
/// duration (seconds), pages, words, slides, created, modified, entries, software, company,
/// product, version, dbPages, pageSize, exposure, fNumber, iso, focalLength, lastModifiedBy.
pub fn extract_meta(type_id: &str, data: &[u8]) -> BTreeMap<String, String> {
    guarded(BTreeMap::new(), || meta::extract(type_id, data))
}

/// A readable name for a carved file from its metadata, without extension
/// ("2024-05-01 14.22.10 Canon EOS R6", "Quarterly report", "Artist - Title"). None = keep the
/// generated name.
#[allow(dead_code)] // public API for other modules
pub fn suggest_name(type_id: &str, meta: &BTreeMap<String, String>) -> Option<String> {
    meta::suggest_name(type_id, meta)
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Validation {
    pub condition: Condition,
    pub note: String,
    /// The preview shows the whole file (false: truncated / partly undecodable).
    pub complete: bool,
}

/// Full structural check of a whole file's bytes.
pub fn validate(type_id: &str, data: &[u8]) -> Validation {
    let fallback = Validation { condition: Condition::Unknown, note: validate::NOTE_UNCHECKABLE.into(), complete: true };
    guarded(fallback, || validate::validate_with(type_id, &data, data, None))
}

/// Try to repair damaged content (truncated JPEG/PNG, ZIP without central directory, PDF without
/// xref, MP4/WAV/AVI with wrong sizes). None = nothing to repair or not repairable. The result
/// passes `validate`.
pub fn repair(type_id: &str, data: &[u8]) -> Option<Vec<u8>> {
    guarded(None, || repair::repair(type_id, data))
}

/// Handler for the `maxfile` URI scheme, registered by main.rs with
/// `register_asynchronous_uri_scheme_protocol("maxfile", content::protocol)`.
pub fn protocol<R: tauri::Runtime>(ctx: tauri::UriSchemeContext<'_, R>, request: tauri::http::Request<Vec<u8>>, responder: tauri::UriSchemeResponder) {
    protocol::protocol(ctx, request, responder)
}

/// A JPEG thumbnail (≤ `px` square) of a found file's content, or None (no preview for the type).
#[allow(dead_code)] // public API for other modules
pub fn thumbnail(src: Option<&dyn BlockSource>, f: &FoundFile, px: u32) -> Option<Vec<u8>> {
    let rr = util::FileRead::new(src, f);
    guarded(None, || thumb::make(&f.type_id, &rr, px.clamp(16, 2048)))
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Inspection {
    pub detected_type: Option<String>,
    pub detected_label: Option<String>,
    /// Type implied by the name's extension.
    pub ext_type: Option<String>,
    pub mismatch: bool,
    /// First 64 bytes, hex with spaces.
    pub header_hex: String,
    /// Parsed header facts ("Dimensions", "Camera", "PDF version", "Brand", "Entries"…).
    pub fields: Vec<(String, String)>,
    pub validation: Validation,
    pub meta: BTreeMap<String, String>,
    /// How to show it: "image" | "video" | "audio" | "pdf" | "document" | "text" | "hex"
    pub preview_kind: String,
    /// Some sectors were unreadable (zeros in their place).
    pub bad_sectors: bool,
    /// The WebView can't display the original (TIFF, camera RAW): show `?thumb=512` instead.
    pub thumb_only: bool,
}

/// Open a session's file and, when its bytes live on the scan source, the source.
fn load(session: &str, id: i64) -> Result<(FoundFile, Option<Source>), String> {
    let f = crate::scan::store::get_file(session, id)?;
    let src = if f.live_path.is_none() && f.resident.is_none() { Some(crate::scan::store::open_session_source(session)?) } else { None };
    Ok((f, src))
}

async fn blocking<T: Send + 'static>(job: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(move || guarded(Err("MAX couldn't read this file.".to_string()), job))
        .await
        .map_err(|_| "Reading the file stopped unexpectedly.".to_string())?
}

/// Header inspection + validation (reads up to 64 MiB; larger files validate their first part).
/// Persists a changed verdict (Good if it decodes, Partial if damaged) and the metadata.
#[tauri::command]
pub async fn inspect_file(session_id: String, id: i64) -> Result<Inspection, String> {
    blocking(move || {
        let (f, src) = load(&session_id, id)?;
        let ins = inspect::inspect(src.as_deref(), src.clone(), &f);
        if let Some(c) = inspect::verdict_change(f.condition, &ins.validation) {
            let set = if ins.bad_sectors { flags::BAD_SECTORS } else { 0 };
            let _ = crate::scan::store::update_condition(&session_id, id, c, &ins.validation.note, set);
        }
        if !ins.meta.is_empty() {
            let _ = crate::scan::store::update_meta(&session_id, id, &ins.meta);
        }
        Ok(ins)
    })
    .await
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct DocPreview {
    /// "text" | "sheet" | "none"
    pub kind: String,
    pub text: Option<String>,
    pub sheets: Vec<Sheet>,
    pub truncated: bool,
    /// A caveat to show with the preview ("approximate text from an older Office file") or why
    /// there is nothing to show.
    pub note: Option<String>,
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Sheet {
    pub name: String,
    pub rows: Vec<Vec<String>>,
}

/// Document text from a file's bytes (pure; `complete` = `data` is the whole file).
#[allow(dead_code)] // public API for other modules
pub fn document_preview(type_id: &str, data: &[u8], complete: bool) -> DocPreview {
    guarded(docs::none("MAX couldn't read the text of this file."), || docs::preview(type_id, data, complete))
}

/// Text of DOCX/ODT/RTF/TXT/HTML/CSV, cells of XLSX/ODS (first 200 rows x 30 columns per sheet),
/// slide text of PPTX, approximate text of DOC/XLS/PPT. Text is capped at 200 KB.
#[tauri::command]
pub async fn preview_document(session_id: String, id: i64) -> Result<DocPreview, String> {
    blocking(move || {
        let (f, src) = load(&session_id, id)?;
        let rr = util::FileRead::new(src.as_deref(), &f);
        let data = util::RandomRead::read_vec(&rr, 0, f.size.min(inspect::READ_CAP) as usize);
        let (_, _, _, eff) = inspect::effective_type(&f, &data[..data.len().min(4096)]);
        Ok(document_preview(&eff, &data, data.len() as u64 >= f.size))
    })
    .await
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct FileBytes {
    pub offset: u64,
    pub size: u64,
    /// Base64.
    pub data: String,
    pub bad_sectors: bool,
}

/// Bytes of a found file for the hex viewer (max 64 KiB).
#[tauri::command]
pub async fn read_file_bytes(session_id: String, id: i64, offset: u64, length: u32) -> Result<FileBytes, String> {
    blocking(move || {
        use base64::Engine;
        let (f, src) = load(&session_id, id)?;
        let len = (length.min(64 * 1024) as u64).min(f.size.saturating_sub(offset)) as usize;
        let mut buf = vec![0u8; len];
        let (n, bad) = crate::fileread::read_at(src.as_deref(), &f, offset, &mut buf)?;
        buf.truncate(n);
        Ok(FileBytes { offset, size: f.size, data: base64::engine::general_purpose::STANDARD.encode(&buf), bad_sectors: bad })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every entry point over junk and over many truncations / corruptions of real samples:
    /// nothing may panic (the public wrappers catch panics; this calls the inner functions).
    #[test]
    fn hostile_inputs_never_panic() {
        let samples: Vec<(&str, Vec<u8>)> = vec![
            ("jpg", validate::tests::jpeg_bytes(48, 40)),
            ("png", validate::tests::png_bytes(30, 20)),
            ("zip", zipscan::tests::make_zip(&[("a.txt", b"aaaa aaaa"), ("word/document.xml", b"<w:p><w:t>x</w:t></w:p>")], true)),
            ("mp4", bmff::tests::sample_mp4(300)),
            ("wav", validate::tests::wav(8000, 600)),
            ("pdf", b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R /Info 1 0 R >>\nstartxref\n9\n%%EOF\n".to_vec()),
        ];
        let types = ["jpg", "png", "gif", "webp", "bmp", "tiff", "cr2", "cr3", "raf", "pdf", "docx", "xlsx", "pptx", "odt", "ods", "epub", "zip", "mp4", "mov", "mp3", "wav", "avi", "flac", "ogg", "mkv", "sqlite", "exe", "rtf", "doc", "txt", "html", "csv"];
        let mut x = 7u32;
        let junk: Vec<u8> = (0..3000)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                (x >> 16) as u8
            })
            .collect();
        let mut inputs: Vec<Vec<u8>> = vec![Vec::new(), junk.clone(), vec![0xFF; 600], vec![0; 600]];
        for (_, s) in &samples {
            for cut in [1, 2, 4, 8, 12, 30, 60, 100, s.len() / 3, s.len() / 2, s.len() - 1] {
                inputs.push(s[..cut.min(s.len())].to_vec());
            }
            let mut c = s.clone();
            for i in (7..c.len()).step_by(13) {
                c[i] ^= 0xA5;
            }
            inputs.push(c);
            inputs.push([&s[..s.len() / 2], &junk[..]].concat());
        }
        for d in &inputs {
            for t in types {
                let _ = meta::extract(t, d);
                let _ = validate::validate_with(t, &d.as_slice(), d, None);
                let _ = repair::repair(t, d);
                let _ = docs::preview(t, d, true);
                let _ = thumb::make(t, &d.as_slice(), 64);
                let mut f = FoundFile { name: format!("x.{t}"), size: d.len() as u64, resident: Some(d.clone()), condition: Condition::Unknown, ..Default::default() };
                assess::assess(None, &mut f);
            }
        }
    }
}
