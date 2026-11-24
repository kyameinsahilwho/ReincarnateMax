//! File-type registry: every type MAX knows, its category, extensions, MIME type and header
//! signature, plus content-based detection. Used by every engine and the UI filters.
//! OWNER: carve agent (extends the table; keep the API).

mod detect;
pub(crate) mod sniff;
mod table;

use crate::model::Category;
use serde::Serialize;
use table::T;

#[derive(Serialize, Clone, Copy, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FileType {
    /// Stable id, also the preferred extension: "jpg", "docx", "mp4".
    pub id: &'static str,
    /// "JPEG image"
    pub label: &'static str,
    pub category: Category,
    /// Extensions that mean this type (lowercase, no dot), the id first.
    pub exts: &'static [&'static str],
    pub mime: &'static str,
}

/// All known types.
pub fn all() -> &'static [FileType] {
    T
}

pub fn by_id(id: &str) -> Option<&'static FileType> {
    T.iter().find(|t| t.id == id)
}

/// Type for a file extension (any case, no dot).
pub fn by_ext(ext: &str) -> Option<&'static FileType> {
    let e = ext.to_ascii_lowercase();
    T.iter().find(|t| t.exts.contains(&e.as_str()))
}

/// Category of a type id (unknown ids -> Other).
pub fn category_of(id: &str) -> Category {
    by_id(id).map(|t| t.category).unwrap_or(Category::Other)
}

/// Recognise a type from the first bytes of content (pass at least 64, ideally 4096 bytes; ISO
/// images need 0x8006). Text kinds (txt/csv/html/xml/json/svg/eml) are recognised heuristically.
pub fn detect(header: &[u8]) -> Option<&'static FileType> {
    detect::detect_id(header).and_then(by_id)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileTypeInfo {
    pub id: &'static str,
    pub label: &'static str,
    pub category: Category,
    pub exts: &'static [&'static str],
    /// Deep scans can find it by signature.
    pub carvable: bool,
}

/// Every type, for the UI's filters and the deep-scan type picker.
#[tauri::command]
pub fn list_file_types() -> Vec<FileTypeInfo> {
    T.iter()
        .map(|t| FileTypeInfo { id: t.id, label: t.label, category: t.category, exts: t.exts, carvable: crate::carve::is_carvable(t.id) })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_consistent() {
        assert!(T.len() >= 60);
        let mut ids = std::collections::HashSet::new();
        let mut exts = std::collections::HashSet::new();
        for t in T {
            assert!(ids.insert(t.id), "duplicate id {}", t.id);
            assert_eq!(t.exts[0], t.id, "{}: first ext must be the id", t.id);
            for e in t.exts {
                assert!(exts.insert(*e), "duplicate ext {e}");
                assert_eq!(by_ext(e).unwrap().id, t.id);
            }
        }
        assert_eq!(by_ext("JPEG").unwrap().id, "jpg");
        assert_eq!(category_of("cr3"), Category::Photo);
        assert_eq!(category_of("nope"), Category::Other);
    }
}
