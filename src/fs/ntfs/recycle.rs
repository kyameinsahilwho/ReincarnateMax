//! Recycle Bin name restoration: a `$R<id>.<ext>` file (or folder) in `\$Recycle.Bin\<SID>\` gets
//! its original name and folder from the `$I<id>.<ext>` record next to it.

use crate::recyclebin::RecycleInfo;
use std::collections::HashMap;

/// A `$I` record found in the MFT (deleted or not).
#[derive(Clone, Debug)]
pub struct InfoRec {
    /// Record number of the folder holding it.
    pub parent: u64,
    /// Upper-cased name after "$I" ("ABC123.JPG").
    pub id: String,
    pub in_use: bool,
    pub data: Vec<u8>,
}

/// "$Rabc123.jpg" -> "ABC123.JPG"; `None` if it isn't a `$R` name.
pub fn r_id(name: &str) -> Option<String> {
    id_after(name, 'R')
}
/// "$Iabc123.jpg" -> "ABC123.JPG".
pub fn i_id(name: &str) -> Option<String> {
    id_after(name, 'I')
}

fn id_after(name: &str, letter: char) -> Option<String> {
    let mut c = name.chars();
    if c.next() != Some('$') || !c.next().map_or(false, |x| x.eq_ignore_ascii_case(&letter)) {
        return None;
    }
    let rest: String = c.collect();
    if rest.is_empty() {
        return None;
    }
    Some(rest.to_uppercase())
}

/// Split "C:\Users\Ann\cat.jpg" into ("\Users\Ann", "cat.jpg"); drive letters and `\\?\` prefixes
/// are dropped. A file in the root gives "" as its folder.
pub fn split_original(path: &str) -> Option<(String, String)> {
    let mut p = path.trim_end_matches('\0').trim();
    if let Some(s) = p.strip_prefix("\\\\?\\") {
        p = s;
    }
    let b = p.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        p = &p[2..];
    } else if let Some(s) = p.strip_prefix("\\\\") {
        // UNC: drop \\server\share.
        let mut parts = s.splitn(3, '\\');
        let _ = (parts.next(), parts.next());
        p = parts.next().unwrap_or("");
    }
    let p = p.trim_end_matches('\\');
    let (folder, name) = match p.rfind('\\') {
        Some(i) => (&p[..i], &p[i + 1..]),
        None => ("", p),
    };
    if name.is_empty() {
        return None;
    }
    let mut folder = folder.to_string();
    if !folder.is_empty() && !folder.starts_with('\\') {
        folder.insert(0, '\\');
    }
    Some((folder, name.to_string()))
}

/// What a `$R` item turns back into.
#[derive(Clone, Debug, PartialEq)]
pub struct Restore {
    pub name: String,
    pub folder: String,
    pub original: String,
    pub deleted: Option<i64>,
    pub recycled_as: String,
}

/// `$I` records by (folder record, id).
#[derive(Default)]
pub struct InfoIndex {
    map: HashMap<(u64, String), Vec<InfoRec>>,
}

impl InfoIndex {
    pub fn new(infos: Vec<InfoRec>) -> Self {
        let mut map: HashMap<(u64, String), Vec<InfoRec>> = HashMap::new();
        for i in infos {
            map.entry((i.parent, i.id.clone())).or_default().push(i);
        }
        InfoIndex { map }
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Restore the `$R` item `name` in folder record `parent`. Prefers a `$I` in the same state
    /// (both deleted / both present) whose info parses.
    pub fn restore(&self, name: &str, parent: u64, in_use: bool, parse: &dyn Fn(&[u8]) -> Option<RecycleInfo>) -> Option<Restore> {
        let id = r_id(name)?;
        let list = self.map.get(&(parent, id))?;
        let mut order: Vec<&InfoRec> = list.iter().collect();
        order.sort_by_key(|i| i.in_use != in_use);
        for i in order {
            let Some(info) = parse(&i.data) else { continue };
            let Some((folder, orig_name)) = split_original(&info.original_path) else { continue };
            return Some(Restore { name: orig_name, folder, original: info.original_path.clone(), deleted: info.deleted, recycled_as: name.to_string() });
        }
        None
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Build a version-2 `$I` file (Windows 10+).
    pub fn info_v2(path: &str, size: u64, deleted_ft: u64) -> Vec<u8> {
        let p16: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut v = Vec::new();
        v.extend_from_slice(&2u64.to_le_bytes());
        v.extend_from_slice(&size.to_le_bytes());
        v.extend_from_slice(&deleted_ft.to_le_bytes());
        v.extend_from_slice(&(p16.len() as u32).to_le_bytes());
        for u in p16 {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    }

    /// Stand-in for `recyclebin::parse_info_file` (v2 only), to test matching on its own.
    pub fn fake_parse(d: &[u8]) -> Option<RecycleInfo> {
        if d.len() < 28 || d[0] != 2 {
            return None;
        }
        let n = u32::from_le_bytes(d[24..28].try_into().ok()?) as usize;
        let units: Vec<u16> = d.get(28..28 + 2 * n)?.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let s = String::from_utf16_lossy(&units).trim_end_matches('\0').to_string();
        let ft = u64::from_le_bytes(d[16..24].try_into().ok()?);
        Some(RecycleInfo { original_path: s, size: u64::from_le_bytes(d[8..16].try_into().ok()?), deleted: crate::model::filetime_to_ms(ft) })
    }

    #[test]
    fn ids_and_paths() {
        assert_eq!(r_id("$RAB12CD.jpg").as_deref(), Some("AB12CD.JPG"));
        assert_eq!(r_id("$rab12cd.JPG").as_deref(), Some("AB12CD.JPG"));
        assert_eq!(i_id("$IAB12CD.jpg").as_deref(), Some("AB12CD.JPG"));
        assert_eq!(r_id("$IAB12CD.jpg"), None);
        assert_eq!(r_id("$R"), None);
        assert_eq!(r_id("photo.jpg"), None);
        assert_eq!(split_original("C:\\Users\\Ann\\cat.jpg"), Some(("\\Users\\Ann".into(), "cat.jpg".into())));
        assert_eq!(split_original("D:\\cat.jpg"), Some((String::new(), "cat.jpg".into())));
        assert_eq!(split_original("\\\\?\\C:\\a\\b\\"), Some(("\\a".into(), "b".into())));
        assert_eq!(split_original("\\\\server\\share\\x\\y.doc"), Some(("\\x".into(), "y.doc".into())));
        assert_eq!(split_original("C:\\"), None);
    }

    #[test]
    fn matches_r_to_i_in_the_same_folder() {
        let ft = 132_000_000_000_000_000u64;
        let idx = InfoIndex::new(vec![
            InfoRec { parent: 900, id: "AB12CD.JPG".into(), in_use: false, data: info_v2("C:\\Users\\Ann\\Pictures\\cat.jpg", 10, ft) },
            InfoRec { parent: 900, id: "AB12CD.JPG".into(), in_use: true, data: info_v2("C:\\Users\\Ann\\Pictures\\newer.jpg", 10, ft) },
            InfoRec { parent: 901, id: "ZZ.TXT".into(), in_use: false, data: vec![1, 2, 3] },
        ]);
        let r = idx.restore("$RAB12CD.jpg", 900, false, &fake_parse).unwrap();
        assert_eq!(r.name, "cat.jpg");
        assert_eq!(r.folder, "\\Users\\Ann\\Pictures");
        assert_eq!(r.recycled_as, "$RAB12CD.jpg");
        assert_eq!(r.deleted, crate::model::filetime_to_ms(ft));
        assert_eq!(idx.restore("$RAB12CD.jpg", 900, true, &fake_parse).unwrap().name, "newer.jpg");
        assert!(idx.restore("$RAB12CD.jpg", 901, false, &fake_parse).is_none(), "other folder");
        assert!(idx.restore("$RZZ.TXT", 901, false, &fake_parse).is_none(), "unparsable $I");
        assert!(idx.restore("cat.jpg", 900, false, &fake_parse).is_none());
    }
}
