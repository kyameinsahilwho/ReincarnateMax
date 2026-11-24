//! Target paths for recovered files: sanitised components, name clashes, long-path form.

use crate::model::safe_file_name;
use std::path::{Path, PathBuf};

/// Paths longer than this are written through the `\\?\` form.
pub const LONG_PATH: usize = 240;

/// `<dest>\<label>\<folder parts>` (or `<dest>\<label>` without keep_folders), every component
/// made safe. ".." and "." can't survive `safe_file_name`, so nothing escapes `dest`.
pub fn target_dir(dest: &Path, label: &str, folder: &str, keep_folders: bool) -> PathBuf {
    let mut p = dest.join(safe_file_name(label));
    if keep_folders {
        for c in folder.split(['\\', '/']).filter(|c| !c.is_empty()) {
            p.push(safe_file_name(c));
        }
    }
    p
}

/// "photo.jpg" + 2 -> "photo (2).jpg"; "README" + 3 -> "README (3)".
pub fn numbered(name: &str, n: u32) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && ext.len() <= 8 => format!("{stem} ({n}).{ext}"),
        _ => format!("{name} ({n})"),
    }
}

/// "photo.jpg" -> "photo (repaired).jpg".
pub fn repaired_name(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && ext.len() <= 8 => format!("{stem} (repaired).{ext}"),
        _ => format!("{name} (repaired)"),
    }
}

/// The form to hand to Windows: `\\?\` (or `\\?\UNC\`) when the path is long.
pub fn io_path(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if s.len() <= LONG_PATH || s.starts_with("\\\\?\\") {
        return p.to_path_buf();
    }
    if let Some(rest) = s.strip_prefix("\\\\") {
        PathBuf::from(format!("\\\\?\\UNC\\{rest}"))
    } else {
        PathBuf::from(format!("\\\\?\\{s}"))
    }
}

pub fn exists(p: &Path) -> bool {
    std::fs::symlink_metadata(io_path(p)).is_ok()
}

/// First free name in `dir` for `name` (also free of its `.maxpart` and of names already taken
/// in this job).
pub fn unique_path(dir: &Path, name: &str, taken: &std::collections::HashSet<String>) -> PathBuf {
    let mut n = 1u32;
    loop {
        let candidate = if n == 1 { name.to_string() } else { numbered(name, n) };
        let p = dir.join(&candidate);
        let key = p.to_string_lossy().to_lowercase();
        if !taken.contains(&key) && !exists(&p) && !exists(&part_path(&p)) {
            return p;
        }
        n += 1;
    }
}

/// `<path>.maxpart`: written first, renamed when complete.
pub fn part_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".maxpart");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirs_and_names() {
        let d = target_dir(Path::new("E:\\R"), "C: scan", "\\Users\\..\\A:b\\.\\x.", true);
        assert_eq!(d, PathBuf::from("E:\\R\\C_ scan\\Users\\unnamed\\A_b\\unnamed\\x"));
        assert_eq!(target_dir(Path::new("E:\\R"), "s", "\\a\\b", false), PathBuf::from("E:\\R\\s"));
        assert_eq!(numbered("a.jpg", 2), "a (2).jpg");
        assert_eq!(numbered(".hidden", 3), ".hidden (3)");
        assert_eq!(repaired_name("a.b.zip"), "a.b (repaired).zip");
        let long = PathBuf::from(format!("E:\\{}", "x".repeat(300)));
        assert!(io_path(&long).to_string_lossy().starts_with("\\\\?\\E:\\"));
        let unc = PathBuf::from(format!("\\\\nas\\s\\{}", "x".repeat(300)));
        assert!(io_path(&unc).to_string_lossy().starts_with("\\\\?\\UNC\\nas\\s\\"));
        assert_eq!(io_path(Path::new("E:\\a")), PathBuf::from("E:\\a"));
    }
}
