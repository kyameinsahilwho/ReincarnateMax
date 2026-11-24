//! Listing `X:\$Recycle.Bin\<SID>\` folders through Windows. Strictly read-only: directory listings
//! and `$I` reads opened with share read|write|delete so nothing else is disturbed.

use crate::model::{flags, Condition, EngineSummary, FileStatus, FoundFile, Origin, ScanCtx};
use std::io::Read;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const NOTE: &str = "It's still in the Recycle Bin.";
/// Largest valid $I record: 28-byte header + 32767 UTF-16 units.
const MAX_INFO_BYTES: u64 = 28 + 2 * 32_767;

fn ms(t: std::io::Result<SystemTime>) -> Option<i64> {
    let d = t.ok()?.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    i64::try_from(d.as_millis()).ok().filter(|&v| v > 0)
}

fn read_info(p: &Path) -> Option<Vec<u8>> {
    let f = std::fs::OpenOptions::new().read(true).share_mode(FILE_SHARE_ALL).open(p).ok()?;
    let mut buf = Vec::new();
    f.take(MAX_INFO_BYTES).read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn is_reparse(m: &std::fs::Metadata) -> bool {
    m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// "C:\Users\Ann\Pictures" -> "\Users\Ann\Pictures"; "C:\" -> "".
pub(crate) fn strip_drive(folder: &str) -> String {
    let b = folder.as_bytes();
    let rest = if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' { &folder[2..] } else { folder };
    let rest = rest.trim_end_matches('\\');
    if rest.is_empty() {
        String::new()
    } else if rest.starts_with('\\') {
        rest.to_string()
    } else {
        format!("\\{rest}")
    }
}

/// Split an original full path into (folder without drive, name).
pub(crate) fn split_original(path: &str) -> (String, String) {
    match path.rsplit_once('\\') {
        Some((dir, name)) => (strip_drive(dir), name.to_string()),
        None => (String::new(), path.to_string()),
    }
}

fn type_of(name: &str) -> String {
    let probe = FoundFile { name: name.to_string(), ..Default::default() };
    crate::formats::by_ext(&probe.ext()).map(|t| t.id.to_string()).unwrap_or_default()
}

fn make_file(name: &str, folder: &str, original: &str, r_path: &Path, md: &std::fs::Metadata, deleted: Option<i64>) -> FoundFile {
    let mut f = FoundFile {
        name: name.to_string(),
        folder: folder.to_string(),
        size: md.len(),
        status: FileStatus::RecycleBin,
        origin: Origin::RecycleBin,
        type_id: type_of(name),
        created: ms(md.created()),
        modified: ms(md.modified()),
        accessed: ms(md.accessed()),
        deleted,
        live_path: Some(r_path.to_string_lossy().into_owned()),
        condition: Condition::Excellent,
        note: NOTE.to_string(),
        flags: flags::FROM_RECYCLE_INFO,
        ..Default::default()
    };
    f.meta.insert("originalPath".into(), original.to_string());
    f
}

/// One `$I`/`$R` pair to report.
struct Item {
    info: PathBuf,
    data: PathBuf,
}

/// Scan a `$Recycle.Bin` folder (the real one, or a synthetic tree in tests).
pub fn scan_bin(root: &Path, ctx: &ScanCtx) -> Result<EngineSummary, String> {
    let mut sum = EngineSummary::default();
    let sids = match std::fs::read_dir(root) {
        Ok(r) => r,
        Err(_) => {
            ctx.info("This drive has no Recycle Bin MAX can read.");
            return Ok(sum);
        }
    };
    let mut denied = 0u32;
    let mut items: Vec<Item> = Vec::new();
    for sid in sids.flatten() {
        let Ok(md) = sid.metadata() else { continue };
        if !md.is_dir() || is_reparse(&md) {
            continue;
        }
        let dir = sid.path();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => {
                denied += 1;
                continue;
            }
        };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.len() > 2 && name[..2].eq_ignore_ascii_case("$I") {
                items.push(Item { info: e.path(), data: dir.join(format!("$R{}", &name[2..])) });
            }
        }
    }
    if denied > 0 {
        ctx.info(if crate::util::is_elevated() {
            format!("Skipped {denied} Recycle Bin folder(s) Windows wouldn't open.")
        } else {
            format!("Skipped {denied} other account(s)' Recycle Bin: Windows only lets administrators read them.")
        });
    }

    ctx.set_stage(&ctx.stage(), items.len() as u64);
    let mut missing = 0u64;
    for it in &items {
        ctx.check()?;
        ctx.progress(1);
        let Some(info) = read_info(&it.info).and_then(|b| super::parse_info_file(&b)) else { continue };
        let Ok(md) = std::fs::symlink_metadata(&it.data) else {
            missing += 1;
            continue;
        };
        if is_reparse(&md) {
            continue;
        }
        let (folder, name) = split_original(&info.original_path);
        if md.is_dir() {
            sum.files += walk_folder(&it.data, &info.original_path, &folder, &name, info.deleted, ctx)?;
        } else {
            ctx.found(make_file(&name, &folder, &info.original_path, &it.data, &md, info.deleted));
            sum.files += 1;
        }
    }
    if missing > 0 {
        ctx.info(format!("{missing} Recycle Bin record(s) had no file next to them and were skipped."));
    }
    if sum.files > 0 {
        sum.notes.push(format!("Found {} item(s) still in the Recycle Bin.", sum.files));
    }
    Ok(sum)
}

/// A deleted folder (`$R` directory): report every file inside, keeping its structure under the
/// original folder. Explicit stack; reparse points are never followed.
fn walk_folder(r_dir: &Path, original: &str, parent_folder: &str, dir_name: &str, deleted: Option<i64>, ctx: &ScanCtx) -> Result<u64, String> {
    let mut n = 0u64;
    let base_folder = format!("{parent_folder}\\{dir_name}");
    let mut stack: Vec<(PathBuf, String, String)> = vec![(r_dir.to_path_buf(), base_folder, original.to_string())];
    while let Some((dir, folder, orig)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            if n % 256 == 0 {
                ctx.check()?;
            }
            let Ok(md) = e.metadata() else { continue };
            if is_reparse(&md) {
                continue;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            let child_orig = format!("{orig}\\{name}");
            if md.is_dir() {
                stack.push((e.path(), format!("{folder}\\{name}"), child_orig));
            } else {
                ctx.found(make_file(&name, &folder, &child_orig, &e.path(), &md, deleted));
                n += 1;
            }
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanOptions;
    use crate::recyclebin::info::{build_v1, build_v2};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> TempDir {
            let n = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos();
            let p = std::env::temp_dir().join(format!("max-rb-{tag}-{}-{n}", std::process::id()));
            assert!(p.starts_with(std::env::temp_dir()));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            assert!(self.0.starts_with(std::env::temp_dir()));
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const FT: u64 = 133_486_382_450_000_000;

    #[test]
    fn paths_split() {
        assert_eq!(split_original("C:\\Users\\Ann\\Pictures\\cat.jpg"), ("\\Users\\Ann\\Pictures".into(), "cat.jpg".into()));
        assert_eq!(split_original("C:\\cat.jpg"), ("".into(), "cat.jpg".into()));
        assert_eq!(strip_drive("D:\\"), "");
    }

    #[test]
    fn lists_a_synthetic_bin() {
        let t = TempDir::new("bin");
        let sid = t.0.join("S-1-5-21-1-2-3-1001");
        std::fs::create_dir_all(&sid).unwrap();
        // A file deleted on its own.
        std::fs::write(sid.join("$IABC123.jpg"), build_v2("C:\\Users\\Ann\\Pictures\\cat.jpg", 5, FT)).unwrap();
        std::fs::write(sid.join("$RABC123.jpg"), b"hello").unwrap();
        // A deleted folder with a sub-folder.
        std::fs::write(sid.join("$IDEF456"), build_v1("C:\\Users\\Ann\\Project", 0, FT)).unwrap();
        std::fs::create_dir_all(sid.join("$RDEF456\\src")).unwrap();
        std::fs::write(sid.join("$RDEF456\\readme.txt"), b"r").unwrap();
        std::fs::write(sid.join("$RDEF456\\src\\main.rs"), b"fn main(){}").unwrap();
        // An orphan $I and junk.
        std::fs::write(sid.join("$IZZZ999.txt"), build_v2("C:\\gone.txt", 1, FT)).unwrap();
        std::fs::write(sid.join("desktop.ini"), b"x").unwrap();
        std::fs::write(sid.join("$IBAD.txt"), b"junk").unwrap();

        let (ctx, sinks) = ScanCtx::for_test(ScanOptions::default(), 0);
        let s = scan_bin(&t.0, &ctx).unwrap();
        assert_eq!(s.files, 3);
        let mut files = sinks.files.lock().unwrap().clone();
        files.sort_by(|a, b| a.name.cmp(&b.name));
        let cat = &files[0];
        assert_eq!(cat.name, "cat.jpg");
        assert_eq!(cat.folder, "\\Users\\Ann\\Pictures");
        assert_eq!(cat.size, 5);
        assert_eq!(cat.status, FileStatus::RecycleBin);
        assert_eq!(cat.origin, Origin::RecycleBin);
        assert_eq!(cat.condition, Condition::Excellent);
        assert_eq!(cat.note, NOTE);
        assert_eq!(cat.type_id, "jpg");
        assert_eq!(cat.deleted, Some(1_704_164_645_000));
        assert!(cat.modified.is_some());
        assert_eq!(cat.meta["originalPath"], "C:\\Users\\Ann\\Pictures\\cat.jpg");
        assert!(cat.live_path.as_ref().unwrap().ends_with("$RABC123.jpg"));
        let main = &files[1];
        assert_eq!(main.name, "main.rs");
        assert_eq!(main.folder, "\\Users\\Ann\\Project\\src");
        assert_eq!(main.type_id, "");
        assert_eq!(main.meta["originalPath"], "C:\\Users\\Ann\\Project\\src\\main.rs");
        let readme = &files[2];
        assert_eq!(readme.folder, "\\Users\\Ann\\Project");
        assert_eq!(readme.type_id, "txt");
        // Everything still in place (read-only).
        assert!(sid.join("$RABC123.jpg").exists() && sid.join("$IABC123.jpg").exists());
        // The orphan was counted in the log.
        assert!(sinks.log.lock().unwrap().iter().any(|(_, m)| m.contains("no file next to them")));
    }

    #[test]
    fn missing_bin_is_not_an_error() {
        let (ctx, _) = ScanCtx::for_test(ScanOptions::default(), 0);
        let s = scan_bin(Path::new("Z:\\definitely-not-here\\$Recycle.Bin"), &ctx).unwrap();
        assert_eq!(s.files, 0);
    }

    /// Lists this PC's C: Recycle Bin (read-only). `cargo test recyclebin_real -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn recyclebin_real_machine_listing() {
        let (ctx, sinks) = ScanCtx::for_test(ScanOptions::default(), 0);
        let s = crate::recyclebin::scan_volume("C", &ctx).unwrap();
        let files = sinks.files.lock().unwrap();
        let bytes: u64 = files.iter().map(|f| f.size).sum();
        println!("C: Recycle Bin: {} files, {} bytes, notes {:?}", s.files, bytes, s.notes);
        for (_, m) in sinks.log.lock().unwrap().iter() {
            println!("log: {m}");
        }
        for f in files.iter().take(10) {
            println!("  {}\\{} ({} bytes)", f.folder, f.name, f.size);
        }
    }
}
