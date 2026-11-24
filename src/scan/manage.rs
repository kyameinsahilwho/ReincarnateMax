//! Session-level operations: list, detail, delete, export, import, log, and the Recovery Map
//! commands (live sets for running scans, persisted ones otherwise).

use super::jobs::running;
use super::map;
use super::query;
use super::session::{self, *};
use super::{FileRow, LogLine, MapData, RegionInfo, SessionDetail, SessionSummary, StageInfo};
use crate::model::{MapKind, ScanOptions, SourceKind, SourceRef};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

fn file_size(path: &Path) -> u64 {
    let len = |p: PathBuf| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    let s = path.to_string_lossy().to_string();
    len(path.to_path_buf()) + len(PathBuf::from(format!("{s}-wal")))
}

fn summary_from(id: &str, path: &Path, c: &Connection) -> Option<SessionSummary> {
    let source: SourceRef = meta_json(c, K_SOURCE)?;
    let mut s = SessionSummary {
        id: id.to_string(),
        label: meta_get(c, K_LABEL).unwrap_or_default(),
        source,
        mode: meta_get(c, K_MODE).unwrap_or_default(),
        state: meta_get(c, K_STATE).unwrap_or_default(),
        created: meta_get(c, K_CREATED).unwrap_or(0),
        updated: meta_get(c, K_UPDATED).unwrap_or(0),
        files: meta_get::<i64>(c, K_FILES).unwrap_or(0).max(0) as u64,
        bytes: meta_get::<i64>(c, K_BYTES).unwrap_or(0).max(0) as u64,
        scanned_bytes: meta_get::<i64>(c, K_SCANNED).unwrap_or(0).max(0) as u64,
        source_len: meta_get::<i64>(c, K_SOURCE_LEN).unwrap_or(0).max(0) as u64,
        bad_bytes: meta_get::<i64>(c, K_BAD).unwrap_or(0).max(0) as u64,
        file_size: file_size(path),
    };
    match running(id) {
        Some(j) => {
            s.state = if j.ctx.paused.load(Ordering::Relaxed) { "paused" } else { "running" }.into();
            s.files = s.files.max(j.ctx.files_found.load(Ordering::Relaxed));
            s.scanned_bytes = j.ranges.total(MapKind::Scanned);
            // From the merged set: re-read sectors (a resumed sweep) aren't counted twice.
            s.bad_bytes = j.ranges.total(MapKind::Bad);
        }
        None if matches!(s.state.as_str(), "running" | "paused") => s.state = "interrupted".into(),
        None => {}
    }
    Some(s)
}

pub fn list_sessions() -> Result<Vec<SessionSummary>, String> {
    sessions_dir()?;
    let mut out = Vec::new();
    for (id, p) in session::all_session_files() {
        let Ok(c) = session::open_read(&p) else { continue };
        if let Some(s) = summary_from(&id, &p, &c) {
            out.push(s);
        }
    }
    out.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| b.id.cmp(&a.id)));
    Ok(out)
}

pub fn get_session(id: &str) -> Result<SessionDetail, String> {
    let path = session_path(id)?;
    with_conn(id, |c| {
        let summary = summary_from(id, &path, c).ok_or(DAMAGED)?;
        let job = running(id);
        let stages: Vec<StageInfo> = match &job {
            Some(j) => j.stages.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            None => meta_json(c, K_STAGES).unwrap_or_default(),
        };
        let notes: Vec<String> = match &job {
            Some(j) => j.notes.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            None => meta_json(c, K_NOTES).unwrap_or_default(),
        };
        Ok(SessionDetail {
            summary,
            options: meta_json::<ScanOptions>(c, K_OPTIONS).unwrap_or_default(),
            stages,
            probe: meta_json(c, K_PROBE).unwrap_or(None),
            partitions: meta_json(c, K_PARTITIONS),
            counts: query::counts(c)?,
            sector_size: meta_get::<i64>(c, K_SECTOR_SIZE).unwrap_or(512) as u32,
            error: meta_get(c, K_ERROR),
            notes,
        })
    })
}

fn remove_files(path: &Path) -> Result<(), String> {
    let s = path.to_string_lossy().to_string();
    for p in [PathBuf::from(format!("{s}-wal")), PathBuf::from(format!("{s}-shm"))] {
        let _ = std::fs::remove_file(p);
    }
    // Another thread may be reading it for a moment (listing sessions): retry briefly.
    for _ in 0..40 {
        match std::fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    }
    Err("MAX couldn't delete this session file. Close anything that has it open and try again.".into())
}

pub fn delete_session(id: &str) -> Result<(), String> {
    if running(id).is_some() {
        return Err("Stop this scan before deleting it.".into());
    }
    let path = session_path(id)?;
    session::evict(id);
    super::store::forget_source(id);
    remove_files(&path)?;
    session::unregister_external(&path);
    session::bump(id);
    Ok(())
}

fn sql_quote(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', "''"))
}

const EXPORT_FAILED: &str = "MAX couldn't save the session file there. Pick a folder you can write to with enough free space.";
const EXPORT_ON_SOURCE: &str =
    "That folder is on the drive this scan read, and saving there could overwrite the deleted files. Pick a folder on another drive.";
const EXPORT_IS_IMAGE: &str = "That file is the disk image this scan read. Pick another name or folder.";

fn lower_norm(p: &str) -> String {
    crate::recover::dest::normalize(p).unwrap_or_else(|_| p.to_string()).to_lowercase()
}

/// `a.001` / `a.002` ...: the same split image set.
fn same_split_set(a: &str, b: &str) -> bool {
    let (Some((sa, ea)), Some((sb, eb))) = (a.rsplit_once('.'), b.rsplit_once('.')) else { return false };
    let digits = |e: &str| e.len() >= 3 && e.chars().all(|c| c.is_ascii_digit());
    sa == sb && digits(ea) && digits(eb)
}

/// Refuse saving a session over the scanned image (or a part of its split set), or onto the
/// physical disk this session read (Volume / Disk sources). Pure for images; Win32 lookups
/// (read-only) for drives.
pub fn check_export_target(dest: &Path, source: &SourceRef, size: u64) -> Result<(), String> {
    let d = dest.to_string_lossy().to_string();
    match source.kind {
        SourceKind::Image => {
            let (dl, il) = (lower_norm(&d), lower_norm(&source.path));
            let same_file = std::fs::canonicalize(dest).ok().zip(std::fs::canonicalize(&source.path).ok()).is_some_and(|(a, b)| a == b);
            if dl == il || same_file || same_split_set(&dl, &il) {
                return Err(EXPORT_IS_IMAGE.into());
            }
            Ok(())
        }
        SourceKind::Volume | SourceKind::Disk | SourceKind::Snapshot => {
            let parent = dest.parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            let (check, facts) = crate::recover::dest::run_check(&parent, source, &[size]);
            if check.on_source_disk {
                return Err(EXPORT_ON_SOURCE.into());
            }
            if facts.free.is_some_and(|f| f < size) {
                return Err(check.error.unwrap_or_else(|| EXPORT_FAILED.to_string()));
            }
            Ok(())
        }
    }
}

pub fn export_session(id: &str, dest: &str) -> Result<(), String> {
    let path = session_path(id)?;
    if !path.is_file() {
        return Err(session::missing(&path));
    }
    let dest = PathBuf::from(dest.trim());
    if dest.as_os_str().is_empty() || dest.file_name().is_none() {
        return Err("Pick where to save the session file.".into());
    }
    let same = std::fs::canonicalize(&dest).ok().zip(std::fs::canonicalize(&path).ok()).is_some_and(|(a, b)| a == b);
    if same {
        return Err("Pick another place to save the session file.".into());
    }
    let source: SourceRef = with_conn(id, |c| meta_json(c, K_SOURCE).ok_or_else(|| DAMAGED.to_string()))?;
    check_export_target(&dest, &source, file_size(&path))?;
    // A consistent snapshot (VACUUM INTO, under the connection lock, whatever else is writing),
    // written next to the target and renamed over it: a failed export leaves an existing file as
    // it was.
    let name = dest.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let tmp = dest.with_file_name(format!("{name}.{}.part", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let r = with_conn(id, |c| c.execute_batch(&format!("VACUUM INTO {}", sql_quote(&tmp))).map_err(|_| EXPORT_FAILED.to_string()))
        .and_then(|_| std::fs::rename(&tmp, &dest).map_err(|_| EXPORT_FAILED.to_string()));
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

pub fn import_session(src_path: &str) -> Result<String, String> {
    let src = PathBuf::from(src_path.trim());
    if !src.is_file() {
        return Err("That file doesn't exist any more. Pick the .maxscan file again.".into());
    }
    let bad = || "That file isn't a MAX scan session.".to_string();
    {
        let c = session::open_read(&src).map_err(|_| bad())?;
        let v: i64 = meta_get(&c, K_SCHEMA).ok_or_else(bad)?;
        if v > SCHEMA_VERSION {
            return Err("This session was saved by a newer version of MAX. Update MAX to open it.".into());
        }
        meta_json::<SourceRef>(&c, K_SOURCE).ok_or_else(bad)?;
        c.query_row("SELECT count(*) FROM files", [], |r| r.get::<_, i64>(0)).map_err(|_| bad())?;
    }
    // A session kept on another drive (scan of MAX's own drive) is already in the list.
    if let Some(stem) = src.file_stem().and_then(|s| s.to_str()).filter(|s| valid_id(s)) {
        if session_path(stem).is_ok_and(|p| p == src) {
            return Ok(stem.to_string());
        }
    }
    let dir = sessions_dir()?;
    if let (Ok(a), Ok(b)) = (std::fs::canonicalize(src.parent().unwrap_or(Path::new("."))), std::fs::canonicalize(&dir)) {
        if a == b {
            if let Some(stem) = src.file_stem().and_then(|s| s.to_str()) {
                if valid_id(stem) && src.extension().and_then(|e| e.to_str()) == Some(EXT) {
                    return Ok(stem.to_string());
                }
            }
        }
    }
    let stem: String = src.file_stem().and_then(|s| s.to_str()).unwrap_or("imported").chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(80).collect();
    let stem = if stem.is_empty() { format!("{}-imported", local_stamp()) } else { stem };
    let mut id = stem.clone();
    let mut n = 2;
    let dest = loop {
        let p = dir.join(format!("{id}.{EXT}"));
        if !p.exists() && running(&id).is_none() {
            break p;
        }
        id = format!("{stem}-{n}");
        n += 1;
    };
    // VACUUM INTO reads through any WAL left next to the file; plain copy as a fallback.
    let copied = session::open_read(&src).map(|c| c.execute_batch(&format!("VACUUM INTO {}", sql_quote(&dest))).is_ok()).unwrap_or(false);
    if !copied {
        let _ = std::fs::remove_file(&dest);
        std::fs::copy(&src, &dest).map_err(|_| "MAX couldn't copy the session into its data folder. Check that the drive has free space.".to_string())?;
    }
    let c = session::open_path(&dest, false)?;
    let _: String = c.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)).unwrap_or_default();
    let state: String = meta_get(&c, K_STATE).unwrap_or_default();
    if matches!(state.as_str(), "running" | "paused") {
        meta_set(&c, K_STATE, "interrupted")?;
    }
    meta_set(&c, K_PID, 0i64)?;
    let _ = c.execute(
        "INSERT INTO log(at, level, message) VALUES (?1, 'info', ?2)",
        params![crate::model::now_ms(), format!("Imported from {}.", src.display())],
    );
    Ok(id)
}

pub fn session_log(id: &str, offset: Option<u64>, limit: Option<u64>) -> Result<Vec<LogLine>, String> {
    if let Some(j) = running(id) {
        j.writer.flush();
    }
    let limit = limit.unwrap_or(500).clamp(1, 5000) as i64;
    let offset = offset.unwrap_or(0).min(i64::MAX as u64) as i64;
    with_conn(id, |c| {
        let mut st = c.prepare_cached("SELECT at, level, message FROM log ORDER BY rowid LIMIT ?1 OFFSET ?2").map_err(db_err)?;
        let rows = st.query_map(params![limit, offset], |r| Ok(LogLine { at: r.get(0)?, level: r.get(1)?, message: r.get(2)? })).map_err(db_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
    })
}

// -------------------------------------------------------------------------------- the map

pub fn map_cells(id: &str, start: Option<u64>, end: Option<u64>, cells: u32) -> Result<MapData, String> {
    if let Some(j) = running(id) {
        let len = j.src.len();
        return Ok(j.ranges.with(|s| map::cells(s, len, start, end, cells)));
    }
    with_conn(id, |c| {
        let len = meta_get::<i64>(c, K_SOURCE_LEN).unwrap_or(0).max(0) as u64;
        let sets = map::cached_sets(id, c);
        Ok(map::cells(map::refs(&sets), len, start, end, cells))
    })
}

pub fn map_region(id: &str, start: u64, end: u64) -> Result<RegionInfo, String> {
    let job = running(id);
    with_conn(id, |c| {
        let len = meta_get::<i64>(c, K_SOURCE_LEN).unwrap_or(0).max(0) as u64;
        let ss = meta_get::<i64>(c, K_SECTOR_SIZE).unwrap_or(512) as u32;
        let end = end.min(len.max(start));
        let start = start.min(end);
        let mut info = match &job {
            Some(j) => j.ranges.with(|s| map::region(s, start, end, ss)),
            None => {
                let sets = map::cached_sets(id, c);
                map::region(map::refs(&sets), start, end, ss)
            }
        };
        if end > start {
            let max_ext = meta_get::<i64>(c, K_MAX_EXTENT)
                .unwrap_or_else(|| c.query_row("SELECT coalesce(max(end_off - start_off), 0) FROM file_extents", [], |r| r.get(0)).unwrap_or(0));
            let lo = (start as i64).saturating_sub(max_ext).max(0);
            let touching = "SELECT DISTINCT file_id FROM file_extents WHERE start_off < ?1 AND start_off >= ?2 AND end_off > ?3";
            let p = params![end as i64, lo, start as i64];
            info.file_count = c.query_row(&format!("SELECT count(*) FROM ({touching})"), p, |r| r.get::<_, i64>(0)).map_err(db_err)? as u64;
            let sql = format!("SELECT {} FROM files WHERE id IN ({touching}) ORDER BY size DESC, id LIMIT 100", query::ROW_COLS);
            let mut st = c.prepare_cached(&sql).map_err(db_err)?;
            let rows = st.query_map(p, query::row_from).map_err(db_err)?;
            info.files = rows.collect::<Result<Vec<FileRow>, _>>().map_err(db_err)?;
        }
        Ok(info)
    })
}
