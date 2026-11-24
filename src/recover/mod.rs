//! Recovery pipeline: destination safety checks (never onto the source disk), batch copy-out with
//! folder structure, timestamps, verification (re-read + BLAKE3), repair attempts, duplicate
//! skipping, reports (HTML + CSV) and the recovery history. Also duplicate detection for the
//! workspace. Events: "recovery-progress", "recovery-done", "dupes-progress", "dupes-done".
//! OWNER: recover agent.
//!
//! Layout: `dest` (destination safety), `engine` (copy-out loop, store-free), `names` (target
//! paths), `report` (HTML/CSV), `history` (history.json), `dupes` (duplicate grouping).

pub mod dest;
pub mod dupes;
pub mod engine;
pub mod history;
pub mod names;
pub mod report;

use crate::model::{now_ms, FileStatus, FoundFile, LogLevel, SourceKind, SourceRef};
use crate::scan::{store, FileQuery};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tauri::Emitter;

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct RecoverOptions {
    /// Recreate the reconstructed folders under the destination (default true).
    #[serde(default)]
    pub keep_folders: Option<bool>,
    /// Write identical content only once (default true).
    #[serde(default)]
    pub skip_duplicates: Option<bool>,
    /// Re-read every written file and compare hashes (default true).
    #[serde(default)]
    pub verify: Option<bool>,
    /// Try to repair files that fail validation; the repaired copy is written next to the original
    /// as "<name> (repaired).<ext>" (default true).
    #[serde(default)]
    pub repair: Option<bool>,
    /// Write "MAX Recovery Report.html" and ".csv" into the destination (default true).
    #[serde(default)]
    pub report: Option<bool>,
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct DestCheck {
    /// Recovery may start.
    pub ok: bool,
    /// One sentence when not ok ("This folder is on the drive you are recovering from. Pick a
    /// folder on another drive.").
    pub error: Option<String>,
    pub warnings: Vec<String>,
    pub free_bytes: u64,
    pub need_bytes: u64,
    /// Normalised destination path.
    pub path: String,
    pub on_source_disk: bool,
}

// ------------------------------------------------------------------------------- job state

static NEXT_JOB: AtomicU64 = AtomicU64::new(1);

fn jobs() -> &'static Mutex<HashMap<u64, Arc<AtomicBool>>> {
    static J: OnceLock<Mutex<HashMap<u64, Arc<AtomicBool>>>> = OnceLock::new();
    J.get_or_init(Default::default)
}
fn active_dests() -> &'static Mutex<HashSet<String>> {
    static D: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    D.get_or_init(Default::default)
}

/// Releases a job's registrations when the job thread ends (even on panic).
struct JobGuard {
    job: u64,
    dest_key: String,
}
impl Drop for JobGuard {
    fn drop(&mut self) {
        jobs().lock().unwrap_or_else(|e| e.into_inner()).remove(&self.job);
        active_dests().lock().unwrap_or_else(|e| e.into_inner()).remove(&self.dest_key);
    }
}

// --------------------------------------------------------------------------------- helpers

/// The file ids to act on: `ids` (deduplicated, order kept) or everything matching `query`.
fn resolve_ids(session: &str, ids: Option<Vec<i64>>, query: Option<FileQuery>) -> Result<Vec<i64>, String> {
    let list = match (ids, query) {
        (Some(ids), _) => ids,
        (None, Some(q)) => store::query_ids(session, &q)?,
        (None, None) => return Err("Pick the files to recover first.".into()),
    };
    let mut seen = HashSet::new();
    Ok(list.into_iter().filter(|id| seen.insert(*id)).collect())
}

/// What the destination check needs from a selection: total bytes and files over 4 GB.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Totals {
    need: u64,
    big: u64,
}

const FAT_LIMIT: u64 = 0xFFFF_FFFF;

type TotalsCache = Mutex<HashMap<(String, u64, String), Totals>>;

fn totals_cache() -> &'static TotalsCache {
    static C: OnceLock<TotalsCache> = OnceLock::new();
    C.get_or_init(Default::default)
}

/// Totals of `ids` (or of everything matching `query`), cached per (session, change counter,
/// selection) so the dialog's repeated checks (one per pause in typing) don't re-read a large
/// selection. A query is summed with one aggregate SQL query instead of resolving every id.
fn selection_totals(session: &str, ids: Option<&[i64]>, query: Option<&FileQuery>) -> Result<Totals, String> {
    let sel = match (ids, query) {
        (Some(ids), _) => {
            let mut h = blake3::Hasher::new();
            for id in ids {
                h.update(&id.to_le_bytes());
            }
            format!("ids:{}:{}", ids.len(), h.finalize().to_hex())
        }
        (None, Some(q)) => {
            let mut k = q.clone();
            (k.sort, k.desc, k.offset, k.limit) = (None, None, None, None);
            format!("q:{}", serde_json::to_string(&k).unwrap_or_default())
        }
        (None, None) => return Err("Pick the files to recover first.".into()),
    };
    let key = (session.to_string(), crate::scan::session::gen(session), sel);
    if let Some(t) = totals_cache().lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
        return Ok(*t);
    }
    let t = match (ids, query) {
        (Some(ids), _) => {
            let mut seen = HashSet::new();
            let unique: Vec<i64> = ids.iter().copied().filter(|id| seen.insert(*id)).collect();
            let sizes = store::sizes_of(session, &unique)?;
            Totals { need: sizes.iter().sum(), big: sizes.iter().filter(|&&n| n > FAT_LIMIT).count() as u64 }
        }
        (None, Some(q)) => crate::scan::session::with_conn(session, |c| {
            let w = crate::scan::query::build_where(q, true);
            let sql = format!("SELECT coalesce(sum(size), 0), coalesce(sum(size > {FAT_LIMIT}), 0) FROM files WHERE {}", w.sql);
            c.query_row(&sql, rusqlite::params_from_iter(w.params.iter()), |r| Ok(Totals { need: r.get::<_, i64>(0)?.max(0) as u64, big: r.get::<_, i64>(1)?.max(0) as u64 }))
                .map_err(crate::scan::session::db_err)
        })?,
        (None, None) => unreachable!(),
    };
    let mut m = totals_cache().lock().unwrap_or_else(|e| e.into_inner());
    if m.len() > 32 {
        m.clear();
    }
    m.insert(key, t);
    Ok(t)
}

async fn session_label(session: &str, src: &SourceRef) -> String {
    let from_session = crate::scan::get_session(session.to_string()).await.ok().map(|d| d.summary.label).filter(|l| !l.trim().is_empty());
    from_session.or_else(|| src.label.clone().filter(|l| !l.trim().is_empty())).unwrap_or_else(|| "Recovered files".to_string())
}

pub fn describe_source(r: &SourceRef) -> String {
    let base = match r.kind {
        SourceKind::Volume => format!("Drive {}:", r.path.trim_end_matches([':', '\\'])),
        SourceKind::Disk => format!("Disk {}", r.path),
        SourceKind::Image => format!("Disk image {}", r.path),
        SourceKind::Snapshot => "Restore point (shadow copy)".to_string(),
    };
    let mut s = match &r.label {
        Some(l) if !l.trim().is_empty() && *l != base => format!("{l} — {base}"),
        _ => base,
    };
    if r.offset > 0 {
        s.push_str(&format!(", partition starting at byte {}", r.offset));
    }
    s
}

fn type_label(type_id: &str) -> String {
    if type_id.is_empty() {
        return "Unknown".into();
    }
    crate::formats::by_id(type_id).map(|t| t.label.to_string()).unwrap_or_else(|| type_id.to_ascii_uppercase())
}

fn status_label(s: FileStatus) -> &'static str {
    match s {
        FileStatus::Deleted => "deleted",
        FileStatus::Existing => "existing",
        FileStatus::Lost => "lost folder",
        FileStatus::Carved => "found by signature",
        FileStatus::RecycleBin => "in Recycle Bin",
    }
}

/// `<dir>\<stem>.html` + `.csv`, numbered so an earlier report is never overwritten.
fn report_paths(dir: &Path, stem: &str) -> (PathBuf, PathBuf) {
    let mut n = 1;
    loop {
        let s = if n == 1 { stem.to_string() } else { format!("{stem} ({n})") };
        let (h, c) = (dir.join(format!("{s}.html")), dir.join(format!("{s}.csv")));
        if !h.exists() && !c.exists() {
            return (h, c);
        }
        n += 1;
    }
}

// ------------------------------------------------------------------------------- commands

/// Check a destination before recovering `ids` (or everything matching `query`) of a session.
#[tauri::command]
pub async fn check_destination(session_id: String, dest: String, ids: Option<Vec<i64>>, query: Option<FileQuery>) -> Result<DestCheck, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let t = selection_totals(&session_id, ids.as_deref(), query.as_ref())?;
        let src = store::session_source_ref(&session_id)?;
        Ok(dest::run_check_totals(&dest, &src, t.need, t.big).0)
    })
    .await
    .map_err(|_| "Checking the destination stopped unexpectedly.".to_string())?
}

/// Recover `ids` (or everything matching `query`). Returns the job id.
#[tauri::command]
pub async fn start_recovery(
    app: tauri::AppHandle,
    session_id: String,
    dest: String,
    ids: Option<Vec<i64>>,
    query: Option<FileQuery>,
    options: Option<RecoverOptions>,
) -> Result<u64, String> {
    let src_ref = {
        let s = session_id.clone();
        tauri::async_runtime::spawn_blocking(move || store::session_source_ref(&s)).await.map_err(|_| "Starting the recovery stopped unexpectedly.".to_string())??
    };
    let label = session_label(&session_id, &src_ref).await;
    tauri::async_runtime::spawn_blocking(move || {
        // Usually a cache hit: the dialog checked the same selection a moment ago.
        let t = selection_totals(&session_id, ids.as_deref(), query.as_ref())?;
        let ids = resolve_ids(&session_id, ids, query)?;
        if ids.is_empty() {
            return Err("Pick the files to recover first.".to_string());
        }
        let (check, facts) = dest::run_check_totals(&dest, &src_ref, t.need, t.big);
        if !check.ok {
            return Err(check.error.unwrap_or_else(|| "Pick another destination folder.".into()));
        }
        let dest_key = check.path.to_lowercase();
        {
            let mut act = active_dests().lock().unwrap_or_else(|e| e.into_inner());
            if !act.insert(dest_key.clone()) {
                return Err("MAX is already recovering into this folder. Wait for it to finish or pick another folder.".into());
            }
        }
        let job = NEXT_JOB.fetch_add(1, Ordering::Relaxed);
        let cancel = Arc::new(AtomicBool::new(false));
        jobs().lock().unwrap_or_else(|e| e.into_inner()).insert(job, cancel.clone());
        let guard = JobGuard { job, dest_key };
        let o = options.unwrap_or_default();
        let opts = engine::EngineOpts {
            keep_folders: o.keep_folders.unwrap_or(true),
            skip_duplicates: o.skip_duplicates.unwrap_or(true),
            verify: o.verify.unwrap_or(true),
            repair: o.repair.unwrap_or(true),
            fat_dest: facts.is_fat(),
        };
        let spec = JobSpec {
            job,
            session: session_id,
            label,
            src_ref,
            dest: PathBuf::from(&check.path),
            ids,
            bytes_total: t.need,
            opts,
            report: o.report.unwrap_or(true),
            cancel,
        };
        std::thread::Builder::new()
            .name(format!("recovery-{job}"))
            .spawn(move || {
                let _g = guard;
                run_job(&app, spec);
            })
            .map_err(|_| "Windows couldn't start the recovery. Try again.".to_string())?;
        Ok(job)
    })
    .await
    .map_err(|_| "Starting the recovery stopped unexpectedly.".to_string())?
}

#[tauri::command]
pub fn cancel_recovery(job: u64) -> Result<(), String> {
    if let Some(c) = jobs().lock().unwrap_or_else(|e| e.into_inner()).get(&job) {
        c.store(true, Ordering::Relaxed);
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryRecord {
    pub job: u64,
    pub session_id: String,
    pub session_label: String,
    pub dest: String,
    pub started: i64,
    pub finished: i64,
    /// "done" | "cancelled" | "failed"
    pub state: String,
    pub recovered: u64,
    pub partial: u64,
    pub failed: u64,
    pub repaired: u64,
    pub skipped_duplicates: u64,
    pub bytes: u64,
    pub report_path: Option<String>,
}

#[tauri::command]
pub async fn recovery_history() -> Result<Vec<RecoveryRecord>, String> {
    tauri::async_runtime::spawn_blocking(history::load).await.map_err(|_| "Reading the recovery history stopped unexpectedly.".to_string())
}

/// Hash candidate files (same size) and group identical content. Returns the job id.
#[tauri::command]
pub async fn find_duplicates(app: tauri::AppHandle, session_id: String) -> Result<u64, String> {
    let job = NEXT_JOB.fetch_add(1, Ordering::Relaxed);
    let cancel = Arc::new(AtomicBool::new(false));
    jobs().lock().unwrap_or_else(|e| e.into_inner()).insert(job, cancel.clone());
    let guard = JobGuard { job, dest_key: String::new() };
    std::thread::Builder::new()
        .name(format!("dupes-{job}"))
        .spawn(move || {
            let _g = guard;
            run_dupes(&app, job, &session_id, &cancel);
        })
        .map_err(|_| "Windows couldn't start the duplicate search. Try again.".to_string())?;
    Ok(job)
}

/// Write a scan report of the session (every file, or those matching `query`).
/// `format`: "html" | "csv".
#[tauri::command]
pub async fn export_report(session_id: String, path: String, format: String, query: Option<FileQuery>) -> Result<String, String> {
    let src_ref = {
        let s = session_id.clone();
        tauri::async_runtime::spawn_blocking(move || store::session_source_ref(&s)).await.map_err(|_| "Writing the report stopped unexpectedly.".to_string())??
    };
    let label = session_label(&session_id, &src_ref).await;
    tauri::async_runtime::spawn_blocking(move || export_scan_report(&session_id, &label, &src_ref, &path, &format, query))
        .await
        .map_err(|_| "Writing the report stopped unexpectedly.".to_string())?
}

// ------------------------------------------------------------------------------- recovery job

struct JobSpec {
    job: u64,
    session: String,
    label: String,
    src_ref: SourceRef,
    dest: PathBuf,
    ids: Vec<i64>,
    bytes_total: u64,
    opts: engine::EngineOpts,
    report: bool,
    cancel: Arc<AtomicBool>,
}

fn run_job(app: &tauri::AppHandle, s: JobSpec) {
    let started = now_ms();
    let src = store::open_session_source(&s.session).ok();
    let hashes: HashMap<i64, String> = if s.opts.skip_duplicates {
        let wanted: HashSet<i64> = s.ids.iter().copied().collect();
        store::sizes_and_hashes(&s.session)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(id, _, h)| h.filter(|_| wanted.contains(&id)).map(|h| (id, h)))
            .collect()
    } else {
        HashMap::new()
    };
    let session = s.session.clone();
    let load = |id: i64| store::get_file(&session, id);
    let known = |id: i64| hashes.get(&id).cloned();
    let on_hash = |id: i64, h: &str| {
        let _ = store::set_hash(&session, id, h);
    };
    let hooks = engine::Hooks { known_hash: &known, on_hash: &on_hash, ..engine::Hooks::default() };
    let (job, sid) = (s.job, s.session.clone());
    let mut emit = |p: &engine::Progress| {
        let _ = app.emit(
            "recovery-progress",
            serde_json::json!({
                "job": job, "sessionId": sid, "filesDone": p.files_done, "filesTotal": p.files_total,
                "bytesDone": p.bytes_done, "bytesTotal": p.bytes_total, "current": p.current,
                "bytesPerSec": p.bytes_per_sec.round() as u64, "etaSeconds": p.eta_seconds.map(|e| e.round() as u64),
            }),
        );
    };
    store::log(&s.session, LogLevel::Info, &format!("Recovering {} file(s) to {}.", s.ids.len(), s.dest.display()));
    let out = engine::recover_files(src, &s.ids, &load, s.bytes_total, &s.dest, &s.label, &s.opts, &s.cancel, &hooks, &mut emit);

    for r in out.results.iter().filter(|r| r.result == engine::ResultKind::Failed) {
        let why = r.notes.last().cloned().unwrap_or_default();
        store::log(&s.session, LogLevel::Error, &format!("Couldn't recover {}\\{}: {why}", r.folder, r.name));
    }
    let state = if out.cancelled {
        "cancelled"
    } else if out.stopped.is_some() {
        "failed"
    } else {
        "done"
    };
    let mut errors: Vec<String> = out.errors.clone();
    let mut report_path = None;
    if s.report && !out.results.is_empty() {
        match write_recovery_report(&s, &out, state) {
            Ok(p) => report_path = Some(p.to_string_lossy().into_owned()),
            Err(e) => errors.push(e),
        }
    }
    store::log(
        &s.session,
        if state == "done" { LogLevel::Info } else { LogLevel::Warn },
        &format!(
            "Recovery {state}: {} recovered, {} partial, {} repaired, {} failed, {} duplicates skipped.",
            out.recovered, out.partial, out.repaired, out.failed, out.skipped_duplicates
        ),
    );
    let rec = RecoveryRecord {
        job: s.job,
        session_id: s.session.clone(),
        session_label: s.label.clone(),
        dest: out.base.to_string_lossy().into_owned(),
        started,
        finished: now_ms(),
        state: state.into(),
        recovered: out.recovered,
        partial: out.partial,
        failed: out.failed,
        repaired: out.repaired,
        skipped_duplicates: out.skipped_duplicates,
        bytes: out.bytes,
        report_path: report_path.clone(),
    };
    if let Err(e) = history::append(rec) {
        store::log(&s.session, LogLevel::Warn, &e);
    }
    errors.truncate(20);
    let _ = app.emit(
        "recovery-done",
        serde_json::json!({
            "job": s.job, "sessionId": s.session, "state": state,
            "recovered": out.recovered, "partial": out.partial, "failed": out.failed, "repaired": out.repaired,
            "skippedDuplicates": out.skipped_duplicates, "bytes": out.bytes,
            "dest": out.base.to_string_lossy(), "reportPath": report_path, "errors": errors,
        }),
    );
}

fn recovery_rows(out: &engine::Outcome) -> Vec<report::ReportRow> {
    out.results
        .iter()
        .map(|r| {
            let mut notes = r.notes.clone();
            if let Some(p) = &r.path {
                let written = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                if written != r.name {
                    notes.insert(0, format!("Saved as {written}."));
                }
            }
            report::ReportRow {
                name: r.name.clone(),
                folder: r.folder.clone(),
                size: r.size,
                type_label: type_label(&r.type_id),
                condition: r.condition,
                condition_note: r.note.clone(),
                result: r.result.label().into(),
                hash: r.hash.clone().unwrap_or_default(),
                notes: notes.join(" "),
            }
        })
        .collect()
}

fn recovery_meta(source: &str, label: &str, dest: &Path, out: &engine::Outcome, state: &str, selected: usize) -> report::ReportMeta {
    let mut summary = vec![
        ("Source".to_string(), source.to_string()),
        ("Session".to_string(), label.to_string()),
        ("Date".to_string(), report::local_time(now_ms())),
        ("Destination".to_string(), dest.display().to_string()),
        ("Files selected".to_string(), selected.to_string()),
        ("Recovered".to_string(), out.recovered.to_string()),
        ("Partial".to_string(), out.partial.to_string()),
        ("Repaired".to_string(), out.repaired.to_string()),
        ("Failed".to_string(), out.failed.to_string()),
        ("Duplicates skipped".to_string(), out.skipped_duplicates.to_string()),
        ("Written".to_string(), format!("{} ({} bytes)", crate::model::human_size(out.bytes), out.bytes)),
    ];
    match state {
        "cancelled" => summary.push(("State".into(), "Cancelled before every file was recovered.".into())),
        "failed" => summary.push(("State".into(), out.stopped.clone().unwrap_or_else(|| "Stopped early.".into()))),
        _ => {}
    }
    report::ReportMeta { title: "MAX Recovery Report".into(), summary, result_header: "Result".into() }
}

fn write_recovery_report(s: &JobSpec, out: &engine::Outcome, state: &str) -> Result<PathBuf, String> {
    let fail = |_| "MAX couldn't write the recovery report into the destination folder.".to_string();
    // The session folder must not be a link to somewhere unchecked (before and after creating it).
    let mut checked = HashSet::new();
    if names::exists(&out.base) {
        engine::check_no_links(&s.dest, &out.base, &mut checked)?;
    }
    std::fs::create_dir_all(&out.base).map_err(fail)?;
    engine::check_no_links(&s.dest, &out.base, &mut checked)?;
    let meta = recovery_meta(&describe_source(&s.src_ref), &s.label, &out.base, out, state, s.ids.len());
    let rows = recovery_rows(out);
    let (h, c) = report_paths(&out.base, "MAX Recovery Report");
    report::write_atomic(&h, report::html(&meta, &rows).as_bytes()).map_err(fail)?;
    report::write_atomic(&c, &report::csv(&meta, &rows)).map_err(fail)?;
    Ok(h)
}

// ---------------------------------------------------------------------------- scan report

fn scan_row(f: &FoundFile, h: Option<&str>) -> report::ReportRow {
    let mut notes = Vec::new();
    if let Some(m) = f.modified {
        notes.push(format!("Modified {}.", report::local_time(m)));
    }
    if let Some(d) = f.deleted {
        notes.push(format!("Deleted {}.", report::local_time(d)));
    }
    if let Some(p) = f.meta.get("originalPath") {
        notes.push(format!("Originally {p}."));
    }
    report::ReportRow {
        name: f.name.clone(),
        folder: f.folder.clone(),
        size: f.size,
        type_label: type_label(&f.type_id),
        condition: f.condition,
        condition_note: f.note.clone(),
        result: status_label(f.status).into(),
        hash: h.unwrap_or_default().to_string(),
        notes: notes.join(" "),
    }
}

/// Columns the scan report needs (no extents or resident bytes).
const REPORT_COLS: &str = "name, folder, size, type_id, status, condition, note, modified, deleted, meta, hash";

fn report_file_from_row(r: &rusqlite::Row) -> rusqlite::Result<(FoundFile, Option<String>)> {
    use crate::scan::query::{parse_condition, parse_status};
    let meta: Option<String> = r.get(9)?;
    let f = FoundFile {
        name: r.get(0)?,
        folder: r.get(1)?,
        size: r.get::<_, i64>(2)?.max(0) as u64,
        type_id: r.get(3)?,
        status: parse_status(&r.get::<_, String>(4)?),
        condition: parse_condition(&r.get::<_, String>(5)?),
        note: r.get(6)?,
        modified: r.get(7)?,
        deleted: r.get(8)?,
        meta: meta.and_then(|m| serde_json::from_str(&m).ok()).unwrap_or_default(),
        ..Default::default()
    };
    Ok((f, r.get(10)?))
}

fn export_scan_report(session: &str, label: &str, src_ref: &SourceRef, path: &str, format: &str, query: Option<FileQuery>) -> Result<String, String> {
    let fmt = format.trim().to_ascii_lowercase();
    if fmt != "html" && fmt != "csv" {
        return Err("Pick HTML or CSV for the report.".into());
    }
    let mut p = dest::normalize(path)?;
    let lower = p.to_ascii_lowercase();
    let has_ext = if fmt == "html" { lower.ends_with(".html") || lower.ends_with(".htm") } else { lower.ends_with(".csv") };
    if !has_ext {
        p.push_str(if fmt == "html" { ".html" } else { ".csv" });
    }
    let file = PathBuf::from(&p);
    let parent = file.parent().map(|d| d.to_string_lossy().into_owned()).ok_or("Pick a file name inside a folder.")?;
    if !Path::new(&parent).is_dir() {
        return Err("That folder doesn't exist. Pick another place for the report.".into());
    }
    if file.is_dir() {
        return Err("That's a folder. Type a file name for the report.".into());
    }
    let (check, _) = dest::run_check(&parent, src_ref, &[]);
    if !check.ok {
        return Err(check.error.unwrap_or_else(|| "Pick another place for the report.".into()));
    }
    if src_ref.kind == SourceKind::Image && dest::normalize(&src_ref.path).map(|i| i.eq_ignore_ascii_case(&p)).unwrap_or(false) {
        return Err("That location is the disk image you are recovering from. Pick a folder on another drive.".into());
    }
    // Stream: one aggregate query for the summary, then one ordered query whose rows go straight
    // to the file, so a million-file session never sits in memory.
    let q = query.unwrap_or_default();
    let w = crate::scan::query::build_where(&q, true);
    let html = fmt == "html";
    let write_failed = "MAX couldn't write the report there. Pick another folder.";
    // The shared session connection is only touched to check the file (and build missing indexes);
    // the export reads through its own connection, so list paging and counts aren't held up while
    // a large report goes to a slow drive. One read transaction keeps summary and rows consistent.
    crate::scan::session::with_conn(session, |_| Ok(()))?;
    let c = crate::scan::session::open_read(&crate::scan::session::session_path(session)?)?;
    let export = |c: &rusqlite::Connection| -> Result<(), String> {
        use crate::scan::session::db_err;
        use rusqlite::params_from_iter;
        c.execute_batch("BEGIN").map_err(db_err)?;
        let (count, total): (i64, i64) = c
            .query_row(&format!("SELECT count(*), coalesce(sum(size), 0) FROM files WHERE {}", w.sql), params_from_iter(w.params.iter()), |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(db_err)?;
        let total = total.max(0) as u64;
        let summary = vec![
            ("Source".to_string(), describe_source(src_ref)),
            ("Session".to_string(), label.to_string()),
            ("Date".to_string(), report::local_time(now_ms())),
            ("Files".to_string(), count.max(0).to_string()),
            ("Total size".to_string(), format!("{} ({total} bytes)", crate::model::human_size(total))),
        ];
        let meta = report::ReportMeta { title: "MAX Scan Report".into(), summary, result_header: "Status".into() };
        let sql = format!("SELECT {REPORT_COLS} FROM files WHERE {} ORDER BY {}", w.sql, crate::scan::query::order_by(&q));
        let mut st = c.prepare(&sql).map_err(db_err)?;
        let mut rows = st.query(params_from_iter(w.params.iter())).map_err(db_err)?;
        let mut db_error: Option<String> = None;
        let written = report::write_atomic_with(&file, |out| {
            use std::io::Write;
            let mut buf = String::with_capacity(1 << 17);
            if html {
                report::html_head(&mut buf, &meta);
            } else {
                report::csv_head(&mut buf, &meta);
            }
            loop {
                let row = match rows.next().and_then(|r| r.map(report_file_from_row).transpose()) {
                    Ok(Some(r)) => r,
                    Ok(None) => break,
                    Err(e) => {
                        db_error = Some(db_err(e));
                        return Err(std::io::Error::other("database"));
                    }
                };
                let rr = scan_row(&row.0, row.1.as_deref());
                if html {
                    report::html_row(&mut buf, &rr);
                } else {
                    report::csv_row(&mut buf, &rr);
                }
                if buf.len() >= 1 << 16 {
                    out.write_all(buf.as_bytes())?;
                    buf.clear();
                }
            }
            if html {
                buf.push_str(report::HTML_TAIL);
            }
            out.write_all(buf.as_bytes())
        });
        written.map_err(|_| db_error.take().unwrap_or_else(|| write_failed.to_string()))
    };
    let result = export(&c);
    let _ = c.execute_batch("ROLLBACK");
    result?;
    Ok(p)
}

// ------------------------------------------------------------------------------- duplicates

fn quick_hash(src: Option<&dyn crate::device::source::BlockSource>, f: &FoundFile) -> Option<[u8; 32]> {
    let mut h = blake3::Hasher::new();
    h.update(&f.size.to_le_bytes());
    let mut buf = vec![0u8; dupes::EDGE.min(f.size as usize)];
    let (n, _) = crate::fileread::read_at(src, f, 0, &mut buf).ok()?;
    h.update(&buf[..n]);
    if f.size > dupes::EDGE as u64 {
        let (n, _) = crate::fileread::read_at(src, f, f.size - buf.len() as u64, &mut buf).ok()?;
        h.update(&buf[..n]);
    }
    Some(*h.finalize().as_bytes())
}

fn full_hash(src: Option<crate::device::source::Source>, f: FoundFile, cancel: &AtomicBool) -> Option<String> {
    use std::io::Read;
    let mut r = crate::fileread::FileReader::new(src, f);
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; 4 << 20];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return None;
        }
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                h.update(&buf[..n]);
            }
            Err(_) => return None,
        }
    }
    Some(h.finalize().to_hex().to_string())
}

fn run_dupes(app: &tauri::AppHandle, job: u64, session: &str, cancel: &AtomicBool) {
    let done = |state: &str, r: Option<&dupes::DupResult>| {
        let _ = app.emit(
            "dupes-done",
            serde_json::json!({
                "job": job, "sessionId": session, "state": state,
                "groups": r.map_or(0, |r| r.group_count), "files": r.map_or(0, |r| r.files),
                "wastedBytes": r.map_or(0, |r| r.wasted_bytes),
            }),
        );
    };
    let entries = match store::sizes_and_hashes(session) {
        Ok(e) => e,
        Err(e) => {
            store::log(session, LogLevel::Error, &e);
            return done("failed", None);
        }
    };
    let src = store::open_session_source(session).ok();
    let quick = |id: i64, _size: u64| {
        let f = store::get_file(session, id).ok()?;
        quick_hash(src.as_deref(), &f)
    };
    let full = |id: i64| {
        let f = store::get_file(session, id).ok()?;
        full_hash(src.clone(), f, cancel)
    };
    let mut last = std::time::Instant::now();
    let mut progress = |d: u64, t: u64| {
        if last.elapsed() >= std::time::Duration::from_millis(250) || d == t {
            last = std::time::Instant::now();
            let _ = app.emit("dupes-progress", serde_json::json!({"job": job, "sessionId": session, "done": d, "total": t}));
        }
    };
    match dupes::group(&entries, &quick, &full, cancel, &mut progress) {
        Ok(r) => {
            for (id, h) in &r.computed {
                let _ = store::set_hash(session, *id, h);
            }
            if let Err(e) = store::set_dup_groups(session, &r.groups) {
                store::log(session, LogLevel::Error, &e);
                return done("failed", None);
            }
            store::log(
                session,
                LogLevel::Info,
                &format!("Found {} group(s) of identical files ({} files, {} could be saved).", r.group_count, r.files, crate::model::human_size(r.wasted_bytes)),
            );
            done("done", Some(&r));
        }
        Err(_) => done("cancelled", None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_report_end_to_end_without_store() {
        let t = engine::tests::TempDir::new("report");
        let files = vec![
            FoundFile { name: "<b>bold</b>.txt".into(), folder: "\\A&B".into(), size: 2, type_id: "txt".into(), resident: Some(b"hi".to_vec()), ..Default::default() },
            FoundFile { name: "same.txt".into(), folder: "\\A&B".into(), size: 2, type_id: "txt".into(), resident: Some(b"hi".to_vec()), ..Default::default() },
        ];
        let load = |id: i64| Ok(files[(id - 1) as usize].clone());
        let cancel = AtomicBool::new(false);
        let out = engine::recover_files(None, &[1, 2], &load, 4, &t.0, "Card", &engine::EngineOpts::default(), &cancel, &engine::Hooks::default(), &mut |_| {});
        assert_eq!((out.recovered, out.skipped_duplicates), (1, 1));
        let src = SourceRef { kind: SourceKind::Image, path: "E:\\card.img".into(), ..Default::default() };
        let spec = JobSpec {
            job: 1,
            session: "s".into(),
            label: "Card".into(),
            src_ref: src,
            dest: t.0.clone(),
            ids: vec![1, 2],
            bytes_total: 4,
            opts: engine::EngineOpts::default(),
            report: true,
            cancel: Arc::new(AtomicBool::new(false)),
        };
        let h = write_recovery_report(&spec, &out, "done").unwrap();
        assert!(h.starts_with(&t.0));
        assert_eq!(h.file_name().unwrap(), "MAX Recovery Report.html");
        let html = std::fs::read_to_string(&h).unwrap();
        assert!(html.contains("&lt;b&gt;bold&lt;/b&gt;.txt") && !html.contains("<b>bold"));
        assert!(html.contains("duplicate skipped") && html.contains("Disk image E:\\card.img"));
        let csv = std::fs::read(h.with_extension("csv")).unwrap();
        assert_eq!(&csv[..3], b"\xEF\xBB\xBF");
        // A second report doesn't overwrite the first.
        let h2 = write_recovery_report(&spec, &out, "cancelled").unwrap();
        assert_eq!(h2.file_name().unwrap(), "MAX Recovery Report (2).html");
    }

    /// Totals for the destination check (cached, one aggregate query) and the streamed scan report,
    /// on a real (temporary) session file.
    #[test]
    fn totals_and_streamed_scan_report() {
        let src = SourceRef { kind: SourceKind::Image, path: std::env::temp_dir().join("maxrec-no-such.img").to_string_lossy().into_owned(), ..Default::default() };
        let (id, path) = crate::scan::session::create(&src, "quick").unwrap();
        crate::scan::session::with_conn(&id, |c| {
            for (i, (name, size, status)) in [("a.jpg", 10i64, "deleted"), ("b<x>.txt", 5_000_000_000, "deleted"), ("c.txt", 7, "existing")].iter().enumerate() {
                c.execute(
                    "INSERT INTO files(id, name, name_lc, folder, folder_lc, ext, type_id, category, size, status, origin, condition, cond_rank, note, fragmented, flags, meta, hash)
                     VALUES (?1, ?2, lower(?2), '\\A', '\\a', '', 'txt', 'documents', ?3, ?4, 'filesystem', 'good', 1, '', 0, 0, '{\"originalPath\":\"C:\\\\x\"}', ?5)",
                    rusqlite::params![i as i64 + 1, name, size, status, if i == 0 { Some("abcd") } else { None }],
                )
                .map_err(|e| e.to_string())?;
            }
            Ok(())
        })
        .unwrap();
        let all = FileQuery::default();
        let t = selection_totals(&id, None, Some(&all)).unwrap();
        assert_eq!(t, Totals { need: 5_000_000_017, big: 1 });
        let deleted = FileQuery { statuses: Some(vec!["deleted".into()]), ..Default::default() };
        assert_eq!(selection_totals(&id, None, Some(&deleted)).unwrap(), Totals { need: 5_000_000_010, big: 1 });
        assert_eq!(selection_totals(&id, Some(&[3, 1, 3]), None).unwrap(), Totals { need: 17, big: 0 });
        // Cached: same answer without touching the store.
        assert_eq!(selection_totals(&id, None, Some(&all)).unwrap().need, 5_000_000_017);

        let out = engine::tests::TempDir::new("scanreport");
        let html = export_scan_report(&id, "Card", &src, &out.0.join("r").to_string_lossy(), "html", None).unwrap();
        assert!(html.ends_with("r.html"));
        let h = std::fs::read_to_string(&html).unwrap();
        assert!(h.contains("b&lt;x&gt;.txt") && h.contains("abcd") && h.contains("Originally C:\\x.") && h.ends_with(report::HTML_TAIL));
        assert!(h.find("a.jpg").unwrap() < h.find("c.txt").unwrap());
        assert!(h.contains("<dt>Files</dt><dd>3</dd>"));
        let csv = export_scan_report(&id, "Card", &src, &out.0.join("r.csv").to_string_lossy(), "csv", Some(deleted)).unwrap();
        let c = std::fs::read_to_string(&csv).unwrap();
        assert!(c.contains("Files,2\r\n") && c.contains("a.jpg") && !c.contains("c.txt"));
        assert_eq!(std::fs::read_dir(&out.0).unwrap().count(), 2, "no temp files left");

        crate::scan::session::evict(&id);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sources_are_described() {
        let v = SourceRef { kind: SourceKind::Volume, path: "C".into(), ..Default::default() };
        assert_eq!(describe_source(&v), "Drive C:");
        let d = SourceRef { kind: SourceKind::Disk, path: "1".into(), offset: 1048576, label: Some("Kingston".into()), ..Default::default() };
        assert_eq!(describe_source(&d), "Kingston — Disk 1, partition starting at byte 1048576");
    }
}
