//! Running scans: the job registry (several sessions at once), start / pause / cancel / resume,
//! the progress ticker (events + checkpoints), the end of a job, and crash restoration.

use super::map::{self, LiveRanges, Sets};
use super::pipeline::{self, Config, Outcome};
use super::session::{self, *};
use super::writer::{source_flags, Msg, Writer};
use super::{ScanStarted, StageInfo};
use crate::device::source::Source;
use crate::model::{FoundFile, FsProbe, LogLevel, MapKind, ScanCtx, ScanOptions, SourceKind, SourceRef};
use serde_json::json;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Stage codes stored with each file row, so a re-run of an unfinished stage can drop its
/// partial results first.
pub const STAGE_FS: u8 = 1;
pub const STAGE_RECYCLE: u8 = 2;
pub const STAGE_SWEEP: u8 = 3;

const MAX_LOG_LINES: u64 = 50_000;

pub struct Job {
    pub id: u64,
    pub session: String,
    pub path: PathBuf,
    pub ctx: Arc<ScanCtx>,
    pub src: Source,
    pub source: SourceRef,
    pub mode: String,
    pub writer: Arc<Writer>,
    pub ranges: Arc<LiveRanges>,
    pub stages: Mutex<Vec<StageInfo>>,
    pub stage_idx: AtomicUsize,
    pub stage_code: Arc<AtomicU8>,
    pub seg: Arc<AtomicU64>,
    pub sweep_pos: AtomicU64,
    pub harvest_pos: AtomicU64,
    pub condition_pos: AtomicI64,
    pub notes: Mutex<Vec<String>>,
    pub finished: AtomicBool,
    pub ticker: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// True while visitors' results are collected (`harvest`): a Stop then waits for it to
    /// finish instead of throwing the sweep away. Its lock also orders cancels against it.
    pub harvesting: Mutex<bool>,
    /// Stop was pressed (shown as "stopping" while a harvest finishes).
    pub stop_requested: AtomicBool,
    /// Held while a pause / continue state is saved and while the job is marked finished, so a
    /// late pause never overwrites the final state.
    pub state_lock: Mutex<()>,
    /// Map set versions last saved by a checkpoint.
    pub saved_versions: Mutex<[u64; 5]>,
}

impl Job {
    /// A fatal store error (the writer couldn't save): the scan must stop.
    pub fn fatal(&self) -> Option<String> {
        self.writer.error()
    }
    /// Collect the visitors' results without being stopped half way: a Stop pressed meanwhile is
    /// applied when `f` returns. Returns `f`'s result.
    pub fn harvest_guarded<R>(&self, f: impl FnOnce() -> R) -> R {
        {
            let mut h = self.harvesting.lock().unwrap_or_else(|e| e.into_inner());
            *h = true;
            if self.fatal().is_none() {
                self.ctx.cancel.store(false, Ordering::Relaxed);
            }
        }
        let r = f();
        let mut h = self.harvesting.lock().unwrap_or_else(|e| e.into_inner());
        *h = false;
        if self.stop_requested.load(Ordering::Relaxed) {
            self.ctx.cancel.store(true, Ordering::Relaxed);
        }
        r
    }
    pub fn stage_key(&self) -> (usize, String, String) {
        let i = self.stage_idx.load(Ordering::Relaxed);
        let st = self.stages.lock().unwrap_or_else(|e| e.into_inner());
        let s = st.get(i).cloned().unwrap_or_default();
        (i, s.key, s.label)
    }
}

fn jobs() -> &'static Mutex<HashMap<String, Arc<Job>>> {
    static J: OnceLock<Mutex<HashMap<String, Arc<Job>>>> = OnceLock::new();
    J.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_JOB: AtomicU64 = AtomicU64::new(1);

pub fn running(session: &str) -> Option<Arc<Job>> {
    jobs().lock().unwrap_or_else(|e| e.into_inner()).get(session).cloned()
}

/// The sources every running scan reads (no new session may be written onto them).
pub fn running_sources() -> Vec<SourceRef> {
    jobs().lock().unwrap_or_else(|e| e.into_inner()).values().map(|j| j.source.clone()).collect()
}

/// The session files of every running scan (they grow while the scan runs).
pub fn running_session_files() -> Vec<PathBuf> {
    jobs().lock().unwrap_or_else(|e| e.into_inner()).values().map(|j| j.path.clone()).collect()
}

// ------------------------------------------------------------------------------- sources

#[cfg(test)]
pub fn test_sources() -> &'static Mutex<HashMap<String, Source>> {
    static T: OnceLock<Mutex<HashMap<String, Source>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Open a source read-only (tests: in-memory sources registered by path win).
pub fn open(r: &SourceRef) -> Result<Source, String> {
    #[cfg(test)]
    {
        let base = test_sources().lock().unwrap().get(&r.path).cloned();
        if let Some(b) = base {
            return crate::device::source::window(b, r.offset, r.length);
        }
    }
    crate::device::source::open_source(r)
}

// --------------------------------------------------------------------------------- start

fn default_include_existing(source: &SourceRef, probe: Option<&FsProbe>) -> bool {
    matches!(source.kind, SourceKind::Image | SourceKind::Snapshot)
        || source.offset > 0
        || (source.kind == SourceKind::Volume && probe.is_none())
        || probe.is_some_and(|p| p.used_backup_boot)
}

#[derive(Default)]
struct Restore {
    sets: Sets,
    known_starts: HashSet<u64>,
    files_found: u64,
    sweep_pos: u64,
    harvest_pos: u64,
    condition_pos: i64,
    notes: Vec<String>,
}

pub fn start(cfg: Config, source: SourceRef, options: ScanOptions) -> Result<ScanStarted, String> {
    let mode = options.mode.trim().to_ascii_lowercase();
    if !matches!(mode.as_str(), "quick" | "deep" | "partitions") {
        return Err("Pick a quick scan, a deep scan or a partition search.".into());
    }
    if mode == "partitions" && (!matches!(source.kind, SourceKind::Disk | SourceKind::Image) || source.offset > 0 || source.length.is_some()) {
        return Err("Searching for lost partitions needs a whole disk or disk image. Pick the disk instead of one of its drives.".into());
    }
    // A folder scan: a quick scan of the folder's volume that keeps only that folder's files.
    // Carved files have no folder, so a deep scan can't be limited to one.
    let folder = options.folder.as_deref().map(super::writer::norm_folder).filter(|f| !f.is_empty());
    if folder.is_some() {
        if mode != "quick" {
            return Err("A folder scan is a quick scan. To search every sector, scan the whole drive.".into());
        }
        if source.kind != SourceKind::Volume || source.offset > 0 || source.length.is_some() {
            return Err("A folder scan needs a drive letter. Pick the folder again, or scan the whole drive.".into());
        }
    }
    let src = open(&source)?;
    if src.len() == 0 {
        return Err("This drive reports a size of zero bytes, so there is nothing to scan.".into());
    }
    let probe = if mode == "partitions" { None } else { cfg.engines.probe(src.as_ref()) };
    let mut opts = options.clone();
    opts.mode = mode.clone();
    opts.folder = folder.clone();
    if opts.include_existing.is_none() {
        opts.include_existing = Some(default_include_existing(&source, probe.as_ref()));
    }
    if opts.carve_free_only.is_none() {
        opts.carve_free_only = Some(probe.is_some());
    }
    // A running scan's session file on this drive would grow onto the space being searched.
    session::check_running_sessions(&source)?;
    // Keep the session off the drive being scanned when another drive can hold it: the same
    // decision scan_location previewed (session::decide).
    let loc = session::pick_location(&source)?;
    let (id, path) = session::create_in(&loc.dir, &source, &mode)?;
    if loc.external {
        session::register_external(&path);
    }
    let mut notes: Vec<String> = loc.note.into_iter().collect();
    if let Some(f) = &folder {
        notes.push(format!(
            "Folder scan: only files from {}:{f} and its subfolders are listed. Files whose folder record is gone (Lost folders) and files found only by their content need a scan of the whole drive.",
            source.path.trim_end_matches([':', '\\'])
        ));
    }
    let label = opts
        .label
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| folder.as_ref().map(|f| format!("{}:{f}", source.path.trim_end_matches([':', '\\']))))
        .or_else(|| source.label.clone().filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(|| src.describe());
    let stages = pipeline::stage_list(&mode, &source);
    {
        let c = session::open_path(&path, false)?;
        c.execute_batch("BEGIN").map_err(|_| WRITE_FAILED.to_string())?;
        let now = crate::model::now_ms();
        meta_set_json(&c, K_SOURCE, &source)?;
        meta_set_json(&c, K_OPTIONS, &opts)?;
        meta_set(&c, K_LABEL, &label)?;
        meta_set(&c, K_MODE, &mode)?;
        meta_set(&c, K_STATE, "running")?;
        meta_set(&c, K_CREATED, now)?;
        meta_set(&c, K_UPDATED, now)?;
        meta_set(&c, K_SOURCE_LEN, src.len() as i64)?;
        meta_set(&c, K_SECTOR_SIZE, src.sector_size() as i64)?;
        meta_set_json(&c, K_PROBE, &probe)?;
        meta_set_json(&c, K_STAGES, &stages)?;
        meta_set_json(&c, K_NOTES, &notes)?;
        meta_set(&c, K_SWEEP_POS, 0i64)?;
        meta_set(&c, K_HARVEST_POS, 0i64)?;
        meta_set(&c, K_CONDITION_POS, 0i64)?;
        meta_set(&c, K_FILES, 0i64)?;
        meta_set(&c, K_BYTES, 0i64)?;
        set_pid(&c)?;
        c.execute_batch("COMMIT").map_err(|_| WRITE_FAILED.to_string())?;
    }
    let restore = Restore { notes: notes.clone(), ..Default::default() };
    let r = launch(cfg, id.clone(), path.clone(), source, src, opts, probe, stages, restore)?;
    if let Some(j) = running(&id) {
        if loc.external {
            j.ctx.info(format!("The session file is {}.", path.display()));
        }
        for n in &notes {
            j.ctx.info(n.clone());
        }
    }
    Ok(r)
}

fn set_pid(c: &rusqlite::Connection) -> Result<(), String> {
    let pid = std::process::id();
    meta_set(c, K_PID, pid as i64)?;
    meta_set(c, K_PID_STARTED, session::process_started(pid))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn launch(
    cfg: Config,
    id: String,
    path: PathBuf,
    source: SourceRef,
    src: Source,
    options: ScanOptions,
    probe: Option<FsProbe>,
    stages: Vec<StageInfo>,
    restore: Restore,
) -> Result<ScanStarted, String> {
    let writer = Writer::spawn(&id, path.clone())?;
    let live = Arc::new(LiveRanges::new(restore.sets.clone()));
    let stage_code = Arc::new(AtomicU8::new(0));
    let seg = Arc::new(AtomicU64::new(restore.harvest_pos));

    let extra = source_flags(source.kind);
    let (tx, sc, sg) = (writer.tx.clone(), stage_code.clone(), seg.clone());
    let sink = Box::new(move |mut f: FoundFile| {
        f.flags |= extra;
        let _ = tx.send(Msg::File(Box::new(f), sc.load(Ordering::Relaxed), sg.load(Ordering::Relaxed)));
    });
    let lv = live.clone();
    let ranges = Box::new(move |k: MapKind, s: u64, e: u64| lv.add(k, s, e));
    let (tx2, lines) = (writer.tx.clone(), AtomicU64::new(0));
    let logger = Box::new(move |level: LogLevel, m: String| {
        let n = lines.fetch_add(1, Ordering::Relaxed);
        if n < MAX_LOG_LINES {
            let _ = tx2.send(Msg::Log(crate::model::now_ms(), level, m));
        } else if n == MAX_LOG_LINES {
            let _ = tx2.send(Msg::Log(crate::model::now_ms(), LogLevel::Warn, "Further messages were left out of this log.".into()));
        }
    });
    #[cfg_attr(test, allow(unused_mut))]
    let mut ctx = ScanCtx::new(options.clone(), src.len(), src.sector_size(), sink, ranges, logger);
    #[cfg(not(test))]
    if options.custom_signatures != Some(false) {
        ctx.custom_signatures = crate::settings::custom_signatures();
    }
    *ctx.allocated.write().unwrap_or_else(|e| e.into_inner()) = restore.sets[MapKind::Allocated.index()].clone();
    *ctx.known_starts.lock().unwrap_or_else(|e| e.into_inner()) = restore.known_starts;
    ctx.files_found.store(restore.files_found, Ordering::Relaxed);
    ctx.bad_bytes.store(restore.sets[MapKind::Bad.index()].total(), Ordering::Relaxed);
    *ctx.probe.lock().unwrap_or_else(|e| e.into_inner()) = probe;
    let ctx = Arc::new(ctx);

    let job = Arc::new(Job {
        id: NEXT_JOB.fetch_add(1, Ordering::Relaxed),
        session: id.clone(),
        path,
        ctx,
        src,
        source,
        mode: options.mode.clone(),
        writer,
        ranges: live,
        stages: Mutex::new(stages),
        stage_idx: AtomicUsize::new(0),
        stage_code,
        seg,
        sweep_pos: AtomicU64::new(restore.sweep_pos),
        harvest_pos: AtomicU64::new(restore.harvest_pos),
        condition_pos: AtomicI64::new(restore.condition_pos),
        notes: Mutex::new(restore.notes),
        finished: AtomicBool::new(false),
        ticker: Mutex::new(None),
        harvesting: Mutex::new(false),
        stop_requested: AtomicBool::new(false),
        state_lock: Mutex::new(()),
        saved_versions: Mutex::new([0; 5]),
    });
    {
        let mut m = jobs().lock().unwrap_or_else(|e| e.into_inner());
        if m.contains_key(&id) {
            job.writer.stop();
            return Err("This scan is already running.".into());
        }
        m.insert(id.clone(), job.clone());
    }
    let (j2, c2) = (job.clone(), cfg.clone());
    let t = std::thread::Builder::new().name(format!("max-scan-tick-{id}")).spawn(move || ticker(j2, c2));
    match t {
        Ok(h) => *job.ticker.lock().unwrap_or_else(|e| e.into_inner()) = Some(h),
        Err(_) => tracing::warn!("couldn't start the progress ticker"),
    }
    let j3 = job.clone();
    let spawned = std::thread::Builder::new().name(format!("max-scan-{id}")).stack_size(8 << 20).spawn(move || pipeline::run(j3, cfg));
    if spawned.is_err() {
        job.finished.store(true, Ordering::Relaxed);
        jobs().lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
        job.writer.meta(K_STATE, "failed");
        job.writer.stop();
        return Err("MAX couldn't start the scan. Close some programs and try again.".into());
    }
    Ok(ScanStarted { session_id: id, job: job.id })
}

// ------------------------------------------------------------------------ pause / cancel

pub fn pause(session: &str, paused: bool) -> Result<(), String> {
    let job = running(session).ok_or("This scan isn't running any more.")?;
    job.ctx.paused.store(paused, Ordering::Relaxed);
    // Saving the state goes through the writer queue, which may be busy: not on the caller's
    // (possibly the UI) thread.
    // The saved state is the current one (a later toggle wins), and nothing is saved once the
    // job is finishing (its final state must stay).
    std::thread::spawn(move || {
        let _g = job.state_lock.lock().unwrap_or_else(|e| e.into_inner());
        // Once stopping, the saved state is the stopped one (see `save_stopped`).
        if job.finished.load(Ordering::Relaxed) || job.stop_requested.load(Ordering::Relaxed) {
            return;
        }
        let now = job.ctx.paused.load(Ordering::Relaxed);
        job.writer.meta(K_STATE, if now { "paused" } else { "running" });
        job.writer.meta(K_UPDATED, crate::model::now_ms());
        job.ctx.info(if paused { "Paused." } else { "Continued." });
    });
    Ok(())
}

/// Stop a scan. While the visitors' results are being collected (after a Stop, or in the rebuild
/// stage) the stop waits for that to finish, so the sweep read so far is kept.
pub fn cancel(session: &str) -> Result<(), String> {
    let job = running(session).ok_or("This scan isn't running any more.")?;
    job.stop_requested.store(true, Ordering::Relaxed);
    job.ctx.paused.store(false, Ordering::Relaxed);
    let h = job.harvesting.lock().unwrap_or_else(|e| e.into_inner());
    if !*h {
        job.ctx.cancel.store(true, Ordering::Relaxed);
    }
    drop(h);
    Ok(())
}

// --------------------------------------------------------------------------------- resume

pub fn resume(cfg: Config, id: &str) -> Result<ScanStarted, String> {
    if running(id).is_some() {
        return Err("This scan is already running.".into());
    }
    let path = session_path(id)?;
    if !path.is_file() {
        return Err(GONE.into());
    }
    session::evict(id);
    let c = session::open_path(&path, false)?;
    let state: String = meta_get(&c, K_STATE).unwrap_or_default();
    if state == "done" {
        return Err("This scan has already finished. Start a new scan to look again.".into());
    }
    let source: SourceRef = meta_json(&c, K_SOURCE).ok_or(DAMAGED)?;
    let options: ScanOptions = meta_json(&c, K_OPTIONS).ok_or(DAMAGED)?;
    let mode: String = meta_get(&c, K_MODE).unwrap_or_else(|| options.mode.clone());
    let mut stages: Vec<StageInfo> = meta_json(&c, K_STAGES).unwrap_or_else(|| pipeline::stage_list(&mode, &source));
    let probe: Option<FsProbe> = meta_json(&c, K_PROBE).unwrap_or(None);
    let notes: Vec<String> = meta_json(&c, K_NOTES).unwrap_or_default();
    let source_len = meta_get::<i64>(&c, K_SOURCE_LEN).unwrap_or(0) as u64;
    let harvest_pos = meta_get::<i64>(&c, K_HARVEST_POS).unwrap_or(0).max(0) as u64;
    let sweep_pos = meta_get::<i64>(&c, K_SWEEP_POS).unwrap_or(0).max(0) as u64;
    let condition_pos = meta_get::<i64>(&c, K_CONDITION_POS).unwrap_or(0);
    // Nothing may grow on a drive another running scan reads, in either direction.
    session::check_running_sessions(&source)?;
    session::check_results_drive(&path)?;

    let src = open(&source)?;
    if source_len != 0 && src.len() != source_len {
        return Err("This drive's size changed since the scan started, so the scan can't be continued. Start a new scan.".into());
    }

    // Stages that didn't finish run again; a sweep must be repeated when its results weren't
    // collected (the rebuild didn't finish).
    for s in stages.iter_mut() {
        if !matches!(s.state.as_str(), "done" | "skipped") {
            s.state = "pending".into();
        }
    }
    let rebuild_pending = stages.iter().any(|s| s.key == "rebuild" && s.state == "pending");
    if rebuild_pending {
        for s in stages.iter_mut().filter(|s| s.key == "sweep") {
            s.state = "pending".into();
        }
    }
    let pending = |k: &str| stages.iter().any(|s| s.key == k && s.state == "pending");
    let mut del: Vec<String> = Vec::new();
    if pending("filesystem") {
        del.push(format!("stage = {STAGE_FS}"));
    }
    if pending("recyclebin") {
        del.push(format!("stage = {STAGE_RECYCLE}"));
    }
    if pending("sweep") {
        del.push(format!("(stage = {STAGE_SWEEP} AND seg >= {harvest_pos})"));
    }
    c.execute_batch("BEGIN").map_err(|_| WRITE_FAILED.to_string())?;
    if !del.is_empty() {
        let w = del.join(" OR ");
        let r = c
            .execute(&format!("DELETE FROM file_extents WHERE file_id IN (SELECT id FROM files WHERE {w})"), [])
            .and_then(|_| c.execute(&format!("DELETE FROM files WHERE {w}"), []));
        if r.is_err() {
            let _ = c.execute_batch("ROLLBACK");
            return Err(WRITE_FAILED.into());
        }
    }
    // The map: persisted sets, with Recoverable rebuilt from the files that are left.
    let mut sets = map::load_sets(&c);
    {
        let mut st = c
            .prepare("SELECT e.start_off, e.end_off FROM file_extents e JOIN files f ON f.id = e.file_id WHERE f.status IN ('deleted', 'lost', 'carved') ORDER BY e.start_off")
            .map_err(db_err)?;
        let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64))).map_err(db_err)?;
        let v: Vec<(u64, u64)> = rows.filter_map(Result::ok).collect();
        sets[MapKind::Recoverable.index()].ranges = map::merge_sorted(&v, &[]);
    }
    let known_starts: HashSet<u64> = {
        let mut st = c.prepare("SELECT first_off FROM files WHERE status <> 'carved' AND first_off IS NOT NULL").map_err(db_err)?;
        let rows = st.query_map([], |r| r.get::<_, i64>(0)).map_err(db_err)?;
        rows.filter_map(Result::ok).map(|v| v as u64).collect()
    };
    let (files_found, bytes_found) =
        c.query_row("SELECT count(*), coalesce(sum(size), 0) FROM files", [], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))).map_err(db_err)?;
    let max_extent = c.query_row("SELECT coalesce(max(end_off - start_off), 0) FROM file_extents", [], |r| r.get::<_, i64>(0)).map_err(db_err)?;
    let files_found = files_found.max(0) as u64;
    // The running totals the file list shows during a scan: rows dropped above no longer count.
    meta_set(&c, K_FILES, files_found as i64)?;
    meta_set(&c, K_BYTES, bytes_found)?;
    meta_set(&c, K_MAX_EXTENT, max_extent)?;
    meta_set(&c, K_STATE, "running")?;
    meta_set(&c, K_UPDATED, crate::model::now_ms())?;
    meta_set(&c, K_ERROR, rusqlite::types::Null)?;
    meta_set_json(&c, K_STAGES, &stages)?;
    set_pid(&c)?;
    map::save_direct(&c, &sets)?;
    c.execute_batch("COMMIT").map_err(|_| WRITE_FAILED.to_string())?;
    drop(c);
    session::bump(id);

    let restore = Restore { sets, known_starts, files_found, sweep_pos, harvest_pos, condition_pos, notes };
    let r = launch(cfg, id.to_string(), path, source, src, options, probe, stages, restore)?;
    if let Some(j) = running(id) {
        j.ctx.info(if harvest_pos > 0 { format!("Continuing the scan from byte {harvest_pos}.") } else { "Continuing the scan.".to_string() });
    }
    Ok(r)
}

// --------------------------------------------------------------------- ticker / progress

struct Rate {
    key: (usize, String),
    samples: VecDeque<(Instant, u64)>,
}

impl Rate {
    /// (per second, stable)
    fn update(&mut self, key: (usize, String), done: u64, paused: bool) -> (f64, bool) {
        let now = Instant::now();
        if key != self.key || paused || self.samples.back().is_some_and(|&(_, d)| done < d) {
            self.samples.clear();
            self.key = key;
        }
        if paused {
            return (0.0, false);
        }
        self.samples.push_back((now, done));
        while self.samples.len() > 2 && now.duration_since(self.samples[0].0) > Duration::from_secs(3) {
            self.samples.pop_front();
        }
        let (t0, d0) = self.samples[0];
        let dt = now.duration_since(t0).as_secs_f64();
        if dt < 0.75 {
            return (0.0, false);
        }
        let rate = (done - d0) as f64 / dt;
        // Stable: a 2+ second window whose two halves agree within a factor of two.
        let mid = self.samples[self.samples.len() / 2];
        let dt1 = mid.0.duration_since(t0).as_secs_f64();
        let dt2 = now.duration_since(mid.0).as_secs_f64();
        let stable = dt >= 2.0 && dt1 > 0.3 && dt2 > 0.3 && {
            let r1 = (mid.1 - d0) as f64 / dt1;
            let r2 = (done - mid.1) as f64 / dt2;
            r1 > 0.0 && r2 > 0.0 && r1 / r2 < 2.0 && r2 / r1 < 2.0
        };
        (rate, stable)
    }
}

fn progress_payload(job: &Job, rate: &mut Rate) -> serde_json::Value {
    let ctx = &job.ctx;
    let (idx, key, label) = job.stage_key();
    let n = job.stages.lock().unwrap_or_else(|e| e.into_inner()).len();
    let done = ctx.done.load(Ordering::Relaxed);
    let total = ctx.total.load(Ordering::Relaxed);
    let paused = ctx.paused.load(Ordering::Relaxed);
    let detail = ctx.stage();
    let (r, stable) = rate.update((idx, detail.clone()), done, paused);
    let eta = (stable && r > 0.0 && total > done).then(|| ((total - done) as f64 / r).ceil() as u64);
    let bytes_stage = matches!(key.as_str(), "sweep" | "partitions");
    let mut v = json!({
        "sessionId": job.session,
        "job": job.id,
        "state": if paused { "paused" } else { "running" },
        "stage": key,
        "stageLabel": label,
        "stageIndex": idx,
        "stageCount": n,
        "done": done,
        "total": total,
        "filesFound": ctx.files_found.load(Ordering::Relaxed),
        "bytesPerSec": if bytes_stage { r.round() as u64 } else { 0 },
        // From the merged set: sectors read again after a resume aren't counted twice.
        "badBytes": job.ranges.total(MapKind::Bad),
    });
    if job.stop_requested.load(Ordering::Relaxed) {
        v["stopping"] = json!(true);
    }
    if let Some(e) = eta {
        v["etaSeconds"] = json!(e);
    }
    if job.mode == "deep" {
        v["sweepPos"] = json!(job.sweep_pos.load(Ordering::Relaxed));
    }
    if !detail.is_empty() && detail != key {
        v["detail"] = json!(detail);
    }
    v
}

fn ticker(job: Arc<Job>, cfg: Config) {
    let mut rate = Rate { key: (usize::MAX, String::new()), samples: VecDeque::new() };
    let mut last_pos = Instant::now();
    let mut last_map = Instant::now();
    while !job.finished.load(Ordering::Relaxed) {
        (cfg.emit)("scan-progress", progress_payload(&job, &mut rate));
        if job.fatal().is_some() {
            job.ctx.cancel.store(true, Ordering::Relaxed);
        }
        if last_map.elapsed() >= Duration::from_secs(5) {
            checkpoint(&job, true);
            last_map = Instant::now();
            last_pos = Instant::now();
        } else if last_pos.elapsed() >= Duration::from_secs(2) {
            checkpoint(&job, false);
            last_pos = Instant::now();
        }
        // Sleep in small steps so the end of a job isn't delayed.
        let until = Instant::now() + cfg.tick;
        while Instant::now() < until && !job.finished.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(20).min(cfg.tick));
        }
    }
}

/// Persist the sweep position (and with `map`, the Recovery Map sets and their totals).
pub fn checkpoint(job: &Job, with_map: bool) {
    let w = &job.writer;
    if job.mode == "deep" {
        w.meta(K_SWEEP_POS, job.sweep_pos.load(Ordering::Relaxed) as i64);
    }
    w.meta(K_UPDATED, crate::model::now_ms());
    if with_map {
        // Only the sets that changed since the last save (Allocated and Metadata are mostly
        // fixed after the file-system stage; rewriting them every 5 s was megabytes of writes).
        let mut saved = job.saved_versions.lock().unwrap_or_else(|e| e.into_inner());
        let changed = job.ranges.changed_since(&saved);
        if changed.is_empty() {
            return;
        }
        w.meta(K_SCANNED, job.ranges.total(MapKind::Scanned) as i64);
        w.meta(K_BAD, job.ranges.total(MapKind::Bad) as i64);
        for (i, set, ver) in changed {
            w.send(Msg::Meta(session::k_ranges(i), rusqlite::types::Value::Blob(map::encode(&set))));
            saved[i] = ver;
        }
        w.meta(K_RANGES_AT, crate::model::now_ms());
    }
}

/// A stopped scan is saved as "cancelled" (with its map, stages and positions) as soon as its
/// stages end, before the slow end-of-scan work (building the indexes). Closing MAX waits only a
/// few seconds: if it ends the process during that work the session is still a stopped one that
/// can be continued, never one left "running". (When the process ends earlier, while a harvest
/// still runs, the state stays "running" and `restore_after_crash` makes it "interrupted"; its
/// positions then say to read the uncollected part of the sweep again.)
pub fn save_stopped(job: &Job) {
    {
        let _g = job.state_lock.lock().unwrap_or_else(|e| e.into_inner());
        job.stop_requested.store(true, Ordering::Relaxed); // no pause / continue is saved after this
        checkpoint(job, true);
        let w = &job.writer;
        w.send(Msg::Meta(K_STAGES.into(), session::json_value(&*job.stages.lock().unwrap_or_else(|e| e.into_inner()))));
        w.meta(K_STATE, "cancelled");
    }
    job.writer.flush();
}

/// End of a job: final checkpoint and state, writer closed, job unregistered, `scan-done`.
pub fn finish(job: &Arc<Job>, cfg: &Config, outcome: Outcome) {
    {
        let _g = job.state_lock.lock().unwrap_or_else(|e| e.into_inner());
        job.finished.store(true, Ordering::Relaxed);
    }
    if let Some(h) = job.ticker.lock().unwrap_or_else(|e| e.into_inner()).take() {
        let _ = h.join();
    }
    let (state, error) = match outcome {
        Outcome::Done => ("done", None),
        Outcome::Cancelled => ("cancelled", None),
        Outcome::Failed(e) => ("failed", Some(e)),
    };
    match state {
        "done" => job.ctx.info("The scan finished."),
        "cancelled" => job.ctx.info("The scan was stopped. The results found so far are kept."),
        _ => job.ctx.log(LogLevel::Error, error.clone().unwrap_or_default()),
    }
    checkpoint(job, true);
    let w = &job.writer;
    w.meta(K_STATE, state);
    match &error {
        Some(e) => w.meta(K_ERROR, e.clone()),
        None => w.meta(K_ERROR, rusqlite::types::Value::Null),
    }
    w.send(Msg::Meta(K_STAGES.into(), session::json_value(&*job.stages.lock().unwrap_or_else(|e| e.into_inner()))));
    w.flush();
    w.stop();
    // A write error during the final flush still fails the session.
    let (state, error) = match (state, job.writer.error()) {
        ("done", Some(e)) => ("failed", Some(e)),
        (s, _) => (s, error),
    };
    if state == "failed" {
        if let Ok(c) = session::open_path(&job.path, false) {
            let _ = meta_set(&c, K_STATE, "failed");
            let _ = meta_set(&c, K_ERROR, error.clone());
        }
    }
    session::bump(&job.session);
    {
        let mut m = jobs().lock().unwrap_or_else(|e| e.into_inner());
        if m.get(&job.session).is_some_and(|j| j.id == job.id) {
            m.remove(&job.session);
        }
    }
    let mut v = json!({
        "sessionId": job.session,
        "job": job.id,
        "state": state,
        "files": job.ctx.files_found.load(Ordering::Relaxed),
    });
    if let Some(e) = error {
        v["error"] = json!(e);
    }
    (cfg.emit)("scan-done", v);
}

// ------------------------------------------------------------------------- crash restore

/// Sessions whose process died while they were running (or paused) become "interrupted".
pub fn restore_after_crash() {
    let me = std::process::id();
    for (id, p) in session::all_session_files() {
        if running(&id).is_some() {
            continue;
        }
        let Ok(c) = session::open_path(&p, false) else { continue };
        let state: String = meta_get(&c, K_STATE).unwrap_or_default();
        if !matches!(state.as_str(), "running" | "paused") {
            continue;
        }
        let pid = meta_get::<i64>(&c, K_PID).unwrap_or(0) as u32;
        let started = meta_get::<i64>(&c, K_PID_STARTED);
        if pid == me || session::process_alive(pid, started) {
            continue;
        }
        let _ = meta_set(&c, K_STATE, "interrupted");
        let _ = c.execute(
            "INSERT INTO log(at, level, message) VALUES (?1, 'warn', ?2)",
            rusqlite::params![crate::model::now_ms(), "MAX closed before this scan finished. You can continue it."],
        );
    }
}
