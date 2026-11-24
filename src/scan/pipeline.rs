//! The stage pipeline (CONTRACT "Scan pipeline"). Runs on the job's own thread, without Tauri:
//! engines come in through the [`Engines`] trait (tests inject fakes) and events go out through an
//! emitter closure. Each stage runs under `catch_unwind`, so a panicking engine fails the session
//! ("Something went wrong…") instead of the app.

use super::jobs::{Job, STAGE_FS, STAGE_RECYCLE, STAGE_SWEEP};
use super::session::{self, K_CONDITION_POS, K_HARVEST_POS, K_PARTITIONS};
use super::writer::{CondUpdate, Msg};
use super::StageInfo;
use crate::device::source::BlockSource;
use crate::model::{ChunkVisitor, EngineSummary, FoundFile, FsProbe, ScanCtx, SourceKind, CANCELLED};
use crate::partitions::PartitionReport;
use rayon::prelude::*;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

/// Everything the pipeline needs from the engines. `RealEngines` calls the crate's modules; tests
/// implement this with fakes.
pub trait Engines: Send + Sync {
    fn probe(&self, src: &dyn BlockSource) -> Option<FsProbe>;
    fn quick_scan(&self, probe: &FsProbe, src: &dyn BlockSource, ctx: &ScanCtx) -> Result<EngineSummary, String>;
    /// Sweep visitors of the file systems: the recognised one, or all of them when `probe` is None.
    fn fs_sweep_visitors(&self, probe: Option<&FsProbe>) -> Vec<Box<dyn ChunkVisitor>>;
    fn carver(&self, ctx: &ScanCtx) -> Box<dyn ChunkVisitor>;
    fn recycle_bin(&self, letter: &str, ctx: &ScanCtx) -> Result<EngineSummary, String>;
    fn assess(&self, src: &dyn BlockSource, f: &mut FoundFile);
    fn analyze_partitions(&self, src: &dyn BlockSource) -> Result<PartitionReport, String>;
    fn search_partitions(&self, src: &dyn BlockSource, ctx: &ScanCtx) -> Result<PartitionReport, String>;
}

pub struct RealEngines;

impl Engines for RealEngines {
    fn probe(&self, src: &dyn BlockSource) -> Option<FsProbe> {
        crate::fs::probe_any(src)
    }
    fn quick_scan(&self, probe: &FsProbe, src: &dyn BlockSource, ctx: &ScanCtx) -> Result<EngineSummary, String> {
        match probe.fs.as_str() {
            "NTFS" => crate::fs::ntfs::quick_scan(src, ctx),
            "exFAT" => crate::fs::exfat::quick_scan(src, ctx),
            _ => crate::fs::fat::quick_scan(src, ctx),
        }
    }
    fn fs_sweep_visitors(&self, probe: Option<&FsProbe>) -> Vec<Box<dyn ChunkVisitor>> {
        match probe.map(|p| p.fs.as_str()) {
            Some("NTFS") => vec![crate::fs::ntfs::sweep_visitor(probe)],
            Some("exFAT") => vec![crate::fs::exfat::sweep_visitor(probe)],
            Some(_) => vec![crate::fs::fat::sweep_visitor(probe)],
            None => vec![crate::fs::ntfs::sweep_visitor(None), crate::fs::exfat::sweep_visitor(None), crate::fs::fat::sweep_visitor(None)],
        }
    }
    fn carver(&self, ctx: &ScanCtx) -> Box<dyn ChunkVisitor> {
        crate::carve::visitor(ctx)
    }
    fn recycle_bin(&self, letter: &str, ctx: &ScanCtx) -> Result<EngineSummary, String> {
        crate::recyclebin::scan_volume(letter, ctx)
    }
    fn assess(&self, src: &dyn BlockSource, f: &mut FoundFile) {
        crate::content::assess(src, f)
    }
    fn analyze_partitions(&self, src: &dyn BlockSource) -> Result<PartitionReport, String> {
        crate::partitions::analyze(src)
    }
    fn search_partitions(&self, src: &dyn BlockSource, ctx: &ScanCtx) -> Result<PartitionReport, String> {
        crate::partitions::search_lost(src, ctx)
    }
}

pub type Emit = Arc<dyn Fn(&str, serde_json::Value) + Send + Sync>;

#[derive(Clone)]
pub struct Config {
    pub engines: Arc<dyn Engines>,
    pub emit: Emit,
    /// Sweep chunk size (4 MiB; tests use smaller chunks).
    pub chunk: u64,
    /// Progress tick.
    pub tick: Duration,
}

impl Config {
    pub fn new(engines: Arc<dyn Engines>, emit: Emit) -> Self {
        Config { engines, emit, chunk: 4 << 20, tick: Duration::from_millis(250) }
    }
}

pub const NO_FS_NOTE: &str = "No NTFS, FAT or exFAT file system was recognised here. A deep scan can still find files by their content.";

pub fn stage_label(key: &str) -> &'static str {
    match key {
        "filesystem" => "Reading the file system",
        "recyclebin" => "Checking the Recycle Bin",
        "sweep" => "Reading every sector",
        "rebuild" => "Rebuilding lost folders and files",
        "condition" => "Checking each file's condition",
        "partitions" => "Searching for partitions",
        _ => "Scanning",
    }
}

pub fn stage_list(mode: &str, source: &crate::model::SourceRef) -> Vec<StageInfo> {
    let keys: Vec<&str> = match mode {
        "partitions" => vec!["partitions"],
        "deep" => {
            let mut v = vec!["filesystem"];
            if source.kind == SourceKind::Volume {
                v.push("recyclebin");
            }
            v.extend(["sweep", "rebuild", "condition"]);
            v
        }
        _ => {
            let mut v = vec!["filesystem"];
            if source.kind == SourceKind::Volume {
                v.push("recyclebin");
            }
            v.push("condition");
            v
        }
    };
    keys.into_iter().map(|k| StageInfo { key: k.into(), label: stage_label(k).into(), state: "pending".into(), note: None }).collect()
}

pub enum Outcome {
    Done,
    Cancelled,
    Failed(String),
}

enum StageEnd {
    Done(Option<String>),
    Skipped(Option<String>),
}

fn stage_code(key: &str) -> u8 {
    match key {
        "filesystem" => STAGE_FS,
        "recyclebin" => STAGE_RECYCLE,
        "sweep" | "rebuild" => STAGE_SWEEP,
        _ => 0,
    }
}

fn set_stage_state(job: &Job, i: usize, state: &str, note: Option<String>) {
    let json = {
        let mut st = job.stages.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = st.get_mut(i) {
            s.state = state.to_string();
            if note.is_some() || state == "running" {
                s.note = note;
            }
        }
        session::json_value(&*st)
    };
    job.writer.send(Msg::Meta(session::K_STAGES.into(), json));
}

fn stage_index(job: &Job, key: &str) -> Option<usize> {
    job.stages.lock().unwrap_or_else(|e| e.into_inner()).iter().position(|s| s.key == key)
}

/// Add a sentence to the session notes (deduplicated) and the log.
pub fn add_note(job: &Job, note: &str) {
    let note = note.trim();
    if note.is_empty() {
        return;
    }
    let json = {
        let mut n = job.notes.lock().unwrap_or_else(|e| e.into_inner());
        if n.iter().any(|x| x == note) {
            return;
        }
        n.push(note.to_string());
        session::json_value(&*n)
    };
    job.writer.send(Msg::Meta(session::K_NOTES.into(), json));
    job.ctx.info(note);
}

fn add_summary(job: &Job, s: &EngineSummary) {
    for n in &s.notes {
        add_note(job, n);
    }
}

pub fn run(job: Arc<Job>, cfg: Config) {
    // Bulk inserts ahead: index later, in one go.
    let inserting = job.stages.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|s| {
        matches!(s.key.as_str(), "filesystem" | "recyclebin" | "sweep" | "rebuild") && !matches!(s.state.as_str(), "done" | "skipped")
    });
    if inserting {
        job.writer.send(Msg::Indexes(false));
    }
    let outcome = run_stages(&job, &cfg);
    if matches!(outcome, Outcome::Cancelled) {
        // Saved before the index build, so closing MAX meanwhile keeps it a stopped scan.
        super::jobs::save_stopped(&job);
    }
    job.ctx.set_stage("Organising the results", 0);
    job.writer.send(Msg::Indexes(true));
    job.writer.flush();
    super::jobs::finish(&job, &cfg, outcome);
}

fn run_stages(job: &Job, cfg: &Config) -> Outcome {
    let n = job.stages.lock().unwrap_or_else(|e| e.into_inner()).len();
    let mut visitors: Option<Vec<Box<dyn ChunkVisitor>>> = None;
    for i in 0..n {
        let (key, state) = {
            let st = job.stages.lock().unwrap_or_else(|e| e.into_inner());
            (st[i].key.clone(), st[i].state.clone())
        };
        if state == "done" || state == "skipped" {
            continue;
        }
        // A Stop that came as the sweep ended (its last chunks were already read) still lets the
        // rebuild collect what the sweep found; otherwise a resume would read the whole sweep again.
        let collect = key == "rebuild" && visitors.is_some() && job.fatal().is_none();
        if job.ctx.is_cancelled() && !collect {
            return Outcome::Cancelled;
        }
        job.stage_idx.store(i, Ordering::Relaxed);
        job.stage_code.store(stage_code(&key), Ordering::Relaxed);
        set_stage_state(job, i, "running", None);
        job.ctx.set_stage(&key, 0);
        let r = catch_unwind(AssertUnwindSafe(|| run_stage(job, cfg, &key, &mut visitors)));
        match r {
            Ok(Ok(StageEnd::Done(note))) => set_stage_state(job, i, "done", note),
            Ok(Ok(StageEnd::Skipped(note))) => set_stage_state(job, i, "skipped", note),
            Ok(Err(e)) if e == CANCELLED => {
                if let Some(f) = job.fatal() {
                    set_stage_state(job, i, "failed", Some(f.clone()));
                    return Outcome::Failed(f);
                }
                // The sweep stage handles its own state (it harvests what it read first).
                if key != "sweep" {
                    set_stage_state(job, i, "pending", Some("Stopped before it finished.".into()));
                }
                return Outcome::Cancelled;
            }
            Ok(Err(e)) => {
                if let Some(f) = job.fatal() {
                    set_stage_state(job, i, "failed", Some(f.clone()));
                    return Outcome::Failed(f);
                }
                tracing::warn!("scan stage {key} failed: {e}");
                job.ctx.warn(e.clone());
                add_note(job, &e);
                set_stage_state(job, i, "failed", Some(e));
            }
            Err(p) => {
                let what = p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_default();
                tracing::error!("scan stage {key} panicked: {what}");
                job.ctx.log(crate::model::LogLevel::Error, format!("The {} step stopped unexpectedly: {what}", stage_label(&key).to_lowercase()));
                set_stage_state(job, i, "failed", None);
                return Outcome::Failed(format!(
                    "Something went wrong while scanning ({}). The results found so far are kept.",
                    stage_label(&key).to_lowercase()
                ));
            }
        }
        super::jobs::checkpoint(job, true);
    }
    match job.fatal() {
        Some(f) => Outcome::Failed(f),
        None => Outcome::Done,
    }
}

fn run_stage(job: &Job, cfg: &Config, key: &str, visitors: &mut Option<Vec<Box<dyn ChunkVisitor>>>) -> Result<StageEnd, String> {
    match key {
        "filesystem" => stage_filesystem(job, cfg),
        "recyclebin" => {
            let letter = job.source.path.trim().trim_end_matches(['\\', ':']).to_string();
            let s = cfg.engines.recycle_bin(&letter, &job.ctx)?;
            add_summary(job, &s);
            Ok(StageEnd::Done(None))
        }
        "sweep" => stage_sweep(job, cfg, visitors),
        "rebuild" => {
            let Some(v) = visitors.take() else { return Ok(StageEnd::Done(None)) };
            // A Stop pressed now waits for the rebuild, so the sweep isn't read again on resume.
            job.harvest_guarded(|| harvest(job, &v))?;
            let pos = job.sweep_pos.load(Ordering::Relaxed);
            job.harvest_pos.store(pos, Ordering::Relaxed);
            job.writer.meta(K_HARVEST_POS, pos as i64);
            Ok(StageEnd::Done(None))
        }
        "condition" => stage_condition(job, cfg),
        "partitions" => {
            job.ctx.set_stage("partitions", job.src.len());
            let rep = cfg.engines.search_partitions(job.src.as_ref(), &job.ctx)?;
            for n in &rep.notes {
                add_note(job, n);
            }
            job.writer.send(Msg::Meta(K_PARTITIONS.into(), session::json_value(&rep)));
            Ok(StageEnd::Done(None))
        }
        _ => Ok(StageEnd::Skipped(None)),
    }
}

fn whole_disk(job: &Job) -> bool {
    matches!(job.source.kind, SourceKind::Disk | SourceKind::Image) && job.source.offset == 0 && job.source.length.map_or(true, |l| l >= job.src.len())
}

fn stage_filesystem(job: &Job, cfg: &Config) -> Result<StageEnd, String> {
    if job.mode == "deep" && whole_disk(job) {
        match cfg.engines.analyze_partitions(job.src.as_ref()) {
            Ok(rep) => job.writer.send(Msg::Meta(K_PARTITIONS.into(), session::json_value(&rep))),
            Err(e) => job.ctx.info(format!("Partition table: {e}")),
        }
    }
    let probe = job.ctx.probe.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let Some(p) = probe else {
        add_note(job, NO_FS_NOTE);
        return Ok(StageEnd::Skipped(Some(NO_FS_NOTE.into())));
    };
    job.ctx.info(format!("Found a {} file system{}.", p.fs, if p.label.is_empty() { String::new() } else { format!(" named \"{}\"", p.label) }));
    if p.used_backup_boot {
        add_note(job, "The first boot sector is damaged, so MAX used its backup copy.");
    }
    let s = cfg.engines.quick_scan(&p, job.src.as_ref(), &job.ctx)?;
    add_summary(job, &s);
    Ok(StageEnd::Done(None))
}

/// Call every visitor's `finish` (file systems first, so their files are in `known_starts` before
/// the carver resolves its hits). A failing visitor is logged and the others still run.
fn harvest(job: &Job, visitors: &[Box<dyn ChunkVisitor>]) -> Result<(), String> {
    let ctx = &job.ctx;
    ctx.set_stage("rebuild", visitors.len() as u64);
    for v in visitors {
        ctx.check()?;
        match v.finish(job.src.as_ref(), ctx) {
            Ok(s) => add_summary(job, &s),
            Err(e) if e == CANCELLED => return Err(e),
            Err(e) => {
                ctx.warn(format!("{}: {e}", v.name()));
                add_note(job, &e);
            }
        }
        ctx.progress(1);
    }
    Ok(())
}

fn stage_sweep(job: &Job, cfg: &Config, visitors: &mut Option<Vec<Box<dyn ChunkVisitor>>>) -> Result<StageEnd, String> {
    let ctx = &job.ctx;
    let probe = ctx.probe.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mut vis = cfg.engines.fs_sweep_visitors(probe.as_ref());
    vis.push(cfg.engines.carver(ctx));
    let start = job.harvest_pos.load(Ordering::Relaxed);
    job.seg.store(start, Ordering::Relaxed);
    let skip_allocated = probe.is_some() && ctx.options.carve_free_only.unwrap_or(true);
    match super::sweep::run(job, cfg.chunk, &vis, start, skip_allocated) {
        Ok(()) => {
            job.writer.meta(session::K_SWEEP_POS, job.src.len() as i64);
            *visitors = Some(vis);
            Ok(StageEnd::Done(None))
        }
        Err(e) if e == CANCELLED => {
            // Keep what the visitors found in the part that was read: run their finish now, then
            // a resumed session continues the sweep from here.
            let pos = job.sweep_pos.load(Ordering::Relaxed);
            job.writer.meta(session::K_SWEEP_POS, pos as i64);
            let len = job.src.len().max(1);
            let pct = (pos as u128 * 100 / len as u128) as u64;
            if let Some(i) = stage_index(job, "sweep") {
                set_stage_state(job, i, "pending", Some(format!("Stopped at {pct}%.")));
            }
            if job.fatal().is_none() {
                let ri = stage_index(job, "rebuild");
                if let Some(ri) = ri {
                    job.stage_idx.store(ri, Ordering::Relaxed);
                    set_stage_state(job, ri, "running", None);
                }
                // Further Stops wait for this (they would throw the whole sweep away).
                let h = job.harvest_guarded(|| harvest(job, &vis));
                if h.is_ok() {
                    job.harvest_pos.store(pos, Ordering::Relaxed);
                    job.writer.meta(K_HARVEST_POS, pos as i64);
                } else if let Some(i) = stage_index(job, "sweep") {
                    // Only what was collected counts: a resume reads again from there.
                    let hp = job.harvest_pos.load(Ordering::Relaxed);
                    let hpct = (hp as u128 * 100 / len as u128) as u64;
                    set_stage_state(job, i, "pending", Some(format!("Stopped at {hpct}%.")));
                }
                if let Some(ri) = ri {
                    set_stage_state(job, ri, "pending", None);
                }
                ctx.cancel.store(true, Ordering::Relaxed);
            }
            Err(CANCELLED.into())
        }
        Err(e) => Err(e),
    }
}

/// Assess every not-existing file not assessed yet (in id order, from the checkpoint), four at a
/// time (random reads), and store what changed.
fn stage_condition(job: &Job, cfg: &Config) -> Result<StageEnd, String> {
    let ctx = &job.ctx;
    job.writer.flush();
    let conn = session::open_path(&job.path, false)?;
    let mut pos = job.condition_pos.load(Ordering::Relaxed);
    const WHERE: &str = "status <> 'existing' AND live_path IS NULL";
    let total: i64 = conn.query_row(&format!("SELECT count(*) FROM files WHERE id > ?1 AND {WHERE}"), [pos], |r| r.get(0)).map_err(session::db_err)?;
    ctx.set_stage("condition", total.max(0) as u64);
    if total == 0 {
        return Ok(StageEnd::Done(None));
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .thread_name(|i| format!("max-assess-{i}"))
        .build()
        .map_err(|_| "MAX couldn't start checking the files.".to_string())?;
    let src = job.src.clone();
    let sql = format!("SELECT {} FROM files WHERE id > ?1 AND {WHERE} ORDER BY id LIMIT 512", super::query::FILE_COLS);
    loop {
        ctx.check()?;
        let batch: Vec<(i64, FoundFile)> = {
            let mut st = conn.prepare_cached(&sql).map_err(session::db_err)?;
            let rows = st.query_map([pos], super::query::file_from_row).map_err(session::db_err)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(session::db_err)?
        };
        let Some(last) = batch.last().map(|b| b.0) else { break };
        let updates: Vec<Option<CondUpdate>> = pool.install(|| {
            batch
                .into_par_iter()
                .map(|(id, mut f)| {
                    if ctx.check().is_err() {
                        return None;
                    }
                    let before = (f.condition, f.note.clone(), f.flags, f.type_id.clone());
                    cfg.engines.assess(src.as_ref(), &mut f);
                    ctx.progress(1);
                    let after = (f.condition, f.note.clone(), f.flags, f.type_id.clone());
                    (before != after).then(|| CondUpdate { id, condition: f.condition, note: f.note, flags: f.flags, type_id: f.type_id })
                })
                .collect()
        });
        if ctx.is_cancelled() {
            return Err(CANCELLED.into());
        }
        for u in updates.into_iter().flatten() {
            job.writer.send(Msg::Update(Box::new(u)));
        }
        pos = last;
        job.condition_pos.store(pos, Ordering::Relaxed);
        job.writer.meta(K_CONDITION_POS, pos);
    }
    Ok(StageEnd::Done(None))
}
