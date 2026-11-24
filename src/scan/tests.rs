//! End-to-end tests of the scan core with fake engines and in-memory sources (no Tauri, no real
//! drives; session files go to a per-process temp folder).

use super::jobs::{self, test_sources};
use super::pipeline::{Config, Engines};
use super::session::{self, *};
use super::*;
use crate::device::source::{BlockSource, MemSource};
use crate::model::*;
use crate::partitions::PartitionReport;
use serde_json::Value as Json;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAGIC: &[u8; 8] = b"MAXFILE!";
const MIB: u64 = 1 << 20;

#[derive(Default)]
struct Fake {
    probe: Option<FsProbe>,
    fs_files: Vec<FoundFile>,
    allocated: Vec<(u64, u64)>,
    visit_delay_ms: u64,
    /// The carver's `finish` takes this long (checking for a stop as it goes).
    finish_delay_ms: u64,
    panic_quick: bool,
    /// Offsets of every chunk the carver saw, per carver instance (one per sweep run).
    visited: Arc<Mutex<Vec<Vec<u64>>>>,
    /// Visits of chunks at or after this offset wait until the gate opens.
    gate: Option<Arc<Gate>>,
}

/// Holds the carver's visits from an offset on, so a test can act at an exact sweep position.
struct Gate {
    at: u64,
    open: std::sync::atomic::AtomicBool,
    /// A visit is waiting at the gate.
    reached: std::sync::atomic::AtomicBool,
}

impl Gate {
    fn new(at: u64) -> Arc<Gate> {
        Arc::new(Gate { at, open: Default::default(), reached: Default::default() })
    }
    fn wait_reached(&self) {
        let t = Instant::now();
        while !self.reached.load(Ordering::SeqCst) {
            assert!(t.elapsed() < Duration::from_secs(30), "the sweep didn't reach the gate");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    fn release(&self) {
        self.open.store(true, Ordering::SeqCst);
    }
}

struct FakeCarver {
    hits: Mutex<Vec<u64>>,
    delay: u64,
    finish_delay: u64,
    visited: Arc<Mutex<Vec<Vec<u64>>>>,
    run: usize,
    gate: Option<Arc<Gate>>,
}

impl ChunkVisitor for FakeCarver {
    fn name(&self) -> &'static str {
        "fake-carver"
    }
    fn visit(&self, _: &dyn BlockSource, offset: u64, data: &[u8], _: &ScanCtx) {
        if let Some(g) = self.gate.as_ref().filter(|g| offset >= g.at) {
            let t = Instant::now();
            while !g.open.load(Ordering::SeqCst) && t.elapsed() < Duration::from_secs(60) {
                g.reached.store(true, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        self.visited.lock().unwrap()[self.run].push(offset);
        if self.delay > 0 {
            std::thread::sleep(Duration::from_millis(self.delay));
        }
        for i in (0..data.len()).step_by(512) {
            if data[i..].starts_with(MAGIC) {
                self.hits.lock().unwrap().push(offset + i as u64);
            }
        }
    }
    fn finish(&self, _: &dyn BlockSource, ctx: &ScanCtx) -> Result<EngineSummary, String> {
        for _ in 0..20 {
            if self.finish_delay == 0 {
                break;
            }
            ctx.check()?;
            std::thread::sleep(Duration::from_millis(self.finish_delay / 20));
        }
        let known = ctx.known_starts.lock().unwrap().clone();
        let mut hits = self.hits.lock().unwrap().clone();
        hits.sort();
        let mut n = 0;
        for h in hits {
            if known.contains(&h) || (ctx.options.carve_free_only == Some(true) && ctx.allocated.read().unwrap().contains(h)) {
                continue;
            }
            ctx.found(FoundFile {
                name: format!("file_{h:x}.max"),
                folder: "\\Found by signature\\Test file".into(),
                size: 1000,
                status: FileStatus::Carved,
                origin: Origin::Carving,
                type_id: "max".into(),
                extents: vec![Extent { offset: h, len: 1000 }],
                flags: flags::NAME_GUESSED,
                ..Default::default()
            });
            n += 1;
        }
        Ok(EngineSummary { files: n, notes: vec!["Carver finished.".into()], ..Default::default() })
    }
}

impl Engines for Fake {
    fn probe(&self, _: &dyn BlockSource) -> Option<FsProbe> {
        self.probe.clone()
    }
    fn quick_scan(&self, _: &FsProbe, _: &dyn BlockSource, ctx: &ScanCtx) -> Result<EngineSummary, String> {
        if self.panic_quick {
            panic!("engine bug");
        }
        ctx.mark(MapKind::Metadata, 0, 65536);
        ctx.mark(MapKind::Scanned, 0, 65536);
        for &(s, e) in &self.allocated {
            ctx.mark(MapKind::Allocated, s, e - s);
        }
        ctx.set_stage("Reading the MFT", self.fs_files.len() as u64);
        for f in &self.fs_files {
            ctx.check()?;
            if f.status != FileStatus::Existing || ctx.include_existing() {
                ctx.found(f.clone());
            }
            ctx.progress(1);
        }
        Ok(EngineSummary { files: self.fs_files.len() as u64, notes: vec!["Fake file system read.".into()], ..Default::default() })
    }
    fn fs_sweep_visitors(&self, _: Option<&FsProbe>) -> Vec<Box<dyn ChunkVisitor>> {
        Vec::new()
    }
    fn carver(&self, _: &ScanCtx) -> Box<dyn ChunkVisitor> {
        let mut v = self.visited.lock().unwrap();
        v.push(Vec::new());
        Box::new(FakeCarver { hits: Mutex::new(Vec::new()), delay: self.visit_delay_ms, finish_delay: self.finish_delay_ms, visited: self.visited.clone(), run: v.len() - 1, gate: self.gate.clone() })
    }
    fn recycle_bin(&self, _: &str, _: &ScanCtx) -> Result<EngineSummary, String> {
        Ok(EngineSummary::default())
    }
    fn assess(&self, _: &dyn BlockSource, f: &mut FoundFile) {
        if f.type_id == "jpg" {
            f.condition = Condition::Good;
            f.note = "The header matches.".into();
        }
    }
    fn analyze_partitions(&self, _: &dyn BlockSource) -> Result<PartitionReport, String> {
        Ok(PartitionReport { style: "None".into(), ..Default::default() })
    }
    fn search_partitions(&self, src: &dyn BlockSource, ctx: &ScanCtx) -> Result<PartitionReport, String> {
        ctx.progress(src.len());
        Ok(PartitionReport { style: "MBR".into(), disk_size: src.len(), notes: vec!["Found 0 lost partitions.".into()], ..Default::default() })
    }
}

type Events = Arc<Mutex<Vec<(String, Json)>>>;

fn config(engines: Fake, chunk: u64) -> (Config, Events) {
    let events: Events = Arc::new(Mutex::new(Vec::new()));
    let e2 = events.clone();
    let mut cfg = Config::new(Arc::new(engines), Arc::new(move |n: &str, v: Json| e2.lock().unwrap().push((n.to_string(), v))));
    cfg.chunk = chunk;
    cfg.tick = Duration::from_millis(40);
    (cfg, events)
}

fn mem_source(name: &str, data: Vec<u8>) -> SourceRef {
    test_sources().lock().unwrap().insert(name.to_string(), Arc::new(MemSource::new(data)));
    SourceRef { kind: SourceKind::Image, path: name.to_string(), ..Default::default() }
}

fn wait_done(events: &Events, job: u64) -> Json {
    let t = Instant::now();
    loop {
        if let Some((_, v)) = events.lock().unwrap().iter().find(|(n, v)| n == "scan-done" && v["job"] == job) {
            return v.clone();
        }
        assert!(t.elapsed() < Duration::from_secs(60), "scan didn't finish");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn file(name: &str, folder: &str, size: u64, status: FileStatus, off: u64, modified: i64) -> FoundFile {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    FoundFile {
        name: name.into(),
        folder: folder.into(),
        size,
        status,
        origin: Origin::Ntfs,
        type_id: ext,
        modified: Some(modified),
        extents: vec![Extent { offset: off, len: size.div_ceil(4096) * 4096 }],
        fs_ref: Some(off / 1024),
        meta: [("mftRecord".to_string(), (off / 1024).to_string())].into_iter().collect(),
        ..Default::default()
    }
}

fn ntfs_probe() -> FsProbe {
    FsProbe { fs: "NTFS".into(), cluster_size: 4096, sector_size: 512, total_size: 8 * MIB, ..Default::default() }
}

fn image_with_magic(len: u64, at: &[u64]) -> Vec<u8> {
    let mut d = vec![0x11u8; len as usize];
    for &a in at {
        d[a as usize..a as usize + 8].copy_from_slice(MAGIC);
    }
    d
}

fn fs_files() -> Vec<FoundFile> {
    vec![
        file("a.jpg", "\\Users\\Ann\\Pictures", 5000, FileStatus::Deleted, 2 * MIB, 1_000),
        file("B.JPG", "\\Users\\Ann\\Pictures\\", 300_000, FileStatus::Deleted, 3 * MIB + 512, 2_000),
        file("c.txt", "\\Users\\Bob", 10, FileStatus::Deleted, 4 * MIB, 3_000),
        file("d.pdf", "\\Lost folders\\Folder 12", 70_000, FileStatus::Lost, 5 * MIB, 4_000),
        file("e.txt", "", 42, FileStatus::Existing, 6 * MIB + 8192, 5_000),
    ]
}

fn query(f: impl FnOnce(&mut FileQuery)) -> FileQuery {
    let mut q = FileQuery::default();
    f(&mut q);
    q
}

fn qf(id: &str, q: &FileQuery) -> FilePage {
    session::with_conn(id, |c| super::query::query_files(id, c, q)).unwrap()
}

#[test]
fn deep_scan_end_to_end() {
    let data = image_with_magic(8 * MIB, &[MIB, 3 * MIB + 512, 6 * MIB]);
    let src = mem_source("e2e-deep", data);
    let fake = Fake { probe: Some(ntfs_probe()), fs_files: fs_files(), allocated: vec![(6 * MIB, 7 * MIB)], ..Default::default() };
    let (cfg, events) = config(fake, MIB);
    let st = jobs::start(cfg, src.clone(), ScanOptions { mode: "deep".into(), label: Some("E2E".into()), ..Default::default() }).unwrap();
    let done = wait_done(&events, st.job);
    assert_eq!(done["state"], "done", "{done}");
    let id = st.session_id.as_str();
    // 5 file-system files + 1 carved (3 MiB+512 is a known start, 6 MiB is inside live data).
    assert_eq!(done["files"], 6);
    let progress: Vec<Json> = events.lock().unwrap().iter().filter(|(n, v)| n == "scan-progress" && v["job"] == st.job).map(|e| e.1.clone()).collect();
    assert!(!progress.is_empty());
    assert!(progress.iter().all(|p| p["sessionId"] == id && p["stageCount"] == 4));

    let d = manage::get_session(id).unwrap();
    assert_eq!(d.summary.state, "done");
    assert_eq!(d.summary.label, "E2E");
    assert_eq!(d.summary.files, 6);
    assert_eq!(d.options.include_existing, Some(true)); // image source
    assert_eq!(d.options.carve_free_only, Some(true)); // a file system was recognised
    assert!(d.stages.iter().all(|s| s.state == "done"), "{:?}", d.stages);
    assert_eq!(d.partitions.as_ref().map(|p| p.style.as_str()), Some("None"));
    assert!(d.notes.iter().any(|n| n == "Fake file system read.") && d.notes.iter().any(|n| n == "Carver finished."));
    assert_eq!(d.counts.by_status.get("carved"), Some(&(1, 1000)));
    assert_eq!(d.counts.by_category.get("photo").map(|x| x.0), Some(2));
    assert_eq!(d.counts.by_condition.get("good").map(|x| x.0), Some(2)); // assessed jpgs
    assert_eq!(d.summary.scanned_bytes, 7 * MIB); // the live-data chunk was skipped

    // Queries: paging, sort, search, filters.
    let all = qf(id, &FileQuery::default());
    assert_eq!(all.total, 6);
    assert_eq!(all.total_size, 5000 + 300_000 + 10 + 70_000 + 42 + 1000);
    let names: Vec<_> = all.items.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["a.jpg", "B.JPG", "c.txt", "d.pdf", "e.txt", "file_100000.max"]);
    let p = qf(id, &query(|q| {
        q.sort = Some("size".into());
        q.desc = Some(true);
        q.offset = Some(1);
        q.limit = Some(2);
    }));
    assert_eq!(p.total, 6);
    assert_eq!(p.items.iter().map(|r| r.size).collect::<Vec<_>>(), [70_000, 5000]);
    assert_eq!(qf(id, &query(|q| q.search = Some("*.jpg".into()))).total, 2);
    assert_eq!(qf(id, &query(|q| q.search = Some(".JPG".into()))).total, 2);
    assert_eq!(qf(id, &query(|q| q.search = Some("b.".into()))).total, 1);
    assert_eq!(qf(id, &query(|q| q.search = Some("file_*".into()))).total, 1);
    assert_eq!(qf(id, &query(|q| q.categories = Some(vec!["photo".into()]))).total, 2);
    assert_eq!(qf(id, &query(|q| q.statuses = Some(vec!["lost".into(), "carved".into()]))).total, 2);
    assert_eq!(qf(id, &query(|q| q.conditions = Some(vec!["good".into()]))).total, 2);
    assert_eq!(qf(id, &query(|q| q.type_ids = Some(vec!["TXT".into()]))).total, 2);
    assert_eq!(qf(id, &query(|q| q.min_size = Some(5000))).total, 3);
    assert_eq!(qf(id, &query(|q| q.max_size = Some(42))).total, 2);
    let dates = qf(id, &query(|q| {
        q.date_from = Some(2_000);
        q.date_to = Some(4_000);
    }));
    assert_eq!(dates.total, 3);
    let rec = qf(id, &query(|q| {
        q.folder = Some("\\users".into());
        q.recursive = Some(true);
    }));
    assert_eq!(rec.total, 3);
    let exact = qf(id, &query(|q| q.folder = Some("\\Users\\Ann\\Pictures".into())));
    assert_eq!(exact.total, 2);
    assert_eq!(qf(id, &query(|q| q.folder = Some("".into()))).total, 1); // root: e.txt
    assert_eq!(qf(id, &query(|q| q.duplicates_only = Some(true))).total, 0);
    let row = &exact.items[0];
    assert_eq!(row.category, Category::Photo);
    assert_eq!(row.condition, Condition::Good);
    assert_eq!(row.meta.get("mftRecord").map(String::as_str), Some("2048"));
    let ids = store::query_ids(id, &query(|q| q.sort = Some("name".into()))).unwrap();
    assert_eq!(ids.len(), 6);

    // Folder tree.
    let fc = |parent: &str, q: Option<&FileQuery>| session::with_conn(id, |c| super::query::folder_children(id, c, parent, q)).unwrap();
    let top = fc("", None);
    assert_eq!(top.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(), ["Users", "Lost folders", "Found by signature"]);
    assert_eq!((top[0].files, top[0].size, top[0].has_children), (3, 305_010, true));
    let users = fc("\\Users", None);
    assert_eq!(users.iter().map(|n| (n.name.as_str(), n.files)).collect::<Vec<_>>(), [("Ann", 2), ("Bob", 1)]);
    assert_eq!(users[0].path, "\\Users\\Ann");
    let photos = query(|q| q.categories = Some(vec!["photo".into()]));
    let top_p = fc("", Some(&photos));
    assert_eq!(top_p.iter().map(|n| (n.name.as_str(), n.files)).collect::<Vec<_>>(), [("Users", 2)]);
    assert!(fc("\\Users\\Ann\\Pictures", None).is_empty());

    // Details and the store API.
    let fd = session::with_conn(id, |c| super::query::file_detail(c, row.id)).unwrap();
    assert_eq!(fd.extents, vec![Extent { offset: 2 * MIB, len: 8192 }]);
    assert_eq!(fd.source, src);
    let f = store::get_file(id, row.id).unwrap();
    assert_eq!((f.name.as_str(), f.fs_ref), ("a.jpg", Some(2048)));
    store::update_condition(id, row.id, Condition::Partial, "Overwritten.", flags::OVERWRITTEN).unwrap();
    store::update_meta(id, row.id, &[("width".to_string(), "640".to_string())].into_iter().collect()).unwrap();
    store::set_hash(id, row.id, "abc").unwrap();
    let f = store::get_file(id, row.id).unwrap();
    assert_eq!((f.condition, f.flags & flags::OVERWRITTEN != 0), (Condition::Partial, true));
    assert_eq!(f.meta.len(), 2);
    store::set_dup_groups(id, &[(row.id, 7), (all.items[1].id, 7)]).unwrap();
    assert_eq!(qf(id, &query(|q| q.duplicates_only = Some(true))).total, 2);
    assert_eq!(store::sizes_and_hashes(id).unwrap().iter().filter(|x| x.2.is_some()).count(), 1);
    assert_eq!(store::session_source_ref(id).unwrap(), src);
    assert_eq!(store::open_session_source(id).unwrap().len(), 8 * MIB);
    store::log(id, LogLevel::Info, "hello from a test");
    let log = manage::session_log(id, None, Some(5000)).unwrap();
    assert!(log.iter().any(|l| l.message == "hello from a test"));
    assert!(log.iter().any(|l| l.message == "The scan finished."));

    // Recovery Map.
    let m = manage::map_cells(id, None, None, 8).unwrap();
    assert_eq!((m.cell_bytes, m.source_len), (MIB, 8 * MIB));
    use base64::Engine;
    let cells = base64::engine::general_purpose::STANDARD.decode(&m.cells).unwrap();
    assert_eq!(cells.len(), 8);
    let s = MapKind::Scanned.bit();
    let a = MapKind::Allocated.bit();
    let r = MapKind::Recoverable.bit();
    assert_eq!(cells[0] & (s | MapKind::Metadata.bit()), s | MapKind::Metadata.bit());
    assert_eq!(cells[1], s | r); // the carved file
    assert_eq!(cells[6] & (s | a), a); // live data, skipped by the sweep
    assert_eq!(cells[7], s);
    assert_eq!(m.totals[MapKind::Scanned.index()], 7 * MIB);
    assert_eq!(m.totals[MapKind::Allocated.index()], MIB);
    let z = manage::map_cells(id, Some(MIB), Some(MIB + 4096), 4096).unwrap();
    assert_eq!(z.cell_bytes, 1);
    assert_eq!(z.totals[MapKind::Recoverable.index()], 1000);
    let reg = manage::map_region(id, MIB, MIB + 4096).unwrap();
    assert_eq!((reg.file_count, reg.first_sector, reg.last_sector), (1, 2048, 2055));
    assert_eq!(reg.files[0].status, FileStatus::Carved);
    let reg2 = manage::map_region(id, 2 * MIB + 4096, 3 * MIB + 1024).unwrap();
    assert_eq!(reg2.file_count, 2); // a.jpg's 2nd cluster, B.JPG's first sector
    assert_eq!(reg2.files[0].name, "B.JPG");

    // Listing and deleting.
    assert!(manage::list_sessions().unwrap().iter().any(|s| s.id == id && s.files == 6 && s.file_size > 0));
}

#[test]
fn quick_scan_and_volume_stages() {
    let src = mem_source("quick-src", vec![0u8; 4 * MIB as usize]);
    let fake = Fake { probe: Some(ntfs_probe()), fs_files: fs_files(), ..Default::default() };
    let (cfg, events) = config(fake, MIB);
    let st = jobs::start(cfg.clone(), src, ScanOptions { mode: "quick".into(), ..Default::default() }).unwrap();
    assert_eq!(wait_done(&events, st.job)["state"], "done");
    let d = manage::get_session(&st.session_id).unwrap();
    assert_eq!(d.stages.iter().map(|s| s.key.as_str()).collect::<Vec<_>>(), ["filesystem", "condition"]);
    assert_eq!(d.summary.files, 5);

    // A volume source: Recycle Bin stage, existing files hidden by default.
    test_sources().lock().unwrap().insert("Q".into(), Arc::new(MemSource::new(vec![0u8; MIB as usize])));
    let vol = SourceRef { kind: SourceKind::Volume, path: "Q".into(), ..Default::default() };
    let st = jobs::start(cfg.clone(), vol.clone(), ScanOptions::default()).unwrap();
    assert_eq!(wait_done(&events, st.job)["state"], "done");
    let d = manage::get_session(&st.session_id).unwrap();
    assert_eq!(d.stages.iter().map(|s| s.key.as_str()).collect::<Vec<_>>(), ["filesystem", "recyclebin", "condition"]);
    assert_eq!(d.summary.files, 4);
    assert_eq!(d.options.include_existing, Some(false));

    // Nothing recognised: the note, and the stage is skipped.
    let (cfg2, ev2) = config(Fake::default(), MIB);
    let st = jobs::start(cfg2, vol, ScanOptions::default()).unwrap();
    assert_eq!(wait_done(&ev2, st.job)["state"], "done");
    let d = manage::get_session(&st.session_id).unwrap();
    assert_eq!(d.stages[0].state, "skipped");
    assert!(d.notes.iter().any(|n| n == pipeline::NO_FS_NOTE));
    assert_eq!(d.options.include_existing, Some(true)); // RAW volume

    // Validation.
    let bad_mode = jobs::start(cfg.clone(), SourceRef::default(), ScanOptions { mode: "fast".into(), ..Default::default() });
    assert!(bad_mode.is_err());
    let vol_parts = jobs::start(cfg.clone(), SourceRef { kind: SourceKind::Volume, path: "Q".into(), ..Default::default() }, ScanOptions { mode: "partitions".into(), ..Default::default() });
    assert!(vol_parts.unwrap_err().contains("whole disk"));
}

#[test]
fn folder_scan_keeps_only_that_folder() {
    test_sources().lock().unwrap().insert("F".into(), Arc::new(MemSource::new(vec![0u8; MIB as usize])));
    let vol = SourceRef { kind: SourceKind::Volume, path: "F".into(), ..Default::default() };
    let fake = Fake { probe: Some(ntfs_probe()), fs_files: fs_files(), ..Default::default() };
    let (cfg, events) = config(fake, MIB);
    // Case, slashes and a trailing separator don't matter.
    let opts = ScanOptions { folder: Some("users/ANN\\".into()), ..Default::default() };
    let st = jobs::start(cfg.clone(), vol.clone(), opts).unwrap();
    assert_eq!(wait_done(&events, st.job)["state"], "done");
    let d = manage::get_session(&st.session_id).unwrap();
    assert_eq!(d.summary.files, 2, "only a.jpg and B.JPG are under \\Users\\Ann");
    assert_eq!(d.summary.label, "F:\\users\\ANN");
    assert_eq!(d.options.folder.as_deref(), Some("\\users\\ANN"));
    assert!(d.notes.iter().any(|n| n.starts_with("Folder scan:")));
    let page = qf(&st.session_id, &query(|_| {}));
    assert!(page.items.iter().all(|r| r.folder.to_lowercase().starts_with("\\users\\ann\\pictures")));

    // The drive's root is the whole drive (no scope).
    let st = jobs::start(cfg.clone(), vol.clone(), ScanOptions { folder: Some("\\".into()), ..Default::default() }).unwrap();
    assert_eq!(wait_done(&events, st.job)["state"], "done");
    let d = manage::get_session(&st.session_id).unwrap();
    assert_eq!(d.summary.files, 4);
    assert_eq!(d.options.folder, None);

    // Only quick scans of a volume.
    let deep = jobs::start(cfg.clone(), vol, ScanOptions { mode: "deep".into(), folder: Some("\\Users".into()), ..Default::default() });
    assert!(deep.unwrap_err().contains("quick scan"));
    let img = mem_source("folder-img", vec![0u8; MIB as usize]);
    let on_image = jobs::start(cfg, img, ScanOptions { folder: Some("\\Users".into()), ..Default::default() });
    assert!(on_image.unwrap_err().contains("drive letter"));

    // A sibling with the same prefix is outside the folder.
    let (ctx, _) = ScanCtx::for_test(ScanOptions { folder: Some("\\Users\\Ann".into()), ..Default::default() }, MIB);
    assert!(ctx.in_scope("\\USERS\\ann"));
    assert!(ctx.in_scope("\\Users\\Ann\\x\\y"));
    assert!(!ctx.in_scope("\\Users\\Annie"));
    assert!(!ctx.in_scope("\\Users"));
    assert!(!ctx.in_scope(""));
}

#[test]
fn partitions_mode_stores_the_report() {
    let src = mem_source("parts-src", vec![0u8; 2 * MIB as usize]);
    let (cfg, events) = config(Fake::default(), MIB);
    let st = jobs::start(cfg, src, ScanOptions { mode: "partitions".into(), ..Default::default() }).unwrap();
    assert_eq!(wait_done(&events, st.job)["state"], "done");
    let d = manage::get_session(&st.session_id).unwrap();
    assert_eq!(d.partitions.unwrap().style, "MBR");
    assert_eq!(d.stages.len(), 1);
}

#[test]
fn engine_panic_fails_the_session_not_the_app() {
    let src = mem_source("panic-src", vec![0u8; MIB as usize]);
    let fake = Fake { probe: Some(ntfs_probe()), panic_quick: true, ..Default::default() };
    let (cfg, events) = config(fake, MIB);
    let st = jobs::start(cfg, src, ScanOptions::default()).unwrap();
    let done = wait_done(&events, st.job);
    assert_eq!(done["state"], "failed");
    assert_eq!(done["error"], "Something went wrong while scanning (reading the file system). The results found so far are kept.");
    let d = manage::get_session(&st.session_id).unwrap();
    assert_eq!(d.summary.state, "failed");
    assert_eq!(d.stages[0].state, "failed");
    assert!(d.error.is_some());
}

#[test]
fn cancel_mid_sweep_then_resume_continues_from_checkpoint() {
    let len = 16 * MIB;
    let chunk = 256 * 1024;
    let hits: Vec<u64> = (0..16).map(|i| i * MIB + 4096).collect();
    let src = mem_source("resume-src", image_with_magic(len, &hits));
    let visited = Arc::new(Mutex::new(Vec::new()));
    let fake = Fake { probe: None, visit_delay_ms: 15, visited: visited.clone(), ..Default::default() };
    let (cfg, events) = config(fake, chunk);
    let st = jobs::start(cfg.clone(), src, ScanOptions { mode: "deep".into(), ..Default::default() }).unwrap();
    let id = st.session_id.clone();
    let job = jobs::running(&id).expect("running");

    // Pause: progress stops and the state is saved.
    let t = Instant::now();
    while job.sweep_pos.load(Ordering::Relaxed) < 2 * MIB {
        assert!(t.elapsed() < Duration::from_secs(30));
        std::thread::sleep(Duration::from_millis(5));
    }
    jobs::pause(&id, true).unwrap();
    std::thread::sleep(Duration::from_millis(150));
    let p1 = job.ctx.done.load(Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(job.ctx.done.load(Ordering::Relaxed), p1);
    assert_eq!(manage::get_session(&id).unwrap().summary.state, "paused");
    assert!(events.lock().unwrap().iter().any(|(n, v)| n == "scan-progress" && v["state"] == "paused"));
    jobs::pause(&id, false).unwrap();

    // Cancel at about half way.
    while job.sweep_pos.load(Ordering::Relaxed) < len / 2 {
        assert!(t.elapsed() < Duration::from_secs(30));
        std::thread::sleep(Duration::from_millis(2));
    }
    jobs::cancel(&id).unwrap();
    assert_eq!(wait_done(&events, st.job)["state"], "cancelled");
    drop(job);
    let (pos, harvest, files_after_cancel) = session::with_conn(&id, |c| {
        Ok((meta_get::<i64>(c, K_SWEEP_POS).unwrap() as u64, meta_get::<i64>(c, K_HARVEST_POS).unwrap() as u64, meta_get::<i64>(c, K_FILES).unwrap()))
    })
    .unwrap();
    assert!(pos >= len / 2 && pos < len, "pos {pos}");
    assert_eq!(pos, harvest);
    assert_eq!(pos % chunk, 0);
    // The hits below the checkpoint were collected when the scan stopped.
    let below = hits.iter().filter(|&&h| h < pos).count() as i64;
    assert!(files_after_cancel >= below, "{files_after_cancel} < {below}");
    let d = manage::get_session(&id).unwrap();
    assert_eq!(d.summary.state, "cancelled");
    assert_eq!(d.stages.iter().find(|s| s.key == "sweep").unwrap().state, "pending");
    assert_eq!(d.stages[0].state, "skipped");
    let resumed = jobs::resume(cfg.clone(), &id).unwrap();
    assert_ne!(resumed.job, st.job);
    assert_eq!(wait_done(&events, resumed.job)["state"], "done");

    // The second run started at the checkpoint, and nothing was found twice.
    let runs = visited.lock().unwrap().clone();
    assert_eq!(runs.len(), 2);
    assert!(runs[1].iter().all(|&o| o >= pos), "resumed sweep re-read data below the checkpoint");
    assert_eq!(*runs[1].iter().min().unwrap(), pos);
    let d = manage::get_session(&id).unwrap();
    assert_eq!(d.summary.state, "done");
    assert_eq!(d.summary.files, 16);
    assert_eq!(d.summary.scanned_bytes, len);
    let page = qf(&id, &FileQuery { limit: Some(100), ..Default::default() });
    let mut starts: Vec<u64> = page.items.iter().map(|r| store::get_file(&id, r.id).unwrap().extents[0].offset).collect();
    starts.sort();
    assert_eq!(starts, hits);
    let m = manage::map_cells(&id, None, None, 16).unwrap();
    assert_eq!(m.totals[MapKind::Scanned.index()], len);
    assert_eq!(m.totals[MapKind::Recoverable.index()], 16 * 1000);
    assert!(jobs::resume(cfg, &id).unwrap_err().contains("already finished"));
}

#[test]
fn restore_after_crash_marks_dead_sessions_interrupted() {
    let src = SourceRef { kind: SourceKind::Image, path: "crash-src".into(), ..Default::default() };
    let mk = |pid: i64, state: &str| {
        let (id, path) = session::create(&src, "quick").unwrap();
        let c = session::open_path(&path, false).unwrap();
        meta_set_json(&c, K_SOURCE, &src).unwrap();
        meta_set(&c, K_STATE, state).unwrap();
        meta_set(&c, K_PID, pid).unwrap();
        meta_set(&c, K_CREATED, 1i64).unwrap();
        id
    };
    let dead = mk(0x7FFF_FFF0, "running");
    let dead_paused = mk(0x7FFF_FFF0, "paused");
    let alive = mk(std::process::id() as i64, "running");
    let done = mk(0x7FFF_FFF0, "done");
    jobs::restore_after_crash();
    let state = |id: &str| session::with_conn(id, |c| Ok(meta_get::<String>(c, K_STATE).unwrap())).unwrap();
    assert_eq!(state(&dead), "interrupted");
    assert_eq!(state(&dead_paused), "interrupted");
    assert_eq!(state(&alive), "running");
    assert_eq!(state(&done), "done");
    assert!(session::process_alive(std::process::id(), session::process_started(std::process::id())));
    assert!(!session::process_alive(std::process::id(), Some(12345)));
    // Deleting works for sessions that aren't running; a deleted session answers with a sentence.
    manage::delete_session(&dead).unwrap();
    assert_eq!(manage::get_session(&dead).unwrap_err(), GONE);
    assert!(!manage::list_sessions().unwrap().iter().any(|s| s.id == dead));
}

#[test]
fn export_import_round_trip() {
    let src = mem_source("export-src", image_with_magic(4 * MIB, &[MIB]));
    let fake = Fake { probe: Some(ntfs_probe()), fs_files: fs_files(), ..Default::default() };
    let (cfg, events) = config(fake, MIB);
    let st = jobs::start(cfg, src, ScanOptions { mode: "deep".into(), ..Default::default() }).unwrap();
    assert_eq!(wait_done(&events, st.job)["state"], "done");
    let id = st.session_id;
    let out = sessions_dir().unwrap().join("..").join(format!("max-export-{}.maxscan", std::process::id()));
    let out_s = out.to_string_lossy().to_string();
    manage::export_session(&id, &out_s).unwrap();
    manage::export_session(&id, &out_s).unwrap(); // overwrites
    let new_id = manage::import_session(&out_s).unwrap();
    assert_ne!(new_id, id);
    let a = manage::get_session(&id).unwrap();
    let b = manage::get_session(&new_id).unwrap();
    assert_eq!((a.summary.files, a.summary.bytes, a.summary.state.as_str()), (b.summary.files, b.summary.bytes, "done"));
    assert_eq!(a.counts.by_status, b.counts.by_status);
    assert_eq!(manage::map_cells(&id, None, None, 64).unwrap().cells, manage::map_cells(&new_id, None, None, 64).unwrap().cells);
    // Importing a file from the sessions folder itself keeps its id; junk is refused.
    let own = session_path(&new_id).unwrap().to_string_lossy().to_string();
    assert_eq!(manage::import_session(&own).unwrap(), new_id);
    let junk = sessions_dir().unwrap().join("..").join(format!("max-junk-{}.maxscan", std::process::id()));
    std::fs::write(&junk, b"not a database at all, just text").unwrap();
    assert!(manage::import_session(&junk.to_string_lossy()).is_err());
    let _ = std::fs::remove_file(junk);
    let _ = std::fs::remove_file(out);
}

#[test]
fn several_scans_run_at_once() {
    let mut started = Vec::new();
    let (cfg, events) = config(Fake { probe: None, visit_delay_ms: 20, ..Default::default() }, 256 * 1024);
    for i in 0..3u64 {
        let hits: Vec<u64> = (0..=i).map(|k| k * MIB + 512).collect();
        let src = mem_source(&format!("multi-{i}"), image_with_magic(4 * MIB, &hits));
        started.push((jobs::start(cfg.clone(), src, ScanOptions { mode: "deep".into(), ..Default::default() }).unwrap(), i + 1));
    }
    assert!(started.iter().filter(|(s, _)| jobs::running(&s.session_id).is_some()).count() >= 2);
    for (s, n) in &started {
        let d = wait_done(&events, s.job);
        assert_eq!(d["state"], "done");
        assert_eq!(d["files"], *n);
        assert_eq!(manage::get_session(&s.session_id).unwrap().summary.scanned_bytes, 4 * MIB);
        // Deleting a running scan is refused; afterwards it works.
        manage::delete_session(&s.session_id).unwrap();
    }
}

#[test]
fn delete_refuses_a_running_scan() {
    let src = mem_source("del-src", vec![0u8; 8 * MIB as usize]);
    let (cfg, events) = config(Fake { visit_delay_ms: 30, ..Default::default() }, 256 * 1024);
    let st = jobs::start(cfg, src, ScanOptions { mode: "deep".into(), ..Default::default() }).unwrap();
    assert_eq!(manage::delete_session(&st.session_id).unwrap_err(), "Stop this scan before deleting it.");
    jobs::cancel(&st.session_id).unwrap();
    assert_eq!(wait_done(&events, st.job)["state"], "cancelled");
    manage::delete_session(&st.session_id).unwrap();
}

#[test]
fn map_cells_merge_walk() {
    let mut sets: map::Sets = Default::default();
    sets[0].ranges = vec![(0, 100), (250, 260), (999, 1000)];
    sets[4].ranges = vec![(150, 151)];
    let m = map::cells(map::refs(&sets), 1000, None, None, 10);
    use base64::Engine;
    let c = base64::engine::general_purpose::STANDARD.decode(m.cells).unwrap();
    assert_eq!(m.cell_bytes, 100);
    assert_eq!(c, [1, 16, 1, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(m.totals[0], 111);
    let m = map::cells(map::refs(&sets), 1000, Some(240), Some(1000), 3);
    let c = base64::engine::general_purpose::STANDARD.decode(m.cells).unwrap();
    assert_eq!((m.cell_bytes, c.len()), (254, 3));
    assert_eq!(c, [1, 0, 1]);
    assert_eq!(map::merge_sorted(&[(0, 5), (10, 20)], &[(3, 7), (20, 25), (30, 31)]), vec![(0, 7), (10, 25), (30, 31)]);
    let live = map::LiveRanges::default();
    for i in (0..100_000u64).rev() {
        live.add(MapKind::Recoverable, i * 10, i * 10 + 5);
    }
    live.add(MapKind::Recoverable, 0, 7);
    assert_eq!(live.total(MapKind::Recoverable), 100_000 * 5 + 2);
}

#[test]
fn folders_and_search_are_normalised() {
    assert_eq!(writer::norm_folder("Users/Ann/"), "\\Users\\Ann");
    assert_eq!(writer::norm_folder("\\\\a\\\\b"), "\\a\\b");
    assert_eq!(writer::norm_folder("\\"), "");
    let w = query::build_where(&FileQuery { search: Some("*.JPG".into()), ..Default::default() }, true);
    assert_eq!(w.sql, "ext = ?");
    let w = query::build_where(&FileQuery { folder: Some("\\A".into()), recursive: Some(true), ..Default::default() }, true);
    assert!(w.sql.contains("folder_lc >= ?"));
    assert_eq!(w.params.len(), 3);
    let w = query::build_where(&FileQuery { categories: Some(vec![]), ..Default::default() }, true);
    assert_eq!(w.sql, "0");
}

/// cargo test scan::tests::perf -- --ignored --nocapture
#[test]
#[ignore]
fn perf_one_million_files() {
    use std::hint::black_box;
    let src = SourceRef { kind: SourceKind::Image, path: "perf-src".into(), ..Default::default() };
    let (id, path) = session::create(&src, "deep").unwrap();
    {
        let c = session::open_path(&path, false).unwrap();
        meta_set_json(&c, K_SOURCE, &src).unwrap();
        meta_set(&c, K_SOURCE_LEN, 1i64 << 40).unwrap();
        meta_set(&c, K_STATE, "done").unwrap();
    }
    let w = writer::Writer::spawn(&id, path.clone()).unwrap();
    let types = ["jpg", "png", "pdf", "mp4", "mp3", "txt", "zip", "docx"];
    let t = Instant::now();
    let n = 1_000_000u64;
    for i in 0..n {
        let folder = match i % 10 {
            0..=5 => format!("\\Users\\U{}\\Folder {}\\Sub {}", i % 7, i % 300, i % 11),
            6..=7 => format!("\\Lost folders\\Folder {}", i % 2000),
            _ => format!("\\Found by signature\\{}", types[(i % 8) as usize]),
        };
        let f = FoundFile {
            name: format!("File {i:07} name.{}", types[(i % 8) as usize]),
            folder,
            size: (i * 7919) % 50_000_000,
            status: if i % 10 >= 8 { FileStatus::Carved } else { FileStatus::Deleted },
            type_id: types[(i % 8) as usize].into(),
            modified: Some(1_600_000_000_000 + i as i64 * 1000),
            condition: if i % 3 == 0 { Condition::Good } else { Condition::Unknown },
            extents: vec![Extent { offset: i * 1_048_576, len: 65536 }, Extent { offset: i * 1_048_576 + 131072, len: 4096 }],
            ..Default::default()
        };
        w.send(writer::Msg::File(Box::new(f), 1, 0));
    }
    w.flush();
    let ins = t.elapsed();
    let t = Instant::now();
    w.send(writer::Msg::Indexes(true));
    w.flush();
    w.stop();
    println!("build indexes: {:?}", t.elapsed());
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    println!("insert 1M files: {ins:?} ({:.0}/s), file {} MB", n as f64 / ins.as_secs_f64(), size >> 20);

    // A map with 100k ranges per kind.
    let mut sets: map::Sets = Default::default();
    for (k, s) in sets.iter_mut().enumerate() {
        s.ranges = (0..100_000u64).map(|i| (i * 10_000_000 + k as u64 * 1000, i * 10_000_000 + k as u64 * 1000 + 500_000)).collect();
    }
    session::with_conn(&id, |c| map::save_direct(c, &sets)).unwrap();

    let time = |label: &str, f: &mut dyn FnMut()| {
        let t = Instant::now();
        f();
        println!("{label:<44} {:?}", t.elapsed());
    };
    let q = |f: &dyn Fn(&mut FileQuery)| {
        let mut q = FileQuery::default();
        f(&mut q);
        q
    };
    time("query_files all, by name (cold totals)", &mut || {
        black_box(qf(&id, &FileQuery::default()));
    });
    time("query_files all, by name (warm)", &mut || {
        black_box(qf(&id, &FileQuery::default()));
    });
    time("query_files all, size desc, offset 500k", &mut || {
        black_box(qf(&id, &q(&|q| {
            q.sort = Some("size".into());
            q.desc = Some(true);
            q.offset = Some(500_000);
        })));
    });
    time("query_files search substring", &mut || {
        black_box(qf(&id, &q(&|q| q.search = Some("0042".into()))));
    });
    time("query_files *.jpg", &mut || {
        black_box(qf(&id, &q(&|q| q.search = Some("*.jpg".into()))));
    });
    time("query_files category photo, by modified", &mut || {
        black_box(qf(&id, &q(&|q| {
            q.categories = Some(vec!["photo".into()]);
            q.sort = Some("modified".into());
        })));
    });
    time("query_files folder recursive \\Users\\U3", &mut || {
        black_box(qf(&id, &q(&|q| {
            q.folder = Some("\\Users\\U3".into());
            q.recursive = Some(true);
        })));
    });
    time("query_files folder exact", &mut || {
        black_box(qf(&id, &q(&|q| q.folder = Some("\\Lost folders\\Folder 77".into()))));
    });
    time("query_ids all", &mut || {
        black_box(store::query_ids(&id, &FileQuery::default()).unwrap());
    });
    let fc = |parent: &str, q: Option<&FileQuery>| session::with_conn(&id, |c| super::query::folder_children(&id, c, parent, q)).unwrap();
    time("folder_children top (cold)", &mut || {
        black_box(fc("", None));
    });
    time("folder_children \\Users\\U3 (warm)", &mut || {
        black_box(fc("\\Users\\U3", None));
    });
    time("folder_children top, photos (cold)", &mut || {
        black_box(fc("", Some(&q(&|q| q.categories = Some(vec!["photo".into()])))));
    });
    time("get_session (counts)", &mut || {
        black_box(manage::get_session(&id).unwrap());
    });
    time("map_cells 16384 (cold load)", &mut || {
        black_box(manage::map_cells(&id, None, None, 16384).unwrap());
    });
    time("map_cells 16384 (warm)", &mut || {
        black_box(manage::map_cells(&id, None, None, 16384).unwrap());
    });
    time("map_cells 65536 zoomed", &mut || {
        black_box(manage::map_cells(&id, Some(1 << 30), Some(1 << 38), 65536).unwrap());
    });
    time("map_region 64 MiB", &mut || {
        black_box(manage::map_region(&id, 1 << 36, (1 << 36) + (64 << 20)).unwrap());
    });
    time("map_region 1 TiB (everything)", &mut || {
        black_box(manage::map_region(&id, 0, 1 << 40).unwrap());
    });
    manage::delete_session(&id).unwrap();
}

// ------------------------------------------------------------------------ review fixes

/// #7: a second Stop while the stopped sweep's results are collected waits for them, so the
/// sweep read so far is kept (harvest_pos moves up to the stop position).
#[test]
fn second_stop_during_post_stop_harvest_keeps_the_sweep() {
    let len = 8 * MIB;
    let hits: Vec<u64> = (0..8).map(|i| i * MIB + 4096).collect();
    let src = mem_source("double-stop-src", image_with_magic(len, &hits));
    // Held half way, so the Stop lands mid-sweep however busy the machine is.
    let gate = Gate::new(len / 2);
    let fake = Fake { probe: None, visit_delay_ms: 10, finish_delay_ms: 600, gate: Some(gate.clone()), ..Default::default() };
    let (cfg, events) = config(fake, 256 * 1024);
    let st = jobs::start(cfg, src, ScanOptions { mode: "deep".into(), ..Default::default() }).unwrap();
    let id = st.session_id.clone();
    let job = jobs::running(&id).unwrap();
    let t = Instant::now();
    gate.wait_reached();
    jobs::cancel(&id).unwrap();
    gate.release();
    while !*job.harvesting.lock().unwrap() {
        assert!(t.elapsed() < Duration::from_secs(30), "harvest didn't start");
        std::thread::sleep(Duration::from_millis(2));
    }
    for _ in 0..5 {
        jobs::cancel(&id).unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!job.ctx.is_cancelled(), "a stop during the harvest must wait");
    assert_eq!(wait_done(&events, st.job)["state"], "cancelled");
    assert!(events.lock().unwrap().iter().any(|(n, v)| n == "scan-progress" && v["sessionId"] == id.as_str() && v["stopping"] == true));
    let (pos, harvest) =
        session::with_conn(&id, |c| Ok((meta_get::<i64>(c, K_SWEEP_POS).unwrap() as u64, meta_get::<i64>(c, K_HARVEST_POS).unwrap() as u64))).unwrap();
    assert!(pos >= len / 2 && pos < len, "pos {pos}");
    assert_eq!(pos, harvest, "the second stop threw the sweep away");
    let d = manage::get_session(&id).unwrap();
    let pct = pos * 100 / len;
    assert_eq!(d.stages.iter().find(|s| s.key == "sweep").unwrap().note.as_deref(), Some(format!("Stopped at {pct}%.").as_str()));
    drop(job);
    manage::delete_session(&id).unwrap();
}

/// #7: a Stop during the regular rebuild stage finishes the rebuild first.
#[test]
fn stop_during_rebuild_finishes_it() {
    let len = 2 * MIB;
    let src = mem_source("rebuild-stop-src", image_with_magic(len, &[MIB]));
    let fake = Fake { probe: None, finish_delay_ms: 600, ..Default::default() };
    let (cfg, events) = config(fake, 256 * 1024);
    let st = jobs::start(cfg, src, ScanOptions { mode: "deep".into(), ..Default::default() }).unwrap();
    let id = st.session_id.clone();
    let job = jobs::running(&id).unwrap();
    let t = Instant::now();
    while !*job.harvesting.lock().unwrap() {
        assert!(t.elapsed() < Duration::from_secs(30), "rebuild didn't start");
        std::thread::sleep(Duration::from_millis(2));
    }
    jobs::cancel(&id).unwrap();
    assert_eq!(wait_done(&events, st.job)["state"], "cancelled");
    drop(job);
    let d = manage::get_session(&id).unwrap();
    assert_eq!(d.stages.iter().find(|s| s.key == "sweep").unwrap().state, "done");
    assert_eq!(d.stages.iter().find(|s| s.key == "rebuild").unwrap().state, "done");
    assert_eq!(d.summary.files, 1);
    let harvest = session::with_conn(&id, |c| Ok(meta_get::<i64>(c, K_HARVEST_POS).unwrap() as u64)).unwrap();
    assert_eq!(harvest, len);
    manage::delete_session(&id).unwrap();
}

/// #37: pause / continue never overwrite the final state.
#[test]
fn pause_toggles_keep_the_final_state() {
    let src = mem_source("pause-race-src", image_with_magic(MIB, &[]));
    let (cfg, events) = config(Fake { probe: None, ..Default::default() }, 256 * 1024);
    let st = jobs::start(cfg, src, ScanOptions { mode: "deep".into(), ..Default::default() }).unwrap();
    let id = st.session_id.clone();
    // Toggle until the job is gone; the last toggle leaves it running.
    let mut n = 0;
    while jobs::pause(&id, n % 2 == 0).is_ok() {
        n += 1;
        if n > 2000 {
            let _ = jobs::pause(&id, false);
            break;
        }
    }
    let _ = jobs::pause(&id, false);
    let done = wait_done(&events, st.job);
    std::thread::sleep(Duration::from_millis(100));
    let state = session::with_conn(&id, |c| Ok(meta_get::<String>(c, K_STATE).unwrap())).unwrap();
    assert_eq!(state, done["state"].as_str().unwrap());
    manage::delete_session(&id).unwrap();
}

/// #36 / #56: overlapping bad ranges count once; checkpoints only see sets that changed.
#[test]
fn live_ranges_totals_and_versions() {
    let live = map::LiveRanges::default();
    live.add(MapKind::Bad, 0, 1000);
    live.add(MapKind::Bad, 500, 1000);
    live.add(MapKind::Bad, 0, 1000);
    assert_eq!(live.total(MapKind::Bad), 1000);
    let v0 = [0u64; 5];
    let ch = live.changed_since(&v0);
    assert_eq!(ch.len(), 1);
    assert_eq!(ch[0].0, MapKind::Bad.index());
    assert_eq!(ch[0].1.total(), 1000);
    let seen = live.versions();
    assert!(live.changed_since(&seen).is_empty());
    live.add(MapKind::Scanned, 0, 10);
    let ch = live.changed_since(&seen);
    assert_eq!(ch.iter().map(|c| c.0).collect::<Vec<_>>(), vec![MapKind::Scanned.index()]);
}

/// #56: after the file-system stage, map checkpoints don't rewrite unchanged sets.
#[test]
fn checkpoints_skip_unchanged_sets() {
    let src = mem_source("ckpt-src", image_with_magic(MIB, &[]));
    let (cfg, events) = config(Fake { probe: None, visit_delay_ms: 40, ..Default::default() }, 128 * 1024);
    let st = jobs::start(cfg, src, ScanOptions { mode: "deep".into(), ..Default::default() }).unwrap();
    let job = jobs::running(&st.session_id).unwrap();
    job.ranges.add(MapKind::Allocated, 0, 4096);
    jobs::checkpoint(&job, true);
    let saved = *job.saved_versions.lock().unwrap();
    let a = MapKind::Allocated.index();
    assert_eq!(saved[a], job.ranges.versions()[a]);
    assert!(!job.ranges.changed_since(&saved).iter().any(|c| c.0 == a));
    assert_eq!(wait_done(&events, st.job)["state"], "done");
    drop(job);
    let sets = session::with_conn(&st.session_id, |c| Ok(map::load_sets(c))).unwrap();
    assert_eq!(sets[MapKind::Allocated.index()].total(), 4096);
    assert_eq!(sets[MapKind::Scanned.index()].total(), MIB);
    manage::delete_session(&st.session_id).unwrap();
}

/// #34: internal callers get every id; the UI command refuses instead of cutting short.
#[test]
fn query_ids_has_no_silent_cap() {
    let src = SourceRef { kind: SourceKind::Image, path: "ids-src".into(), ..Default::default() };
    let (id, path) = session::create(&src, "quick").unwrap();
    {
        let c = session::open_path(&path, false).unwrap();
        meta_set_json(&c, K_SOURCE, &src).unwrap();
        meta_set(&c, K_STATE, "done").unwrap();
        meta_set(&c, K_CREATED, 1i64).unwrap();
    }
    let w = writer::Writer::spawn(&id, path.clone()).unwrap();
    for i in 0..30u64 {
        w.send(writer::Msg::File(Box::new(file(&format!("f{i:02}.txt"), "\\A", 10, FileStatus::Deleted, i * 4096, 0)), 1, 0));
    }
    w.flush();
    w.stop();
    assert_eq!(store::query_ids(&id, &FileQuery::default()).unwrap().len(), 30);
    let ids = session::with_conn(&id, |c| super::query::query_ids_limited(c, &FileQuery::default(), 30)).unwrap();
    assert_eq!(ids.len(), 30);
    let e = session::with_conn(&id, |c| super::query::query_ids_limited(c, &FileQuery::default(), 29)).unwrap_err();
    assert_eq!(e, super::query::TOO_MANY_IDS);
    manage::delete_session(&id).unwrap();
}

/// #32: without the folder index (during a scan) the tree is one pass, no per-folder lookup, and
/// gives the same tree as the indexed query.
#[test]
fn folder_tree_without_indexes_is_one_pass() {
    let src = SourceRef { kind: SourceKind::Image, path: "tree-src".into(), ..Default::default() };
    let (id, path) = session::create(&src, "quick").unwrap();
    {
        let c = session::open_path(&path, false).unwrap();
        meta_set_json(&c, K_SOURCE, &src).unwrap();
        meta_set(&c, K_STATE, "done").unwrap();
    }
    let w = writer::Writer::spawn(&id, path.clone()).unwrap();
    for i in 0..3000u64 {
        let folder = format!("\\Lost folders\\Folder {}\\Sub {}", i % 500, i % 3);
        w.send(writer::Msg::File(Box::new(file(&format!("f{i}.txt"), &folder, i, FileStatus::Lost, i * 4096, 0)), 1, 0));
    }
    w.send(writer::Msg::Indexes(true));
    w.flush();
    w.stop();
    let c = session::open_path(&path, false).unwrap();
    let plan = |c: &rusqlite::Connection| -> String {
        let sql = super::query::tree_sql(c, "1");
        let mut st = c.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let rows = st.query_map([], |r| r.get::<_, String>(3)).unwrap();
        rows.map(|r| r.unwrap()).collect::<Vec<_>>().join(" | ")
    };
    let flat = |t: &super::query::Tree| {
        let mut v: Vec<(String, String, u64, u64, usize)> = t.iter().map(|(k, n)| (k.clone(), n.path.clone(), n.files, n.size, n.children.len())).collect();
        v.sort();
        v
    };
    assert!(plan(&c).contains("USING COVERING INDEX files_folder"), "{}", plan(&c));
    let with_index = flat(&super::query::build_tree(&c, None).unwrap());
    session::drop_indexes(&c).unwrap();
    let p = plan(&c);
    assert!(!p.contains("CORRELATED"), "{p}");
    let t = Instant::now();
    let without = flat(&super::query::build_tree(&c, None).unwrap());
    assert!(t.elapsed() < Duration::from_secs(5));
    assert_eq!(with_index, without);
    assert_eq!(without.iter().find(|r| r.0.is_empty()).unwrap().2, 3000);
    session::create_indexes(&c).unwrap();
    drop(c);
    manage::delete_session(&id).unwrap();
}

/// #5: where a session goes when the sessions folder is on the disk being scanned.
#[test]
fn session_location_avoids_the_source_disk() {
    use session::{choose, locate_with, Candidate, Choice, Place};
    // A scan of the whole disk 0 (C: is on it): every volume on disk 0 counts.
    let c_src = Place { disks: vec![0], root: Some("C:\\".into()), whole_disk: true, ..Default::default() };
    let data_on_c = Place { disks: vec![0], root: Some("C:\\".into()), ..Default::default() };
    let data_on_d = Place { disks: vec![1], root: Some("D:\\".into()), ..Default::default() };
    let gib = 1u64 << 30;
    let cand = |root: &str, disks: Vec<u32>, free: u64| Candidate { root: root.into(), disks, free, ..Default::default() };
    let cands = vec![
        cand("C:\\", vec![0], 500 * gib),
        cand("E:\\", vec![0], 300 * gib), // another partition of disk 0
        cand("F:\\", vec![2], 20 * gib),
        cand("G:\\", vec![3], 90 * gib),
        cand("H:\\", vec![4], gib / 2), // too little space
        cand("R:\\", vec![], 900 * gib), // unknown disk
    ];
    assert_eq!(choose(&c_src, &data_on_d, &cands), Choice::Default);
    assert_eq!(choose(&Place::default(), &data_on_c, &cands), Choice::Default);
    assert_eq!(choose(&c_src, &data_on_c, &cands), Choice::Elsewhere(vec!["G:\\".into(), "F:\\".into()]));
    assert_eq!(choose(&c_src, &data_on_c, &cands[..2]), Choice::Stuck);
    // A volume source whose disks are unknown is still matched by its root.
    let c_unknown = Place { disks: vec![], root: Some("C:\\".into()), ..Default::default() };
    assert_eq!(choose(&c_unknown, &data_on_c, &cands[..1]), Choice::Stuck);

    // The folder is made on the first candidate that takes it; a read-only drive is skipped.
    let default = sessions_dir().unwrap();
    let base = default.join(format!("loc-{}", std::process::id()));
    let g = base.join("G");
    let f = base.join("F");
    let roots = vec![
        cand(&g.to_string_lossy(), vec![3], 90 * gib),
        cand(&f.to_string_lossy(), vec![2], 20 * gib),
    ];
    let loc = locate_with(default.clone(), &c_src, &data_on_c, &roots, |d| {
        !d.starts_with(&g) && std::fs::create_dir_all(d).is_ok()
    });
    assert!(loc.external);
    assert_eq!(loc.dir, f.join(session::EXTERNAL_DIR));
    assert!(loc.dir.is_dir());
    assert!(loc.note.as_deref().unwrap().contains("nothing is written to the drive being scanned"));
    let stuck = locate_with(default.clone(), &c_src, &data_on_c, &roots, |_| false);
    assert!(!stuck.external);
    assert_eq!(stuck.dir, default);
    assert_eq!(stuck.note.as_deref(), Some(session::SAME_DRIVE_NOTE));
    let fine = locate_with(default.clone(), &c_src, &data_on_d, &roots, |_| true);
    assert!(!fine.external && fine.note.is_none());
    let _ = std::fs::remove_dir_all(base);
}

/// R1: drives other running scans read are never chosen, and a sessions folder on one of them
/// moves too; with nothing left the default stays, with the note.
#[test]
fn session_location_avoids_drives_other_scans_read() {
    use session::{choose_avoiding, locate_avoiding, Candidate, Choice, Place};
    let gib = 1u64 << 30;
    let c_src = Place { disks: vec![0], root: Some("C:\\".into()), ..Default::default() };
    let data_on_c = Place { disks: vec![0], root: Some("C:\\".into()), ..Default::default() };
    let g_busy = Place { disks: vec![3], root: Some("G:\\".into()), ..Default::default() };
    let disk2_busy = Place { disks: vec![2], root: None, whole_disk: true, ..Default::default() };
    let cand = |root: &str, disks: Vec<u32>, free: u64| Candidate { root: root.into(), disks, free, ..Default::default() };
    let cands = vec![cand("F:\\", vec![2], 20 * gib), cand("G:\\", vec![3], 90 * gib), cand("J:\\", vec![5], 10 * gib)];
    assert_eq!(choose_avoiding(&c_src, &[], &data_on_c, &cands), Choice::Elsewhere(vec!["G:\\".into(), "F:\\".into(), "J:\\".into()]));
    assert_eq!(choose_avoiding(&c_src, &[g_busy.clone()], &data_on_c, &cands), Choice::Elsewhere(vec!["F:\\".into(), "J:\\".into()]));
    assert_eq!(choose_avoiding(&c_src, &[g_busy.clone(), disk2_busy.clone()], &data_on_c, &cands), Choice::Elsewhere(vec!["J:\\".into()]));
    // An image scan (unknown place) while another scan reads C:, where the sessions folder is.
    assert_eq!(choose_avoiding(&Place::default(), &[c_src.clone(), g_busy.clone()], &data_on_c, &cands), Choice::Elsewhere(vec!["F:\\".into(), "J:\\".into()]));
    // Busy drives elsewhere don't move a sessions folder that is on none of them.
    let data_on_d = Place { disks: vec![1], root: Some("D:\\".into()), ..Default::default() };
    assert_eq!(choose_avoiding(&c_src, &[g_busy.clone()], &data_on_d, &cands), Choice::Default);
    // Nothing left: the default folder, with the note.
    let default = sessions_dir().unwrap();
    let busy = [g_busy, disk2_busy, Place { disks: vec![5], root: None, whole_disk: true, ..Default::default() }];
    assert_eq!(choose_avoiding(&c_src, &busy, &data_on_c, &cands), Choice::Stuck);
    let stuck = locate_avoiding(default.clone(), &c_src, &busy, &data_on_c, &cands, |_| true);
    assert!(!stuck.external);
    assert_eq!(stuck.dir, default);
    assert_eq!(stuck.note.as_deref(), Some(session::SAME_DRIVE_NOTE));
}

/// R2: a resume that drops an unfinished stage's rows also corrects the running totals.
#[test]
fn resume_corrects_the_running_totals() {
    let len = MIB;
    let src = mem_source("resume-totals-src", image_with_magic(len, &[]));
    let (id, path) = session::create(&src, "quick").unwrap();
    {
        let c = session::open_path(&path, false).unwrap();
        let mut stages = pipeline::stage_list("quick", &src);
        stages[0].state = "running".into();
        meta_set_json(&c, K_SOURCE, &src).unwrap();
        meta_set_json(&c, K_OPTIONS, &ScanOptions { mode: "quick".into(), ..Default::default() }).unwrap();
        meta_set(&c, K_MODE, "quick").unwrap();
        meta_set(&c, K_STATE, "interrupted").unwrap();
        meta_set(&c, K_CREATED, 1i64).unwrap();
        meta_set(&c, K_SOURCE_LEN, len as i64).unwrap();
        meta_set_json(&c, K_PROBE, &None::<FsProbe>).unwrap();
        meta_set_json(&c, K_STAGES, &stages).unwrap();
        for i in 0..3u64 {
            let f = file(&format!("half{i}.jpg"), "\\Pictures", 1000, FileStatus::Deleted, 4096 * (i + 1), 1);
            writer::insert_file(&c, &f, jobs::STAGE_FS, 0).unwrap();
        }
        meta_set(&c, K_FILES, 3i64).unwrap();
        meta_set(&c, K_BYTES, 3000i64).unwrap();
    }
    let (cfg, events) = config(Fake { probe: None, ..Default::default() }, 256 * 1024);
    let r = jobs::resume(cfg, &id).unwrap();
    // Right after the resume (before any new insert) the totals already match the rows left.
    let (f, b) = session::with_conn(&id, |c| Ok((meta_get::<i64>(c, K_FILES).unwrap(), meta_get::<i64>(c, K_BYTES).unwrap()))).unwrap();
    assert_eq!((f, b), (0, 0));
    assert_eq!(wait_done(&events, r.job)["state"], "done");
    let d = manage::get_session(&id).unwrap();
    assert_eq!((d.summary.files, d.summary.bytes), (0, 0));
    manage::delete_session(&id).unwrap();
}

/// R3: MAX closing while a post-stop harvest still runs leaves a session that becomes
/// "interrupted" and continues without losing or doubling files; when the harvest does finish,
/// the scan is saved as stopped, never left "running".
#[test]
fn exit_during_post_stop_harvest_leaves_a_resumable_session() {
    let len = 8 * MIB;
    let hits: Vec<u64> = (0..8).map(|i| i * MIB + 4096).collect();
    let src = mem_source("exit-harvest-src", image_with_magic(len, &hits));
    // Held half way, so the Stop lands mid-sweep however busy the machine is.
    let gate = Gate::new(len / 2);
    let fake = Fake { probe: None, visit_delay_ms: 10, finish_delay_ms: 1500, gate: Some(gate.clone()), ..Default::default() };
    let (cfg, events) = config(fake, 256 * 1024);
    let st = jobs::start(cfg.clone(), src, ScanOptions { mode: "deep".into(), ..Default::default() }).unwrap();
    let id = st.session_id.clone();
    let job = jobs::running(&id).unwrap();
    let t = Instant::now();
    gate.wait_reached();
    jobs::cancel(&id).unwrap(); // what closing MAX does
    gate.release();
    while !*job.harvesting.lock().unwrap() {
        assert!(t.elapsed() < Duration::from_secs(30), "harvest didn't start");
        std::thread::sleep(Duration::from_millis(2));
    }
    // The process "ends" now: a copy of the session file as it is on disk at this moment.
    job.writer.flush();
    let copy_id = format!("{id}-crash");
    let copy = sessions_dir().unwrap().join(format!("{copy_id}.{EXT}"));
    {
        let c = session::open_read(&job.path).unwrap();
        c.execute("VACUUM INTO ?1", [copy.to_string_lossy().to_string()]).unwrap();
    }
    {
        let c = session::open_path(&copy, false).unwrap();
        let state: String = meta_get(&c, K_STATE).unwrap();
        assert!(matches!(state.as_str(), "running" | "paused"), "{state}");
        meta_set(&c, K_PID, 0x7FFF_FFF0i64).unwrap();
    }
    jobs::restore_after_crash();
    assert_eq!(session::with_conn(&copy_id, |c| Ok(meta_get::<String>(c, K_STATE).unwrap())).unwrap(), "interrupted");

    // The harvest of the real session finishes: it is saved as stopped.
    assert_eq!(wait_done(&events, st.job)["state"], "cancelled");
    drop(job);
    assert_eq!(session::with_conn(&id, |c| Ok(meta_get::<String>(c, K_STATE).unwrap())).unwrap(), "cancelled");

    // The interrupted copy continues and ends with every file once.
    let r = jobs::resume(cfg, &copy_id).unwrap();
    assert_eq!(wait_done(&events, r.job)["state"], "done");
    let d = manage::get_session(&copy_id).unwrap();
    assert_eq!(d.summary.files, 8);
    let page = qf(&copy_id, &FileQuery { limit: Some(100), ..Default::default() });
    let mut starts: Vec<u64> = page.items.iter().map(|r| store::get_file(&copy_id, r.id).unwrap().extents[0].offset).collect();
    starts.sort();
    assert_eq!(starts, hits);
    manage::delete_session(&copy_id).unwrap();
    manage::delete_session(&id).unwrap();
}

/// #5: sessions kept on another drive are listed, opened, deleted and unregistered.
#[test]
fn external_sessions_are_found_through_the_registry() {
    let ext = sessions_dir().unwrap().join(format!("ext-{}", std::process::id())).join(session::EXTERNAL_DIR);
    std::fs::create_dir_all(&ext).unwrap();
    let src = SourceRef { kind: SourceKind::Image, path: "ext-src".into(), ..Default::default() };
    let (id, path) = session::create_in(&ext, &src, "exttest").unwrap();
    assert!(path.starts_with(&ext));
    {
        let c = session::open_path(&path, false).unwrap();
        meta_set_json(&c, K_SOURCE, &src).unwrap();
        meta_set(&c, K_STATE, "done").unwrap();
        meta_set(&c, K_CREATED, 1i64).unwrap();
    }
    // Registered as it was created (registering again changes nothing).
    session::register_external(&path);
    assert_eq!(session::external_paths().iter().filter(|p| **p == path).count(), 1);
    assert_eq!(session_path(&id).unwrap(), path);
    assert!(manage::list_sessions().unwrap().iter().any(|s| s.id == id));
    assert_eq!(manage::get_session(&id).unwrap().summary.state, "done");
    // A new id never collides with it.
    let (id2, p2) = session::create(&src, "quick").unwrap();
    assert_ne!(id2, id);
    let _ = std::fs::remove_file(p2);
    // Importing the external file itself keeps its id.
    assert_eq!(manage::import_session(&path.to_string_lossy()).unwrap(), id);
    // The registry is saved as a JSON list.
    let reg = std::fs::read_to_string(sessions_dir().unwrap().join("external-sessions.json")).unwrap();
    assert!(serde_json::from_str::<Vec<std::path::PathBuf>>(&reg).unwrap().contains(&path));
    manage::delete_session(&id).unwrap();
    assert!(!path.exists());
    assert!(!session::external_paths().contains(&path));
    assert!(!manage::list_sessions().unwrap().iter().any(|s| s.id == id));
    let _ = std::fs::remove_dir_all(ext.parent().unwrap().parent().unwrap());
}

/// #4 / #38: an export never replaces the scanned image (or a part of its split set), and a
/// refused or failed export leaves an existing file alone.
#[test]
fn export_refuses_the_source_image() {
    let dir = sessions_dir().unwrap().join(format!("img-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let img = dir.join("card.001");
    let part2 = dir.join("card.002");
    std::fs::write(&img, vec![7u8; 4096]).unwrap();
    std::fs::write(&part2, vec![8u8; 4096]).unwrap();
    let src = SourceRef { kind: SourceKind::Image, path: img.to_string_lossy().to_string(), ..Default::default() };
    let (id, path) = session::create(&src, "quick").unwrap();
    {
        let c = session::open_path(&path, false).unwrap();
        meta_set_json(&c, K_SOURCE, &src).unwrap();
        meta_set(&c, K_STATE, "done").unwrap();
    }
    for target in [&img, &part2] {
        let e = manage::export_session(&id, &target.to_string_lossy()).unwrap_err();
        assert!(e.contains("disk image this scan read"), "{e}");
    }
    let upper = img.to_string_lossy().to_uppercase();
    assert!(manage::export_session(&id, &upper).is_err());
    assert_eq!(std::fs::read(&img).unwrap(), vec![7u8; 4096]);
    assert_eq!(std::fs::read(&part2).unwrap(), vec![8u8; 4096]);
    // A normal export replaces an older file in one step, with no leftovers.
    let out = dir.join("saved.maxscan");
    std::fs::write(&out, b"old").unwrap();
    manage::export_session(&id, &out.to_string_lossy()).unwrap();
    let c = session::open_read(&out).unwrap();
    assert_eq!(meta_get::<String>(&c, K_STATE).as_deref(), Some("done"));
    drop(c);
    let left: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
    assert!(!left.iter().any(|n| n.ends_with(".part")), "{left:?}");
    // A failed export (target is a folder) leaves it as it was.
    let blocked = dir.join("folder.maxscan");
    std::fs::create_dir_all(&blocked).unwrap();
    assert!(manage::export_session(&id, &blocked.to_string_lossy()).is_err());
    assert!(blocked.is_dir());
    manage::delete_session(&id).unwrap();
    let _ = std::fs::remove_dir_all(dir);
}

/// #33: totals of a live scan are reused between identical polls.
#[test]
fn live_totals_survive_identical_polls() {
    let src = mem_source("poll-src", image_with_magic(4 * MIB, &[]));
    let fake = Fake { probe: Some(ntfs_probe()), fs_files: fs_files(), visit_delay_ms: 60, ..Default::default() };
    let (cfg, events) = config(fake, 256 * 1024);
    let st = jobs::start(cfg, src, ScanOptions { mode: "deep".into(), ..Default::default() }).unwrap();
    let id = st.session_id.clone();
    let q = FileQuery { search: Some("jpg".into()), ..Default::default() };
    let a = qf(&id, &q);
    session::bump(&id);
    let b = qf(&id, &q);
    assert_eq!((a.total, a.total_size), (b.total, b.total_size));
    // No filter: the writer's running totals.
    let all = qf(&id, &FileQuery::default());
    assert!(all.total <= 5);
    assert_eq!(wait_done(&events, st.job)["state"], "done");
    assert_eq!(qf(&id, &FileQuery::default()).total, 5);
    manage::delete_session(&id).unwrap();
}

/// R2: a Stop that arrives after the sweep read its last chunk still runs the rebuild, so the
/// stopped scan keeps the whole sweep and a resume never reads the disk again.
#[test]
fn stop_as_the_sweep_ends_still_rebuilds() {
    let len = 4 * MIB;
    let chunk = 256 * 1024;
    let hits: Vec<u64> = (0..4).map(|i| i * MIB + 8192).collect();
    let src = mem_source("stop-at-end-src", image_with_magic(len, &hits));
    // The last chunk's visit waits: by then every chunk was read and queued.
    let gate = Gate::new(len - chunk);
    let fake = Fake { probe: None, finish_delay_ms: 200, gate: Some(gate.clone()), ..Default::default() };
    let visited = fake.visited.clone();
    let (cfg, events) = config(fake, chunk);
    let st = jobs::start(cfg.clone(), src, ScanOptions { mode: "deep".into(), ..Default::default() }).unwrap();
    let id = st.session_id.clone();
    gate.wait_reached();
    jobs::cancel(&id).unwrap();
    gate.release();
    assert_eq!(wait_done(&events, st.job)["state"], "cancelled");
    let d = manage::get_session(&id).unwrap();
    let state = |k: &str| d.stages.iter().find(|s| s.key == k).unwrap().state.clone();
    assert_eq!(state("sweep"), "done");
    assert_eq!(state("rebuild"), "done");
    assert_eq!(state("condition"), "pending");
    assert_eq!(d.summary.files, 4);
    let harvest = session::with_conn(&id, |c| Ok(meta_get::<i64>(c, K_HARVEST_POS).unwrap() as u64)).unwrap();
    assert_eq!(harvest, len);
    // The resume only checks the files: no second sweep, nothing lost or doubled.
    let r = jobs::resume(cfg, &id).unwrap();
    assert_eq!(wait_done(&events, r.job)["state"], "done");
    assert_eq!(visited.lock().unwrap().len(), 1, "the disk was read again");
    assert_eq!(manage::get_session(&id).unwrap().summary.files, 4);
    manage::delete_session(&id).unwrap();
}

/// R3: a session file on the drive about to be scanned (or a scan reading the drive with a
/// stopped scan's results) is found; unknown places never match.
#[test]
fn session_files_on_a_scanned_drive_are_found() {
    use session::{files_on, Place};
    let c = Place { disks: vec![0], root: Some("C:\\".into()), ..Default::default() };
    let d = Place { disks: vec![1], root: Some("D:\\".into()), ..Default::default() };
    let disk1 = Place { disks: vec![1], root: None, whole_disk: true, ..Default::default() };
    let d_letter_only = Place { disks: vec![], root: Some("d:\\".into()), ..Default::default() };
    assert!(files_on(&d, &[c.clone(), d.clone()]));
    assert!(files_on(&disk1, &[d.clone()]));
    assert!(files_on(&d, &[d_letter_only]));
    assert!(!files_on(&d, &[c.clone()]));
    assert!(!files_on(&Place::default(), &[c.clone(), d.clone()]));
    assert!(!files_on(&c, &[Place::default()]));
    // Tests see no real drives: the checks never refuse an image scan.
    let img = SourceRef { kind: SourceKind::Image, path: "x.img".into(), ..Default::default() };
    assert!(session::check_running_sessions(&img).is_ok());
    assert!(session::check_results_drive(&sessions_dir().unwrap()).is_ok());
    for m in [session::SESSION_ON_SOURCE, session::RESULTS_ON_SCANNED, session::SAME_DRIVE_WARNING] {
        assert!(m.ends_with('.') && !m.contains('\n'), "{m}");
    }
}

/// #5: before a scan starts, the UI can say where its results go, and warn when they must stay
/// on the drive being scanned.
#[test]
fn location_preview_warns_before_a_same_drive_scan() {
    use session::{preview_for, Choice, LocationPreview, Place};
    let c = Place { disks: vec![0], root: Some("C:\\".into()), ..Default::default() };
    let d = Place { disks: vec![0], root: Some("D:\\".into()), ..Default::default() };
    let unknown = Place::default();
    assert_eq!(preview_for(&Choice::Default, &unknown, &c), LocationPreview::default());
    let stay = preview_for(&Choice::Default, &d, &c);
    assert!(!stay.same_drive && stay.moved_to.is_none());
    assert_eq!(stay.message.as_deref(), Some("This scan's results will be saved in MAX's data folder on C:, so nothing is written to D:."));
    let moved = preview_for(&Choice::Elsewhere(vec!["E:\\".into(), "F:\\".into()]), &c, &c);
    assert!(!moved.same_drive);
    assert_eq!(moved.moved_to.as_deref(), Some("E:"));
    assert_eq!(moved.message.as_deref(), Some("This scan's results will be saved in E:\\MAX Recovery\\sessions, so nothing is written to C:."));
    let disk0 = Place { disks: vec![0], whole_disk: true, ..Default::default() };
    assert!(preview_for(&Choice::Elsewhere(vec!["E:\\".into()]), &disk0, &c).message.unwrap().ends_with("nothing is written to the disk being scanned."));
    let stuck = preview_for(&Choice::Stuck, &c, &c);
    assert!(stuck.same_drive);
    assert_eq!(stuck.message.as_deref(), Some(session::SAME_DRIVE_WARNING));
    let json = serde_json::to_value(&stuck).unwrap();
    assert_eq!(json["sameDrive"], true);
    assert!(json.get("movedTo").is_some());
    for p in [&stay, &moved] {
        let m = p.message.as_deref().unwrap();
        assert!(m.ends_with('.') && m.matches(". ").count() == 0, "{m}");
    }
    // An image scan never warns and never moves anything (tests see no real drives).
    let img = SourceRef { kind: SourceKind::Image, path: "x.img".into(), ..Default::default() };
    let p = session::preview_location(&img).unwrap();
    assert!(!p.same_drive && p.moved_to.is_none() && p.refuse.is_none());
}

/// S1: volume and snapshot sources count only their own volume; whole-disk sources count every
/// volume on the disk; image sources are only a preference and are never refused.
#[test]
fn session_location_compares_volumes_for_volume_sources() {
    use session::{choose_avoiding, files_on, Candidate, Choice, Place};
    let gib = 1u64 << 30;
    // C: and D: are partitions of disk 0; E: is on disk 1.
    let c = Place { disks: vec![0], root: Some("C:\\".into()), ..Default::default() };
    let d = Place { disks: vec![0], root: Some("D:\\".into()), ..Default::default() };
    let disk0 = Place { disks: vec![0], whole_disk: true, ..Default::default() };
    let data_on_c = c.clone();
    let cand = |root: &str, disks: Vec<u32>, free: u64| Candidate { root: root.into(), disks, free, ..Default::default() };
    let cands = vec![cand("D:\\", vec![0], 400 * gib), cand("E:\\", vec![1], 50 * gib)];

    // Scanning D: never moves a sessions folder that is on C:, and D: isn't refused while a session
    // file on C: grows (another scan of an SD card or an image).
    assert_eq!(choose_avoiding(&d, &[], &data_on_c, &cands), Choice::Default);
    assert!(!files_on(&d, &[c.clone()]));
    // Scanning C: may use D: (same disk, other volume) and prefers it for its free space.
    assert_eq!(choose_avoiding(&c, &[], &data_on_c, &cands), Choice::Elsewhere(vec!["D:\\".into(), "E:\\".into()]));
    // Scanning the whole disk 0: neither C: nor D: may be written.
    assert_eq!(choose_avoiding(&disk0, &[], &data_on_c, &cands), Choice::Elsewhere(vec!["E:\\".into()]));
    assert!(files_on(&disk0, &[d.clone()]));
    // A running scan of D: keeps a new C: scan's results off D:.
    assert_eq!(choose_avoiding(&c, &[d.clone()], &data_on_c, &cands), Choice::Elsewhere(vec!["E:\\".into()]));
    // A stopped scan's results on C: can be continued while D: is being scanned.
    assert!(!files_on(&d, &[data_on_c.clone()]));

    // Image on C:: a sessions folder on C: is harmless, another drive is only preferred.
    let img_on_c = Place { disks: vec![0], root: Some("C:\\".into()), soft: true, ..Default::default() };
    assert_eq!(choose_avoiding(&img_on_c, &[], &data_on_c, &cands), Choice::Prefer(vec!["D:\\".into(), "E:\\".into()]));
    assert_eq!(choose_avoiding(&img_on_c, &[], &data_on_c, &cands[..0]), Choice::Default);
    assert!(!files_on(&img_on_c, &[data_on_c.clone()]));
    // Prefer never ends in the same-drive warning when no folder can be made.
    let default = sessions_dir().unwrap();
    let loc = session::locate_choice(default.clone(), Choice::Prefer(vec!["Q:\\".into()]), |_| false);
    assert!(!loc.external && loc.note.is_none() && loc.dir == default);
    // An image scan while another scan reads C:: the results still leave C:.
    assert_eq!(choose_avoiding(&img_on_c, &[c.clone()], &data_on_c, &cands), Choice::Elsewhere(vec!["D:\\".into(), "E:\\".into()]));
    // A sessions folder whose real disk is unknown moves when it can, and is never claimed safe.
    let unsure = Place { root: Some("C:\\".into()), unsure: true, ..Default::default() };
    assert_eq!(choose_avoiding(&d, &[], &unsure, &cands), Choice::Elsewhere(vec!["E:\\".into()]));
    assert!(session::preview_for(&Choice::Default, &d, &unsure).message.is_none());
}

/// A whole-disk scan never vouches for a data folder whose disks are unknown; a sessions folder
/// stuck on a drive only another scan reads says so; volumes match by name however mounted.
#[test]
fn session_location_unknown_disks_busy_drives_and_volume_names() {
    use session::{choose_avoiding, preview_for, Candidate, Choice, Place};
    let gib = 1u64 << 30;
    let cand = |root: &str, disks: Vec<u32>, free: u64| Candidate { root: root.into(), disks, free, ..Default::default() };
    let cands = vec![cand("E:\\", vec![1], 50 * gib)];

    // R1: a data folder on C: whose disks couldn't be read, while disk 0 is scanned whole.
    let disk0 = Place { disks: vec![0], whole_disk: true, ..Default::default() };
    let data_c_unknown = Place { root: Some("C:\\".into()), ..Default::default() };
    assert_eq!(choose_avoiding(&disk0, &[], &data_c_unknown, &cands), Choice::Elsewhere(vec!["E:\\".into()]));
    assert_eq!(choose_avoiding(&disk0, &[], &data_c_unknown, &[]), Choice::Stuck);
    assert!(preview_for(&Choice::Default, &disk0, &data_c_unknown).message.is_none());
    // A network data folder has no local disk: it stays and is vouched for.
    let data_remote = Place { root: Some("\\\\nas\\share\\".into()), remote: true, ..Default::default() };
    assert_eq!(choose_avoiding(&disk0, &[], &data_remote, &cands), Choice::Default);
    assert!(preview_for(&Choice::Default, &disk0, &data_remote).message.unwrap().ends_with("the disk being scanned."));
    // A volume scan still compares volumes only.
    let d = Place { disks: vec![0], root: Some("D:\\".into()), ..Default::default() };
    assert_eq!(choose_avoiding(&d, &[], &data_c_unknown, &cands), Choice::Default);

    // R2: scanning D: while another scan reads C:, where the sessions folder is, and nothing else.
    let c = Place { disks: vec![0], root: Some("C:\\".into()), ..Default::default() };
    let busy = choose_avoiding(&d, &[c.clone()], &c, &[]);
    assert_eq!(busy, Choice::Busy);
    let p = preview_for(&busy, &d, &c);
    assert!(p.same_drive);
    assert_eq!(p.message.as_deref(), Some(session::BUSY_DRIVE_WARNING));
    let loc = session::locate_choice(sessions_dir().unwrap(), busy, |_| true);
    assert_eq!(loc.note.as_deref(), Some(session::BUSY_DRIVE_NOTE));
    // Scanning C: itself in the same spot is still the same-drive case.
    assert_eq!(choose_avoiding(&c, &[d.clone()], &c, &[]), Choice::Stuck);
    for m in [session::BUSY_DRIVE_WARNING, session::BUSY_DRIVE_NOTE] {
        assert!(m.ends_with('.') && !m.contains('\n'), "{m}");
    }

    // R3: a snapshot of a volume with no drive letter, mounted in a folder (C:\mnt\vol\) that
    // holds the sessions folder: the volume names match.
    let vol = "\\\\?\\volume{1234}\\";
    let snap = Place { disks: vec![0], root: Some(vol.into()), volume: Some(vol.into()), ..Default::default() };
    let data_mounted = Place { disks: vec![0], root: Some("C:\\mnt\\vol\\".into()), volume: Some("\\\\?\\Volume{1234}\\".into()), ..Default::default() };
    assert!(snap.hits(&data_mounted));
    assert_eq!(choose_avoiding(&snap, &[], &data_mounted, &cands), Choice::Elsewhere(vec!["E:\\".into()]));
    // A candidate drive letter for that same volume is left out.
    let same_vol = Candidate { volume: Some(vol.into()), ..cand("V:\\", vec![0], 900 * gib) };
    assert_eq!(choose_avoiding(&snap, &[], &data_mounted, &[same_vol, cands[0].clone()]), Choice::Elsewhere(vec!["E:\\".into()]));
    // Other volumes don't match.
    let other = Place { volume: Some("\\\\?\\volume{9999}\\".into()), root: Some("C:\\".into()), disks: vec![0], ..Default::default() };
    assert!(!snap.hits(&other));
}

/// S2: a virtual disk (VHD/VHDX) whose file is on the source's disk is never used for results, nor
/// is a drive whose real disk can't be determined; a subst drive counts as the drive it points to.
#[test]
fn session_location_skips_virtual_disks_on_the_source() {
    use session::{candidate_from, choose_avoiding, Choice, DriveFacts, Place};
    let gib = 1u64 << 30;
    let facts = |root: &str, own: Vec<u32>, disks: Option<Vec<u32>>, free: u64| DriveFacts {
        root: root.into(),
        free,
        own_disks: own,
        disks,
        real_root: Some(root.into()),
        ..Default::default()
    };
    // V: is a Dev Drive (disk 5) whose VHDX lives on disk 0; E: is a plain drive on disk 1.
    let v = candidate_from(facts("V:\\", vec![5], Some(vec![0, 5]), 900 * gib)).unwrap();
    assert_eq!(v.hosts, vec![0]);
    assert_eq!(v.disks, vec![0, 5]);
    let e = candidate_from(facts("E:\\", vec![1], Some(vec![1]), 50 * gib)).unwrap();
    assert!(e.hosts.is_empty() && e.real_root.is_none());
    // Unknown disks, an unplaceable virtual disk and network drives are left out.
    assert!(candidate_from(facts("X:\\", vec![], Some(vec![2]), 900 * gib)).is_none());
    assert!(candidate_from(facts("X:\\", vec![2], None, 900 * gib)).is_none());
    assert!(candidate_from(facts("X:\\", vec![2], Some(vec![]), 900 * gib)).is_none());
    assert!(candidate_from(DriveFacts { refused: true, ..facts("X:\\", vec![6], Some(vec![6]), 900 * gib) }).is_none());
    assert!(candidate_from(DriveFacts { network: true, ..facts("X:\\", vec![6], Some(vec![6]), 900 * gib) }).is_none());
    // A subst drive of a folder on C: is C:.
    let s = candidate_from(DriveFacts { real_root: Some("c:\\".into()), ..facts("S:\\", vec![0], Some(vec![0]), 800 * gib) }).unwrap();
    assert_eq!(s.real_root.as_deref(), Some("c:\\"));

    let c = Place { disks: vec![0], root: Some("C:\\".into()), ..Default::default() };
    let data_on_c = c.clone();
    let cands = vec![v.clone(), e.clone(), s.clone()];
    // Scanning C:: V: would grow its VHDX into disk 0, S: is C: itself.
    assert_eq!(choose_avoiding(&c, &[], &data_on_c, &cands), Choice::Elsewhere(vec!["E:\\".into()]));
    // Scanning E:: V:'s file isn't on E:, so V: (most free space) takes the sessions folder only if
    // it has to move; it doesn't (the sessions folder is on C:).
    let e_src = Place { disks: vec![1], root: Some("E:\\".into()), ..Default::default() };
    assert_eq!(choose_avoiding(&e_src, &[], &data_on_c, &cands), Choice::Default);
    // Scanning disk 0 whole: V: and S: are out too.
    let disk0 = Place { disks: vec![0], whole_disk: true, ..Default::default() };
    assert_eq!(choose_avoiding(&disk0, &[], &data_on_c, &cands), Choice::Elsewhere(vec!["E:\\".into()]));
    // Scanning V: itself while the sessions folder is on V: (data on a virtual disk on disk 0).
    let v_src = Place { disks: vec![5], root: Some("V:\\".into()), ..Default::default() };
    let data_on_v = Place { disks: vec![0, 5], root: Some("V:\\".into()), hosts: vec![0], ..Default::default() };
    assert_eq!(choose_avoiding(&v_src, &[], &data_on_v, &cands), Choice::Elsewhere(vec!["S:\\".into(), "E:\\".into()]));
    // Scanning C: while the sessions folder is on V: (its file on disk 0): it moves.
    assert_eq!(choose_avoiding(&c, &[], &data_on_v, &cands), Choice::Elsewhere(vec!["E:\\".into()]));
}

#[test]
fn folder_on_volume_resolves_real_folders() {
    use crate::device::win::folder_on_volume;
    let win = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let letter = win.chars().next().unwrap().to_ascii_uppercase();
    let sys32 = format!(r"{}\System32\", win.to_lowercase());
    assert_eq!(folder_on_volume(&sys32).unwrap(), (letter, r"\Windows\System32".to_string()));
    assert_eq!(folder_on_volume(&format!(r"{letter}:\")).unwrap(), (letter, String::new()));
    // A junction resolves to its target.
    let docs = format!(r"{letter}:\Documents and Settings");
    if std::fs::metadata(&docs).is_ok() {
        assert_eq!(folder_on_volume(&docs).unwrap(), (letter, r"\Users".to_string()));
    }
    let missing = folder_on_volume(&format!(r"{letter}:\no such folder 81723")).unwrap_err();
    assert!(missing.contains("pick the folder that contained it"));
    assert!(folder_on_volume(&format!(r"{win}\notepad.exe")).is_err());
}
