//! Session files: where they live, their schema, connections (a small per-session cache), meta
//! keys, ids, per-session change generations and the process-alive check used for crash recovery.

use rusqlite::types::{FromSql, ToSql, Value};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

pub const SCHEMA_VERSION: i64 = 1;
pub const EXT: &str = "maxscan";

pub const GONE: &str = "This scan session no longer exists. It may have been deleted; pick another one from the list.";
pub const DAMAGED: &str = "MAX couldn't read this scan session. The session file may be damaged.";
pub const WRITE_FAILED: &str = "MAX couldn't save to this scan session. Check that the drive with MAX's data folder has free space.";

// Meta keys.
pub const K_SCHEMA: &str = "schema";
pub const K_SOURCE: &str = "source";
pub const K_OPTIONS: &str = "options";
pub const K_LABEL: &str = "label";
pub const K_MODE: &str = "mode";
pub const K_STATE: &str = "state";
pub const K_CREATED: &str = "created";
pub const K_UPDATED: &str = "updated";
pub const K_PID: &str = "pid";
pub const K_PID_STARTED: &str = "pid_started";
pub const K_PROBE: &str = "probe";
pub const K_PARTITIONS: &str = "partitions";
pub const K_STAGES: &str = "stages";
pub const K_NOTES: &str = "notes";
pub const K_ERROR: &str = "error";
pub const K_SWEEP_POS: &str = "sweep_pos";
/// Sweep position up to which the visitors' results were collected (`finish` ran).
pub const K_HARVEST_POS: &str = "harvest_pos";
/// Highest file id whose condition was assessed (in id order).
pub const K_CONDITION_POS: &str = "condition_pos";
pub const K_SOURCE_LEN: &str = "source_len";
pub const K_SECTOR_SIZE: &str = "sector_size";
pub const K_SCANNED: &str = "scanned_bytes";
pub const K_BAD: &str = "bad_bytes";
pub const K_FILES: &str = "files";
pub const K_BYTES: &str = "bytes";
pub const K_MAX_EXTENT: &str = "max_extent";
pub const K_RANGES_AT: &str = "ranges_at";
pub fn k_ranges(kind: usize) -> String {
    format!("ranges.{kind}")
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS files(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL, name_lc TEXT NOT NULL, folder TEXT NOT NULL, folder_lc TEXT NOT NULL,
  ext TEXT NOT NULL, type_id TEXT NOT NULL, category TEXT NOT NULL, size INTEGER NOT NULL,
  status TEXT NOT NULL, origin TEXT NOT NULL, condition TEXT NOT NULL, cond_rank INTEGER NOT NULL,
  note TEXT NOT NULL, created INTEGER, modified INTEGER, accessed INTEGER, deleted INTEGER,
  fragmented INTEGER NOT NULL, flags INTEGER NOT NULL, fs_ref INTEGER, meta TEXT,
  extents BLOB, resident BLOB, live_path TEXT, hash TEXT, dup_group INTEGER,
  first_off INTEGER, stage INTEGER NOT NULL DEFAULT 0, seg INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS file_extents(start_off INTEGER NOT NULL, end_off INTEGER NOT NULL, file_id INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS log(at INTEGER NOT NULL, level TEXT NOT NULL, message TEXT NOT NULL);
";

// ------------------------------------------------------------------------------------ paths

/// The folder holding the session files. Tests use a private temp folder so they never touch the
/// user's sessions.
pub fn sessions_dir() -> Result<PathBuf, String> {
    #[cfg(test)]
    {
        static D: OnceLock<PathBuf> = OnceLock::new();
        let d = D.get_or_init(|| {
            let p = std::env::temp_dir().join(format!("max-scan-tests-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&p);
            p
        });
        Ok(d.clone())
    }
    #[cfg(not(test))]
    {
        crate::paths::sessions_dir().ok_or_else(|| "MAX couldn't create its data folder. Check that your user folder is writable.".to_string())
    }
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 100 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// The session's file: in the sessions folder, or (scans of the drive that holds MAX's data folder)
/// a registered file on another drive. A missing session gets its default path (not a file).
pub fn session_path(id: &str) -> Result<PathBuf, String> {
    if !valid_id(id) {
        return Err(GONE.into());
    }
    let p = sessions_dir()?.join(format!("{id}.{EXT}"));
    if p.is_file() {
        return Ok(p);
    }
    Ok(external_paths().into_iter().find(|x| stem_of(x).as_deref() == Some(id)).unwrap_or(p))
}

fn stem_of(p: &Path) -> Option<String> {
    p.file_stem().and_then(|s| s.to_str()).map(str::to_string)
}

// ------------------------------------------------------------------- external session files

/// Kept as a note when no other drive could hold the session of a scan of MAX's own drive.
pub const SAME_DRIVE_NOTE: &str = "MAX had to keep this scan's results on the drive being scanned. Connect another drive (or run MAX in portable mode from a USB stick) to avoid overwriting deleted files.";
/// Note for a session kept on a drive that another running scan was reading ([`Choice::Busy`]).
pub const BUSY_DRIVE_NOTE: &str = "MAX had to keep this scan's results on a drive another scan was reading. Connect another drive (or run MAX in portable mode from a USB stick) to avoid overwriting deleted files there.";
/// Folder (under a drive root) for sessions kept away from the drive being scanned.
pub const EXTERNAL_DIR: &str = "MAX Recovery\\sessions";
const MIN_FREE: u64 = 1 << 30;

/// The registry of session files kept outside the sessions folder (a JSON list of paths).
fn registry_file() -> Option<PathBuf> {
    #[cfg(test)]
    {
        sessions_dir().ok().map(|d| d.join("external-sessions.json"))
    }
    #[cfg(not(test))]
    {
        crate::paths::data_dir().map(|d| d.join("external-sessions.json"))
    }
}

fn registry() -> &'static Mutex<Option<Vec<PathBuf>>> {
    static R: OnceLock<Mutex<Option<Vec<PathBuf>>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(None))
}

fn with_registry<R>(f: impl FnOnce(&mut Vec<PathBuf>) -> R) -> R {
    let mut g = registry().lock().unwrap_or_else(|e| e.into_inner());
    let list = g.get_or_insert_with(|| {
        registry_file()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str::<Vec<PathBuf>>(&s).ok())
            .unwrap_or_default()
    });
    f(list)
}

fn save_registry(list: &[PathBuf]) {
    let Some(p) = registry_file() else { return };
    let tmp = p.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(list).unwrap_or_else(|_| "[]".into());
    if std::fs::write(&tmp, json).is_ok() && std::fs::rename(&tmp, &p).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Registered session files outside the sessions folder (they may be on a drive that isn't
/// connected right now).
pub fn external_paths() -> Vec<PathBuf> {
    with_registry(|l| l.clone())
}

pub fn register_external(path: &Path) {
    with_registry(|l| {
        if !l.iter().any(|x| x == path) {
            l.push(path.to_path_buf());
            save_registry(l);
        }
    });
}

pub fn unregister_external(path: &Path) {
    with_registry(|l| {
        let n = l.len();
        l.retain(|x| x != path);
        if l.len() != n {
            save_registry(l);
        }
    });
}

/// Every session file that exists now: the sessions folder, then registered files elsewhere
/// (an id already seen in the sessions folder wins).
pub fn all_session_files() -> Vec<(String, PathBuf)> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    if let Ok(dir) = sessions_dir() {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) != Some(EXT) {
                    continue;
                }
                if let Some(id) = stem_of(&p).filter(|s| valid_id(s)) {
                    out.push((id, p));
                }
            }
        }
    }
    for p in external_paths() {
        let Some(id) = stem_of(&p).filter(|s| valid_id(s)) else { continue };
        if p.is_file() && !out.iter().any(|(i, _)| *i == id) {
            out.push((id, p));
        }
    }
    out
}

/// A local drive that could hold session files.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Candidate {
    /// "E:\" (where the folder is made).
    pub root: String,
    /// Physical disks its bytes really land on, including the disks holding the file of a virtual
    /// disk (empty = unknown; such a drive is never used).
    pub disks: Vec<u32>,
    pub free: u64,
    /// Disks holding the file behind a virtual disk (VHD/VHDX) this drive is on (empty = not one).
    pub hosts: Vec<u32>,
    /// Mount root of the volume it really is ("C:\" for a subst drive of a folder on C:), when it
    /// differs from `root`.
    pub real_root: Option<String>,
    /// `\\?\volume{…}\` of the volume it really is, when known.
    pub volume: Option<String>,
}

/// What MAX learned about a fixed drive (read-only lookups), for [`candidate_from`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DriveFacts {
    /// "E:\"
    pub root: String,
    pub free: u64,
    /// Disks under the volume itself (its extents; empty = unknown).
    pub own_disks: Vec<u32>,
    /// Every disk its bytes land on, virtual-disk files included (`device::win::locate_path`;
    /// None = unknown).
    pub disks: Option<Vec<u32>>,
    /// Mount root of the real path.
    pub real_root: Option<String>,
    /// A network drive.
    pub network: bool,
    /// `locate_path` refused it (a virtual disk whose file couldn't be placed, too many links…).
    pub refused: bool,
    /// `\\?\volume{…}\` of the volume it really is, when known.
    pub volume: Option<String>,
}

/// Pure: a fixed drive as a place for session files, or None when MAX can't tell which physical
/// disk really holds its bytes (unknown disks, a virtual disk whose file couldn't be placed, a
/// network drive). A virtual disk keeps its host disks in `hosts`, so [`choose_avoiding`] leaves
/// it out when its file is on the drive being scanned.
pub fn candidate_from(f: DriveFacts) -> Option<Candidate> {
    if f.refused || f.network || f.own_disks.is_empty() {
        return None;
    }
    let mut disks = f.disks.filter(|d| !d.is_empty())?;
    disks.extend(f.own_disks.iter().copied());
    disks.sort_unstable();
    disks.dedup();
    let hosts: Vec<u32> = disks.iter().copied().filter(|d| !f.own_disks.contains(d)).collect();
    let real_root = f.real_root.filter(|r| !same_root(r, &f.root));
    Some(Candidate { root: f.root, disks, free: f.free, hosts, real_root, volume: f.volume })
}

fn same_root(a: &str, b: &str) -> bool {
    a.trim_end_matches('\\').eq_ignore_ascii_case(b.trim_end_matches('\\'))
}

/// Where something lives. For a scan source: what must not be written to. For a file or folder:
/// where its bytes land.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Place {
    /// Physical disks (empty = unknown); for a file or folder this includes the disks holding the
    /// file of a virtual disk it is on.
    pub disks: Vec<u32>,
    /// Volume root ("C:\"; a folder path for a volume mounted in a folder).
    pub root: Option<String>,
    /// `\\?\volume{…}\` of the volume, when known: matches a volume however it is mounted.
    pub volume: Option<String>,
    /// On another computer (a network share): no local disk can be hit.
    pub remote: bool,
    /// A file or folder on a virtual disk: the disks holding that disk's file.
    pub hosts: Vec<u32>,
    /// A source that is a whole disk (or a window on one): every volume on its disks counts. Volume
    /// and snapshot sources count only their own volume (a write to C: can't touch D:'s free
    /// clusters, even on the same disk).
    pub whole_disk: bool,
    /// An image file's volume: writing there can't change the image, so it is avoided only when
    /// another drive can take the results, and never refused.
    pub soft: bool,
    /// A folder whose real disks couldn't be determined: moved away from a scanned drive when
    /// another drive can take the results.
    pub unsure: bool,
}

impl Place {
    fn known(&self) -> bool {
        !self.disks.is_empty() || self.root.is_some() || self.volume.is_some()
    }
    /// Can writing to `target` change what a scan of `self` reads? Unknown places never match.
    pub fn hits(&self, target: &Place) -> bool {
        if !self.known() || !target.known() {
            return false;
        }
        if matches!((&self.root, &target.root), (Some(a), Some(b)) if same_root(a, b))
            || matches!((&self.volume, &target.volume), (Some(a), Some(b)) if same_root(a, b))
        {
            return true;
        }
        if self.whole_disk {
            return self.disks.iter().any(|d| target.disks.contains(d));
        }
        // A virtual disk whose file is on the source's disk grows into it. Only the disk of that
        // file is known, so any virtual disk stored on the source's disk counts.
        !target.hosts.is_empty() && (self.disks.is_empty() || target.hosts.iter().any(|d| self.disks.contains(d)))
    }
    /// [`hits`](Self::hits), or MAX can't rule it out: `target` is marked [`unsure`](Self::unsure),
    /// or `self` is a whole disk and `target` is a local place whose disks are unknown.
    pub fn risks(&self, target: &Place) -> bool {
        self.known()
            && (target.unsure
                || self.hits(target)
                || (self.whole_disk && target.known() && !target.remote && target.disks.is_empty()))
    }
    /// Kept for callers that compare two places: true when either hits the other.
    #[allow(dead_code)]
    pub fn shares(&self, other: &Place) -> bool {
        self.hits(other) || other.hits(self)
    }
}

#[derive(Debug, PartialEq)]
pub enum Choice {
    /// The sessions folder isn't on the drive being scanned.
    Default,
    /// Candidate roots to try, best (most free space) first.
    Elsewhere(Vec<String>),
    /// Same drive and no other drive.
    Stuck,
    /// The sessions folder is on a drive only another running scan reads (not the one about to be
    /// scanned), and no other drive can take the results.
    Busy,
    /// The sessions folder is only on an image's drive (harmless), but these roots are better;
    /// if none of them takes the folder, the sessions folder is fine.
    Prefer(Vec<String>),
}

/// Pure decision (no Windows calls).
#[allow(dead_code)]
pub fn choose(source: &Place, data: &Place, cands: &[Candidate]) -> Choice {
    choose_avoiding(source, &[], data, cands)
}

/// [`choose`] that also keeps away from `busy`: the drives and disks other running scans read.
/// The sessions folder moves when it is on any of them; a candidate on any of them is left out.
/// Image sources ([`Place::soft`]) are avoided only when another drive is free of everything.
pub fn choose_avoiding(source: &Place, busy: &[Place], data: &Place, cands: &[Candidate]) -> Choice {
    let all: Vec<&Place> = std::iter::once(source).chain(busy.iter()).filter(|p| p.known()).collect();
    let hard: Vec<&Place> = all.iter().copied().filter(|p| !p.soft).collect();
    let hit = |avoid: &[&Place], at: &Place| avoid.iter().any(|p| p.hits(at));
    let data_hard = hard.iter().any(|p| p.risks(data));
    let data_soft = all.iter().any(|p| p.risks(data));
    if !data_soft {
        return Choice::Default;
    }
    let usable = |avoid: &[&Place]| -> Vec<String> {
        let mut ok: Vec<&Candidate> = cands
            .iter()
            .filter(|c| c.free >= MIN_FREE && !c.disks.is_empty())
            .filter(|c| {
                let root = c.real_root.clone().unwrap_or_else(|| c.root.clone());
                let at = Place { disks: c.disks.clone(), root: Some(root), volume: c.volume.clone(), hosts: c.hosts.clone(), ..Default::default() };
                !hit(avoid, &at)
            })
            .collect();
        ok.sort_by(|a, b| b.free.cmp(&a.free).then_with(|| a.root.cmp(&b.root)));
        ok.into_iter().map(|c| c.root.clone()).collect()
    };
    let clean = usable(&all);
    if !data_hard {
        return if clean.is_empty() { Choice::Default } else { Choice::Prefer(clean) };
    }
    if !clean.is_empty() {
        return Choice::Elsewhere(clean);
    }
    let ok = usable(&hard);
    if ok.is_empty() {
        if !source.soft && source.risks(data) {
            Choice::Stuck
        } else {
            Choice::Busy
        }
    } else {
        Choice::Elsewhere(ok)
    }
}

/// Where a new session's file goes, and a note for the session when it says something.
pub struct Location {
    pub dir: PathBuf,
    pub external: bool,
    pub note: Option<String>,
}

/// Decide with the facts gathered (testable: `make_dir` creates the folder on a candidate).
#[allow(dead_code)]
pub fn locate_with(default: PathBuf, source: &Place, data: &Place, cands: &[Candidate], make_dir: impl Fn(&Path) -> bool) -> Location {
    locate_avoiding(default, source, &[], data, cands, make_dir)
}

/// [`locate_with`] that also keeps away from the drives other running scans read (`busy`).
pub fn locate_avoiding(
    default: PathBuf,
    source: &Place,
    busy: &[Place],
    data: &Place,
    cands: &[Candidate],
    make_dir: impl Fn(&Path) -> bool,
) -> Location {
    locate_choice(default, choose_avoiding(source, busy, data, cands), make_dir)
}

/// The location for a decided [`Choice`]: the first root whose folder can be made.
pub fn locate_choice(default: PathBuf, choice: Choice, make_dir: impl Fn(&Path) -> bool) -> Location {
    match choice {
        Choice::Default => Location { dir: default, external: false, note: None },
        Choice::Prefer(roots) => {
            for r in roots {
                let dir = Path::new(&r).join(EXTERNAL_DIR);
                if make_dir(&dir) {
                    let shown = r.trim_end_matches('\\').to_string();
                    let note = format!("MAX is keeping this scan's results on {shown}, away from the drive that holds the image. Keep {shown} connected to open this scan later.");
                    return Location { dir, external: true, note: Some(note) };
                }
            }
            Location { dir: default, external: false, note: None }
        }
        Choice::Elsewhere(roots) => {
            for r in roots {
                let dir = Path::new(&r).join(EXTERNAL_DIR);
                if make_dir(&dir) {
                    let shown = r.trim_end_matches('\\').to_string();
                    let note = format!(
                        "MAX is keeping this scan's results on {shown} so nothing is written to the drive being scanned. Keep {shown} connected to open this scan later."
                    );
                    return Location { dir, external: true, note: Some(note) };
                }
            }
            Location { dir: default, external: false, note: Some(SAME_DRIVE_NOTE.into()) }
        }
        Choice::Stuck => Location { dir: default, external: false, note: Some(SAME_DRIVE_NOTE.into()) },
        Choice::Busy => Location { dir: default, external: false, note: Some(BUSY_DRIVE_NOTE.into()) },
    }
}

/// The facts and the decision behind a new session's location. `scan_location` previews it and
/// `start_scan` follows it, so both always agree.
pub struct Decision {
    /// The sessions folder.
    pub default: PathBuf,
    pub source: Place,
    pub data: Place,
    pub choice: Choice,
}

/// Decide where a new scan of `source` keeps its results (read-only lookups, nothing is made):
/// the sessions folder, unless it is on the drive being scanned (or one another running scan
/// reads); then a "MAX Recovery\sessions" folder on the fixed local drive with the most free
/// space (at least 1 GiB) that is on none of them, whose real disk is known and that isn't a
/// virtual disk stored on one of them; or the sessions folder, with a warning.
pub fn decide(source: &crate::model::SourceRef) -> Result<Decision, String> {
    let default = sessions_dir()?;
    let src = source_place(source);
    let busy: Vec<Place> = super::jobs::running_sources().iter().map(source_place).filter(Place::known).collect();
    let data = path_place(&default);
    let avoid: Vec<&Place> = std::iter::once(&src).chain(busy.iter()).filter(|p| p.known()).collect();
    // Only look at the other drives when the sessions folder has to move.
    let moves = avoid.iter().any(|p| p.risks(&data));
    let cands = if moves { candidates() } else { Vec::new() };
    let choice = choose_avoiding(&src, &busy, &data, &cands);
    Ok(Decision { default, source: src, data, choice })
}

/// The session location for a new scan of `source`: [`decide`], then the first folder that can
/// be made (or the sessions folder with a note).
pub fn pick_location(source: &crate::model::SourceRef) -> Result<Location, String> {
    let d = decide(source)?;
    Ok(locate_choice(d.default, d.choice, |dir| std::fs::create_dir_all(dir).is_ok() && dir.is_dir()))
}

/// What a scan must not write to. Volumes and snapshots: their own volume (a snapshot's free
/// clusters are its original volume's). Disks: every volume on them. Images: the image file's
/// volume, as a preference only (writing next to an image can't change it).
fn source_place(r: &crate::model::SourceRef) -> Place {
    use crate::model::SourceKind;
    match r.kind {
        SourceKind::Volume => match r.path.trim().chars().next().filter(|c| c.is_ascii_alphabetic()) {
            Some(l) => {
                let l = l.to_ascii_uppercase();
                Place { disks: letter_disks(l), root: Some(format!("{l}:\\")), volume: letter_volume(l), ..Default::default() }
            }
            None => Place::default(),
        },
        SourceKind::Disk => Place {
            disks: r.path.trim().trim_start_matches(|c: char| !c.is_ascii_digit()).parse::<u32>().ok().into_iter().collect(),
            whole_disk: true,
            ..Default::default()
        },
        SourceKind::Snapshot => snapshot_place(r),
        SourceKind::Image => {
            let p = path_place(Path::new(r.path.trim()));
            Place { disks: p.disks, root: p.root, volume: p.volume, soft: true, ..Default::default() }
        }
    }
}

#[cfg(not(test))]
fn snapshot_place(r: &crate::model::SourceRef) -> Place {
    let loc = crate::device::win::source_location(r);
    let root = loc.volume.as_deref().and_then(|v| {
        ('A'..='Z').find(|&l| crate::device::win::letter_volume(l).is_some_and(|x| x.eq_ignore_ascii_case(v))).map(|l| format!("{l}:\\"))
    });
    // An original volume without a drive letter is matched by its volume name, also against a
    // folder on it that is reached through a folder mount point.
    let root = root.or_else(|| loc.volume.clone());
    Place { disks: loc.disks.unwrap_or_default(), root, volume: loc.volume, ..Default::default() }
}

#[cfg(test)]
fn snapshot_place(_: &crate::model::SourceRef) -> Place {
    Place::default() // tests never look at real drives
}

/// Refusal when a running scan keeps its session file on the drive about to be scanned: that file
/// grows for as long as the scan runs, onto the free space being searched.
pub const SESSION_ON_SOURCE: &str = "Another scan is saving its results on this drive. Stop that scan or wait for it to finish, then scan this drive.";
/// Refusal when the drive holding a stopped scan's results is being read by another scan.
pub const RESULTS_ON_SCANNED: &str = "Another scan is reading the drive that holds this scan's results. Wait for that scan to finish, then continue this one.";

/// Pure check: does any of `files` (places of session files) lie on `source`, so that writing it
/// changes what a scan of `source` reads? Image sources ([`Place::soft`]) never match: writing
/// next to an image can't change it.
pub fn files_on(source: &Place, files: &[Place]) -> bool {
    !source.soft && files.iter().any(|f| source.hits(f))
}

/// Refuse a scan of `source` while a running scan's session file is on that drive.
pub fn check_running_sessions(source: &crate::model::SourceRef) -> Result<(), String> {
    let src = source_place(source);
    if !src.known() || src.soft {
        return Ok(());
    }
    let files: Vec<Place> = super::jobs::running_session_files().iter().map(|p| path_place(p)).collect();
    if files_on(&src, &files) {
        return Err(SESSION_ON_SOURCE.into());
    }
    Ok(())
}

/// Refuse to continue a scan whose session file is on a drive another running scan reads.
pub fn check_results_drive(path: &Path) -> Result<(), String> {
    let busy: Vec<Place> = super::jobs::running_sources().iter().map(source_place).filter(|p| p.known() && !p.soft).collect();
    if busy.is_empty() {
        return Ok(());
    }
    let here = path_place(path);
    if busy.iter().any(|b| files_on(b, std::slice::from_ref(&here))) {
        return Err(RESULTS_ON_SCANNED.into());
    }
    Ok(())
}

/// Shown before a scan starts when its results must stay on the drive being scanned.
pub const SAME_DRIVE_WARNING: &str = "MAX will have to keep this scan's results on the drive being scanned, which can overwrite deleted files. Connect another drive with at least 1 GB free (or run MAX in portable mode from a USB stick) before you scan, if you can.";
/// Shown before a scan starts when its results must stay on a drive another running scan reads.
pub const BUSY_DRIVE_WARNING: &str = "MAX will have to keep this scan's results on a drive another scan is reading, which can overwrite deleted files there. Wait for that scan to finish (or connect another drive with at least 1 GB free) before you scan, if you can.";

/// What starting a scan of a source would do with its session file (`scan_location` command).
#[derive(serde::Serialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LocationPreview {
    /// The results would be written to the drive being scanned (or to one another running scan
    /// reads; `message` says which).
    pub same_drive: bool,
    /// The drive the results would go to instead ("E:"), when they move.
    pub moved_to: Option<String>,
    /// A sentence to show before the scan starts (a warning when `same_drive`).
    pub message: Option<String>,
    /// Why the scan would be refused right now.
    pub refuse: Option<String>,
}

/// "C:" for a drive-letter root, None otherwise.
fn letter_of(root: Option<&str>) -> Option<String> {
    let r = root?.trim_end_matches('\\');
    let b = r.as_bytes();
    (b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':').then(|| r.to_ascii_uppercase())
}

/// How the preview names what a scan of `source` must not write to.
fn source_name(source: &Place) -> String {
    if source.whole_disk {
        return "the disk being scanned".into();
    }
    letter_of(source.root.as_deref()).unwrap_or_else(|| "the drive being scanned".into())
}

/// Pure: the preview of a decision ([`decide`]): one sentence saying where the results go.
pub fn preview_for(choice: &Choice, source: &Place, data: &Place) -> LocationPreview {
    let moved = |roots: &[String]| roots.first().map(|r| (r.trim_end_matches('\\').to_string(), Path::new(r).join(EXTERNAL_DIR)));
    match choice {
        Choice::Default => {
            // `risks` covers an unsure folder and, for a whole disk, a folder whose disks are unknown.
            let safe = source.known() && !source.soft && data.known() && !source.risks(data);
            let message = safe.then(|| {
                let at = match letter_of(data.root.as_deref()) {
                    Some(l) => format!("MAX's data folder on {l}"),
                    None => "MAX's data folder".into(),
                };
                format!("This scan's results will be saved in {at}, so nothing is written to {}.", source_name(source))
            });
            LocationPreview { message, ..Default::default() }
        }
        Choice::Elsewhere(roots) => {
            let Some((shown, dir)) = moved(roots) else {
                let stuck = if !source.soft && source.risks(data) { Choice::Stuck } else { Choice::Busy };
                return preview_for(&stuck, source, data);
            };
            let away = if source.known() && !source.soft { source_name(source) } else { "the drives other scans are reading".into() };
            LocationPreview {
                moved_to: Some(shown),
                message: Some(format!("This scan's results will be saved in {}, so nothing is written to {away}.", dir.display())),
                ..Default::default()
            }
        }
        Choice::Prefer(roots) => {
            let Some((shown, dir)) = moved(roots) else { return preview_for(&Choice::Default, source, data) };
            LocationPreview {
                moved_to: Some(shown),
                message: Some(format!("This scan's results will be saved in {}, away from the drive that holds the image.", dir.display())),
                ..Default::default()
            }
        }
        Choice::Stuck => LocationPreview { same_drive: true, message: Some(SAME_DRIVE_WARNING.into()), ..Default::default() },
        Choice::Busy => LocationPreview { same_drive: true, message: Some(BUSY_DRIVE_WARNING.into()), ..Default::default() },
    }
}

/// Where a scan of `source` would keep its results, without creating anything (read-only
/// lookups): the same [`decide`] that `start_scan` follows. The UI shows `message` before the
/// scan starts.
pub fn preview_location(source: &crate::model::SourceRef) -> Result<LocationPreview, String> {
    if let Err(e) = check_running_sessions(source) {
        return Ok(LocationPreview { refuse: Some(e), ..Default::default() });
    }
    let d = decide(source)?;
    Ok(preview_for(&d.choice, &d.source, &d.data))
}

#[cfg(not(test))]
fn letter_disks(l: char) -> Vec<u32> {
    let mut d: Vec<u32> = crate::device::win::letter_extents(&l.to_string()).iter().map(|e| e.disk).collect();
    d.sort_unstable();
    d.dedup();
    d
}

#[cfg(test)]
fn letter_disks(_: char) -> Vec<u32> {
    Vec::new() // tests never look at real drives
}

#[cfg(not(test))]
fn letter_volume(l: char) -> Option<String> {
    crate::device::win::letter_volume(l)
}

#[cfg(test)]
fn letter_volume(_: char) -> Option<String> {
    None // tests never look at real drives
}

/// Where the bytes of `p` really land (after links, subst drives and virtual disks; read-only).
#[cfg(not(test))]
fn path_place(p: &Path) -> Place {
    use crate::device::win;
    let s = p.to_string_lossy().to_string();
    let lexical = win::volume_of_path(&s);
    let lexical_root = lexical.as_ref().map(|(r, _)| r.clone());
    let lexical_volume = lexical.as_ref().and_then(|(_, g)| g.as_deref().map(str::to_ascii_lowercase));
    let loc = win::locate_path(&s);
    if loc.refuse.is_some() {
        // A virtual disk whose file couldn't be placed: keep results away from scanned drives.
        return Place { disks: win::disks_of_path(&s), root: lexical_root, volume: lexical_volume, unsure: true, ..Default::default() };
    }
    if loc.network_root.is_some() {
        return Place { root: loc.root, remote: true, ..Default::default() }; // on another computer
    }
    // The lexical volume stands in only when the real path is on that same mount root.
    let same_mount = matches!((&loc.root, &lexical_root), (Some(a), Some(b)) if same_root(a, b));
    let volume = loc.volume.clone().or(if same_mount { lexical_volume } else { None });
    let real = loc.real_path.clone().unwrap_or_else(|| s.clone());
    let own = win::disks_of_path(&real);
    let mut disks = loc.disks.unwrap_or_default();
    let hosts: Vec<u32> = if own.is_empty() { Vec::new() } else { disks.iter().copied().filter(|d| !own.contains(d)).collect() };
    disks.extend(own);
    disks.sort_unstable();
    disks.dedup();
    Place { disks, root: loc.root.or(lexical_root), volume, hosts, ..Default::default() }
}

#[cfg(test)]
fn path_place(_: &Path) -> Place {
    Place::default()
}

/// Local fixed drives with their disks and free space (read-only lookups). Removable drives (SD
/// cards, USB sticks) are left out: they are often the very media holding the deleted files. So
/// are drives whose real disk can't be determined ([`candidate_from`]).
#[cfg(not(test))]
fn candidates() -> Vec<Candidate> {
    use windows_sys::Win32::Storage::FileSystem::{GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDrives};
    const DRIVE_FIXED: u32 = 3;
    let mask = unsafe { GetLogicalDrives() };
    let mut out = Vec::new();
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let l = (b'A' + i as u8) as char;
        let root = format!("{l}:\\");
        let w: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
        let t = unsafe { GetDriveTypeW(w.as_ptr()) };
        if t != DRIVE_FIXED {
            continue;
        }
        let mut free = 0u64;
        if unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut free, std::ptr::null_mut(), std::ptr::null_mut()) } == 0 {
            continue; // no media, locked, unreadable
        }
        let loc = crate::device::win::locate_path(&root);
        out.extend(candidate_from(DriveFacts {
            own_disks: letter_disks(l),
            disks: loc.disks,
            real_root: loc.root,
            network: loc.network_root.is_some(),
            refused: loc.refuse.is_some(),
            volume: loc.volume.or_else(|| letter_volume(l)),
            root,
            free,
        }));
    }
    out
}

#[cfg(test)]
fn candidates() -> Vec<Candidate> {
    Vec::new()
}

/// "20261124-193012" in local time.
pub fn local_stamp() -> String {
    let mut st: windows_sys::Win32::Foundation::SYSTEMTIME = unsafe { std::mem::zeroed() };
    unsafe { windows_sys::Win32::System::SystemInformation::GetLocalTime(&mut st) };
    format!("{:04}{:02}{:02}-{:02}{:02}{:02}", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond)
}

fn source_tag(r: &crate::model::SourceRef) -> String {
    use crate::model::SourceKind;
    let clean: String = r.path.chars().filter(|c| c.is_ascii_alphanumeric()).take(8).collect::<String>().to_ascii_lowercase();
    let base = match r.kind {
        SourceKind::Volume => if clean.is_empty() { "volume".to_string() } else { clean },
        SourceKind::Disk => format!("disk{clean}"),
        SourceKind::Image => "image".to_string(),
        SourceKind::Snapshot => "snapshot".to_string(),
    };
    if r.offset > 0 {
        format!("{base}-p{}", r.offset / (1 << 20))
    } else {
        base
    }
}

/// Reserve a new unique session file (created empty, then given the schema). Returns (id, path).
#[allow(dead_code)]
pub fn create(source: &crate::model::SourceRef, mode: &str) -> Result<(String, PathBuf), String> {
    create_in(&sessions_dir()?, source, mode)
}

/// [`create`] in `dir` (the sessions folder or an external one). Ids stay unique across both.
pub fn create_in(dir: &Path, source: &crate::model::SourceRef, mode: &str) -> Result<(String, PathBuf), String> {
    let base = format!("{}-{}-{}", local_stamp(), source_tag(source), mode);
    for n in 1..10_000 {
        let id = if n == 1 { base.clone() } else { format!("{base}-{n}") };
        if session_path(&id).is_ok_and(|p| p.is_file()) || super::jobs::running(&id).is_some() {
            continue;
        }
        let path = dir.join(format!("{id}.{EXT}"));
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(_) => {
                // Outside the sessions folder: registered at once, so its id stays taken.
                if sessions_dir().is_ok_and(|d| d.as_path() != dir) {
                    register_external(&path);
                }
                let c = open_path(&path, true)?;
                init_schema(&c)?;
                return Ok((id, path));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err("MAX couldn't create a session file in its data folder. Check that the drive has free space.".into()),
        }
    }
    Err("MAX couldn't pick a name for the new session file.".into())
}

/// Secondary indexes. They are dropped while a scan inserts (random-order index inserts made
/// every commit rewrite most index pages: 1M files took minutes) and built in bulk when it ends.
const INDEXES: &str = "
CREATE INDEX IF NOT EXISTS files_folder ON files(folder_lc, size);
CREATE INDEX IF NOT EXISTS files_name ON files(name_lc);
CREATE INDEX IF NOT EXISTS files_size ON files(size);
CREATE INDEX IF NOT EXISTS files_modified ON files(modified);
CREATE INDEX IF NOT EXISTS files_cond ON files(cond_rank, size);
CREATE INDEX IF NOT EXISTS files_cat ON files(category, size);
CREATE INDEX IF NOT EXISTS files_status ON files(status, size);
CREATE INDEX IF NOT EXISTS files_dup ON files(dup_group) WHERE dup_group IS NOT NULL;
CREATE INDEX IF NOT EXISTS file_extents_start ON file_extents(start_off, end_off, file_id);
CREATE INDEX IF NOT EXISTS file_extents_file ON file_extents(file_id);
";
const INDEX_NAMES: [&str; 10] =
    ["files_folder", "files_name", "files_size", "files_modified", "files_cond", "files_cat", "files_status", "files_dup", "file_extents_start", "file_extents_file"];

pub fn has_indexes(c: &Connection) -> bool {
    c.query_row("SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name LIKE 'file%'", [], |r| r.get::<_, i64>(0)).unwrap_or(0) as usize
        >= INDEX_NAMES.len()
}

pub fn create_indexes(c: &Connection) -> rusqlite::Result<()> {
    c.execute_batch(INDEXES)?;
    let _ = c.execute_batch("ANALYZE");
    Ok(())
}

pub fn drop_indexes(c: &Connection) -> rusqlite::Result<()> {
    for n in INDEX_NAMES {
        c.execute_batch(&format!("DROP INDEX IF EXISTS {n}"))?;
    }
    Ok(())
}

pub fn init_schema(c: &Connection) -> Result<(), String> {
    let _: String = c.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)).map_err(|_| WRITE_FAILED.to_string())?;
    c.execute_batch(SCHEMA).map_err(|_| WRITE_FAILED.to_string())?;
    meta_set(c, K_SCHEMA, SCHEMA_VERSION)?;
    Ok(())
}

// ------------------------------------------------------------------------------ connections

/// Open a session file read-write (never creates it unless `create`).
pub fn open_path(path: &Path, create: bool) -> Result<Connection, String> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let c = Connection::open_with_flags(path, flags).map_err(|_| DAMAGED.to_string())?;
    tune(&c);
    Ok(c)
}

/// Open read-only (for listing); falls back to read-write when SQLite can't read a WAL file
/// read-only.
pub fn open_read(path: &Path) -> Result<Connection, String> {
    let ro = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX);
    if let Ok(c) = ro {
        tune(&c);
        if c.query_row("SELECT count(*) FROM meta", [], |r| r.get::<_, i64>(0)).is_ok() {
            return Ok(c);
        }
    }
    open_path(path, false)
}

fn tune(c: &Connection) {
    let _ = c.busy_timeout(Duration::from_secs(15));
    let _ = c.pragma_update(None, "synchronous", "NORMAL");
    let _ = c.pragma_update(None, "temp_store", "MEMORY");
    let _ = c.pragma_update(None, "cache_size", -32000i64);
}

type Shared = Arc<Mutex<Connection>>;

fn conns() -> &'static Mutex<HashMap<String, Shared>> {
    static C: OnceLock<Mutex<HashMap<String, Shared>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

const MAX_CACHED: usize = 8;

/// Run `f` on the session's cached connection. Fails with a sentence when the file is gone.
pub fn with_conn<R>(id: &str, f: impl FnOnce(&Connection) -> Result<R, String>) -> Result<R, String> {
    let path = session_path(id)?;
    if !path.is_file() {
        evict(id);
        return Err(missing(&path));
    }
    let cached = conns().lock().unwrap_or_else(|e| e.into_inner()).get(id).cloned();
    let shared = match cached {
        Some(s) => s,
        None => {
            let c = open_path(&path, false)?;
            // A session whose scan ended without building its indexes (crash, older import).
            if super::jobs::running(id).is_none() && !has_indexes(&c) {
                let _ = create_indexes(&c);
            }
            let s = Arc::new(Mutex::new(c));
            let mut m = conns().lock().unwrap_or_else(|e| e.into_inner());
            if m.len() >= MAX_CACHED {
                if let Some(k) = m.keys().find(|k| k.as_str() != id).cloned() {
                    m.remove(&k);
                }
            }
            m.entry(id.to_string()).or_insert(s).clone()
        }
    };
    let c = shared.lock().unwrap_or_else(|e| e.into_inner());
    f(&c)
}

/// Why a session file isn't there: deleted, or on a drive that isn't connected.
pub fn missing(path: &Path) -> String {
    let in_default = sessions_dir().is_ok_and(|d| path.parent() == Some(d.as_path()));
    if !in_default && external_paths().iter().any(|x| x == path) {
        let drive: String = path.to_string_lossy().chars().take(2).collect();
        if !path.parent().is_some_and(|p| p.is_dir()) {
            return format!("This scan is saved on drive {drive}, which isn't connected. Connect that drive and try again.");
        }
    }
    GONE.into()
}

/// Drop the cached connection (before deleting or replacing the file).
pub fn evict(id: &str) {
    let s = conns().lock().unwrap_or_else(|e| e.into_inner()).remove(id);
    drop(s);
}

// ----------------------------------------------------------------------------------- meta

pub fn meta_set<T: ToSql>(c: &Connection, key: &str, v: T) -> Result<(), String> {
    c.execute("INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value", rusqlite::params![key, v])
        .map(|_| ())
        .map_err(|_| WRITE_FAILED.to_string())
}

pub fn meta_get<T: FromSql>(c: &Connection, key: &str) -> Option<T> {
    c.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get::<_, Option<T>>(0)).optional().ok().flatten().flatten()
}

pub fn meta_json<T: serde::de::DeserializeOwned>(c: &Connection, key: &str) -> Option<T> {
    meta_get::<String>(c, key).and_then(|s| serde_json::from_str(&s).ok())
}

pub fn json_value<T: serde::Serialize>(v: &T) -> Value {
    Value::Text(serde_json::to_string(v).unwrap_or_else(|_| "null".into()))
}

pub fn meta_set_json<T: serde::Serialize>(c: &Connection, key: &str, v: &T) -> Result<(), String> {
    meta_set(c, key, json_value(v))
}

// ------------------------------------------------------------------------------ generations

fn gens() -> &'static Mutex<HashMap<String, u64>> {
    static G: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    G.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Changes whenever this process changed the session's files (inserts, updates); keys caches.
pub fn gen(id: &str) -> u64 {
    *gens().lock().unwrap_or_else(|e| e.into_inner()).get(id).unwrap_or(&0)
}

pub fn bump(id: &str) {
    *gens().lock().unwrap_or_else(|e| e.into_inner()).entry(id.to_string()).or_insert(0) += 1;
}

// ------------------------------------------------------------------------------- processes

/// This process's creation time (FILETIME ticks), stored with the pid to tell pid reuse apart.
pub fn process_started(pid: u32) -> Option<i64> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut c: FILETIME = std::mem::zeroed();
        let mut e: FILETIME = std::mem::zeroed();
        let mut k: FILETIME = std::mem::zeroed();
        let mut u: FILETIME = std::mem::zeroed();
        let ok = GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u);
        CloseHandle(h);
        (ok != 0).then(|| (((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64) as i64)
    }
}

/// Is process `pid` (started at `started`, if known) still running?
pub fn process_alive(pid: u32, started: Option<i64>) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ACCESS_DENIED, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    if pid == 0 {
        return false;
    }
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            // Exists but belongs to someone we can't query (e.g. an elevated copy of MAX).
            return GetLastError() == ERROR_ACCESS_DENIED;
        }
        let mut code = 0u32;
        let ok = GetExitCodeProcess(h, &mut code);
        CloseHandle(h);
        if ok == 0 || code != STILL_ACTIVE as u32 {
            return false;
        }
    }
    match (started, process_started(pid)) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    }
}

pub fn db_err<E>(_: E) -> String {
    DAMAGED.to_string()
}
