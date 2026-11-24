//! The copy-out loop, independent of Tauri and the session store so it can be tested with
//! in-memory sources: stream each file through `fileread::FileReader` into `<name>.maxpart` while
//! hashing, rename, set its dates, verify, validate, repair, skip duplicates. One file's failure
//! never stops the job (a full destination does).

use super::names::{io_path, part_path, repaired_name, target_dir, unique_path};
use crate::content::Validation;
use crate::device::source::Source;
use crate::fileread::FileReader;
use crate::model::{safe_file_name, Condition, FoundFile};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::os::windows::fs::{FileTimesExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

const BLOCK: usize = 4 << 20;
/// Files up to this size are validated (and possibly repaired) in memory.
pub const VALIDATE_MAX: u64 = 64 << 20;
const FAT_LIMIT: u64 = 0xFFFF_FFFF;
const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
const EMIT_EVERY: Duration = Duration::from_millis(250);
pub const DISK_FULL: &str = "The destination drive is full. Free up space or pick another drive, then recover the rest.";
pub const LINK_INSIDE: &str = "A folder inside the destination is a link to another place, so MAX stopped rather than write somewhere it didn't check. Pick another destination folder.";

/// True when `p` is a junction, symbolic link or mount point (a name-surrogate reparse point).
/// Cloud placeholders (OneDrive) are reparse points too but not links, so they pass. Anything
/// that can't be inspected counts as a link (fail closed).
fn is_link(p: &Path) -> bool {
    use windows_sys::Win32::Storage::FileSystem::{FindClose, FindFirstFileW, FILE_ATTRIBUTE_REPARSE_POINT, WIN32_FIND_DATAW};
    let w = crate::util::wide(&io_path(p).to_string_lossy());
    let mut fd: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    let h = unsafe { FindFirstFileW(w.as_ptr(), &mut fd) };
    if h == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE || h.is_null() {
        return true;
    }
    unsafe { FindClose(h) };
    // IsReparseTagNameSurrogate: bit 29 of the tag (dwReserved0 for a reparse point).
    fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 && fd.dwReserved0 & 0x2000_0000 != 0
}

/// Check that no folder between `dest` (exclusive) and `dir` (inclusive) is a link, so a folder
/// MAX creates (or finds) under the checked destination can't redirect writes to another drive.
/// `checked` remembers folders already verified in this job.
pub fn check_no_links(dest: &Path, dir: &Path, checked: &mut HashSet<PathBuf>) -> Result<(), String> {
    let mut chain = Vec::new();
    let mut cur = Some(dir);
    while let Some(d) = cur {
        if d == dest || !d.starts_with(dest) || checked.contains(d) {
            break;
        }
        if is_link(d) {
            return Err(LINK_INSIDE.to_string());
        }
        chain.push(d.to_path_buf());
        cur = d.parent();
    }
    checked.extend(chain);
    Ok(())
}

#[derive(Clone, Debug)]
pub struct EngineOpts {
    pub keep_folders: bool,
    pub skip_duplicates: bool,
    pub verify: bool,
    pub repair: bool,
    /// The destination is FAT12/16/32 (4 GB file limit).
    pub fat_dest: bool,
}

impl Default for EngineOpts {
    fn default() -> Self {
        EngineOpts { keep_folders: true, skip_duplicates: true, verify: true, repair: true, fat_dest: false }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultKind {
    Recovered,
    Partial,
    Repaired,
    Failed,
    Duplicate,
}

impl ResultKind {
    pub fn label(self) -> &'static str {
        match self {
            ResultKind::Recovered => "recovered",
            ResultKind::Partial => "partial",
            ResultKind::Repaired => "repaired",
            ResultKind::Failed => "failed",
            ResultKind::Duplicate => "duplicate skipped",
        }
    }
}

#[derive(Clone, Debug)]
pub struct FileResult {
    pub id: i64,
    pub name: String,
    pub folder: String,
    pub size: u64,
    pub type_id: String,
    pub condition: Condition,
    pub note: String,
    pub result: ResultKind,
    pub path: Option<PathBuf>,
    pub repaired_path: Option<PathBuf>,
    pub hash: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Outcome {
    pub results: Vec<FileResult>,
    pub recovered: u64,
    pub partial: u64,
    pub failed: u64,
    pub repaired: u64,
    pub skipped_duplicates: u64,
    /// Bytes written (recovered files, not repaired copies).
    pub bytes: u64,
    /// "name: sentence" per failure.
    pub errors: Vec<String>,
    pub cancelled: bool,
    /// Set when the job stopped early for a reason that affects every file (destination full).
    pub stopped: Option<String>,
    /// `<dest>\<label>`.
    pub base: PathBuf,
}

#[derive(Clone, Debug, Default)]
pub struct Progress {
    pub files_done: u64,
    pub files_total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub current: String,
    pub bytes_per_sec: f64,
    pub eta_seconds: Option<f64>,
}

/// Replaceable collaborators (tests inject their own).
pub struct Hooks<'a> {
    pub validate: &'a dyn Fn(&str, &[u8]) -> Validation,
    pub repair: &'a dyn Fn(&str, &[u8]) -> Option<Vec<u8>>,
    /// BLAKE3 hex already known for a file (from the store).
    pub known_hash: &'a dyn Fn(i64) -> Option<String>,
    /// Called with a freshly computed hash for a file that had none.
    pub on_hash: &'a dyn Fn(i64, &str),
    /// Tests: runs after a file is written and before it is verified.
    pub after_write: Option<&'a dyn Fn(&Path)>,
}

fn no_hash(_: i64) -> Option<String> {
    None
}
fn ignore_hash(_: i64, _: &str) {}

impl Default for Hooks<'static> {
    fn default() -> Self {
        Hooks { validate: &crate::content::validate, repair: &crate::content::repair, known_hash: &no_hash, on_hash: &ignore_hash, after_write: None }
    }
}

struct Ticker<'a> {
    p: Progress,
    last: Instant,
    last_bytes: u64,
    emit: &'a mut dyn FnMut(&Progress),
}

impl Ticker<'_> {
    fn tick(&mut self, force: bool) {
        let dt = self.last.elapsed();
        if !force && dt < EMIT_EVERY {
            return;
        }
        let secs = dt.as_secs_f64();
        if secs > 0.0 {
            let inst = self.p.bytes_done.saturating_sub(self.last_bytes) as f64 / secs;
            self.p.bytes_per_sec = if self.p.bytes_per_sec == 0.0 { inst } else { self.p.bytes_per_sec * 0.7 + inst * 0.3 };
        }
        self.p.eta_seconds = (self.p.bytes_per_sec > 1.0).then(|| self.p.bytes_total.saturating_sub(self.p.bytes_done) as f64 / self.p.bytes_per_sec);
        self.last = Instant::now();
        self.last_bytes = self.p.bytes_done;
        (self.emit)(&self.p);
    }
}

fn ms_to_time(ms: i64) -> SystemTime {
    if ms >= 0 {
        SystemTime::UNIX_EPOCH + Duration::from_millis(ms as u64)
    } else {
        SystemTime::UNIX_EPOCH - Duration::from_millis(ms.unsigned_abs())
    }
}

/// Set created / modified / accessed from the found file (handle opened with FILE_WRITE_ATTRIBUTES).
pub fn set_times(p: &Path, f: &FoundFile) -> std::io::Result<()> {
    let mut t = std::fs::FileTimes::new();
    let mut any = false;
    if let Some(m) = f.modified {
        t = t.set_modified(ms_to_time(m));
        any = true;
    }
    if let Some(a) = f.accessed.or(f.modified) {
        t = t.set_accessed(ms_to_time(a));
        any = true;
    }
    if let Some(c) = f.created {
        t = t.set_created(ms_to_time(c));
        any = true;
    }
    if !any {
        return Ok(());
    }
    let h = std::fs::OpenOptions::new().access_mode(FILE_WRITE_ATTRIBUTES).open(io_path(p))?;
    h.set_times(t)
}

/// Rename without replacing anything (MoveFileExW without MOVEFILE_REPLACE_EXISTING).
fn rename_no_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::MoveFileExW;
    let a = crate::util::wide(&io_path(from).to_string_lossy());
    let b = crate::util::wide(&io_path(to).to_string_lossy());
    if unsafe { MoveFileExW(a.as_ptr(), b.as_ptr(), 0) } != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn write_error(e: &std::io::Error) -> (String, bool) {
    match e.raw_os_error() {
        Some(39) | Some(112) => (DISK_FULL.to_string(), true),
        Some(5) => ("Windows didn't allow writing to the destination folder. Pick another folder.".into(), false),
        Some(223) => ("It's larger than 4 GB, which a FAT32 drive can't hold. Recover it to an NTFS or exFAT drive.".into(), false),
        _ => (format!("Windows couldn't write it to the destination ({e})."), false),
    }
}

pub fn hash_file(p: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(io_path(p))?;
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; BLOCK];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().to_hex().to_string())
}

enum CopyEnd {
    Done { hash: String, bad: bool, written: u64, kept: Option<Vec<u8>> },
    Cancelled,
    Failed(String, bool),
}

fn copy_out(src: &Option<Source>, f: &FoundFile, part: &Path, keep: bool, cancel: &AtomicBool, tk: &mut Ticker) -> CopyEnd {
    let mut out = match std::fs::OpenOptions::new().write(true).create_new(true).open(io_path(part)) {
        Ok(o) => o,
        Err(e) => {
            let (m, full) = write_error(&e);
            return CopyEnd::Failed(m, full);
        }
    };
    let mut reader = FileReader::new(src.clone(), f.clone());
    let mut hasher = blake3::Hasher::new();
    let mut kept = keep.then(|| Vec::with_capacity(f.size as usize));
    let mut buf = vec![0u8; BLOCK.min(f.size.max(1) as usize)];
    let mut written = 0u64;
    let end = loop {
        if cancel.load(Ordering::Relaxed) {
            break Some(CopyEnd::Cancelled);
        }
        let n = match reader.read(&mut buf) {
            Ok(0) => break None,
            Ok(n) => n,
            Err(e) => break Some(CopyEnd::Failed(e.to_string(), false)),
        };
        hasher.update(&buf[..n]);
        if let Err(e) = out.write_all(&buf[..n]) {
            let (m, full) = write_error(&e);
            break Some(CopyEnd::Failed(m, full));
        }
        if let Some(k) = kept.as_mut() {
            k.extend_from_slice(&buf[..n]);
        }
        written += n as u64;
        tk.p.bytes_done += n as u64;
        tk.tick(false);
    };
    let flushed = out.flush().and_then(|_| out.sync_all());
    drop(out);
    if let Some(e) = end {
        let _ = std::fs::remove_file(io_path(part));
        return e;
    }
    if let Err(e) = flushed {
        let _ = std::fs::remove_file(io_path(part));
        let (m, full) = write_error(&e);
        return CopyEnd::Failed(m, full);
    }
    CopyEnd::Done { hash: hasher.finalize().to_hex().to_string(), bad: reader.hit_bad_sectors, written, kept }
}

/// Write `data` as a new file next to `beside`, named "<name> (repaired).<ext>".
fn write_repaired(dir: &Path, name: &str, data: &[u8], f: &FoundFile, taken: &mut HashSet<String>) -> std::io::Result<PathBuf> {
    let target = unique_path(dir, &repaired_name(name), taken);
    let part = part_path(&target);
    {
        let mut o = std::fs::OpenOptions::new().write(true).create_new(true).open(io_path(&part))?;
        o.write_all(data)?;
        o.sync_all()?;
    }
    if let Err(e) = rename_no_replace(&part, &target) {
        let _ = std::fs::remove_file(io_path(&part));
        return Err(e);
    }
    taken.insert(target.to_string_lossy().to_lowercase());
    let _ = set_times(&target, f);
    Ok(target)
}

/// Recover `ids` (loaded one at a time through `load`) into `<dest>\<label>\…`.
#[allow(clippy::too_many_arguments)]
pub fn recover_files(
    src: Option<Source>,
    ids: &[i64],
    load: &dyn Fn(i64) -> Result<FoundFile, String>,
    bytes_total: u64,
    dest: &Path,
    label: &str,
    opts: &EngineOpts,
    cancel: &AtomicBool,
    hooks: &Hooks,
    emit: &mut dyn FnMut(&Progress),
) -> Outcome {
    let base = dest.join(safe_file_name(label));
    let mut out = Outcome { base: base.clone(), ..Default::default() };
    let mut tk = Ticker {
        p: Progress { files_total: ids.len() as u64, bytes_total, ..Default::default() },
        last: Instant::now(),
        last_bytes: 0,
        emit,
    };
    tk.tick(true);
    let mut seen: HashMap<String, PathBuf> = HashMap::new();
    let mut taken: HashSet<String> = HashSet::new();
    let mut checked: HashSet<PathBuf> = HashSet::new();

    for &id in ids {
        if cancel.load(Ordering::Relaxed) {
            out.cancelled = true;
            break;
        }
        let f = match load(id) {
            Ok(f) => f,
            Err(e) => {
                out.failed += 1;
                out.errors.push(format!("File {id}: {e}"));
                out.results.push(FileResult {
                    id,
                    name: format!("File {id}"),
                    folder: String::new(),
                    size: 0,
                    type_id: String::new(),
                    condition: Condition::Unknown,
                    note: String::new(),
                    result: ResultKind::Failed,
                    path: None,
                    repaired_path: None,
                    hash: None,
                    notes: vec![e],
                });
                tk.p.files_done += 1;
                continue;
            }
        };
        tk.p.current = f.name.clone();
        let mut r = FileResult {
            id,
            name: f.name.clone(),
            folder: f.folder.clone(),
            size: f.size,
            type_id: f.type_id.clone(),
            condition: f.condition,
            note: f.note.clone(),
            result: ResultKind::Failed,
            path: None,
            repaired_path: None,
            hash: None,
            notes: Vec::new(),
        };
        let bytes_before = tk.p.bytes_done;
        let stop = recover_one(&src, &f, &mut r, dest, label, opts, cancel, hooks, &mut seen, &mut taken, &mut checked, &mut tk);
        // Keep the byte counter honest for files that were skipped or stopped early.
        tk.p.bytes_done = bytes_before + f.size;
        tk.p.files_done += 1;
        match stop {
            Stop::Cancelled => {
                out.cancelled = true;
                break;
            }
            Stop::Full(m) => {
                out.failed += 1;
                out.errors.push(format!("{}: {m}", f.name));
                r.notes.push(m.clone());
                out.results.push(r);
                out.stopped = Some(m);
                break;
            }
            Stop::No => {}
        }
        match r.result {
            ResultKind::Recovered => out.recovered += 1,
            ResultKind::Partial => out.partial += 1,
            ResultKind::Repaired => out.repaired += 1,
            ResultKind::Duplicate => out.skipped_duplicates += 1,
            ResultKind::Failed => {
                out.failed += 1;
                out.errors.push(format!("{}: {}", f.name, r.notes.last().cloned().unwrap_or_default()));
            }
        }
        if matches!(r.result, ResultKind::Recovered | ResultKind::Partial | ResultKind::Repaired) {
            out.bytes += f.size;
        }
        out.results.push(r);
        tk.tick(false);
    }
    tk.tick(true);
    out
}

enum Stop {
    No,
    Cancelled,
    Full(String),
}

#[allow(clippy::too_many_arguments)]
fn recover_one(
    src: &Option<Source>,
    f: &FoundFile,
    r: &mut FileResult,
    dest: &Path,
    label: &str,
    opts: &EngineOpts,
    cancel: &AtomicBool,
    hooks: &Hooks,
    seen: &mut HashMap<String, PathBuf>,
    taken: &mut HashSet<String>,
    checked: &mut HashSet<PathBuf>,
    tk: &mut Ticker,
) -> Stop {
    let fail = |r: &mut FileResult, m: String| {
        r.result = ResultKind::Failed;
        r.notes.push(m);
        Stop::No
    };
    if opts.fat_dest && f.size > FAT_LIMIT {
        return fail(r, "It's larger than 4 GB, which a FAT32 drive can't hold. Recover it to an NTFS or exFAT drive.".into());
    }
    let known = (hooks.known_hash)(r.id);
    if opts.skip_duplicates {
        if let Some(p) = known.as_ref().and_then(|h| seen.get(h)) {
            r.result = ResultKind::Duplicate;
            r.hash = known.clone();
            r.notes.push(format!("Same content as {}.", p.display()));
            return Stop::No;
        }
    }
    let dir = target_dir(dest, label, &f.folder, opts.keep_folders);
    // Folders that already exist on the way are checked before anything is created through them,
    // the new ones right after they are created.
    let mut existing = dir.as_path();
    while existing != dest && !super::names::exists(existing) {
        match existing.parent() {
            Some(p) => existing = p,
            None => break,
        }
    }
    if let Err(m) = check_no_links(dest, existing, checked) {
        return Stop::Full(m);
    }
    if let Err(e) = std::fs::create_dir_all(io_path(&dir)) {
        let (m, full) = write_error(&e);
        return if full { Stop::Full(m) } else { fail(r, format!("MAX couldn't create the folder {} ({e}).", dir.display())) };
    }
    if let Err(m) = check_no_links(dest, &dir, checked) {
        return Stop::Full(m);
    }
    let name = safe_file_name(&f.name);
    let target = unique_path(&dir, &name, taken);
    taken.insert(target.to_string_lossy().to_lowercase());
    let part = part_path(&target);
    let keep = f.size <= VALIDATE_MAX && !f.type_id.is_empty();
    let (hash, bad, written, kept) = match copy_out(src, f, &part, keep, cancel, tk) {
        CopyEnd::Done { hash, bad, written, kept } => (hash, bad, written, kept),
        CopyEnd::Cancelled => return Stop::Cancelled,
        CopyEnd::Failed(m, true) => return Stop::Full(m),
        CopyEnd::Failed(m, false) => return fail(r, m),
    };
    r.hash = Some(hash.clone());
    if known.is_none() {
        (hooks.on_hash)(r.id, &hash);
    }
    if opts.skip_duplicates {
        if let Some(p) = seen.get(&hash) {
            let _ = std::fs::remove_file(io_path(&part));
            r.result = ResultKind::Duplicate;
            r.notes.push(format!("Same content as {}.", p.display()));
            return Stop::No;
        }
    }
    if let Err(e) = rename_no_replace(&part, &target) {
        let _ = std::fs::remove_file(io_path(&part));
        return fail(r, format!("Windows couldn't finish writing it ({e})."));
    }
    r.path = Some(target.clone());
    if set_times(&target, f).is_err() {
        r.notes.push("Its dates couldn't be set.".into());
    }
    if let Some(cb) = hooks.after_write {
        cb(&target);
    }
    if opts.verify {
        match hash_file(&target) {
            Ok(h) if h == hash => {}
            Ok(_) => return fail(r, "The written copy doesn't match what was read from the drive. The destination drive may be faulty; try another one.".into()),
            Err(e) => return fail(r, format!("MAX couldn't read the written copy back to check it ({e}).")),
        }
    }
    seen.insert(hash, target.clone());

    let mut result = ResultKind::Recovered;
    if bad {
        result = ResultKind::Partial;
        r.notes.push("Some sectors couldn't be read; those parts are zeros.".into());
    }
    if written < f.size {
        result = ResultKind::Partial;
        r.notes.push(format!("Only {} of {} bytes could be found.", written, f.size));
    }
    let mut validated_ok = false;
    if let Some(data) = kept.as_deref() {
        let v = (hooks.validate)(&f.type_id, data);
        match v.condition {
            Condition::Partial => {
                result = ResultKind::Partial;
                if !v.note.is_empty() {
                    r.notes.push(v.note.clone());
                }
                if opts.repair {
                    if let Some(fixed) = (hooks.repair)(&f.type_id, data) {
                        match write_repaired(&dir, target.file_name().and_then(|n| n.to_str()).unwrap_or(&name), &fixed, f, taken) {
                            Ok(p) => {
                                result = ResultKind::Repaired;
                                r.notes.push(format!("A repaired copy was saved as {}.", p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()));
                                r.repaired_path = Some(p);
                            }
                            Err(e) => r.notes.push(format!("A repaired copy couldn't be written ({e}).")),
                        }
                    }
                }
            }
            Condition::Excellent | Condition::Good => validated_ok = true,
            Condition::Unknown => {}
        }
    }
    if result == ResultKind::Recovered && f.condition == Condition::Partial && !validated_ok {
        result = ResultKind::Partial;
    }
    r.result = result;
    Stop::No
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::device::source::MemSource;
    use crate::model::{Extent, SPARSE};
    use std::sync::Arc;

    pub(crate) struct TempDir(pub PathBuf);
    impl TempDir {
        pub fn new(tag: &str) -> TempDir {
            let n = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos();
            let p = std::env::temp_dir().join(format!("max-rec-{tag}-{}-{n}", std::process::id()));
            assert!(p.starts_with(std::env::temp_dir()));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            assert!(self.0.starts_with(std::env::temp_dir()));
            let _ = std::fs::remove_dir_all(io_path(&self.0));
        }
    }

    fn mem() -> (Source, Vec<u8>) {
        let data: Vec<u8> = (0..65536u32).map(|i| (i * 7 % 251) as u8).collect();
        (Arc::new(MemSource::new(data.clone())), data)
    }

    fn run(src: Option<Source>, files: Vec<FoundFile>, dest: &Path, opts: &EngineOpts, hooks: &Hooks) -> Outcome {
        let total: u64 = files.iter().map(|f| f.size).sum();
        let ids: Vec<i64> = (1..=files.len() as i64).collect();
        let load = |id: i64| Ok(files[(id - 1) as usize].clone());
        let cancel = AtomicBool::new(false);
        let mut ticks = 0;
        let o = recover_files(src, &ids, &load, total, dest, "Session 1", opts, &cancel, hooks, &mut |_| ticks += 1);
        assert!(ticks >= 2);
        o
    }

    fn no_check(_: &str, _: &[u8]) -> Validation {
        Validation { condition: Condition::Unknown, note: String::new(), complete: true }
    }
    fn no_repair(_: &str, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn hooks_plain() -> Hooks<'static> {
        Hooks { validate: &no_check, repair: &no_repair, ..Hooks::default() }
    }

    #[test]
    fn recovers_fragmented_sparse_resident_and_live_files() {
        let t = TempDir::new("kinds");
        let (src, data) = mem();
        let live = t.0.join("live-source.bin");
        std::fs::write(&live, b"from the recycle bin").unwrap();
        let frag = FoundFile {
            name: "frag.jpg".into(),
            folder: "\\Users\\Ann\\Pictures".into(),
            size: 5000,
            type_id: "jpg".into(),
            extents: vec![Extent { offset: 8192, len: 4096 }, Extent { offset: 1024, len: 4096 }],
            created: Some(1_600_000_000_000),
            modified: Some(1_650_000_000_000),
            accessed: Some(1_660_000_000_000),
            ..Default::default()
        };
        let sparse = FoundFile {
            name: "sparse.bin".into(),
            folder: "\\Data".into(),
            size: 3000,
            extents: vec![Extent { offset: 0, len: 1024 }, Extent { offset: SPARSE, len: 1024 }, Extent { offset: 2048, len: 1024 }],
            ..Default::default()
        };
        let resident = FoundFile { name: "tiny.txt".into(), folder: "\\Data".into(), size: 5, resident: Some(b"hello".to_vec()), ..Default::default() };
        let livef = FoundFile { name: "bin.txt".into(), folder: "\\Data".into(), size: 20, live_path: Some(live.to_string_lossy().into()), ..Default::default() };
        let o = run(Some(src), vec![frag.clone(), sparse, resident, livef], &t.0, &EngineOpts::default(), &hooks_plain());
        assert_eq!((o.recovered, o.failed, o.partial), (4, 0, 0), "{:?}", o.errors);
        assert_eq!(o.bytes, 8025);
        let base = t.0.join("Session 1");
        let got = std::fs::read(base.join("Users\\Ann\\Pictures\\frag.jpg")).unwrap();
        let mut want = data[8192..8192 + 4096].to_vec();
        want.extend_from_slice(&data[1024..1024 + 904]);
        assert_eq!(got, want);
        let sp = std::fs::read(base.join("Data\\sparse.bin")).unwrap();
        assert_eq!(&sp[..1024], &data[..1024]);
        assert!(sp[1024..2048].iter().all(|&b| b == 0));
        assert_eq!(&sp[2048..], &data[2048..2048 + 952]);
        assert_eq!(std::fs::read(base.join("Data\\tiny.txt")).unwrap(), b"hello");
        assert_eq!(std::fs::read(base.join("Data\\bin.txt")).unwrap(), b"from the recycle bin");
        // Dates.
        let md = std::fs::metadata(base.join("Users\\Ann\\Pictures\\frag.jpg")).unwrap();
        let ms = |t: SystemTime| t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as i64;
        assert_eq!(ms(md.modified().unwrap()), 1_650_000_000_000);
        assert_eq!(ms(md.created().unwrap()), 1_600_000_000_000);
        // Hashes recorded, no .maxpart left behind.
        assert_eq!(o.results[0].hash.as_deref(), Some(blake3::hash(&want).to_hex().as_str()));
        let leftovers = walk(&t.0).into_iter().filter(|p| p.to_string_lossy().ends_with(".maxpart")).count();
        assert_eq!(leftovers, 0);
    }

    fn walk(p: &Path) -> Vec<PathBuf> {
        let mut v = Vec::new();
        let mut st = vec![p.to_path_buf()];
        while let Some(d) = st.pop() {
            for e in std::fs::read_dir(io_path(&d)).unwrap().flatten() {
                let p = d.join(e.file_name());
                if e.file_type().unwrap().is_dir() {
                    st.push(p);
                } else {
                    v.push(p);
                }
            }
        }
        v
    }

    #[test]
    fn clashes_unsafe_names_and_flat_mode() {
        let t = TempDir::new("names");
        let f = |name: &str, folder: &str, body: &[u8]| FoundFile { name: name.into(), folder: folder.into(), size: body.len() as u64, resident: Some(body.to_vec()), ..Default::default() };
        let files = vec![
            f("a.txt", "\\x", b"1"),
            f("a.txt", "\\x", b"2"),
            f("A.TXT", "\\x", b"3"),
            f("con.txt", "\\..\\..\\evil", b"4"),
            f("b?:*.txt", "\\x", b"5"),
            f("", "\\x", b"6"),
        ];
        let o = run(None, files.clone(), &t.0, &EngineOpts { skip_duplicates: false, ..Default::default() }, &hooks_plain());
        assert_eq!(o.recovered, 6, "{:?}", o.errors);
        let b = t.0.join("Session 1");
        assert_eq!(std::fs::read(b.join("x\\a.txt")).unwrap(), b"1");
        assert_eq!(std::fs::read(b.join("x\\a (2).txt")).unwrap(), b"2");
        assert_eq!(std::fs::read(b.join("x\\A (3).TXT")).unwrap(), b"3");
        assert_eq!(std::fs::read(b.join("unnamed\\unnamed\\evil\\_con.txt")).unwrap(), b"4");
        assert_eq!(std::fs::read(b.join("x\\b___.txt")).unwrap(), b"5");
        assert_eq!(std::fs::read(b.join("x\\unnamed")).unwrap(), b"6");
        for p in walk(&t.0) {
            assert!(p.starts_with(&t.0));
        }
        // Flat mode, second run into the same destination: no overwrite.
        let o2 = run(None, files[..2].to_vec(), &t.0, &EngineOpts { keep_folders: false, skip_duplicates: false, ..Default::default() }, &hooks_plain());
        assert_eq!(o2.recovered, 2);
        assert_eq!(std::fs::read(b.join("a.txt")).unwrap(), b"1");
        assert_eq!(std::fs::read(b.join("a (2).txt")).unwrap(), b"2");
        assert_eq!(std::fs::read(b.join("x\\a.txt")).unwrap(), b"1");
    }

    /// A junction under the destination (here: the session folder itself) stops the job before
    /// anything is written through it; ordinary folders (and the long-path test) pass.
    #[test]
    fn links_under_the_destination_stop_the_job() {
        let t = TempDir::new("links");
        let elsewhere = TempDir::new("links-target");
        assert!(crate::device::win::tests::make_junction(&t.0.join("Session 1"), &elsewhere.0), "mklink /J failed");
        let f = FoundFile { name: "a.txt".into(), folder: "\\x".into(), size: 2, resident: Some(b"hi".to_vec()), ..Default::default() };
        let o = run(None, vec![f.clone(), f], &t.0, &EngineOpts::default(), &hooks_plain());
        let _ = std::fs::remove_dir(t.0.join("Session 1"));
        assert_eq!(o.stopped.as_deref(), Some(LINK_INSIDE), "{o:?}");
        assert_eq!(o.recovered, 0);
        assert_eq!(std::fs::read_dir(&elsewhere.0).unwrap().count(), 0, "nothing is created through the link");
        // A plain folder tree is fine, and checked folders are remembered.
        let mut checked = HashSet::new();
        let d = t.0.join("ok").join("a");
        std::fs::create_dir_all(&d).unwrap();
        assert!(check_no_links(&t.0, &d, &mut checked).is_ok());
        assert_eq!(checked.len(), 2);
        assert!(check_no_links(&t.0, &t.0, &mut checked).is_ok());
    }

    #[test]
    fn long_paths_are_written() {
        let t = TempDir::new("long");
        let deep = format!("\\{}\\{}\\{}", "d".repeat(120), "e".repeat(120), "f".repeat(120));
        let name = format!("{}.txt", "n".repeat(150));
        let file = FoundFile { name: name.clone(), folder: deep.clone(), size: 3, resident: Some(b"abc".to_vec()), modified: Some(1_500_000_000_000), ..Default::default() };
        let o = run(None, vec![file], &t.0, &EngineOpts::default(), &hooks_plain());
        assert_eq!(o.recovered, 1, "{:?}", o.errors);
        let p = o.results[0].path.clone().unwrap();
        assert!(p.to_string_lossy().len() > 400);
        assert_eq!(std::fs::read(io_path(&p)).unwrap(), b"abc");
    }

    #[test]
    fn duplicates_are_skipped() {
        let t = TempDir::new("dupes");
        let f = |name: &str, body: &[u8]| FoundFile { name: name.into(), size: body.len() as u64, resident: Some(body.to_vec()), ..Default::default() };
        let files = vec![f("a.bin", b"same"), f("b.bin", b"same"), f("c.bin", b"other"), f("d.bin", b"same")];
        // d's hash is "known" from the store: skipped without writing.
        let same = blake3::hash(b"same").to_hex().to_string();
        let known = move |id: i64| (id == 4).then(|| same.clone());
        let stored = std::sync::Mutex::new(Vec::new());
        let on_hash = |id: i64, h: &str| stored.lock().unwrap().push((id, h.to_string()));
        let hooks = Hooks { known_hash: &known, on_hash: &on_hash, ..hooks_plain() };
        let o = run(None, files, &t.0, &EngineOpts::default(), &hooks);
        assert_eq!((o.recovered, o.skipped_duplicates), (2, 2));
        assert_eq!(o.bytes, 9);
        let b = t.0.join("Session 1");
        assert!(b.join("a.bin").exists() && !b.join("b.bin").exists() && b.join("c.bin").exists() && !b.join("d.bin").exists());
        assert!(!b.join("b.bin.maxpart").exists());
        assert_eq!(stored.lock().unwrap().len(), 3);
    }

    #[test]
    fn verify_catches_a_mismatch() {
        let t = TempDir::new("verify");
        let file = FoundFile { name: "a.bin".into(), size: 4, resident: Some(b"good".to_vec()), ..Default::default() };
        let tamper = |p: &Path| std::fs::write(io_path(p), b"evil").unwrap();
        let hooks = Hooks { after_write: Some(&tamper), ..hooks_plain() };
        let o = run(None, vec![file.clone()], &t.0, &EngineOpts::default(), &hooks);
        assert_eq!((o.recovered, o.failed), (0, 1));
        assert!(o.errors[0].contains("doesn't match"));
        // Without verify the tampering goes unnoticed (proves the check is what caught it).
        let o = run(None, vec![file], &t.0, &EngineOpts { verify: false, skip_duplicates: false, ..Default::default() }, &hooks);
        assert_eq!(o.recovered, 1);
    }

    #[test]
    fn partial_files_get_a_repaired_copy() {
        let t = TempDir::new("repair");
        let file = FoundFile { name: "broken.jpg".into(), type_id: "jpg".into(), size: 4, resident: Some(b"\xFF\xD8\xFF\x00".to_vec()), ..Default::default() };
        let val = |_: &str, _: &[u8]| Validation { condition: Condition::Partial, note: "The image ends early.".into(), complete: false };
        let rep = |_: &str, d: &[u8]| {
            let mut v = d.to_vec();
            v.extend_from_slice(b"\xFF\xD9");
            Some(v)
        };
        let hooks = Hooks { validate: &val, repair: &rep, ..Hooks::default() };
        let o = run(None, vec![file.clone()], &t.0, &EngineOpts::default(), &hooks);
        assert_eq!(o.repaired, 1);
        let b = t.0.join("Session 1");
        assert_eq!(std::fs::read(b.join("broken.jpg")).unwrap(), b"\xFF\xD8\xFF\x00");
        assert_eq!(std::fs::read(b.join("broken (repaired).jpg")).unwrap(), b"\xFF\xD8\xFF\x00\xFF\xD9");
        assert!(o.results[0].notes.iter().any(|n| n.contains("ends early")));
        // Not repairable -> partial; repair off -> partial.
        let none = |_: &str, _: &[u8]| None;
        let hooks = Hooks { validate: &val, repair: &none, ..Hooks::default() };
        let o = run(None, vec![file.clone()], &t.0, &EngineOpts { skip_duplicates: false, ..Default::default() }, &hooks);
        assert_eq!((o.partial, o.repaired), (1, 0));
        // The real content stubs/implementations must not panic.
        let o = run(None, vec![file], &t.0, &EngineOpts { skip_duplicates: false, ..Default::default() }, &Hooks::default());
        assert_eq!(o.failed, 0);
    }

    #[test]
    fn bad_sectors_and_failures_are_reported_honestly() {
        let t = TempDir::new("bad");
        let data: Vec<u8> = vec![7u8; 8192];
        let mut m = MemSource::new(data);
        m.bad = vec![(1024, 1536)];
        let src: Source = Arc::new(m);
        let ok = FoundFile { name: "bad.bin".into(), size: 4096, extents: vec![Extent { offset: 0, len: 4096 }], ..Default::default() };
        let short = FoundFile { name: "short.bin".into(), size: 4096, extents: vec![Extent { offset: 4096, len: 1000 }], ..Default::default() };
        let gone = FoundFile { name: "gone.bin".into(), size: 10, live_path: Some(t.0.join("nope").to_string_lossy().into()), ..Default::default() };
        let o = run(Some(src), vec![ok, gone, short], &t.0, &EngineOpts::default(), &hooks_plain());
        assert_eq!((o.partial, o.failed), (2, 1), "{:?}", o.results);
        let got = std::fs::read(t.0.join("Session 1\\bad.bin")).unwrap();
        assert!(got[1024..1536].iter().all(|&b| b == 0) && got[0] == 7);
        assert!(o.errors[0].starts_with("gone.bin: Windows couldn't open"));
        assert_eq!(std::fs::metadata(t.0.join("Session 1\\short.bin")).unwrap().len(), 1000);
        // No source at all: extents can't be read, one sentence each.
        let o = run(None, vec![FoundFile { name: "x".into(), size: 3, extents: vec![Extent { offset: 0, len: 3 }], ..Default::default() }], &t.0, &EngineOpts::default(), &hooks_plain());
        assert_eq!(o.failed, 1);
        assert!(o.errors[0].contains("isn't available"));
    }

    #[test]
    fn cancel_stops_and_cleans_up() {
        let t = TempDir::new("cancel");
        let file = FoundFile { name: "a".into(), size: 1, resident: Some(vec![1]), ..Default::default() };
        let cancel = AtomicBool::new(true);
        let load = |_: i64| Ok(file.clone());
        let o = recover_files(None, &[1, 2], &load, 2, &t.0, "s", &EngineOpts::default(), &cancel, &hooks_plain(), &mut |_| {});
        assert!(o.cancelled && o.results.is_empty());
    }
}
