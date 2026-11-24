//! Shared types every engine compiles against (owned by the orchestrator; see CONTRACT.md).
//!
//! The flow: a scan opens a [`BlockSource`](crate::device::source::BlockSource) read-only, the
//! scan orchestrator (`scan`) runs engines with a [`ScanCtx`], engines report [`FoundFile`]s and
//! [`MapKind`] byte ranges through it, and the store persists both into the session file.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// Sentence returned (as `Err`) by anything stopped through [`ScanCtx::check`].
pub const CANCELLED: &str = "The scan was cancelled.";

// ------------------------------------------------------------------------------------- sources

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "camelCase")]
pub enum SourceKind {
    /// A drive letter: `path` = "C".
    #[default]
    Volume,
    /// A physical disk: `path` = "0" for \\.\PhysicalDrive0.
    Disk,
    /// A disk image file: `path` = absolute file path (.img/.dd/.raw/.bin/.iso/.vhd/.vhdx).
    Image,
    /// A Volume Shadow Copy (restore point): `path` = device object,
    /// e.g. \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3
    Snapshot,
}

/// Which bytes to read. JSON: `{kind, path, offset?, length?, label?}`.
/// `offset`/`length` narrow the source to a window (a partition inside a disk or image).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct SourceRef {
    pub kind: SourceKind,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub offset: u64,
    #[serde(default)]
    pub length: Option<u64>,
    /// Display name only, never used to open anything.
    #[serde(default)]
    pub label: Option<String>,
}

// --------------------------------------------------------------------------------------- files

/// A byte range on the scan source. `offset == SPARSE` means "len bytes of zeros" (NTFS sparse run).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Extent {
    pub offset: u64,
    pub len: u64,
}
pub const SPARSE: u64 = u64::MAX;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "camelCase")]
pub enum FileStatus {
    /// Deleted, found through file-system metadata (name and folder known).
    #[default]
    Deleted,
    /// Still present in the file system (shown for RAW/damaged/formatted sources and images).
    Existing,
    /// Deleted and its folder is gone too: placed under a reconstructed "Lost folders" tree.
    Lost,
    /// Found by signature in raw sectors; no file-system record.
    Carved,
    /// Sitting in the Windows Recycle Bin (restorable through Windows).
    RecycleBin,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "camelCase")]
pub enum Origin {
    #[default]
    Ntfs,
    Fat,
    ExFat,
    Carving,
    RecycleBin,
}

/// Recovery confidence. Never shown as a percentage or a guarantee.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum Condition {
    /// Metadata and content appear intact.
    Excellent,
    /// Some uncertainty, but the content checks out (header matches / preview decodes).
    Good,
    /// Incomplete, partly overwritten, erased by TRIM, or damaged.
    Partial,
    /// Not enough evidence either way.
    #[default]
    Unknown,
}

impl Condition {
    /// Sort rank, best first.
    pub fn rank(self) -> u8 {
        match self {
            Condition::Excellent => 0,
            Condition::Good => 1,
            Condition::Unknown => 2,
            Condition::Partial => 3,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "camelCase")]
pub enum Category {
    Photo,
    Video,
    Audio,
    Document,
    Archive,
    #[default]
    Other,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Photo => "photo",
            Category::Video => "video",
            Category::Audio => "audio",
            Category::Document => "document",
            Category::Archive => "archive",
            Category::Other => "other",
        }
    }
    pub fn parse(s: &str) -> Option<Category> {
        Some(match s {
            "photo" => Category::Photo,
            "video" => Category::Video,
            "audio" => Category::Audio,
            "document" => Category::Document,
            "archive" => Category::Archive,
            "other" => Category::Other,
            _ => return None,
        })
    }
}

pub mod flags {
    /// NTFS-compressed data: stored extents are LZNT1 chunks, not plain bytes.
    pub const COMPRESSED: u32 = 1;
    /// EFS-encrypted: content can't be read without the user's key.
    pub const ENCRYPTED: u32 = 2;
    pub const SPARSE: u32 = 4;
    /// The content's signature says another type than the name's extension.
    pub const EXT_MISMATCH: u32 = 8;
    /// The name was made up (carved) or rebuilt from embedded metadata.
    pub const NAME_GUESSED: u32 = 16;
    /// The first sector reads as all zeros (typical after SSD TRIM).
    pub const ZEROED: u32 = 32;
    /// Some of its clusters now belong to another file.
    pub const OVERWRITTEN: u32 = 64;
    /// Some sectors couldn't be read (filled with zeros on recovery).
    pub const BAD_SECTORS: u32 = 128;
    /// Name/folder restored from a Recycle Bin $I record.
    pub const FROM_RECYCLE_INFO: u32 = 256;
    /// Found in a Volume Shadow Copy.
    pub const SNAPSHOT: u32 = 512;
    /// A file-system record found outside the live metadata (formatted / damaged volume).
    pub const LOOSE_RECORD: u32 = 1024;
}

/// One recoverable file, as engines report it. Stored as one row of the session's `files` table.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FoundFile {
    pub name: String,
    /// Reconstructed folder, backslash-separated, starting with "\" ("" = root).
    /// Lost: "\Lost folders\Folder 1234\…". Carved: "\Found by signature\JPEG image".
    pub folder: String,
    pub size: u64,
    pub status: FileStatus,
    pub origin: Origin,
    /// Detected type id (from the content signature when known, else from the extension), e.g. "jpg".
    pub type_id: String,
    /// Unix milliseconds.
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub accessed: Option<i64>,
    pub deleted: Option<i64>,
    /// Content location on the scan source, in file order. Sum of lens >= size.
    pub extents: Vec<Extent>,
    /// Small content stored inside the metadata (NTFS resident data).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resident: Option<Vec<u8>>,
    /// Readable through Windows (Recycle Bin items): recovery copies this path instead of extents.
    #[serde(default)]
    pub live_path: Option<String>,
    pub condition: Condition,
    /// One sentence explaining the condition ("Its clusters are free and the header matches.").
    pub note: String,
    pub fragmented: bool,
    /// Bit set of [`flags`].
    pub flags: u32,
    /// Engine-specific reference (MFT record number, directory-entry byte offset).
    pub fs_ref: Option<u64>,
    /// Extra facts: "width", "height", "camera", "taken", "title", "author", "artist", "album",
    /// "duration", "pages", "originalPath", "mftRecord", …
    #[serde(default)]
    pub meta: BTreeMap<String, String>,
}

impl FoundFile {
    pub fn ext(&self) -> String {
        match self.name.rsplit_once('.') {
            Some((stem, e)) if !stem.is_empty() && e.len() <= 8 => e.to_ascii_lowercase(),
            _ => String::new(),
        }
    }
    pub fn first_offset(&self) -> Option<u64> {
        self.extents.iter().find(|e| e.offset != SPARSE).map(|e| e.offset)
    }
}

// ------------------------------------------------------------------------------------- ranges

/// What a byte range on the source is, for the Recovery Map.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum MapKind {
    /// Read successfully (anything read at all).
    Scanned,
    /// File-system structures: boot sectors, MFT, FAT, directories, bitmaps.
    Metadata,
    /// In use by live (existing) files.
    Allocated,
    /// Content of deleted / lost / carved files: potentially recoverable.
    Recoverable,
    /// Couldn't be read.
    Bad,
}

impl MapKind {
    pub const ALL: [MapKind; 5] = [MapKind::Scanned, MapKind::Metadata, MapKind::Allocated, MapKind::Recoverable, MapKind::Bad];
    pub fn index(self) -> usize {
        match self {
            MapKind::Scanned => 0,
            MapKind::Metadata => 1,
            MapKind::Allocated => 2,
            MapKind::Recoverable => 3,
            MapKind::Bad => 4,
        }
    }
    pub fn bit(self) -> u8 {
        1 << self.index()
    }
}

/// Sorted, non-overlapping, merged half-open byte ranges.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct IntervalSet {
    pub ranges: Vec<(u64, u64)>,
}

impl IntervalSet {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
    pub fn total(&self) -> u64 {
        self.ranges.iter().map(|(s, e)| e - s).sum()
    }
    /// Add [start, end). O(log n) to find, O(n) worst case to merge.
    pub fn insert(&mut self, start: u64, end: u64) {
        if end <= start {
            return;
        }
        // First range whose end >= start (could merge/touch).
        let i = self.ranges.partition_point(|&(_, e)| e < start);
        let mut s = start;
        let mut e = end;
        let mut j = i;
        while j < self.ranges.len() && self.ranges[j].0 <= e {
            s = s.min(self.ranges[j].0);
            e = e.max(self.ranges[j].1);
            j += 1;
        }
        self.ranges.splice(i..j, std::iter::once((s, e)));
    }
    pub fn extend(&mut self, other: &IntervalSet) {
        for &(s, e) in &other.ranges {
            self.insert(s, e);
        }
    }
    pub fn contains(&self, pos: u64) -> bool {
        let i = self.ranges.partition_point(|&(_, e)| e <= pos);
        i < self.ranges.len() && self.ranges[i].0 <= pos
    }
    /// Bytes of [start, end) covered by this set.
    pub fn overlap(&self, start: u64, end: u64) -> u64 {
        if end <= start {
            return 0;
        }
        let mut i = self.ranges.partition_point(|&(_, e)| e <= start);
        let mut n = 0;
        while i < self.ranges.len() && self.ranges[i].0 < end {
            let (s, e) = self.ranges[i];
            n += e.min(end) - s.max(start);
            i += 1;
        }
        n
    }
    /// The ranges intersecting [start, end), clipped.
    pub fn clip(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut i = self.ranges.partition_point(|&(_, e)| e <= start);
        while i < self.ranges.len() && self.ranges[i].0 < end {
            let (s, e) = self.ranges[i];
            out.push((s.max(start), e.min(end)));
            i += 1;
        }
        out
    }
}

// ------------------------------------------------------------------------------------- engines

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

/// What a file-system engine recognised on a source (`probe`).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FsProbe {
    /// "NTFS" | "FAT12" | "FAT16" | "FAT32" | "exFAT"
    pub fs: String,
    pub cluster_size: u32,
    pub sector_size: u32,
    /// Bytes the file system says it spans.
    pub total_size: u64,
    pub label: String,
    pub serial: String,
    /// The primary boot sector was damaged and the backup copy was used.
    pub used_backup_boot: bool,
}

/// What an engine did, for the session summary and log.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EngineSummary {
    pub files: u64,
    pub deleted: u64,
    pub lost_folders: u64,
    /// Plain sentences for the log ("Used the backup boot sector because the first one is damaged.").
    pub notes: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScanOptions {
    /// "quick" | "deep" | "partitions"
    pub mode: String,
    /// Also list files that still exist (default: only for RAW/damaged/image/snapshot/partition sources).
    #[serde(default)]
    pub include_existing: Option<bool>,
    /// Type ids or category names to carve in deep scans; `None` = everything.
    #[serde(default)]
    pub carve_types: Option<Vec<String>>,
    /// Carve only space no live file uses (default true when a file system was recognised).
    #[serde(default)]
    pub carve_free_only: Option<bool>,
    /// Use the user's custom signatures (Settings) in deep scans. Default true.
    #[serde(default)]
    pub custom_signatures: Option<bool>,
    /// Session display name.
    #[serde(default)]
    pub label: Option<String>,
    /// Folder scan (quick scans of a volume only): keep only files whose original folder is this
    /// one or below it, relative to the volume root ("\Users\Ann\Photos"). The whole file
    /// table is still read; files whose folder is unknown (Lost folders) are left out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions { mode: "quick".into(), include_existing: None, carve_types: None, carve_free_only: None, custom_signatures: None, label: None, folder: None }
    }
}

/// A user-defined carving rule (Settings -> File carving rules).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct CustomSignature {
    pub id: String,
    pub name: String,
    /// Extension for carved files, without the dot.
    pub ext: String,
    /// "photo" | "video" | "audio" | "document" | "archive" | "other"
    pub category: String,
    /// Header bytes as hex ("FF D8 FF", spaces optional). "??" matches any byte.
    pub header: String,
    /// Where the header sits inside the file (usually 0).
    #[serde(default)]
    pub header_offset: u32,
    /// Optional footer hex: the file ends after it.
    #[serde(default)]
    pub footer: String,
    /// Upper size limit in bytes (also the size used when there is no footer).
    pub max_size: u64,
    #[serde(default = "yes")]
    pub enabled: bool,
}
fn yes() -> bool {
    true
}

/// Sector-sweep participant (deep scans). The orchestrator reads the source once, chunk by chunk
/// (chunks are sector-aligned, normally 4 MiB, visited in parallel and in no particular order), and
/// hands every readable chunk to each visitor. Unreadable sectors arrive as zeros and are already
/// marked [`MapKind::Bad`]. Visitors may read more from `src` (e.g. to find a file's end).
/// `finish` runs once after the sweep, single-threaded: resolve, reconstruct, then `ctx.found(..)`.
pub trait ChunkVisitor: Send + Sync {
    fn name(&self) -> &'static str;
    fn visit(&self, src: &dyn crate::device::source::BlockSource, offset: u64, data: &[u8], ctx: &ScanCtx);
    fn finish(&self, src: &dyn crate::device::source::BlockSource, ctx: &ScanCtx) -> Result<EngineSummary, String>;
}

type FileSink = Box<dyn Fn(FoundFile) + Send + Sync>;
type RangeSink = Box<dyn Fn(MapKind, u64, u64) + Send + Sync>;
type LogSink = Box<dyn Fn(LogLevel, String) + Send + Sync>;

/// Everything an engine may touch while running. Cheap to call from many threads.
pub struct ScanCtx {
    pub cancel: AtomicBool,
    pub paused: AtomicBool,
    /// Progress of the current stage, in bytes (or items for item-based stages).
    pub done: AtomicU64,
    pub total: AtomicU64,
    pub files_found: AtomicU64,
    pub bad_bytes: AtomicU64,
    stage: Mutex<String>,
    pub options: ScanOptions,
    /// Size of the scan source.
    pub source_len: u64,
    pub sector_size: u32,
    /// Live-file ranges reported so far (MapKind::Allocated), for "carve free space only".
    pub allocated: RwLock<IntervalSet>,
    /// First-extent offsets of files the file-system engines reported, so carving doesn't
    /// report the same file a second time.
    pub known_starts: Mutex<HashSet<u64>>,
    /// The file system recognised by the quick stage, if any.
    pub probe: Mutex<Option<FsProbe>>,
    /// Enabled custom signatures (copied from Settings at scan start).
    pub custom_signatures: Vec<CustomSignature>,
    /// Lowercased `options.folder` ("" never: no scope then), see `in_scope`.
    scope: Option<String>,
    sink: FileSink,
    ranges: RangeSink,
    logger: LogSink,
}

impl ScanCtx {
    pub fn new(options: ScanOptions, source_len: u64, sector_size: u32, sink: FileSink, ranges: RangeSink, logger: LogSink) -> Self {
        let scope = options.folder.as_deref().map(scope_key).filter(|s| !s.is_empty());
        ScanCtx {
            cancel: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            done: AtomicU64::new(0),
            total: AtomicU64::new(0),
            files_found: AtomicU64::new(0),
            bad_bytes: AtomicU64::new(0),
            stage: Mutex::new(String::new()),
            options,
            source_len,
            sector_size: sector_size.max(512),
            allocated: RwLock::new(IntervalSet::new()),
            known_starts: Mutex::new(HashSet::new()),
            probe: Mutex::new(None),
            custom_signatures: Vec::new(),
            scope,
            sink,
            ranges,
            logger,
        }
    }

    /// A context for unit tests: collects files, ranges and log lines into the returned handles.
    pub fn for_test(options: ScanOptions, source_len: u64) -> (ScanCtx, TestSinks) {
        let t = TestSinks::default();
        let (f, r, l) = (t.files.clone(), t.ranges.clone(), t.log.clone());
        let ctx = ScanCtx::new(
            options,
            source_len,
            512,
            Box::new(move |x| f.lock().unwrap().push(x)),
            Box::new(move |k, s, e| r.lock().unwrap().push((k, s, e))),
            Box::new(move |lv, m| l.lock().unwrap().push((lv, m))),
        );
        (ctx, t)
    }

    /// Call often (per chunk / per few hundred records). Blocks while paused; `Err(CANCELLED)`
    /// once cancelled — return it unchanged so the orchestrator can tell cancel from failure.
    pub fn check(&self) -> Result<(), String> {
        loop {
            if self.cancel.load(Ordering::Relaxed) {
                return Err(CANCELLED.to_string());
            }
            if !self.paused.load(Ordering::Relaxed) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// Report a file. For FS engines, its first extent offset is remembered (see `known_starts`)
    /// and its extents are marked Recoverable (deleted/lost) — engines needn't mark them.
    pub fn found(&self, f: FoundFile) {
        if f.status != FileStatus::Carved {
            if let Some(o) = f.first_offset() {
                self.known_starts.lock().unwrap_or_else(|e| e.into_inner()).insert(o);
            }
        }
        if !self.in_scope(&f.folder) {
            return;
        }
        if matches!(f.status, FileStatus::Deleted | FileStatus::Lost | FileStatus::Carved) {
            for e in &f.extents {
                if e.offset != SPARSE && e.len > 0 {
                    (self.ranges)(MapKind::Recoverable, e.offset, e.offset.saturating_add(e.len));
                }
            }
        }
        self.files_found.fetch_add(1, Ordering::Relaxed);
        (self.sink)(f)
    }

    /// A folder scan keeps only files in its folder or below it (everything without a scope).
    pub fn in_scope(&self, folder: &str) -> bool {
        let Some(scope) = &self.scope else { return true };
        let f = scope_key(folder);
        f.len() >= scope.len() && f.starts_with(scope.as_str()) && (f.len() == scope.len() || f.as_bytes()[scope.len()] == b'\\')
    }

    /// Mark [start, start+len) on the Recovery Map.
    pub fn mark(&self, kind: MapKind, start: u64, len: u64) {
        if len == 0 {
            return;
        }
        let end = start.saturating_add(len);
        if kind == MapKind::Allocated {
            self.allocated.write().unwrap_or_else(|e| e.into_inner()).insert(start, end);
        }
        if kind == MapKind::Bad {
            self.bad_bytes.fetch_add(len, Ordering::Relaxed);
        }
        (self.ranges)(kind, start, end)
    }

    pub fn log(&self, level: LogLevel, msg: impl Into<String>) {
        (self.logger)(level, msg.into())
    }
    pub fn info(&self, msg: impl Into<String>) {
        self.log(LogLevel::Info, msg)
    }
    pub fn warn(&self, msg: impl Into<String>) {
        self.log(LogLevel::Warn, msg)
    }

    /// Start a stage: resets done/total. `total` in bytes or items.
    pub fn set_stage(&self, name: &str, total: u64) {
        *self.stage.lock().unwrap_or_else(|e| e.into_inner()) = name.to_string();
        self.total.store(total, Ordering::Relaxed);
        self.done.store(0, Ordering::Relaxed);
    }
    pub fn stage(&self) -> String {
        self.stage.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    pub fn progress(&self, n: u64) {
        self.done.fetch_add(n, Ordering::Relaxed);
    }
    pub fn set_progress(&self, n: u64) {
        self.done.store(n, Ordering::Relaxed);
    }
    pub fn include_existing(&self) -> bool {
        self.options.include_existing.unwrap_or(false)
    }
}

/// Collected output of [`ScanCtx::for_test`].
#[derive(Clone, Default)]
pub struct TestSinks {
    pub files: Arc<Mutex<Vec<FoundFile>>>,
    pub ranges: Arc<Mutex<Vec<(MapKind, u64, u64)>>>,
    pub log: Arc<Mutex<Vec<(LogLevel, String)>>>,
}

// ------------------------------------------------------------------------------------- helpers

/// Unix ms from a Windows FILETIME (100 ns ticks since 1601). 0 / out-of-range -> None.
pub fn filetime_to_ms(ft: u64) -> Option<i64> {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    if ft <= EPOCH_DIFF || ft > EPOCH_DIFF + 100 * 365 * 86_400 * 10_000_000 * 2 {
        return None;
    }
    Some(((ft - EPOCH_DIFF) / 10_000) as i64)
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Sizes as people read them: base 1024, "1 byte", "512 bytes", "3.2 MB", "120 GB".
pub fn human_size(n: u64) -> String {
    if n == 1 {
        return "1 byte".into();
    }
    if n < 1024 {
        return format!("{n} bytes");
    }
    let units = ["KB", "MB", "GB", "TB", "PB"];
    let mut v = n as f64 / 1024.0;
    let mut u = 0;
    while v >= 1024.0 && u < units.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if v >= 100.0 {
        format!("{v:.0} {}", units[u])
    } else {
        format!("{v:.1} {}", units[u])
    }
}

/// Replace characters Windows forbids in file names; never returns an empty or reserved name.
pub fn safe_file_name(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| if c < ' ' || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') { '_' } else { c })
        .collect();
    while s.ends_with('.') || s.ends_with(' ') {
        s.pop();
    }
    if s.is_empty() {
        s = "unnamed".into();
    }
    let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4",
        "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if RESERVED.contains(&stem.as_str()) {
        s.insert(0, '_');
    }
    if s.chars().count() > 200 {
        let ext = s.rsplit_once('.').map(|(_, e)| e.to_string()).filter(|e| e.len() <= 8);
        let mut t: String = s.chars().take(180).collect();
        if let Some(e) = ext {
            t.push('.');
            t.push_str(&e);
        }
        s = t;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_set_merges_and_queries() {
        let mut s = IntervalSet::new();
        s.insert(10, 20);
        s.insert(30, 40);
        s.insert(20, 30); // touches both -> one range
        assert_eq!(s.ranges, vec![(10, 40)]);
        s.insert(50, 60);
        s.insert(5, 12);
        assert_eq!(s.ranges, vec![(5, 40), (50, 60)]);
        assert!(s.contains(5) && s.contains(39) && !s.contains(40) && !s.contains(45) && s.contains(55));
        assert_eq!(s.overlap(0, 100), 45);
        assert_eq!(s.overlap(35, 55), 10);
        assert_eq!(s.clip(35, 55), vec![(35, 40), (50, 55)]);
        s.insert(0, 100);
        assert_eq!(s.ranges, vec![(0, 100)]);
    }

    #[test]
    fn names_are_made_safe() {
        assert_eq!(safe_file_name("a/b:c?.txt"), "a_b_c_.txt");
        assert_eq!(safe_file_name("con.txt"), "_con.txt");
        assert_eq!(safe_file_name("..."), "unnamed");
        assert_eq!(safe_file_name("x. "), "x");
    }

    #[test]
    fn sizes_read_naturally() {
        assert_eq!(human_size(1), "1 byte");
        assert_eq!(human_size(512), "512 bytes");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(300 * 1024 * 1024 * 1024), "300 GB");
    }

    #[test]
    fn ctx_check_and_found() {
        let (ctx, t) = ScanCtx::for_test(ScanOptions::default(), 1 << 20);
        assert!(ctx.check().is_ok());
        ctx.found(FoundFile { extents: vec![Extent { offset: 4096, len: 100 }], ..Default::default() });
        assert!(ctx.known_starts.lock().unwrap().contains(&4096));
        assert_eq!(t.files.lock().unwrap().len(), 1);
        assert_eq!(t.ranges.lock().unwrap()[0], (MapKind::Recoverable, 4096, 4196));
        ctx.cancel.store(true, Ordering::Relaxed);
        assert_eq!(ctx.check(), Err(CANCELLED.to_string()));
    }
}

/// A folder as compared by folder scans: backslashes, one leading "\", no trailing or doubled
/// separators, lowercase ("" for the root).
pub fn scope_key(folder: &str) -> String {
    let mut out = String::with_capacity(folder.len() + 1);
    for part in folder.split(['\\', '/']).filter(|p| !p.is_empty()) {
        out.push('\\');
        out.push_str(&part.to_lowercase());
    }
    out
}
