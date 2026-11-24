//! Scan orchestration and the session store: jobs (start / pause / resume / cancel, several drives
//! at once), the stage pipeline (quick, deep, partitions), the sector sweep that feeds every
//! ChunkVisitor, one SQLite session file per scan (results, Recovery Map ranges, log, checkpoints,
//! crash restoration), and the queries the recovery workspace runs. OWNER: scan agent.
//!
//! Events: "scan-progress", "scan-done" (payloads in CONTRACT.md).

pub mod jobs;
pub mod manage;
pub mod map;
pub mod pipeline;
pub mod query;
pub mod session;
pub mod store;
pub mod sweep;
pub mod writer;

#[cfg(test)]
mod tests;

use crate::model::{ScanOptions, SourceRef};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The real engines, events through Tauri.
fn real_config(app: tauri::AppHandle) -> pipeline::Config {
    use tauri::Emitter;
    pipeline::Config::new(
        Arc::new(pipeline::RealEngines),
        Arc::new(move |name: &str, v: serde_json::Value| {
            let _ = app.emit(name, v);
        }),
    )
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|_| "Something went wrong in MAX. Try again.".to_string())?
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScanStarted {
    pub session_id: String,
    pub job: u64,
}

/// Start a scan of `source`. Returns at once; progress arrives as events.
#[tauri::command]
pub async fn start_scan(app: tauri::AppHandle, source: SourceRef, options: ScanOptions) -> Result<ScanStarted, String> {
    let cfg = real_config(app);
    blocking(move || jobs::start(cfg, source, options)).await
}

/// A folder picked for a folder scan, as the drive to scan and the folder to keep results from.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FolderSource {
    pub source: SourceRef,
    /// Below the drive's root: "\\Users\\Ann\\Photos" ("" = the whole drive).
    pub folder: String,
    /// "D:\\Users\\Ann\\Photos"
    pub display: String,
}

/// Turn a folder the user picked into the volume to scan and the folder scope (`folder` option of
/// a quick scan). Read-only.
#[tauri::command]
pub async fn folder_source(path: String) -> Result<FolderSource, String> {
    blocking(move || {
        let (letter, folder) = crate::device::win::folder_on_volume(&path)?;
        Ok(FolderSource {
            source: SourceRef { kind: crate::model::SourceKind::Volume, path: letter.to_string(), ..Default::default() },
            display: format!("{letter}:{}", if folder.is_empty() { "\\" } else { &folder }),
            folder,
        })
    })
    .await
}

/// Before a scan starts: where its results would be kept, with a warning to show when they must
/// stay on the drive being scanned (`refuse`: why start_scan would refuse right now). Read-only.
#[tauri::command]
pub async fn scan_location(source: SourceRef) -> Result<session::LocationPreview, String> {
    blocking(move || session::preview_location(&source)).await
}

#[tauri::command]
pub fn pause_scan(session_id: String, paused: bool) -> Result<(), String> {
    jobs::pause(&session_id, paused)
}

#[tauri::command]
pub fn cancel_scan(session_id: String) -> Result<(), String> {
    jobs::cancel(&session_id)
}

/// Continue an interrupted (crashed / closed while running) or paused-and-closed session from its
/// last checkpoint.
#[tauri::command]
pub async fn resume_session(app: tauri::AppHandle, session_id: String) -> Result<ScanStarted, String> {
    let cfg = real_config(app);
    blocking(move || jobs::resume(cfg, &session_id)).await
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    pub id: String,
    pub label: String,
    pub source: SourceRef,
    /// "quick" | "deep" | "partitions"
    pub mode: String,
    /// "running" | "paused" | "done" | "cancelled" | "failed" | "interrupted"
    pub state: String,
    pub created: i64,
    pub updated: i64,
    pub files: u64,
    pub bytes: u64,
    /// Bytes of the source covered so far by the sweep (deep) or the FS walk (quick).
    pub scanned_bytes: u64,
    pub source_len: u64,
    pub bad_bytes: u64,
    /// Session file size on disk.
    pub file_size: u64,
}

#[tauri::command]
pub async fn list_sessions() -> Result<Vec<SessionSummary>, String> {
    blocking(manage::list_sessions).await
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct StageInfo {
    /// "filesystem" | "recyclebin" | "sweep" | "rebuild" | "condition" | "partitions"
    pub key: String,
    /// "Reading the file system" …
    pub label: String,
    /// "pending" | "running" | "done" | "skipped" | "failed"
    pub state: String,
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    /// keyed by Category::as_str / FileStatus / Condition (camelCase names)
    pub by_category: std::collections::BTreeMap<String, (u64, u64)>,
    pub by_status: std::collections::BTreeMap<String, (u64, u64)>,
    pub by_condition: std::collections::BTreeMap<String, (u64, u64)>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct SessionDetail {
    pub summary: SessionSummary,
    pub options: ScanOptions,
    pub stages: Vec<StageInfo>,
    pub probe: Option<crate::model::FsProbe>,
    /// "partitions" mode (and deep scans of whole disks): what was found.
    pub partitions: Option<crate::partitions::PartitionReport>,
    pub counts: Counts,
    /// Sector size of the source, for the map inspector.
    pub sector_size: u32,
    pub error: Option<String>,
    /// Plain sentences from the engines (EngineSummary notes) and warnings worth showing.
    pub notes: Vec<String>,
}

#[tauri::command]
pub async fn get_session(session_id: String) -> Result<SessionDetail, String> {
    blocking(move || manage::get_session(&session_id)).await
}

#[tauri::command]
pub async fn delete_session(session_id: String) -> Result<(), String> {
    blocking(move || manage::delete_session(&session_id)).await
}

/// Copy the session file to `path` (a .maxscan file the user can keep or move to another PC).
#[tauri::command]
pub async fn export_session(session_id: String, path: String) -> Result<(), String> {
    blocking(move || manage::export_session(&session_id, &path)).await
}

/// Add a .maxscan file to the session list. Returns its id.
#[tauri::command]
pub async fn import_session(path: String) -> Result<String, String> {
    blocking(move || manage::import_session(&path)).await
}

/// Workspace query. All fields optional; combine freely.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct FileQuery {
    /// Folder path ("\\Users\\Ann"); with `recursive`, include sub-folders.
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub recursive: Option<bool>,
    /// Case-insensitive substring of the name; "*.jpg" / ".jpg" match extensions.
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub categories: Option<Vec<String>>,
    #[serde(default)]
    pub type_ids: Option<Vec<String>>,
    /// FileStatus names: "deleted" | "existing" | "lost" | "carved" | "recycleBin"
    #[serde(default)]
    pub statuses: Option<Vec<String>>,
    /// Condition names: "excellent" | "good" | "partial" | "unknown"
    #[serde(default)]
    pub conditions: Option<Vec<String>>,
    #[serde(default)]
    pub min_size: Option<u64>,
    #[serde(default)]
    pub max_size: Option<u64>,
    /// Unix ms, inclusive, applied to `date_field`.
    #[serde(default)]
    pub date_from: Option<i64>,
    #[serde(default)]
    pub date_to: Option<i64>,
    /// "modified" (default) | "created" | "deleted"
    #[serde(default)]
    pub date_field: Option<String>,
    #[serde(default)]
    pub duplicates_only: Option<bool>,
    /// "name" | "size" | "modified" | "created" | "deleted" | "condition" | "type" | "folder"
    #[serde(default)]
    pub sort: Option<String>,
    #[serde(default)]
    pub desc: Option<bool>,
    #[serde(default)]
    pub offset: Option<u64>,
    /// Default 200, max 2000.
    #[serde(default)]
    pub limit: Option<u64>,
}

/// One list row (FoundFile without extents/resident bytes, plus its id).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct FileRow {
    pub id: i64,
    pub name: String,
    pub folder: String,
    pub size: u64,
    pub type_id: String,
    pub category: crate::model::Category,
    pub status: crate::model::FileStatus,
    pub origin: crate::model::Origin,
    pub condition: crate::model::Condition,
    pub note: String,
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub deleted: Option<i64>,
    pub fragmented: bool,
    pub flags: u32,
    /// Files with the same content share a group id (after duplicate detection).
    pub dup_group: Option<i64>,
    pub meta: std::collections::BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct FilePage {
    pub total: u64,
    pub total_size: u64,
    pub items: Vec<FileRow>,
}

#[tauri::command]
pub async fn query_files(session_id: String, query: FileQuery) -> Result<FilePage, String> {
    blocking(move || session::with_conn(&session_id, |c| query::query_files(&session_id, c, &query))).await
}

/// Ids of every file matching (no paging), for "select all". More than `query::MAX_IDS` matches
/// is refused with a sentence (recovery and reports use the uncapped `store::query_ids`).
#[tauri::command]
pub async fn query_ids(session_id: String, query: FileQuery) -> Result<Vec<i64>, String> {
    blocking(move || session::with_conn(&session_id, |c| query::query_ids_limited(c, &query, query::MAX_IDS))).await
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct FolderNode {
    pub path: String,
    pub name: String,
    /// Files directly and below.
    pub files: u64,
    pub size: u64,
    pub has_children: bool,
}

/// One level of the reconstructed folder tree under `parent` ("" = top level).
#[tauri::command]
pub async fn folder_children(session_id: String, parent: String, query: Option<FileQuery>) -> Result<Vec<FolderNode>, String> {
    blocking(move || session::with_conn(&session_id, |c| query::folder_children(&session_id, c, &parent, query.as_ref()))).await
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct FileDetail {
    pub row: FileRow,
    pub extents: Vec<crate::model::Extent>,
    pub accessed: Option<i64>,
    pub fs_ref: Option<u64>,
    pub has_resident: bool,
    pub live_path: Option<String>,
    pub hash: Option<String>,
    pub source: SourceRef,
    pub sector_size: u32,
}

#[tauri::command]
pub async fn file_detail(session_id: String, id: i64) -> Result<FileDetail, String> {
    blocking(move || session::with_conn(&session_id, |c| query::file_detail(c, id))).await
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct MapData {
    pub start: u64,
    pub end: u64,
    pub cell_bytes: u64,
    /// Base64, one byte per cell: bit i set = MapKind with index i covers part of the cell
    /// (0 Scanned, 1 Metadata, 2 Allocated, 3 Recoverable, 4 Bad).
    pub cells: String,
    pub source_len: u64,
    /// Totals over [start, end) per MapKind index, bytes.
    pub totals: [u64; 5],
}

/// The Recovery Map for [start, end) at `cells` resolution (zoomable; max 65536 cells).
#[tauri::command]
pub async fn map_cells(session_id: String, start: Option<u64>, end: Option<u64>, cells: u32) -> Result<MapData, String> {
    blocking(move || manage::map_cells(&session_id, start, end, cells)).await
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct RegionInfo {
    pub start: u64,
    pub end: u64,
    pub sector_size: u32,
    pub first_sector: u64,
    pub last_sector: u64,
    /// Bytes per MapKind index within the region.
    pub totals: [u64; 5],
    pub bad_ranges: Vec<(u64, u64)>,
    /// Files with an extent inside the region (max 100), and the total count.
    pub files: Vec<FileRow>,
    pub file_count: u64,
}

/// What a clicked map region contains.
#[tauri::command]
pub async fn map_region(session_id: String, start: u64, end: u64) -> Result<RegionInfo, String> {
    blocking(move || manage::map_region(&session_id, start, end)).await
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct LogLine {
    pub at: i64,
    /// "info" | "warn" | "error"
    pub level: String,
    pub message: String,
}

#[tauri::command]
pub async fn session_log(session_id: String, offset: Option<u64>, limit: Option<u64>) -> Result<Vec<LogLine>, String> {
    blocking(move || manage::session_log(&session_id, offset, limit)).await
}

/// Mark sessions left "running" by a crash as "interrupted" (called once at startup).
pub fn restore_after_crash() {
    jobs::restore_after_crash()
}
