//! Partition intelligence: MBR/GPT tables (primary and backup), boot-sector search for lost and
//! deleted partitions, damaged-table detection. OWNER: fat agent.
//!
//! - `table`: MBR + extended chain, GPT primary/backup with CRCs, per-entry file system detection
//!   (backup boot sectors when the first one is damaged), unallocated gaps.
//! - `search`: boot-sector search of the space no table covers.
//! - `view`: borrowed windows on a source.

mod search;
mod table;
mod view;

#[cfg(test)]
mod tests;

use crate::device::source::BlockSource;
use crate::model::{ScanCtx, SourceRef};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PartitionReport {
    /// "GPT" | "MBR" | "None" (no table: a bare volume or an empty disk)
    pub style: String,
    pub sector_size: u32,
    pub disk_size: u64,
    pub entries: Vec<FoundPartition>,
    /// GPT only.
    pub gpt: Option<GptHealth>,
    /// Gaps not covered by any listed partition (byte ranges), ignoring < 16 MiB alignment slack.
    pub unallocated: Vec<(u64, u64)>,
    /// Plain sentences ("The primary GPT header is damaged; the backup copy was used.").
    pub notes: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GptHealth {
    pub primary_ok: bool,
    pub backup_ok: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FoundPartition {
    /// Byte offset on the disk / image.
    pub offset: u64,
    pub size: u64,
    /// "NTFS" | "FAT32" | "FAT16" | "FAT12" | "exFAT" | None (not recognised)
    pub fs: Option<String>,
    pub label: Option<String>,
    /// "Basic data", "EFI system", "Microsoft reserved", "Recovery", "Extended", "Linux", "Unknown"…
    pub type_name: String,
    /// "ok" (in the table, readable) | "lost" (not in any table: found by its boot sector)
    /// | "damaged" (in the table, its boot sector is unreadable or wrong) | "backupOnly"
    /// (only the backup boot sector / backup GPT knows it)
    pub status: String,
    /// "mbr" | "gpt" | "gptBackup" | "bootSector" | "backupBootSector"
    pub found_by: String,
    pub number: Option<u32>,
    /// One sentence for the UI.
    pub note: String,
}

/// Read the partition tables of a disk or image (fast, no sweep).
pub fn analyze(src: &dyn BlockSource) -> Result<PartitionReport, String> {
    if src.len() == 0 {
        return Err("The drive reports a size of zero. Check that it is connected and try again.".into());
    }
    Ok(table::analyze_inner(src).0)
}

/// The "partitions" scan mode: tables plus a search of the whole source for boot sectors of
/// partitions no table lists (deleted / lost). Uses ctx for progress/cancel and Bad marks.
pub fn search_lost(src: &dyn BlockSource, ctx: &ScanCtx) -> Result<PartitionReport, String> {
    if src.len() == 0 {
        return Err("The drive reports a size of zero. Check that it is connected and try again.".into());
    }
    search::search(src, ctx, search::DENSE_BUDGET)
}

#[tauri::command]
pub async fn analyze_partitions(source: SourceRef) -> Result<PartitionReport, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let src = crate::device::source::open_source(&source)?;
        analyze(src.as_ref())
    })
    .await
    .map_err(|_| "Reading the partition table stopped unexpectedly.".to_string())?
}
