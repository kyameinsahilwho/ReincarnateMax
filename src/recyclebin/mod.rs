//! Recycle Bin: lists items still in $Recycle.Bin (readable through Windows) and parses $I records,
//! which the NTFS engine also uses to restore names of $R files after the bin was emptied.
//! Read-only: nothing here deletes, restores or renames anything in the bin.
//! OWNER: recover agent.

mod info;
mod scan;

use crate::model::{EngineSummary, ScanCtx};

#[derive(Clone, Debug, PartialEq)]
pub struct RecycleInfo {
    /// Original full path ("C:\Users\Ann\Pictures\cat.jpg").
    pub original_path: String,
    pub size: u64,
    /// Unix ms.
    pub deleted: Option<i64>,
}

/// Parse a $I file (version 1: Vista/7/8, version 2: Windows 10+). None = not a valid record.
pub fn parse_info_file(data: &[u8]) -> Option<RecycleInfo> {
    info::parse(data)
}

/// Report the items in drive `letter`'s Recycle Bin (all users when elevated, else the current
/// user) as FileStatus::RecycleBin with live_path set.
pub fn scan_volume(letter: &str, ctx: &ScanCtx) -> Result<EngineSummary, String> {
    let l = letter.trim().trim_end_matches(['\\', ':']).to_ascii_uppercase();
    if l.len() != 1 || !l.as_bytes()[0].is_ascii_alphabetic() {
        return Ok(EngineSummary::default());
    }
    let root = std::path::PathBuf::from(format!("{l}:\\$Recycle.Bin"));
    scan::scan_bin(&root, ctx)
}
