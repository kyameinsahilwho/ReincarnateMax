//! NTFS engine: MFT walk for deleted files, folder-path reconstruction, lost folders, Recycle Bin
//! $I/$R name restoration, loose-MFT-record sweep for formatted/damaged volumes.
//! OWNER: ntfs agent.
//!
//! Our own tolerant parser (rather than a strict NTFS crate): deleted, torn, formatted-over and
//! loose records must be read without a consistent surrounding volume.
//!
//! Files: `boot` (boot sector), `record` (MFT record + attributes), `runs` (data runs),
//! `report` (streams -> FoundFile + condition), `tree` (folder paths), `recycle` ($I/$R),
//! `scan` (quick scan), `sweep` (deep-scan visitor), `lznt1` (compressed files).
//!
//! FoundFile.meta keys set here: "mftRecord", "stream" (alternate data stream name),
//! "clusterSize" + "compressionUnit" (compressed files, used by `read_compressed`),
//! "originalPath" + "recycledAs" (Recycle Bin), "recordOffset" (loose records).

pub mod boot;
pub mod lznt1;
pub mod record;
pub mod recycle;
pub mod report;
pub mod runs;
pub mod scan;
pub mod sweep;
pub mod tree;

#[cfg(test)]
mod testimg;
#[cfg(test)]
mod tests;

use crate::device::source::{read_tolerant, BlockSource};
use crate::model::{ChunkVisitor, EngineSummary, FoundFile, FsProbe, ScanCtx};

/// Volume label from $Volume (record 3), from the MFT or its mirror.
fn volume_label(src: &dyn BlockSource, b: &boot::Boot) -> String {
    let rs = b.record_size as u64;
    for off in [b.mft_offset() + 3 * rs, b.mftmirr_offset() + 3 * rs] {
        let mut buf = vec![0u8; rs as usize];
        let (n, bad) = read_tolerant(src, off, &mut buf, None);
        if n as u64 != rs || !bad.is_empty() {
            continue;
        }
        if let Some(r) = record::parse_record(&mut buf) {
            if let Some(l) = r.volume_name {
                return l.trim_end_matches('\0').to_string();
            }
            if r.name.as_ref().map_or(false, |n| n.name == "$Volume") {
                return String::new();
            }
        }
    }
    String::new()
}

/// Recognise NTFS (primary boot sector, else the backup at the end of the volume).
/// `total_size` includes the backup boot sector (= the partition size Windows creates).
pub fn probe(src: &dyn BlockSource) -> Option<FsProbe> {
    let (b, used_backup) = boot::find_boot(src)?;
    Some(FsProbe {
        fs: "NTFS".into(),
        cluster_size: b.cluster_size,
        sector_size: b.bytes_per_sector,
        total_size: b.volume_bytes().saturating_add(b.bytes_per_sector as u64),
        label: volume_label(src, &b),
        serial: b.serial_text(),
        used_backup_boot: used_backup,
    })
}

/// Walk the MFT and report deleted (and, if `ctx.include_existing()`, existing) files.
pub fn quick_scan(src: &dyn BlockSource, ctx: &ScanCtx) -> Result<EngineSummary, String> {
    scan::quick_scan(src, ctx)
}

/// Deep scans: find MFT records outside the live MFT (formatted / damaged volumes).
pub fn sweep_visitor(probe: Option<&FsProbe>) -> Box<dyn ChunkVisitor> {
    Box::new(sweep::Sweep::new(probe))
}

/// Read `buf.len()` bytes at file offset `pos` of an NTFS-compressed file (flags::COMPRESSED),
/// decompressing LZNT1 compression units from its extents. Returns bytes produced.
/// Uses `meta["clusterSize"]` / `meta["compressionUnit"]` (defaults 4096 / 16).
pub fn read_compressed(src: &dyn BlockSource, f: &FoundFile, pos: u64, buf: &mut [u8]) -> Result<usize, String> {
    lznt1::read_compressed(src, f, pos, buf)
}

/// Like [`read_compressed`], and also says whether any of the bytes came from unreadable sectors
/// (zero-filled before decompressing), so callers can report the file as damaged.
/// Returns (bytes produced, hit bad sectors).
pub fn read_compressed_checked(src: &dyn BlockSource, f: &FoundFile, pos: u64, buf: &mut [u8]) -> Result<(usize, bool), String> {
    lznt1::read_compressed_checked(src, f, pos, buf)
}
