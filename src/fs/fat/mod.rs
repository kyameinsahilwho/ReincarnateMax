//! FAT12/16/32 engine: deleted directory entries (0xE5), long names, lost directories.
//! OWNER: fat agent.
//!
//! - `bpb`: boot sector / geometry (backup boot sector at sector 6 for FAT32).
//! - `table`: the FAT (second copy used for unreadable sectors), chains.
//! - `dir`: 8.3 + LFN entries, deleted-name reconstruction, plausibility checks.
//! - `scan`: quick scan (tree walk incl. deleted folders), condition assessment.
//! - `sweep`: deep-scan directory sweep and lost-folder rebuild.
//!
//! Timestamps: FAT stores local wall-clock time; they are converted with the PC's current UTC
//! offset (see `util::local_offset_ms`).

pub(crate) mod bpb;
pub(crate) mod dir;
pub(crate) mod scan;
pub(crate) mod sweep;
pub(crate) mod table;
pub(crate) mod util;

#[cfg(test)]
mod tests;

use crate::device::source::{read_tolerant, BlockSource};
use crate::model::{ChunkVisitor, EngineSummary, FsProbe, ScanCtx};

pub fn probe(src: &dyn BlockSource) -> Option<FsProbe> {
    let g = bpb::read_geom(src)?;
    // The volume label lives in the root directory (Windows keeps the BPB copy in sync, others don't).
    let mut label = g.bpb_label.clone();
    let (off, len) = if g.kind == bpb::FatKind::Fat32 {
        (g.cluster_offset(g.root_cluster), g.cluster_size as u64)
    } else {
        (g.root_offset, g.root_bytes.min(16 * 1024))
    };
    let mut buf = vec![0u8; len as usize];
    let (n, _) = read_tolerant(src, off, &mut buf, None);
    buf.truncate(n / 32 * 32);
    let offs: Vec<u64> = (0..buf.len() as u64 / 32).map(|i| off + i * 32).collect();
    let p = dir::parse_dir(&buf, &offs, g.kind == bpb::FatKind::Fat32, false, None, 0);
    if let Some(l) = p.label {
        if !l.is_empty() {
            label = l;
        }
    }
    Some(FsProbe {
        fs: g.kind.name().to_string(),
        cluster_size: g.cluster_size,
        sector_size: g.bps,
        total_size: g.total_size(),
        label,
        serial: g.serial.map(|s| format!("{:04X}-{:04X}", s >> 16, s & 0xFFFF)).unwrap_or_default(),
        used_backup_boot: g.used_backup,
    })
}

pub fn quick_scan(src: &dyn BlockSource, ctx: &ScanCtx) -> Result<EngineSummary, String> {
    scan::quick_scan(src, ctx)
}

pub fn sweep_visitor(probe: Option<&FsProbe>) -> Box<dyn ChunkVisitor> {
    Box::new(sweep::new_sweep(probe))
}
