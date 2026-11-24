//! exFAT engine: deleted entry sets (in-use bit cleared), lost directories.
//! OWNER: fat agent.
//!
//! - `boot`: boot region + checksum, backup region at sector 12.
//! - `scan`: entry sets (File 0x85/0x05, Stream 0xC0/0x40, Name 0xC1/0x41, set checksum), FAT,
//!   allocation bitmap, tree walk, condition assessment.
//! - `sweep`: deep-scan search for entry sets outside the live tree.

pub(crate) mod boot;
pub(crate) mod scan;
pub(crate) mod sweep;

#[cfg(test)]
mod tests;

use crate::device::source::{read_tolerant, BlockSource};
use crate::model::{ChunkVisitor, EngineSummary, FsProbe, ScanCtx};

pub fn probe(src: &dyn BlockSource) -> Option<FsProbe> {
    let g = boot::read_xgeom(src)?;
    // Label: the volume-label entry of the root directory (first cluster is enough in practice).
    let mut buf = vec![0u8; g.cluster_size.min(64 * 1024) as usize];
    let (n, _) = read_tolerant(src, g.cluster_offset(g.root_cluster), &mut buf, None);
    buf.truncate(n / 32 * 32);
    let offs: Vec<u64> = (0..buf.len() as u64 / 32).collect();
    let label = scan::parse_dir(&buf, &offs, 0).label.unwrap_or_default();
    Some(FsProbe {
        fs: "exFAT".into(),
        cluster_size: g.cluster_size,
        sector_size: g.bps,
        total_size: g.total_size,
        label,
        serial: format!("{:04X}-{:04X}", g.serial >> 16, g.serial & 0xFFFF),
        used_backup_boot: g.used_backup,
    })
}

pub fn quick_scan(src: &dyn BlockSource, ctx: &ScanCtx) -> Result<EngineSummary, String> {
    scan::quick_scan(src, ctx)
}

pub fn sweep_visitor(probe: Option<&FsProbe>) -> Box<dyn ChunkVisitor> {
    Box::new(sweep::new_sweep(probe))
}
