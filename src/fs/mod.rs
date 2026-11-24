//! File-system engines. Each one exposes the same three entry points (see CONTRACT.md):
//! `probe(src)`, `quick_scan(src, ctx)` and `sweep_visitor(probe)` for deep scans.

pub mod exfat;
pub mod fat;
pub mod ntfs;

use crate::device::source::BlockSource;
use crate::model::FsProbe;

/// Which engine understands this source (primary boot sector first, then backups). NTFS, exFAT, FAT.
pub fn probe_any(src: &dyn BlockSource) -> Option<FsProbe> {
    ntfs::probe(src).or_else(|| exfat::probe(src)).or_else(|| fat::probe(src))
}
