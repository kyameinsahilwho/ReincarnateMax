//! NTFS boot sector: geometry of the volume (sector and cluster size, where the MFT lives, record
//! size). The primary copy sits in sector 0; Windows keeps a backup in the volume's last sector.

use crate::device::source::{read_full, BlockSource};

/// Parsed, sanity-checked boot sector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Boot {
    pub bytes_per_sector: u32,
    pub cluster_size: u32,
    /// Sectors the file system covers (the backup boot sector sits right after them).
    pub total_sectors: u64,
    pub mft_lcn: u64,
    pub mftmirr_lcn: u64,
    /// Bytes per MFT record (normally 1024, 4096 on some 4Kn drives).
    pub record_size: u32,
    /// Bytes per directory index block (normally 4096).
    pub index_size: u32,
    pub serial: u64,
}

impl Boot {
    pub fn volume_bytes(&self) -> u64 {
        self.total_sectors.saturating_mul(self.bytes_per_sector as u64)
    }
    pub fn mft_offset(&self) -> u64 {
        self.mft_lcn.saturating_mul(self.cluster_size as u64)
    }
    pub fn mftmirr_offset(&self) -> u64 {
        self.mftmirr_lcn.saturating_mul(self.cluster_size as u64)
    }
    /// "1234-ABCD", the way `vol` shows it (low 32 bits).
    pub fn serial_text(&self) -> String {
        let s = self.serial as u32;
        format!("{:04X}-{:04X}", s >> 16, s & 0xFFFF)
    }
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// Size encoded as "clusters per X" in one signed byte: positive = that many clusters,
/// negative = 2^(-v) bytes (used when X is smaller than a cluster).
fn clusters_or_shift(v: u8, cluster: u32) -> Option<u32> {
    let v = v as i8;
    if v > 0 {
        (v as u32).checked_mul(cluster)
    } else if v < 0 {
        let shift = -(v as i32);
        if shift >= 31 {
            None
        } else {
            Some(1u32 << shift)
        }
    } else {
        None
    }
}

/// Parse a 512+ byte boot sector. `None` unless it is a plausible NTFS boot sector.
pub fn parse_boot(b: &[u8]) -> Option<Boot> {
    if b.len() < 512 || &b[3..11] != b"NTFS    " {
        return None;
    }
    let bps = le16(b, 0x0B) as u32;
    if !bps.is_power_of_two() || !(256..=4096).contains(&bps) {
        return None;
    }
    // Sectors per cluster; values above 128 are a negative power of two (clusters >= 128 KiB with
    // 512-byte sectors on Windows 10 1709+): 0xF8 -> 2^8 sectors.
    let spc_raw = b[0x0D];
    let spc: u32 = if spc_raw <= 0x80 {
        spc_raw as u32
    } else {
        let shift = 256 - spc_raw as u32;
        if shift > 20 {
            return None;
        }
        1u32 << shift
    };
    if spc == 0 || !spc.is_power_of_two() {
        return None;
    }
    let cluster = bps.checked_mul(spc)?;
    if cluster > 2 * 1024 * 1024 {
        return None;
    }
    let total_sectors = le64(b, 0x28);
    if total_sectors == 0 {
        return None;
    }
    let total_clusters = total_sectors / spc as u64;
    let mft_lcn = le64(b, 0x30);
    let mftmirr_lcn = le64(b, 0x38);
    if mft_lcn == 0 || mft_lcn >= total_clusters.max(1) || mftmirr_lcn >= total_clusters.max(1) {
        return None;
    }
    let record_size = clusters_or_shift(b[0x40], cluster)?;
    if !record_size.is_power_of_two() || !(512..=65536).contains(&record_size) {
        return None;
    }
    let index_size = clusters_or_shift(b[0x44], cluster).filter(|s| s.is_power_of_two() && (512..=65536).contains(s)).unwrap_or(4096);
    Some(Boot {
        bytes_per_sector: bps,
        cluster_size: cluster,
        total_sectors,
        mft_lcn,
        mftmirr_lcn,
        record_size,
        index_size,
        serial: le64(b, 0x48),
    })
}

/// Find a usable boot sector: the primary one, else the backup in the last sector (also trying the
/// sector before it, for sources one sector longer than the volume, and 4 KiB sectors).
/// Returns (boot, used_backup).
pub fn find_boot(src: &dyn BlockSource) -> Option<(Boot, bool)> {
    let mut buf = vec![0u8; 512];
    if read_full(src, 0, &mut buf).ok() == Some(512) {
        if let Some(b) = parse_boot(&buf) {
            return Some((b, false));
        }
    }
    let len = src.len();
    let mut tried = Vec::new();
    for ss in [src.sector_size().max(512) as u64, 512, 4096] {
        for back in [1u64, 2] {
            let Some(off) = len.checked_sub(ss * back) else { continue };
            if tried.contains(&off) {
                continue;
            }
            tried.push(off);
            if read_full(src, off, &mut buf).ok() != Some(512) {
                continue;
            }
            if let Some(b) = parse_boot(&buf) {
                // The backup describes the volume it ends: it must sit at (or just after) its end.
                let vb = b.volume_bytes();
                if vb <= off + b.bytes_per_sector as u64 && vb + 2 * 4096 >= off {
                    return Some((b, true));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::source::MemSource;

    pub fn sample_boot(bps: u16, spc: u8, total: u64, mft: u64, mirr: u64, rec: u8) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
        b[3..11].copy_from_slice(b"NTFS    ");
        b[0x0B..0x0D].copy_from_slice(&bps.to_le_bytes());
        b[0x0D] = spc;
        b[0x15] = 0xF8;
        b[0x28..0x30].copy_from_slice(&total.to_le_bytes());
        b[0x30..0x38].copy_from_slice(&mft.to_le_bytes());
        b[0x38..0x40].copy_from_slice(&mirr.to_le_bytes());
        b[0x40] = rec;
        b[0x44] = 1;
        b[0x48..0x50].copy_from_slice(&0x1234_5678_9ABC_DEF0u64.to_le_bytes());
        b[510] = 0x55;
        b[511] = 0xAA;
        b
    }

    #[test]
    fn parses_common_geometry() {
        let b = parse_boot(&sample_boot(512, 8, 1_000_000, 786432 / 8, 2, 0xF6)).unwrap();
        assert_eq!(b.cluster_size, 4096);
        assert_eq!(b.record_size, 1024);
        assert_eq!(b.index_size, 4096);
        assert_eq!(b.serial_text(), "9ABC-DEF0");
        assert_eq!(b.mft_offset(), 786432 / 8 * 4096);
    }

    #[test]
    fn parses_large_cluster_encoding() {
        // 0xF8 = 2^8 sectors = 128 KiB clusters with 512-byte sectors; record size 0xF6 = 1024.
        let b = parse_boot(&sample_boot(512, 0xF8, 100_000_000, 16, 2, 0xF6)).unwrap();
        assert_eq!(b.cluster_size, 128 * 1024);
        assert_eq!(b.record_size, 1024);
        // 0x80 = 128 sectors = 64 KiB.
        let b = parse_boot(&sample_boot(512, 0x80, 100_000_000, 16, 2, 0xF6)).unwrap();
        assert_eq!(b.cluster_size, 64 * 1024);
        // Positive record size in clusters (512-byte clusters, 2 per record).
        let b = parse_boot(&sample_boot(512, 1, 100_000, 16, 2, 2)).unwrap();
        assert_eq!(b.record_size, 1024);
    }

    #[test]
    fn rejects_nonsense() {
        assert!(parse_boot(&sample_boot(500, 8, 1000, 4, 2, 0xF6)).is_none());
        assert!(parse_boot(&sample_boot(512, 3, 1000, 4, 2, 0xF6)).is_none());
        assert!(parse_boot(&sample_boot(512, 8, 0, 4, 2, 0xF6)).is_none());
        assert!(parse_boot(&sample_boot(512, 8, 1000, 0, 2, 0xF6)).is_none());
        assert!(parse_boot(&sample_boot(512, 8, 1000, 4, 2, 0)).is_none());
        assert!(parse_boot(&[0u8; 100]).is_none());
    }

    #[test]
    fn uses_backup_when_primary_is_damaged() {
        let total = 2047u64;
        let mut img = vec![0u8; 2048 * 512];
        let bs = sample_boot(512, 8, total, 4, 2, 0xF6);
        img[(total as usize) * 512..].copy_from_slice(&bs);
        let m = MemSource::new(img.clone());
        let (b, backup) = find_boot(&m).unwrap();
        assert!(backup);
        assert_eq!(b.total_sectors, total);
        // Source one sector longer than the volume: the backup is in the second-to-last sector.
        let mut img2 = img;
        img2.extend_from_slice(&[0u8; 512]);
        let (_, backup2) = find_boot(&MemSource::new(img2)).unwrap();
        assert!(backup2);
        // Primary present: no backup used.
        let mut img3 = vec![0u8; 2048 * 512];
        img3[..512].copy_from_slice(&bs);
        assert!(!find_boot(&MemSource::new(img3)).unwrap().1);
    }
}
