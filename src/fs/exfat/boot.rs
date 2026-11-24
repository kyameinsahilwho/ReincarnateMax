//! exFAT boot region: main boot sector, boot checksum (sector 11), backup region at sector 12.

use crate::device::source::{read_tolerant, BlockSource};
use crate::fs::fat::util::{rd16, rd32, rd64};

#[derive(Clone, Debug)]
pub(crate) struct XGeom {
    pub bps: u32,
    pub cluster_size: u32,
    pub fat_offset: u64,
    pub fat_bytes: u64,
    pub nfats: u32,
    pub heap_offset: u64,
    pub cluster_count: u32,
    pub root_cluster: u32,
    pub serial: u32,
    pub total_size: u64,
    pub used_backup: bool,
    pub checksum_ok: bool,
}

impl XGeom {
    pub fn valid_cluster(&self, c: u32) -> bool {
        c >= 2 && c <= self.cluster_count.saturating_add(1)
    }
    pub fn cluster_offset(&self, c: u32) -> u64 {
        self.heap_offset + (c.max(2) as u64 - 2) * self.cluster_size as u64
    }
    pub fn cluster_of(&self, off: u64) -> Option<u32> {
        if off < self.heap_offset {
            return None;
        }
        let c = (off - self.heap_offset) / self.cluster_size as u64 + 2;
        if c > self.cluster_count as u64 + 1 {
            return None;
        }
        Some(c as u32)
    }
}

/// Boot checksum over the first 11 sectors of a boot region (bytes 106, 107 and 112 skipped).
pub(crate) fn boot_checksum(region: &[u8], bps: usize) -> u32 {
    let mut c: u32 = 0;
    for (i, &b) in region[..11 * bps].iter().enumerate() {
        if i == 106 || i == 107 || i == 112 {
            continue;
        }
        c = c.rotate_right(1).wrapping_add(b as u32);
    }
    c
}

/// Parse the main boot sector fields (no checksum).
pub(crate) fn parse_boot_sector(b: &[u8]) -> Option<XGeom> {
    if b.len() < 512 || &b[3..11] != b"EXFAT   " || b[510] != 0x55 || b[511] != 0xAA {
        return None;
    }
    if b[11..64].iter().any(|&x| x != 0) {
        return None;
    }
    let vol_len = rd64(b, 72);
    let fat_off = rd32(b, 80) as u64;
    let fat_len = rd32(b, 84) as u64;
    let heap_off = rd32(b, 88) as u64;
    let count = rd32(b, 92);
    let root = rd32(b, 96);
    let serial = rd32(b, 100);
    let rev = rd16(b, 104);
    let bps_shift = b[108] as u32;
    let spc_shift = b[109] as u32;
    let nfats = b[110] as u32;
    if !(9..=12).contains(&bps_shift) || spc_shift > 25 - bps_shift || !(1..=2).contains(&nfats) {
        return None;
    }
    if rev >> 8 != 1 {
        return None;
    }
    let bps = 1u32 << bps_shift;
    let cs = 1u64 << (bps_shift + spc_shift);
    if fat_off < 24 || fat_len == 0 || count == 0 || count > 0xFFFF_FFF5 {
        return None;
    }
    if heap_off < fat_off + fat_len * nfats as u64 {
        return None;
    }
    if fat_len * bps as u64 / 4 < count as u64 + 2 {
        return None;
    }
    let heap_end_sectors = heap_off + ((count as u64 * cs) >> bps_shift);
    if vol_len < heap_end_sectors {
        return None;
    }
    if root < 2 || root > count + 1 {
        return None;
    }
    Some(XGeom {
        bps,
        cluster_size: cs as u32,
        fat_offset: fat_off * bps as u64,
        fat_bytes: fat_len * bps as u64,
        nfats,
        heap_offset: heap_off * bps as u64,
        cluster_count: count,
        root_cluster: root,
        serial,
        total_size: vol_len.saturating_mul(bps as u64),
        used_backup: false,
        checksum_ok: false,
    })
}

fn read_region(src: &dyn BlockSource, at: u64, bps: u32) -> Option<Vec<u8>> {
    let mut r = vec![0u8; 12 * bps as usize];
    let (n, bad) = read_tolerant(src, at, &mut r, None);
    if n < r.len() || !bad.is_empty() {
        return None;
    }
    Some(r)
}

fn checksum_ok(region: &[u8], bps: u32) -> bool {
    let c = boot_checksum(region, bps as usize);
    let s11 = &region[11 * bps as usize..12 * bps as usize];
    s11.chunks_exact(4).all(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == c)
}

/// The main boot region when it is intact, else the backup region (sector 12), else the main
/// boot sector alone when its fields are consistent but the checksum fails.
pub(crate) fn read_xgeom(src: &dyn BlockSource) -> Option<XGeom> {
    let mut first = vec![0u8; 512];
    let (n, _) = read_tolerant(src, 0, &mut first, None);
    let main = if n == 512 { parse_boot_sector(&first) } else { None };
    if let Some(g) = &main {
        if let Some(r) = read_region(src, 0, g.bps) {
            if checksum_ok(&r, g.bps) {
                return Some(XGeom { checksum_ok: true, ..g.clone() });
            }
        }
    }
    for shift in 9..=12u32 {
        let bps = 1u32 << shift;
        let Some(r) = read_region(src, 12 * bps as u64, bps) else { continue };
        if let Some(g) = parse_boot_sector(&r) {
            if g.bps == bps && checksum_ok(&r, bps) {
                return Some(XGeom { used_backup: true, checksum_ok: true, ..g });
            }
        }
    }
    main
}

/// True when the FAT starts with the media entries (F8 FF FF FF, FF FF FF FF): a real volume start.
pub(crate) fn fat_signature_ok(src: &dyn BlockSource, g: &XGeom) -> bool {
    let mut b = [0u8; 8];
    let (n, bad) = read_tolerant(src, g.fat_offset, &mut b, None);
    n == 8 && bad.is_empty() && b == [0xF8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
}
