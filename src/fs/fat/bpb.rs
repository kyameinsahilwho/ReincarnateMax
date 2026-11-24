//! FAT boot sector (BIOS parameter block) parsing and volume geometry.

use super::util::{rd16, rd32};
use crate::device::source::{read_tolerant, BlockSource};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FatKind {
    Fat12,
    Fat16,
    Fat32,
}

impl FatKind {
    pub fn name(self) -> &'static str {
        match self {
            FatKind::Fat12 => "FAT12",
            FatKind::Fat16 => "FAT16",
            FatKind::Fat32 => "FAT32",
        }
    }
}

/// Everything needed to find clusters, FATs and the root directory, in bytes from the volume start.
#[derive(Clone, Debug)]
pub(crate) struct Geom {
    pub kind: FatKind,
    pub bps: u32,
    pub cluster_size: u32,
    pub nfats: u32,
    pub total_sectors: u64,
    pub root_cluster: u32,
    pub fat_offset: u64,
    pub fat_bytes: u64,
    pub root_offset: u64,
    pub root_bytes: u64,
    pub data_offset: u64,
    /// Number of data clusters (valid cluster numbers are 2..=cluster_count+1), limited to the
    /// clusters that start inside the source.
    pub cluster_count: u32,
    /// The cluster count the BPB itself describes, before that limit. Directory entries are
    /// checked against it, so an entry pointing past the end of a truncated source still counts.
    pub bpb_cluster_count: u32,
    pub media: u8,
    pub serial: Option<u32>,
    pub bpb_label: String,
    pub used_backup: bool,
}

impl Geom {
    /// Highest cluster number a directory entry may name (from the BPB, not limited to the source).
    pub fn entry_max_cluster(&self) -> u32 {
        self.bpb_cluster_count.max(self.cluster_count).saturating_add(1)
    }
    pub fn valid_cluster(&self, c: u32) -> bool {
        c >= 2 && c <= self.cluster_count.saturating_add(1)
    }
    pub fn cluster_offset(&self, c: u32) -> u64 {
        self.data_offset + (c.max(2) as u64 - 2) * self.cluster_size as u64
    }
    pub fn total_size(&self) -> u64 {
        self.total_sectors * self.bps as u64
    }
    pub fn cluster_of(&self, off: u64) -> Option<u32> {
        if off < self.data_offset {
            return None;
        }
        let c = (off - self.data_offset) / self.cluster_size as u64 + 2;
        if c > self.cluster_count as u64 + 1 {
            return None;
        }
        Some(c as u32)
    }
}

/// Parse a FAT boot sector. Returns None unless every field is consistent.
pub(crate) fn parse_bpb(b: &[u8]) -> Option<Geom> {
    if b.len() < 512 || b[510] != 0x55 || b[511] != 0xAA {
        return None;
    }
    if !(b[0] == 0xEB || b[0] == 0xE9) {
        return None;
    }
    let bps = rd16(b, 11) as u32;
    if !matches!(bps, 512 | 1024 | 2048 | 4096) {
        return None;
    }
    let spc = b[13] as u32;
    if spc == 0 || !spc.is_power_of_two() || spc > 128 {
        return None;
    }
    let cluster_size = bps * spc;
    if cluster_size > 256 * 1024 {
        return None;
    }
    let reserved = rd16(b, 14) as u32;
    let nfats = b[16] as u32;
    if reserved == 0 || !(1..=2).contains(&nfats) {
        return None;
    }
    let root_entries = rd16(b, 17) as u32;
    let tot16 = rd16(b, 19) as u64;
    let media = b[21];
    if !(media == 0xF0 || media >= 0xF8) {
        return None;
    }
    let fatsz16 = rd16(b, 22) as u64;
    let tot32 = rd32(b, 32) as u64;
    let total = if tot16 != 0 { tot16 } else { tot32 };
    if total == 0 {
        return None;
    }
    let fat32_layout = fatsz16 == 0;
    let fatsz = if fat32_layout { rd32(b, 36) as u64 } else { fatsz16 };
    if fatsz == 0 {
        return None;
    }
    if fat32_layout && root_entries != 0 {
        return None;
    }
    if !fat32_layout && root_entries == 0 {
        return None;
    }
    let root_sectors = (root_entries as u64 * 32).div_ceil(bps as u64);
    let meta = reserved as u64 + nfats as u64 * fatsz + root_sectors;
    if total <= meta {
        return None;
    }
    let mut count = (total - meta) / spc as u64;
    if count == 0 {
        return None;
    }
    let kind = if fat32_layout {
        FatKind::Fat32
    } else if count < 4085 {
        FatKind::Fat12
    } else if count < 65525 {
        FatKind::Fat16
    } else {
        return None;
    };
    if count > 0x0FFF_FFF5 {
        return None;
    }
    // The FAT must be able to describe the clusters; if it is a little short, clamp (the clusters
    // past its end can't be allocated anyway).
    let fat_bytes = fatsz * bps as u64;
    let capacity = match kind {
        FatKind::Fat12 => fat_bytes * 2 / 3,
        FatKind::Fat16 => fat_bytes / 2,
        FatKind::Fat32 => fat_bytes / 4,
    };
    if capacity < 3 {
        return None;
    }
    if capacity < count + 2 {
        if capacity + 64 < count + 2 && capacity * 2 < count {
            return None;
        }
        count = capacity - 2;
    }
    let mut root_cluster = 0;
    if kind == FatKind::Fat32 {
        root_cluster = rd32(b, 44);
        if root_cluster < 2 || root_cluster as u64 > count + 1 {
            return None;
        }
        if rd16(b, 42) != 0 {
            return None;
        }
    }
    let sigpos = if kind == FatKind::Fat32 { 66 } else { 38 };
    let (serial, bpb_label) = if b[sigpos] == 0x29 || b[sigpos] == 0x28 {
        let serial = Some(rd32(b, sigpos + 1));
        let label = if b[sigpos] == 0x29 { label_from_bytes(&b[sigpos + 5..sigpos + 16]) } else { String::new() };
        (serial, label)
    } else {
        (None, String::new())
    };
    let fat_offset = reserved as u64 * bps as u64;
    let root_offset = fat_offset + nfats as u64 * fat_bytes;
    let root_bytes = root_sectors * bps as u64;
    Some(Geom {
        kind,
        bps,
        cluster_size,
        nfats,
        total_sectors: total,
        root_cluster,
        fat_offset,
        fat_bytes,
        root_offset,
        root_bytes,
        data_offset: root_offset + root_bytes,
        cluster_count: count as u32,
        bpb_cluster_count: count as u32,
        media,
        serial,
        bpb_label,
        used_backup: false,
    })
}

/// A volume label from 11 OEM bytes; "NO NAME" and blanks become "".
pub(crate) fn label_from_bytes(b: &[u8]) -> String {
    let s: String = b.iter().map(|&c| if c < 0x20 { ' ' } else { super::util::oem_char(c) }).collect();
    let s = s.trim_end().to_string();
    if s == "NO NAME" {
        String::new()
    } else {
        s
    }
}

/// Limit the cluster count to the clusters that start inside a source of `len` bytes, so a
/// damaged BPB can't make the FAT reader allocate and decode far more than the drive holds.
/// `total_sectors` and `bpb_cluster_count` keep the BPB's values (callers compare the size with
/// the partition, and directory entries are validated against the BPB's count).
pub(crate) fn fit_to_source(g: &mut Geom, len: u64) {
    if len == 0 {
        return;
    }
    let fit = len.saturating_sub(g.data_offset).div_ceil(g.cluster_size as u64).max(1);
    if (g.cluster_count as u64) > fit {
        g.cluster_count = fit as u32;
    }
}

/// Primary boot sector, then (FAT32) the backup copy at sector 6.
pub(crate) fn read_geom(src: &dyn BlockSource) -> Option<Geom> {
    let mut g = read_geom_raw(src)?;
    fit_to_source(&mut g, src.len());
    Some(g)
}

fn read_geom_raw(src: &dyn BlockSource) -> Option<Geom> {
    let mut buf = vec![0u8; 512];
    let (n, _) = read_tolerant(src, 0, &mut buf, None);
    if n == 512 {
        if let Some(g) = parse_bpb(&buf) {
            return Some(g);
        }
    }
    for s in [512u64, 4096, 1024, 2048] {
        let (n, bad) = read_tolerant(src, 6 * s, &mut buf, None);
        if n < 512 || !bad.is_empty() {
            continue;
        }
        if let Some(mut g) = parse_bpb(&buf) {
            if g.kind == FatKind::Fat32 && g.bps as u64 == s && rd16(&buf, 50) == 6 {
                g.used_backup = true;
                return Some(g);
            }
        }
    }
    None
}

/// True when the first FAT starts with the media descriptor entry (F8 FF FF 0F style), which
/// tells a real FAT volume start from a stray copy of a boot sector.
pub(crate) fn fat_signature_ok(src: &dyn BlockSource, g: &Geom) -> bool {
    let mut b = [0u8; 4];
    let (n, bad) = read_tolerant(src, g.fat_offset, &mut b, None);
    if n < 4 || !bad.is_empty() {
        return false;
    }
    if b[0] != g.media && !(b[0] >= 0xF0) {
        return false;
    }
    match g.kind {
        FatKind::Fat12 => b[1] == 0xFF && b[2] & 0x0F == 0x0F,
        FatKind::Fat16 => b[1] == 0xFF,
        FatKind::Fat32 => b[1] == 0xFF && b[2] == 0xFF && b[3] & 0x0F == 0x0F,
    }
}
