//! Minimal NTFS image generator for tests: boot sector (+ backup), an MFT with the system records
//! the engine needs ($MFT, $MFTMirr, $Volume, root, $Bitmap) and whatever records a test adds.
//! 4 KiB clusters, 1 KiB records.

use super::record::build::*;
use super::record::*;
use super::runs::Run;

pub const CS: u64 = 4096;
pub const RS: usize = 1024;
pub const MIRR_LCN: u64 = 2;
pub const BITMAP_LCN: u64 = 8;
pub const MFT_LCN: u64 = 16;
pub const MFT_RECORDS: u64 = 128;
pub const FIRST_DATA_LCN: u64 = 64;

pub fn boot_sector(total_sectors: u64, mft_lcn: u64, mirr_lcn: u64) -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
    b[3..11].copy_from_slice(b"NTFS    ");
    b[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
    b[0x0D] = (CS / 512) as u8;
    b[0x15] = 0xF8;
    b[0x28..0x30].copy_from_slice(&total_sectors.to_le_bytes());
    b[0x30..0x38].copy_from_slice(&mft_lcn.to_le_bytes());
    b[0x38..0x40].copy_from_slice(&mirr_lcn.to_le_bytes());
    b[0x40] = 0xF6; // 2^10 = 1024-byte records
    b[0x44] = 1;
    b[0x48..0x50].copy_from_slice(&0xA1B2_C3D4_0000_1234u64.to_le_bytes());
    b[510] = 0x55;
    b[511] = 0xAA;
    b
}

pub struct Img {
    pub total_clusters: u64,
    pub data: Vec<u8>,
    pub used: Vec<bool>,
    pub records: Vec<Option<Vec<u8>>>,
    pub label: String,
    next: u64,
}

impl Img {
    pub fn new(total_clusters: u64) -> Img {
        let mut img = Img {
            total_clusters,
            data: vec![0u8; (total_clusters * CS) as usize],
            used: vec![false; total_clusters as usize],
            records: vec![None; MFT_RECORDS as usize],
            label: "TESTVOL".into(),
            next: FIRST_DATA_LCN,
        };
        img.mark(0, 1, true);
        img.mark(MIRR_LCN, 1, true);
        img.mark(BITMAP_LCN, 1, true);
        img.mark(MFT_LCN, MFT_RECORDS * RS as u64 / CS, true);
        img
    }

    /// Next free clusters (not marked used: callers decide).
    pub fn alloc(&mut self, n: u64) -> u64 {
        let l = self.next;
        self.next += n;
        l
    }
    pub fn write(&mut self, lcn: u64, bytes: &[u8]) {
        let o = (lcn * CS) as usize;
        self.data[o..o + bytes.len()].copy_from_slice(bytes);
    }
    pub fn mark(&mut self, lcn: u64, n: u64, used: bool) {
        for c in lcn..lcn + n {
            self.used[c as usize] = used;
        }
    }
    pub fn put(&mut self, num: u64, rec: Vec<u8>) {
        self.records[num as usize] = Some(rec);
    }

    /// Store `content` in fresh clusters; returns its single run.
    pub fn store(&mut self, content: &[u8], used: bool) -> Run {
        let n = (content.len() as u64).div_ceil(CS).max(1);
        let l = self.alloc(n);
        self.write(l, content);
        self.mark(l, n, used);
        Run { len: n, lcn: Some(l) }
    }

    fn system_records(&mut self) {
        let root = mk_ref(5, 5);
        let mft_bytes = MFT_RECORDS * RS as u64;
        let sys = |num: u32, name: &str, extra: Vec<Vec<u8>>| {
            let mut a = vec![std_info(0, 0, 0, 6), file_name(root, name, 3, 0, false)];
            a.extend(extra);
            record(RS, num, num.max(1) as u16, REC_IN_USE, 0, &a)
        };
        let r0 = sys(
            0,
            "$MFT",
            vec![attr_nonresident(ATTR_DATA, "", &[Run { len: mft_bytes / CS, lcn: Some(MFT_LCN) }], 0, mft_bytes, mft_bytes, mft_bytes, 0, 0)],
        );
        let r1 = sys(1, "$MFTMirr", vec![attr_nonresident(ATTR_DATA, "", &[Run { len: 1, lcn: Some(MIRR_LCN) }], 0, CS, CS, CS, 0, 0)]);
        let r2 = sys(2, "$LogFile", vec![]);
        let label16: Vec<u8> = self.label.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let r3 = sys(3, "$Volume", vec![attr_resident(ATTR_VOLUME_NAME, "", &label16, 0)]);
        let bm_bytes = self.total_clusters.div_ceil(8);
        let r6 = sys(6, "$Bitmap", vec![attr_nonresident(ATTR_DATA, "", &[Run { len: 1, lcn: Some(BITMAP_LCN) }], 0, CS, bm_bytes, bm_bytes, 0, 0)]);
        let r5 = record(
            RS,
            5,
            5,
            REC_IN_USE | REC_DIRECTORY,
            0,
            &[std_info(0, 0, 0, 6), file_name(root, ".", 3, 0, true), attr_resident(ATTR_INDEX_ROOT, "$I30", &[0u8; 32], 0)],
        );
        for (n, r) in [(0u64, r0), (1, r1), (2, r2), (3, r3), (5, r5), (6, r6)] {
            if self.records[n as usize].is_none() {
                self.records[n as usize] = Some(r);
            }
        }
    }

    /// The finished image bytes.
    pub fn build(mut self) -> Vec<u8> {
        self.system_records();
        let mut bm = vec![0u8; CS as usize];
        for (c, &u) in self.used.iter().enumerate() {
            if u {
                bm[c / 8] |= 1 << (c % 8);
            }
        }
        self.write(BITMAP_LCN, &bm);
        for (n, r) in self.records.clone().into_iter().enumerate() {
            if let Some(r) = r {
                let o = (MFT_LCN * CS) as usize + n * RS;
                self.data[o..o + RS].copy_from_slice(&r);
                if n < 4 {
                    let m = (MIRR_LCN * CS) as usize + n * RS;
                    self.data[m..m + RS].copy_from_slice(&r);
                }
            }
        }
        let sectors = self.total_clusters * CS / 512;
        let bs = boot_sector(sectors - 1, MFT_LCN, MIRR_LCN);
        self.data[..512].copy_from_slice(&bs);
        let last = self.data.len() - 512;
        self.data[last..].copy_from_slice(&bs);
        self.data
    }
}

/// A deleted/in-use file record with one unnamed $DATA attribute (`data_attr`) plus extras.
pub fn file_rec(num: u64, seq: u16, in_use: bool, parent: u64, name: &str, size: u64, attrs: Vec<Vec<u8>>) -> Vec<u8> {
    let mut a = vec![std_info(130_000_000_000_000_000, 131_000_000_000_000_000, 131_000_000_000_000_000, 0x20), file_name(parent, name, 1, size, false)];
    a.extend(attrs);
    record(RS, num as u32, seq, if in_use { REC_IN_USE } else { 0 }, 0, &a)
}

pub fn dir_rec(num: u64, seq: u16, in_use: bool, parent: u64, name: &str) -> Vec<u8> {
    record(
        RS,
        num as u32,
        seq,
        REC_DIRECTORY | if in_use { REC_IN_USE } else { 0 },
        0,
        &[std_info(0, 0, 0, 0x10), file_name(parent, name, 1, 0, true), attr_resident(ATTR_INDEX_ROOT, "$I30", &[0u8; 32], 0)],
    )
}

pub fn data_nr(runs: &[Run], size: u64) -> Vec<u8> {
    let alloc: u64 = runs.iter().map(|r| r.len).sum::<u64>() * CS;
    attr_nonresident(ATTR_DATA, "", runs, 0, alloc, size, size, 0, 0)
}

pub fn data_res(bytes: &[u8]) -> Vec<u8> {
    attr_resident(ATTR_DATA, "", bytes, 0)
}

/// Deterministic test content.
pub fn content(seed: u32, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}
