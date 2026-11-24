//! exFAT tests on a hand-built image: boot region with checksum, FAT, bitmap, up-case table, root
//! with live and deleted entry sets, subfolders, a fragmented file through the FAT chain.

use super::boot::boot_checksum;
use super::scan::set_checksum;
use super::*;
use crate::device::source::MemSource;
use crate::model::{flags, Condition, FileStatus, FoundFile, ScanCtx, ScanOptions, SPARSE};

const BPS: usize = 512;
const CS: usize = 4096;
const HEAP: usize = 64 * BPS;
const COUNT: u32 = 1016;
const FAT_OFF: usize = 32 * BPS;

fn content(seed: u32, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).max(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

fn coff(c: u32) -> usize {
    HEAP + (c as usize - 2) * CS
}

/// 2023-06-01 12:00:00 local, offset +1 h (4 x 15 min) -> 11:00 UTC.
const TS: u32 = ((2023 - 1980) << 25) | (6 << 21) | (1 << 16) | (12 << 11);
const TS_UTC_MS: i64 = 1_685_617_200_000;

fn file_set(name: &str, attr: u16, first: u32, len: u64, valid: u64, nfc: bool, deleted: bool) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let nn = units.len().div_ceil(15);
    let sc = 1 + nn;
    let mut v = vec![0u8; (sc + 1) * 32];
    v[0] = 0x85;
    v[1] = sc as u8;
    v[4..6].copy_from_slice(&attr.to_le_bytes());
    for o in [8, 12, 16] {
        v[o..o + 4].copy_from_slice(&TS.to_le_bytes());
    }
    v[22] = 0x80 | 4;
    v[23] = 0x80 | 4;
    v[24] = 0x80 | 4;
    let s = &mut v[32..64];
    s[0] = 0xC0;
    s[1] = 1 | if nfc { 2 } else { 0 };
    s[3] = units.len() as u8;
    s[8..16].copy_from_slice(&valid.to_le_bytes());
    s[20..24].copy_from_slice(&first.to_le_bytes());
    s[24..32].copy_from_slice(&len.to_le_bytes());
    for k in 0..nn {
        let e = &mut v[64 + k * 32..96 + k * 32];
        e[0] = 0xC1;
        for j in 0..15 {
            let u = units.get(k * 15 + j).copied().unwrap_or(0);
            e[2 + j * 2..4 + j * 2].copy_from_slice(&u.to_le_bytes());
        }
    }
    let c = set_checksum(&v);
    v[2..4].copy_from_slice(&c.to_le_bytes());
    if deleted {
        for k in 0..=sc {
            v[k * 32] &= 0x7F;
        }
    }
    v
}

struct Img {
    data: Vec<u8>,
    files: Vec<(&'static str, &'static str, Vec<u8>)>,
}

fn set_fat(d: &mut [u8], c: u32, v: u32) {
    let o = FAT_OFF + c as usize * 4;
    d[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

fn set_bit(d: &mut [u8], c: u32) {
    let i = (c - 2) as usize;
    d[coff(2) + i / 8] |= 1 << (i % 8);
}

fn root_system_entries() -> Vec<u8> {
    let mut v = vec![0u8; 96];
    v[0] = 0x83;
    let label: Vec<u16> = "MYEXFAT".encode_utf16().collect();
    v[1] = label.len() as u8;
    for (j, u) in label.iter().enumerate() {
        v[2 + j * 2..4 + j * 2].copy_from_slice(&u.to_le_bytes());
    }
    v[32] = 0x81;
    v[32 + 20..32 + 24].copy_from_slice(&2u32.to_le_bytes());
    v[32 + 24..32 + 32].copy_from_slice(&127u64.to_le_bytes());
    v[64] = 0x82;
    v[64 + 20..64 + 24].copy_from_slice(&3u32.to_le_bytes());
    v[64 + 24..64 + 32].copy_from_slice(&128u64.to_le_bytes());
    v
}

fn build() -> Img {
    let mut d = vec![0u8; 4 << 20];
    // Boot sector.
    let b = &mut d[..512];
    b[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
    b[3..11].copy_from_slice(b"EXFAT   ");
    b[72..80].copy_from_slice(&8192u64.to_le_bytes());
    b[80..84].copy_from_slice(&32u32.to_le_bytes());
    b[84..88].copy_from_slice(&8u32.to_le_bytes());
    b[88..92].copy_from_slice(&64u32.to_le_bytes());
    b[92..96].copy_from_slice(&COUNT.to_le_bytes());
    b[96..100].copy_from_slice(&4u32.to_le_bytes());
    b[100..104].copy_from_slice(&0x1234_ABCDu32.to_le_bytes());
    b[104..106].copy_from_slice(&0x0100u16.to_le_bytes());
    b[108] = 9;
    b[109] = 3;
    b[110] = 1;
    b[111] = 0x80;
    b[510] = 0x55;
    b[511] = 0xAA;
    let c = boot_checksum(&d[..12 * BPS], BPS);
    for k in 0..BPS / 4 {
        d[11 * BPS + k * 4..11 * BPS + k * 4 + 4].copy_from_slice(&c.to_le_bytes());
    }
    let (main, rest) = d.split_at_mut(12 * BPS);
    rest[..12 * BPS].copy_from_slice(main);
    // FAT.
    set_fat(&mut d, 0, 0xFFFF_FFF8);
    set_fat(&mut d, 1, 0xFFFF_FFFF);
    for c in [2, 3, 4, 5] {
        set_fat(&mut d, c, 0xFFFF_FFFF);
    }
    set_fat(&mut d, 16, 18);
    set_fat(&mut d, 18, 0xFFFF_FFFF);
    // The chain of a deleted fragmented file, left in place.
    set_fat(&mut d, 9, 11);
    set_fat(&mut d, 11, 10);
    set_fat(&mut d, 10, 0xFFFF_FFFF);
    for c in [2, 3, 4, 5, 6, 7, 16, 18] {
        set_bit(&mut d, c);
    }
    // Up-case table content (not interpreted).
    for i in 0..64u16 {
        d[coff(3) + i as usize * 2..coff(3) + i as usize * 2 + 2].copy_from_slice(&i.to_le_bytes());
    }
    let live = content(1, 8000);
    let deleted_jpg = content(2, 3000);
    let frag = content(3, 10000);
    let inner = content(4, 2000);
    let photo = content(5, 5000);
    let livefrag = content(6, 8000);
    let put = |d: &mut Vec<u8>, c: u32, data: &[u8]| {
        let o = coff(c);
        d[o..o + data.len()].copy_from_slice(data);
    };
    put(&mut d, 6, &live);
    put(&mut d, 8, &deleted_jpg);
    put(&mut d, 9, &frag[..CS]);
    put(&mut d, 11, &frag[CS..2 * CS]);
    put(&mut d, 10, &frag[2 * CS..]);
    put(&mut d, 12, &inner);
    put(&mut d, 14, &photo);
    put(&mut d, 16, &livefrag[..CS]);
    put(&mut d, 18, &livefrag[CS..]);
    // Root directory.
    let mut root = root_system_entries();
    root.extend(file_set("live.txt", 0x20, 6, 8000, 8000, true, false));
    root.extend(file_set("deleted.jpg", 0x20, 8, 3000, 3000, true, true));
    root.extend(file_set("A fragmented file with a long name.bin", 0x20, 9, 10000, 10000, false, true));
    root.extend(file_set("Sub", 0x10, 5, CS as u64, CS as u64, false, false));
    root.extend(file_set("Gone", 0x10, 13, CS as u64, CS as u64, true, true));
    root.extend(file_set("livefrag.dat", 0x20, 16, 8000, 8000, false, false));
    root.extend(file_set("over.txt", 0x20, 6, 100, 100, true, true));
    put(&mut d, 4, &root);
    put(&mut d, 5, &file_set("inner.doc", 0x20, 12, 2000, 2000, true, true));
    put(&mut d, 13, &file_set("lost photo.png", 0x20, 14, 5000, 5000, true, true));
    Img {
        data: d,
        files: vec![
            ("", "deleted.jpg", deleted_jpg),
            ("", "A fragmented file with a long name.bin", frag),
            ("\\Sub", "inner.doc", inner),
            ("\\Gone", "lost photo.png", photo),
            ("", "live.txt", live),
            ("", "livefrag.dat", livefrag),
        ],
    }
}

fn read_all(src: &MemSource, f: &FoundFile) -> Vec<u8> {
    let mut buf = vec![0u8; f.size as usize];
    let (n, _) = crate::fileread::read_at(Some(src), f, 0, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn scan(src: &MemSource, existing: bool) -> (Vec<FoundFile>, crate::model::EngineSummary) {
    let (ctx, t) = ScanCtx::for_test(ScanOptions { include_existing: Some(existing), ..Default::default() }, src.len());
    let sum = quick_scan(src, &ctx).unwrap();
    let files = t.files.lock().unwrap().clone();
    (files, sum)
}

#[test]
fn probe_reads_boot_region_and_label() {
    let img = build();
    let src = MemSource::new(img.data.clone());
    let p = probe(&src).expect("probe");
    assert_eq!(p.fs, "exFAT");
    assert_eq!(p.label, "MYEXFAT");
    assert_eq!(p.cluster_size, 4096);
    assert_eq!(p.serial, "1234-ABCD");
    assert!(!p.used_backup_boot);
    // Damaged main boot sector: the backup region is used.
    let mut d = img.data;
    d[100] ^= 0xFF;
    let p = probe(&MemSource::new(d.clone())).expect("probe from backup");
    assert!(p.used_backup_boot);
    d[..512].fill(0);
    assert!(probe(&MemSource::new(d)).unwrap().used_backup_boot);
}

#[test]
fn quick_scan_finds_deleted_and_existing() {
    let img = build();
    let src = MemSource::new(img.data.clone());
    let (files, sum) = scan(&src, false);
    assert_eq!(sum.deleted, 5, "{files:#?}");
    for (folder, name, data) in &img.files[..4] {
        let f = files.iter().find(|f| &f.name == name).unwrap_or_else(|| panic!("{name}: {files:#?}"));
        assert_eq!(&f.folder, folder, "{name}");
        assert_eq!(f.status, FileStatus::Deleted);
        assert_eq!(f.condition, Condition::Excellent, "{name}: {}", f.note);
        assert_eq!(&read_all(&src, f), data, "{name}");
        assert_eq!(f.modified, Some(TS_UTC_MS));
    }
    let frag = files.iter().find(|f| f.name.starts_with("A fragmented")).unwrap();
    assert!(frag.fragmented);
    assert_eq!(frag.extents.len(), 3);
    let over = files.iter().find(|f| f.name == "over.txt").unwrap();
    assert_eq!(over.condition, Condition::Partial);
    assert_ne!(over.flags & flags::OVERWRITTEN, 0);
    assert!(!files.iter().any(|f| f.name == "live.txt"));

    let (files, _) = scan(&src, true);
    for (folder, name, data) in &img.files[4..] {
        let f = files.iter().find(|f| &f.name == name).unwrap();
        assert_eq!(&f.folder, folder);
        assert_eq!(f.status, FileStatus::Existing);
        assert_eq!(&read_all(&src, f), data, "{name}");
    }
    assert!(files.iter().find(|f| f.name == "livefrag.dat").unwrap().fragmented);
}

#[test]
fn valid_data_length_reads_zeros_after() {
    let mut img = build();
    // Shrink live.txt's valid data length to 5000 bytes.
    let root = coff(4);
    let p = root + 96; // first set after the 3 system entries
    img.data[p + 32 + 8..p + 32 + 16].copy_from_slice(&5000u64.to_le_bytes());
    let mut set = img.data[p..p + 96].to_vec();
    set[2] = 0;
    set[3] = 0;
    let c = set_checksum(&set);
    img.data[p + 2..p + 4].copy_from_slice(&c.to_le_bytes());
    let src = MemSource::new(img.data);
    let (files, _) = scan(&src, true);
    let f = files.iter().find(|f| f.name == "live.txt").unwrap();
    assert_eq!(f.extents.last().unwrap().offset, SPARSE);
    let data = read_all(&src, f);
    assert_eq!(&data[..5000], &img.files[4].2[..5000]);
    assert!(data[5000..].iter().all(|&b| b == 0));
}

#[test]
fn sweep_rebuilds_folders_after_format() {
    let img = build();
    let mut d = img.data.clone();
    // Simulate a quick format: fresh root (system entries only), bitmap with only 2..4, FAT reset.
    d[coff(4)..coff(4) + CS].fill(0);
    let sys = root_system_entries();
    d[coff(4)..coff(4) + sys.len()].copy_from_slice(&sys);
    d[coff(2)..coff(2) + 127].fill(0);
    for c in [2, 3, 4] {
        set_bit(&mut d, c);
    }
    d[FAT_OFF + 8..FAT_OFF + 8 * BPS].fill(0);
    for c in [2, 3, 4] {
        set_fat(&mut d, c, 0xFFFF_FFFF);
    }
    let src = MemSource::new(d);
    let (files, _) = scan(&src, true);
    assert!(files.is_empty());
    let (ctx, t) = ScanCtx::for_test(ScanOptions::default(), src.len());
    let v = sweep_visitor(probe(&src).as_ref());
    for (i, chunk) in src.data.chunks(1 << 20).enumerate() {
        v.visit(&src, (i << 20) as u64, chunk, &ctx);
    }
    let sum = v.finish(&src, &ctx).unwrap();
    let files = t.files.lock().unwrap().clone();
    assert!(sum.lost_folders >= 2, "{sum:?}");
    let inner = files.iter().find(|f| f.name == "inner.doc").expect("inner.doc");
    assert_eq!(inner.folder, "\\Lost folders\\Folder 5");
    assert_eq!(inner.status, FileStatus::Lost);
    assert_ne!(inner.flags & flags::LOOSE_RECORD, 0);
    assert_eq!(inner.condition, Condition::Excellent, "{}", inner.note);
    assert_eq!(read_all(&src, inner), img.files[2].2);
    let photo = files.iter().find(|f| f.name == "lost photo.png").expect("photo");
    assert_eq!(photo.folder, "\\Lost folders\\Folder 13");
    assert_eq!(read_all(&src, photo), img.files[3].2);
}

#[test]
fn random_and_corrupted_input_never_panics() {
    let mut x: u32 = 0x9E37_79B9;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    };
    for _ in 0..20 {
        let data: Vec<u8> = (0..256 * 1024).map(|_| rnd() as u8).collect();
        let src = MemSource::new(data);
        let _ = probe(&src);
        let (ctx, _) = ScanCtx::for_test(ScanOptions { include_existing: Some(true), ..Default::default() }, src.len());
        let _ = quick_scan(&src, &ctx);
        let v = sweep_visitor(None);
        v.visit(&src, 0, &src.data, &ctx);
        let _ = v.finish(&src, &ctx);
    }
    let base = build().data;
    for round in 0..60 {
        let mut d = base.clone();
        for _ in 0..(20 + round * 10) {
            // Damage the metadata area and the first directory/data clusters (keep the boot region
            // intact half of the time so the deeper code runs).
            let lo = if round % 2 == 0 { 24 * BPS } else { 0 };
            let pos = lo + (rnd() as usize % (coff(20) - lo));
            d[pos] = rnd() as u8;
        }
        let src = MemSource::new(d);
        let _ = probe(&src);
        let (ctx, _) = ScanCtx::for_test(ScanOptions { include_existing: Some(true), ..Default::default() }, src.len());
        let _ = quick_scan(&src, &ctx);
        let v = sweep_visitor(None);
        v.visit(&src, 0, &src.data, &ctx);
        let _ = v.finish(&src, &ctx);
    }
}

#[test]
fn damaged_bitmap_length_is_clamped() {
    let mut img = build();
    // Bitmap entry (second system entry) and up-case entry with absurd lengths.
    let root = coff(4);
    img.data[root + 32 + 24..root + 32 + 32].copy_from_slice(&(1u64 << 40).to_le_bytes());
    img.data[root + 64 + 24..root + 64 + 32].copy_from_slice(&(1u64 << 40).to_le_bytes());
    let src = MemSource::new(img.data.clone());
    let v = scan::mount(&src, None).unwrap();
    assert_eq!(v.bitmap.as_ref().unwrap().len(), 127);
    // Only the bitmap's own cluster and the up-case table's 128 KiB are metadata, not the volume.
    assert!(v.meta.contains(coff(2) as u64));
    assert!(!v.meta.contains(coff(100) as u64));
    let (files, _) = scan(&src, false);
    let f = files.iter().find(|f| f.name == "deleted.jpg").unwrap();
    assert_eq!(f.condition, Condition::Excellent);
}

#[test]
fn deleted_folder_with_reused_start_does_not_hide_live_folder() {
    let mut img = build();
    // Root: a deleted folder "Old" whose start cluster (5) now belongs to the live folder "Sub".
    let mut root = root_system_entries();
    root.extend(file_set("Old", 0x10, 5, CS as u64, CS as u64, false, true));
    root.extend(file_set("Sub", 0x10, 5, CS as u64, CS as u64, false, false));
    img.data[coff(4)..coff(4) + CS].fill(0);
    img.data[coff(4)..coff(4) + root.len()].copy_from_slice(&root);
    let src = MemSource::new(img.data.clone());
    let (files, _) = scan(&src, false);
    let f = files.iter().find(|f| f.name == "inner.doc").unwrap_or_else(|| panic!("{files:#?}"));
    assert_eq!(f.folder, r"\Sub");
    assert_eq!(read_all(&src, f), img.files[2].2);
}

#[test]
fn fat_loops_are_cut() {
    let mut img = build();
    // The root's chain points back to itself, and so does a live file's first cluster.
    set_fat(&mut img.data, 4, 4);
    set_fat(&mut img.data, 16, 16);
    let src = MemSource::new(img.data.clone());
    let v = scan::mount(&src, None).unwrap();
    assert_eq!(v.chain(4, 1 << 16), (vec![4], scan::End::Broken));
    let (files, _) = scan(&src, true);
    assert_eq!(files.iter().filter(|f| f.name == "deleted.jpg").count(), 1);
    let lf = files.iter().find(|f| f.name == "livefrag.dat").unwrap();
    assert_eq!(lf.condition, Condition::Partial, "{}", lf.note);
    assert_eq!(lf.extents.len(), 1);
}
