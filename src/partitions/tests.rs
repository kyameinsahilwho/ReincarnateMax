//! Partition tests on synthetic disk images (volumes formatted with `fatfs`).

use super::*;
use crate::device::source::MemSource;
use crate::model::{ScanCtx, ScanOptions};
use fatfs::{FatType, FormatVolumeOptions};
use std::io::Cursor;
use std::time::Duration;

const MIB: usize = 1 << 20;

fn fmt(img: &mut [u8], off: usize, len: usize, kind: FatType, cluster: u32, label: &[u8; 11]) {
    let opts = FormatVolumeOptions::new().fat_type(kind).bytes_per_cluster(cluster).volume_label(*label);
    fatfs::format_volume(Cursor::new(&mut img[off..off + len]), opts).unwrap();
}

fn mbr_entry(sector: &mut [u8], i: usize, boot: u8, ptype: u8, start: u32, count: u32) {
    let e = &mut sector[446 + i * 16..462 + i * 16];
    e.fill(0);
    e[0] = boot;
    e[4] = ptype;
    e[8..12].copy_from_slice(&start.to_le_bytes());
    e[12..16].copy_from_slice(&count.to_le_bytes());
    sector[510] = 0x55;
    sector[511] = 0xAA;
}

const S: u32 = 512;
fn lba(bytes: usize) -> u32 {
    (bytes / 512) as u32
}

/// 64 MiB: FAT16 primary at 1 MiB, extended at 20 MiB with two logical drives.
fn mbr_disk() -> Vec<u8> {
    let mut d = vec![0u8; 64 * MIB];
    fmt(&mut d, MIB, 16 * MIB, FatType::Fat16, 512, b"PRIMARY    ");
    mbr_entry(&mut d[..512], 0, 0x80, 0x06, lba(MIB), lba(16 * MIB));
    mbr_entry(&mut d[..512], 1, 0, 0x0F, lba(20 * MIB), lba(40 * MIB));
    // EBR 1 at 20 MiB: logical FAT12 at +1 MiB (4 MiB); next EBR at ext + 8 MiB.
    let ebr1 = 20 * MIB;
    mbr_entry(&mut d[ebr1..ebr1 + 512], 0, 0, 0x01, lba(MIB), lba(4 * MIB));
    mbr_entry(&mut d[ebr1..ebr1 + 512], 1, 0, 0x05, lba(8 * MIB), lba(20 * MIB));
    fmt(&mut d, ebr1 + MIB, 4 * MIB, FatType::Fat12, 2048, b"LOGICAL1   ");
    let ebr2 = 28 * MIB;
    mbr_entry(&mut d[ebr2..ebr2 + 512], 0, 0, 0x06, lba(MIB), lba(16 * MIB));
    fmt(&mut d, ebr2 + MIB, 16 * MIB, FatType::Fat16, 512, b"LOGICAL2   ");
    d
}

#[test]
fn mbr_with_logical_partitions() {
    let d = mbr_disk();
    let r = analyze(&MemSource::new(d)).unwrap();
    assert_eq!(r.style, "MBR");
    let names: Vec<_> = r.entries.iter().map(|e| (e.number, e.type_name.as_str(), e.fs.clone(), e.status.as_str())).collect();
    assert_eq!(r.entries.len(), 4, "{names:?}");
    let p1 = &r.entries[0];
    assert_eq!((p1.offset, p1.size), (MIB as u64, 16 * MIB as u64));
    assert_eq!(p1.fs.as_deref(), Some("FAT16"));
    assert_eq!(p1.label.as_deref(), Some("PRIMARY"));
    assert_eq!(p1.status, "ok");
    assert_eq!(r.entries[1].type_name, "Extended");
    let l1 = r.entries.iter().find(|e| e.number == Some(5)).unwrap();
    assert_eq!(l1.offset, 21 * MIB as u64);
    assert_eq!(l1.fs.as_deref(), Some("FAT12"));
    assert_eq!(l1.label.as_deref(), Some("LOGICAL1"));
    let l2 = r.entries.iter().find(|e| e.number == Some(6)).unwrap();
    assert_eq!(l2.offset, 29 * MIB as u64);
    assert_eq!(l2.fs.as_deref(), Some("FAT16"));
    // 45..64 MiB is free (19 MiB >= 16 MiB); the gaps inside the extended partition are smaller.
    assert_eq!(r.unallocated, vec![(45 * MIB as u64, 64 * MIB as u64)]);
}

#[test]
fn ebr_loop_is_guarded() {
    let mut d = mbr_disk();
    let ebr2 = 28 * MIB;
    // Second EBR points back to the first one.
    mbr_entry(&mut d[ebr2..ebr2 + 512], 1, 0, 0x05, 0, lba(4 * MIB));
    let r = analyze(&MemSource::new(d)).unwrap();
    assert!(r.notes.iter().any(|n| n.contains("loops")), "{:?}", r.notes);
}

fn guid_bytes(s: &str) -> [u8; 16] {
    let h: String = s.chars().filter(|c| *c != '-').collect();
    let b: Vec<u8> = (0..16).map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap()).collect();
    let mut o = [0u8; 16];
    o[0..4].copy_from_slice(&[b[3], b[2], b[1], b[0]]);
    o[4..6].copy_from_slice(&[b[5], b[4]]);
    o[6..8].copy_from_slice(&[b[7], b[6]]);
    o[8..16].copy_from_slice(&b[8..16]);
    o
}

const EFI: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
const MSR: &str = "E3C9E316-0B5C-4DB8-817D-F92DF00215AE";
const DATA: &str = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7";

fn write_gpt(d: &mut [u8], parts: &[(&str, u64, u64, &str)]) {
    let n = (d.len() / 512) as u64;
    mbr_entry(&mut d[..512], 0, 0, 0xEE, 1, (n - 1) as u32);
    let mut entries = vec![0u8; 128 * 128];
    for (i, (t, first, last, name)) in parts.iter().enumerate() {
        let e = &mut entries[i * 128..(i + 1) * 128];
        e[..16].copy_from_slice(&guid_bytes(t));
        e[16] = i as u8 + 1;
        e[32..40].copy_from_slice(&first.to_le_bytes());
        e[40..48].copy_from_slice(&last.to_le_bytes());
        for (k, u) in name.encode_utf16().enumerate() {
            e[56 + k * 2..58 + k * 2].copy_from_slice(&u.to_le_bytes());
        }
    }
    let ecrc = crc32fast::hash(&entries);
    let header = |my: u64, alt: u64, elba: u64| -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[0..8].copy_from_slice(b"EFI PART");
        h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        h[12..16].copy_from_slice(&92u32.to_le_bytes());
        h[24..32].copy_from_slice(&my.to_le_bytes());
        h[32..40].copy_from_slice(&alt.to_le_bytes());
        h[40..48].copy_from_slice(&34u64.to_le_bytes());
        h[48..56].copy_from_slice(&(n - 34).to_le_bytes());
        h[56] = 0x42;
        h[72..80].copy_from_slice(&elba.to_le_bytes());
        h[80..84].copy_from_slice(&128u32.to_le_bytes());
        h[84..88].copy_from_slice(&128u32.to_le_bytes());
        h[88..92].copy_from_slice(&ecrc.to_le_bytes());
        let c = crc32fast::hash(&h[..92]);
        h[16..20].copy_from_slice(&c.to_le_bytes());
        h
    };
    d[512..1024].copy_from_slice(&header(1, n - 1, 2));
    d[1024..1024 + entries.len()].copy_from_slice(&entries);
    let be = ((n - 33) * 512) as usize;
    d[be..be + entries.len()].copy_from_slice(&entries);
    let bh = ((n - 1) * 512) as usize;
    d[bh..bh + 512].copy_from_slice(&header(n - 1, 1, n - 33));
}

fn gpt_disk() -> Vec<u8> {
    let mut d = vec![0u8; 96 * MIB];
    fmt(&mut d, MIB, 16 * MIB, FatType::Fat16, 512, b"SYSTEM     ");
    fmt(&mut d, 25 * MIB, 32 * MIB, FatType::Fat16, 1024, b"DATAVOL    ");
    let l = |b: usize| (b / 512) as u64;
    write_gpt(
        &mut d,
        &[
            (EFI, l(MIB), l(17 * MIB) - 1, "EFI system partition"),
            (MSR, l(17 * MIB), l(25 * MIB) - 1, "Microsoft reserved partition"),
            (DATA, l(25 * MIB), l(57 * MIB) - 1, "Basic data partition"),
        ],
    );
    d
}

#[test]
fn gpt_entries_and_health() {
    let r = analyze(&MemSource::new(gpt_disk())).unwrap();
    assert_eq!(r.style, "GPT");
    assert_eq!(r.gpt, Some(GptHealth { primary_ok: true, backup_ok: true }));
    assert_eq!(r.entries.len(), 3);
    let t: Vec<&str> = r.entries.iter().map(|e| e.type_name.as_str()).collect();
    assert_eq!(t, vec!["EFI system", "Microsoft reserved", "Basic data"]);
    assert_eq!(r.entries[0].fs.as_deref(), Some("FAT16"));
    assert_eq!(r.entries[0].label.as_deref(), Some("SYSTEM"));
    assert_eq!(r.entries[1].fs, None);
    assert_eq!(r.entries[1].status, "ok");
    assert_eq!(r.entries[1].label.as_deref(), Some("Microsoft reserved partition"));
    assert_eq!(r.entries[2].label.as_deref(), Some("DATAVOL"));
    assert!(r.entries.iter().all(|e| e.found_by == "gpt"));
    assert_eq!(r.unallocated.len(), 1);
    assert_eq!(r.unallocated[0].0, 57 * MIB as u64);
}

#[test]
fn damaged_primary_gpt_uses_backup() {
    let mut d = gpt_disk();
    d[512 + 40] ^= 0x01; // breaks the header CRC
    let r = analyze(&MemSource::new(d.clone())).unwrap();
    assert_eq!(r.gpt, Some(GptHealth { primary_ok: false, backup_ok: true }));
    assert_eq!(r.entries.len(), 3);
    assert!(r.entries.iter().all(|e| e.found_by == "gptBackup"));
    assert!(r.notes.iter().any(|n| n.contains("backup copy was used")));
    // Entries array damaged instead: same outcome.
    let mut d2 = gpt_disk();
    d2[1024 + 60] ^= 0xFF;
    let r = analyze(&MemSource::new(d2)).unwrap();
    assert_eq!(r.gpt, Some(GptHealth { primary_ok: false, backup_ok: true }));
    // Both gone: GPT style, no entries, advice to search.
    d[96 * MIB - 512..].fill(0);
    let r = analyze(&MemSource::new(d)).unwrap();
    assert_eq!(r.style, "GPT");
    assert!(r.entries.is_empty());
    assert!(r.notes.iter().any(|n| n.contains("Search for lost partitions")));
}

/// 80 MiB: FAT16 at 1 MiB (listed), FAT32 at 20 MiB (40 MiB), FAT16 at 62 MiB (16 MiB).
fn lost_disk() -> Vec<u8> {
    let mut d = vec![0u8; 80 * MIB];
    fmt(&mut d, MIB, 16 * MIB, FatType::Fat16, 512, b"KEPT       ");
    fmt(&mut d, 20 * MIB, 40 * MIB, FatType::Fat32, 512, b"BIGONE     ");
    fmt(&mut d, 62 * MIB, 16 * MIB, FatType::Fat16, 512, b"GONE       ");
    mbr_entry(&mut d[..512], 0, 0x80, 0x06, lba(MIB), lba(16 * MIB));
    mbr_entry(&mut d[..512], 1, 0, 0x0C, lba(20 * MIB), lba(40 * MIB));
    // Partition 3 (62 MiB) was deleted from the table.
    d
}

fn search_with(d: Vec<u8>, budget: Duration) -> PartitionReport {
    let src = MemSource::new(d);
    let (ctx, _) = ScanCtx::for_test(ScanOptions { mode: "partitions".into(), ..Default::default() }, src.len());
    search::search(&src, &ctx, budget).unwrap()
}

#[test]
fn search_finds_deleted_partition() {
    for budget in [Duration::from_secs(60), Duration::ZERO] {
        let r = search_with(lost_disk(), budget);
        let lost: Vec<_> = r.entries.iter().filter(|e| e.status == "lost").collect();
        assert_eq!(lost.len(), 1, "{:#?}", r.entries);
        let l = lost[0];
        assert_eq!(l.offset, 62 * MIB as u64);
        assert_eq!(l.size, 16 * MIB as u64);
        assert_eq!(l.fs.as_deref(), Some("FAT16"));
        assert_eq!(l.label.as_deref(), Some("GONE"));
        assert_eq!(l.found_by, "bootSector");
        assert_eq!(l.type_name, "FAT16");
        assert_eq!(r.entries.len(), 3);
    }
}

#[test]
fn damaged_entry_and_backup_only_partition() {
    let mut d = lost_disk();
    // The listed FAT32 partition loses its first boot sector: "damaged", backup intact.
    d[20 * MIB..20 * MIB + 512].fill(0);
    let r = analyze(&MemSource::new(d.clone())).unwrap();
    let p2 = r.entries.iter().find(|e| e.number == Some(2)).unwrap();
    assert_eq!(p2.status, "damaged");
    assert_eq!(p2.fs.as_deref(), Some("FAT32"));
    assert_eq!(p2.note, "Its first boot sector is damaged; the backup copy is intact.");
    // Now delete it from the table too: only the backup boot sector knows it.
    mbr_entry(&mut d[..512], 1, 0, 0, 0, 0);
    for budget in [Duration::from_secs(60), Duration::ZERO] {
        let r = search_with(d.clone(), budget);
        let b = r.entries.iter().find(|e| e.offset == 20 * MIB as u64).unwrap_or_else(|| panic!("{:#?}", r.entries));
        assert_eq!(b.status, "backupOnly");
        assert_eq!(b.found_by, "backupBootSector");
        assert_eq!(b.fs.as_deref(), Some("FAT32"));
        assert_eq!(b.size, 40 * MIB as u64);
        // Nothing reported at the backup sector's own offset.
        assert!(!r.entries.iter().any(|e| e.offset == 20 * MIB as u64 + 3072));
        assert!(r.entries.iter().any(|e| e.offset == 62 * MIB as u64 && e.status == "lost"));
    }
}

#[test]
fn bare_volume_has_style_none() {
    let mut d = vec![0u8; 16 * MIB];
    fmt(&mut d, 0, 16 * MIB, FatType::Fat16, 512, b"STICK      ");
    let r = analyze(&MemSource::new(d)).unwrap();
    assert_eq!(r.style, "None");
    assert_eq!(r.entries.len(), 1);
    assert_eq!(r.entries[0].size, 16 * MIB as u64);
    assert_eq!(r.entries[0].fs.as_deref(), Some("FAT16"));
    let r = analyze(&MemSource::new(vec![0u8; 8 * MIB])).unwrap();
    assert_eq!(r.style, "None");
    assert!(r.entries.is_empty());
    assert!(r.notes[0].contains("No partition table"));
}

#[test]
fn random_and_corrupted_tables_never_panic() {
    let mut x: u32 = 0xDEAD_BEEF;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    };
    for _ in 0..10 {
        let d: Vec<u8> = (0..2 * MIB).map(|_| rnd() as u8).collect();
        let _ = analyze(&MemSource::new(d.clone()));
        let _ = search_with(d, Duration::from_millis(50));
    }
    let base = gpt_disk();
    for round in 0..30 {
        let mut d = base.clone();
        for _ in 0..(5 + round) {
            let pos = (rnd() as usize) % (34 * 512);
            d[pos] = rnd() as u8;
        }
        let _ = analyze(&MemSource::new(d));
    }
    let base = mbr_disk();
    for _ in 0..30 {
        let mut d = base.clone();
        for _ in 0..8 {
            let at = [446usize, 20 * MIB + 446, 28 * MIB + 446][rnd() as usize % 3];
            d[at + rnd() as usize % 64] = rnd() as u8;
        }
        let _ = analyze(&MemSource::new(d));
    }
    assert!(analyze(&MemSource::new(Vec::new())).is_err());
    let _ = analyze(&MemSource::new(vec![0u8; 100]));
}

/// Throughput of the dense pass (CPU side; real disks are I/O bound). Run with --ignored.
#[test]
#[ignore]
fn dense_search_throughput() {
    let d = vec![0u8; 512 * MIB];
    let t = std::time::Instant::now();
    let _ = search_with(d, Duration::from_secs(600));
    let s = t.elapsed().as_secs_f64();
    eprintln!("dense: 512 MiB in {s:.2} s = {:.0} MB/s", 512.0 / s);
    let d = vec![0u8; 512 * MIB];
    let t = std::time::Instant::now();
    let _ = search_with(d, Duration::ZERO);
    eprintln!("sparse: 512 MiB in {:.3} s", t.elapsed().as_secs_f64());
}

/// A 4 MiB exFAT volume at `off`: boot region + backup, FAT, root with bitmap/up-case entries.
fn put_exfat(d: &mut [u8], off: usize) {
    let v = &mut d[off..off + 4 * MIB];
    let b = &mut v[..512];
    b[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
    b[3..11].copy_from_slice(b"EXFAT   ");
    b[72..80].copy_from_slice(&8192u64.to_le_bytes());
    b[80..84].copy_from_slice(&32u32.to_le_bytes());
    b[84..88].copy_from_slice(&8u32.to_le_bytes());
    b[88..92].copy_from_slice(&64u32.to_le_bytes());
    b[92..96].copy_from_slice(&1016u32.to_le_bytes());
    b[96..100].copy_from_slice(&4u32.to_le_bytes());
    b[104..106].copy_from_slice(&0x0100u16.to_le_bytes());
    b[108] = 9;
    b[109] = 3;
    b[110] = 1;
    b[510] = 0x55;
    b[511] = 0xAA;
    let c = crate::fs::exfat::boot::boot_checksum(&v[..12 * 512], 512);
    for k in 0..128 {
        v[11 * 512 + k * 4..11 * 512 + k * 4 + 4].copy_from_slice(&c.to_le_bytes());
    }
    let (main, rest) = v.split_at_mut(12 * 512);
    rest[..12 * 512].copy_from_slice(main);
    v[32 * 512..32 * 512 + 8].copy_from_slice(&[0xF8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    let root = 64 * 512 + 2 * 4096;
    v[root] = 0x81;
    v[root + 32] = 0x82;
}

#[test]
fn exfat_backup_boot_sector_is_not_taken_for_a_start() {
    let at = 2 * MIB;
    // Main boot sector gone and the FAT's first bytes damaged: only the backup (sector 12) is left.
    let mut d = vec![0u8; 8 * MIB];
    put_exfat(&mut d, at);
    d[at..at + 512].fill(0);
    d[at + 32 * 512] = 0;
    for budget in [Duration::from_secs(60), Duration::ZERO] {
        let r = search_with(d.clone(), budget);
        let e = r.entries.iter().find(|e| e.offset == at as u64).unwrap_or_else(|| panic!("{:#?}", r.entries));
        assert_eq!(e.status, "backupOnly");
        assert_eq!(e.fs.as_deref(), Some("exFAT"));
        assert!(!r.entries.iter().any(|e| e.offset == (at + 12 * 512) as u64), "{:#?}", r.entries);
    }
    // Main boot sector intact but the FAT start damaged: still found at its real start.
    let mut d = vec![0u8; 8 * MIB];
    put_exfat(&mut d, at);
    d[at + 32 * 512] = 0;
    for budget in [Duration::from_secs(60), Duration::ZERO] {
        let r = search_with(d.clone(), budget);
        let e = r.entries.iter().find(|e| e.offset == at as u64).unwrap_or_else(|| panic!("{:#?}", r.entries));
        assert_eq!(e.status, "lost");
        assert!(!r.entries.iter().any(|e| e.offset == (at + 12 * 512) as u64), "{:#?}", r.entries);
    }
}
