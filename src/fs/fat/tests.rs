//! FAT engine tests on real images built in memory with the `fatfs` crate.

use super::*;
use crate::device::source::MemSource;
use crate::model::{flags, Condition, FileStatus, FoundFile, ScanOptions, ScanCtx, TestSinks};
use fatfs::{FatType, FileSystem, FormatVolumeOptions, FsOptions};
use std::io::{Cursor, Write};

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

fn format(buf: &mut [u8], kind: FatType, cluster: u32) {
    let opts = FormatVolumeOptions::new().fat_type(kind).bytes_per_cluster(cluster).volume_label(*b"TESTVOL    ");
    fatfs::format_volume(Cursor::new(buf), opts).unwrap();
}

fn with_fs<R>(buf: &mut [u8], f: impl FnOnce(&FileSystem<Cursor<&mut [u8]>>) -> R) -> R {
    let fs = FileSystem::new(Cursor::new(buf), FsOptions::new()).unwrap();
    let r = f(&fs);
    fs.unmount().unwrap();
    r
}

fn write(fs: &FileSystem<Cursor<&mut [u8]>>, path: &str, data: &[u8]) {
    let mut f = fs.root_dir().create_file(path).unwrap();
    f.truncate().unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
}

struct Built {
    img: Vec<u8>,
    files: Vec<(&'static str, &'static str, Vec<u8>)>, // (folder, name, content) of deleted files
}

/// A volume with nested folders, long names, deleted files and a deleted folder.
fn build(kind: FatType, size: usize, cluster: u32) -> Built {
    let mut img = vec![0u8; size];
    format(&mut img, kind, cluster);
    let long = content(1, 5000);
    let beach = content(2, 7000);
    let abin = content(3, 2000);
    let report = content(4, 9000);
    with_fs(&mut img, |fs| {
        write(fs, "keep.txt", &content(9, 3000));
        write(fs, "Long file name document.txt", &long);
        fs.root_dir().create_dir("Photos").unwrap();
        fs.root_dir().create_dir("Photos/2019").unwrap();
        write(fs, "Photos/2019/beach holiday.jpg", &beach);
        write(fs, "Photos/2019/small.txt", b"small");
        fs.root_dir().create_dir("Old stuff").unwrap();
        write(fs, "Old stuff/a.bin", &abin);
        write(fs, "Old stuff/Report final version.docx", &report);
    });
    with_fs(&mut img, |fs| {
        let r = fs.root_dir();
        r.remove("Long file name document.txt").unwrap();
        r.remove("Photos/2019/beach holiday.jpg").unwrap();
        r.remove("Old stuff/a.bin").unwrap();
        r.remove("Old stuff/Report final version.docx").unwrap();
        r.remove("Old stuff").unwrap();
    });
    Built {
        img,
        files: vec![
            ("", "Long file name document.txt", long),
            ("\\Photos\\2019", "beach holiday.jpg", beach),
            ("\\Old stuff", "a.bin", abin),
            ("\\Old stuff", "Report final version.docx", report),
        ],
    }
}

fn scan(src: &MemSource, existing: bool) -> (Vec<FoundFile>, crate::model::EngineSummary, TestSinks) {
    let opts = ScanOptions { include_existing: Some(existing), ..Default::default() };
    let (ctx, t) = ScanCtx::for_test(opts, src.len());
    let sum = quick_scan(src, &ctx).unwrap();
    let files = t.files.lock().unwrap().clone();
    (files, sum, t)
}

fn read_all(src: &MemSource, f: &FoundFile) -> Vec<u8> {
    let mut buf = vec![0u8; f.size as usize];
    let (n, bad) = crate::fileread::read_at(Some(src), f, 0, &mut buf).unwrap();
    assert!(!bad);
    buf.truncate(n);
    buf
}

fn check_deleted(kind: FatType, size: usize, cluster: u32, fs_name: &str) {
    let b = build(kind, size, cluster);
    let src = MemSource::new(b.img.clone());
    let p = probe(&src).expect("probe");
    assert_eq!(p.fs, fs_name);
    assert_eq!(p.label, "TESTVOL");
    assert!(!p.used_backup_boot);
    let (files, sum, t) = scan(&src, false);
    assert_eq!(sum.deleted, 4, "{files:#?}");
    for (folder, name, data) in &b.files {
        let f = files.iter().find(|f| &f.name == name).unwrap_or_else(|| panic!("{name} not found in {files:#?}"));
        assert_eq!(&f.folder, folder, "{name}");
        assert_eq!(f.status, FileStatus::Deleted);
        assert_eq!(f.size, data.len() as u64);
        assert_eq!(f.condition, Condition::Excellent, "{name}: {}", f.note);
        assert_eq!(f.flags & flags::NAME_GUESSED, 0);
        assert_eq!(&read_all(&src, f), data, "{name} content");
        let now = crate::model::now_ms();
        let m = f.modified.expect("modified time");
        assert!((m - now).abs() < 2 * 86_400_000, "{name} time {m} vs {now}");
    }
    assert!(!files.iter().any(|f| f.name == "keep.txt"));
    // Map marks: metadata and allocated ranges exist.
    let ranges = t.ranges.lock().unwrap();
    assert!(ranges.iter().any(|r| r.0 == crate::model::MapKind::Metadata));
    assert!(ranges.iter().any(|r| r.0 == crate::model::MapKind::Allocated));
    drop(ranges);
    // With existing files.
    let (files, _, _) = scan(&src, true);
    let keep = files.iter().find(|f| f.name == "keep.txt").unwrap();
    assert_eq!(keep.status, FileStatus::Existing);
    assert_eq!(read_all(&src, keep), content(9, 3000));
    let small = files.iter().find(|f| f.name == "small.txt").unwrap();
    assert_eq!(small.folder, "\\Photos\\2019");
}

#[test]
fn fat12_deleted_files() {
    check_deleted(FatType::Fat12, 1 << 20, 512, "FAT12");
}

#[test]
fn fat16_deleted_files() {
    check_deleted(FatType::Fat16, 16 << 20, 512, "FAT16");
}

#[test]
fn fat32_deleted_files() {
    check_deleted(FatType::Fat32, 40 << 20, 512, "FAT32");
}

#[test]
fn fat32_backup_boot_sector() {
    let b = build(FatType::Fat32, 40 << 20, 512);
    let mut img = b.img;
    img[..512].fill(0);
    let src = MemSource::new(img);
    let p = probe(&src).expect("probe from backup");
    assert!(p.used_backup_boot);
    let (files, sum, _) = scan(&src, false);
    assert!(sum.notes.iter().any(|n| n.contains("backup boot sector")));
    assert_eq!(files.len(), 4);
}

#[test]
fn unreadable_first_fat_uses_second_copy() {
    let b = build(FatType::Fat16, 16 << 20, 512);
    let mut src = MemSource::new(b.img);
    let g = bpb::read_geom(&src).unwrap();
    src.bad = vec![(g.fat_offset, g.fat_offset + 1024)];
    let (files, sum, _) = scan(&src, true);
    assert!(sum.notes.iter().any(|n| n.contains("second copy")), "{:?}", sum.notes);
    let keep = files.iter().find(|f| f.name == "keep.txt").unwrap();
    assert_eq!(keep.condition, Condition::Excellent);
    assert_eq!(read_all(&src, keep), content(9, 3000));
}

#[test]
fn overwritten_start_is_partial() {
    let mut img = vec![0u8; 16 << 20];
    format(&mut img, FatType::Fat16, 512);
    with_fs(&mut img, |fs| {
        fs.root_dir().create_dir("d").unwrap();
        write(fs, "victim.bin", &content(5, 4000));
        write(fs, "other.bin", &content(6, 1000));
    });
    with_fs(&mut img, |fs| fs.root_dir().remove("victim.bin").unwrap());
    // A fresh mount allocates from the start of the volume: the freed clusters are reused.
    with_fs(&mut img, |fs| write(fs, "d/new.bin", &content(7, 1500)));
    let src = MemSource::new(img);
    let (files, _, _) = scan(&src, false);
    let v = files.iter().find(|f| f.name == "victim.bin").expect("victim");
    assert_eq!(v.condition, Condition::Partial);
    assert_ne!(v.flags & flags::OVERWRITTEN, 0);
    assert_eq!(v.note, "Its start has been overwritten.");
}

fn sweep_all(src: &MemSource, probe: Option<&crate::model::FsProbe>) -> (Vec<FoundFile>, crate::model::EngineSummary) {
    let (ctx, t) = ScanCtx::for_test(ScanOptions::default(), src.len());
    let v = sweep_visitor(probe);
    let chunk = 4 << 20;
    let mut off = 0usize;
    while off < src.data.len() {
        let end = (off + chunk).min(src.data.len());
        v.visit(src, off as u64, &src.data[off..end], &ctx);
        off = end;
    }
    let sum = v.finish(src, &ctx).unwrap();
    let files = t.files.lock().unwrap().clone();
    (files, sum)
}

fn build_for_format(size: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut img = vec![0u8; size];
    format(&mut img, FatType::Fat32, 512);
    let a = content(11, 6000);
    let b = content(12, 1234);
    let c = content(13, 777);
    with_fs(&mut img, |fs| {
        fs.root_dir().create_dir("Docs").unwrap();
        write(fs, "Docs/Annual report.pdf", &a);
        write(fs, "Docs/notes.txt", &b);
        fs.root_dir().create_dir("Docs/Sub folder").unwrap();
        write(fs, "Docs/Sub folder/deep file.dat", &c);
        // Enough entries to spill the folder into more clusters.
        for i in 0..20 {
            write(fs, &format!("Docs/filler number {i}.txt"), format!("filler {i}").as_bytes());
        }
    });
    (img, a, b, c)
}

#[test]
fn formatted_volume_lost_folders() {
    let (mut img, a, b, c) = build_for_format(40 << 20);
    // Quick format over it: new boot sector, FATs and root directory.
    format(&mut img, FatType::Fat32, 512);
    let src = MemSource::new(img);
    let (files, _, _) = scan(&src, true);
    assert!(files.is_empty(), "{files:#?}");
    let p = probe(&src);
    let (files, sum) = sweep_all(&src, p.as_ref());
    assert!(sum.lost_folders >= 1, "{sum:?}");
    let fa = files.iter().find(|f| f.name == "Annual report.pdf").expect("annual report");
    assert!(fa.folder.starts_with("\\Lost folders\\Folder "), "{}", fa.folder);
    assert_eq!(fa.status, FileStatus::Lost);
    assert_ne!(fa.flags & flags::LOOSE_RECORD, 0);
    assert_eq!(fa.condition, Condition::Excellent, "{}", fa.note);
    assert_eq!(read_all(&src, fa), a);
    let fb = files.iter().find(|f| f.name == "notes.txt").unwrap();
    assert_eq!(read_all(&src, fb), b);
    let fc = files.iter().find(|f| f.name == "deep file.dat").unwrap();
    assert_eq!(fc.folder, format!("{}\\Sub folder", fa.folder));
    assert_eq!(read_all(&src, fc), c);
    assert!(files.iter().any(|f| f.name == "filler number 19.txt"));
}

#[test]
fn formatted_with_other_cluster_size_infers_layout() {
    let (mut img, a, _, c) = build_for_format(80 << 20);
    format(&mut img, FatType::Fat32, 1024);
    let src = MemSource::new(img);
    let p = probe(&src);
    assert_eq!(p.as_ref().unwrap().cluster_size, 1024);
    let (files, _) = sweep_all(&src, p.as_ref());
    let fa = files.iter().find(|f| f.name == "Annual report.pdf").expect("annual report");
    assert_eq!(read_all(&src, fa), a);
    let fc = files.iter().find(|f| f.name == "deep file.dat").unwrap();
    assert_eq!(read_all(&src, fc), c);
    // Without any probe (boot sector wiped), the layout is inferred too.
    let mut img2 = src.data.clone();
    img2[..512].fill(0);
    img2[6 * 512..7 * 512].fill(0);
    let src2 = MemSource::new(img2);
    assert!(probe(&src2).is_none());
    let (files, _) = sweep_all(&src2, None);
    let fa = files.iter().find(|f| f.name == "Annual report.pdf").expect("annual report without probe");
    assert_eq!(read_all(&src2, fa), a);
}

#[test]
fn sweep_skips_files_already_reported() {
    let b = build(FatType::Fat16, 16 << 20, 512);
    let src = MemSource::new(b.img);
    let (ctx, t) = ScanCtx::for_test(ScanOptions::default(), src.len());
    quick_scan(&src, &ctx).unwrap();
    let n = t.files.lock().unwrap().len();
    let v = sweep_visitor(probe(&src).as_ref());
    v.visit(&src, 0, &src.data, &ctx);
    v.finish(&src, &ctx).unwrap();
    // The deleted "Old stuff" folder was reachable through its entry, so nothing new is lost.
    assert_eq!(t.files.lock().unwrap().len(), n);
}

#[test]
fn random_and_corrupted_input_never_panics() {
    let mut x: u32 = 0x1234_5678;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    };
    // Pure noise.
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
    // A real volume with random damage in its metadata and directories.
    let base = build(FatType::Fat16, 4 << 20, 512).img;
    let g = bpb::read_geom(&MemSource::new(base.clone())).unwrap();
    let hot = (g.data_offset + 64 * 1024) as u32;
    for round in 0..40 {
        let mut img = base.clone();
        for _ in 0..(50 + round * 20) {
            let pos = (rnd() % hot) as usize;
            img[pos] = rnd() as u8;
        }
        let src = MemSource::new(img);
        let _ = probe(&src);
        let (ctx, _) = ScanCtx::for_test(ScanOptions { include_existing: Some(true), ..Default::default() }, src.len());
        let _ = quick_scan(&src, &ctx);
        let v = sweep_visitor(None);
        v.visit(&src, 0, &src.data, &ctx);
        let _ = v.finish(&src, &ctx);
    }
    // Boot sector fields at extreme values.
    let mut img = base.clone();
    for (o, v) in [(13usize, 0u8), (16, 0), (14, 0), (17, 0)] {
        img[o] = v;
        let _ = probe(&MemSource::new(img.clone()));
    }
}


#[test]
fn deleted_folder_with_reused_start_does_not_hide_live_folder() {
    let mut img = vec![0u8; 16 << 20];
    format(&mut img, FatType::Fat16, 512);
    with_fs(&mut img, |fs| {
        fs.root_dir().create_dir("Aold").unwrap();
        fs.root_dir().create_dir("Work").unwrap();
    });
    with_fs(&mut img, |fs| fs.root_dir().remove("Aold").unwrap());
    // A fresh mount allocates from the start: "Projects" takes the cluster "Aold" had.
    let gone = content(21, 1500);
    with_fs(&mut img, |fs| {
        fs.root_dir().create_dir("Work/Projects").unwrap();
        write(fs, "Work/Projects/live.txt", b"still here");
        write(fs, "Work/Projects/gone.bin", &gone);
    });
    with_fs(&mut img, |fs| fs.root_dir().remove("Work/Projects/gone.bin").unwrap());
    let src = MemSource::new(img);
    // The scenario holds: the deleted "Aold" entry names the start cluster "Projects" now uses.
    let v = scan::mount(&src, None).unwrap();
    let root = v.parse(&v.read_root16(None), false);
    let old = root.entries.iter().find(|e| e.deleted && e.is_dir()).expect("deleted Aold entry");
    assert!(v.fat.is_used(old.start));
    let (files, _, _) = scan(&src, true);
    let g = files.iter().find(|f| f.name == "gone.bin").unwrap_or_else(|| panic!("{files:#?}"));
    assert_eq!(g.folder, r"\Work\Projects");
    assert_eq!(read_all(&src, g), gone);
    let l = files.iter().find(|f| f.name == "live.txt").expect("live.txt");
    assert_eq!(l.folder, r"\Work\Projects");
}

#[test]
fn deleted_folder_does_not_absorb_next_deleted_subfolder() {
    let mut img = vec![0u8; 16 << 20];
    format(&mut img, FatType::Fat16, 512);
    let inner = content(22, 700);
    with_fs(&mut img, |fs| {
        fs.root_dir().create_dir("A").unwrap();
        fs.root_dir().create_dir("A/B").unwrap();
        write(fs, "A/B/INNER.TXT", &inner);
        // Fill A's first cluster (16 slots: ".", "..", "B" and 13 files) and spill into another.
        for i in 0..20 {
            write(fs, &format!("A/F{i:02}.TXT"), format!("file {i}").as_bytes());
        }
    });
    with_fs(&mut img, |fs| {
        let r = fs.root_dir();
        r.remove("A/B/INNER.TXT").unwrap();
        r.remove("A/B").unwrap();
        for i in 0..20 {
            r.remove(&format!("A/F{i:02}.TXT")).unwrap();
        }
        r.remove("A").unwrap();
    });
    let src = MemSource::new(img);
    let (files, _, _) = scan(&src, false);
    let hits: Vec<_> = files.iter().filter(|f| f.name.ends_with("NNER.TXT")).collect();
    assert_eq!(hits.len(), 1, "{files:#?}");
    assert_eq!(hits[0].folder, r"\A\B");
    assert_eq!(read_all(&src, hits[0]), inner);
}

#[test]
fn geometry_is_limited_to_the_source() {
    let b = build(FatType::Fat32, 40 << 20, 512);
    let full = bpb::read_geom(&MemSource::new(b.img.clone())).unwrap();
    let mut img = b.img;
    img.truncate(8 << 20);
    let src = MemSource::new(img);
    let g = bpb::read_geom(&src).unwrap();
    let fit = (src.len() - g.data_offset).div_ceil(g.cluster_size as u64);
    assert!(full.cluster_count as u64 > fit);
    assert_eq!(g.cluster_count as u64, fit);
    // The BPB's own size is still reported, so callers can see it claims more than the source.
    assert_eq!(probe(&src).unwrap().total_size, 40 << 20);
    let v = scan::mount(&src, None).unwrap();
    assert_eq!(v.fat.entries.len(), fit as usize + 2);
    let _ = scan(&src, true);
    // Directory entries are still checked against the BPB's count: an entry whose clusters lie
    // past the end of the truncated source doesn't make its directory cluster look like garbage.
    assert_eq!(g.bpb_cluster_count, full.cluster_count);
    assert_eq!(g.entry_max_cluster(), full.cluster_count + 1);
    let past = fit as u32 + 10;
    let mut ent = [0u8; 64];
    ent[..11].copy_from_slice(b"\xE5AST    BIN");
    ent[11] = 0x20;
    ent[20..22].copy_from_slice(&((past >> 16) as u16).to_le_bytes());
    ent[26..28].copy_from_slice(&(past as u16).to_le_bytes());
    ent[28..32].copy_from_slice(&4096u32.to_le_bytes());
    assert!(super::dir::dir_score(&ent, Some(g.entry_max_cluster())).is_some());
    let p = super::dir::parse_dir(&ent, &[0, 32], true, true, Some(g.entry_max_cluster()), 0);
    assert_eq!(p.entries.len(), 1);
    let a = scan::assess_deleted(&v, &p.entries[0], true);
    assert_eq!(a.condition, Condition::Partial);
    assert!(a.note.contains("beyond the end"), "{}", a.note);
}
