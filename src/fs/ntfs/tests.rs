//! End-to-end tests: synthetic images (always run) and public test images under
//! `testdata/downloads/` (skipped with a message when absent).

use super::record::build::*;
use super::record::*;
use super::recycle::tests::info_v2;
use super::runs::Run;
use super::testimg::*;
use crate::device::source::{BlockSource, MemSource};
use crate::model::*;

// ------------------------------------------------------------------------------- helpers

fn run_quick(src: &dyn BlockSource, include_existing: bool) -> (Vec<FoundFile>, EngineSummary, TestSinks) {
    let opts = ScanOptions { include_existing: Some(include_existing), ..Default::default() };
    let (ctx, t) = ScanCtx::for_test(opts, src.len());
    let sum = super::quick_scan(src, &ctx).expect("quick scan");
    let files = t.files.lock().unwrap().clone();
    (files, sum, t)
}

fn find<'a>(files: &'a [FoundFile], name: &str) -> &'a FoundFile {
    files.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("{name} not found in {:?}", files.iter().map(|f| (&f.folder, &f.name)).collect::<Vec<_>>()))
}

fn read_all(src: &dyn BlockSource, f: &FoundFile) -> Vec<u8> {
    crate::fileread::read_prefix(Some(src), f, f.size as usize).unwrap()
}

/// MD5 (RFC 1321), for checking the DFTT answer key.
fn md5(data: &[u8]) -> String {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16,
        23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64).map(|i| ((i as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32).collect();
    let mut h = [0x6745_2301u32, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64).wrapping_mul(8)).to_le_bytes());
    for chunk in msg.chunks(64) {
        let m: Vec<u32> = chunk.chunks(4).map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]])).collect();
        let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f2 = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f2.rotate_left(S[i]));
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
    }
    h.iter().flat_map(|x| x.to_le_bytes()).map(|b| format!("{b:02x}")).collect()
}

#[test]
fn md5_works() {
    assert_eq!(md5(b""), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(md5(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(md5(b"The quick brown fox jumps over the lazy dog"), "9e107d9d372bb6826bd81d3542a419d6");
}

// --------------------------------------------------------------------- synthetic scenario

struct Scenario {
    img: Vec<u8>,
    cat: Vec<u8>,
    big: Vec<u8>,
    comp: Vec<u8>,
    recycled: Vec<u8>,
    live_lcn: u64,
}

fn scenario() -> Scenario {
    let mut img = Img::new(1024);
    let root = mk_ref(5, 5);
    img.put(30, dir_rec(30, 1, true, root, "Users"));
    img.put(31, dir_rec(31, 1, true, mk_ref(30, 1), "Ann"));
    img.put(32, dir_rec(32, 2, false, mk_ref(31, 1), "Pictures"));

    // Deleted, clusters free.
    let cat = content(40, 6000);
    let r = img.store(&cat, false);
    img.put(40, file_rec(40, 2, false, mk_ref(32, 1), "cat.jpg", 6000, vec![data_nr(&[r], 6000)]));

    // A live file, and deleted files sharing its clusters.
    let live = content(42, 2 * CS as usize);
    let lr = img.store(&live, true);
    let live_lcn = lr.lcn.unwrap();
    img.put(42, file_rec(42, 1, true, mk_ref(31, 1), "live.bin", live.len() as u64, vec![data_nr(&[lr], live.len() as u64)]));
    let own = img.store(&content(41, 100), false);
    img.put(41, file_rec(41, 2, false, mk_ref(31, 1), "dog.jpg", 2 * CS, vec![data_nr(&[Run { len: 1, lcn: Some(live_lcn) }, own], 2 * CS)]));
    let own2 = img.store(&content(45, 100), false);
    img.put(45, file_rec(45, 2, false, root, "half.bin", 2 * CS, vec![data_nr(&[own2, Run { len: 1, lcn: Some(live_lcn + 1) }], 2 * CS)]));

    // Resident.
    img.put(43, file_rec(43, 2, false, root, "notes.txt", 11, vec![data_res(b"hello notes")]));

    // Parent reused (sequence mismatch) -> Lost under "Folder 50".
    img.put(50, dir_rec(50, 4, true, root, "Other"));
    img.put(44, file_rec(44, 2, false, mk_ref(50, 3), "orphan.doc", 3, vec![data_res(b"abc")]));

    // Deleted folder whose own parent is gone -> lost tree keeping its name.
    img.put(51, dir_rec(51, 2, false, mk_ref(60, 1), "Holiday"));
    img.put(52, file_rec(52, 2, false, mk_ref(51, 1), "beach.jpg", 4, vec![data_res(b"sand")]));

    // Alternate data stream on a deleted file; Zone.Identifier is ignored.
    img.put(
        53,
        file_rec(53, 2, false, root, "report.docx", 4, vec![data_res(b"main"), attr_resident(ATTR_DATA, "secret", b"classified", 0)]),
    );
    img.put(
        85,
        file_rec(85, 2, false, root, "tiny.txt", 1, vec![data_res(b"t"), attr_resident(ATTR_DATA, "Zone.Identifier", b"[ZoneTransfer]", 0)]),
    );

    // Fragmented file whose second run list lives in a (deleted) extension record.
    let big = content(54, 4 * CS as usize - 100);
    let a = img.store(&big[..2 * CS as usize], false);
    let _gap = img.store(&[1u8], true);
    let b = img.store(&big[2 * CS as usize..], false);
    let real = big.len() as u64;
    img.put(
        54,
        file_rec(
            54,
            2,
            false,
            root,
            "big.dat",
            real,
            vec![attr_list(&[(ATTR_DATA, "", 0, mk_ref(54, 1)), (ATTR_DATA, "", 2, mk_ref(55, 1))]), attr_nonresident(ATTR_DATA, "", &[a], 0, 4 * CS, real, real, 0, 0)],
        ),
    );
    img.put(55, record(RS, 55, 2, 0, mk_ref(54, 1), &[attr_nonresident(ATTR_DATA, "", &[b], 2, 0, 0, 0, 0, 0)]));

    // Recycle Bin: a recycled file and a recycled folder, bin emptied (all deleted).
    img.put(70, dir_rec(70, 1, true, root, "$Recycle.Bin"));
    img.put(71, dir_rec(71, 1, true, mk_ref(70, 1), "S-1-5-21-1000"));
    let recycled = content(72, 5000);
    let rr = img.store(&recycled, false);
    img.put(72, file_rec(72, 2, false, mk_ref(71, 1), "$RAB12CD.jpg", 5000, vec![data_nr(&[rr], 5000)]));
    let i1 = info_v2("C:\\Users\\Ann\\Desktop\\holiday photo.jpg", 5000, 132_500_000_000_000_000);
    img.put(73, file_rec(73, 2, false, mk_ref(71, 1), "$IAB12CD.jpg", i1.len() as u64, vec![data_res(&i1)]));
    img.put(74, dir_rec(74, 2, false, mk_ref(71, 1), "$RFOLDER1"));
    let i2 = info_v2("C:\\Users\\Ann\\Old stuff", 0, 132_500_000_000_000_000);
    img.put(75, file_rec(75, 2, false, mk_ref(71, 1), "$IFOLDER1", i2.len() as u64, vec![data_res(&i2)]));
    img.put(76, file_rec(76, 2, false, mk_ref(74, 1), "inner.txt", 6, vec![data_res(b"inside")]));

    // NTFS-compressed deleted file: two 64 KiB units, each LZNT1 in its first clusters.
    let mut comp = Vec::new();
    for i in 0..(65536 + 1000) {
        comp.push(b"The quick brown fox jumps over the lazy dog. "[i % 45]);
    }
    let c0 = super::lznt1::tests::compress(&comp[..65536]);
    let c1 = super::lznt1::tests::compress(&comp[65536..]);
    let r0 = img.store(&c0, false);
    let r1 = img.store(&c1, false);
    let runs = [r0, Run { len: 16 - r0.len, lcn: None }, r1, Run { len: 16 - r1.len, lcn: None }];
    let creal = comp.len() as u64;
    img.put(77, file_rec(77, 2, false, root, "comp.txt", creal, vec![attr_nonresident(ATTR_DATA, "", &runs, 0, 2 * 65536, creal, creal, AF_COMPRESSED, 4)]));

    // EFS-encrypted.
    let er = img.store(&content(78, 3000), false);
    let mut rec78 = vec![
        std_info(0, 0, 0, FA_ENCRYPTED),
        file_name(root, "secret.efs", 1, 3000, false),
        attr_nonresident(ATTR_DATA, "", &[er], 0, CS, 3000, 3000, AF_ENCRYPTED, 0),
    ];
    img.put(78, record(RS, 78, 2, 0, 0, &std::mem::take(&mut rec78)));

    // Torn record: everything needed is in the first 512 bytes, the second stride is stale.
    let tr = img.store(&content(79, 2000), false);
    let mut torn = file_rec(79, 2, false, root, "torn.bin", 2000, vec![data_nr(&[tr], 2000)]);
    torn[1022] ^= 0xFF;
    img.put(79, torn);

    // Folder loop.
    img.put(80, dir_rec(80, 2, false, mk_ref(81, 1), "LoopA"));
    img.put(81, dir_rec(81, 2, false, mk_ref(80, 1), "LoopB"));
    img.put(82, file_rec(82, 2, false, mk_ref(81, 1), "inloop.txt", 2, vec![data_res(b"lo")]));

    // Nothing to recover.
    img.put(83, file_rec(83, 2, false, root, "empty.txt", 0, vec![data_res(b"")]));

    Scenario { img: img.build(), cat, big, comp, recycled, live_lcn }
}

#[test]
fn probe_reads_geometry_and_label() {
    let s = scenario();
    let m = MemSource::new(s.img.clone());
    let p = super::probe(&m).unwrap();
    assert_eq!(p.fs, "NTFS");
    assert_eq!(p.cluster_size, 4096);
    assert_eq!(p.sector_size, 512);
    assert_eq!(p.total_size, m.len());
    assert_eq!(p.label, "TESTVOL");
    assert_eq!(p.serial, "0000-1234");
    assert!(!p.used_backup_boot);
    // Damage the primary boot sector: the backup is used.
    let mut d = s.img;
    d[3] = b'X';
    let p = super::probe(&MemSource::new(d.clone())).unwrap();
    assert!(p.used_backup_boot);
    let (files, sum, _) = run_quick(&MemSource::new(d), false);
    assert!(sum.notes.iter().any(|n| n.contains("backup boot sector")));
    assert!(files.iter().any(|f| f.name == "cat.jpg"));
}

#[test]
fn quick_scan_end_to_end() {
    let s = scenario();
    let m = MemSource::new(s.img.clone());
    let (files, sum, t) = run_quick(&m, false);

    let cat = find(&files, "cat.jpg");
    assert_eq!(cat.folder, "\\Users\\Ann\\Pictures");
    assert_eq!(cat.status, FileStatus::Deleted);
    assert_eq!(cat.condition, Condition::Excellent);
    assert_eq!(cat.note, "Its clusters are still free.");
    assert_eq!(cat.size, 6000);
    assert_eq!(cat.fs_ref, Some(40));
    assert_eq!(cat.meta["mftRecord"], "40");
    assert_eq!(cat.type_id, "jpg");
    assert!(cat.created.is_some() && cat.modified.is_some());
    assert_eq!(read_all(&m, cat), s.cat);

    let dog = find(&files, "dog.jpg");
    assert_eq!(dog.folder, "\\Users\\Ann");
    assert_eq!((dog.condition, dog.flags & flags::OVERWRITTEN), (Condition::Partial, flags::OVERWRITTEN));
    assert_eq!(dog.note, "Its start has been overwritten.");
    let half = find(&files, "half.bin");
    assert_eq!(half.note, "Part of it has been overwritten by other files.");
    assert!(half.fragmented);

    let notes = find(&files, "notes.txt");
    assert_eq!(notes.folder, "");
    assert_eq!(notes.resident.as_deref(), Some(&b"hello notes"[..]));
    assert_eq!(notes.note, "Stored inside the file table.");

    let orphan = find(&files, "orphan.doc");
    assert_eq!((orphan.status, orphan.folder.as_str()), (FileStatus::Lost, "\\Lost folders\\Folder 50"));
    let beach = find(&files, "beach.jpg");
    assert_eq!((beach.status, beach.folder.as_str()), (FileStatus::Lost, "\\Lost folders\\Holiday (folder 51)"));
    let inloop = find(&files, "inloop.txt");
    assert_eq!(inloop.status, FileStatus::Lost);
    assert!(inloop.folder.starts_with("\\Lost folders\\Loop"), "{}", inloop.folder);

    find(&files, "report.docx");
    let ads = find(&files, "report.docx:secret");
    assert_eq!(ads.resident.as_deref(), Some(&b"classified"[..]));
    assert_eq!(ads.meta["stream"], "secret");
    find(&files, "tiny.txt");
    assert!(!files.iter().any(|f| f.name.contains("Zone.Identifier")));

    let big = find(&files, "big.dat");
    assert!(big.fragmented);
    assert_eq!(big.extents.len(), 2);
    assert_eq!(big.condition, Condition::Excellent, "{}", big.note);
    assert_eq!(read_all(&m, big), s.big);

    let comp = find(&files, "comp.txt");
    assert_ne!(comp.flags & flags::COMPRESSED, 0);
    assert_eq!(comp.meta["compressionUnit"], "16");
    assert_eq!(read_all(&m, comp), s.comp);

    let efs = find(&files, "secret.efs");
    assert_eq!((efs.condition, efs.flags & flags::ENCRYPTED), (Condition::Partial, flags::ENCRYPTED));
    let torn = find(&files, "torn.bin");
    assert_eq!((torn.condition, torn.note.as_str()), (Condition::Good, "Its clusters are still free."));

    // Recycle Bin: restored when recyclebin::parse_info_file is implemented, $R name otherwise.
    let parse_works = crate::recyclebin::parse_info_file(&info_v2("C:\\a\\b.txt", 1, 132_500_000_000_000_000)).is_some();
    if parse_works {
        let r = find(&files, "holiday photo.jpg");
        assert_eq!(r.folder, "\\Users\\Ann\\Desktop");
        assert_eq!(r.status, FileStatus::Deleted);
        assert_ne!(r.flags & flags::FROM_RECYCLE_INFO, 0);
        assert_eq!(r.meta["recycledAs"], "$RAB12CD.jpg");
        assert_eq!(r.meta["originalPath"], "C:\\Users\\Ann\\Desktop\\holiday photo.jpg");
        assert!(r.deleted.is_some());
        assert_eq!(read_all(&m, r), s.recycled);
        assert_eq!(find(&files, "inner.txt").folder, "\\Users\\Ann\\Old stuff");
    } else {
        println!("recyclebin::parse_info_file is still a stub: checking the unrestored names only");
        let r = find(&files, "$RAB12CD.jpg");
        assert_eq!(r.folder, "\\$Recycle.Bin\\S-1-5-21-1000");
        assert_eq!(find(&files, "inner.txt").folder, "\\$Recycle.Bin\\S-1-5-21-1000\\$RFOLDER1");
    }
    assert!(!files.iter().any(|f| f.name.starts_with("$I")), "$I bookkeeping files aren't listed");

    // Not reported: live files, empty files, folders.
    for n in ["live.bin", "empty.txt", "Pictures", "Holiday"] {
        assert!(!files.iter().any(|f| f.name == n), "{n} must not be reported");
    }
    assert_eq!(sum.files as usize, files.len());
    assert_eq!(sum.deleted as usize, files.len());
    assert!(sum.lost_folders >= 3);

    // Map: metadata, allocated (live.bin), scanned.
    let ranges = t.ranges.lock().unwrap().clone();
    let has = |k: MapKind, s0: u64, e0: u64| ranges.iter().any(|&(kk, s, e)| kk == k && s <= s0 && e >= e0);
    assert!(has(MapKind::Metadata, MFT_LCN * CS, (MFT_LCN + 1) * CS));
    assert!(has(MapKind::Metadata, 0, 512));
    assert!(has(MapKind::Allocated, s.live_lcn * CS, (s.live_lcn + 2) * CS));
    assert!(has(MapKind::Scanned, MFT_LCN * CS, (MFT_LCN + 1) * CS));
    assert!(has(MapKind::Recoverable, cat.extents[0].offset, cat.extents[0].offset + 6000));
    assert!(!has(MapKind::Allocated, cat.extents[0].offset, cat.extents[0].offset + 1));

    // With existing files.
    let (files, _, _) = run_quick(&m, true);
    let live = find(&files, "live.bin");
    assert_eq!(live.status, FileStatus::Existing);
    assert_eq!(live.folder, "\\Users\\Ann");
}

#[test]
fn recycle_restoration_with_fake_parser_end_to_end() {
    // Exercise the matching on the scenario's records through the index directly.
    use super::recycle::{InfoIndex, InfoRec};
    let i1 = info_v2("C:\\Users\\Ann\\Desktop\\holiday photo.jpg", 5000, 132_500_000_000_000_000);
    let idx = InfoIndex::new(vec![InfoRec { parent: 71, id: "AB12CD.JPG".into(), in_use: false, data: i1 }]);
    let r = idx.restore("$RAB12CD.jpg", 71, false, &super::recycle::tests::fake_parse).unwrap();
    assert_eq!((r.folder.as_str(), r.name.as_str()), ("\\Users\\Ann\\Desktop", "holiday photo.jpg"));
}

#[test]
fn mirror_and_bad_sectors() {
    let s = scenario();
    // Record 0 destroyed: the copy in $MFTMirr is used.
    let mut d = s.img.clone();
    let o = (MFT_LCN * CS) as usize;
    d[o..o + 4].copy_from_slice(b"XXXX");
    let (files, sum, _) = run_quick(&MemSource::new(d), false);
    assert!(sum.notes.iter().any(|n| n.contains("mirror")), "{:?}", sum.notes);
    assert!(files.iter().any(|f| f.name == "cat.jpg"));

    // A bad sector inside the MFT: records there are skipped and counted, the rest still works.
    let mut m = MemSource::new(s.img.clone());
    let rec40 = MFT_LCN * CS + 40 * RS as u64;
    m.bad = vec![(rec40, rec40 + 512)];
    let opts = ScanOptions { include_existing: Some(false), ..Default::default() };
    let (ctx, t) = ScanCtx::for_test(opts, m.len());
    let sum = super::quick_scan(&m, &ctx).unwrap();
    let files = t.files.lock().unwrap().clone();
    assert!(!files.iter().any(|f| f.name == "cat.jpg"));
    assert!(files.iter().any(|f| f.name == "big.dat"));
    assert!(sum.notes.iter().any(|n| n.contains("bad sectors")), "{:?}", sum.notes);
    assert!(t.ranges.lock().unwrap().iter().any(|&(k, s0, _)| k == MapKind::Bad && s0 == rec40));
    assert!(ctx.bad_bytes.load(std::sync::atomic::Ordering::Relaxed) >= 512);
}

#[test]
fn mft_whose_own_runs_continue_in_an_extension_record() {
    // $MFT's $DATA split in two pieces: records 0-63 described in record 0, records 64-127 in
    // extension record 20 (listed in record 0's $ATTRIBUTE_LIST). A file at record 100 is only
    // reachable by following the list.
    let mut img = Img::new(1024);
    let root = mk_ref(5, 5);
    let mft_bytes = MFT_RECORDS * RS as u64;
    let half = mft_bytes / CS / 2;
    img.put(
        0,
        record(
            RS,
            0,
            1,
            REC_IN_USE,
            0,
            &[
                std_info(0, 0, 0, 6),
                attr_list(&[(ATTR_DATA, "", 0, mk_ref(0, 1)), (ATTR_DATA, "", half, mk_ref(20, 1))]),
                file_name(root, "$MFT", 3, 0, false),
                attr_nonresident(ATTR_DATA, "", &[Run { len: half, lcn: Some(MFT_LCN) }], 0, mft_bytes, mft_bytes, mft_bytes, 0, 0),
            ],
        ),
    );
    img.put(20, record(RS, 20, 1, REC_IN_USE, mk_ref(0, 1), &[attr_nonresident(ATTR_DATA, "", &[Run { len: half, lcn: Some(MFT_LCN + half) }], half, 0, 0, 0, 0, 0)]));
    let c = content(100, 3000);
    let r = img.store(&c, false);
    img.put(100, file_rec(100, 2, false, root, "far.txt", 3000, vec![data_nr(&[r], 3000)]));
    let m = MemSource::new(img.build());
    let (files, sum, _) = run_quick(&m, false);
    assert!(sum.notes.is_empty(), "{:?}", sum.notes);
    assert_eq!(read_all(&m, find(&files, "far.txt")), c);
}

#[test]
fn cancel_is_reported_unchanged() {
    let s = scenario();
    let m = MemSource::new(s.img);
    let (ctx, _) = ScanCtx::for_test(ScanOptions::default(), m.len());
    ctx.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(super::quick_scan(&m, &ctx), Err(CANCELLED.to_string()));
}

#[test]
fn damaged_images_never_panic() {
    let s = scenario();
    let mut x: u64 = 0xDEAD_BEEF_1234_5678;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mft = (MFT_LCN * CS) as usize;
    let mft_end = mft + (MFT_RECORDS as usize) * RS;
    for round in 0..60 {
        let mut d = s.img.clone();
        let hits = 20 + (next() % 400) as usize;
        for _ in 0..hits {
            let p = if round % 3 == 0 { (next() as usize) % d.len() } else { mft + (next() as usize) % (mft_end - mft) };
            d[p] = next() as u8;
        }
        let m = MemSource::new(d);
        let (ctx, _) = ScanCtx::for_test(ScanOptions { include_existing: Some(round % 2 == 0), ..Default::default() }, m.len());
        let _ = super::probe(&m);
        let _ = super::quick_scan(&m, &ctx);
        let v = super::sweep_visitor(None);
        for (i, c) in m.data.chunks(1 << 20).enumerate() {
            v.visit(&m, (i << 20) as u64, c, &ctx);
        }
        let _ = v.finish(&m, &ctx);
    }
    // Pure noise with FILE magics sprinkled at sector starts.
    let mut noise: Vec<u8> = (0..(2 << 20)).map(|_| next() as u8).collect();
    for i in (0..noise.len()).step_by(512) {
        if next() % 3 == 0 {
            noise[i..i + 4].copy_from_slice(b"FILE");
            noise[i + 4] = 0x30;
            noise[i + 5] = 0;
            noise[i + 6] = 3;
            noise[i + 7] = 0;
        }
    }
    noise[3..11].copy_from_slice(b"NTFS    ");
    let m = MemSource::new(noise);
    let (ctx, _) = ScanCtx::for_test(ScanOptions::default(), m.len());
    let _ = super::quick_scan(&m, &ctx);
    let v = super::sweep_visitor(None);
    v.visit(&m, 0, &m.data, &ctx);
    let _ = v.finish(&m, &ctx);
}

// -------------------------------------------------------------------------------- sweep

fn sweep(src: &MemSource, probe: Option<&FsProbe>, ctx: &ScanCtx) -> EngineSummary {
    let v = super::sweep_visitor(probe);
    // Odd chunk size so records straddle chunk ends.
    let chunk = 3 * 1024 * 1024 + 512;
    let mut off = 0usize;
    while off < src.data.len() {
        let end = (off + chunk).min(src.data.len());
        v.visit(src, off as u64, &src.data[off..end], ctx);
        off = end;
    }
    v.finish(src, ctx).unwrap()
}

#[test]
fn sweep_rebuilds_a_formatted_volume_inside_a_disk() {
    // The scenario volume at 1 MiB into a "disk", its boot sectors wiped (formatted/damaged):
    // nothing recognises it, so every record is loose and the geometry comes from record 0.
    let s = scenario();
    let mut vol = s.img.clone();
    vol[..512].fill(0);
    let n = vol.len();
    vol[n - 512..].fill(0);
    let start = 1u64 << 20;
    let mut disk = vec![0u8; start as usize];
    disk.extend_from_slice(&vol);
    disk.extend_from_slice(&vec![0u8; 4096]);
    let m = MemSource::new(disk);
    assert!(super::probe(&m).is_none());
    let (ctx, t) = ScanCtx::for_test(ScanOptions::default(), m.len());
    let sum = sweep(&m, None, &ctx);
    assert!(sum.notes.iter().any(|n| n.contains(&format!("starting at byte {start}"))), "{:?}", sum.notes);
    let files = t.files.lock().unwrap().clone();
    let cat = find(&files, "cat.jpg");
    assert_eq!(cat.folder, "\\Users\\Ann\\Pictures");
    assert_ne!(cat.flags & flags::LOOSE_RECORD, 0);
    assert_eq!(cat.extents[0].offset % CS, 0);
    assert!(cat.extents[0].offset >= start);
    assert_eq!(read_all(&m, cat), s.cat);
    assert_eq!(read_all(&m, find(&files, "big.dat")), s.big);
    assert_eq!(find(&files, "beach.jpg").folder, "\\Lost folders\\Holiday (folder 51)");
    assert_eq!(find(&files, "live.bin").status, FileStatus::Deleted);
    assert!(!files.iter().any(|f| ["$MFT", "$MFTMirr", "$Bitmap", "$Volume", "$LogFile"].contains(&f.name.as_str())));
    assert!(!files.iter().any(|f| f.name.starts_with("$I")), "$I bookkeeping files aren't listed");
    if crate::recyclebin::parse_info_file(&info_v2("C:\\a\\b.txt", 1, 132_500_000_000_000_000)).is_some() {
        assert_eq!(find(&files, "holiday photo.jpg").folder, "\\Users\\Ann\\Desktop");
        assert_eq!(find(&files, "inner.txt").folder, "\\Users\\Ann\\Old stuff");
    }
}

#[test]
fn sweep_finds_records_outside_the_live_mft_and_skips_known_files() {
    // A live volume plus an old MFT fragment in free space (from before a reformat).
    let mut img = Img::new(1024);
    let root = mk_ref(5, 5);
    let old = content(301, 9000);
    let run = img.store(&old, false);
    let frag_lcn = img.alloc(1);
    let mut frag = Vec::new();
    frag.extend_from_slice(&dir_rec(300, 1, true, root, "Old docs"));
    frag.extend_from_slice(&file_rec(301, 1, true, mk_ref(300, 1), "old.pdf", 9000, vec![data_nr(&[run], 9000)]));
    frag.extend_from_slice(&file_rec(302, 1, true, mk_ref(999, 1), "stray.txt", 3, vec![data_res(b"xyz")]));
    img.write(frag_lcn, &frag);
    let cat = content(40, 6000);
    let r = img.store(&cat, false);
    img.put(40, file_rec(40, 2, false, root, "cat.jpg", 6000, vec![data_nr(&[r], 6000)]));
    let m = MemSource::new(img.build());

    let probe = super::probe(&m).unwrap();
    let opts = ScanOptions { include_existing: Some(false), ..Default::default() };
    let (ctx, t) = ScanCtx::for_test(opts, m.len());
    super::quick_scan(&m, &ctx).unwrap();
    let quick = t.files.lock().unwrap().len();
    sweep(&m, Some(&probe), &ctx);
    let files = t.files.lock().unwrap().clone();
    let loose: Vec<&FoundFile> = files[quick..].iter().collect();
    let old_pdf = loose.iter().find(|f| f.name == "old.pdf").expect("old.pdf");
    assert_eq!(old_pdf.folder, "\\Old docs");
    assert_eq!(old_pdf.status, FileStatus::Deleted);
    assert_ne!(old_pdf.flags & flags::LOOSE_RECORD, 0);
    assert_eq!(old_pdf.condition, Condition::Excellent, "{}", old_pdf.note);
    assert_eq!(read_all(&m, old_pdf), old);
    let stray = loose.iter().find(|f| f.name == "stray.txt").expect("stray");
    assert_eq!((stray.status, stray.folder.as_str()), (FileStatus::Lost, "\\Lost folders\\Folder 999"));
    assert!(!loose.iter().any(|f| f.name == "cat.jpg"), "records in the live MFT aren't loose");
}

/// The scenario volume as partition 1 (MBR, type 07) of a disk, at 1 MiB, followed by free space.
fn disk_with_partition(vol: &[u8]) -> Vec<u8> {
    let start = 1usize << 20;
    let mut disk = vec![0u8; start];
    let e = &mut disk[446..462];
    e[4] = 0x07;
    e[8..12].copy_from_slice(&((start / 512) as u32).to_le_bytes());
    e[12..16].copy_from_slice(&((vol.len() / 512) as u32).to_le_bytes());
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk.extend_from_slice(vol);
    disk.extend_from_slice(&vec![0u8; 1 << 16]);
    disk
}

#[test]
fn sweep_of_a_whole_disk_doesnt_list_live_files_as_deleted() {
    // A deep scan of a whole disk: no quick scan ran on the partition, so the sweep reads its
    // live MFT. Existing files there are existing, not deleted.
    let s = scenario();
    let m = MemSource::new(disk_with_partition(&s.img));
    assert!(super::probe(&m).is_none());
    let rep = crate::partitions::analyze(&m).unwrap();
    assert!(rep.entries.iter().any(|p| p.offset == 1 << 20 && p.status == "ok" && p.fs.as_deref() == Some("NTFS")), "{:?}", rep.entries);

    let opts = ScanOptions { include_existing: Some(false), ..Default::default() };
    let (ctx, t) = ScanCtx::for_test(opts, m.len());
    let sum = sweep(&m, None, &ctx);
    let files = t.files.lock().unwrap().clone();
    assert!(!files.iter().any(|f| f.name == "live.bin"), "existing files aren't listed as deleted");
    assert!(files.iter().all(|f| f.status != FileStatus::Existing));
    assert_eq!(sum.deleted as usize, files.len());
    assert!(!sum.notes.iter().any(|n| n.contains("leftover file table shows")), "{:?}", sum.notes);
    let cat = find(&files, "cat.jpg");
    assert_eq!((cat.status, cat.folder.as_str()), (FileStatus::Deleted, "\\Users\\Ann\\Pictures"));
    assert_eq!(read_all(&m, cat), s.cat);
    assert_eq!(find(&files, "orphan.doc").status, FileStatus::Lost);

    // With existing files wanted, they come back as Existing.
    let opts = ScanOptions { include_existing: Some(true), ..Default::default() };
    let (ctx, t) = ScanCtx::for_test(opts, m.len());
    let sum = sweep(&m, None, &ctx);
    let files = t.files.lock().unwrap().clone();
    let live = find(&files, "live.bin");
    assert_eq!((live.status, live.folder.as_str(), live.condition), (FileStatus::Existing, "\\Users\\Ann", Condition::Excellent));
    assert_eq!(find(&files, "cat.jpg").status, FileStatus::Deleted);
    assert_eq!(sum.deleted as usize, files.iter().filter(|f| f.status != FileStatus::Existing).count());

    // Without the partition table the same volume is a leftover: its in-use flags are stale.
    let mut d = disk_with_partition(&s.img);
    d[510] = 0;
    d[1 << 20..(1 << 20) + 512].fill(0);
    let m = MemSource::new(d);
    let (ctx, t) = ScanCtx::for_test(ScanOptions { include_existing: Some(false), ..Default::default() }, m.len());
    sweep(&m, None, &ctx);
    assert_eq!(find(&t.files.lock().unwrap(), "live.bin").status, FileStatus::Deleted);
}

#[test]
fn unreadable_bitmap_sectors_are_not_free_space() {
    // The $Bitmap's only sector with bits in it is unreadable: no file may be judged "still free",
    // and the whole volume counts as allocated (nothing is carved as free space).
    let s = scenario();
    let mut m = MemSource::new(s.img.clone());
    m.bad = vec![(BITMAP_LCN * CS, BITMAP_LCN * CS + 512)];
    let (files, sum, t) = run_quick(&m, false);
    assert!(sum.notes.iter().any(|n| n.contains("Part of the volume's cluster bitmap")), "{:?}", sum.notes);
    let cat = find(&files, "cat.jpg");
    assert_eq!(cat.condition, Condition::Unknown, "{}", cat.note);
    assert!(cat.note.contains("bitmap"));
    assert_eq!(find(&files, "notes.txt").condition, Condition::Excellent, "resident files don't depend on the bitmap");
    let ranges = t.ranges.lock().unwrap().clone();
    let off = cat.extents[0].offset;
    assert!(ranges.iter().any(|&(k, s0, e0)| k == MapKind::Allocated && s0 <= off && e0 > off));

    // A $Bitmap whose run lies far beyond the volume (corrupt run list): same, and no panic.
    let mut img = Img::new(1024);
    let root = mk_ref(5, 5);
    let c = content(9, 3000);
    let r = img.store(&c, false);
    img.put(40, file_rec(40, 2, false, root, "a.txt", 3000, vec![data_nr(&[r], 3000)]));
    let sys = |num: u32, name: &str, runs: &[Run]| {
        record(
            RS,
            num,
            num as u16,
            REC_IN_USE,
            0,
            &[std_info(0, 0, 0, 6), file_name(root, name, 3, 0, false), attr_nonresident(ATTR_DATA, "", runs, 0, CS, 128, 128, 0, 0)],
        )
    };
    img.put(6, sys(6, "$Bitmap", &[Run { len: 1, lcn: Some(1 << 60) }]));
    img.put(9, sys(9, "$Secure", &[Run { len: 1 << 40, lcn: Some(1 << 58) }]));
    img.put(
        30,
        record(
            RS,
            30,
            1,
            REC_IN_USE | REC_DIRECTORY,
            0,
            &[
                std_info(0, 0, 0, 0x10),
                file_name(root, "Docs", 1, 0, true),
                attr_resident(ATTR_INDEX_ROOT, "$I30", &[0u8; 32], 0),
                attr_nonresident(ATTR_INDEX_ALLOC, "$I30", &[Run { len: 1 << 44, lcn: Some(1 << 59) }], 0, CS, CS, CS, 0, 0),
            ],
        ),
    );
    let m = MemSource::new(img.build());
    let (files, _, _) = run_quick(&m, true);
    let a = find(&files, "a.txt");
    assert_eq!(a.condition, Condition::Unknown, "{}", a.note);
    assert_eq!(read_all(&m, a), c);
}

#[test]
fn existing_files_survive_bad_sectors_in_the_second_pass() {
    // Existing files come from a second pass over the MFT, which skips the sectors the first one
    // found unreadable instead of retrying them.
    let s = scenario();
    let mut m = MemSource::new(s.img.clone());
    let rec40 = MFT_LCN * CS + 40 * RS as u64;
    m.bad = vec![(rec40, rec40 + 512)];
    let (files, sum, _) = run_quick(&m, true);
    assert!(!files.iter().any(|f| f.name == "cat.jpg"));
    let live = find(&files, "live.bin");
    assert_eq!((live.status, live.folder.as_str()), (FileStatus::Existing, "\\Users\\Ann"));
    assert_eq!(sum.files as usize, files.len());
    assert_eq!(sum.deleted as usize, files.iter().filter(|f| f.status != FileStatus::Existing).count());
    // Same deleted files as without existing ones.
    let (only_deleted, _, _) = run_quick(&m, false);
    let mut a: Vec<_> = files.iter().filter(|f| f.status != FileStatus::Existing).map(|f| (f.folder.clone(), f.name.clone())).collect();
    let mut b: Vec<_> = only_deleted.iter().map(|f| (f.folder.clone(), f.name.clone())).collect();
    a.sort();
    b.sort();
    assert_eq!(a, b);
}

// ------------------------------------------------------------------- downloaded images

fn downloaded(rel: &str) -> Option<Vec<u8>> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata").join("downloads").join(rel);
    match std::fs::read(&p) {
        Ok(d) => Some(d),
        Err(_) => {
            println!("SKIPPED: {} is not there (download it to run this test).", p.display());
            None
        }
    }
}

/// Digital Forensics Tool Testing image #7, "NTFS Undelete" (dftt.sourceforge.net, Brian Carrier,
/// GPL). Answer key: http://dftt.sourceforge.net/test7/index.html
#[test]
fn dftt_7_ntfs_undelete() {
    let Some(img) = downloaded("dftt7/x/7-undel-ntfs/7-ntfs-undel.dd") else { return };
    let m = MemSource::new(img);
    let p = super::probe(&m).expect("NTFS");
    println!("probe: {p:?}");
    let (files, sum, _) = run_quick(&m, false);
    for f in &files {
        println!("{:>4} {:<28} {:<20} {:>5} {:?} {:?} {}", f.fs_ref.unwrap_or(0), f.name, f.folder, f.size, f.status, f.condition, f.note);
    }
    println!("{sum:?}");
    // (record, folder, name, size, md5)
    let key: [(u64, &str, &str, u64, &str); 9] = [
        (37, "", "res1.dat", 101, "9036637712b491904cd0bfbdbe648453"),
        (31, "", "sing1.dat", 780, "59b20779f69ff9f0ac5fcd2c38835a79"),
        (32, "", "mult1.dat", 3801, "ffd27bd782bdce67750b6b9ee069d2ef"),
        (32, "", "mult1.dat:ADS", 1234, "ba1b9eedb1c091ddca253d35dde8f616"),
        (29, "", "frag1.dat", 1584, "7a3bc5b763bef201202108f4ba128149"),
        (30, "", "frag2.dat", 3873, "0e80ab84ef0087e60dfc67b88a1cf13e"),
        (36, "\\dir1", "mult2.dat", 1715, "59cf0e9cd107bc1e75afb7374f6e05bb"),
        (35, "\\dir1\\dir2", "frag3.dat", 2027, "21121699487f3fbbdb9a4b3391b6d3e0"),
        // dir3's record (37) was reused by res1.dat, so sing2.dat's folder is lost.
        (38, "\\Lost folders\\Folder 37", "sing2.dat", 1005, "c229626f6a71b167ad7e50c4f2fccdb1"),
    ];
    for (rec, folder, name, size, sum5) in key {
        let f = files.iter().find(|f| f.name == name && f.fs_ref == Some(rec)).unwrap_or_else(|| panic!("{name} missing"));
        assert_eq!(f.folder, folder, "{name}");
        assert_eq!(f.size, size, "{name}");
        assert_eq!(md5(&read_all(&m, f)), sum5, "{name} content");
        assert_eq!(f.status, if folder.starts_with("\\Lost") { FileStatus::Lost } else { FileStatus::Deleted }, "{name}");
        // Leap-year check: created 29 Feb 2004 (local time somewhere; allow the day either side).
        let feb29 = 1_078_012_800_000i64;
        let c = f.created.expect("created");
        assert!((feb29 - 86_400_000..feb29 + 2 * 86_400_000).contains(&c), "{name} created {c}");
    }
    assert!(files.iter().any(|f| f.name == "frag2.dat" && f.fragmented));
    assert!(!files.iter().any(|f| f.name == "dir1" || f.name == "dir2"), "folders aren't files");

    // Deep scan of the live volume: every record is inside the live MFT, nothing is loose.
    let (ctx, t) = ScanCtx::for_test(ScanOptions::default(), m.len());
    sweep(&m, Some(&p), &ctx);
    assert!(t.files.lock().unwrap().is_empty());

    // The same volume with its boot sector wiped, 63 sectors into a "disk": the sweep must work
    // out the 1 KiB clusters and the volume start from the leftover $MFT record and still
    // recover every file of the answer key with the right content.
    let start = 63 * 512u64;
    let mut disk = vec![0u8; start as usize];
    disk.extend_from_slice(&m.data);
    disk[start as usize..start as usize + 512].fill(0);
    let dm = MemSource::new(disk);
    assert!(super::probe(&dm).is_none());
    let (ctx, t) = ScanCtx::for_test(ScanOptions::default(), dm.len());
    let s = sweep(&dm, None, &ctx);
    println!("{s:?}");
    assert!(s.notes.iter().any(|n| n.contains(&format!("starting at byte {start} with 1.0 KB clusters"))), "{:?}", s.notes);
    let loose = t.files.lock().unwrap().clone();
    for (_, folder, name, size, sum5) in key {
        let f = loose.iter().find(|f| f.name == name && f.size == size).unwrap_or_else(|| panic!("{name} missing from the sweep"));
        assert_eq!(f.folder, folder, "{name}");
        assert_ne!(f.flags & flags::LOOSE_RECORD, 0);
        assert_eq!(md5(&read_all(&dm, f)), sum5, "{name} content via sweep");
    }
}

/// The `ntfs` crate's test image (github.com/ColinFinck/ntfs, testdata/testfs1, made by
/// create-testfs1.sh: mkntfs -c 512 -L mylabel, then a few files and 512 folders). Nothing is
/// deleted, so it is read with existing files included.
#[test]
fn ntfs_crate_testfs1() {
    let Some(img) = downloaded("ntfs-testfs1/testfs1") else { return };
    let m = MemSource::new(img);
    let p = super::probe(&m).expect("NTFS");
    assert_eq!(p.label, "mylabel");
    assert_eq!(p.cluster_size, 512);
    let (none, _, _) = run_quick(&m, false);
    assert!(none.is_empty(), "nothing was deleted: {:?}", none.iter().map(|f| &f.name).collect::<Vec<_>>());
    let (files, sum, t) = run_quick(&m, true);
    for f in &files {
        println!("{:<20} {:<10} {:>7} {:?} {:?}", f.name, f.folder, f.size, f.extents, f.status);
    }
    println!("{sum:?}");
    let r = find(&files, "file-with-12345");
    assert_eq!((r.status, r.resident.as_deref()), (FileStatus::Existing, Some(&b"12345"[..])));
    let k = find(&files, "1000-bytes-file");
    assert_eq!(read_all(&m, k), b"12345".repeat(200));
    let sp = find(&files, "sparse-file");
    assert_eq!(sp.size, 500_005);
    let d = read_all(&m, sp);
    assert_eq!(&d[..5], b"12345");
    assert_eq!(&d[500_000..], b"11111");
    assert!(d[5..500_000].iter().all(|&b| b == 0));
    assert!(sp.extents.iter().any(|e| e.offset == SPARSE));
    assert!(!files.iter().any(|f| f.name == "empty-file"), "no data");
    // 512 folders need index allocation blocks: marked as metadata.
    assert!(files.iter().all(|f| f.folder.is_empty()));
    let meta = t.ranges.lock().unwrap().iter().filter(|r| r.0 == MapKind::Metadata).count();
    assert!(meta > 5);

    // Both boot sectors wiped: the sweep infers 512-byte clusters and finds the same files.
    // (With the backup intact the live MFT is known and nothing is loose.)
    let mut d = m.data.clone();
    d[..512].fill(0);
    let n = d.len();
    d[n - 512..].fill(0);
    let dm = MemSource::new(d);
    let (ctx, t) = ScanCtx::for_test(ScanOptions::default(), dm.len());
    let s = sweep(&dm, None, &ctx);
    assert!(s.notes.iter().any(|n| n.contains("starting at byte 0 with 512 bytes clusters")), "{:?}", s.notes);
    let loose = t.files.lock().unwrap().clone();
    assert_eq!(read_all(&dm, find(&loose, "1000-bytes-file")), b"12345".repeat(200));
    let sp = find(&loose, "sparse-file");
    assert_eq!(&read_all(&dm, sp)[500_000..], b"11111");
}

/// Throughput check on a synthetic MFT (run explicitly: cargo test ntfs_perf -- --ignored --nocapture).
#[test]
#[ignore]
fn ntfs_perf() {
    let n: u64 = std::env::var("NTFS_PERF_RECORDS").ok().and_then(|v| v.parse().ok()).unwrap_or(200_000);
    let mft_lcn = 16u64;
    let mft_bytes = n * RS as u64;
    let clusters = mft_lcn + mft_bytes / CS + 1024;
    let mut d = vec![0u8; (clusters * CS) as usize];
    let root = mk_ref(5, 5);
    let r0 = record(
        RS,
        0,
        1,
        REC_IN_USE,
        0,
        &[std_info(0, 0, 0, 6), file_name(root, "$MFT", 3, 0, false), attr_nonresident(ATTR_DATA, "", &[Run { len: mft_bytes / CS, lcn: Some(mft_lcn) }], 0, mft_bytes, mft_bytes, mft_bytes, 0, 0)],
    );
    let base = (mft_lcn * CS) as usize;
    d[base..base + RS].copy_from_slice(&r0);
    let r5 = dir_rec(5, 5, true, root, ".");
    d[base + 5 * RS..base + 6 * RS].copy_from_slice(&r5);
    for i in 24..n {
        let parent = if i % 50 == 0 { root } else { mk_ref(i - i % 50, 1) };
        let r = if i % 50 == 0 {
            dir_rec(i, 1, true, parent, &format!("dir{i}"))
        } else {
            file_rec(i, 1, i % 10 != 0, parent, &format!("file number {i}.txt"), 5000, vec![data_nr(&[Run { len: 2, lcn: Some(100 + i) }], 5000)])
        };
        d[base + i as usize * RS..base + (i as usize + 1) * RS].copy_from_slice(&r);
    }
    let bs = boot_sector(clusters * CS / 512 - 1, mft_lcn, 2);
    d[..512].copy_from_slice(&bs);
    let m = MemSource::new(d);
    let t0 = std::time::Instant::now();
    let (files, _, _) = run_quick(&m, false);
    let dt = t0.elapsed();
    println!("{n} records, {} deleted files reported in {:?} ({:.1} µs/record)", files.len(), dt, dt.as_secs_f64() * 1e6 / n as f64);
    let t0 = std::time::Instant::now();
    let (files, _, _) = run_quick(&m, true);
    let dt = t0.elapsed();
    println!("with existing: {} files in {:?}", files.len(), dt);
}
