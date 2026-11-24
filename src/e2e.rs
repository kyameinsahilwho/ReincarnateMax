//! End-to-end checks with every real engine wired together (no fakes): a deep scan of a public
//! forensic test image through the scan pipeline and the SQLite store, then recovery through the
//! recovery engine, comparing recovered bytes with the image's published answer key (MD5).
//! The images live in testdata/downloads (gitignored; the NTFS agent's tests fetch them); the tests
//! say why and pass when they're missing.

use crate::model::{FileStatus, ScanOptions, SourceKind, SourceRef};
use crate::scan::pipeline::{Config, RealEngines};
use crate::scan::{jobs, store, FileQuery};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn testdata(rel: &str) -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata").join("downloads").join(rel);
    p.is_file().then_some(p)
}

/// Minimal MD5 (RFC 1321) — only to compare with published answer keys.
fn md5(data: &[u8]) -> String {
    let s: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11,
        16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64).map(|i| ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32).collect();
    let (mut a0, mut b0, mut c0, mut d0) = (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_le_bytes());
    for chunk in msg.chunks(64) {
        let m: Vec<u32> = chunk.chunks(4).map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]])).collect();
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
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
            b = b.wrapping_add(f2.rotate_left(s[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    [a0, b0, c0, d0].iter().flat_map(|x| x.to_le_bytes()).map(|b| format!("{b:02x}")).collect()
}

#[test]
fn md5_matches_rfc_vectors() {
    assert_eq!(md5(b""), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(md5(b"The quick brown fox jumps over the lazy dog"), "9e107d9d372bb6826bd81d3542a419d6");
}

/// Deep scan of DFTT #7 "NTFS Undelete" with all real engines, then recover every deleted file and
/// check each one against the image's answer key.
#[test]
fn dftt7_deep_scan_and_recover_end_to_end() {
    let Some(img) = testdata("dftt7/x/7-undel-ntfs/7-ntfs-undel.dd") else {
        eprintln!("skipped: testdata/downloads/dftt7 is missing (run the fs::ntfs tests to download it)");
        return;
    };
    let events: Arc<Mutex<Vec<(String, serde_json::Value)>>> = Arc::new(Mutex::new(Vec::new()));
    let ev = events.clone();
    let cfg = Config::new(Arc::new(RealEngines), Arc::new(move |n: &str, v: serde_json::Value| ev.lock().unwrap().push((n.to_string(), v))));
    let source = SourceRef { kind: SourceKind::Image, path: img.to_string_lossy().into_owned(), ..Default::default() };
    let started = jobs::start(cfg, source, ScanOptions { mode: "deep".into(), ..Default::default() }).expect("scan starts");
    let t = Instant::now();
    let done = loop {
        if let Some((_, v)) = events.lock().unwrap().iter().find(|(n, v)| n == "scan-done" && v["job"] == started.job) {
            break v.clone();
        }
        assert!(t.elapsed() < Duration::from_secs(120), "scan didn't finish");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(done["state"], "done", "scan-done: {done}");

    let sid = &started.session_id;
    let ids = store::query_ids(sid, &FileQuery::default()).unwrap();
    let files: Vec<_> = ids.iter().map(|&id| (id, store::get_file(sid, id).unwrap())).collect();
    let path_of = |f: &crate::model::FoundFile| format!("{}\\{}", f.folder, f.name);
    for (_, f) in &files {
        eprintln!("{:?} {:?} {} ({} bytes, {:?})", f.status, f.origin, path_of(f), f.size, f.condition);
    }

    // Answer key: (name, size, md5). sing2.dat's folder record was reused, so its folder can't be
    // known — MAX lists it under Lost folders, which the key accepts ("dir3\sing2.dat").
    let key = [
        ("res1.dat", 101, "9036637712b491904cd0bfbdbe648453"),
        ("sing1.dat", 780, "59b20779f69ff9f0ac5fcd2c38835a79"),
        ("mult1.dat", 3801, "ffd27bd782bdce67750b6b9ee069d2ef"),
        ("mult1.dat:ADS", 1234, "ba1b9eedb1c091ddca253d35dde8f616"),
        ("frag1.dat", 1584, "7a3bc5b763bef201202108f4ba128149"),
        ("frag2.dat", 3873, "0e80ab84ef0087e60dfc67b88a1cf13e"),
        ("mult2.dat", 1715, "59cf0e9cd107bc1e75afb7374f6e05bb"),
        ("frag3.dat", 2027, "21121699487f3fbbdb9a4b3391b6d3e0"),
        ("sing2.dat", 1005, "c229626f6a71b167ad7e50c4f2fccdb1"),
    ];

    // Recover the file-system finds through the real recovery engine into a temp folder.
    let fs_ids: Vec<i64> = files.iter().filter(|(_, f)| f.status != FileStatus::Carved).map(|(id, _)| *id).collect();
    let dest = std::env::temp_dir().join(format!("max-e2e-{}-{}", std::process::id(), crate::model::now_ms()));
    std::fs::create_dir_all(&dest).unwrap();
    let src = store::open_session_source(sid).unwrap();
    let sid2 = sid.clone();
    let load = move |id: i64| store::get_file(&sid2, id);
    let opts = crate::recover::engine::EngineOpts { keep_folders: true, skip_duplicates: false, verify: true, repair: false, fat_dest: false };
    let cancel = AtomicBool::new(false);
    let hooks = crate::recover::engine::Hooks::default();
    let out = crate::recover::engine::recover_files(Some(src), &fs_ids, &load, 0, &dest, "dftt7", &opts, &cancel, &hooks, &mut |_| {});
    assert_eq!(out.failed, 0, "failures: {:?}", out.results.iter().filter(|r| r.path.is_none()).map(|r| (&r.name, &r.notes)).collect::<Vec<_>>());

    for (name, size, want) in key {
        let r = out.results.iter().find(|r| r.name == name || r.name.replace(':', "_") == name.replace(':', "_")).unwrap_or_else(|| panic!("{name} wasn't recovered"));
        assert_eq!(r.size, size, "{name} size");
        let bytes = std::fs::read(r.path.as_ref().unwrap()).unwrap();
        assert_eq!(md5(&bytes), want, "{name} MD5");
    }
    // Folder reconstruction: mult2.dat and frag3.dat inside their deleted folders.
    let folder = |n: &str| files.iter().find(|(_, f)| f.name == n).map(|(_, f)| f.folder.clone()).unwrap_or_default();
    assert_eq!(folder("mult2.dat"), "\\dir1");
    assert_eq!(folder("frag3.dat"), "\\dir1\\dir2");
    assert!(folder("sing2.dat").starts_with("\\Lost folders"), "sing2.dat folder: {}", folder("sing2.dat"));
    // Leap-day timestamps (2004-02-29) survive the trip.
    let res1 = files.iter().find(|(_, f)| f.name == "res1.dat").unwrap();
    let created = res1.1.created.expect("created time");
    assert_eq!(created / 86_400_000, 12_477, "2004-02-29 is day 12477 since 1970");

    // The Recovery Map has file-system metadata and recoverable data marked.
    let md = tauri::async_runtime::block_on(crate::scan::map_cells(sid.clone(), Some(0), Some(src_len(sid)), 1024)).unwrap();
    assert!(md.totals[1] > 0 && md.totals[3] > 0, "map totals {:?}", md.totals);

    assert!(dest.starts_with(std::env::temp_dir()));
    let _ = std::fs::remove_dir_all(&dest);
}

fn src_len(sid: &str) -> u64 {
    store::open_session_source(sid).map(|s| s.len()).unwrap_or(0)
}
