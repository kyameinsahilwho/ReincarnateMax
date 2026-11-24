//! Destination safety: where recovered files (and reports) may be written. The rule that matters:
//! never onto the physical disk being recovered from. Win32 lookups gather [`DestFacts`] /
//! [`SourceFacts`]; [`decide`] is the pure decision, unit-tested without any drive.
//! Nothing here creates, opens for writing or changes anything.

use super::DestCheck;
use crate::model::{human_size, SourceKind, SourceRef};
use crate::util::wide;
use std::path::Path;
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetDiskFreeSpaceExW, GetFullPathNameW, GetVolumeInformationW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::Storage::FileSystem::IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS;
use windows_sys::Win32::System::IO::DeviceIoControl;

pub const SAME_DISK: &str = "This folder is on the drive you are recovering from. Recovering there could overwrite the files you want back — pick a folder on another drive.";
const INSIDE_IMAGE: &str = "That location is the disk image you are recovering from. Pick a folder on another drive.";
const DEST_UNKNOWN: &str = "MAX couldn't tell which drive this folder is on, so it can't rule out the drive you are recovering from. Pick a folder on another drive.";
const SOURCE_UNKNOWN: &str = "MAX couldn't tell which physical drive you are recovering from, so it can't rule this folder out. Pick a folder on a USB drive or another disk.";
const FAT_LIMIT: u64 = 0xFFFF_FFFF;

/// What we know about a destination folder.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DestFacts {
    /// Normalised absolute path.
    pub path: String,
    /// The path exists and is a file.
    pub is_file: bool,
    /// A parent component exists as a file, so the folder can't be created.
    pub blocked_by_file: bool,
    /// `\\?\Volume{…}\`, lowercase.
    pub volume: Option<String>,
    /// Physical disk numbers holding the volume.
    pub disks: Option<Vec<u32>>,
    /// `\\server\share` (lowercase) for network folders.
    pub network_root: Option<String>,
    /// "NTFS", "FAT32", "exFAT" …
    pub fs_name: String,
    pub free: Option<u64>,
    /// The real path after junctions, symlinks, subst and mapped drives (additive).
    pub real_path: Option<String>,
    /// A sentence when the folder can't be checked safely (a share on this PC that can't be
    /// placed, a virtual disk whose file can't be found): refuse it.
    pub refuse: Option<String>,
}

/// What we know about where the scanned bytes live.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SourceFacts {
    pub volume: Option<String>,
    pub disks: Option<Vec<u32>>,
    pub network_root: Option<String>,
    /// Image sources: the image file's normalised path (lowercase).
    pub image_path: Option<String>,
    /// Image sources: the image file's real path after links (lowercase).
    pub image_real_path: Option<String>,
}

impl DestFacts {
    pub fn is_fat(&self) -> bool {
        let f = self.fs_name.to_ascii_uppercase();
        f.starts_with("FAT") && f != "FATX"
    }
}

fn server_of(root: &str) -> &str {
    root.trim_start_matches('\\').split('\\').next().unwrap_or("")
}

/// The decision, without touching Windows.
#[allow(dead_code)]
pub fn decide(d: &DestFacts, s: &SourceFacts, sizes: &[u64]) -> DestCheck {
    let need: u64 = sizes.iter().sum();
    let big = sizes.iter().filter(|&&n| n > FAT_LIMIT).count() as u64;
    decide_totals(d, s, need, big)
}

/// [`decide`] from totals: `need` bytes in all, `big` files larger than 4 GB.
pub fn decide_totals(d: &DestFacts, s: &SourceFacts, need: u64, big: u64) -> DestCheck {
    let mut c = DestCheck { ok: false, error: None, warnings: Vec::new(), free_bytes: d.free.unwrap_or(0), need_bytes: need, path: d.path.clone(), on_source_disk: false };
    let fail = |mut c: DestCheck, msg: &str, on_source: bool| {
        c.error = Some(msg.to_string());
        c.on_source_disk = on_source;
        c.ok = false;
        c
    };
    if d.is_file {
        return fail(c, "That's a file, not a folder. Pick a folder.", false);
    }
    if d.blocked_by_file {
        return fail(c, "Part of that path is a file, so the folder can't be created. Pick another folder.", false);
    }
    let dest_paths: Vec<String> = std::iter::once(&d.path).chain(d.real_path.iter()).map(|p| p.to_lowercase()).collect();
    for img in s.image_path.iter().chain(s.image_real_path.iter()) {
        if dest_paths.iter().any(|lp| lp == img || lp.starts_with(&format!("{img}\\"))) {
            return fail(c, INSIDE_IMAGE, true);
        }
    }
    if let Some(msg) = &d.refuse {
        return fail(c, msg, false);
    }
    if let (Some(a), Some(b)) = (&d.volume, &s.volume) {
        if a == b {
            return fail(c, SAME_DISK, true);
        }
    }
    if let (Some(a), Some(b)) = (&d.disks, &s.disks) {
        if a.iter().any(|x| b.contains(x)) {
            return fail(c, SAME_DISK, true);
        }
    }
    match (&d.network_root, &d.disks) {
        (Some(root), _) => {
            if let Some(sr) = &s.network_root {
                if sr == root || server_of(sr).eq_ignore_ascii_case(server_of(root)) {
                    return fail(c, SAME_DISK, true);
                }
            }
            c.warnings.push("This is a network folder: MAX can't see which drive holds it, but it isn't a drive in this PC. Copying over the network may be slow.".into());
        }
        (None, None) => {
            // A local folder on an unknown disk could be the source — unless the source is remote.
            if !(s.disks.is_none() && (s.network_root.is_some() || s.image_path.is_some())) {
                return fail(c, DEST_UNKNOWN, false);
            }
        }
        (None, Some(_)) => {
            if s.disks.is_none() && s.network_root.is_none() && s.image_path.is_none() {
                return fail(c, SOURCE_UNKNOWN, false);
            }
        }
    }
    if let Some(free) = d.free {
        if need > free {
            return fail(c, &format!("The destination needs at least {} free; it has {}.", human_size(need), human_size(free)), false);
        }
    }
    if d.is_fat() {
        if big > 0 {
            c.warnings.push(if big == 1 {
                "1 file is larger than 4 GB and can't be written to a FAT32 drive.".to_string()
            } else {
                format!("{big} files are larger than 4 GB and can't be written to a FAT32 drive.")
            });
        }
    }
    c.ok = true;
    c
}

// ------------------------------------------------------------------------------ normalisation

/// Refuse what Windows would silently reinterpret. Pure; runs before `GetFullPathNameW`.
pub fn pre_check(input: &str) -> Result<String, String> {
    let p = input.replace('/', "\\");
    if p.trim().is_empty() {
        return Err("Pick a folder to recover to.".into());
    }
    if p.starts_with("\\\\?\\") || p.starts_with("\\\\.\\") {
        return Err("Use a normal folder path, like D:\\Recovered.".into());
    }
    let b = p.as_bytes();
    let drive_abs = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
    let unc = p.starts_with("\\\\") && p[2..].split('\\').filter(|s| !s.is_empty()).count() >= 2;
    if !drive_abs && !unc {
        return Err("Use a full folder path that starts with a drive letter, like D:\\Recovered.".into());
    }
    let rest = if drive_abs { &p[3..] } else { &p[2..] };
    for comp in rest.split('\\') {
        if comp.is_empty() || comp == "." || comp == ".." {
            continue;
        }
        if comp.ends_with('.') || comp.ends_with(' ') {
            return Err("Folder names can't end with a dot or a space. Pick another folder.".into());
        }
        if comp.chars().any(|c| c < ' ' || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')) {
            return Err("That folder name has characters Windows doesn't allow. Pick another folder.".into());
        }
    }
    Ok(p)
}

fn full_path(p: &str) -> Option<String> {
    let w = wide(p);
    let mut buf = vec![0u16; 1024];
    loop {
        let n = unsafe { GetFullPathNameW(w.as_ptr(), buf.len() as u32, buf.as_mut_ptr(), std::ptr::null_mut()) } as usize;
        if n == 0 {
            return None;
        }
        if n < buf.len() {
            return Some(String::from_utf16_lossy(&buf[..n]));
        }
        buf.resize(n + 1, 0);
    }
}

/// Normalised absolute path (no trailing backslash except on a drive root).
pub fn normalize(input: &str) -> Result<String, String> {
    let p = pre_check(input)?;
    let mut full = full_path(&p).ok_or_else(|| "Windows couldn't make sense of that folder path. Pick another folder.".to_string())?;
    while full.ends_with('\\') && !(full.len() == 3 && full.as_bytes()[1] == b':') {
        full.pop();
    }
    if full.starts_with("\\\\?\\") || full.starts_with("\\\\.\\") {
        return Err("Use a normal folder path, like D:\\Recovered.".into());
    }
    Ok(full)
}

// --------------------------------------------------------------------------------- lookups

/// Physical disk numbers behind a device path (`\\?\Volume{…}`, `\\.\C:`), via
/// IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS on a handle opened with no data access (works unelevated).
#[allow(dead_code)]
pub fn disks_of_device(device: &str) -> Option<Vec<u32>> {
    let dev = device.trim_end_matches('\\');
    let w = wide(dev);
    let h = unsafe { CreateFileW(w.as_ptr(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, std::ptr::null(), OPEN_EXISTING, 0, std::ptr::null_mut()) };
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        return None;
    }
    // VOLUME_DISK_EXTENTS: u32 count, pad, then { u32 disk, pad, i64 start, i64 len } × n.
    let mut out = vec![0u64; 4 + 3 * 32];
    let mut ret = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            h,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            std::ptr::null(),
            0,
            out.as_mut_ptr() as *mut _,
            (out.len() * 8) as u32,
            &mut ret,
            std::ptr::null_mut(),
        )
    };
    unsafe { CloseHandle(h) };
    if ok == 0 || ret < 8 {
        return None;
    }
    let count = (out[0] & 0xFFFF_FFFF) as usize;
    let mut disks = Vec::new();
    for i in 0..count.min(32) {
        let idx = 1 + i * 3;
        if (idx + 3) * 8 > ret as usize {
            break;
        }
        let d = (out[idx] & 0xFFFF_FFFF) as u32;
        if !disks.contains(&d) {
            disks.push(d);
        }
    }
    (!disks.is_empty()).then_some(disks)
}

fn fs_name(volume_path: &str) -> String {
    let w = wide(volume_path);
    let mut fs = [0u16; 64];
    let ok = unsafe {
        GetVolumeInformationW(w.as_ptr(), std::ptr::null_mut(), 0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), fs.as_mut_ptr(), fs.len() as u32)
    };
    if ok != 0 {
        crate::util::from_wide(&fs)
    } else {
        String::new()
    }
}

pub fn free_space(dir: &str) -> Option<u64> {
    let mut d = dir.to_string();
    if !d.ends_with('\\') {
        d.push('\\');
    }
    let w = wide(&d);
    let mut avail = 0u64;
    let ok = unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut avail, std::ptr::null_mut(), std::ptr::null_mut()) };
    (ok != 0).then_some(avail)
}

/// Gather destination facts (read-only lookups). The folder is judged by where its bytes would
/// really land: junctions, symlinks, subst and mapped drives, shares on this PC and virtual disks
/// stored in a file are all resolved (device::win::locate_path, shared with imaging).
pub fn dest_facts(path: &str) -> DestFacts {
    let mut f = DestFacts { path: path.to_string(), ..Default::default() };
    let p = Path::new(path);
    if p.is_file() {
        f.is_file = true;
    }
    // Nearest existing ancestor must be a folder.
    let mut anc = Some(p);
    while let Some(a) = anc {
        if a.exists() {
            if !a.is_dir() && a != p {
                f.blocked_by_file = true;
            }
            break;
        }
        anc = a.parent();
    }
    let loc = crate::device::win::locate_path(path);
    f.volume = loc.volume;
    f.disks = loc.disks;
    f.network_root = loc.network_root;
    f.real_path = loc.real_path;
    f.refuse = loc.refuse;
    if let Some(root) = &loc.root {
        f.fs_name = fs_name(root);
        f.free = free_space(root);
    }
    f
}

/// Gather source facts from the session's SourceRef (read-only lookups; no source is opened for
/// data). Unknown stays unknown, so [`decide`] refuses: a snapshot's volume is looked up, never
/// guessed.
pub fn source_facts(r: &SourceRef) -> SourceFacts {
    let loc = crate::device::win::source_location(r);
    match r.kind {
        SourceKind::Image => {
            let norm = normalize(&r.path).unwrap_or_else(|_| r.path.clone());
            // Only the image file itself must not be written: recovering next to it (same drive) can't
            // change the image's bytes, and refusing its whole drive blocked the common "image on C:,
            // recover to C:" case (decided 2026-11-24).
            SourceFacts { image_path: Some(norm.to_lowercase()), image_real_path: loc.image_real_path.map(|p| p.to_lowercase()), ..Default::default() }
        }
        _ => SourceFacts { volume: loc.volume, disks: loc.disks, ..Default::default() },
    }
}

/// Full check of a destination folder for `sizes` worth of files.
pub fn run_check(dest: &str, src: &SourceRef, sizes: &[u64]) -> (DestCheck, DestFacts) {
    let need: u64 = sizes.iter().sum();
    let big = sizes.iter().filter(|&&n| n > FAT_LIMIT).count() as u64;
    run_check_totals(dest, src, need, big)
}

/// [`run_check`] from totals: `need` bytes in all, `big` files larger than 4 GB.
pub fn run_check_totals(dest: &str, src: &SourceRef, need: u64, big: u64) -> (DestCheck, DestFacts) {
    let path = match normalize(dest) {
        Ok(p) => p,
        Err(e) => {
            return (DestCheck { ok: false, error: Some(e), path: dest.to_string(), need_bytes: need, ..Default::default() }, DestFacts::default());
        }
    };
    let d = dest_facts(&path);
    let s = source_facts(src);
    (decide_totals(&d, &s, need, big), d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest(disks: &[u32]) -> DestFacts {
        DestFacts {
            path: "E:\\Recovered".into(),
            volume: Some("\\\\?\\volume{e}\\".into()),
            disks: Some(disks.to_vec()),
            fs_name: "NTFS".into(),
            free: Some(1 << 40),
            ..Default::default()
        }
    }
    fn src(disks: &[u32]) -> SourceFacts {
        SourceFacts { volume: Some("\\\\?\\volume{c}\\".into()), disks: Some(disks.to_vec()), ..Default::default() }
    }

    #[test]
    fn same_disk_is_refused() {
        let c = decide(&dest(&[0]), &src(&[0]), &[10]);
        assert!(!c.ok && c.on_source_disk);
        assert_eq!(c.error.as_deref(), Some(SAME_DISK));
        // Spanned volume touching the source disk.
        assert!(!decide(&dest(&[2, 1]), &src(&[1]), &[10]).ok);
        // Same volume even when disks are unknown.
        let mut d = dest(&[]);
        d.disks = None;
        d.volume = Some("\\\\?\\volume{c}\\".into());
        let c = decide(&d, &src(&[0]), &[1]);
        assert!(!c.ok && c.on_source_disk);
        // Other disk is fine.
        let c = decide(&dest(&[1]), &src(&[0]), &[10]);
        assert!(c.ok && c.error.is_none() && !c.on_source_disk);
        assert_eq!(c.need_bytes, 10);
    }

    #[test]
    fn image_path_is_refused() {
        let mut s = src(&[3]);
        s.image_path = Some("e:\\images\\card.img".into());
        let mut d = dest(&[1]);
        d.path = "E:\\Images\\card.img".into();
        let c = decide(&d, &s, &[]);
        assert!(!c.ok && c.on_source_disk);
        d.path = "E:\\Images\\card.img\\x".into();
        assert!(!decide(&d, &s, &[]).ok);
        d.path = "E:\\Images\\card.img2".into();
        assert!(decide(&d, &s, &[]).ok);
    }

    #[test]
    fn short_space_and_fat32() {
        let mut d = dest(&[1]);
        d.free = Some(1000);
        let c = decide(&d, &src(&[0]), &[600, 600]);
        assert!(!c.ok && !c.on_source_disk);
        assert!(c.error.unwrap().contains("needs at least 1.2 KB free; it has 1000 bytes"));
        let mut d = dest(&[1]);
        d.fs_name = "FAT32".into();
        let c = decide(&d, &src(&[0]), &[5 << 30, 1, 6 << 30]);
        assert!(c.ok);
        assert_eq!(c.warnings, vec!["2 files are larger than 4 GB and can't be written to a FAT32 drive.".to_string()]);
        d.fs_name = "exFAT".into();
        assert!(decide(&d, &src(&[0]), &[5 << 30]).warnings.is_empty());
    }

    #[test]
    fn unknown_mappings() {
        // Local dest on an unknown disk: refused.
        let mut d = dest(&[]);
        d.disks = None;
        d.volume = None;
        let c = decide(&d, &src(&[0]), &[1]);
        assert!(!c.ok && !c.on_source_disk);
        // Network dest: allowed with a warning.
        d.network_root = Some("\\\\nas\\share".into());
        let c = decide(&d, &src(&[0]), &[1]);
        assert!(c.ok && !c.warnings.is_empty());
        // Network dest on the server holding the source image: refused.
        let s = SourceFacts { network_root: Some("\\\\nas\\other".into()), image_path: Some("\\\\nas\\other\\a.img".into()), ..Default::default() };
        assert!(!decide(&d, &s, &[1]).ok);
        // Local dest, source image on a network share: allowed.
        assert!(decide(&dest(&[0]), &s, &[1]).ok);
        // Source disk unknown, local dest: refused.
        assert!(!decide(&dest(&[0]), &SourceFacts::default(), &[1]).ok);
    }

    #[test]
    fn dest_paths_are_validated() {
        assert!(pre_check("").is_err());
        assert!(pre_check("Recovered").is_err());
        assert!(pre_check("D:Recovered").is_err());
        assert!(pre_check("\\\\?\\D:\\x").is_err());
        assert!(pre_check("\\\\.\\PhysicalDrive1").is_err());
        assert!(pre_check("D:\\Recovered.").is_err());
        assert!(pre_check("D:\\Recovered \\x").is_err());
        assert!(pre_check("D:\\a|b").is_err());
        assert!(pre_check("D:\\Recovered").is_ok());
        assert!(pre_check("D:/Recovered/..").is_ok());
        assert!(pre_check("\\\\nas\\share\\x").is_ok());
        assert_eq!(normalize("D:\\a\\..\\b\\").unwrap(), "D:\\b");
        assert_eq!(normalize("D:\\").unwrap(), "D:\\");
    }

    /// Real lookups on this PC (read-only): the temp folder vs its own volume.
    #[test]
    fn temp_folder_on_its_own_volume_is_refused() {
        let tmp = std::env::temp_dir().to_string_lossy().into_owned();
        let letter = tmp.chars().next().unwrap();
        let r = SourceRef { kind: SourceKind::Volume, path: letter.to_string(), ..Default::default() };
        let (c, f) = run_check(&tmp, &r, &[1]);
        // IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS works unelevated on a local fixed drive.
        assert!(f.disks.is_some() && f.volume.is_some(), "{f:?}");
        assert!(f.free.is_some() && !f.fs_name.is_empty(), "{f:?}");
        assert!(!c.ok && c.on_source_disk, "{c:?}");
        assert_eq!(source_facts(&r).disks, f.disks);
    }

    #[test]
    fn refusals_from_the_lookup_win() {
        let mut d = dest(&[1]);
        d.refuse = Some("This network folder is on this PC, and MAX couldn't tell which drive holds it. Pick the folder by its drive letter instead, like D:\\Recovered.".into());
        let c = decide(&d, &src(&[0]), &[1]);
        assert!(!c.ok && c.error == d.refuse);
        // The image file is matched by its real path too (reached through a link).
        let s = SourceFacts { image_path: Some("x:\\link\\card.img".into()), image_real_path: Some("e:\\images\\card.img".into()), ..Default::default() };
        let mut d = dest(&[1]);
        d.path = "Y:\\other\\card.img\\x".into();
        d.real_path = Some("E:\\Images\\card.img\\x".into());
        let c = decide(&d, &s, &[]);
        assert!(!c.ok && c.on_source_disk && c.error.as_deref() == Some(INSIDE_IMAGE));
        // Totals give the same answer as sizes.
        let mut d = dest(&[1]);
        d.fs_name = "FAT32".into();
        assert_eq!(decide(&d, &src(&[0]), &[5 << 30, 1]).warnings, decide_totals(&d, &src(&[0]), (5 << 30) + 1, 1).warnings);
    }

    /// A restore point whose volume can't be found is refused, never taken for the system drive.
    #[test]
    fn unknown_snapshot_is_refused() {
        let tmp = std::env::temp_dir().to_string_lossy().into_owned();
        let r = SourceRef { kind: SourceKind::Snapshot, path: "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy9999".into(), ..Default::default() };
        assert_eq!(source_facts(&r), SourceFacts::default());
        let (c, _) = run_check(&tmp, &r, &[1]);
        assert!(!c.ok && c.error.as_deref() == Some(SOURCE_UNKNOWN), "{c:?}");
    }

    /// A destination reached through a junction is judged by where the junction leads: a link in
    /// the project folder pointing into %TEMP% is refused when recovering the %TEMP% drive.
    #[test]
    fn junction_to_the_source_drive_is_refused() {
        let n = crate::model::now_ms();
        let target = std::env::temp_dir().join(format!("maxrec-dest-target-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&target).unwrap();
        let link = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(".maxrec-test-link-{}-{n}", std::process::id()));
        assert!(crate::device::win::tests::make_junction(&link, &target), "mklink /J failed");
        let letter = target.to_string_lossy().chars().next().unwrap();
        let r = SourceRef { kind: SourceKind::Volume, path: letter.to_string(), ..Default::default() };
        let (c, f) = run_check(&link.join("Recovered").to_string_lossy(), &r, &[1]);
        let _ = std::fs::remove_dir(&link);
        let _ = std::fs::remove_dir_all(&target);
        assert!(f.real_path.as_deref().is_some_and(|p| p.to_lowercase().contains("maxrec-dest-target")), "{f:?}");
        assert!(!c.ok && c.on_source_disk, "{c:?}");
    }
}
