//! Where MAX keeps its data. Normal installs use %LOCALAPPDATA%\com.maxrecovery.app; portable mode
//! (a `portable` file or a `MAXData` folder next to the exe, or the `--portable` flag) keeps
//! everything (sessions, settings, logs, cache, WebView2 data) in `<exe folder>\MAXData` so the app
//! can run from a USB stick without leaving traces. Deciding where the data goes writes nothing:
//! folders are made the first time something is saved in them (reads never create them).
//!
//! Three cases are never handled silently:
//! - Portable mode on read-only media (locked SD card, CD, read-only share): the data goes to a folder
//!   under %TEMP% and `portable_warning()` says so (shown in system_info).
//! - Elevated as another account (over-the-shoulder UAC, Administrator protection): the data is in
//!   that account's own %LOCALAPPDATA%, never in the desktop user's profile (a less trusted account
//!   could redirect the administrator's writes there), and `data_note()` says whose it is.
//! - A scan reads the drive that holds the data folder: optional writes (log lines, cache entries)
//!   are held in memory meanwhile (`hold_writes`, set by main.rs) and written once it ends.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

pub const IDENTIFIER: &str = "com.maxrecovery.app";
pub const PORTABLE_ARG: &str = "--portable";

#[cfg_attr(test, allow(dead_code))]
fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(|p| p.to_path_buf())
}

/// True when running in portable mode (decided once per process).
pub fn is_portable() -> bool {
    root().portable
}

/// Where the data lives, decided once per process.
#[derive(Default)]
struct Root {
    /// `None` only when not even a fallback could be found.
    dir: Option<PathBuf>,
    portable: bool,
    portable_warning: Option<String>,
    note: Option<String>,
}

fn root() -> &'static Root {
    static R: OnceLock<Root> = OnceLock::new();
    R.get_or_init(resolve)
}

#[cfg_attr(test, allow(dead_code))]
fn portable_requested(exe: &Path) -> bool {
    std::env::args().any(|a| a == PORTABLE_ARG) || exe.join("portable").exists() || exe.join("MAXData").is_dir()
}

/// True when the volume holding `dir` is mounted read-only (write-protected media, CD/DVD).
fn read_only_volume(dir: &Path) -> bool {
    use windows_sys::Win32::Storage::FileSystem::{GetVolumeInformationW, GetVolumePathNameW};
    const FILE_READ_ONLY_VOLUME: u32 = 0x0008_0000;
    let p = crate::util::wide(&dir.to_string_lossy());
    let mut root = [0u16; 1024];
    if unsafe { GetVolumePathNameW(p.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
        return false;
    }
    let mut flags = 0u32;
    let ok = unsafe {
        GetVolumeInformationW(root.as_ptr(), std::ptr::null_mut(), 0, std::ptr::null_mut(), std::ptr::null_mut(), &mut flags, std::ptr::null_mut(), 0)
    } != 0;
    ok && flags & FILE_READ_ONLY_VOLUME != 0
}

/// Whether files and folders can be created in the existing folder `dir`, checked without writing
/// anything: the folder is opened asking for the right to add files and folders, which Windows
/// refuses on read-only media and without permission.
fn may_write_in(dir: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_ADD_FILE: u32 = 0x2;
    const FILE_ADD_SUBDIRECTORY: u32 = 0x4;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    dir.is_dir()
        && !read_only_volume(dir)
        && std::fs::OpenOptions::new()
            .access_mode(FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY)
            .share_mode(7)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(dir)
            .is_ok()
}

/// Data folder used in portable mode when the program's folder is read-only.
fn portable_fallback() -> PathBuf {
    std::env::temp_dir().join(format!("{IDENTIFIER}-portable"))
}

fn portable_warning_for(fallback: &Path) -> String {
    format!(
        "The folder MAX runs from is read-only, so its data is kept in {} on this PC for now; copy MAX to a writable drive to keep everything next to the program.",
        fallback.display()
    )
}

#[cfg_attr(test, allow(dead_code))]
const OTHER_ACCOUNT_NOTE: &str =
    "MAX is running as a different Windows account, so this scan list and these settings belong to that account.";

/// Tests never touch the user's real data folder.
#[cfg(test)]
fn resolve() -> Root {
    Root { dir: Some(std::env::temp_dir().join("max-test-data")), ..Root::default() }
}

#[cfg(not(test))]
fn resolve() -> Root {
    let mut r = Root::default();
    if let Some(exe) = exe_dir().filter(|e| portable_requested(e)) {
        r.portable = true;
        let next_to_exe = exe.join("MAXData");
        // Checked without creating MAXData or anything in it.
        let check = if next_to_exe.is_dir() { next_to_exe.clone() } else { exe };
        if may_write_in(&check) {
            r.dir = Some(next_to_exe);
        } else {
            let fb = portable_fallback();
            r.portable_warning = Some(portable_warning_for(&fb));
            r.dir = Some(fb);
        }
        return r;
    }
    // Always this account's own folder. Elevated as another account, the desktop user's profile is
    // never used: that less trusted user could redirect the administrator's writes from there.
    // `None` (elevated while Explorer isn't running): nothing to say.
    if crate::other_account::desktop_account_differs() == Some(true) {
        r.note = Some(OTHER_ACCOUNT_NOTE.into());
    }
    r.dir = std::env::var_os("LOCALAPPDATA").map(|l| PathBuf::from(l).join(IDENTIFIER));
    r
}

/// Set when portable mode had to give up the folder next to the program after all.
static FALLBACK: OnceLock<PathBuf> = OnceLock::new();

/// The data folder, without creating it (for reads and for showing it).
pub fn data_path() -> Option<PathBuf> {
    FALLBACK.get().cloned().or_else(|| root().dir.clone())
}

/// Root data folder, created when needed (by whatever saves something in it).
pub fn data_dir() -> Option<PathBuf> {
    let d = data_path()?;
    if std::fs::create_dir_all(&d).is_ok() {
        return Some(d);
    }
    // Portable mode on media that turned out to be read-only: keep the data under %TEMP%.
    let r = root();
    if r.portable && r.portable_warning.is_none() && FALLBACK.get().is_none() {
        let fb = FALLBACK.get_or_init(portable_fallback).clone();
        return std::fs::create_dir_all(&fb).ok().map(|_| fb);
    }
    None
}

/// One sentence when portable mode can't keep its data next to the program (read-only media).
pub fn portable_warning() -> Option<String> {
    root().portable_warning.clone().or_else(|| FALLBACK.get().map(|fb| portable_warning_for(fb)))
}

/// One sentence when the data folder isn't the signed-in user's (elevated as another account: the
/// data folder is that account's own).
pub fn data_note() -> Option<String> {
    root().note.clone()
}

fn sub(name: &str) -> Option<PathBuf> {
    let d = data_dir()?.join(name);
    std::fs::create_dir_all(&d).ok()?;
    Some(d)
}

/// Scan sessions: one `<id>.maxscan` SQLite file each.
pub fn sessions_dir() -> Option<PathBuf> {
    sub("sessions")
}
/// App log files.
pub fn logs_dir() -> Option<PathBuf> {
    sub("logs")
}
/// Small JSON cache (cache.rs), created when needed.
pub fn cache_dir() -> Option<PathBuf> {
    sub("cache")
}
/// The cache folder without creating it (for reads).
pub fn cache_path() -> Option<PathBuf> {
    Some(data_path()?.join("cache"))
}
/// WebView2 user data in portable mode (None = Tauri's default location). Also in portable mode on
/// read-only media: then it is in the %TEMP% fallback folder, never in %LOCALAPPDATA%.
pub fn webview_dir(elevated: bool) -> Option<PathBuf> {
    if !is_portable() {
        return None;
    }
    sub(if elevated { "webview-elevated" } else { "webview" })
}

static HOLD: AtomicBool = AtomicBool::new(false);

/// Hold optional writes (log lines, cache entries) in memory while a scan reads the drive that holds
/// the data folder, so they don't land in the free space being searched. Returns the previous value.
pub fn set_hold_writes(on: bool) -> bool {
    HOLD.swap(on, Ordering::SeqCst)
}

pub fn hold_writes() -> bool {
    HOLD.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("max-paths-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn write_check_writes_nothing() {
        let d = temp("maywrite");
        assert!(may_write_in(&d));
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0);
        assert!(!may_write_in(&d.join("missing")));
        assert!(!d.join("missing").exists());
        std::fs::write(d.join("file"), b"x").unwrap();
        assert!(!may_write_in(&d.join("file")));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn portable_fallback_is_under_temp_and_explained() {
        let fb = portable_fallback();
        assert!(fb.starts_with(std::env::temp_dir()));
        let w = portable_warning_for(&fb);
        assert!(w.contains("read-only") && w.contains(&fb.display().to_string()) && w.ends_with('.'));
    }

    #[test]
    fn portable_mode_is_asked_for_by_marker_or_folder() {
        let d = temp("portable");
        assert!(!portable_requested(&d));
        std::fs::write(d.join("portable"), b"").unwrap();
        assert!(portable_requested(&d));
        std::fs::remove_file(d.join("portable")).unwrap();
        std::fs::create_dir_all(d.join("MAXData")).unwrap();
        assert!(portable_requested(&d));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tests_use_a_temp_data_folder_and_reads_create_nothing() {
        let d = data_path().unwrap();
        assert!(d.starts_with(std::env::temp_dir()), "{}", d.display());
        assert_eq!(cache_path().unwrap(), d.join("cache"));
        assert!(data_note().is_none());
    }

    #[test]
    fn other_account_note_says_whose_data_it_is() {
        assert_eq!(
            OTHER_ACCOUNT_NOTE,
            "MAX is running as a different Windows account, so this scan list and these settings belong to that account."
        );
    }
}
