//! User settings kept in `<data>\settings.json` (not the cache: these must never be cleared by a
//! cache wipe or a benchmark). Theme and the startup admin prompt live in the cache as in Platter.
//!
//! A settings file that can't be parsed is never overwritten: it is moved aside as
//! `settings.json.bad-<ms>` and the user is told (`Settings.load_warning`). One that exists but can't
//! be read (locked, no access) is left alone. When the UI got the defaults because of that, it holds
//! them instead of the user's settings, so its saves are refused (they would replace the real file)
//! until it has loaded the real settings: in practice, after a restart.

use crate::model::CustomSignature;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// User-defined carving rules (File carving rules).
    pub custom_signatures: Vec<CustomSignature>,
    /// Last folder files were recovered to.
    pub default_destination: Option<String>,
    /// Check for a new version once a day.
    pub check_updates: bool,
    /// Release feed (a GitHub "releases/latest" API URL or any JSON with tag_name + html_url).
    pub update_feed: String,
    /// Recover into folders that mirror the reconstructed structure.
    pub keep_folders: bool,
    pub verify_recovered: bool,
    pub repair_damaged: bool,
    pub skip_duplicates: bool,
    /// Set when settings.json couldn't be used (it was kept aside or left alone): one sentence for the
    /// user. Never read from the UI or written to the file.
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub load_warning: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            custom_signatures: Vec::new(),
            default_destination: None,
            check_updates: true,
            update_feed: String::new(),
            keep_folders: true,
            verify_recovered: true,
            repair_damaged: true,
            skip_duplicates: true,
            load_warning: None,
        }
    }
}

static LOCK: Mutex<()> = Mutex::new(());
/// Why a damaged settings file was set aside, until the next successful save (shown by get_settings).
static NOTICE: Mutex<Option<String>> = Mutex::new(None);
/// The UI's last get_settings returned defaults because settings.json couldn't be read.
static UI_HAS_DEFAULTS: AtomicBool = AtomicBool::new(false);

/// Where settings.json is; reading never creates the data folder.
fn path() -> Option<PathBuf> {
    Some(crate::paths::data_path()?.join("settings.json"))
}

const UNREAD_AT_START: &str =
    "MAX couldn't read your settings file when it started, so it didn't replace it; restart MAX to load your settings, then change them.";

/// What is on disk at the settings path.
enum OnDisk {
    Missing,
    Good(Settings),
    /// There, but it couldn't be read (locked by another program, no access).
    Unreadable,
    /// Read, but it isn't valid settings JSON (damaged, or edited by hand).
    Damaged,
}

fn read_at(p: &Path) -> OnDisk {
    for attempt in 0..3 {
        match std::fs::read(p) {
            Ok(b) => return serde_json::from_slice(&b).map(OnDisk::Good).unwrap_or(OnDisk::Damaged),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return OnDisk::Missing,
            // A virus scanner or backup tool may hold the file for a moment.
            Err(_) if attempt < 2 => std::thread::sleep(std::time::Duration::from_millis(40)),
            Err(_) => {}
        }
    }
    OnDisk::Unreadable
}

/// Move a damaged settings file aside as `settings.json.bad-<ms>`, so it is never overwritten.
fn back_up(p: &Path) -> Option<PathBuf> {
    let name = p.file_name()?.to_string_lossy().into_owned();
    let mut ms = crate::model::now_ms();
    let mut to = p.with_file_name(format!("{name}.bad-{ms}"));
    while to.exists() {
        ms += 1;
        to = p.with_file_name(format!("{name}.bad-{ms}"));
    }
    std::fs::rename(p, &to).ok().map(|_| to)
}

/// Settings from `p`, plus a warning when the file there couldn't be used. A damaged file is moved
/// aside first (so it is never overwritten later); an unreadable one is left where it is.
fn load_from(p: &Path) -> (Settings, Option<String>) {
    match read_at(p) {
        OnDisk::Missing => (Settings::default(), None),
        OnDisk::Good(s) => (s, None),
        OnDisk::Damaged => match back_up(p) {
            Some(b) => (
                Settings::default(),
                Some(format!(
                    "MAX couldn't read its settings file, so it kept it as {} and started from the default settings; check your carving rules and options.",
                    b.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
                )),
            ),
            None => (
                Settings::default(),
                Some("MAX couldn't read its settings file and is using the default settings; fix or remove settings.json in its data folder before changing settings.".into()),
            ),
        },
        OnDisk::Unreadable => (Settings::default(), Some(UNREADABLE.into())),
    }
}

const UNREADABLE: &str =
    "MAX couldn't open its settings file and is using the default settings for now; close any program that is using settings.json and restart MAX.";

/// [`store_to`], refusing while the caller holds defaults it got because the file couldn't be read
/// (`ui_has_defaults`) and the user's settings may still be on disk: saving would replace them.
fn store_checked(p: &Path, s: &Settings, ui_has_defaults: bool) -> Result<(), String> {
    if ui_has_defaults && !matches!(read_at(p), OnDisk::Missing | OnDisk::Damaged) {
        return Err(UNREAD_AT_START.into());
    }
    store_to(p, s)
}

/// Save `s` to `p` (temp file, then rename). A damaged file at `p` is moved aside first; a file that
/// exists but can't be read is never replaced.
fn store_to(p: &Path, s: &Settings) -> Result<(), String> {
    const NOT_WRITABLE: &str = "MAX couldn't save its settings. Check that its data folder is writable.";
    let tmp = p.with_extension(format!("{}.tmp", std::process::id()));
    match read_at(p) {
        OnDisk::Missing | OnDisk::Good(_) => {}
        OnDisk::Damaged => {
            back_up(p).ok_or("MAX couldn't move its damaged settings file aside, so it didn't save. Check that its data folder is writable.")?;
        }
        OnDisk::Unreadable => {
            return Err("MAX couldn't read its current settings file, so it didn't replace it. Close any program that is using settings.json and try again.".into());
        }
    }
    let bytes = serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?;
    // create_new: never writes through something already there under the temp name.
    let _ = std::fs::remove_file(&tmp);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut f| std::io::Write::write_all(&mut f, &bytes))
        .map_err(|_| {
            let _ = std::fs::remove_file(&tmp);
            NOT_WRITABLE.to_string()
        })?;
    std::fs::rename(&tmp, p).map_err(|_| {
        let _ = std::fs::remove_file(&tmp);
        NOT_WRITABLE.to_string()
    })
}

pub fn load() -> Settings {
    load_checked().0
}

/// The settings, and whether they are defaults because settings.json couldn't be read.
fn load_checked() -> (Settings, bool) {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(p) = path() else { return (Settings::default(), false) };
    let (mut s, warning) = load_from(&p);
    let unreadable = warning.as_deref() == Some(UNREADABLE);
    let mut notice = NOTICE.lock().unwrap_or_else(|e| e.into_inner());
    if unreadable {
        // Only for this load: the next one may read the file.
        s.load_warning = warning;
    } else {
        if warning.is_some() {
            *notice = warning;
        }
        s.load_warning = notice.clone();
    }
    (s, unreadable)
}

fn store(s: &Settings) -> Result<(), String> {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let p = crate::paths::data_dir()
        .map(|d| d.join("settings.json"))
        .ok_or("MAX couldn't create its data folder. Check that your user folder is writable.")?;
    store_checked(&p, s, UI_HAS_DEFAULTS.load(Ordering::SeqCst))?;
    UI_HAS_DEFAULTS.store(false, Ordering::SeqCst);
    *NOTICE.lock().unwrap_or_else(|e| e.into_inner()) = None;
    Ok(())
}

/// Enabled custom signatures, for scans.
pub fn custom_signatures() -> Vec<CustomSignature> {
    load().custom_signatures.into_iter().filter(|s| s.enabled).collect()
}

/// The settings for the UI, which keeps them and saves them back whole (save_settings).
#[tauri::command]
pub fn get_settings() -> Settings {
    let (s, unreadable) = load_checked();
    UI_HAS_DEFAULTS.store(unreadable, Ordering::SeqCst);
    s
}

/// Validate and save. Returns what was saved.
#[tauri::command]
pub async fn save_settings(settings: Settings) -> Result<Settings, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut s = settings;
        let mut seen = std::collections::HashSet::new();
        for sig in &mut s.custom_signatures {
            sig.name = sig.name.trim().to_string();
            sig.ext = sig.ext.trim().trim_start_matches('.').to_ascii_lowercase();
            if sig.id.is_empty() {
                sig.id = format!("custom-{}", crate::model::now_ms());
            }
            if !seen.insert(sig.id.clone()) {
                sig.id = format!("{}-{}", sig.id, seen.len());
            }
            crate::carve::validate_custom(sig).map_err(|e| format!("{}: {e}", if sig.name.is_empty() { "A custom signature" } else { &sig.name }))?;
        }
        s.update_feed = s.update_feed.trim().to_string();
        if !s.update_feed.is_empty() && !s.update_feed.starts_with("https://") {
            return Err("The update feed must be an https:// address.".into());
        }
        s.load_warning = None;
        store(&s)?;
        Ok(s)
    })
    .await
    .map_err(|_| "Saving settings stopped unexpectedly.".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("max-settings-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn backups(d: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(d)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("settings.json.bad-"))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn missing_file_gives_defaults_quietly() {
        let d = temp_dir("missing");
        let (s, w) = load_from(&d.join("settings.json"));
        assert_eq!(s, Settings::default());
        assert!(w.is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn round_trip_keeps_settings() {
        let d = temp_dir("roundtrip");
        let p = d.join("settings.json");
        let s = Settings { update_feed: "https://example.com/feed".into(), keep_folders: false, ..Default::default() };
        store_to(&p, &s).unwrap();
        let (back, w) = load_from(&p);
        assert_eq!(back, s);
        assert!(w.is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn damaged_file_is_kept_aside_never_overwritten() {
        let d = temp_dir("damaged");
        let p = d.join("settings.json");
        let damaged: &[u8] =
            br#"{"customSignatures":[{"id":"x","name":"X","ext":"x","category":"other","header":"00","maxSize":1.5e6}]}"#;
        std::fs::write(&p, damaged).unwrap();
        let (s, w) = load_from(&p);
        assert_eq!(s, Settings::default());
        let w = w.expect("warning");
        assert!(w.contains("settings.json.bad-"), "{w}");
        let kept = backups(&d);
        assert_eq!(kept.len(), 1);
        assert_eq!(std::fs::read(&kept[0]).unwrap(), damaged);
        assert!(!p.exists());
        // Saving now writes a fresh file and leaves the copy alone.
        store_to(&p, &Settings::default()).unwrap();
        assert_eq!(std::fs::read(&kept[0]).unwrap(), damaged);
        assert!(matches!(read_at(&p), OnDisk::Good(_)));

        // A file damaged between load and save is moved aside by the save too.
        std::fs::write(&p, b"{ not json").unwrap();
        store_to(&p, &Settings::default()).unwrap();
        let kept = backups(&d);
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().any(|k| std::fs::read(k).unwrap() == b"{ not json"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn warning_is_never_saved_or_read_back() {
        let s = Settings { load_warning: Some("x".into()), ..Default::default() };
        let json = serde_json::to_string(&s).unwrap();
        let back: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.load_warning, None);
        let plain = serde_json::to_string(&Settings::default()).unwrap();
        assert!(!plain.contains("loadWarning"));
    }

    /// Opens `p` so no other program can read it (as a virus scanner or backup tool might).
    fn lock(p: &Path) -> std::fs::File {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().read(true).share_mode(0).open(p).unwrap()
    }

    #[test]
    fn defaults_from_a_locked_file_never_replace_it() {
        let d = temp_dir("locked");
        let p = d.join("settings.json");
        let mine = Settings { update_feed: "https://example.com/mine".into(), keep_folders: false, ..Default::default() };
        store_to(&p, &mine).unwrap();
        let original = std::fs::read(&p).unwrap();

        // Locked at startup: defaults plus a warning, and the file is left alone.
        let held = lock(&p);
        let (s, w) = load_from(&p);
        assert_eq!(s, Settings::default());
        assert_eq!(w.as_deref(), Some(UNREADABLE));
        assert!(store_checked(&p, &Settings::default(), true).is_err());
        drop(held);

        // Released later: saving the defaults the UI holds is still refused, and nothing changed.
        let e = store_checked(&p, &Settings { check_updates: false, ..Default::default() }, true).unwrap_err();
        assert_eq!(e, UNREAD_AT_START);
        assert_eq!(std::fs::read(&p).unwrap(), original);
        assert!(backups(&d).is_empty());

        // Once the UI has the real settings (flag off), saving works again.
        store_checked(&p, &mine, false).unwrap();
        assert!(matches!(read_at(&p), OnDisk::Good(s) if s == mine));
        // Nothing left to lose (file gone): the defaults may be saved.
        std::fs::remove_file(&p).unwrap();
        store_checked(&p, &Settings::default(), true).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_stale_temp_file_is_replaced_not_written_through() {
        let d = temp_dir("staletmp");
        let p = d.join("settings.json");
        let tmp = p.with_extension(format!("{}.tmp", std::process::id()));
        std::fs::write(&tmp, b"old").unwrap();
        store_to(&p, &Settings::default()).unwrap();
        assert!(!tmp.exists());
        assert!(matches!(read_at(&p), OnDisk::Good(_)));
        let _ = std::fs::remove_dir_all(&d);
    }
}
