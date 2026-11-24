//! TEMPLATE from Platter src/cache.rs — stale-while-revalidate JSON cache in %LOCALAPPDATA%\<id>\cache.
//! The folder name ("com.maxrecovery.app") must equal tauri.conf.json `identifier`. Files are
//! { "savedAt", "version", "data" }; wrong-version entries are dropped. Needs serde (derive), serde_json
//! (features ["preserve_order"] if the UI compares cached JSON with fresh JSON) and tauri (register
//! cache::cache_get_many). Writes are best-effort: keep real user settings that must not be lost in a
//! separate settings file, or at least exclude them from any "clear cache" step (benchmarks!).

//! Small persistent cache so the UI can paint last-known results instantly at launch
//! (stale-while-revalidate) instead of waiting for PowerShell, the event log or a clean-up measure.
//!
//! Files live in `<data folder>\cache\<key>.json` (paths.rs: %LOCALAPPDATA%\com.maxrecovery.app, the
//! elevated account's own when elevated as another account, or MAXData in portable mode) as `{ "savedAt": <ms since epoch>, "data": … }`.
//! Writes go to a temp file and are renamed into place, so a crash never leaves a half-written entry.
//! While a scan reads the drive that holds the data folder, writes are held in memory (paths.rs).

use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const VERSION: u32 = 1;

fn dir() -> Option<PathBuf> {
    crate::paths::cache_dir()
}

fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 48 && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[derive(Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub saved_at: u64,
    #[serde(default)]
    pub version: u32,
    pub data: Value,
}

/// Entries written while `paths::hold_writes()` is on (a scan reads the drive that holds the data
/// folder): kept here, seen by `read`, and saved by `flush_held`.
fn held() -> &'static Mutex<HashMap<String, Entry>> {
    static H: OnceLock<Mutex<HashMap<String, Entry>>> = OnceLock::new();
    H.get_or_init(Default::default)
}

/// Store `value` under `key`. Failures are ignored: the cache is an optimisation only.
pub fn write<T: Serialize>(key: &str, value: &T) {
    if !valid_key(key) {
        return;
    }
    let Ok(data) = serde_json::to_value(value) else { return };
    let entry = Entry { saved_at: now_ms(), version: VERSION, data };
    if crate::paths::hold_writes() {
        held().lock().unwrap_or_else(|e| e.into_inner()).insert(key.to_string(), entry);
        return;
    }
    held().lock().unwrap_or_else(|e| e.into_inner()).remove(key);
    save(key, &entry);
}

fn save(key: &str, entry: &Entry) {
    let Some(d) = dir() else { return };
    let Ok(bytes) = serde_json::to_vec(entry) else { return };
    // Unique temp name: the standard and the elevated instance (or two threads) may write at once.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = d.join(format!("{key}.{}.{n}.tmp", std::process::id()));
    let dst = d.join(format!("{key}.json"));
    // create_new: never writes through something already there under the temp name.
    let _ = std::fs::remove_file(&tmp);
    let wrote = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp).and_then(|mut f| f.write_all(&bytes)).is_ok();
    if wrote && std::fs::rename(&tmp, &dst).is_ok() {
        return;
    }
    let _ = std::fs::remove_file(&tmp);
}

/// Save the entries held back while writes were held (call once the hold is off).
pub fn flush_held() {
    let entries: Vec<(String, Entry)> = held().lock().unwrap_or_else(|e| e.into_inner()).drain().collect();
    for (key, entry) in entries {
        save(&key, &entry);
    }
}

/// Forget `key`, e.g. clean-up sizes once files have been deleted, so they're never shown as current.
pub fn remove(key: &str) {
    if valid_key(key) {
        held().lock().unwrap_or_else(|e| e.into_inner()).remove(key);
        if let Some(d) = crate::paths::cache_path() {
            let _ = std::fs::remove_file(d.join(format!("{key}.json")));
        }
    }
}

pub fn read(key: &str) -> Option<Entry> {
    if !valid_key(key) {
        return None;
    }
    if let Some(e) = held().lock().unwrap_or_else(|e| e.into_inner()).get(key) {
        return Some(e.clone());
    }
    // Reads never create the cache folder.
    let bytes = std::fs::read(crate::paths::cache_path()?.join(format!("{key}.json"))).ok()?;
    let e: Entry = serde_json::from_slice(&bytes).ok()?;
    (e.version == VERSION).then_some(e)
}

/// Last-known values for several keys in one IPC round trip. Missing or unreadable keys are omitted.
#[tauri::command]
pub fn cache_get_many(keys: Vec<String>) -> HashMap<String, Entry> {
    keys.into_iter().filter_map(|k| read(&k).map(|e| (k, e))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_key_validation() {
        write("test-roundtrip", &serde_json::json!({ "a": 1 }));
        let e = read("test-roundtrip").expect("entry");
        assert_eq!(e.data["a"], 1);
        assert!(e.saved_at > 0);
        assert!(read("../evil").is_none());
        assert!(!valid_key("a/b") && !valid_key("") && valid_key("disks"));
        if let Some(d) = dir() {
            let _ = std::fs::remove_file(d.join("test-roundtrip.json"));
        }
    }

    #[test]
    fn held_entries_are_read_then_saved() {
        let e = Entry { saved_at: 1, version: VERSION, data: serde_json::json!({ "b": 2 }) };
        held().lock().unwrap().insert("test-held".into(), e);
        assert_eq!(read("test-held").expect("held entry").data["b"], 2);
        flush_held();
        assert!(held().lock().unwrap().get("test-held").is_none());
        assert_eq!(read("test-held").expect("saved entry").data["b"], 2);
        remove("test-held");
        assert!(read("test-held").is_none());
    }
}
