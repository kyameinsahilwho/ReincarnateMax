//! `<data>\history.json`: one RecoveryRecord per recovery job, newest first, at most 500.

use super::RecoveryRecord;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const KEEP: usize = 500;
static LOCK: Mutex<()> = Mutex::new(());

fn file() -> Option<PathBuf> {
    Some(crate::paths::data_dir()?.join("history.json"))
}

pub fn load_from(p: &Path) -> Vec<RecoveryRecord> {
    std::fs::read(p).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

pub fn append_to(p: &Path, rec: RecoveryRecord) -> Result<(), String> {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut all = load_from(p);
    all.insert(0, rec);
    all.truncate(KEEP);
    let bytes = serde_json::to_vec_pretty(&all).map_err(|e| e.to_string())?;
    super::report::write_atomic(p, &bytes).map_err(|_| "MAX couldn't save its recovery history. Check that its data folder is writable.".to_string())
}

pub fn load() -> Vec<RecoveryRecord> {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    file().map(|p| load_from(&p)).unwrap_or_default()
}

pub fn append(rec: RecoveryRecord) -> Result<(), String> {
    let p = file().ok_or("MAX couldn't find its data folder.")?;
    append_to(&p, rec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newest_first_and_capped() {
        let t = crate::recover::engine::tests::TempDir::new("hist");
        let p = t.0.join("history.json");
        for i in 0..(KEEP as u64 + 5) {
            append_to(&p, RecoveryRecord { job: i, state: "done".into(), ..Default::default() }).unwrap();
        }
        let all = load_from(&p);
        assert_eq!(all.len(), KEEP);
        assert_eq!(all[0].job, KEEP as u64 + 4);
        assert!(!std::fs::read_dir(&t.0).unwrap().flatten().any(|e| e.file_name().to_string_lossy().ends_with(".tmp")));
        // camelCase on disk.
        assert!(String::from_utf8(std::fs::read(&p).unwrap()).unwrap().contains("\"skippedDuplicates\""));
    }
}
