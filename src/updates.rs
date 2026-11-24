//! Update checks against a release feed (Settings -> update feed): a GitHub `releases/latest` API
//! URL or any JSON with `tag_name` and `html_url`. Uses Windows' own curl.exe (System32, Windows 10
//! 1803+) instead of an HTTP stack in the exe. Never downloads or runs anything: a newer version
//! opens its release page.
//!
//! The app usually runs elevated while settings.json is writable by the signed-in user, so curl is
//! started from the real System32 folder, ignores any .curlrc (`--disable`, which must come first),
//! only speaks https (also after redirects) and gets the feed through `--url`, never as an option.

use serde::Serialize;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub current: String,
    pub latest: Option<String>,
    pub url: Option<String>,
    pub update_available: bool,
    pub checked_at: i64,
    /// Feed not set up in Settings.
    pub not_configured: bool,
}

/// "v1.2.10" -> [1, 2, 10]
fn parse_version(v: &str) -> Vec<u64> {
    v.trim().trim_start_matches(['v', 'V']).split(['.', '-', '+']).map_while(|p| p.parse::<u64>().ok()).collect()
}

fn newer(latest: &str, current: &str) -> bool {
    let (a, b) = (parse_version(latest), parse_version(current));
    !a.is_empty() && a > b
}

fn curl() -> std::path::PathBuf {
    crate::util::system32().join("curl.exe")
}

/// curl's arguments for one feed request. `--disable` must be the very first argument.
fn curl_args(feed: &str) -> Vec<&str> {
    vec![
        "--disable",
        "-sS",
        "-L",
        "--max-redirs",
        "5",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--max-time",
        "15",
        "--max-filesize",
        "1048576",
        "-H",
        "Accept: application/json",
        "-A",
        "MAX-File-Recovery-update-check",
        "--url",
        feed,
    ]
}

#[tauri::command]
pub async fn check_for_updates() -> Result<UpdateInfo, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let current = env!("CARGO_PKG_VERSION").to_string();
        let feed = crate::settings::load().update_feed.trim().to_string();
        let mut info = UpdateInfo { current: current.clone(), checked_at: crate::model::now_ms(), ..Default::default() };
        if feed.is_empty() {
            info.not_configured = true;
            return Ok(info);
        }
        // settings.json can be edited by hand: check the feed again here, not only when it is saved.
        if !crate::util::is_https_url(&feed) {
            return Err("The update feed in Settings must be an https:// address. Correct it in Settings and try again.".into());
        }
        let out = Command::new(curl())
            .args(curl_args(&feed))
            .stdin(Stdio::null())
            .creation_flags(crate::util::CREATE_NO_WINDOW)
            .output()
            .map_err(|_| "Windows' curl.exe is missing, so MAX can't check for updates.".to_string())?;
        if !out.status.success() {
            return Err("MAX couldn't reach the update server. Check your internet connection and try again.".into());
        }
        let v: serde_json::Value =
            serde_json::from_slice(&out.stdout).map_err(|_| "The update server sent something MAX doesn't understand.".to_string())?;
        let tag = v.get("tag_name").and_then(|t| t.as_str()).map(str::to_string);
        info.url = v.get("html_url").and_then(|t| t.as_str()).filter(|u| crate::util::is_https_url(u)).map(str::to_string);
        info.update_available = tag.as_deref().is_some_and(|t| newer(t, &current));
        info.latest = tag;
        Ok(info)
    })
    .await
    .map_err(|_| "The update check stopped unexpectedly.".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_compare() {
        assert!(newer("v0.2.0", "0.1.9"));
        assert!(newer("1.10.0", "1.9.3"));
        assert!(!newer("v0.1.0", "0.1.0"));
        assert!(!newer("nightly", "0.1.0"));
    }

    #[test]
    fn curl_ignores_curlrc_and_takes_the_feed_as_url() {
        let feed = "-KC:\\Users\\u\\x.cfg";
        let a = curl_args(feed);
        assert_eq!(a[0], "--disable");
        assert_eq!(&a[a.len() - 2..], ["--url", feed]);
        assert!(a.windows(2).any(|w| w == ["--proto", "=https"]));
        assert!(a.windows(2).any(|w| w == ["--proto-redir", "=https"]));
        // Such a value never even reaches curl.
        assert!(!crate::util::is_https_url(feed));
        assert!(curl().is_absolute());
        assert!(curl().to_string_lossy().to_ascii_lowercase().ends_with("system32\\curl.exe"));
    }
}
