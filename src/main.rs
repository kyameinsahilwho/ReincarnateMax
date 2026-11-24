//! MAX File Recovery - app shell. Startup order: perf timeline -> SetErrorMode -> single instance
//! (second launch activates the first) -> elevated-relaunch takeover -> startup UAC prompt (recovery
//! needs raw drive access, which Windows only grants to administrators; opt out in Settings or with
//! --no-elevate) -> Tauri with the main window built hidden in theme colours and shown right after
//! build. app_ready starts the drive watcher. Feature modules own their commands (CONTRACT.md).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod cache;
mod carve;
mod content;
mod device;
#[cfg(test)]
mod e2e;
mod fileread;
mod formats;
mod fs;
mod model;
mod other_account;
mod partitions;
mod paths;
mod perf;
mod recover;
mod recyclebin;
mod scan;
mod settings;
mod updates;
mod util;

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Mutex, OnceLock};
use std::time::Duration;
use tauri::webview::PageLoadEvent;
use tauri::window::Color;
use tauri::{Manager, PhysicalPosition, PhysicalSize, Theme};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemInfo {
    elevated: bool,
    /// Ask for administrator rights each time the app starts (on unless the user turned it off).
    /// `None` when this instance runs elevated as another account: the setting lives in the desktop
    /// user's profile, which this process doesn't use, so it can only be changed in standard mode.
    ask_admin_at_start: Option<bool>,
    computer_name: String,
    system_drive: String,
    user_profile: String,
    downloads: String,
    version: String,
    portable: bool,
    data_dir: String,
    /// Portable mode can't keep its data next to the program (read-only media): where it went instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    portable_warning: Option<String>,
    /// The data folder belongs to another Windows account (elevated with other credentials: that
    /// account's own profile is used, never the desktop user's).
    #[serde(skip_serializing_if = "Option::is_none")]
    data_note: Option<String>,
}

/// The startup admin prompt setting can be read and changed here: not when this instance runs as
/// another account (its data folder is that account's, not the desktop user's).
fn admin_setting_reachable() -> bool {
    !other_account::other_account()
}

#[tauri::command]
fn system_info() -> SystemInfo {
    let profile = util::env_path("USERPROFILE").unwrap_or_default();
    SystemInfo {
        elevated: util::is_elevated(),
        ask_admin_at_start: admin_setting_reachable().then(util::ask_admin_at_start),
        computer_name: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "This PC".into()),
        system_drive: util::system_drive_letter(),
        downloads: profile.join("Downloads").to_string_lossy().into_owned(),
        user_profile: profile.to_string_lossy().into_owned(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        portable: paths::is_portable(),
        // Shown only: reading where it is never creates it.
        data_dir: paths::data_path().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default(),
        portable_warning: paths::portable_warning(),
        data_note: paths::data_note(),
    }
}

/// Async so the UAC prompt (ShellExecuteW blocks until it is answered) never stalls the UI thread.
#[tauri::command]
async fn relaunch_elevated(app: tauri::AppHandle) -> Result<bool, String> {
    let owner = app
        .get_webview_window("main")
        .and_then(|w| w.hwnd().ok())
        .map(|h| h.0 as usize)
        .unwrap_or(0);
    // One UAC prompt at a time: with the secure desktop off, the window stays clickable.
    static PROMPTING: AtomicBool = AtomicBool::new(false);
    // Recoveries and disk images can't be continued after a restart; scans can (they are stopped
    // cleanly below and resumed in the new instance).
    let running = RunningJobs::now();
    if running.recoveries > 0 || running.imaging > 0 {
        return Err("Wait for the recovery or disk image to finish, or stop it, then restart MAX as administrator.".into());
    }
    if PROMPTING.swap(true, Ordering::SeqCst) {
        return Ok(false);
    }
    let res = tauri::async_runtime::spawn_blocking(move || util::relaunch_elevated(owner)).await;
    PROMPTING.store(false, Ordering::SeqCst);
    let ok = res.map_err(|e| e.to_string())?;
    if ok {
        // The elevated copy waits up to 10 s for this process to go.
        exit_after_stopping_jobs(app, RELAUNCH_STOP_WAIT).await;
    }
    Ok(ok)
}

/// Turn the startup administrator prompt on or off for the next launches.
#[tauri::command]
async fn set_ask_admin(enabled: bool) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        if !admin_setting_reachable() {
            return Err("MAX File Recovery is running as a different Windows account. Change this setting in standard mode.".to_string());
        }
        cache::write(util::ASK_ADMIN_KEY, &enabled);
        if util::ask_admin_at_start() != enabled {
            return Err("MAX File Recovery couldn't save this setting.".into());
        }
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

// ------------------------------------------------------------------------------------- showing
//
// The main window is built hidden, placed and sized from the saved state, and shown as soon as that
// is done (well before the page has painted): its window and WebView background and its title bar are
// already in the theme the page will use, so it appears at once without a white or light flash, and
// the page fills in a moment later (measured: visible ~110 ms sooner than when shown after the first
// paint, page content on screen at about the same time). `app_ready` (called by the UI after its first paint) shows it too,
// as a safety net, and starts the background work that must not compete with startup; if that call
// never comes (a script error), that work starts after STARTUP_FALLBACK.

const STARTUP_FALLBACK: Duration = Duration::from_millis(1500);
static SHOWN: AtomicBool = AtomicBool::new(false);
static STARTED: AtomicBool = AtomicBool::new(false);

/// Show the main window the first time this is called; later calls do nothing. Only shown, not
/// forced to the front: Windows activates it when this launch may take the foreground (the user just
/// started it) and flashes its taskbar button when the user has meanwhile gone on in another app.
fn show_main(app: &tauri::AppHandle, mark: &str) {
    if SHOWN.swap(true, Ordering::SeqCst) {
        return;
    }
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
    }
    perf::mark(mark);
}

/// Work that waits until the UI is up, once.
fn after_startup(app: &tauri::AppHandle) {
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    start_drive_watcher(app.clone());
}

/// Called by the UI after its first paint.
#[tauri::command]
fn app_ready(app: tauri::AppHandle) {
    perf::mark("rust:app-ready");
    show_main(&app, "rust:window-shown-late");
    after_startup(&app);
}

// --------------------------------------------------------------------------------------- theme

const BG_LIGHT: Color = Color(0xF3, 0xF2, 0xF7, 0xFF);
const BG_DARK: Color = Color(0x15, 0x13, 0x1F, 0xFF);

fn valid_theme(t: &str) -> bool {
    matches!(t, "light" | "dark" | "system")
}

/// The theme the UI last asked for ("light" | "dark" | "system"), if it ever did.
fn saved_theme_pref() -> Option<String> {
    cache::read("theme").and_then(|e| e.data.as_str().map(str::to_owned)).filter(|t| valid_theme(t))
}

/// Runs in the page before its own scripts. The backend's choice (the cache is shared by every
/// instance of this user) is the one that counts: an elevated instance has its own WebView2 profile and
/// so its own, empty localStorage, and a choice made there must also reach the normal one. Seeding
/// both keys the UI reads keeps the page, the window background and the title bar in one theme, and
/// keeps the UI from pushing a stale or default value back.
fn theme_seed_script(pref: &str) -> String {
    let t = serde_json::to_string(pref).unwrap_or_else(|_| "\"system\"".into());
    format!("try{{localStorage.setItem(\"maxrec.theme\",{t});localStorage.setItem(\"maxrec.themeSynced\",{t})}}catch(e){{}}")
}

fn is_dark(pref: &str) -> bool {
    match pref {
        "dark" => true,
        "light" => false,
        _ => util::system_uses_light_theme() == Some(false),
    }
}

/// Title-bar theme: forced for an explicit choice, `None` follows Windows.
fn window_theme(pref: &str) -> Option<Theme> {
    match pref {
        "dark" => Some(Theme::Dark),
        "light" => Some(Theme::Light),
        _ => None,
    }
}

/// Remember the UI's theme choice so the next launch paints the window and title bar in it from the
/// first frame, and apply it to the title bar and the page background now.
#[tauri::command]
async fn set_theme_pref(app: tauri::AppHandle, theme: String) -> Result<(), String> {
    if !valid_theme(&theme) {
        return Err("Unknown theme.".into());
    }
    let pref = theme.clone();
    tauri::async_runtime::spawn_blocking(move || cache::write("theme", &pref)).await.map_err(|e| e.to_string())?;
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.set_theme(window_theme(&theme));
        let _ = w.set_background_color(Some(if is_dark(&theme) { BG_DARK } else { BG_LIGHT }));
    }
    Ok(())
}

// -------------------------------------------------------------------------------- window state
//
// Size, position and maximized state are kept in the cache ("window") and restored while the window
// is still hidden, so it appears in place without a jump. `x`/`y` are the outer position and
// `width`/`height` the inner size, in physical pixels; they always describe the restored (normal)
// rectangle, also while maximized.

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
struct WindowState {
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    maximized: bool,
}

static WINDOW_STATE: Mutex<Option<WindowState>> = Mutex::new(None);
static SAVE_TX: OnceLock<Mutex<mpsc::Sender<()>>> = OnceLock::new();

/// A rectangle worth restoring: big enough, and with the middle of its title bar on a monitor that is
/// connected now. Returns the rectangle clamped to that monitor's work area.
fn usable_rect(s: &WindowState, monitors: &[(i32, i32, u32, u32)]) -> Option<(i32, i32, u32, u32)> {
    if s.width < 200 || s.height < 150 {
        return None;
    }
    let (px, py) = (s.x.saturating_add((s.width / 2) as i32), s.y.saturating_add(24));
    let &(_, _, mw, mh) = monitors.iter().find(|&&(mx, my, mw, mh)| {
        px >= mx && py >= my && (px as i64) < mx as i64 + mw as i64 && (py as i64) < my as i64 + mh as i64
    })?;
    Some((s.x, s.y, s.width.min(mw), s.height.min(mh)))
}

fn restore_window_state(w: &tauri::WebviewWindow) {
    let saved = cache::read("window").and_then(|e| serde_json::from_value::<WindowState>(e.data).ok());
    let rect = saved.and_then(|s| {
        let monitors: Vec<_> = w
            .available_monitors()
            .unwrap_or_default()
            .iter()
            .map(|m| {
                let a = m.work_area();
                (a.position.x, a.position.y, a.size.width, a.size.height)
            })
            .collect();
        usable_rect(&s, &monitors)
    });
    match rect {
        Some((x, y, width, height)) => {
            let _ = w.set_position(PhysicalPosition::new(x, y));
            let _ = w.set_size(PhysicalSize::new(width, height));
        }
        None => fit_default_size(w),
    }
    // Start from what the window really is now (default size when nothing usable was saved).
    let mut state = saved.unwrap_or_default();
    if let (Ok(p), Ok(sz)) = (w.outer_position(), w.inner_size()) {
        (state.x, state.y, state.width, state.height) = (p.x, p.y, sz.width, sz.height);
    }
    // Last, because tao's set_position/set_size clear its maximized flag: so the window also opens
    // maximized when the saved rectangle's monitor is gone (with the default as its restored size).
    // While hidden this only sets the flag; the window is shown maximized.
    if state.maximized {
        let _ = w.maximize();
    }
    if let Ok(mut g) = WINDOW_STATE.lock() {
        *g = Some(state);
    }
}

/// The default size (tauri.conf.json) is taller than the work area of a 1080p screen at 125 %: shrink
/// it to fit the monitor's work area (never below the minimum size) and center it there.
fn fit_default_size(w: &tauri::WebviewWindow) {
    let (Ok(Some(m)), Ok(outer), Ok(inner)) = (w.current_monitor(), w.outer_size(), w.inner_size()) else { return };
    let a = m.work_area();
    let (fw, fh) = (outer.width.min(a.size.width), outer.height.min(a.size.height));
    if (fw, fh) != (outer.width, outer.height) {
        let width = inner.width.saturating_sub(outer.width - fw);
        let height = inner.height.saturating_sub(outer.height - fh);
        let _ = w.set_size(PhysicalSize::new(width, height));
    }
    let x = a.position.x + (a.size.width.saturating_sub(fw) / 2) as i32;
    let y = a.position.y + (a.size.height.saturating_sub(fh) / 2) as i32;
    let _ = w.set_position(PhysicalPosition::new(x, y));
}

/// Track the main window's geometry after a move or resize and save it shortly after it settles.
/// The rectangle is only taken while the window is neither maximized nor minimized, as Windows has it
/// right now (tao's maximized flag is updated only after the move event of a maximize, or of a restore
/// to maximized from minimized), so it always stays the restored (normal) rectangle.
fn note_window_change(w: &tauri::Window) {
    if !SHOWN.load(Ordering::SeqCst) {
        return;
    }
    let Ok(h) = w.hwnd() else { return };
    let (maximized, minimized) = util::window_zoomed_iconic(h.0 as usize);
    if minimized {
        return;
    }
    let Ok(mut g) = WINDOW_STATE.lock() else { return };
    let mut s = g.unwrap_or_default();
    s.maximized = maximized;
    if !maximized {
        if let (Ok(p), Ok(sz)) = (w.outer_position(), w.inner_size()) {
            (s.x, s.y, s.width, s.height) = (p.x, p.y, sz.width, sz.height);
        }
    }
    if *g == Some(s) {
        return;
    }
    *g = Some(s);
    drop(g);
    let tx = SAVE_TX.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<()>();
        let _ = std::thread::Builder::new().name("maxrec-window-state".into()).spawn(move || {
            while rx.recv().is_ok() {
                // Wait until moves/resizes stop for a moment, then write once.
                while rx.recv_timeout(Duration::from_millis(500)).is_ok() {}
                save_window_state_now();
            }
        });
        Mutex::new(tx)
    });
    if let Ok(tx) = tx.lock() {
        let _ = tx.send(());
    }
}

fn save_window_state_now() {
    let s = WINDOW_STATE.lock().ok().and_then(|g| *g);
    if let Some(s) = s {
        cache::write("window", &s);
    }
}

// ------------------------------------------------------------------------------ background work
//
// Watchers and pollers start only after the UI is up (after_startup), so they never compete with startup.
// Platter polled GetLogicalDrives + a per-drive media signature every 2 s here and emitted "drives-changed".

/// Emits "devices-changed" when a drive letter appears or disappears (USB stick, card reader), so
/// the source list refreshes without the user asking. GetLogicalDrives is a cheap bitmask read.
fn start_drive_watcher(handle: tauri::AppHandle) {
    use tauri::Emitter;
    let _ = std::thread::Builder::new().name("maxrec-watch".into()).spawn(move || {
        let mut last = unsafe { windows_sys::Win32::Storage::FileSystem::GetLogicalDrives() };
        loop {
            std::thread::sleep(Duration::from_secs(2));
            let now = unsafe { windows_sys::Win32::Storage::FileSystem::GetLogicalDrives() };
            if now != last {
                last = now;
                let _ = handle.emit("devices-changed", now);
            }
            update_write_hold();
        }
    });
}

// ------------------------------------------------------------- writes while the data drive is scanned
//
// While a scan reads the volume or physical disk that holds MAX's data folder (the usual case: a
// scan of C:), the app log and the cache (window position, theme) are kept in memory and written
// once no such scan runs, or when MAX exits, so they don't land in the free space being searched.
// The hold starts with the scan's first progress event and ends on the drive watcher's next tick
// after the scan. A snapshot counts as its original volume. (The scan's own session file is placed
// by scan::session::pick_location.)

/// Turn the hold on or off from the running scans (every 2 s, from the drive watcher).
fn update_write_hold() {
    let hold = scan_reads_data_drive(scan::jobs::running_sources(), true);
    let was = paths::set_hold_writes(hold);
    if was && !hold {
        write_held();
    }
}

/// On every scan-progress event (the first one is sent as soon as a scan starts): turn the hold on
/// at once when a scan of the data drive has just started, rather than on the next watcher tick.
/// Only ever turns it on; the watcher turns it off and writes what was held.
fn hold_writes_for_new_scan() {
    if !paths::hold_writes() && scan_reads_data_drive(scan::jobs::running_sources(), false) {
        paths::set_hold_writes(true);
    }
}

/// Start the hold as soon as a scan starts (see hold_writes_for_new_scan).
fn watch_scans_for_hold(app: &tauri::AppHandle) {
    use tauri::Listener;
    app.listen_any("scan-progress", |_| hold_writes_for_new_scan());
}

/// Write what was held back (the hold must be off).
fn write_held() {
    cache::flush_held();
    flush_held_log();
}

/// End any hold and write what it kept (when exiting).
fn release_held_writes() {
    paths::set_hold_writes(false);
    write_held();
}

/// Where the data folder is: its volume root ("C:\"), volume GUID path and physical disks.
struct DataPlace {
    root: Option<String>,
    volume: Option<String>,
    disks: Vec<u32>,
}

/// The data folder's place, looked up once.
fn data_place() -> Option<&'static DataPlace> {
    static P: OnceLock<DataPlace> = OnceLock::new();
    if let Some(p) = P.get() {
        return Some(p);
    }
    let d = paths::data_path()?.to_string_lossy().into_owned();
    let (root, volume) = device::win::volume_of_path(&d).map_or((None, None), |(r, g)| (Some(r), g));
    let disks = device::win::disks_of_path(&d);
    if root.is_none() && disks.is_empty() {
        return None; // try again next time
    }
    Some(P.get_or_init(|| DataPlace { root, volume, disks }))
}

/// The last answer, kept for the same running sources so scan-progress events stay cheap.
static HOLD_MEMO: Mutex<Option<(Vec<model::SourceRef>, bool)>> = Mutex::new(None);

/// Whether any of the running `sources` reads the data folder's drive. `fresh` looks again even when
/// the sources are the same as last time (drives come and go); otherwise the last answer is reused.
fn scan_reads_data_drive(sources: Vec<model::SourceRef>, fresh: bool) -> bool {
    if sources.is_empty() {
        return false;
    }
    if !fresh {
        if let Some((s, hold)) = HOLD_MEMO.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            if *s == sources {
                return *hold;
            }
        }
    }
    let Some(place) = data_place() else { return false };
    let letter_disks = |l: char| device::win::letter_extents(&l.to_string()).iter().map(|e| e.disk).collect::<Vec<u32>>();
    let snapshot = |s: &model::SourceRef| {
        let loc = device::win::source_location(s);
        (loc.volume, loc.disks.unwrap_or_default())
    };
    let hold = sources.iter().any(|s| source_shares(s, place, letter_disks, snapshot));
    *HOLD_MEMO.lock().unwrap_or_else(|e| e.into_inner()) = Some((sources, hold));
    hold
}

/// Whether scanning `src` reads the volume or a physical disk of the data folder. A snapshot counts
/// as its original volume (`snapshot` gives its volume GUID path and disks): its free clusters are
/// that volume's, as in scan/session.rs. An image is only read, so writing next to it changes nothing.
fn source_shares(
    src: &model::SourceRef,
    data: &DataPlace,
    letter_disks: impl Fn(char) -> Vec<u32>,
    snapshot: impl Fn(&model::SourceRef) -> (Option<String>, Vec<u32>),
) -> bool {
    let on_data_disk = |disks: &[u32]| disks.iter().any(|d| data.disks.contains(d));
    match src.kind {
        model::SourceKind::Volume => {
            let Some(l) = src.path.trim().chars().next().filter(|c| c.is_ascii_alphabetic()).map(|c| c.to_ascii_uppercase()) else { return false };
            data.root.as_deref().is_some_and(|r| r.to_ascii_uppercase().starts_with(&format!("{l}:"))) || on_data_disk(&letter_disks(l))
        }
        model::SourceKind::Disk => src
            .path
            .trim()
            .trim_start_matches(|c: char| !c.is_ascii_digit())
            .parse::<u32>()
            .is_ok_and(|d| data.disks.contains(&d)),
        model::SourceKind::Snapshot => {
            let (volume, disks) = snapshot(src);
            let same_volume = match (volume.as_deref(), data.volume.as_deref()) {
                (Some(a), Some(b)) => a.trim_end_matches('\\').eq_ignore_ascii_case(b.trim_end_matches('\\')),
                _ => false,
            };
            same_volume || on_data_disk(&disks)
        }
        model::SourceKind::Image => false,
    }
}

/// Show a file or folder in Explorer (recovered files, reports, images): a folder is opened, a file
/// is selected in its folder. Only existing paths on a drive or a network share; nothing is run.
#[tauri::command]
async fn reveal_path(path: String) -> Result<(), String> {
    let p = util::local_or_unc_path(&path)
        .map(std::path::PathBuf::from)
        .ok_or("MAX can only show files and folders on a drive or a network share.")?;
    tauri::async_runtime::spawn_blocking(move || {
        if !p.exists() {
            return Err("That file or folder no longer exists.".to_string());
        }
        util::reveal_in_explorer(&p)
    })
    .await
    .map_err(|_| "Windows couldn't open Explorer. Open the folder yourself in File Explorer.".to_string())?
}

/// Open an https:// address (release page, help) in the default browser.
#[tauri::command]
async fn open_url(url: String) -> Result<(), String> {
    let url = url.trim().to_string();
    if !util::is_https_url(&url) {
        return Err("MAX only opens https:// web addresses.".into());
    }
    tauri::async_runtime::spawn_blocking(move || util::open_url(&url))
        .await
        .map_err(|_| "Windows couldn't open your web browser. Copy the address into your browser instead.".to_string())?
}

// ------------------------------------------------------------------------- closing while busy
//
// Closing the window (X, Alt+F4, the installer's close message) or restarting as administrator must
// not silently end a recovery or a disk image (neither can be continued) or leave a scan without its
// last checkpoint. Scans are listed from the scan module's own registry; recoveries and imaging jobs
// have no public registry, so they are followed through their progress/done events.
//
// While anything runs, closing is prevented and the UI gets "confirm-exit" {scans, recoveries,
// imaging}; it calls `exit_app` when the user still wants to quit. The installer can't answer, so its
// close message (util::close_forced) stops the jobs and exits without asking. Stopping means: scans
// are cancelled, which keeps their results and sweep checkpoint (they can be resumed), recoveries and
// imaging jobs are cancelled so they record what was done; then MAX waits a few seconds for them.

struct EventJobs {
    recoveries: BTreeSet<u64>,
    imaging: BTreeSet<u64>,
}

static EVENT_JOBS: Mutex<EventJobs> = Mutex::new(EventJobs { recoveries: BTreeSet::new(), imaging: BTreeSet::new() });
/// Set once the app is leaving (after stopping jobs): every close request is let through.
static EXIT_NOW: AtomicBool = AtomicBool::new(false);
/// Set while jobs are being stopped before exiting: further close requests are ignored.
static STOPPING: AtomicBool = AtomicBool::new(false);

const EXIT_STOP_WAIT: Duration = Duration::from_secs(10);
/// The installer waits about 10 s for MAX to go, the elevated copy 10 s for this process.
const FORCED_STOP_WAIT: Duration = Duration::from_secs(6);
const RELAUNCH_STOP_WAIT: Duration = Duration::from_secs(6);

/// The `job` id of a progress/done event payload.
fn event_job(payload: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(payload).ok()?.get("job")?.as_u64()
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum JobKind {
    Recovery,
    Imaging,
}

impl JobKind {
    fn set(self, j: &mut EventJobs) -> &mut BTreeSet<u64> {
        match self {
            JobKind::Recovery => &mut j.recoveries,
            JobKind::Imaging => &mut j.imaging,
        }
    }
    /// The name of the job's thread (recover::start_recovery, device::imaging::start_imaging).
    fn thread_name(self, job: u64) -> String {
        match self {
            JobKind::Recovery => format!("recovery-{job}"),
            JobKind::Imaging => format!("maxrec-image-{job}"),
        }
    }
}

/// Forgets a job when its thread ends, also when the thread panicked and never sent its done event.
struct JobThreadGone(JobKind, u64);

impl Drop for JobThreadGone {
    fn drop(&mut self) {
        let mut g = EVENT_JOBS.lock().unwrap_or_else(|e| e.into_inner());
        self.0.set(&mut g).remove(&self.1);
    }
}

thread_local! {
    static JOB_THREAD: std::cell::RefCell<Option<JobThreadGone>> = const { std::cell::RefCell::new(None) };
}

/// A progress (`add`) or done event of a job. Event listeners run in the thread that emits, normally
/// the job's own: then a thread-local guard forgets the job when that thread ends.
fn note_job_event(kind: JobKind, job: u64, add: bool) {
    {
        let mut g = EVENT_JOBS.lock().unwrap_or_else(|e| e.into_inner());
        let set = kind.set(&mut g);
        if add {
            set.insert(job);
        } else {
            set.remove(&job);
        }
    }
    if add && std::thread::current().name() == Some(kind.thread_name(job).as_str()) {
        let _ = JOB_THREAD.try_with(|t| {
            let mut t = t.borrow_mut();
            if t.is_none() {
                *t = Some(JobThreadGone(kind, job));
            }
        });
    }
}

/// Follow recovery and imaging jobs through their events (they have no public registry).
fn track_jobs(app: &tauri::AppHandle) {
    use tauri::Listener;
    fn on(app: &tauri::AppHandle, event: &str, kind: JobKind, add: bool) {
        app.listen_any(event, move |e| {
            if let Some(job) = event_job(e.payload()) {
                note_job_event(kind, job, add);
            }
        });
    }
    on(app, "recovery-progress", JobKind::Recovery, true);
    on(app, "recovery-done", JobKind::Recovery, false);
    on(app, "imaging-progress", JobKind::Imaging, true);
    on(app, "imaging-done", JobKind::Imaging, false);
}

/// Sessions whose scan runs (or is paused) in this process, wherever their session file is (the
/// sessions folder or a registered folder on another drive).
fn running_scans() -> Vec<String> {
    scan::session::all_session_files()
        .into_iter()
        .map(|(id, _)| id)
        .filter(|id| scan::jobs::running(id).is_some())
        .collect()
}

#[derive(Serialize, Clone, Copy, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
struct RunningJobs {
    scans: usize,
    recoveries: usize,
    imaging: usize,
}

impl RunningJobs {
    fn now() -> RunningJobs {
        let scans = running_scans().len();
        let g = EVENT_JOBS.lock().unwrap_or_else(|e| e.into_inner());
        RunningJobs { scans, recoveries: g.recoveries.len(), imaging: g.imaging.len() }
    }
    fn any(&self) -> bool {
        self.scans + self.recoveries + self.imaging > 0
    }
}

/// Ask every running job to stop and wait (up to `wait`) until they have.
fn stop_jobs_and_wait(wait: Duration) {
    let (recoveries, imaging) = {
        let g = EVENT_JOBS.lock().unwrap_or_else(|e| e.into_inner());
        (g.recoveries.iter().copied().collect::<Vec<_>>(), g.imaging.iter().copied().collect::<Vec<_>>())
    };
    for id in running_scans() {
        let _ = scan::jobs::cancel(&id);
    }
    for job in recoveries {
        let _ = recover::cancel_recovery(job);
    }
    for job in imaging {
        let _ = device::imaging::cancel_imaging(job);
    }
    let deadline = std::time::Instant::now() + wait;
    while RunningJobs::now().any() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let left = RunningJobs::now();
    if left.any() {
        tracing::warn!(?left, "exiting before every job had stopped");
    }
}

/// Stop the running jobs (off the UI thread), save the window state and exit.
async fn exit_after_stopping_jobs(app: tauri::AppHandle, wait: Duration) {
    STOPPING.store(true, Ordering::SeqCst);
    util::note_main_window_closing();
    let _ = tauri::async_runtime::spawn_blocking(move || {
        stop_jobs_and_wait(wait);
        release_held_writes();
    })
    .await;
    save_window_state_now();
    EXIT_NOW.store(true, Ordering::SeqCst);
    app.exit(0);
}

/// Quit after the user confirmed it ("confirm-exit"): scans are stopped so they can be resumed later,
/// recoveries and disk images are stopped where they are.
#[tauri::command]
async fn exit_app(app: tauri::AppHandle) {
    exit_after_stopping_jobs(app, EXIT_STOP_WAIT).await;
}

/// The main window was asked to close. `true` lets the close go ahead.
fn allow_close(app: &tauri::AppHandle) -> bool {
    use tauri::Emitter;
    let stopping = STOPPING.load(Ordering::SeqCst);
    let running = if EXIT_NOW.load(Ordering::SeqCst) || stopping { RunningJobs::default() } else { RunningJobs::now() };
    match close_action(EXIT_NOW.load(Ordering::SeqCst), stopping, running, util::close_forced()) {
        CloseAction::Close => true,
        CloseAction::Ignore => false,
        CloseAction::StopThenExit => {
            tauri::async_runtime::spawn(exit_after_stopping_jobs(app.clone(), FORCED_STOP_WAIT));
            false
        }
        CloseAction::Ask => {
            let _ = app.emit("confirm-exit", running);
            false
        }
    }
}

#[derive(Debug, PartialEq)]
enum CloseAction {
    /// Let the window close now.
    Close,
    /// Already stopping jobs before exiting: nothing more to do.
    Ignore,
    /// The installer asked: stop the jobs (scans stay resumable) and exit without asking anyone.
    StopThenExit,
    /// Ask the user first ("confirm-exit"); the page calls exit_app.
    Ask,
}

fn close_action(exit_now: bool, stopping: bool, running: RunningJobs, forced: bool) -> CloseAction {
    if exit_now {
        CloseAction::Close
    } else if stopping {
        CloseAction::Ignore
    } else if !running.any() {
        CloseAction::Close
    } else if forced {
        CloseAction::StopThenExit
    } else {
        CloseAction::Ask
    }
}

/// max.log, and the lines logged while writes are held (paths::hold_writes), up to LOG_HOLD_MAX.
struct LogSink {
    file: Option<std::fs::File>,
    held: Vec<u8>,
}

static LOG: Mutex<LogSink> = Mutex::new(LogSink { file: None, held: Vec::new() });
const LOG_HOLD_MAX: usize = 1 << 20;

impl LogSink {
    fn take(&mut self, buf: &[u8], hold: bool) {
        use std::io::Write;
        if hold {
            if self.held.len() + buf.len() <= LOG_HOLD_MAX {
                self.held.extend_from_slice(buf);
            }
            return;
        }
        let held = std::mem::take(&mut self.held);
        if let Some(f) = &mut self.file {
            let _ = f.write_all(&held);
            let _ = f.write_all(buf);
        }
    }
}

/// The tracing writer: every line goes through LOG.
struct LogWriter;

impl std::io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LOG.lock().unwrap_or_else(|e| e.into_inner()).take(buf, paths::hold_writes());
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn flush_held_log() {
    LOG.lock().unwrap_or_else(|e| e.into_inner()).take(&[], false);
}

/// App log (tracing) in <data>\logs\max.log, appended; scan logs live in each session file.
fn init_logging() {
    let Some(dir) = paths::logs_dir() else { return };
    let path = dir.join("max.log");
    let old = dir.join("max.old.log");
    // Keep the log small: start over past 8 MB.
    if std::fs::metadata(&path).map(|m| m.len() > 8 << 20).unwrap_or(false) {
        let _ = std::fs::rename(&path, &old);
    }
    let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) else { return };
    LOG.lock().unwrap_or_else(|e| e.into_inner()).file = Some(file);
    let _ = tracing_subscriber::fmt().with_writer(|| LogWriter).with_ansi(false).with_target(false).try_init();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), elevated = util::is_elevated(), portable = paths::is_portable(), "MAX started");
}

// ------------------------------------------------------------------------------------- commands

/// Marks the first IPC call from the page on the perf timeline.
fn with_first_ipc_mark<F>(handler: F) -> impl Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync + 'static
where
    F: Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync + 'static,
{
    static FIRST_IPC: AtomicBool = AtomicBool::new(false);
    move |invoke| {
        perf::mark_once(&FIRST_IPC, "rust:first-ipc");
        handler(invoke)
    }
}

fn main() {
    perf::init();
    perf::mark("rust:main");
    // Polling empty card readers / optical drives must never pop "There is no disk in the drive".
    util::suppress_critical_error_dialogs();
    // Started by relaunch_elevated: take over as the single instance at once (the old instance still
    // holds the mutex, so it is never free in between), let the old instance know, then wait for it
    // (and its WebView2) to go away before starting our own.
    let elevated_relaunch = util::wait_for_pid_arg(std::env::args().skip(1)).is_some();
    if !util::claim_single_instance(elevated_relaunch) && util::defer_to_existing_instance() {
        perf::mark("rust:already-running");
        return;
    }
    if elevated_relaunch {
        util::note_taken_over();
        util::wait_for_parent_from_args();
        util::hold_instance_mutex();
    }
    // This is the one instance: ask for administrator rights before any window or WebView exists.
    // Accepted, the elevated copy takes over once this process has exited; declined, run standard.
    if util::should_elevate_at_start(elevated_relaunch) && util::elevate_at_start() {
        perf::mark("rust:elevated-at-start");
        return;
    }

    init_logging();
    // Sessions left "running" by a crash or power loss become "interrupted" (resumable).
    scan::restore_after_crash();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .register_asynchronous_uri_scheme_protocol("maxfile", content::protocol)
        .setup(|app| {
            perf::mark("rust:setup");
            // The main window is declared in tauri.conf.json with "create": false and built here, so an
            // elevated instance can get its own WebView2 user data folder: WebView2 can't share one
            // folder between processes running at different integrity levels.
            let elevated = util::is_elevated();
            let cfg = app
                .config()
                .app
                .windows
                .iter()
                .find(|w| w.label == "main")
                .cloned()
                .ok_or("tauri.conf.json has no \"main\" window")?;
            let saved_pref = saved_theme_pref();
            let pref = saved_pref.clone().unwrap_or_else(|| "system".into());
            let mut builder = tauri::WebviewWindowBuilder::from_config(app.handle(), &cfg)?
                .title(if elevated { "MAX File Recovery (Administrator)" } else { "MAX File Recovery" })
                .visible(false)
                .window_classname(util::MAIN_WINDOW_CLASS)
                // Window and WebView background in the theme the page will use, so nothing flashes.
                .background_color(if is_dark(&pref) { BG_DARK } else { BG_LIGHT })
                .theme(window_theme(&pref))
                .on_page_load(|_, payload| match payload.event() {
                    PageLoadEvent::Started => perf::mark("rust:page-load-started"),
                    PageLoadEvent::Finished => perf::mark("rust:page-load-finished"),
                });
            if let Some(p) = &saved_pref {
                builder = builder.initialization_script(theme_seed_script(p));
            }
            if let Some(dir) = paths::webview_dir(elevated) {
                builder = builder.data_directory(dir);
            } else if elevated {
                if let Ok(dir) = app.path().app_local_data_dir() {
                    builder = builder.data_directory(dir.join("elevated"));
                }
            }
            let window = builder.build()?;
            perf::mark("rust:window-built");
            restore_window_state(&window);
            if let Ok(h) = window.hwnd() {
                util::install_activation_handler(h.0 as usize);
            }
            show_main(app.handle(), "rust:window-shown");
            track_jobs(app.handle());
            watch_scans_for_hold(app.handle());

            let handle = app.handle().clone();
            let _ = std::thread::Builder::new().name("maxrec-startup-fallback".into()).spawn(move || {
                std::thread::sleep(STARTUP_FALLBACK);
                after_startup(&handle);
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if window.label() != "main" {
                return;
            }
            match event {
                tauri::WindowEvent::Moved(_) | tauri::WindowEvent::Resized(_) => note_window_change(window),
                tauri::WindowEvent::CloseRequested { api, .. } => {
                    if !allow_close(window.app_handle()) {
                        api.prevent_close();
                        return;
                    }
                    util::note_main_window_closing();
                    release_held_writes();
                    save_window_state_now();
                }
                _ => {}
            }
        })
        .invoke_handler(with_first_ipc_mark(tauri::generate_handler![
            system_info,
            perf::perf_mark,
            perf::perf_enabled,
            app_ready,
            set_theme_pref,
            cache::cache_get_many,
            relaunch_elevated,
            set_ask_admin,
            reveal_path,
            open_url,
            exit_app,
            settings::get_settings,
            settings::save_settings,
            updates::check_for_updates,
            formats::list_file_types,
            device::list::list_devices,
            device::smart::smart_info,
            device::image::open_image,
            device::source::read_sectors,
            device::imaging::start_imaging,
            device::imaging::pause_imaging,
            device::imaging::cancel_imaging,
            partitions::analyze_partitions,
            scan::start_scan,
            scan::scan_location,
            scan::folder_source,
            scan::pause_scan,
            scan::cancel_scan,
            scan::resume_session,
            scan::list_sessions,
            scan::get_session,
            scan::delete_session,
            scan::export_session,
            scan::import_session,
            scan::query_files,
            scan::query_ids,
            scan::folder_children,
            scan::file_detail,
            scan::map_cells,
            scan::map_region,
            scan::session_log,
            content::inspect_file,
            content::preview_document,
            content::read_file_bytes,
            recover::check_destination,
            recover::start_recovery,
            recover::cancel_recovery,
            recover::recovery_history,
            recover::find_duplicates,
            recover::export_report,
        ]))
        .run(tauri::generate_context!())
        .expect("error while running MAX File Recovery");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_rect_must_be_on_a_connected_monitor() {
        let mons = [(0, 0, 1920, 1040), (1920, 0, 2560, 1400)];
        let s = WindowState { x: 100, y: 50, width: 1320, height: 860, maximized: false };
        assert_eq!(usable_rect(&s, &mons), Some((100, 50, 1320, 860)));
        // On the second monitor, larger than the first one.
        let s2 = WindowState { x: 2000, y: 10, width: 2400, height: 1300, ..s };
        assert_eq!(usable_rect(&s2, &mons), Some((2000, 10, 2400, 1300)));
        // Bigger than its monitor: clamped.
        let s3 = WindowState { x: 0, y: 0, width: 3000, height: 2000, ..s };
        assert_eq!(usable_rect(&s3, &mons), Some((0, 0, 1920, 1040)));
        // Monitor gone (was left of the primary), title bar off every monitor, or junk size.
        assert_eq!(usable_rect(&WindowState { x: -1800, ..s }, &mons), None);
        assert_eq!(usable_rect(&WindowState { y: 1100, ..s }, &mons), None);
        assert_eq!(usable_rect(&WindowState { width: 0, height: 0, ..s }, &mons), None);
        assert_eq!(usable_rect(&s, &[]), None);
    }

    #[test]
    fn job_ids_from_event_payloads() {
        assert_eq!(event_job(r#"{"job":7,"sessionId":"abc","filesDone":1}"#), Some(7));
        assert_eq!(event_job(r#"{"sessionId":"abc"}"#), None);
        assert_eq!(event_job("not json"), None);
        let r = RunningJobs { scans: 1, recoveries: 0, imaging: 2 };
        assert!(r.any() && !RunningJobs::default().any());
        assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"scans":1,"recoveries":0,"imaging":2}"#);
    }

    #[test]
    fn a_job_whose_thread_panicked_is_forgotten() {
        let job = 9_000_000 + u64::from(std::process::id() % 1000);
        let has = |k: JobKind, j: u64| k.set(&mut EVENT_JOBS.lock().unwrap_or_else(|e| e.into_inner())).contains(&j);
        let t = std::thread::Builder::new()
            .name(JobKind::Recovery.thread_name(job))
            .spawn(move || {
                note_job_event(JobKind::Recovery, job, true);
                assert!(has(JobKind::Recovery, job));
                panic!("engine panic (expected by this test)");
            })
            .unwrap();
        assert!(t.join().is_err());
        assert!(!has(JobKind::Recovery, job), "the job ended with its thread");

        // Events seen on another thread still count until the done event.
        note_job_event(JobKind::Imaging, job, true);
        assert!(has(JobKind::Imaging, job));
        note_job_event(JobKind::Imaging, job, false);
        assert!(!has(JobKind::Imaging, job));
        assert_eq!(JobKind::Imaging.thread_name(3), "maxrec-image-3");
    }

    #[test]
    fn scans_of_the_data_drive() {
        let vol = |p: &str| model::SourceRef { kind: model::SourceKind::Volume, path: p.into(), ..Default::default() };
        let disk = |p: &str| model::SourceRef { kind: model::SourceKind::Disk, path: p.into(), ..Default::default() };
        let c_disks = |l: char| if l == 'C' || l == 'E' { vec![0] } else { vec![1] };
        let data = DataPlace { root: Some("C:\\".into()), volume: Some(r"\\?\Volume{c0}\".into()), disks: vec![0] };
        // Snapshots: path "c" is a shadow copy of C:, "d" of D: (on disk 1), "x" unknown.
        let snaps = |s: &model::SourceRef| match s.path.as_str() {
            "c" => (Some(r"\\?\volume{c0}\".to_string()), vec![]),
            "d" => (Some(r"\\?\volume{d1}\".to_string()), vec![1]),
            _ => (None, vec![]),
        };
        let shares = |s: &model::SourceRef| source_shares(s, &data, c_disks, snaps);
        assert!(shares(&vol("c")));
        // Another partition of the same disk shares its free space with nothing, but the disk is read.
        assert!(shares(&vol("E:")));
        assert!(!shares(&vol("D")));
        assert!(shares(&disk("0")));
        assert!(!shares(&disk("1")));
        let image = model::SourceRef { kind: model::SourceKind::Image, path: r"C:\x.img".into(), ..Default::default() };
        assert!(!shares(&image));
        // A shadow copy counts as its original volume.
        let snap = |p: &str| model::SourceRef { kind: model::SourceKind::Snapshot, path: p.into(), ..Default::default() };
        assert!(shares(&snap("c")), "same volume (GUID compared without case)");
        assert!(!shares(&snap("d")));
        assert!(!shares(&snap("x")));
        let on_disk0 = |_: &model::SourceRef| (None, vec![0]);
        assert!(source_shares(&snap("x"), &data, c_disks, on_disk0), "same physical disk");
    }

    #[test]
    fn hold_answer_is_reused_for_the_same_sources() {
        assert!(!scan_reads_data_drive(Vec::new(), false), "no scan, no hold");
        // A remembered answer for these sources is used without looking at any drive.
        let srcs = vec![model::SourceRef { kind: model::SourceKind::Volume, path: "Q-test".into(), ..Default::default() }];
        *HOLD_MEMO.lock().unwrap() = Some((srcs.clone(), true));
        assert!(scan_reads_data_drive(srcs, false));
    }

    #[test]
    fn held_log_lines_are_written_later() {
        let mut s = LogSink { file: None, held: Vec::new() };
        s.take(b"a\n", true);
        s.take(b"b\n", true);
        assert_eq!(s.held, b"a\nb\n");
        s.take(&vec![b'x'; LOG_HOLD_MAX], true);
        assert_eq!(s.held.len(), 4, "the hold never grows past its limit");
        s.take(b"c\n", false);
        assert!(s.held.is_empty());
    }

    #[test]
    fn closing_while_jobs_run() {
        let idle = RunningJobs::default();
        let busy = RunningJobs { scans: 0, recoveries: 1, imaging: 0 };
        assert_eq!(close_action(false, false, idle, false), CloseAction::Close);
        assert_eq!(close_action(false, false, idle, true), CloseAction::Close);
        assert_eq!(close_action(false, false, busy, false), CloseAction::Ask);
        // The installer's close message never waits for an answer.
        assert_eq!(close_action(false, false, busy, true), CloseAction::StopThenExit);
        assert_eq!(close_action(false, true, busy, true), CloseAction::Ignore);
        assert_eq!(close_action(true, true, busy, false), CloseAction::Close);
    }

    #[test]
    fn theme_prefs() {
        assert!(valid_theme("light") && valid_theme("dark") && valid_theme("system") && !valid_theme("blue"));
        assert!(is_dark("dark") && !is_dark("light"));
        assert_eq!(window_theme("system"), None);
        assert_eq!(window_theme("dark"), Some(Theme::Dark));
        assert_eq!(
            theme_seed_script("dark"),
            r#"try{localStorage.setItem("maxrec.theme","dark");localStorage.setItem("maxrec.themeSynced","dark")}catch(e){}"#
        );
    }
}
