//! Disk imaging: copy a source sector by sector into a raw image file, skipping unreadable sectors
//! (zero-filled, logged, retried at the end), so recovery can run on the copy instead of a failing
//! drive. Events: "imaging-progress", "imaging-done" (see CONTRACT.md). OWNER: device agent.
//!
//! The source is only ever read (through `open_source`, read-only). The destination must be a new
//! file on another physical disk. A reader thread fills 4 MiB chunks (one big read; on an error the
//! chunk is bisected down to single sectors, each tried `retries` times) while the job thread writes
//! them sequentially and hashes them (BLAKE3). After the main pass, unreadable sectors get one more
//! round of attempts and anything that reads now is patched into the file in place.

use super::source::{open_source, read_full, BlockSource};
use crate::model::{human_size, now_ms, SourceKind, SourceRef};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ImagingOptions {
    /// Read attempts per bad sector (default 2, max 8).
    #[serde(default)]
    pub retries: Option<u32>,
    /// Compute a BLAKE3 hash of the image while writing (default true).
    #[serde(default)]
    pub hash: Option<bool>,
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ImagingStarted {
    pub job: u64,
    pub path: String,
}

/// `imaging-progress` payload.
#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ImagingProgress {
    pub job: u64,
    /// "running" | "paused" | "retrying" (second pass over unreadable sectors) | "hashing"
    pub state: String,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub bad_bytes: u64,
    pub bytes_per_sec: u64,
    pub eta_seconds: Option<u64>,
}

/// `imaging-done` payload.
#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ImagingDone {
    pub job: u64,
    /// "done" | "cancelled" | "failed"
    pub state: String,
    pub error: Option<String>,
    pub path: String,
    pub bytes_written: u64,
    pub bad_ranges: Vec<(u64, u64)>,
    pub blake3: Option<String>,
    pub log_path: String,
    /// One sentence about the outcome ("The partial image was kept …", "12 KB couldn't be read …").
    /// Additive field.
    pub note: Option<String>,
}

pub enum ImagingEvent {
    Progress(ImagingProgress),
    Done(ImagingDone),
}

/// Pause / cancel switches of one running job.
#[derive(Default)]
pub struct JobCtl {
    pub paused: AtomicBool,
    pub cancel: AtomicBool,
}

static NEXT_JOB: AtomicU64 = AtomicU64::new(1);
fn jobs() -> &'static Mutex<HashMap<u64, Arc<JobCtl>>> {
    static J: OnceLock<Mutex<HashMap<u64, Arc<JobCtl>>>> = OnceLock::new();
    J.get_or_init(|| Mutex::new(HashMap::new()))
}

const CHUNK: usize = 4 << 20;
const TICK: Duration = Duration::from_millis(250);

#[tauri::command]
pub async fn start_imaging(app: tauri::AppHandle, source: SourceRef, dest: String, options: Option<ImagingOptions>) -> Result<ImagingStarted, String> {
    let opts = options.unwrap_or_default();
    let (src, file, path) = tauri::async_runtime::spawn_blocking({
        let (source, dest) = (source.clone(), dest.clone());
        move || prepare(&source, &dest)
    })
    .await
    .map_err(|_| "Starting the disk image stopped unexpectedly.".to_string())??;

    let job = NEXT_JOB.fetch_add(1, Ordering::SeqCst);
    let ctl = Arc::new(JobCtl::default());
    jobs().lock().unwrap_or_else(|e| e.into_inner()).insert(job, ctl.clone());
    let path_s = path.to_string_lossy().into_owned();
    let spawned = std::thread::Builder::new().name(format!("maxrec-image-{job}")).spawn(move || {
        use tauri::Emitter;
        let emit = |ev: ImagingEvent| {
            let _ = match ev {
                ImagingEvent::Progress(p) => app.emit("imaging-progress", p),
                ImagingEvent::Done(d) => app.emit("imaging-done", d),
            };
        };
        run_job(job, src.as_ref(), &source, file, &path, &opts, &ctl, &emit);
        jobs().lock().unwrap_or_else(|e| e.into_inner()).remove(&job);
    });
    if spawned.is_err() {
        jobs().lock().unwrap_or_else(|e| e.into_inner()).remove(&job);
        return Err("Windows couldn't start the imaging job. Close some programs and try again.".into());
    }
    Ok(ImagingStarted { job, path: path_s })
}

#[tauri::command]
pub fn pause_imaging(job: u64, paused: bool) -> Result<(), String> {
    let j = jobs().lock().unwrap_or_else(|e| e.into_inner());
    let ctl = j.get(&job).ok_or_else(|| "That disk image has already finished.".to_string())?;
    ctl.paused.store(paused, Ordering::SeqCst);
    Ok(())
}

#[tauri::command]
pub fn cancel_imaging(job: u64) -> Result<(), String> {
    let j = jobs().lock().unwrap_or_else(|e| e.into_inner());
    let ctl = j.get(&job).ok_or_else(|| "That disk image has already finished.".to_string())?;
    ctl.cancel.store(true, Ordering::SeqCst);
    ctl.paused.store(false, Ordering::SeqCst);
    Ok(())
}

// ------------------------------------------------------------------------------- preparation

/// Physical disks the source's bytes live on (empty = unknown). Shared lookup with the recovery
/// destination check (win::source_location).
#[cfg(test)]
fn source_disks(source: &SourceRef) -> Vec<u32> {
    super::win::source_location(source).disks.unwrap_or_default()
}

const REFUSE_SAME: &str = "This image would be written to the drive you are imaging. Pick a folder on another drive.";
const REFUSE_DEST_UNKNOWN: &str = "MAX couldn't tell which drive this folder is on, so it can't rule out the drive you are imaging. Pick a folder on another drive.";
const REFUSE_SOURCE_UNKNOWN: &str = "MAX couldn't tell which physical drive you are imaging, so it can't rule this folder out. Pick a folder on a USB drive or another disk.";

/// Never write the image onto the drive being imaged. `parent` is the image's folder (exists),
/// `file` the image path. The same rules as the recovery destination check, failing closed: an
/// unknown disk on either side is refused, links / mapped drives / shares on this PC / virtual
/// disks are resolved first. An Image source only forbids the image file itself.
fn check_dest(source: &SourceRef, parent: &str, file: &Path) -> Result<super::win::PathLocation, String> {
    let loc = super::win::locate_path(parent);
    if let Some(r) = &loc.refuse {
        return Err(r.clone());
    }
    if source.kind == SourceKind::Image {
        let src = super::win::source_location(source);
        let name = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let real_file = loc.real_path.as_deref().map(|p| format!("{}\\{name}", p.trim_end_matches('\\')).to_lowercase());
        let lexical = file.to_string_lossy().to_lowercase();
        let image = src.image_real_path.map(|p| p.to_lowercase()).unwrap_or_else(|| source.path.trim().to_lowercase());
        if real_file.as_deref() == Some(image.as_str()) || lexical == image {
            return Err("That is the disk image you are imaging. Pick another name.".into());
        }
        return Ok(loc);
    }
    if loc.network_root.is_some() {
        return Ok(loc); // a share on another computer can't be a drive in this PC
    }
    let src = super::win::source_location(source);
    if let (Some(a), Some(b)) = (&loc.volume, &src.volume) {
        if a == b {
            return Err(REFUSE_SAME.into());
        }
    }
    if source.kind == SourceKind::Volume {
        let letter = source.path.trim().trim_end_matches([':', '\\']).to_ascii_uppercase();
        if loc.real_path.as_deref().is_some_and(|p| p.to_ascii_uppercase().starts_with(&format!("{letter}:"))) {
            return Err(REFUSE_SAME.into());
        }
    }
    let Some(src_disks) = &src.disks else { return Err(REFUSE_SOURCE_UNKNOWN.into()) };
    let Some(dest_disks) = &loc.disks else { return Err(REFUSE_DEST_UNKNOWN.into()) };
    if dest_disks.iter().any(|d| src_disks.contains(d)) {
        return Err(REFUSE_SAME.into());
    }
    Ok(loc)
}

fn io_sentence(e: &std::io::Error) -> String {
    let s = e.to_string();
    let s = s.split(" (os error").next().unwrap_or(&s).trim().trim_end_matches('.').to_string();
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().chain(c).collect(),
        None => s,
    }
}

/// Check the destination and open everything. Returns (source, new image file, its path).
pub(crate) fn prepare(source: &SourceRef, dest: &str) -> Result<(super::source::Source, File, PathBuf), String> {
    let path = PathBuf::from(dest.trim());
    if dest.trim().is_empty() || !path.is_absolute() {
        return Err("Pick a folder and a file name for the image.".into());
    }
    if path.is_dir() {
        return Err("That is a folder. Add a file name for the image.".into());
    }
    if path.exists() {
        return Err("A file with that name already exists. Pick another name.".into());
    }
    let parent = path.parent().filter(|p| p.is_dir()).ok_or_else(|| "That folder doesn't exist. Pick another folder.".to_string())?;
    let parent_s = parent.to_string_lossy().into_owned();

    // Never write the image onto the drive being imaged.
    let loc = check_dest(source, &parent_s, &path)?;

    let src = open_source(source)?;
    let need = src.len();

    // Room for it, and a file system that can hold one file that big.
    let w = crate::util::wide(&parent_s);
    let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
    if unsafe { windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(w.as_ptr(), &mut avail, &mut total, &mut free) } != 0 && avail < need + (1 << 20) {
        return Err(format!(
            "There isn't enough free space there: the image needs {} and only {} is free. Pick a folder on a bigger drive.",
            human_size(need),
            human_size(avail)
        ));
    }
    let dest_root = loc.root.as_deref().unwrap_or("").to_ascii_uppercase();
    if let Some(l) = dest_root.chars().next().filter(|_| dest_root.as_bytes().get(1) == Some(&b':')) {
        if let Some(fs) = super::win::fs_name(l) {
            if fs.to_ascii_uppercase().starts_with("FAT") && !fs.eq_ignore_ascii_case("exFAT") && need >= 4u64 << 30 {
                return Err(format!("That drive is {fs}, which can't hold files of 4 GB or more. Pick a folder on an NTFS or exFAT drive."));
            }
        }
    }

    let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).map_err(|e| match e.raw_os_error() {
        Some(80) | Some(183) => "A file with that name already exists. Pick another name.".to_string(),
        Some(5) => "Windows didn't let MAX create a file there. Pick another folder.".to_string(),
        _ => format!("Windows couldn't create the image file ({}). Pick another folder.", io_sentence(&e)),
    })?;
    Ok((src, file, path))
}

// --------------------------------------------------------------------------------------- job

/// Read `buf` at `off`; on an error bisect down to single sectors, each tried `attempts` times.
/// Unreadable sectors are zero-filled and appended (merged) to `bad`.
fn read_bisect(src: &dyn BlockSource, off: u64, buf: &mut [u8], ss: usize, attempts: u32, bad: &mut Vec<(u64, u64)>, ctl: &JobCtl) {
    if matches!(read_full(src, off, buf), Ok(n) if n == buf.len()) {
        return;
    }
    if buf.len() <= ss {
        for _ in 1..attempts {
            if ctl.cancel.load(Ordering::Relaxed) {
                break;
            }
            if matches!(read_full(src, off, buf), Ok(n) if n == buf.len()) {
                return;
            }
        }
        buf.fill(0);
        let end = off + buf.len() as u64;
        match bad.last_mut() {
            Some(last) if last.1 == off => last.1 = end,
            _ => bad.push((off, end)),
        }
        return;
    }
    // Split on a sector boundary (relative to the source, so sectors stay whole).
    let mid_abs = (off + buf.len() as u64 / 2) / ss as u64 * ss as u64;
    let mid = if mid_abs <= off { ss.min(buf.len()) } else { (mid_abs - off) as usize };
    let (a, b) = buf.split_at_mut(mid);
    read_bisect(src, off, a, ss, attempts, bad, ctl);
    read_bisect(src, off + mid as u64, b, ss, attempts, bad, ctl);
}

/// Smoothed throughput + throttled progress events.
struct Meter<'a> {
    job: u64,
    total: u64,
    last_at: Instant,
    last_done: u64,
    rate: f64,
    emit: &'a dyn Fn(ImagingEvent),
}

impl Meter<'_> {
    fn tick(&mut self, state: &str, done: u64, bad: u64, force: bool) {
        let dt = self.last_at.elapsed();
        if !force && dt < TICK {
            return;
        }
        if state != "paused" && dt.as_secs_f64() > 0.0 {
            let inst = done.saturating_sub(self.last_done) as f64 / dt.as_secs_f64();
            self.rate = if self.rate == 0.0 { inst } else { 0.3 * inst + 0.7 * self.rate };
        }
        self.last_at = Instant::now();
        self.last_done = done;
        let eta = (self.rate > 1.0 && state == "running").then(|| (self.total.saturating_sub(done) as f64 / self.rate).ceil() as u64);
        (self.emit)(ImagingEvent::Progress(ImagingProgress {
            job: self.job,
            state: state.into(),
            bytes_done: done,
            bytes_total: self.total,
            bad_bytes: bad,
            bytes_per_sec: self.rate as u64,
            eta_seconds: eta,
        }));
    }
}

fn write_sentence(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(112) | Some(39) => "The destination drive is full. Free some space or pick another drive.".into(),
        Some(21) | Some(1167) | Some(55) => "The destination drive was disconnected. Reconnect it and start again.".into(),
        _ => format!("Windows couldn't write the image ({}). Check the destination drive and start again.", io_sentence(e)),
    }
}

/// The whole imaging job, without Tauri: emits progress and exactly one `Done`, writes the log.
#[allow(clippy::too_many_arguments)]
pub fn run_job(job: u64, src: &dyn BlockSource, source: &SourceRef, mut file: File, path: &Path, opts: &ImagingOptions, ctl: &JobCtl, emit: &dyn Fn(ImagingEvent)) -> ImagingDone {
    let started = now_ms();
    let t0 = Instant::now();
    let total = src.len();
    let ss = src.sector_size().max(512) as usize;
    let attempts = opts.retries.unwrap_or(2).clamp(1, 8);
    let want_hash = opts.hash.unwrap_or(true);
    let mut hasher = want_hash.then(blake3::Hasher::new);
    let mut bad: Vec<(u64, u64)> = Vec::new();
    let mut written = 0u64;
    let mut error: Option<String> = None;
    let mut meter = Meter { job, total, last_at: Instant::now(), last_done: 0, rate: 0.0, emit };
    meter.tick("running", 0, 0, true);

    // ---- main pass: reader thread → bounded channel → sequential writer + hasher
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| {
        let (tx, rx) = mpsc::sync_channel::<(Vec<u8>, Vec<(u64, u64)>)>(3);
        let stop = &stop;
        s.spawn(move || {
            let mut off = 0u64;
            while off < total {
                while ctl.paused.load(Ordering::Relaxed) && !ctl.cancel.load(Ordering::Relaxed) && !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(50));
                }
                if ctl.cancel.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
                    break;
                }
                let n = (CHUNK as u64).min(total - off) as usize;
                let mut buf = vec![0u8; n];
                let mut b = Vec::new();
                read_bisect(src, off, &mut buf, ss, attempts, &mut b, ctl);
                if ctl.cancel.load(Ordering::Relaxed) || tx.send((buf, b)).is_err() {
                    break;
                }
                off += n as u64;
            }
        });
        let mut bad_bytes = 0u64;
        loop {
            match rx.recv_timeout(TICK) {
                Ok((buf, b)) => {
                    if let Err(e) = file.write_all(&buf) {
                        error = Some(write_sentence(&e));
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                    if let Some(h) = hasher.as_mut() {
                        h.update(&buf);
                    }
                    written += buf.len() as u64;
                    for r in b {
                        bad_bytes += r.1 - r.0;
                        match bad.last_mut() {
                            Some(last) if last.1 == r.0 => last.1 = r.1,
                            _ => bad.push(r),
                        }
                    }
                    meter.tick("running", written, bad_bytes, false);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let st = if ctl.paused.load(Ordering::Relaxed) { "paused" } else { "running" };
                    meter.tick(st, written, bad_bytes, false);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        drop(rx); // unblocks a reader stuck on a full channel after a write error
    });
    let main_ms = t0.elapsed().as_millis() as u64;
    let cancelled = ctl.cancel.load(Ordering::Relaxed) && error.is_none() && written < total;

    // ---- retry pass over unreadable sectors (only for a complete image)
    let mut recovered = 0u64;
    let mut retry_skipped = false;
    let t1 = Instant::now();
    if error.is_none() && !cancelled && !bad.is_empty() {
        let bad_total: u64 = bad.iter().map(|r| r.1 - r.0).sum();
        let mut still: Vec<(u64, u64)> = Vec::new();
        let mut sector = vec![0u8; ss];
        let ranges = bad.clone();
        let mut stopped_at: Option<usize> = None;
        'ranges: for (i, &(s, e)) in ranges.iter().enumerate() {
            let mut pos = s;
            while pos < e {
                if ctl.cancel.load(Ordering::Relaxed) {
                    retry_skipped = true;
                    still.push((pos, e));
                    stopped_at = Some(i);
                    break 'ranges;
                }
                while ctl.paused.load(Ordering::Relaxed) && !ctl.cancel.load(Ordering::Relaxed) {
                    meter.tick("paused", written, bad_total - recovered, false);
                    std::thread::sleep(Duration::from_millis(50));
                }
                let n = (ss as u64).min(e - pos) as usize;
                let piece = &mut sector[..n];
                let ok = (0..attempts).any(|_| matches!(read_full(src, pos, piece), Ok(k) if k == n));
                if ok {
                    if let Err(err) = file.seek_write(piece, pos).and_then(|w| if w == n { Ok(()) } else { Err(std::io::Error::from_raw_os_error(112)) }) {
                        error = Some(write_sentence(&err));
                        still.push((pos, e));
                        stopped_at = Some(i);
                        break 'ranges;
                    }
                    recovered += n as u64;
                } else {
                    match still.last_mut() {
                        Some(last) if last.1 == pos => last.1 = pos + n as u64,
                        _ => still.push((pos, pos + n as u64)),
                    }
                }
                pos += n as u64;
                meter.tick("retrying", written, bad_total - recovered, false);
            }
        }
        // Ranges not visited (after a cancel or a write error) stay bad.
        if let Some(i) = stopped_at {
            still.extend_from_slice(&ranges[i + 1..]);
        }
        bad = still;
    }
    let retry_ms = t1.elapsed().as_millis() as u64;
    let _ = file.flush();
    let _ = file.sync_all();

    // ---- hash (re-read the file when the retry pass patched it)
    let mut digest = hasher.map(|h| h.finalize().to_hex().to_string());
    let mut hash_skipped = false;
    if want_hash && error.is_none() && !cancelled && recovered > 0 {
        // The file was patched, so the streamed hash is stale: re-read it, honouring Pause / Stop.
        digest = None;
        if ctl.cancel.load(Ordering::Relaxed) {
            hash_skipped = true;
        } else {
            let still_bad: u64 = bad.iter().map(|r| r.1 - r.0).sum();
            meter.last_done = 0;
            meter.tick("hashing", 0, still_bad, true);
            match hash_file(path, ctl, &mut |done, paused| meter.tick(if paused { "paused" } else { "hashing" }, done, still_bad, false)) {
                Ok(Some(h)) => digest = Some(h),
                Ok(None) => hash_skipped = true,
                Err(_) => {}
            }
        }
    }
    if cancelled || error.is_some() {
        digest = None; // a hash of a partial image would only mislead
    }
    drop(file);

    let bad_bytes: u64 = bad.iter().map(|r| r.1 - r.0).sum();
    let state = if error.is_some() {
        "failed"
    } else if cancelled {
        "cancelled"
    } else {
        "done"
    };
    let note = match state {
        "cancelled" => Some(format!("Imaging was cancelled. The partial image ({} of {}) was kept at {}.", human_size(written), human_size(total), path.display())),
        "failed" if written > 0 => Some(format!("The partial image ({} of {}) was kept at {}.", human_size(written), human_size(total), path.display())),
        _ if retry_skipped => Some(format!(
            "The image is complete, but the last retry of unreadable sectors was skipped; {} couldn't be read and are zeros in the image.{}",
            human_size(bad_bytes),
            if hash_skipped { " Its hash wasn't computed." } else { "" }
        )),
        _ if hash_skipped => Some(format!(
            "The image is complete, but its hash wasn't computed because you stopped it.{}",
            if bad_bytes > 0 { format!(" {} couldn't be read and are zeros in the image.", human_size(bad_bytes)) } else { String::new() }
        )),
        _ if bad_bytes > 0 => Some(format!("{} couldn't be read and are zeros in the image. Scan the image, not the drive.", human_size(bad_bytes))),
        _ => None,
    };

    let log_path = PathBuf::from(format!("{}.maxlog.json", path.display()));
    let log = serde_json::json!({
        "app": "MAX File Recovery",
        "version": env!("CARGO_PKG_VERSION"),
        "job": job,
        "state": state,
        "error": error,
        "note": note,
        "source": source,
        "sourceDescription": src.describe(),
        "sourceSize": total,
        "sectorSize": ss,
        "image": path.display().to_string(),
        "format": "raw",
        "bytesWritten": written,
        "badRanges": bad,
        "badBytes": bad_bytes,
        "recoveredOnRetry": recovered,
        "readAttemptsPerSector": attempts,
        "blake3": digest,
        "startedAt": started,
        "finishedAt": now_ms(),
        "durationMs": t0.elapsed().as_millis() as u64,
        "mainPassMs": main_ms,
        "retryPassMs": retry_ms,
    });
    let log_written = serde_json::to_vec_pretty(&log).ok().and_then(|b| std::fs::write(&log_path, b).ok()).is_some();

    let done = ImagingDone {
        job,
        state: state.into(),
        error,
        path: path.display().to_string(),
        bytes_written: written,
        bad_ranges: bad,
        blake3: digest,
        log_path: if log_written { log_path.display().to_string() } else { String::new() },
        note,
    };
    emit(ImagingEvent::Done(done.clone()));
    done
}

/// BLAKE3 of the image file. Ok(None) when the job was stopped meanwhile; waits while paused.
/// `progress(bytes hashed, paused)` is called per chunk and while paused.
fn hash_file(path: &Path, ctl: &JobCtl, progress: &mut dyn FnMut(u64, bool)) -> std::io::Result<Option<String>> {
    let mut f = File::open(path)?;
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK];
    let mut done = 0u64;
    loop {
        while ctl.paused.load(Ordering::Relaxed) && !ctl.cancel.load(Ordering::Relaxed) {
            progress(done, true);
            std::thread::sleep(Duration::from_millis(50));
        }
        if ctl.cancel.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        done += n as u64;
        progress(done, false);
    }
    Ok(Some(h.finalize().to_hex().to_string()))
}

#[cfg(test)]
mod tests {
    use super::super::image::tests::TempFile;
    use super::super::source::MemSource;
    use super::*;
    use std::sync::atomic::AtomicU32;

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i as u32).wrapping_mul(2654435761).rotate_left(7) as u8 | 1).collect()
    }

    fn collect() -> (Arc<Mutex<Vec<ImagingProgress>>>, Arc<Mutex<Vec<ImagingDone>>>, impl Fn(ImagingEvent)) {
        let p = Arc::new(Mutex::new(Vec::new()));
        let d = Arc::new(Mutex::new(Vec::new()));
        let (p2, d2) = (p.clone(), d.clone());
        (p, d, move |ev| match ev {
            ImagingEvent::Progress(x) => p2.lock().unwrap().push(x),
            ImagingEvent::Done(x) => d2.lock().unwrap().push(x),
        })
    }

    fn image_source(t: &TempFile, len: usize) -> Vec<u8> {
        let d = data(len);
        std::fs::write(&t.0, &d).unwrap();
        d
    }

    #[test]
    fn images_a_source_with_a_bad_range() {
        let len = 10 * (1 << 20) + 3 * 512; // not a chunk multiple
        let mut m = MemSource::new(data(len));
        m.bad = vec![(5_000_000 / 512 * 512, 5_000_000 / 512 * 512 + 8 * 512)];
        let (bs, be) = m.bad[0];
        let mut expected = m.data.clone();
        expected[bs as usize..be as usize].fill(0);

        let out = TempFile::new("img");
        let log = TempFile(PathBuf::from(format!("{}.maxlog.json", out.path())));
        let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&out.0).unwrap();
        let ctl = JobCtl::default();
        let (_p, d, emit) = collect();
        let src_ref = SourceRef { kind: SourceKind::Image, path: "memory".into(), ..Default::default() };
        let done = run_job(7, &m, &src_ref, file, &out.0, &ImagingOptions { retries: Some(3), hash: Some(true) }, &ctl, &emit);

        assert_eq!(done.state, "done", "{done:?}");
        assert_eq!(done.bad_ranges, vec![(bs, be)]);
        assert_eq!(done.bytes_written, len as u64);
        let got = std::fs::read(&out.0).unwrap();
        assert!(got == expected, "image content differs");
        assert_eq!(done.blake3.as_deref(), Some(blake3::hash(&expected).to_hex().as_str()));
        assert!(done.note.as_deref().unwrap().contains("4.0 KB couldn't be read"), "{:?}", done.note);
        assert_eq!(d.lock().unwrap().len(), 1);
        let l: serde_json::Value = serde_json::from_slice(&std::fs::read(&log.0).unwrap()).unwrap();
        assert_eq!(l["badBytes"], 4096);
        assert_eq!(l["state"], "done");
        assert_eq!(done.log_path, log.path());
    }

    /// Sectors that fail on the first reads but answer later are patched in by the retry pass,
    /// and the hash is the hash of the final file.
    struct Flaky {
        inner: MemSource,
        bad: (u64, u64),
        failures_left: AtomicU32,
    }
    impl BlockSource for Flaky {
        fn len(&self) -> u64 {
            self.inner.len()
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let end = offset + buf.len() as u64;
            if offset < self.bad.1 && self.bad.0 < end && self.failures_left.load(Ordering::SeqCst) > 0 {
                self.failures_left.fetch_sub(1, Ordering::SeqCst);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "flaky"));
            }
            self.inner.read_at(offset, buf)
        }
        fn describe(&self) -> String {
            "flaky".into()
        }
    }

    #[test]
    fn retry_pass_recovers_flaky_sectors() {
        let len = 6 << 20;
        let d = data(len);
        // One sector, failing for the first 3 reads of it (chunk read, bisect steps, 1 attempt).
        let mut inner = MemSource::new(d.clone());
        inner.bad = vec![(3 << 20, (3 << 20) + 1024)]; // permanently unreadable, before the flaky sector
        let mut d = d;
        d[3 << 20..(3 << 20) + 1024].fill(0);
        let src = Flaky { inner, bad: (4 << 20, (4 << 20) + 512), failures_left: AtomicU32::new(1000) };
        let out = TempFile::new("img");
        let _log = TempFile(PathBuf::from(format!("{}.maxlog.json", out.path())));
        let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&out.0).unwrap();
        let ctl = JobCtl::default();
        let (p, _d, emit) = collect();
        // Make the sector readable once the main pass is over: count how many failures it takes.
        let opts = ImagingOptions { retries: Some(1), hash: Some(true) };
        // Main pass: the 2 MiB chunk read + 12 bisect reads down to the 512-byte sector all fail.
        src.failures_left.store(1 + 12, Ordering::SeqCst);
        let done = run_job(8, &src, &SourceRef::default(), file, &out.0, &opts, &ctl, &emit);
        assert_eq!(done.state, "done");
        assert_eq!(done.bad_ranges, vec![(3 << 20, (3 << 20) + 1024)]);
        let got = std::fs::read(&out.0).unwrap();
        assert!(got == d, "patched image differs");
        assert_eq!(done.blake3.as_deref(), Some(blake3::hash(&d).to_hex().as_str()));
        assert!(p.lock().unwrap().iter().any(|x| x.state == "retrying" || x.state == "hashing"));
    }

    #[test]
    fn cancel_keeps_the_partial_image() {
        let m = MemSource::new(data(12 << 20));
        let out = TempFile::new("img");
        let _log = TempFile(PathBuf::from(format!("{}.maxlog.json", out.path())));
        let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&out.0).unwrap();
        let ctl = JobCtl::default();
        ctl.cancel.store(true, Ordering::SeqCst);
        let (_p, d, emit) = collect();
        let done = run_job(9, &m, &SourceRef::default(), file, &out.0, &ImagingOptions::default(), &ctl, &emit);
        assert_eq!(done.state, "cancelled");
        assert!(done.blake3.is_none());
        assert!(done.note.unwrap().contains("partial image"));
        assert!(out.0.exists());
        assert_eq!(d.lock().unwrap().len(), 1);
    }

    #[test]
    fn destination_rules() {
        let tmp = std::env::temp_dir();
        // An image in %TEMP% imaged into %TEMP%: only the image file itself is off limits, so a
        // copy next to it is fine (it can't change the image's bytes).
        let img = TempFile::new("img");
        image_source(&img, 1 << 20);
        let src = SourceRef { kind: SourceKind::Image, path: img.path(), ..Default::default() };
        let dest = TempFile(tmp.join(format!("maxrec-dev-out-{}.img", now_ms())));
        let (_s, f, p) = prepare(&src, &dest.path()).unwrap();
        drop(f);
        assert_eq!(p, dest.0);
        std::fs::remove_file(&dest.0).unwrap();
        // The system volume into %TEMP% (on it): refused before any raw open.
        let sys = crate::util::system_drive_letter();
        if tmp.to_string_lossy().to_ascii_uppercase().starts_with(&format!("{sys}:")) {
            let e = prepare(&SourceRef { kind: SourceKind::Volume, path: sys.clone(), ..Default::default() }, &dest.path()).err().unwrap();
            assert!(e.contains("drive you are imaging"), "{e}");
        }
        // Existing file.
        let e = prepare(&src, &img.path()).err().unwrap();
        assert_eq!(e, "A file with that name already exists. Pick another name.");
        // Missing folder / relative path.
        assert!(prepare(&src, &tmp.join("no-such-dir-maxrec").join("x.img").to_string_lossy()).err().unwrap().contains("doesn't exist"));
        assert!(prepare(&src, "x.img").is_err());
        assert!(source_disks(&SourceRef { kind: SourceKind::Disk, path: "3".into(), ..Default::default() }) == vec![3]);
    }

    /// Unknown disks on either side are refused (fail closed), and a link is followed first.
    #[test]
    fn destination_check_fails_closed() {
        let tmp = std::env::temp_dir();
        let file = tmp.join("x.img");
        let tmp_s = tmp.to_string_lossy().into_owned();
        // Source volume on a letter that doesn't exist: its disk is unknown.
        let missing = ('M'..='Z').rev().find(|l| !Path::new(&format!("{l}:\\")).exists()).expect("a free drive letter");
        let src = SourceRef { kind: SourceKind::Volume, path: missing.to_string(), ..Default::default() };
        assert_eq!(check_dest(&src, &tmp_s, &file).err().as_deref(), Some(REFUSE_SOURCE_UNKNOWN));
        let src = SourceRef { kind: SourceKind::Snapshot, path: r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy9999".into(), ..Default::default() };
        assert_eq!(check_dest(&src, &tmp_s, &file).err().as_deref(), Some(REFUSE_SOURCE_UNKNOWN));
        // Destination on a drive that doesn't exist: unknown, refused.
        let src = SourceRef { kind: SourceKind::Disk, path: "99".into(), ..Default::default() };
        assert_eq!(check_dest(&src, &format!("{missing}:\\x"), &file).err().as_deref(), Some(REFUSE_DEST_UNKNOWN));
        // Through a loopback admin share to the drive being imaged: refused.
        let sys = crate::util::system_drive_letter();
        let src = SourceRef { kind: SourceKind::Volume, path: sys.clone(), ..Default::default() };
        assert_eq!(check_dest(&src, &format!(r"\\localhost\{sys}$\Windows"), &file).err().as_deref(), Some(REFUSE_SAME));
        // Through a junction into %TEMP% while imaging %TEMP%'s drive: refused.
        let base = tmp.join(format!("maxrec-img-link-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(base.join("real")).unwrap();
        assert!(super::super::win::tests::make_junction(&base.join("link"), &base.join("real")));
        let letter = tmp_s.chars().next().unwrap().to_string();
        let src = SourceRef { kind: SourceKind::Volume, path: letter, ..Default::default() };
        let r = check_dest(&src, &base.join("link").to_string_lossy(), &file);
        let _ = std::fs::remove_dir(base.join("link"));
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(r.err().as_deref(), Some(REFUSE_SAME));
    }

    #[test]
    fn rehash_stops_on_cancel() {
        let t = TempFile::new("img");
        image_source(&t, 9 << 20);
        let ctl = JobCtl::default();
        let mut calls = 0;
        let h = hash_file(&t.0, &ctl, &mut |_, _| calls += 1).unwrap();
        assert_eq!(h.as_deref(), Some(blake3::hash(&std::fs::read(&t.0).unwrap()).to_hex().as_str()));
        assert!(calls >= 3);
        ctl.cancel.store(true, Ordering::SeqCst);
        assert_eq!(hash_file(&t.0, &ctl, &mut |_, _| {}).unwrap(), None);
        // Cancel while paused: the pause loop lets go.
        ctl.paused.store(true, Ordering::SeqCst);
        assert_eq!(hash_file(&t.0, &ctl, &mut |_, _| {}).unwrap(), None);
    }
}
