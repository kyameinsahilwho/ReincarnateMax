//! Drive inventory: physical disks with their partitions, volumes, shadow copies. Works without
//! administrator rights (fields that need them come back as None). OWNER: device agent.
//!
//! Fast path (called at launch): plain Win32 only. Every drive letter is queried on its own thread
//! against one overall deadline (a dead network share or card reader can't stall the list); physical
//! disks are opened with no data access (storage/geometry/layout queries are allowed unelevated); disk
//! health comes from the Storage WMI provider through raw COM (no PowerShell), on a parallel thread.

use super::win::{self, Handle};
use crate::util::{from_wide, is_elevated, system_drive_letter, wide};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Storage::FileSystem::{GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW, GetVolumePathNamesForVolumeNameW};

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct DeviceList {
    pub disks: Vec<DiskInfo>,
    pub volumes: Vec<VolumeInfo>,
    pub snapshots: Vec<SnapshotInfo>,
    /// Shadow copies can only be listed when elevated.
    pub snapshots_need_admin: bool,
    pub elevated: bool,
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct DiskInfo {
    pub index: u32,
    pub model: String,
    pub serial: String,
    pub size: u64,
    pub sector_size: u32,
    /// "NVMe" | "SATA" | "USB" | "SD" | "SAS" | "RAID" | "Virtual" | "Other"
    pub bus: String,
    /// "SSD" | "HDD" | "Unknown"
    pub media: String,
    pub removable: bool,
    /// TRIM (deleted-data erasure) enabled for this SSD. None = unknown / not an SSD.
    pub trim_enabled: Option<bool>,
    /// "GPT" | "MBR" | "RAW" | "Unknown"
    pub partition_style: String,
    pub partitions: Vec<PartitionInfo>,
    /// "Healthy" | "Warning" | "Unhealthy" | None (unknown)
    pub health: Option<String>,
    /// Holds the running Windows.
    pub is_system: bool,
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct PartitionInfo {
    pub number: u32,
    /// Byte offset on the disk.
    pub offset: u64,
    pub size: u64,
    /// "Basic data", "EFI system", "Microsoft reserved", "Recovery", "Extended", "Linux", …
    pub type_name: String,
    pub letter: Option<String>,
    pub fs: Option<String>,
    pub label: Option<String>,
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct VolumeInfo {
    /// "C"
    pub letter: String,
    pub label: String,
    /// "NTFS" | "FAT32" | "FAT" | "exFAT" | "ReFS" | "RAW" | "" (unknown / no media)
    pub fs: String,
    pub size: u64,
    pub free: u64,
    /// "fixed" | "removable" | "network" | "cdrom" | "ram"
    pub drive_type: String,
    pub disk_index: Option<u32>,
    /// Byte offset of the volume on its disk.
    pub offset: Option<u64>,
    /// "none" | "locked" | "unlocked" | "unknown"
    pub bitlocker: String,
    pub is_system: bool,
    pub ssd: Option<bool>,
    pub trim_enabled: Option<bool>,
    /// "ready" | "noMedia" | "raw" | "locked"
    pub state: String,
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotInfo {
    pub id: String,
    /// \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN
    pub device_path: String,
    /// Drive letter of the original volume ("C"), if known.
    pub volume: String,
    /// Unix ms.
    pub created: i64,
}

#[tauri::command]
pub async fn list_devices() -> Result<DeviceList, String> {
    tauri::async_runtime::spawn_blocking(list).await.map_err(|_| "Listing the drives stopped unexpectedly.".to_string())
}

// ======================================================================================= list

/// How long the list waits for slow drives / WMI before answering without them.
const DEADLINE: Duration = Duration::from_millis(1500);
/// A late answer from a slow drive is reused for this long.
const LATE_TTL: Duration = Duration::from_secs(120);
/// How long the list waits for the disk-health WMI answer.
const HEALTH_WAIT: Duration = Duration::from_millis(250);
const STORAGE_NS: &str = r"ROOT\Microsoft\Windows\Storage";

/// One bit per letter whose query thread is still running, so a hung drive never piles up threads.
static BUSY: AtomicU32 = AtomicU32::new(0);
static LAST: Mutex<Vec<Option<(Instant, VolumeInfo)>>> = Mutex::new(Vec::new());
/// Last disk health answer, used while a slow WMI query hasn't answered yet.
static LAST_HEALTH: Mutex<Option<HashMap<u32, String>>> = Mutex::new(None);

pub fn list() -> DeviceList {
    let elevated = is_elevated();
    let sys = system_drive_letter();
    let deadline = Instant::now() + DEADLINE;
    let health_by = Instant::now() + HEALTH_WAIT;

    // Disk health (WMI) and shadow copies (WMI, elevated only) run beside the Win32 queries.
    let (htx, hrx) = mpsc::channel();
    let _ = std::thread::Builder::new().name("maxrec-health".into()).spawn(move || {
        let h = disk_health();
        if let Some(h) = &h {
            *LAST_HEALTH.lock().unwrap_or_else(|e| e.into_inner()) = Some(h.clone());
        }
        let _ = htx.send(h);
    });
    let (stx, srx) = mpsc::channel();
    if elevated {
        let _ = std::thread::Builder::new().name("maxrec-vss".into()).spawn(move || {
            let _ = stx.send(shadow_copies());
        });
    }

    let volumes = list_volumes(&sys, elevated, deadline);
    let sys_disk = volumes.iter().find(|v| v.is_system).and_then(|v| v.disk_index);

    let mut disks: Vec<(DiskInfo, bool)> = (0..32).filter_map(query_disk).collect();
    // Layout denied (shouldn't happen: it's a FILE_ANY_ACCESS query) → the Storage WMI provider.
    if disks.iter().any(|(_, ok)| !ok) {
        if let Ok(parts) = wmi_partitions() {
            for (d, ok) in disks.iter_mut().filter(|(_, ok)| !ok) {
                if let Some((style, p)) = parts.get(&d.index) {
                    d.partition_style = style.clone();
                    d.partitions = p.clone();
                    *ok = true;
                }
            }
        }
    }
    let mut disks: Vec<DiskInfo> = disks.into_iter().map(|(d, _)| d).collect();
    for d in &mut disks {
        d.is_system = Some(d.index) == sys_disk;
        for p in &mut d.partitions {
            if let Some(v) = volumes.iter().find(|v| v.disk_index == Some(d.index) && v.offset == Some(p.offset)) {
                p.letter = Some(v.letter.clone());
                if !v.fs.is_empty() {
                    p.fs = Some(v.fs.clone());
                }
                if !v.label.is_empty() {
                    p.label = Some(v.label.clone());
                }
            }
        }
    }

    // Health is worth a short wait only: a cold Storage provider can take ~1 s to start. A late
    // answer still lands in LAST_HEALTH for the next call.
    let health = match hrx.recv_timeout(health_by.saturating_duration_since(Instant::now())) {
        Ok(Some(h)) => Some(h),
        _ => LAST_HEALTH.lock().unwrap_or_else(|e| e.into_inner()).clone(),
    };
    if let Some(h) = health {
        for d in &mut disks {
            d.health = h.get(&d.index).cloned();
        }
    }
    let snapshots = if elevated { srx.recv_timeout(deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(500))).unwrap_or_default() } else { Vec::new() };

    DeviceList { disks, volumes, snapshots, snapshots_need_admin: !elevated, elevated }
}

// ------------------------------------------------------------------------------------ volumes

fn drive_type(letter: char) -> Option<&'static str> {
    let root = wide(&format!("{letter}:\\"));
    Some(match unsafe { GetDriveTypeW(root.as_ptr()) } {
        2 => "removable",
        3 => "fixed",
        4 => "network",
        5 => "cdrom",
        6 => "ram",
        _ => return None,
    })
}

fn list_volumes(sys: &str, elevated: bool, deadline: Instant) -> Vec<VolumeInfo> {
    let mask = unsafe { GetLogicalDrives() };
    let (tx, rx) = mpsc::channel::<(usize, VolumeInfo)>();
    let mut wanted = Vec::new();
    for i in (0..26usize).filter(|i| mask & (1 << i) != 0) {
        let letter = (b'A' + i as u8) as char;
        let Some(kind) = drive_type(letter) else { continue };
        wanted.push((i, letter, kind));
        if BUSY.fetch_or(1 << i, Ordering::SeqCst) & (1 << i) != 0 {
            continue; // an earlier query of this drive is still stuck
        }
        let (tx, sys) = (tx.clone(), sys.to_string());
        let spawned = std::thread::Builder::new().name(format!("maxrec-vol-{letter}")).spawn(move || {
            let v = query_volume(letter, kind, &sys, elevated);
            if let Ok(mut last) = LAST.lock() {
                if last.len() < 26 {
                    last.resize(26, None);
                }
                last[i] = Some((Instant::now(), v.clone()));
            }
            BUSY.fetch_and(!(1 << i), Ordering::SeqCst);
            let _ = tx.send((i, v));
        });
        if spawned.is_err() {
            BUSY.fetch_and(!(1 << i), Ordering::SeqCst);
        }
    }
    drop(tx);
    let mut got: Vec<Option<VolumeInfo>> = vec![None; 26];
    while let Ok((i, v)) = rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        got[i] = Some(v);
    }
    wanted
        .into_iter()
        .map(|(i, letter, kind)| {
            got[i]
                .take()
                .or_else(|| {
                    let last = LAST.lock().ok()?;
                    let (at, v) = last.get(i)?.as_ref()?;
                    (at.elapsed() < LATE_TTL && v.drive_type == kind).then(|| v.clone())
                })
                .unwrap_or_else(|| VolumeInfo {
                    letter: letter.to_string(),
                    drive_type: kind.into(),
                    is_system: letter.to_string().eq_ignore_ascii_case(sys),
                    bitlocker: "unknown".into(),
                    state: "noMedia".into(),
                    ..Default::default()
                })
        })
        .collect()
}

/// A mapped drive whose share is remembered but not connected (asking it more would block).
fn is_disconnected_share(letter: char) -> bool {
    #[link(name = "mpr")]
    extern "system" {
        fn WNetGetConnectionW(local: *const u16, remote: *mut u16, len: *mut u32) -> u32;
    }
    let local = wide(&format!("{letter}:"));
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    unsafe { WNetGetConnectionW(local.as_ptr(), buf.as_mut_ptr(), &mut len) == 1201 }
}

/// GetVolumeInformationW failure → state.
pub(crate) fn failure_state(err: u32, kind: &str) -> &'static str {
    match err {
        21 | 1112 => "noMedia",
        1005 | 1785 => "raw",
        e if e & 0xFFFF_0000 == 0x8031_0000 => "locked", // FVE_E_* (BitLocker)
        5 if kind == "fixed" || kind == "removable" => "locked",
        _ => "noMedia",
    }
}

fn query_volume(letter: char, kind: &'static str, sys: &str, elevated: bool) -> VolumeInfo {
    let mut v = VolumeInfo {
        letter: letter.to_string(),
        drive_type: kind.into(),
        is_system: letter.to_string().eq_ignore_ascii_case(sys),
        bitlocker: "none".into(),
        state: "ready".into(),
        ..Default::default()
    };
    if kind == "network" && is_disconnected_share(letter) {
        v.state = "noMedia".into();
        return v;
    }
    let root = wide(&format!("{letter}:\\"));
    let mut name = [0u16; 261];
    let mut fs = [0u16; 261];
    let ok = unsafe {
        GetVolumeInformationW(root.as_ptr(), name.as_mut_ptr(), name.len() as u32, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), fs.as_mut_ptr(), fs.len() as u32)
    } != 0;
    let err = if ok { 0 } else { unsafe { GetLastError() } };
    if ok {
        v.label = from_wide(&name);
        v.fs = from_wide(&fs);
        v.state = if v.fs.eq_ignore_ascii_case("RAW") { "raw" } else { "ready" }.into();
        let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
        if unsafe { GetDiskFreeSpaceExW(root.as_ptr(), &mut avail, &mut total, &mut free) } != 0 {
            v.size = total;
            v.free = free;
        }
    } else {
        v.state = failure_state(err, kind).into();
    }
    if kind == "network" {
        return v;
    }

    if v.state != "noMedia" {
        if let Some(h) = win::open_query(&format!(r"\\.\{letter}:")) {
            let ext = win::volume_extents_of(&h);
            if let Some(first) = ext.first() {
                v.disk_index = Some(first.disk);
                v.offset = Some(first.offset);
                if v.size == 0 {
                    v.size = ext.iter().map(|e| e.len).sum();
                }
            }
            v.ssd = win::seek_penalty(&h).map(|p| !p);
            if v.ssd == Some(true) {
                v.trim_enabled = win::trim_descriptor(&h).map(|t| t && !trim_disabled_globally(&v.fs));
            }
        }
    }

    v.bitlocker = if v.state == "locked" {
        "locked".into()
    } else if v.state == "noMedia" || kind == "cdrom" {
        "none".into()
    } else {
        match bitlocker_shell(letter).and_then(bitlocker_from_shell) {
            Some(b) => b.into(),
            None if elevated => bitlocker_raw(letter, &v).into(),
            None => "unknown".into(),
        }
    };
    v
}

/// System.Volume.BitLockerProtection → our words. 1 on, 2 off, 3 encrypting, 4 decrypting,
/// 5 suspended, 6 on + locked, 8 waiting for activation (encrypted with a clear key).
pub(crate) fn bitlocker_from_shell(v: i64) -> Option<&'static str> {
    Some(match v {
        2 => "none",
        6 => "locked",
        1 | 3 | 4 | 5 | 7 | 8 => "unlocked",
        0 => "none",
        _ => return None,
    })
}

/// Elevated fallback: the volume's own first sector shows "-FVE-FS-" only while locked; the raw
/// partition bytes on the disk show it whenever the volume is BitLocker-encrypted.
fn bitlocker_raw(letter: char, v: &VolumeInfo) -> &'static str {
    if let Ok(src) = win::open_volume(&letter.to_string()) {
        if win::bitlocker_locked(src.as_ref()) {
            return "locked";
        }
    }
    if let (Some(d), Some(off)) = (v.disk_index, v.offset) {
        if let Ok(src) = win::open_disk(&d.to_string()) {
            let mut b = [0u8; 512];
            if matches!(src.read_at(off, &mut b), Ok(512)) {
                return if win::is_fve_boot_sector(&b) { "unlocked" } else { "none" };
            }
        }
    }
    "unknown"
}

/// The Shell's System.Volume.BitLockerProtection for "X:\" (readable without administrator rights).
/// PKEY {2D15A9A1-A556-4189-91AD-027458F11A07} 1717 (resolved with PSGetPropertyKeyFromName).
fn bitlocker_shell(letter: char) -> Option<i64> {
    use com::{method, Unk};
    use windows_sys::core::{GUID, HRESULT};
    #[link(name = "shell32")]
    extern "system" {
        fn SHGetPropertyStoreFromParsingName(path: *const u16, pbc: *mut std::ffi::c_void, flags: i32, riid: *const GUID, ppv: *mut *mut std::ffi::c_void) -> HRESULT;
    }
    #[link(name = "ole32")]
    extern "system" {
        fn PropVariantClear(pv: *mut [u64; 3]) -> HRESULT;
    }
    #[repr(C)]
    struct PropertyKey {
        fmtid: GUID,
        pid: u32,
    }
    const IID_IPROPERTYSTORE: GUID = GUID::from_u128(0x886d8eeb_8cf2_4446_8d02_cdba1dbdcf99);
    let key = PropertyKey { fmtid: GUID::from_u128(0x2d15a9a1_a556_4189_91ad_027458f11a07), pid: 1717 };
    com::in_mta(|| {
        let path = wide(&format!("{letter}:\\"));
        let mut p = std::ptr::null_mut();
        let hr = unsafe { SHGetPropertyStoreFromParsingName(path.as_ptr(), std::ptr::null_mut(), 0, &IID_IPROPERTYSTORE, &mut p) };
        if hr < 0 || p.is_null() {
            return None;
        }
        let store = Unk(p);
        let mut pv = [0u64; 3];
        type GetValue = unsafe extern "system" fn(*mut std::ffi::c_void, *const PropertyKey, *mut [u64; 3]) -> HRESULT;
        let hr = unsafe { method::<GetValue>(store.0, 5)(store.0, &key, &mut pv) };
        if hr < 0 {
            return None;
        }
        let vt = (pv[0] & 0xFFFF) as u16;
        let val = pv[1];
        let r = match vt {
            2 => Some(val as u16 as i16 as i64), // VT_I2
            3 | 22 => Some(val as u32 as i32 as i64),
            18 => Some(val as u16 as i64),
            19 | 23 => Some(val as u32 as i64),
            _ => None,
        };
        unsafe { PropVariantClear(&mut pv) };
        r
    })
}

/// `fsutil behavior set DisableDeleteNotify 1` turns TRIM off system-wide (NTFS / ReFS values).
fn trim_disabled_globally(fs: &str) -> bool {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD};
    let value = if fs.eq_ignore_ascii_case("ReFS") { "RefsDisableDeleteNotification" } else { "DisableDeleteNotification" };
    let key = wide(r"SYSTEM\CurrentControlSet\Control\FileSystem");
    let name = wide(value);
    let mut data = 0u32;
    let mut len = 4u32;
    let r = unsafe { RegGetValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), name.as_ptr(), RRF_RT_REG_DWORD, std::ptr::null_mut(), &mut data as *mut u32 as *mut _, &mut len) };
    r == 0 && data == 1
}

// -------------------------------------------------------------------------------------- disks

pub(crate) fn bus_name(code: u32) -> &'static str {
    match code {
        17 => "NVMe",
        3 | 11 => "SATA",
        7 => "USB",
        12 | 13 => "SD",
        10 => "SAS",
        8 => "RAID",
        14 | 15 | 16 => "Virtual",
        _ => "Other",
    }
}

/// One physical disk through a no-access handle. (info, layout read).
fn query_disk(n: u32) -> Option<(DiskInfo, bool)> {
    let h = win::open_query(&format!(r"\\.\PhysicalDrive{n}"))?;
    let (size, bps) = win::geometry(&h)?;
    if size == 0 {
        return None; // card reader without a card
    }
    let desc = win::device_descriptor(&h).unwrap_or_default();
    let ssd = win::seek_penalty(&h).map(|p| !p);
    let mut d = DiskInfo {
        index: n,
        model: Some(desc.model()).filter(|m| !m.is_empty()).unwrap_or_else(|| format!("Disk {n}")),
        // NVMe serials come back as "0000_0000_…_5501." (Windows appends the period).
        serial: desc.serial.trim().trim_end_matches('.').to_string(),
        size,
        sector_size: win::logical_sector_size(&h).unwrap_or(if bps >= 512 { bps } else { 512 }),
        bus: bus_name(desc.bus_type).into(),
        media: match ssd {
            Some(true) => "SSD",
            Some(false) => "HDD",
            None => "Unknown",
        }
        .into(),
        removable: desc.removable,
        trim_enabled: if ssd == Some(true) { win::trim_descriptor(&h).map(|t| t && !trim_disabled_globally("NTFS")) } else { None },
        partition_style: "Unknown".into(),
        ..Default::default()
    };
    let ok = match drive_layout(&h) {
        Some((style, parts)) => {
            d.partition_style = style;
            d.partitions = parts;
            true
        }
        None => false,
    };
    Some((d, ok))
}

fn drive_layout(h: &Handle) -> Option<(String, Vec<PartitionInfo>)> {
    let mut size = 48 + 144 * 32;
    loop {
        let mut b = vec![0u8; size];
        match win::ioctl(h, win::IOCTL_DISK_GET_DRIVE_LAYOUT_EX, &[], &mut b) {
            Ok(n) => return Some(parse_layout(&b[..n])),
            Err(122) | Err(234) if size < 48 + 144 * 1024 => size *= 4, // buffer too small
            Err(_) => return None,
        }
    }
}

/// DRIVE_LAYOUT_INFORMATION_EX → (style, partitions sorted by offset).
pub(crate) fn parse_layout(b: &[u8]) -> (String, Vec<PartitionInfo>) {
    use super::win::{le_u32, le_u64};
    let style = match le_u32(b, 0) {
        0 => "MBR",
        1 => "GPT",
        2 => "RAW",
        _ => "Unknown",
    };
    let count = le_u32(b, 4) as usize;
    let mut out = Vec::new();
    for i in 0..count {
        let o = 48 + i * 144;
        if o + 144 > b.len() {
            break;
        }
        let e = &b[o..o + 144];
        let (offset, len, number) = (le_u64(e, 8), le_u64(e, 16), le_u32(e, 24));
        if len == 0 {
            continue;
        }
        let (type_name, label) = match le_u32(e, 0) {
            0 => {
                if e[32] == 0 {
                    continue;
                }
                (super::image::partition_type_name(None, Some(e[32])), None)
            }
            1 => {
                let g = guid_text(&e[32..48]);
                let name: Vec<u16> = e[72..144].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
                let name = String::from_utf16_lossy(&name).trim().to_string();
                let generic = name.is_empty() || name.to_ascii_lowercase().ends_with(" partition");
                (super::image::partition_type_name(Some(&g), None), (!generic).then_some(name))
            }
            _ => ("Unknown".to_string(), None),
        };
        out.push(PartitionInfo { number, offset, size: len, type_name, letter: None, fs: None, label });
    }
    out.sort_by_key(|p| p.offset);
    (style.into(), out)
}

fn guid_text(b: &[u8]) -> String {
    use super::win::le_u32;
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        le_u32(b, 0),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

/// MSFT_PhysicalDisk.HealthStatus by disk number. None = WMI unavailable.
fn disk_health() -> Option<HashMap<u32, String>> {
    let rows = wmi::query(STORAGE_NS, "SELECT DeviceId, HealthStatus FROM MSFT_PhysicalDisk", &["DeviceId", "HealthStatus"]).ok()?;
    Some(
        rows.iter()
            .filter_map(|r| {
                let n: u32 = r.get("DeviceId").string()?.trim().parse().ok()?;
                Some((n, health_word(r.get("HealthStatus").u32())?.to_string()))
            })
            .collect(),
    )
}

pub(crate) fn health_word(code: Option<u32>) -> Option<&'static str> {
    Some(match code? {
        0 => "Healthy",
        1 => "Warning",
        2 => "Unhealthy",
        _ => return None,
    })
}

/// MSFT_Disk + MSFT_Partition fallback for the partition layout: disk → (style, partitions).
fn wmi_partitions() -> Result<HashMap<u32, (String, Vec<PartitionInfo>)>, i32> {
    let disks = wmi::query(STORAGE_NS, "SELECT Number, PartitionStyle FROM MSFT_Disk", &["Number", "PartitionStyle"])?;
    let parts = wmi::query(
        STORAGE_NS,
        "SELECT DiskNumber, PartitionNumber, Offset, Size, GptType, MbrType FROM MSFT_Partition",
        &["DiskNumber", "PartitionNumber", "Offset", "Size", "GptType", "MbrType"],
    )?;
    let mut out: HashMap<u32, (String, Vec<PartitionInfo>)> = HashMap::new();
    for d in &disks {
        let Some(n) = d.get("Number").u32() else { continue };
        let style = match d.get("PartitionStyle").u32() {
            Some(1) => "MBR",
            Some(2) => "GPT",
            Some(0) => "RAW",
            _ => "Unknown",
        };
        out.insert(n, (style.into(), Vec::new()));
    }
    for p in &parts {
        let Some(n) = p.get("DiskNumber").u32() else { continue };
        let gpt = p.get("GptType").string().filter(|s| !s.trim().is_empty());
        let mbr = p.get("MbrType").u32().filter(|&t| t != 0).map(|t| t as u8);
        if let Some((_, list)) = out.get_mut(&n) {
            list.push(PartitionInfo {
                number: p.get("PartitionNumber").u32().unwrap_or(0),
                offset: p.get("Offset").u64().unwrap_or(0),
                size: p.get("Size").u64().unwrap_or(0),
                type_name: super::image::partition_type_name(gpt.as_deref(), mbr),
                ..Default::default()
            });
        }
    }
    for (_, list) in out.values_mut() {
        list.sort_by_key(|p| p.offset);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------- snapshots

fn shadow_copies() -> Vec<SnapshotInfo> {
    let Ok(rows) = wmi::query(r"ROOT\CIMV2", "SELECT ID, DeviceObject, VolumeName, InstallDate FROM Win32_ShadowCopy", &["ID", "DeviceObject", "VolumeName", "InstallDate"]) else {
        return Vec::new();
    };
    let mut out: Vec<SnapshotInfo> = rows
        .iter()
        .filter_map(|r| {
            Some(SnapshotInfo {
                id: r.get("ID").string()?,
                device_path: r.get("DeviceObject").string()?,
                volume: r.get("VolumeName").string().and_then(|v| letter_of_volume(&v)).unwrap_or_default(),
                created: r.get("InstallDate").string().and_then(|s| cim_datetime_ms(&s)).unwrap_or(0),
            })
        })
        .collect();
    out.sort_by(|a, b| b.created.cmp(&a.created));
    out
}

/// "\\?\Volume{guid}\" → "C" (first mount point that is a drive letter).
pub(crate) fn letter_of_volume(volume_name: &str) -> Option<String> {
    let mut name = volume_name.to_string();
    if !name.ends_with('\\') {
        name.push('\\');
    }
    let w = wide(&name);
    let mut buf = vec![0u16; 1024];
    let mut ret = 0u32;
    if unsafe { GetVolumePathNamesForVolumeNameW(w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32, &mut ret) } == 0 {
        return None;
    }
    buf.split(|&c| c == 0).map(String::from_utf16_lossy).find(|s| s.len() == 3 && s.ends_with(":\\")).map(|s| s[..1].to_ascii_uppercase())
}

/// CIM DATETIME "yyyymmddHHMMSS.mmmmmmsUUU" (local time, UUU = minutes east of UTC) → Unix ms.
pub(crate) fn cim_datetime_ms(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() < 25 || !s.is_ascii() {
        return None;
    }
    let n = |a: usize, b: usize| s[a..b].parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (n(0, 4)?, n(4, 6)?, n(6, 8)?, n(8, 10)?, n(10, 12)?, n(12, 14)?);
    let micros = n(15, 21).unwrap_or(0);
    let sign = if &s[21..22] == "-" { -1 } else { 1 };
    let off = n(22, 25)? * sign;
    // Days from civil (Howard Hinnant).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400 + h * 3600 + mi * 60 + se - off * 60) * 1000) + micros / 1000)
}

// ======================================================================= COM / WMI (raw vtables)

/// Minimal COM plumbing (windows-sys has no interface wrappers). Adapted from Platter.
pub(crate) mod com {
    use std::ffi::c_void;
    use windows_sys::core::{BSTR, GUID, HRESULT};
    use windows_sys::Win32::Foundation::{SysAllocString, SysFreeString};
    use windows_sys::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CoSetProxyBlanket, CoUninitialize};

    #[link(name = "oleaut32")]
    extern "system" {
        fn VariantClear(v: *mut c_void) -> HRESULT;
    }

    /// Run `f` with this thread in the multithreaded apartment. Only on threads we created.
    pub fn in_mta<R>(f: impl FnOnce() -> R) -> R {
        let hr = unsafe { CoInitializeEx(std::ptr::null(), 0) };
        let r = f();
        if hr >= 0 {
            unsafe { CoUninitialize() };
        }
        r
    }

    /// Run `f` on a fresh MTA thread (pooled threads may have another apartment).
    pub fn on_mta_thread<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> Option<R> {
        std::thread::Builder::new().name("maxrec-com".into()).spawn(move || in_mta(f)).ok()?.join().ok()
    }

    /// # Safety
    /// `obj` must be a live interface pointer whose vtable has a method of type `F` at `idx`.
    pub unsafe fn method<F: Copy>(obj: *mut c_void, idx: usize) -> F {
        let vtbl = *(obj as *const *const *const c_void);
        std::mem::transmute_copy(&*vtbl.add(idx))
    }

    /// An owned interface pointer, released on drop.
    pub struct Unk(pub *mut c_void);
    impl Drop for Unk {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { method::<unsafe extern "system" fn(*mut c_void) -> u32>(self.0, 2)(self.0) };
            }
        }
    }

    pub fn create(clsid: &GUID, iid: &GUID) -> Result<Unk, HRESULT> {
        let mut p = std::ptr::null_mut();
        let hr = unsafe { CoCreateInstance(clsid, std::ptr::null_mut(), 1, iid, &mut p) };
        if hr < 0 || p.is_null() {
            return Err(hr);
        }
        Ok(Unk(p))
    }

    /// Calls through this proxy impersonate the caller (WMI refuses the default "identify" level).
    pub fn set_blanket(p: &Unk) {
        unsafe { CoSetProxyBlanket(p.0, 10, 0, std::ptr::null(), 3, 3, std::ptr::null(), 0) };
    }

    pub struct Bstr(pub BSTR);
    impl Bstr {
        pub fn new(s: &str) -> Bstr {
            Bstr(unsafe { SysAllocString(crate::util::wide(s).as_ptr()) })
        }
    }
    impl Drop for Bstr {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { SysFreeString(self.0) };
            }
        }
    }

    /// VARIANT as an out-parameter (24 bytes on x64), cleared on drop.
    #[repr(C)]
    pub struct Variant {
        vt: u16,
        _reserved: [u16; 3],
        data: [u64; 2],
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum Val {
        Null,
        Int(i64),
        Float(f64),
        Bool(bool),
        Str(String),
        Ints(Vec<i64>),
    }

    #[repr(C)]
    struct SafeArray {
        dims: u16,
        features: u16,
        element_size: u32,
        locks: u32,
        data: *mut c_void,
        count: u32,
        lower_bound: i32,
    }

    unsafe fn bstr_string(b: *const u16) -> String {
        if b.is_null() {
            return String::new();
        }
        let len = *(b as *const u32).offset(-1) as usize / 2;
        String::from_utf16_lossy(std::slice::from_raw_parts(b, len))
    }

    impl Default for Variant {
        fn default() -> Self {
            Variant { vt: 0, _reserved: [0; 3], data: [0; 2] }
        }
    }

    impl Variant {
        pub fn value(&self) -> Val {
            let d = self.data[0];
            unsafe {
                match self.vt {
                    0 | 1 => Val::Null,
                    16 => Val::Int(d as u8 as i8 as i64),
                    17 => Val::Int(d as u8 as i64),
                    2 => Val::Int(d as u16 as i16 as i64),
                    18 => Val::Int(d as u16 as i64),
                    3 | 22 => Val::Int(d as u32 as i32 as i64),
                    19 | 23 => Val::Int(d as u32 as i64),
                    20 | 21 => Val::Int(d as i64),
                    4 => Val::Float(f32::from_bits(d as u32) as f64),
                    5 => Val::Float(f64::from_bits(d)),
                    11 => Val::Bool(d as u16 != 0),
                    8 => Val::Str(bstr_string(d as usize as *const u16)),
                    vt if vt & 0x2000 != 0 => {
                        let sa = d as usize as *const SafeArray;
                        if sa.is_null() || (*sa).dims != 1 || (*sa).data.is_null() {
                            return Val::Ints(vec![]);
                        }
                        let (n, p) = ((*sa).count as usize, (*sa).data as *const u8);
                        let elem = vt & !0x2000;
                        let read = |i: usize| -> Option<i64> {
                            Some(match elem {
                                16 => *(p.add(i) as *const i8) as i64,
                                17 => *p.add(i) as i64,
                                2 => (p.add(i * 2) as *const i16).read_unaligned() as i64,
                                18 => (p.add(i * 2) as *const u16).read_unaligned() as i64,
                                3 | 22 => (p.add(i * 4) as *const i32).read_unaligned() as i64,
                                19 | 23 => (p.add(i * 4) as *const u32).read_unaligned() as i64,
                                _ => return None,
                            })
                        };
                        Val::Ints((0..n).filter_map(read).collect())
                    }
                    _ => Val::Null,
                }
            }
        }
    }

    impl Drop for Variant {
        fn drop(&mut self) {
            unsafe { VariantClear(self as *mut Variant as *mut c_void) };
        }
    }

    impl Val {
        pub fn int(&self) -> Option<i64> {
            match self {
                Val::Int(i) => Some(*i),
                Val::Float(f) => Some(*f as i64),
                // WMI hands 64-bit integers over as strings.
                Val::Str(s) => s.trim().parse().ok(),
                Val::Bool(b) => Some(*b as i64),
                _ => None,
            }
        }
        pub fn u64(&self) -> Option<u64> {
            match self {
                Val::Str(s) => s.trim().parse().ok(),
                _ => self.int().map(|i| i as u64),
            }
        }
        pub fn u32(&self) -> Option<u32> {
            self.int().map(|i| i as u32)
        }
        #[allow(dead_code)]
        pub fn f64(&self) -> Option<f64> {
            match self {
                Val::Float(f) => Some(*f),
                Val::Str(s) => s.trim().parse().ok(),
                _ => self.int().map(|i| i as f64),
            }
        }
        pub fn string(&self) -> Option<String> {
            match self {
                Val::Str(s) => Some(s.clone()),
                Val::Int(i) => Some(i.to_string()),
                _ => None,
            }
        }
        pub fn bytes(&self) -> Option<Vec<u8>> {
            match self {
                Val::Ints(v) => Some(v.iter().map(|&x| x as u8).collect()),
                _ => None,
            }
        }
    }
}

/// In-process WMI queries through raw COM.
pub(crate) mod wmi {
    use super::com::{self, Bstr, Unk, Val, Variant};
    use std::collections::BTreeMap;
    use std::ffi::c_void;
    use windows_sys::core::{GUID, HRESULT};

    const CLSID_WBEM_LOCATOR: GUID = GUID::from_u128(0x4590f811_1d3a_11d0_891f_00aa004b2e24);
    const IID_IWBEM_LOCATOR: GUID = GUID::from_u128(0xdc12a687_737f_11cf_884d_00aa004b2e24);

    type ConnectServer = unsafe extern "system" fn(*mut c_void, *const u16, *const u16, *const u16, *const u16, i32, *const u16, *mut c_void, *mut *mut c_void) -> HRESULT;
    type ExecQuery = unsafe extern "system" fn(*mut c_void, *const u16, *const u16, i32, *mut c_void, *mut *mut c_void) -> HRESULT;
    type EnumNext = unsafe extern "system" fn(*mut c_void, i32, u32, *mut *mut c_void, *mut u32) -> HRESULT;
    type ClassGet = unsafe extern "system" fn(*mut c_void, *const u16, i32, *mut Variant, *mut i32, *mut i32) -> HRESULT;

    /// One result object's requested properties.
    #[derive(Debug, Clone, Default)]
    pub struct Row(pub BTreeMap<String, Val>);
    impl Row {
        pub fn get(&self, name: &str) -> Val {
            self.0.get(name).cloned().unwrap_or(Val::Null)
        }
    }

    pub struct Wmi(Unk);

    impl Wmi {
        /// Must run on an MTA thread.
        pub fn connect(namespace: &str) -> Result<Wmi, HRESULT> {
            let loc = com::create(&CLSID_WBEM_LOCATOR, &IID_IWBEM_LOCATOR)?;
            let ns = Bstr::new(namespace);
            let mut svc = std::ptr::null_mut();
            let z = std::ptr::null();
            let hr = unsafe { com::method::<ConnectServer>(loc.0, 3)(loc.0, ns.0, z, z, z, 0, z, std::ptr::null_mut(), &mut svc) };
            if hr < 0 || svc.is_null() {
                return Err(hr);
            }
            let svc = Unk(svc);
            com::set_blanket(&svc);
            Ok(Wmi(svc))
        }

        /// Run a WQL query; read `fields` of every object.
        pub fn rows(&self, wql: &str, fields: &[&str]) -> Result<Vec<Row>, HRESULT> {
            let (lang, q) = (Bstr::new("WQL"), Bstr::new(wql));
            let mut en = std::ptr::null_mut();
            let svc = self.0 .0;
            let hr = unsafe { com::method::<ExecQuery>(svc, 20)(svc, lang.0, q.0, 0x30, std::ptr::null_mut(), &mut en) };
            if hr < 0 || en.is_null() {
                return Err(hr);
            }
            let en = Unk(en);
            com::set_blanket(&en);
            let mut out = Vec::new();
            loop {
                let mut batch = [std::ptr::null_mut::<c_void>(); 32];
                let mut n = 0u32;
                let hr = unsafe { com::method::<EnumNext>(en.0, 4)(en.0, -1, batch.len() as u32, batch.as_mut_ptr(), &mut n) };
                for &p in &batch[..(n as usize).min(batch.len())] {
                    let obj = Unk(p);
                    let mut row = Row::default();
                    for f in fields {
                        let w = crate::util::wide(f);
                        let mut v = Variant::default();
                        let r = unsafe { com::method::<ClassGet>(obj.0, 4)(obj.0, w.as_ptr(), 0, &mut v, std::ptr::null_mut(), std::ptr::null_mut()) };
                        row.0.insert(f.to_string(), if r < 0 { Val::Null } else { v.value() });
                    }
                    out.push(row);
                }
                if hr < 0 {
                    return Err(hr);
                }
                if hr != 0 || n == 0 {
                    return Ok(out); // WBEM_S_FALSE: end of results
                }
            }
        }
    }

    /// Connect + query on a fresh MTA thread.
    pub fn query(namespace: &str, wql: &str, fields: &[&str]) -> Result<Vec<Row>, HRESULT> {
        let (ns, q) = (namespace.to_string(), wql.to_string());
        let fields: Vec<String> = fields.iter().map(|s| s.to_string()).collect();
        com::on_mta_thread(move || {
            let f: Vec<&str> = fields.iter().map(|s| s.as_str()).collect();
            Wmi::connect(&ns)?.rows(&q, &f)
        })
        .unwrap_or(Err(-1))
    }

    /// Several queries on one connection, on a fresh MTA thread.
    pub fn with<R: Send + 'static>(namespace: &str, f: impl FnOnce(&Wmi) -> R + Send + 'static) -> Option<R> {
        let ns = namespace.to_string();
        com::on_mta_thread(move || Wmi::connect(&ns).ok().map(|w| f(&w))).flatten()
    }
}

// ========================================================================================= tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_states() {
        assert_eq!(failure_state(21, "removable"), "noMedia");
        assert_eq!(failure_state(1112, "cdrom"), "noMedia");
        assert_eq!(failure_state(1005, "fixed"), "raw");
        assert_eq!(failure_state(0x8031_0000, "fixed"), "locked");
        assert_eq!(failure_state(5, "removable"), "locked");
        assert_eq!(failure_state(5, "network"), "noMedia");
    }

    #[test]
    fn shell_bitlocker_values() {
        assert_eq!(bitlocker_from_shell(1), Some("unlocked"));
        assert_eq!(bitlocker_from_shell(2), Some("none"));
        assert_eq!(bitlocker_from_shell(6), Some("locked"));
        assert_eq!(bitlocker_from_shell(99), None);
    }

    #[test]
    fn cim_datetimes() {
        assert_eq!(cim_datetime_ms("19700101000000.000000+000"), Some(0));
        // 2024-11-24 10:30:00.250 at UTC+1 = 09:30:00.250 UTC.
        assert_eq!(cim_datetime_ms("20241124103000.250000+060"), Some(1_732_440_600_250));
        assert_eq!(cim_datetime_ms("2024"), None);
    }

    #[test]
    fn layout_parsing() {
        let mut b = vec![0u8; 48 + 144 * 3];
        b[0] = 1; // GPT
        b[4] = 3;
        let mut put = |i: usize, off: u64, len: u64, n: u32, guid: u128, name: &str| {
            let e = &mut b[48 + i * 144..48 + (i + 1) * 144];
            e[0] = 1;
            e[8..16].copy_from_slice(&off.to_le_bytes());
            e[16..24].copy_from_slice(&len.to_le_bytes());
            e[24..28].copy_from_slice(&n.to_le_bytes());
            e[32..48].copy_from_slice(&super::super::image::guid_bytes(guid));
            for (k, c) in name.encode_utf16().enumerate() {
                e[72 + k * 2..74 + k * 2].copy_from_slice(&c.to_le_bytes());
            }
        };
        put(0, 1 << 30, 500 << 30, 3, 0xEBD0A0A2_B9E5_4433_87C0_68B6B72699C7, "Basic data partition");
        put(1, 1 << 20, 100 << 20, 1, 0xC12A7328_F81F_11D2_BA4B_00A0C93EC93B, "EFI system partition");
        put(2, 600 << 30, 1 << 30, 4, 0xDE94BBA4_06D1_4D40_A16A_BFD50179D6AC, "Tools");
        let (style, p) = parse_layout(&b);
        assert_eq!(style, "GPT");
        let got: Vec<(u32, &str, Option<&str>)> = p.iter().map(|p| (p.number, p.type_name.as_str(), p.label.as_deref())).collect();
        assert_eq!(got, vec![(1, "EFI system", None), (3, "Basic data", None), (4, "Recovery", Some("Tools"))]);

        // MBR: empty slots skipped.
        let mut b = vec![0u8; 48 + 144 * 4];
        b[4] = 4;
        let e = &mut b[48..48 + 144];
        e[8..16].copy_from_slice(&(1u64 << 20).to_le_bytes());
        e[16..24].copy_from_slice(&(64u64 << 20).to_le_bytes());
        e[24] = 1;
        e[32] = 0x07;
        let (style, p) = parse_layout(&b);
        assert_eq!((style.as_str(), p.len(), p[0].type_name.as_str()), ("MBR", 1, "Basic data"));
    }

    /// `cargo test device::list::tests::real_machine -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn real_machine() {
        let t = Instant::now();
        let first = list();
        let cold = t.elapsed();
        let t = Instant::now();
        let again = list();
        let warm = t.elapsed();
        println!("{}", serde_json::to_string_pretty(&again).unwrap());
        println!("list_devices: cold {} ms, warm {} ms", cold.as_millis(), warm.as_millis());
        let sys = system_drive_letter();
        let c = first.volumes.iter().find(|v| v.letter == sys).expect("system volume");
        assert!(c.is_system && c.state == "ready" && c.size > 0 && c.disk_index.is_some(), "{c:?}");
        assert!(first.disks.iter().any(|d| d.is_system && d.partitions.iter().any(|p| p.letter.as_deref() == Some(sys.as_str()))));
        assert_eq!(first.snapshots_need_admin, !first.elevated);
    }
}

