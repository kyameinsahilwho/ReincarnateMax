//! Raw, read-only handles on volumes (\\.\C:), physical disks (\\.\PhysicalDriveN) and shadow
//! copies. OWNER: device agent.
//!
//! Every handle here is opened with `GENERIC_READ` (or no data access at all, for queries) and
//! shared read|write so Windows and other programs keep working. The only control code that is not a
//! pure query is `FSCTL_ALLOW_EXTENDED_DASD_IO`, which changes nothing on disk: it lets a volume handle
//! read the sectors past the end of the file system (e.g. the NTFS backup boot sector).

use super::source::{BlockSource, Source};
use crate::util::{from_wide, wide};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetVolumeInformationW, GetVolumeNameForVolumeMountPointW, GetVolumePathNameW, ReadFile, FILE_FLAG_NO_BUFFERING,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::{DeviceIoControl, OVERLAPPED};

/// The sentence for every "access denied" on a raw open (CONTRACT.md).
pub const ADMIN_NEEDED: &str = "Windows only lets administrators read drives directly. Restart MAX as administrator.";
const GONE: &str = "That drive isn't connected anymore.";
const NOT_READY: &str = "The drive isn't ready. Insert the card or reconnect the drive.";

pub(crate) const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
pub(crate) const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405C;
pub(crate) const IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: u32 = 0x0007_00A0;
pub(crate) const IOCTL_DISK_GET_DRIVE_LAYOUT_EX: u32 = 0x0007_0050;
pub(crate) const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x0056_0000;
/// Read-only in effect: allows reads past the file system's end on a volume handle.
const FSCTL_ALLOW_EXTENDED_DASD_IO: u32 = 0x0009_0083;

pub(crate) const GENERIC_READ: u32 = 0x8000_0000;
pub(crate) const FILE_READ_ATTRIBUTES: u32 = 0x80;
pub(crate) const SYNCHRONIZE: u32 = 0x0010_0000;

/// Largest single ReadFile.
const MAX_IO: usize = 8 << 20;
/// Alignment of the bounce buffer (covers every sector size and DMA alignment mask in practice).
const ALIGN: usize = 4096;

// ------------------------------------------------------------------------------------ handles

/// An owned Win32 handle, closed on drop. Reads through it are positional, so it can be shared.
pub(crate) struct Handle(pub HANDLE);
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// `CreateFileW(path, access, share read|write, OPEN_EXISTING, flags)`. `access` is only ever
/// `GENERIC_READ`, `FILE_READ_ATTRIBUTES|SYNCHRONIZE` or 0. Err = Win32 error code.
pub(crate) fn open_device(path: &str, access: u32, flags: u32) -> Result<Handle, u32> {
    debug_assert!(access & !(GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE) == 0, "read-only access only");
    let p = wide(path);
    let h = unsafe { CreateFileW(p.as_ptr(), access, FILE_SHARE_READ | FILE_SHARE_WRITE, std::ptr::null(), OPEN_EXISTING, flags, std::ptr::null_mut()) };
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        return Err(unsafe { GetLastError() });
    }
    Ok(Handle(h))
}

/// A query handle (no data access): works without administrator rights for storage/volume queries.
pub(crate) fn open_query(path: &str) -> Option<Handle> {
    open_device(path, FILE_READ_ATTRIBUTES | SYNCHRONIZE, 0).or_else(|_| open_device(path, 0, 0)).ok()
}

/// DeviceIoControl with byte buffers. Ok(bytes returned) or Err(Win32 error).
pub(crate) fn ioctl(h: &Handle, code: u32, input: &[u8], out: &mut [u8]) -> Result<usize, u32> {
    let mut ret = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            h.0,
            code,
            if input.is_empty() { std::ptr::null() } else { input.as_ptr() as *const c_void },
            input.len() as u32,
            if out.is_empty() { std::ptr::null_mut() } else { out.as_mut_ptr() as *mut c_void },
            out.len() as u32,
            &mut ret,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok(ret as usize)
}

/// IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery. Some(bytes returned).
pub(crate) fn storage_query(h: &Handle, property_id: u32, out: &mut [u8]) -> Option<usize> {
    let mut q = [0u8; 12];
    q[0..4].copy_from_slice(&property_id.to_le_bytes());
    ioctl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, out).ok()
}

pub(crate) fn le_u32(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap())).unwrap_or(0)
}
pub(crate) fn le_u64(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap())).unwrap_or(0)
}

/// STORAGE_DEVICE_DESCRIPTOR fields.
#[derive(Default, Clone, Debug)]
pub(crate) struct DeviceDescriptor {
    pub vendor: String,
    pub product: String,
    pub serial: String,
    pub removable: bool,
    /// STORAGE_BUS_TYPE (17 NVMe, 11 SATA, 7 USB, …).
    pub bus_type: u32,
}

impl DeviceDescriptor {
    pub fn model(&self) -> String {
        let (v, p) = (self.vendor.trim(), self.product.trim());
        if v.is_empty() || p.to_ascii_lowercase().starts_with(&v.to_ascii_lowercase()) {
            p.to_string()
        } else if p.is_empty() {
            v.to_string()
        } else {
            format!("{v} {p}")
        }
    }
}

pub(crate) fn device_descriptor(h: &Handle) -> Option<DeviceDescriptor> {
    let mut buf = vec![0u8; 1024];
    let n = storage_query(h, 0, &mut buf)?;
    Some(parse_device_descriptor(&buf[..n.max(32).min(buf.len())]))
}

pub(crate) fn parse_device_descriptor(buf: &[u8]) -> DeviceDescriptor {
    let cstr = |o: usize| -> String {
        if o == 0 || o >= buf.len() {
            return String::new();
        }
        let end = buf[o..].iter().position(|&b| b == 0).map(|p| o + p).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[o..end]).trim().to_string()
    };
    DeviceDescriptor {
        removable: buf.get(10).copied().unwrap_or(0) != 0,
        vendor: cstr(le_u32(buf, 12) as usize),
        product: cstr(le_u32(buf, 16) as usize),
        serial: cstr(le_u32(buf, 24) as usize),
        bus_type: le_u32(buf, 28),
    }
}

/// Seek penalty: Some(true) = rotating disk, Some(false) = SSD.
pub(crate) fn seek_penalty(h: &Handle) -> Option<bool> {
    let mut b = [0u8; 12];
    storage_query(h, 7, &mut b)?;
    Some(b[8] != 0)
}

/// DEVICE_TRIM_DESCRIPTOR.TrimEnabled (PropertyId 8).
pub(crate) fn trim_descriptor(h: &Handle) -> Option<bool> {
    let mut b = [0u8; 12];
    storage_query(h, 8, &mut b)?;
    Some(b[8] != 0)
}

/// Logical bytes per sector (StorageAccessAlignmentProperty, then the drive geometry).
pub(crate) fn logical_sector_size(h: &Handle) -> Option<u32> {
    let mut b = [0u8; 28];
    if storage_query(h, 6, &mut b).is_some() {
        let s = le_u32(&b, 16);
        if valid_sector(s) {
            return Some(s);
        }
    }
    geometry(h).map(|g| g.1).filter(|&s| valid_sector(s))
}

fn valid_sector(s: u32) -> bool {
    (512..=65536).contains(&s) && s.is_power_of_two()
}

/// (disk size, bytes per sector) from IOCTL_DISK_GET_DRIVE_GEOMETRY_EX (works on a query handle).
pub(crate) fn geometry(h: &Handle) -> Option<(u64, u32)> {
    let mut b = [0u8; 256];
    let n = ioctl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, &[], &mut b).ok()?;
    if n < 32 {
        return None;
    }
    Some((le_u64(&b, 24), le_u32(&b, 20)))
}

/// IOCTL_DISK_GET_LENGTH_INFO (needs a read handle).
fn length_info(h: &Handle) -> Option<u64> {
    let mut b = [0u8; 8];
    ioctl(h, IOCTL_DISK_GET_LENGTH_INFO, &[], &mut b).ok()?;
    Some(u64::from_le_bytes(b))
}

/// One piece of a volume on a physical disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DiskExtent {
    pub disk: u32,
    pub offset: u64,
    pub len: u64,
}

/// IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS on an open volume handle (works with no data access).
pub(crate) fn volume_extents_of(h: &Handle) -> Vec<DiskExtent> {
    let mut b = vec![0u8; 8 + 24 * 32];
    let Ok(n) = ioctl(h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, &[], &mut b) else { return Vec::new() };
    parse_extents(&b[..n])
}

pub(crate) fn parse_extents(b: &[u8]) -> Vec<DiskExtent> {
    let count = le_u32(b, 0) as usize;
    (0..count)
        .filter_map(|i| {
            let o = 8 + i * 24;
            (o + 24 <= b.len()).then(|| DiskExtent { disk: le_u32(b, o), offset: le_u64(b, o + 8), len: le_u64(b, o + 16) })
        })
        .collect()
}

/// Extents of drive letter `letter` ("C").
pub(crate) fn letter_extents(letter: &str) -> Vec<DiskExtent> {
    open_query(&format!(r"\\.\{letter}:")).map(|h| volume_extents_of(&h)).unwrap_or_default()
}

/// The volume that holds `path` (which need not exist yet): (mount root like "D:\", volume GUID path
/// like "\\?\Volume{…}\").
pub(crate) fn volume_of_path(path: &str) -> Option<(String, Option<String>)> {
    let p = wide(path);
    let mut root = [0u16; 1024];
    if unsafe { GetVolumePathNameW(p.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
        return None;
    }
    let root_s = from_wide(&root);
    let mut guid = [0u16; 128];
    let r = wide(&root_s);
    let g = (unsafe { GetVolumeNameForVolumeMountPointW(r.as_ptr(), guid.as_mut_ptr(), guid.len() as u32) } != 0).then(|| from_wide(&guid));
    Some((root_s, g))
}

/// Physical disks under the volume that holds `path`. Empty = unknown (network share, RAM disk…).
/// Lexical only (does not follow links): for safety decisions use [`locate_path`].
pub(crate) fn disks_of_path(path: &str) -> Vec<u32> {
    let Some((root, guid)) = volume_of_path(path) else { return Vec::new() };
    let dev = match guid {
        Some(g) => g.trim_end_matches('\\').to_string(),
        None => match root.as_bytes() {
            [l, b':', ..] => format!(r"\\.\{}:", *l as char),
            _ => return Vec::new(),
        },
    };
    let mut d: Vec<u32> = open_query(&dev).map(|h| volume_extents_of(&h)).unwrap_or_default().iter().map(|e| e.disk).collect();
    d.sort_unstable();
    d.dedup();
    d
}

// ------------------------------------------------------------------ where a path really lives
//
// Shared by the recovery destination check (recover::dest) and imaging: a folder is judged by
// where its bytes would really land, after junctions, symlinks, subst and mapped drives, shares
// on this PC and virtual disks stored in a file. Read-only lookups only.

const VHD_UNRESOLVED: &str = "This drive is a virtual disk stored in a file, and MAX couldn't tell which drive holds that file. Pick a folder on another drive.";
const LOOPBACK_UNRESOLVED: &str = "This network folder is on this PC, and MAX couldn't tell which drive holds it. Pick the folder by its drive letter instead, like D:\\Recovered.";
const TOO_DEEP: &str = "This folder leads through too many links or virtual disks for MAX to check. Pick a folder on another drive.";
const DISK_UNRESOLVED: &str = "MAX couldn't tell what kind of disk holds this folder, so it might be a virtual disk stored on the drive you are recovering from. Pick a folder on another drive.";
const WSL_FOLDER: &str = "This folder is inside a Linux (WSL) system whose disk is a file on this PC, and MAX can't tell which drive holds it. Pick the folder by its drive letter instead, like D:\\Recovered.";
const BUS_VIRTUAL: u32 = 14;
const BUS_FILE_BACKED_VIRTUAL: u32 = 15;
const BUS_SPACES: u32 = 16;
const DRIVE_REMOTE: u32 = 4;
const VOLUME_NAME_DOS: u32 = 0;
const VOLUME_NAME_GUID: u32 = 1;
const FILE_SHARE_DELETE: u32 = 4;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x800;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(name: *const u16, file: HANDLE, flags: u32) -> HANDLE;
    fn GetProcAddress(module: HANDLE, name: *const u8) -> *const c_void;
    fn GetFinalPathNameByHandleW(h: HANDLE, buf: *mut u16, len: u32, flags: u32) -> u32;
    fn GetDriveTypeW(root: *const u16) -> u32;
}

/// Where a path's bytes would really be written.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct PathLocation {
    /// The real path ("D:\Docs\Recovered", "\\nas\share\x"); None when it couldn't be resolved.
    pub real_path: Option<String>,
    /// Mount root of the real path ("D:\", "\\nas\share\", "\\?\Volume{…}\"), for free space and
    /// the file-system name.
    pub root: Option<String>,
    /// `\\?\volume{…}\`, lowercase.
    pub volume: Option<String>,
    /// Physical disks that would receive the bytes, including the disks that hold the file of a
    /// virtual disk (VHD/VHDX). None = unknown.
    pub disks: Option<Vec<u32>>,
    /// `\\server\share` (lowercase) for a share on another computer.
    pub network_root: Option<String>,
    /// A sentence when the place can't be checked safely: refuse it.
    pub refuse: Option<String>,
}

fn refused(msg: &str) -> PathLocation {
    PathLocation { refuse: Some(msg.to_string()), ..Default::default() }
}

/// A function exported by a System32 DLL, loaded on first use (the DLL stays loaded).
fn system_fn(dll: &'static str, name: &'static [u8]) -> Option<*const c_void> {
    static FNS: OnceLock<Mutex<HashMap<(&'static str, &'static [u8]), usize>>> = OnceLock::new();
    let fns = FNS.get_or_init(Default::default);
    if let Some(&f) = fns.lock().unwrap_or_else(|e| e.into_inner()).get(&(dll, name)) {
        return (f != 0).then_some(f as *const c_void);
    }
    let w = wide(dll);
    let m = unsafe { LoadLibraryExW(w.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    let f = if m.is_null() { std::ptr::null() } else { unsafe { GetProcAddress(m, name.as_ptr()) } };
    fns.lock().unwrap_or_else(|e| e.into_inner()).insert((dll, name), f as usize);
    (!f.is_null()).then_some(f)
}

/// A NUL-terminated UTF-16 string at `p` (bounded).
unsafe fn wstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0usize;
    while n < 32768 && *p.add(n) != 0 {
        n += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
}

/// The `\\?\` form for long paths.
fn long_form(p: &str) -> String {
    if p.len() < 240 || p.starts_with(r"\\?\") {
        return p.to_string();
    }
    match p.strip_prefix(r"\\") {
        Some(rest) => format!(r"\\?\UNC\{rest}"),
        None => format!(r"\\?\{p}"),
    }
}

/// `\\?\C:\x` → `C:\x`, `\\?\UNC\s\x` → `\\s\x`; anything else unchanged.
pub(crate) fn plain_path(p: &str) -> String {
    if let Some(rest) = p.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    if let Some(rest) = p.strip_prefix(r"\\?\") {
        let b = rest.as_bytes();
        if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
            return rest.to_string();
        }
    }
    p.to_string()
}

fn join(base: &str, rest: &str) -> String {
    let rest = rest.trim_matches('\\');
    if rest.is_empty() {
        return base.to_string();
    }
    format!("{}\\{rest}", base.trim_end_matches('\\'))
}

/// (server, share, rest) of a UNC path `\\server\share\rest`.
pub(crate) fn unc_parts(p: &str) -> Option<(String, String, String)> {
    let p = plain_path(p);
    let tail = p.strip_prefix(r"\\")?;
    if tail.starts_with(['?', '.']) && tail.as_bytes().get(1) == Some(&b'\\') {
        return None; // \\?\Volume{…}, \\.\device
    }
    let mut it = tail.splitn(3, '\\');
    let server = it.next().filter(|s| !s.is_empty())?.to_string();
    let share = it.next().filter(|s| !s.is_empty())?.to_string();
    Some((server, share, it.next().unwrap_or("").to_string()))
}

/// Open an existing file or folder, following links, with no data access (works unelevated).
fn open_existing(path: &str) -> Option<Handle> {
    let w = wide(&long_form(path));
    for access in [FILE_READ_ATTRIBUTES, 0] {
        let h = unsafe {
            CreateFileW(w.as_ptr(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, std::ptr::null(), OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, std::ptr::null_mut())
        };
        if h != INVALID_HANDLE_VALUE && !h.is_null() {
            return Some(Handle(h));
        }
    }
    None
}

fn final_path_of(h: &Handle, flags: u32) -> Option<String> {
    let mut buf = vec![0u16; 512];
    loop {
        let n = unsafe { GetFinalPathNameByHandleW(h.0, buf.as_mut_ptr(), buf.len() as u32, flags) } as usize;
        if n == 0 {
            return None;
        }
        if n < buf.len() {
            return Some(String::from_utf16_lossy(&buf[..n]));
        }
        buf.resize(n + 1, 0);
    }
}

/// The real path of an existing file or folder after every junction, symlink, subst and mapped
/// drive: (`D:\Docs` or `\\server\share\x`, and the `\\?\Volume{…}\Docs` form when it has one).
pub(crate) fn final_paths(existing: &str) -> Option<(String, Option<String>)> {
    let h = open_existing(existing)?;
    let guid = final_path_of(&h, VOLUME_NAME_GUID);
    let dos = final_path_of(&h, VOLUME_NAME_DOS).map(|p| plain_path(&p)).or_else(|| guid.clone())?;
    Some((dos, guid))
}

/// A folder picked for a folder scan: its drive letter and its path below that drive's root
/// ("\Users\Ann\Photos", "" for the root), after junctions, symlinks, subst and mapped drives.
/// Refused when the real folder isn't on a lettered local volume, because the scan reads that
/// volume and the stored folders are relative to its root.
pub(crate) fn folder_on_volume(path: &str) -> Result<(char, String), String> {
    let p = path.trim();
    if !std::fs::metadata(long_form(p)).map(|m| m.is_dir()).unwrap_or(false) {
        return Err("This folder can't be opened. Pick a folder that exists; if it was deleted, pick the folder that contained it.".into());
    }
    let (dos, guid) = final_paths(p).ok_or("Windows didn't say where this folder really is. Pick the drive instead and scan all of it.")?;
    let b = dos.as_bytes();
    if b.len() < 2 || b[1] != b':' || !b[0].is_ascii_alphabetic() {
        return Err("MAX can only scan folders on a local drive with a drive letter. Pick that drive instead and scan all of it.".into());
    }
    let letter = (b[0] as char).to_ascii_uppercase();
    // A volume mounted into a folder of another drive: the DOS path names the other drive.
    let root_guid = final_paths(&format!("{letter}:\\")).and_then(|(_, g)| g).and_then(|g| volume_prefix(&g));
    if let (Some(a), Some(b)) = (guid.as_deref().and_then(volume_prefix), root_guid) {
        if a != b {
            return Err("This folder is on a drive mounted inside another drive's folder. Give that drive a letter in Disk Management, or scan it as a whole drive.".into());
        }
    }
    let rest = dos[2..].trim_end_matches('\\');
    let folder = if rest.is_empty() { String::new() } else if rest.starts_with('\\') { rest.to_string() } else { format!("\\{rest}") };
    Ok((letter, folder))
}

/// The nearest existing ancestor of `path` (or `path` itself) and the part below it.
fn split_existing(path: &str) -> Option<(String, String)> {
    let p = Path::new(path);
    let mut cur = Some(p);
    while let Some(a) = cur {
        let s = a.to_string_lossy();
        if std::fs::metadata(long_form(&s)).is_ok() {
            let rest = p.strip_prefix(a).map(|r| r.to_string_lossy().into_owned()).unwrap_or_default();
            return Some((s.into_owned(), rest));
        }
        cur = a.parent();
    }
    None
}

/// `\\?\volume{…}\` (lowercase) from a `\\?\Volume{…}\x` path.
fn volume_prefix(guid_path: &str) -> Option<String> {
    let l = guid_path.to_ascii_lowercase();
    if !l.starts_with(r"\\?\volume{") {
        return None;
    }
    let end = l.find("}\\").map(|i| i + 2).or_else(|| l.ends_with('}').then_some(l.len()))?;
    let mut v = l[..end].to_string();
    if !v.ends_with('\\') {
        v.push('\\');
    }
    Some(v)
}

/// The `\\server\share` a mapped drive letter points to.
fn mapped_drive(letter: char) -> Option<String> {
    use windows_sys::Win32::NetworkManagement::WNet::WNetGetConnectionW;
    let local = wide(&format!("{letter}:"));
    let mut buf = vec![0u16; 1024];
    let mut n = buf.len() as u32;
    let rc = unsafe { WNetGetConnectionW(local.as_ptr(), buf.as_mut_ptr(), &mut n) };
    (rc == 0).then(|| from_wide(&buf)).filter(|s| s.starts_with(r"\\"))
}

fn drive_is_remote(letter: char) -> bool {
    let root = wide(&format!("{letter}:\\"));
    unsafe { GetDriveTypeW(root.as_ptr()) == DRIVE_REMOTE }
}

fn ip_is_local(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    // Binding a socket to an address only succeeds for addresses of this PC.
    ip.is_loopback() || ip.is_unspecified() || std::net::UdpSocket::bind((ip, 0)).is_ok()
}

/// This PC's names, lowercase (NetBIOS, DNS host name, full DNS name).
fn own_names() -> &'static [String] {
    use windows_sys::Win32::System::SystemInformation::{ComputerNameDnsFullyQualified, ComputerNameDnsHostname, ComputerNameNetBIOS, GetComputerNameExW};
    static N: OnceLock<Vec<String>> = OnceLock::new();
    N.get_or_init(|| {
        let mut v: Vec<String> = Vec::new();
        for kind in [ComputerNameNetBIOS, ComputerNameDnsHostname, ComputerNameDnsFullyQualified] {
            let mut buf = vec![0u16; 512];
            let mut n = buf.len() as u32;
            if unsafe { GetComputerNameExW(kind, buf.as_mut_ptr(), &mut n) } != 0 {
                v.push(from_wide(&buf).to_lowercase());
            }
        }
        if let Ok(c) = std::env::var("COMPUTERNAME") {
            v.push(c.to_lowercase());
        }
        v.retain(|s| !s.is_empty());
        v.sort();
        v.dedup();
        v
    })
}

/// True when a UNC server name is this PC (localhost, a loopback or own address, its own name).
/// `may_resolve` allows a DNS lookup of other names (only when the server answered already).
pub(crate) fn is_local_server(server: &str, may_resolve: bool) -> bool {
    let s = server.split('@').next().unwrap_or("").trim_matches(['[', ']']).trim_end_matches('.').to_lowercase();
    if s.is_empty() || s == "localhost" || s == "." || is_wsl_server(&s) {
        return true;
    }
    // "fe80--1.ipv6-literal.net" is how Windows spells an IPv6 address in a UNC path.
    let s = match s.strip_suffix(".ipv6-literal.net") {
        Some(a) => a.replace('-', ":").replace('s', "%"),
        None => s,
    };
    if let Ok(ip) = s.split('%').next().unwrap_or("").parse::<std::net::IpAddr>() {
        return ip_is_local(ip);
    }
    if own_names().iter().any(|n| *n == s || (!s.contains('.') && n.split('.').next() == Some(s.as_str()))) {
        return true;
    }
    if !may_resolve {
        return false;
    }
    static CACHE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(&v) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(&s) {
        return v;
    }
    use std::net::ToSocketAddrs;
    let local = (s.as_str(), 445).to_socket_addrs().map(|mut it| it.any(|a| ip_is_local(a.ip()))).unwrap_or(false);
    let mut m = cache.lock().unwrap_or_else(|e| e.into_inner());
    if m.len() > 64 {
        m.clear();
    }
    m.insert(s, local);
    local
}

/// True for the UNC server names of WSL distros (`\\wsl$\…`, `\\wsl.localhost\…`): their files
/// live in a virtual disk file (ext4.vhdx) on this PC.
pub(crate) fn is_wsl_server(server: &str) -> bool {
    let s = server.split('@').next().unwrap_or("").trim_end_matches('.').to_ascii_lowercase();
    s == "wsl$" || s == "wsl.localhost"
}

/// The local folder a share of this PC points to (`C$` → `C:\`; others through NetShareGetInfo,
/// which needs administrator rights).
fn share_local_path(share: &str) -> Option<String> {
    let b = share.as_bytes();
    if b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b'$' {
        return Some(format!("{}:\\", (b[0] as char).to_ascii_uppercase()));
    }
    #[repr(C)]
    struct ShareInfo2 {
        netname: *const u16,
        kind: u32,
        remark: *const u16,
        permissions: u32,
        max_uses: u32,
        current_uses: u32,
        path: *const u16,
        passwd: *const u16,
    }
    type GetInfo = unsafe extern "system" fn(*const u16, *const u16, u32, *mut *mut u8) -> u32;
    type Free = unsafe extern "system" fn(*mut c_void) -> u32;
    let get: GetInfo = unsafe { std::mem::transmute(system_fn("netapi32.dll", b"NetShareGetInfo\0")?) };
    let free: Free = unsafe { std::mem::transmute(system_fn("netapi32.dll", b"NetApiBufferFree\0")?) };
    let name = wide(share);
    let mut buf: *mut u8 = std::ptr::null_mut();
    if unsafe { get(std::ptr::null(), name.as_ptr(), 2, &mut buf) } != 0 || buf.is_null() {
        return None;
    }
    let info = unsafe { &*(buf as *const ShareInfo2) };
    let path = if info.kind & 0xFF == 0 { unsafe { wstr(info.path) } } else { String::new() };
    unsafe { free(buf as *mut c_void) };
    let b = path.as_bytes();
    (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':').then_some(path)
}

/// Host volumes (or folders) holding the files behind a virtual disk volume, parsed from a
/// STORAGE_DEPENDENCY_INFO (version 2) buffer. Pointers outside the buffer are ignored.
pub(crate) fn parse_dependency_hosts(buf: &[u8]) -> Vec<String> {
    // Header: Version u32, NumberEntries u32; entries (64 bytes each) from offset 8. In an entry the
    // pointers are at 32 (DependencyDeviceName), 40 (HostVolumeName), 48, 56.
    let count = le_u32(buf, 4) as usize;
    let lo = buf.as_ptr() as usize;
    let hi = lo + buf.len();
    let mut out = Vec::new();
    for i in 0..count.min(64) {
        let o = 8 + i * 64;
        if o + 64 > buf.len() {
            break;
        }
        let p = le_u64(buf, o + 40) as usize;
        if p < lo || p >= hi || (p - lo) % 2 != 0 {
            continue;
        }
        // Bounded by the buffer: read until NUL or the end.
        let words: Vec<u16> = buf[p - lo..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
        let s = String::from_utf16_lossy(&words);
        if !s.is_empty() && !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

/// The host volumes of a virtual disk volume (GetStorageDependencyInformation). None = not known.
fn dependency_hosts(volume: &str) -> Option<Vec<String>> {
    type GetDep = unsafe extern "system" fn(HANDLE, u32, u32, *mut u8, *mut u32) -> u32;
    let f: GetDep = unsafe { std::mem::transmute(system_fn("virtdisk.dll", b"GetStorageDependencyInformation\0")?) };
    let dev = volume.trim_end_matches('\\');
    let handles = [open_existing(&format!("{dev}\\")), open_query(dev)];
    for h in handles.into_iter().flatten() {
        let mut buf = vec![0u64; 1024];
        for _ in 0..3 {
            buf.iter_mut().for_each(|w| *w = 0);
            buf[0] = 2; // STORAGE_DEPENDENCY_INFO_VERSION_2
            let mut used = 0u32;
            // GET_STORAGE_DEPENDENCY_FLAG_HOST_VOLUMES: every host volume in the chain.
            let rc = unsafe { f(h.0, 1, (buf.len() * 8) as u32, buf.as_mut_ptr() as *mut u8, &mut used) };
            if rc == 122 && (used as usize) > buf.len() * 8 && used < (4 << 20) {
                buf.resize(used as usize / 8 + 1, 0);
                continue;
            }
            if rc != 0 {
                break;
            }
            let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len() * 8) };
            return Some(parse_dependency_hosts(bytes));
        }
    }
    None
}

/// STORAGE_BUS_TYPE of physical disk `n`.
fn disk_bus_type(n: u32) -> Option<u32> {
    open_query(&format!(r"\\.\PhysicalDrive{n}")).and_then(|h| device_descriptor(&h)).map(|d| d.bus_type)
}

/// GPT partition type of a Storage Spaces pool member (E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D), as stored.
const SPACES_PART_TYPE: [u8; 16] = [0x8F, 0xAF, 0x5C, 0xE7, 0x80, 0xF6, 0xEE, 0x4C, 0xAF, 0xA3, 0xB0, 0x01, 0xE5, 0x6E, 0xFC, 0x2D];

/// True when a DRIVE_LAYOUT_INFORMATION_EX buffer holds a Storage Spaces member partition.
pub(crate) fn layout_has_spaces_member(b: &[u8]) -> bool {
    let count = le_u32(b, 4) as usize;
    (0..count.min(1024)).map(|i| 48 + i * 144).take_while(|&o| o + 144 <= b.len()).any(|o| le_u32(b, o) == 1 && b[o + 32..o + 48] == SPACES_PART_TYPE)
}

/// The physical disks that may hold a Storage Spaces pool: those with a Storage Spaces member
/// partition, plus (to stay safe) those whose layout can't be read. Other virtual disks are skipped.
fn spaces_pool_disks() -> Vec<u32> {
    let mut out = Vec::new();
    for n in 0..256u32 {
        let Some(h) = open_query(&format!(r"\\.\PhysicalDrive{n}")) else { continue };
        if device_descriptor(&h).map(|d| d.bus_type) == Some(BUS_SPACES) {
            continue;
        }
        let mut size = 48 + 144 * 32;
        let member = loop {
            let mut b = vec![0u8; size];
            match ioctl(&h, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, &[], &mut b) {
                Ok(len) => break layout_has_spaces_member(&b[..len.min(b.len())]),
                Err(122) | Err(234) if size < 48 + 144 * 1024 => size *= 4,
                Err(_) => break true,
            }
        };
        if member {
            out.push(n);
        }
    }
    out
}

/// A Storage Spaces virtual disk reports its own disk number, not the pool's: add the disks that
/// may hold the pool so overlap checks see them.
fn add_space_members(disks: &mut Vec<u32>, buses: &[Option<u32>]) {
    if buses.contains(&Some(BUS_SPACES)) {
        disks.extend(spaces_pool_disks());
        disks.sort_unstable();
        disks.dedup();
    }
}

/// [`add_space_members`] for a disk list whose bus types aren't known yet.
fn with_space_members(mut disks: Vec<u32>) -> Vec<u32> {
    let buses: Vec<Option<u32>> = disks.iter().map(|&d| disk_bus_type(d)).collect();
    add_space_members(&mut disks, &buses);
    disks
}

/// Physical disks under a volume (`\\?\Volume{…}\`), plus the disks that hold the file of a
/// virtual disk. Ok(None) = unknown; Err = a virtual disk whose file couldn't be placed.
fn volume_disks_resolved(volume: &str, depth: u32) -> Result<Option<Vec<u32>>, String> {
    let Some(h) = open_query(volume.trim_end_matches('\\')) else { return Ok(None) };
    let mut disks: Vec<u32> = volume_extents_of(&h).iter().map(|e| e.disk).collect();
    drop(h);
    disks.sort_unstable();
    disks.dedup();
    if disks.is_empty() {
        return Ok(None);
    }
    let buses: Vec<Option<u32>> = disks.iter().map(|&d| disk_bus_type(d)).collect();
    add_space_members(&mut disks, &buses);
    let file_backed = buses.contains(&Some(BUS_FILE_BACKED_VIRTUAL));
    let bus_unknown = buses.contains(&None);
    let maybe_virtual = file_backed || bus_unknown || buses.contains(&Some(BUS_VIRTUAL));
    if !maybe_virtual {
        return Ok(Some(disks));
    }
    let own = volume.to_ascii_lowercase();
    match dependency_hosts(volume) {
        Some(hosts) if !hosts.is_empty() => {
            for host in hosts {
                if host.to_ascii_lowercase().trim_end_matches('\\') == own.trim_end_matches('\\') {
                    continue;
                }
                let l = locate_depth(&host, depth + 1);
                if let Some(r) = l.refuse {
                    return Err(r);
                }
                if l.network_root.is_some() {
                    continue; // the file lives on another computer
                }
                match l.disks {
                    Some(d) => disks.extend(d),
                    None => return Err(VHD_UNRESOLVED.into()),
                }
            }
            disks.sort_unstable();
            disks.dedup();
            Ok(Some(disks))
        }
        _ if file_backed => Err(VHD_UNRESOLVED.into()),
        // Neither the disk's kind nor what it depends on is known: it may be a virtual disk file.
        None if bus_unknown => Err(DISK_UNRESOLVED.into()),
        _ => Ok(Some(disks)),
    }
}

fn volume_path_name(path: &str) -> Option<String> {
    let p = wide(path);
    let mut root = [0u16; 1024];
    (unsafe { GetVolumePathNameW(p.as_ptr(), root.as_mut_ptr(), root.len() as u32) } != 0).then(|| from_wide(&root))
}

/// Where the bytes of `path` (which need not exist yet) would really be written.
pub(crate) fn locate_path(path: &str) -> PathLocation {
    locate_depth(path, 0)
}

fn locate_depth(path: &str, depth: u32) -> PathLocation {
    if depth > 4 {
        return refused(TOO_DEEP);
    }
    let path = plain_path(path.trim());
    // Refused before anything is opened: touching \\wsl$ can start the Linux VM.
    if unc_parts(&path).is_some_and(|(server, _, _)| is_wsl_server(&server)) {
        return refused(WSL_FOLDER);
    }
    let (real, guid_form, resolved) = match split_existing(&path) {
        Some((anc, rest)) => match final_paths(&anc) {
            Some((dos, guid)) => (join(&dos, &rest), guid.map(|g| join(&g, &rest)), true),
            None => (path.clone(), None, false),
        },
        None => (path.clone(), None, false),
    };
    if !resolved {
        // A mapped drive that isn't answering: judge it by the share it points to.
        let b = path.as_bytes();
        if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && drive_is_remote(b[0] as char) {
            if let Some(unc) = mapped_drive(b[0] as char) {
                return locate_depth(&join(&unc, &path[2..]), depth + 1);
            }
        }
    }
    if let Some((server, share, rest)) = unc_parts(&real) {
        if is_wsl_server(&server) {
            return refused(WSL_FOLDER);
        }
        if is_local_server(&server, resolved) {
            return match share_local_path(&share) {
                Some(local) => locate_depth(&join(&local, &rest), depth + 1),
                None => refused(LOOPBACK_UNRESOLVED),
            };
        }
        return PathLocation {
            real_path: Some(real),
            root: Some(format!(r"\\{server}\{share}\")),
            network_root: Some(format!(r"\\{server}\{share}").to_lowercase()),
            ..Default::default()
        };
    }
    if !resolved {
        return PathLocation::default(); // nothing on the way exists or it can't be opened: unknown
    }
    let volume = guid_form.as_deref().and_then(volume_prefix);
    let root = volume_path_name(&real).or_else(|| volume.clone());
    let disks = match volume.as_deref() {
        Some(v) => match volume_disks_resolved(v, depth) {
            Ok(d) => d,
            Err(e) => return refused(&e),
        },
        None => None,
    };
    PathLocation { real_path: Some(real), root, volume, disks, network_root: None, refuse: None }
}

/// Where a scan source's bytes live.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct SourceLocation {
    /// `\\?\volume{…}\`, lowercase.
    pub volume: Option<String>,
    /// None = unknown.
    pub disks: Option<Vec<u32>>,
    /// Image sources: the real path of the image file (after links), when it exists.
    pub image_real_path: Option<String>,
}

/// `\\?\volume{…}\` (lowercase) of drive letter `letter`.
pub(crate) fn letter_volume(letter: char) -> Option<String> {
    let r = wide(&format!("{letter}:\\"));
    let mut guid = [0u16; 128];
    (unsafe { GetVolumeNameForVolumeMountPointW(r.as_ptr(), guid.as_mut_ptr(), guid.len() as u32) } != 0).then(|| from_wide(&guid).to_ascii_lowercase())
}

/// The original volume (`\\?\volume{…}\`, lowercase) of a shadow copy device, from WMI (cached).
pub(crate) fn snapshot_volume(device_path: &str) -> Option<String> {
    let p = snapshot_path(device_path)?;
    let tail = p.rsplit('\\').next().unwrap_or("").to_ascii_lowercase();
    static CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(v) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(&tail) {
        return Some(v.clone());
    }
    let rows = super::list::wmi::query(r"ROOT\CIMV2", "SELECT DeviceObject, VolumeName FROM Win32_ShadowCopy", &["DeviceObject", "VolumeName"]).unwrap_or_default();
    for r in rows {
        let dev = r.get("DeviceObject").string().unwrap_or_default().to_ascii_lowercase();
        if dev.rsplit('\\').next() == Some(tail.as_str()) {
            let v = r.get("VolumeName").string().map(|v| v.to_ascii_lowercase()).filter(|v| v.starts_with(r"\\?\volume{"))?;
            cache.lock().unwrap_or_else(|e| e.into_inner()).insert(tail, v.clone());
            return Some(v);
        }
    }
    None
}

fn extents_disks(device: &str) -> Option<Vec<u32>> {
    let h = open_query(device.trim_end_matches('\\'))?;
    let mut d: Vec<u32> = volume_extents_of(&h).iter().map(|e| e.disk).collect();
    d.sort_unstable();
    d.dedup();
    (!d.is_empty()).then_some(d)
}

/// Where the source's bytes live (read-only lookups; the source is not opened for data).
pub(crate) fn source_location(r: &crate::model::SourceRef) -> SourceLocation {
    use crate::model::SourceKind;
    match r.kind {
        SourceKind::Volume => {
            let Some(l) = r.path.trim().chars().next().filter(|c| c.is_ascii_alphabetic()).map(|c| c.to_ascii_uppercase()) else {
                return SourceLocation::default();
            };
            let volume = letter_volume(l);
            let disks = extents_disks(&format!(r"\\.\{l}:")).or_else(|| volume.as_deref().and_then(extents_disks)).map(with_space_members);
            SourceLocation { volume, disks, image_real_path: None }
        }
        SourceKind::Disk => SourceLocation { disks: r.path.trim().trim_start_matches(r"\\.\PhysicalDrive").parse::<u32>().ok().map(|n| with_space_members(vec![n])), ..Default::default() },
        SourceKind::Image => SourceLocation { image_real_path: final_paths(&r.path).map(|p| p.0), ..Default::default() },
        SourceKind::Snapshot => {
            // A shadow copy's free clusters are its original volume's: that volume's disks.
            let volume = snapshot_volume(&r.path);
            let mut disks = snapshot_path(&r.path).and_then(|p| extents_disks(&p));
            if let Some(v) = volume.as_deref().and_then(extents_disks) {
                let d = disks.get_or_insert_with(Vec::new);
                d.extend(v);
                d.sort_unstable();
                d.dedup();
            }
            let disks = disks.map(with_space_members);
            if volume.is_none() && disks.is_none() {
                return SourceLocation::default();
            }
            SourceLocation { volume, disks, image_real_path: None }
        }
    }
}

// ------------------------------------------------------------------------------- error texts

/// One sentence for a failed raw open.
pub fn open_error(code: u32) -> String {
    match code {
        5 => ADMIN_NEEDED.into(),
        2 | 3 | 15 | 1167 => GONE.into(),
        21 | 1112 => NOT_READY.into(),
        32 | 33 => "Another program has locked the drive. Close it and try again.".into(),
        e => format!("Windows couldn't open the drive (error {e}). Reconnect it and try again."),
    }
}

// ---------------------------------------------------------------------------- aligned buffer

struct AlignedBuf {
    ptr: *mut u8,
    layout: Layout,
}

impl AlignedBuf {
    fn new(len: usize) -> AlignedBuf {
        let layout = Layout::from_size_align(len.max(ALIGN), ALIGN).expect("layout");
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        AlignedBuf { ptr, layout }
    }
    fn cap(&self) -> usize {
        self.layout.size()
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        unsafe { dealloc(self.ptr, self.layout) };
    }
}

thread_local! {
    /// One reusable bounce buffer per reading thread (≤ 8 MiB).
    static BOUNCE: RefCell<Option<AlignedBuf>> = const { RefCell::new(None) };
}

// ----------------------------------------------------------------------------------- source

/// A raw volume / disk / shadow copy, read through whole aligned sectors.
pub struct WinSource {
    handle: Handle,
    len: u64,
    sector: u32,
    desc: String,
}

impl WinSource {
    /// Positional read of whole sectors: `offset` and `buf.len()` are sector multiples.
    fn read_aligned(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.Anonymous.Anonymous.Offset = offset as u32;
        ov.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
        let mut got = 0u32;
        let ok = unsafe { ReadFile(self.handle.0, buf.as_mut_ptr(), buf.len() as u32, &mut got, &mut ov) };
        if ok == 0 {
            let e = unsafe { GetLastError() };
            if e == 38 {
                return Ok(0); // ERROR_HANDLE_EOF
            }
            return Err(std::io::Error::from_raw_os_error(e as i32));
        }
        Ok(got as usize)
    }
}

impl BlockSource for WinSource {
    fn len(&self) -> u64 {
        self.len
    }
    fn sector_size(&self) -> u32 {
        self.sector
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.len - offset) as usize;
        let ss = self.sector as u64;
        BOUNCE.with(|cell| {
            let mut cell = cell.borrow_mut();
            let mut done = 0usize;
            while done < want {
                let pos = offset + done as u64;
                let a_start = pos - pos % ss;
                let lead = (pos - a_start) as usize;
                let rest = want - done;
                // Aligned span covering [pos, pos+rest), capped at MAX_IO.
                let span = ((lead + rest) as u64).div_ceil(ss) * ss;
                let span = (span as usize).min(MAX_IO);
                let span = (span as u64).min((self.len - a_start).div_ceil(ss) * ss) as usize;
                if cell.as_ref().map_or(true, |b| b.cap() < span) {
                    *cell = Some(AlignedBuf::new(span.max(64 * 1024)));
                }
                let b = cell.as_ref().unwrap();
                let bounce = unsafe { std::slice::from_raw_parts_mut(b.ptr, span) };
                let got = self.read_aligned(a_start, bounce)?;
                if got <= lead {
                    break; // end of the device
                }
                let n = (got - lead).min(rest);
                buf[done..done + n].copy_from_slice(&bounce[lead..lead + n]);
                done += n;
                if got < span {
                    break;
                }
            }
            Ok(done)
        })
    }
    fn describe(&self) -> String {
        self.desc.clone()
    }
}

/// Open a raw device read-only and size it.
fn open_raw(path: &str, volume: bool) -> Result<(Handle, u64, u32), String> {
    let h = open_device(path, GENERIC_READ, FILE_FLAG_NO_BUFFERING).map_err(open_error)?;
    if volume {
        let _ = ioctl(&h, FSCTL_ALLOW_EXTENDED_DASD_IO, &[], &mut []);
    }
    let len = length_info(&h).or_else(|| geometry(&h).map(|g| g.0)).filter(|&l| l > 0);
    let Some(len) = len else {
        return Err(NOT_READY.into());
    };
    let sector = logical_sector_size(&h).unwrap_or(512);
    Ok((h, len, sector))
}

fn parse_letter(letter: &str) -> Result<char, String> {
    let t = letter.trim().trim_end_matches('\\').trim_end_matches(':');
    match t.chars().next() {
        Some(c) if t.len() == 1 && c.is_ascii_alphabetic() => Ok(c.to_ascii_uppercase()),
        _ => Err("That isn't a drive letter. Pick a drive from the list.".into()),
    }
}

/// File system name Windows reports for a drive letter ("NTFS"), if mounted.
pub(crate) fn fs_name(letter: char) -> Option<String> {
    let root = wide(&format!("{letter}:\\"));
    let mut fs = [0u16; 64];
    let ok = unsafe {
        GetVolumeInformationW(root.as_ptr(), std::ptr::null_mut(), 0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), fs.as_mut_ptr(), fs.len() as u32)
    } != 0;
    ok.then(|| from_wide(&fs)).filter(|s| !s.is_empty())
}

/// Open drive letter `letter` ("C") read-only. Needs administrator rights.
pub fn open_volume(letter: &str) -> Result<Source, String> {
    let l = parse_letter(letter)?;
    let (handle, len, sector) = open_raw(&format!(r"\\.\{l}:"), true)?;
    let mut src = WinSource { handle, len, sector, desc: format!("{l}:") };
    src.desc = match fs_name(l) {
        Some(fs) => format!("{l}: ({fs})"),
        None if bitlocker_locked(&src) => format!("{l}: (BitLocker, locked)"),
        None => format!("{l}:"),
    };
    Ok(Arc::new(src))
}

/// Open physical disk `index` ("0") read-only. Needs administrator rights.
pub fn open_disk(index: &str) -> Result<Source, String> {
    let n: u32 = index.trim().trim_start_matches(r"\\.\PhysicalDrive").parse().map_err(|_| "That isn't a disk number. Pick a disk from the list.".to_string())?;
    let (handle, len, sector) = open_raw(&format!(r"\\.\PhysicalDrive{n}"), false)?;
    let model = device_descriptor(&handle).map(|d| d.model()).filter(|m| !m.is_empty());
    let desc = match model {
        Some(m) => format!("Disk {n} \u{2013} {m}"),
        None => format!("Disk {n}"),
    };
    Ok(Arc::new(WinSource { handle, len, sector, desc }))
}

/// Normalise a shadow-copy device path to something CreateFileW opens, or None if it isn't one.
pub(crate) fn snapshot_path(device_path: &str) -> Option<String> {
    let p = device_path.trim().trim_end_matches('\\');
    let tail = p.rsplit('\\').next()?;
    if !tail.to_ascii_lowercase().starts_with("harddiskvolumeshadowcopy") || !tail[24..].chars().all(|c| c.is_ascii_digit()) || tail.len() == 24 {
        return None;
    }
    Some(format!(r"\\?\GLOBALROOT\Device\{tail}"))
}

/// Open a Volume Shadow Copy device read-only. Needs administrator rights.
pub fn open_snapshot(device_path: &str) -> Result<Source, String> {
    let path = snapshot_path(device_path).ok_or_else(|| "That isn't a restore point. Pick one from the list.".to_string())?;
    let (handle, len, sector) = open_raw(&path, true)?;
    let n = path.rsplit("ShadowCopy").next().unwrap_or("").to_string();
    Ok(Arc::new(WinSource { handle, len, sector, desc: format!("Restore point {n}") }))
}

// --------------------------------------------------------------------------------- BitLocker

/// A BitLocker-encrypted volume's boot sector has the OEM id "-FVE-FS-" at offset 3. Read through
/// the volume device, only a *locked* volume shows it (an unlocked one is presented decrypted); read
/// through the physical disk, every BitLocker volume shows it.
pub fn is_fve_boot_sector(sector: &[u8]) -> bool {
    sector.get(3..11) == Some(b"-FVE-FS-")
}

/// True when the source's first sector is a BitLocker header (locked volume / raw partition bytes).
pub fn bitlocker_locked(src: &dyn BlockSource) -> bool {
    let mut b = [0u8; 512];
    matches!(src.read_at(0, &mut b), Ok(n) if n >= 11) && is_fve_boot_sector(&b)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn errors_are_sentences() {
        assert_eq!(open_error(5), ADMIN_NEEDED);
        assert!(open_error(5).contains("administrator"));
        assert_eq!(open_error(2), GONE);
        assert_eq!(open_error(15), GONE);
        assert_eq!(open_error(21), NOT_READY);
        assert!(open_error(87).contains("87"));
    }

    #[test]
    fn unelevated_raw_opens_need_admin() {
        if crate::util::is_elevated() {
            return;
        }
        let e = open_volume(&crate::util::system_drive_letter()).err().expect("unelevated open must fail");
        assert_eq!(e, ADMIN_NEEDED);
        assert_eq!(open_disk("0").err().unwrap(), ADMIN_NEEDED);
        assert!(open_volume("CC").is_err() && open_disk("x").is_err());
        assert!(open_snapshot(r"C:\Windows\notepad.exe").err().unwrap().contains("restore point"));
    }

    #[test]
    fn snapshot_paths_normalise() {
        assert_eq!(snapshot_path(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3").as_deref(), Some(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3"));
        assert_eq!(snapshot_path(r"\\.\HarddiskVolumeShadowCopy12\").as_deref(), Some(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12"));
        assert_eq!(snapshot_path(r"\\.\PhysicalDrive0"), None);
        assert_eq!(snapshot_path(r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy"), None);
    }

    #[test]
    fn fve_and_descriptor_parsing() {
        let mut s = [0u8; 512];
        s[3..11].copy_from_slice(b"-FVE-FS-");
        assert!(is_fve_boot_sector(&s));
        s[3..11].copy_from_slice(b"NTFS    ");
        assert!(!is_fve_boot_sector(&s));

        let mut d = vec![0u8; 128];
        d[10] = 1;
        d[12..16].copy_from_slice(&64u32.to_le_bytes());
        d[16..20].copy_from_slice(&72u32.to_le_bytes());
        d[24..28].copy_from_slice(&96u32.to_le_bytes());
        d[28..32].copy_from_slice(&7u32.to_le_bytes());
        d[64..68].copy_from_slice(b"WD  ");
        d[72..86].copy_from_slice(b"WD My Passport");
        d[96..104].copy_from_slice(b" ABC123 ");
        let p = parse_device_descriptor(&d);
        assert!(p.removable && p.bus_type == 7 && p.serial == "ABC123");
        assert_eq!(p.model(), "WD My Passport");

        let mut e = vec![0u8; 8 + 48];
        e[0] = 2;
        e[8] = 1;
        e[16..24].copy_from_slice(&1048576u64.to_le_bytes());
        e[24..32].copy_from_slice(&999u64.to_le_bytes());
        e[32] = 3;
        let x = parse_extents(&e);
        assert_eq!(x, vec![DiskExtent { disk: 1, offset: 1 << 20, len: 999 }, DiskExtent { disk: 3, offset: 0, len: 0 }]);
    }

    /// A regular file opened with FILE_FLAG_NO_BUFFERING has the same alignment rules as a raw
    /// device, so the bounce-buffer path can be checked without administrator rights.
    #[test]
    fn unaligned_reads_through_aligned_sectors() {
        let t = super::super::image::tests::TempFile::new("bin");
        let len = (9 << 20) + 700; // > MAX_IO, not a sector multiple
        let data: Vec<u8> = (0..len as u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        std::fs::write(&t.0, &data).unwrap();
        let handle = open_device(&t.path(), GENERIC_READ, FILE_FLAG_NO_BUFFERING).unwrap();
        let src = WinSource { handle, len: len as u64, sector: 512, desc: "t".into() };
        for &(off, n) in &[(0u64, 1usize), (1, 511), (511, 2), (1000, 70_000), (3, (9 << 20) - 3), (len as u64 - 10, 10), (len as u64 - 600, 4096), ((8 << 20) - 5, 10)] {
            let mut b = vec![0u8; n];
            let got = src.read_at(off, &mut b).unwrap();
            let want = n.min(len - off as usize);
            assert_eq!(got, want, "read {off}+{n}");
            assert!(b[..got] == data[off as usize..off as usize + got], "content at {off}+{n}");
        }
        let mut b = [0u8; 16];
        assert_eq!(src.read_at(len as u64, &mut b).unwrap(), 0);
        drop(src);
    }

    /// `mklink /J link target` (junctions need no administrator rights). Test helper; only ever
    /// called on folders under %TEMP% or the project.
    pub(crate) fn make_junction(link: &Path, target: &Path) -> bool {
        use std::os::windows::process::CommandExt;
        let cmd = std::env::var_os("SystemRoot").map(|r| std::path::PathBuf::from(r).join(r"System32\cmd.exe")).unwrap_or_else(|| r"C:\Windows\System32\cmd.exe".into());
        std::process::Command::new(cmd)
            .raw_arg(format!("/S /C \"mklink /J \"{}\" \"{}\"\"", link.display(), target.display()))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(crate::util::CREATE_NO_WINDOW)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("maxrec-win-{tag}-{}-{}", std::process::id(), crate::model::now_ms()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn locate_follows_junctions() {
        let base = temp_dir("junction");
        let target = base.join("real");
        std::fs::create_dir_all(&target).unwrap();
        let link = base.join("link");
        assert!(make_junction(&link, &target), "mklink /J failed");
        let real = final_paths(&target.to_string_lossy()).unwrap().0;
        let loc = locate_path(&link.join("new").join("sub").to_string_lossy());
        assert_eq!(loc.real_path.as_deref().map(str::to_lowercase), Some(format!("{}\\new\\sub", real).to_lowercase()), "{loc:?}");
        assert!(loc.volume.is_some() && loc.disks.is_some() && loc.root.is_some() && loc.refuse.is_none(), "{loc:?}");
        // The link itself resolves to the target.
        assert_eq!(final_paths(&link.to_string_lossy()).unwrap().0.to_lowercase(), real.to_lowercase());
        let _ = std::fs::remove_dir(&link);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn local_servers_are_recognised() {
        for s in ["localhost", "LOCALHOST.", "127.0.0.1", "127.1.2.3", "[::1]", "::1", "0--1.ipv6-literal.net", ".", "localhost@SSL@443"] {
            assert!(is_local_server(s, false), "{s}");
        }
        assert!(own_names().iter().all(|n| is_local_server(n, false)));
        if let Ok(c) = std::env::var("COMPUTERNAME") {
            assert!(is_local_server(&c, false));
        }
        for s in ["8.8.8.8", "nas", "192.0.2.1", "fileserver.example"] {
            assert!(!is_local_server(s, false), "{s}");
        }
        // WSL distros live in a virtual disk file on this PC.
        for s in ["wsl$", "WSL$", "wsl.localhost", "WSL.LOCALHOST."] {
            assert!(is_wsl_server(s) && is_local_server(s, false), "{s}");
        }
    }

    #[test]
    fn wsl_folders_are_refused() {
        for p in [r"\\wsl$\Ubuntu\home\x\maxrec-not-there", r"\\wsl.localhost\Ubuntu\maxrec-not-there", r"\\?\UNC\wsl$\Debian\x"] {
            let loc = locate_path(p);
            assert_eq!(loc.refuse.as_deref(), Some(WSL_FOLDER), "{p}: {loc:?}");
            assert!(loc.network_root.is_none(), "{p}: {loc:?}");
        }
    }

    #[test]
    fn spaces_member_partition_is_found_in_a_layout() {
        let mut b = vec![0u8; 48 + 144 * 2];
        b[0] = 1; // GPT
        b[4] = 2;
        b[48] = 1;
        b[48 + 144] = 1;
        assert!(!layout_has_spaces_member(&b));
        b[48 + 144 + 32..48 + 144 + 48].copy_from_slice(&SPACES_PART_TYPE);
        assert!(layout_has_spaces_member(&b));
        // An MBR entry with the same bytes doesn't count; a short buffer is ignored.
        b[48 + 144] = 0;
        assert!(!layout_has_spaces_member(&b));
        assert!(!layout_has_spaces_member(&b[..100]));
    }

    #[test]
    fn loopback_admin_share_is_the_local_drive() {
        let sys = crate::util::system_drive_letter();
        let loc = locate_path(&format!(r"\\localhost\{sys}$\Windows\maxrec-not-there"));
        assert!(loc.network_root.is_none(), "{loc:?}");
        assert_eq!(loc.real_path.as_deref().map(|p| p[..2].to_ascii_uppercase()), Some(format!("{sys}:")), "{loc:?}");
        assert_eq!(loc.disks, locate_path(&format!(r"{sys}:\Windows")).disks);
        // A share of this PC that can't be placed is refused, not treated as remote.
        let loc = locate_path(r"\\127.0.0.1\maxrec-no-such-share\x");
        assert!(loc.refuse.is_some() && loc.network_root.is_none(), "{loc:?}");
    }

    #[test]
    fn path_helpers() {
        assert_eq!(plain_path(r"\\?\C:\a"), r"C:\a");
        assert_eq!(plain_path(r"\\?\UNC\nas\s\x"), r"\\nas\s\x");
        assert_eq!(plain_path(r"\\?\Volume{1}\x"), r"\\?\Volume{1}\x");
        assert_eq!(unc_parts(r"\\nas\share\a\b"), Some(("nas".into(), "share".into(), r"a\b".into())));
        assert_eq!(unc_parts(r"\\?\UNC\nas\share"), Some(("nas".into(), "share".into(), String::new())));
        assert_eq!(unc_parts(r"\\?\Volume{1}\x"), None);
        assert_eq!(unc_parts(r"C:\x"), None);
        assert_eq!(volume_prefix(r"\\?\Volume{AB-12}\Docs\x").as_deref(), Some(r"\\?\volume{ab-12}\"));
        assert_eq!(volume_prefix(r"C:\x"), None);
        assert_eq!(join(r"C:\", r"a\b"), r"C:\a\b");
        assert_eq!(join(r"C:\x", ""), r"C:\x");
        assert_eq!(share_local_path("d$").as_deref(), Some(r"D:\"));
        assert!(locate_path(r"Q:\").real_path.is_none() || Path::new(r"Q:\").exists());
    }

    #[test]
    fn dependency_info_parses_host_volumes() {
        // STORAGE_DEPENDENCY_INFO v2 with two entries whose HostVolumeName points into the buffer.
        let mut buf = vec![0u8; 8 + 2 * 64 + 256];
        buf[0] = 2;
        buf[4] = 3; // claims 3 entries; the third runs past the buffer's entries and is ignored
        let s1: Vec<u16> = r"\\?\Volume{aaa}\".encode_utf16().chain([0]).collect();
        let s2: Vec<u16> = r"\\?\Volume{bbb}\".encode_utf16().chain([0]).collect();
        let (o1, o2) = (8 + 2 * 64, 8 + 2 * 64 + 64);
        for (i, w) in s1.iter().enumerate() {
            buf[o1 + 2 * i..o1 + 2 * i + 2].copy_from_slice(&w.to_le_bytes());
        }
        for (i, w) in s2.iter().enumerate() {
            buf[o2 + 2 * i..o2 + 2 * i + 2].copy_from_slice(&w.to_le_bytes());
        }
        let base = buf.as_ptr() as usize as u64;
        buf[8 + 40..8 + 48].copy_from_slice(&(base + o1 as u64).to_le_bytes());
        buf[8 + 64 + 40..8 + 64 + 48].copy_from_slice(&(base + o2 as u64).to_le_bytes());
        assert_eq!(parse_dependency_hosts(&buf), vec![r"\\?\Volume{aaa}\".to_string(), r"\\?\Volume{bbb}\".to_string()]);
        // A pointer outside the buffer is ignored.
        buf[8 + 40..8 + 48].copy_from_slice(&8u64.to_le_bytes());
        assert_eq!(parse_dependency_hosts(&buf), vec![r"\\?\Volume{bbb}\".to_string()]);
    }

    #[test]
    fn unknown_sources_stay_unknown() {
        use crate::model::{SourceKind, SourceRef};
        // A restore point that doesn't exist: nothing is guessed (no system-drive fallback).
        let s = SourceRef { kind: SourceKind::Snapshot, path: r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy9999".into(), ..Default::default() };
        assert_eq!(source_location(&s), SourceLocation::default());
        let s = SourceRef { kind: SourceKind::Disk, path: "2".into(), ..Default::default() };
        assert_eq!(source_location(&s).disks, Some(vec![2]));
        let sys = crate::util::system_drive_letter();
        let s = SourceRef { kind: SourceKind::Volume, path: sys.clone(), ..Default::default() };
        let l = source_location(&s);
        assert!(l.volume.is_some() && l.disks.is_some(), "{l:?}");
        assert_eq!(l.disks, locate_path(&format!(r"{sys}:\")).disks);
    }

    #[test]
    fn system_drive_extents_without_admin() {
        let sys = crate::util::system_drive_letter();
        let ex = letter_extents(&sys);
        assert!(!ex.is_empty(), "extents of {sys}:");
        let d = disks_of_path(&std::env::temp_dir().to_string_lossy());
        assert!(!d.is_empty());
    }
}
