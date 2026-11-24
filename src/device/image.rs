//! Disk image files as sources: raw (.img .dd .raw .bin .iso .001), VHD (fixed and dynamic) and
//! VHDX. OWNER: device agent.
//!
//! Files are opened read-only and shared read|write|delete. Unknown extensions are treated as raw
//! images. A split raw set (`name.001`, `name.002`, …) reads as one disk. Differencing virtual disks
//! (which need their parent) are refused.

use super::list::PartitionInfo;
use super::source::{BlockSource, Source, SubSource};
use serde::Serialize;
use std::fs::File;
use std::os::windows::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ImageInfo {
    pub path: String,
    /// Virtual disk size in bytes (what scans see).
    pub size: u64,
    /// File size on disk.
    pub file_size: u64,
    /// "raw" | "vhd-fixed" | "vhd-dynamic" | "vhdx"
    pub format: String,
    /// "GPT" | "MBR" | "None" (a bare volume image) | "Unknown"
    pub partition_style: String,
    /// File system when the image is a bare volume ("NTFS", "FAT32", "exFAT"), else None.
    pub fs: Option<String>,
    pub partitions: Vec<crate::device::list::PartitionInfo>,
    /// Logical sector size of the virtual disk (additive).
    #[serde(default)]
    pub sector_size: Option<u32>,
    /// One sentence worth showing, e.g. "This image is split into 3 files." (additive).
    #[serde(default)]
    pub note: Option<String>,
}

const DIFFERENCING: &str = "Differencing virtual disks aren't supported. Merge it into its parent first.";
const DAMAGED: &str = "This virtual disk file is damaged. Try a copy of it or open it as a raw image.";

// ---------------------------------------------------------------------------- file helpers

fn open_file(path: &Path) -> Result<File, String> {
    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;
    const FILE_SHARE_DELETE: u32 = 4;
    std::fs::OpenOptions::new().read(true).share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).open(path).map_err(|e| match e.raw_os_error() {
        Some(2) | Some(3) => "That image file doesn't exist anymore. Pick it again.".to_string(),
        Some(5) => "Windows didn't let MAX open that image file. Check that you can open it, then try again.".to_string(),
        Some(32) | Some(33) => "Another program has that image file locked. Close it and try again.".to_string(),
        _ => format!("Windows couldn't open that image file ({}). Pick it again.", short_io(&e)),
    })
}

fn short_io(e: &std::io::Error) -> String {
    let s = e.to_string();
    let s = s.split(" (os error").next().unwrap_or(&s).trim().trim_end_matches('.').to_string();
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().chain(c).collect(),
        None => s,
    }
}

/// Positional read until `buf` is full or end of file.
fn pread(f: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match f.seek_read(&mut buf[got..], offset + got as u64) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.raw_os_error() == Some(38) => break, // ERROR_HANDLE_EOF
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}

/// Positional read that must be complete.
fn pread_exact(f: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
    if pread(f, offset, buf)? < buf.len() {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "the image file ends early"));
    }
    Ok(())
}

fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(b[o..o + 4].try_into().unwrap())
}
fn be64(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(b[o..o + 8].try_into().unwrap())
}
fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

fn file_name(path: &Path) -> String {
    path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| path.display().to_string())
}

// ------------------------------------------------------------------------------- raw images

struct Part {
    file: File,
    start: u64,
    len: u64,
}

/// One raw image, or a split set read as one, optionally cut short (fixed VHD footer).
struct RawImage {
    parts: Vec<Part>,
    len: u64,
    desc: String,
}

impl BlockSource for RawImage {
    fn len(&self) -> u64 {
        self.len
    }
    fn sector_size(&self) -> u32 {
        512
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.len - offset) as usize;
        let mut done = 0usize;
        let mut i = self.parts.partition_point(|p| p.start + p.len <= offset);
        while done < want && i < self.parts.len() {
            let p = &self.parts[i];
            let pos = offset + done as u64;
            let within = pos - p.start;
            let n = ((p.len - within) as usize).min(want - done);
            let got = pread(&p.file, within, &mut buf[done..done + n])?;
            done += got;
            if got < n {
                break;
            }
            i += 1;
        }
        Ok(done)
    }
    fn describe(&self) -> String {
        self.desc.clone()
    }
}

/// `x.001` → every consecutive `x.002`, `x.003`, … that exists.
fn split_set(path: &Path) -> Vec<PathBuf> {
    let mut out = vec![path.to_path_buf()];
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else { return out };
    if ext.len() < 3 || !ext.chars().all(|c| c.is_ascii_digit()) || ext.parse::<u32>().ok() != Some(1) {
        return out;
    }
    let width = ext.len();
    for n in 2u32..10_000 {
        let next = path.with_extension(format!("{n:0width$}"));
        if !next.is_file() {
            break;
        }
        out.push(next);
    }
    out
}

// ------------------------------------------------------------------------------------- VHD

/// A dynamic VHD: blocks found through the BAT, sector bitmaps honoured, missing blocks = zeros.
struct VhdDynamic {
    file: File,
    size: u64,
    block_size: u64,
    /// Bytes of the per-block sector bitmap, rounded up to whole sectors.
    bitmap_len: u64,
    bat: Vec<u32>,
    desc: String,
}

impl BlockSource for VhdDynamic {
    fn len(&self) -> u64 {
        self.size
    }
    fn sector_size(&self) -> u32 {
        512
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.size - offset) as usize;
        let mut done = 0usize;
        let mut bitmap = vec![0u8; self.bitmap_len as usize];
        while done < want {
            let pos = offset + done as u64;
            let idx = (pos / self.block_size) as usize;
            let within = pos % self.block_size;
            let n = ((self.block_size - within) as usize).min(want - done);
            let out = &mut buf[done..done + n];
            match self.bat.get(idx).copied() {
                None | Some(0xFFFF_FFFF) => out.fill(0),
                Some(sec) => {
                    let block = sec as u64 * 512;
                    pread_exact(&self.file, block, &mut bitmap)?;
                    pread_exact(&self.file, block + self.bitmap_len + within, out)?;
                    // Sectors whose bitmap bit is clear were never written: they read as zeros.
                    let first = within / 512;
                    let last = (within + n as u64 - 1) / 512;
                    for s in first..=last {
                        let bit = bitmap.get((s / 8) as usize).map_or(0, |b| b & (0x80 >> (s % 8)));
                        if bit == 0 {
                            let a = (s * 512).max(within) - within;
                            let b = ((s + 1) * 512).min(within + n as u64) - within;
                            out[a as usize..b as usize].fill(0);
                        }
                    }
                }
            }
            done += n;
        }
        Ok(done)
    }
    fn describe(&self) -> String {
        self.desc.clone()
    }
}

/// The 512-byte VHD footer: (disk type, current size, data offset).
fn vhd_footer(b: &[u8]) -> Option<(u32, u64, u64)> {
    if b.len() < 512 || &b[0..8] != b"conectix" {
        return None;
    }
    Some((be32(b, 60), be64(b, 48), be64(b, 16)))
}

fn open_vhd(file: File, file_len: u64, footer: (u32, u64, u64), desc: String) -> Result<(Source, &'static str), String> {
    let (disk_type, size, data_offset) = footer;
    match disk_type {
        2 => {
            let len = size.min(file_len.saturating_sub(512));
            Ok((Arc::new(RawImage { parts: vec![Part { file, start: 0, len }], len, desc }), "vhd-fixed"))
        }
        3 => {
            let mut h = [0u8; 1024];
            pread_exact(&file, data_offset, &mut h).map_err(|_| DAMAGED.to_string())?;
            if &h[0..8] != b"cxsparse" {
                return Err(DAMAGED.into());
            }
            let table = be64(&h, 16);
            let entries = be32(&h, 28) as u64;
            let block_size = be32(&h, 32) as u64;
            if block_size < 512 || block_size % 512 != 0 || entries == 0 || entries > (1 << 26) {
                return Err(DAMAGED.into());
            }
            let needed = size.div_ceil(block_size);
            if needed > entries {
                return Err(DAMAGED.into());
            }
            let mut raw = vec![0u8; entries as usize * 4];
            pread_exact(&file, table, &mut raw).map_err(|_| DAMAGED.to_string())?;
            let bat = raw.chunks_exact(4).map(|c| u32::from_be_bytes(c.try_into().unwrap())).collect();
            let bitmap_len = (block_size / 512).div_ceil(8).div_ceil(512) * 512;
            Ok((Arc::new(VhdDynamic { file, size, block_size, bitmap_len, bat, desc }), "vhd-dynamic"))
        }
        4 => Err(DIFFERENCING.into()),
        _ => Err(DAMAGED.into()),
    }
}

// ------------------------------------------------------------------------------------ VHDX

/// CRC-32C (Castagnoli), as VHDX headers and tables use.
pub(crate) fn crc32c(data: &[u8]) -> u32 {
    const fn table() -> [u32; 256] {
        let mut t = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 { 0x82F6_3B78 ^ (c >> 1) } else { c >> 1 };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    }
    static T: [u32; 256] = table();
    let mut c = !0u32;
    for &b in data {
        c = T[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

/// Checksum of a VHDX structure whose CRC field sits at bytes 4..8.
fn vhdx_crc_ok(b: &[u8]) -> bool {
    let mut c = b.to_vec();
    c[4..8].fill(0);
    crc32c(&c) == le32(b, 4)
}

/// A GUID in its on-disk (Windows, mixed-endian) byte order.
pub(crate) const fn guid_bytes(u: u128) -> [u8; 16] {
    let d1 = (u >> 96) as u32;
    let d2 = (u >> 80) as u16;
    let d3 = (u >> 64) as u16;
    let d4 = (u as u64).to_be_bytes();
    let a = d1.to_le_bytes();
    let b = d2.to_le_bytes();
    let c = d3.to_le_bytes();
    [a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]]
}

pub(crate) const BAT_REGION: [u8; 16] = guid_bytes(0x2DC27766_F623_4200_9D64_115E9BFD4A08);
pub(crate) const META_REGION: [u8; 16] = guid_bytes(0x8B7CA206_4790_4B9A_B8FE_575F050F886E);
pub(crate) const META_FILE_PARAMS: [u8; 16] = guid_bytes(0xCAA16737_FA36_4D43_B3B6_33F0AA44E76B);
pub(crate) const META_DISK_SIZE: [u8; 16] = guid_bytes(0x2FA54224_CD1B_4876_B211_5DBED83BF4B8);
pub(crate) const META_LOGICAL_SECTOR: [u8; 16] = guid_bytes(0x8141BF1D_A96F_4709_BA47_F233A8FAAB5F);

struct Vhdx {
    file: File,
    size: u64,
    block_size: u64,
    sector: u32,
    chunk_ratio: u64,
    bat: Vec<u64>,
    desc: String,
}

impl BlockSource for Vhdx {
    fn len(&self) -> u64 {
        self.size
    }
    fn sector_size(&self) -> u32 {
        self.sector
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.size - offset) as usize;
        let mut done = 0usize;
        while done < want {
            let pos = offset + done as u64;
            let idx = pos / self.block_size;
            let within = pos % self.block_size;
            let n = ((self.block_size - within) as usize).min(want - done);
            let out = &mut buf[done..done + n];
            let entry = self.bat.get((idx + idx / self.chunk_ratio) as usize).copied().unwrap_or(0);
            match entry & 7 {
                // FULLY_PRESENT (and PARTIALLY_PRESENT, which can't happen without a parent).
                6 | 7 => pread_exact(&self.file, (entry >> 20 << 20) + within, out)?,
                // NOT_PRESENT, UNDEFINED, ZERO, UNMAPPED
                _ => out.fill(0),
            }
            done += n;
        }
        Ok(done)
    }
    fn describe(&self) -> String {
        self.desc.clone()
    }
}

fn open_vhdx(file: File, desc: String) -> Result<(Source, &'static str, Option<String>), String> {
    let rd = |off: u64, len: usize| -> Result<Vec<u8>, String> {
        let mut b = vec![0u8; len];
        pread_exact(&file, off, &mut b).map_err(|_| DAMAGED.to_string())?;
        Ok(b)
    };
    // Headers at 64 KiB and 128 KiB: the valid one with the higher sequence number wins.
    let mut best: Option<Vec<u8>> = None;
    for off in [64 * 1024u64, 128 * 1024] {
        let h = rd(off, 4096)?;
        if &h[0..4] == b"head" && vhdx_crc_ok(&h) && best.as_ref().map_or(true, |b| le64(&h, 8) > le64(b, 8)) {
            best = Some(h);
        }
    }
    let header = best.ok_or_else(|| DAMAGED.to_string())?;
    let note = (header[48..64].iter().any(|&b| b != 0))
        .then(|| "This virtual disk wasn't closed cleanly, so its most recent changes may be missing.".to_string());

    // Region table (primary at 192 KiB, backup at 256 KiB).
    let mut regions = None;
    for off in [192 * 1024u64, 256 * 1024] {
        let r = rd(off, 64 * 1024)?;
        if &r[0..4] == b"regi" && vhdx_crc_ok(&r) {
            regions = Some(r);
            break;
        }
    }
    let r = regions.ok_or_else(|| DAMAGED.to_string())?;
    let (mut bat_at, mut meta_at) = (None, None);
    for i in 0..(le32(&r, 8) as usize).min(2047) {
        let e = &r[16 + i * 32..16 + i * 32 + 32];
        let at = (le64(e, 16), le32(e, 24) as u64);
        if e[0..16] == BAT_REGION {
            bat_at = Some(at);
        } else if e[0..16] == META_REGION {
            meta_at = Some(at);
        }
    }
    let (bat_off, bat_len) = bat_at.ok_or_else(|| DAMAGED.to_string())?;
    let (meta_off, meta_len) = meta_at.ok_or_else(|| DAMAGED.to_string())?;

    // Metadata table: file parameters, virtual disk size, logical sector size.
    let m = rd(meta_off, meta_len.clamp(64 * 1024, 4 << 20) as usize)?;
    if &m[0..8] != b"metadata" {
        return Err(DAMAGED.into());
    }
    let item = |id: &[u8; 16], len: usize| -> Option<&[u8]> {
        (0..le16(&m, 10) as usize).find_map(|i| {
            let e = m.get(32 + i * 32..64 + i * 32)?;
            if &e[0..16] != id {
                return None;
            }
            let o = le32(e, 16) as usize;
            m.get(o..o + len)
        })
    };
    let params = item(&META_FILE_PARAMS, 8).ok_or_else(|| DAMAGED.to_string())?;
    let block_size = le32(params, 0) as u64;
    if le32(params, 4) & 2 != 0 {
        return Err(DIFFERENCING.into());
    }
    let size = item(&META_DISK_SIZE, 8).map(|b| le64(b, 0)).ok_or_else(|| DAMAGED.to_string())?;
    let sector = item(&META_LOGICAL_SECTOR, 4).map(|b| le32(b, 0)).unwrap_or(512);
    if !(1 << 20..=256 << 20).contains(&block_size) || !block_size.is_power_of_two() || !(sector == 512 || sector == 4096) || size == 0 {
        return Err(DAMAGED.into());
    }
    let chunk_ratio = (1u64 << 23) * sector as u64 / block_size;
    let blocks = size.div_ceil(block_size);
    let entries = blocks + blocks.saturating_sub(1) / chunk_ratio + 1;
    let need = (entries * 8).min(bat_len);
    let raw = rd(bat_off, need as usize)?;
    let bat = raw.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
    Ok((Arc::new(Vhdx { file, size, block_size, sector, chunk_ratio, bat, desc }), "vhdx", note))
}

// ----------------------------------------------------------------------------------- opening

struct Opened {
    src: Source,
    format: &'static str,
    file_size: u64,
    note: Option<String>,
}

fn open_any(path: &str) -> Result<Opened, String> {
    let p = Path::new(path.trim());
    let meta = std::fs::metadata(p).map_err(|e| match e.raw_os_error() {
        Some(2) | Some(3) => "That image file doesn't exist anymore. Pick it again.".to_string(),
        Some(5) => "Windows didn't let MAX open that image file. Check that you can open it, then try again.".to_string(),
        _ => format!("Windows couldn't open that image file ({}). Pick it again.", short_io(&e)),
    })?;
    if meta.is_dir() {
        return Err("That is a folder, not a disk image. Pick an image file.".into());
    }
    let file = open_file(p)?;
    let file_len = meta.len();
    if file_len < 512 {
        return Err("That file is too small to be a disk image. Pick another file.".into());
    }
    let desc = file_name(p);

    let mut head = [0u8; 512];
    pread_exact(&file, 0, &mut head).map_err(|_| "Windows couldn't read that image file. Pick it again.".to_string())?;
    let mut tail = [0u8; 512];
    pread_exact(&file, file_len - 512, &mut tail).map_err(|_| "Windows couldn't read that image file. Pick it again.".to_string())?;

    if &head[0..8] == b"vhdxfile" {
        let (src, format, note) = open_vhdx(file, desc)?;
        return Ok(Opened { src, format, file_size: file_len, note });
    }
    // The footer sits at the end; dynamic disks also keep a copy at the start.
    if let Some(f) = vhd_footer(&tail).or_else(|| vhd_footer(&head).filter(|f| f.0 != 2)) {
        let (src, format) = open_vhd(file, file_len, f, desc)?;
        return Ok(Opened { src, format, file_size: file_len, note: None });
    }

    let set = split_set(p);
    if set.len() > 1 {
        let mut parts = Vec::with_capacity(set.len());
        let mut start = 0u64;
        for (i, sp) in set.iter().enumerate() {
            let f = if i == 0 { file.try_clone().map_err(|_| "Windows couldn't read that image file. Pick it again.".to_string())? } else { open_file(sp)? };
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            parts.push(Part { file: f, start, len });
            start += len;
        }
        let n = parts.len();
        let src: Source = Arc::new(RawImage { parts, len: start, desc: format!("{desc} (+{} parts)", n - 1) });
        return Ok(Opened { src, format: "raw", file_size: start, note: Some(format!("This image is split into {n} files; they are read as one disk.")) });
    }
    let src: Source = Arc::new(RawImage { parts: vec![Part { file, start: 0, len: file_len }], len: file_len, desc });
    Ok(Opened { src, format: "raw", file_size: file_len, note: None })
}

/// Open an image file read-only as a byte source of its virtual disk.
pub fn open_image_source(path: &str) -> Result<Source, String> {
    open_any(path).map(|o| o.src)
}

// -------------------------------------------------------------------------- partition tables

/// File system named by a volume boot sector, without the engines (fallback while they're stubs).
pub(crate) fn fs_from_boot_sector(b: &[u8]) -> Option<String> {
    if b.len() < 512 {
        return None;
    }
    if &b[3..11] == b"NTFS    " {
        return Some("NTFS".into());
    }
    if &b[3..11] == b"EXFAT   " {
        return Some("exFAT".into());
    }
    if &b[3..11] == b"-FVE-FS-" {
        return Some("BitLocker".into());
    }
    if b[510] != 0x55 || b[511] != 0xAA {
        return None;
    }
    if &b[82..87] == b"FAT32" {
        return Some("FAT32".into());
    }
    if &b[54..59] == b"FAT16" {
        return Some("FAT16".into());
    }
    if &b[54..59] == b"FAT12" {
        return Some("FAT12".into());
    }
    None
}

/// A volume boot sector rather than a master boot record: known OEM id or a plausible FAT BPB.
pub(crate) fn looks_like_vbr(b: &[u8]) -> bool {
    if b.len() < 512 {
        return false;
    }
    if fs_from_boot_sector(b).is_some() {
        return true;
    }
    let bps = u16::from_le_bytes([b[11], b[12]]);
    let spc = b[13];
    let reserved = u16::from_le_bytes([b[14], b[15]]);
    (b[0] == 0xEB || b[0] == 0xE9)
        && matches!(bps, 512 | 1024 | 2048 | 4096)
        && spc != 0
        && spc.is_power_of_two()
        && reserved >= 1
        && matches!(b[16], 1 | 2)
        && b[510] == 0x55
        && b[511] == 0xAA
}

fn guid_string(b: &[u8]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        le32(b, 0),
        le16(b, 4),
        le16(b, 6),
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

/// Display name for a partition type (GPT type GUID or MBR type byte).
pub(crate) fn partition_type_name(gpt: Option<&str>, mbr: Option<u8>) -> String {
    let guid = gpt.unwrap_or("").trim().trim_matches(|c| c == '{' || c == '}').to_ascii_lowercase();
    if !guid.is_empty() {
        return match guid.as_str() {
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" => "EFI system",
            "e3c9e316-0b5c-4db8-817d-f92df00215ae" => "Microsoft reserved",
            "de94bba4-06d1-4d40-a16a-bfd50179d6ac" => "Recovery",
            "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" => "Basic data",
            "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3" => "Dynamic (metadata)",
            "af9b60a0-1431-4f62-bc68-3311714a69ad" => "Dynamic (data)",
            "e75caf8f-f680-4cee-afa3-b001e56efc2d" => "Storage Spaces",
            "0fc63daf-8483-4772-8e79-3d69d8477de4" => "Linux",
            "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f" => "Linux swap",
            "e6d6d379-f507-44c2-a23c-238f2a3df928" => "Linux LVM",
            "48465300-0000-11aa-aa11-00306543ecac" => "Apple HFS+",
            "7c3457ef-0000-11aa-aa11-00306543ecac" => "Apple APFS",
            "21686148-6449-6e6f-744e-656564454649" => "BIOS boot",
            "00000000-0000-0000-0000-000000000000" => "Unused",
            _ => "Other",
        }
        .into();
    }
    match mbr {
        Some(0x07) => "Basic data",
        Some(0x01) | Some(0x04) | Some(0x06) | Some(0x0E) => "FAT",
        Some(0x0B) | Some(0x0C) => "FAT32",
        Some(0x05) | Some(0x0F) | Some(0x85) => "Extended",
        Some(0x27) => "Recovery",
        Some(0xEF) => "EFI system",
        Some(0x42) => "Dynamic (data)",
        Some(0x83) => "Linux",
        Some(0x82) => "Linux swap",
        Some(0x8E) => "Linux LVM",
        Some(0x11) | Some(0x14) | Some(0x16) | Some(0x17) | Some(0x1B) | Some(0x1C) | Some(0x1E) => "Hidden",
        Some(0xEE) => "GPT protective",
        Some(_) => "Other",
        None => "Unknown",
    }
    .into()
}

fn is_extended(t: u8) -> bool {
    matches!(t, 0x05 | 0x0F | 0x85)
}

/// Read the MBR/GPT of a disk or image without the partitions module: (style, partitions).
pub(crate) fn parse_tables(src: &dyn BlockSource) -> (String, Vec<PartitionInfo>) {
    let mut s0 = [0u8; 512];
    if !matches!(super::source::read_full(src, 0, &mut s0), Ok(512)) {
        return ("Unknown".into(), Vec::new());
    }
    for ss in [512u64, 4096] {
        let mut h = [0u8; 512];
        if matches!(super::source::read_full(src, ss, &mut h), Ok(512)) && &h[0..8] == b"EFI PART" {
            return ("GPT".into(), parse_gpt(src, &h, ss));
        }
    }
    if looks_like_vbr(&s0) {
        return ("None".into(), Vec::new());
    }
    if s0[510] == 0x55 && s0[511] == 0xAA && (0..4).all(|i| matches!(s0[446 + i * 16], 0x00 | 0x80)) {
        return ("MBR".into(), parse_mbr(src, &s0));
    }
    ("Unknown".into(), Vec::new())
}

fn parse_gpt(src: &dyn BlockSource, h: &[u8], ss: u64) -> Vec<PartitionInfo> {
    let entries_lba = le64(h, 72);
    let count = le32(h, 80).min(1024) as u64;
    let esize = le32(h, 84) as u64;
    if esize < 128 || esize > 4096 {
        return Vec::new();
    }
    let mut buf = vec![0u8; (count * esize) as usize];
    let n = super::source::read_full(src, entries_lba * ss, &mut buf).unwrap_or(0);
    let mut out = Vec::new();
    for i in 0..count {
        let o = (i * esize) as usize;
        if o + 128 > n {
            break;
        }
        let e = &buf[o..o + 128];
        if e[0..16].iter().all(|&b| b == 0) {
            continue;
        }
        let (first, last) = (le64(e, 32), le64(e, 40));
        if last < first {
            continue;
        }
        let name: Vec<u16> = e[56..128].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
        let name = String::from_utf16_lossy(&name);
        out.push(PartitionInfo {
            number: i as u32 + 1,
            offset: first * ss,
            size: (last - first + 1) * ss,
            type_name: partition_type_name(Some(&guid_string(&e[0..16])), None),
            letter: None,
            fs: None,
            label: (!name.trim().is_empty()).then(|| name.trim().to_string()),
        });
    }
    out
}

fn parse_mbr(src: &dyn BlockSource, s0: &[u8]) -> Vec<PartitionInfo> {
    let mut out = Vec::new();
    let mut ext: Option<u64> = None;
    for i in 0..4 {
        let e = &s0[446 + i * 16..462 + i * 16];
        let (t, start, sectors) = (e[4], le32(e, 8) as u64, le32(e, 12) as u64);
        if t == 0 || sectors == 0 {
            continue;
        }
        if is_extended(t) && ext.is_none() {
            ext = Some(start);
        }
        out.push(PartitionInfo { number: i as u32 + 1, offset: start * 512, size: sectors * 512, type_name: partition_type_name(None, Some(t)), ..Default::default() });
    }
    // Logical partitions: the EBR chain inside the extended partition.
    if let Some(base) = ext {
        let mut ebr = base;
        let mut number = 5;
        for _ in 0..128 {
            let mut b = [0u8; 512];
            if !matches!(super::source::read_full(src, ebr * 512, &mut b), Ok(512)) || b[510] != 0x55 || b[511] != 0xAA {
                break;
            }
            let e = &b[446..462];
            let (t, start, sectors) = (e[4], le32(e, 8) as u64, le32(e, 12) as u64);
            if t != 0 && sectors != 0 {
                out.push(PartitionInfo { number, offset: (ebr + start) * 512, size: sectors * 512, type_name: partition_type_name(None, Some(t)), ..Default::default() });
                number += 1;
            }
            let next = &b[462..478];
            let rel = le32(next, 8) as u64;
            if next[4] == 0 || rel == 0 || base + rel <= ebr {
                break;
            }
            ebr = base + rel;
        }
    }
    out
}

/// fs + label of a partition window, through the engines when they recognise it.
fn probe_window(src: &Source, offset: u64, size: u64) -> (Option<String>, Option<String>) {
    let w = SubSource { inner: src.clone(), offset, len: size.min(src.len().saturating_sub(offset)) };
    if let Some(p) = crate::fs::probe_any(&w) {
        return (Some(p.fs), (!p.label.is_empty()).then_some(p.label));
    }
    let mut b = [0u8; 512];
    if matches!(super::source::read_full(&w, 0, &mut b), Ok(512)) {
        return (fs_from_boot_sector(&b), None);
    }
    (None, None)
}

/// Partition style and partitions of any source (image, disk window), filling fs/label.
pub(crate) fn describe_layout(src: &Source) -> (String, Option<String>, Vec<PartitionInfo>) {
    let (style, mut parts) = match crate::partitions::analyze(src.as_ref()) {
        Ok(rep) if rep.style != "None" || rep.entries.is_empty() => {
            let parts = rep
                .entries
                .iter()
                .filter(|e| e.status != "lost")
                .enumerate()
                .map(|(i, e)| PartitionInfo {
                    number: e.number.unwrap_or(i as u32 + 1),
                    offset: e.offset,
                    size: e.size,
                    type_name: e.type_name.clone(),
                    letter: None,
                    fs: e.fs.clone(),
                    label: e.label.clone(),
                })
                .collect();
            (rep.style, parts)
        }
        _ => parse_tables(src.as_ref()),
    };
    if style == "None" {
        let (fs, _) = probe_window(src, 0, src.len());
        return (style, fs, Vec::new());
    }
    for p in parts.iter_mut().filter(|p| p.type_name != "Extended" && p.type_name != "GPT protective") {
        if p.fs.is_none() {
            let (fs, label) = probe_window(src, p.offset, p.size);
            p.fs = fs;
            // The volume label beats the GPT partition name ("Basic data partition").
            if label.is_some() {
                p.label = label;
            }
        }
    }
    (style, None, parts)
}

fn image_info(path: &str) -> Result<ImageInfo, String> {
    let o = open_any(path)?;
    let (style, fs, partitions) = describe_layout(&o.src);
    Ok(ImageInfo {
        path: path.to_string(),
        size: o.src.len(),
        file_size: o.file_size,
        format: o.format.into(),
        partition_style: style,
        fs,
        partitions,
        sector_size: Some(o.src.sector_size()),
        note: o.note,
    })
}

/// Validate an image file the user picked and describe it.
#[tauri::command]
pub async fn open_image(path: String) -> Result<ImageInfo, String> {
    tauri::async_runtime::spawn_blocking(move || image_info(&path)).await.map_err(|_| "Reading the image stopped unexpectedly.".to_string())?
}

// ------------------------------------------------------------------------------------- tests

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    /// A unique file under %TEMP%, removed on drop.
    pub(crate) struct TempFile(pub PathBuf);
    impl TempFile {
        pub(crate) fn new(ext: &str) -> TempFile {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let name = format!("maxrec-dev-{}-{}-{}.{ext}", std::process::id(), crate::model::now_ms(), N.fetch_add(1, Ordering::Relaxed));
            TempFile(std::env::temp_dir().join(name))
        }
        pub(crate) fn path(&self) -> String {
            self.0.to_string_lossy().into_owned()
        }
    }
    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn pattern(len: usize, seed: u32) -> Vec<u8> {
        let mut x = seed.wrapping_mul(2654435761) | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    }

    fn read_all(src: &dyn BlockSource) -> Vec<u8> {
        let mut v = vec![0u8; src.len() as usize];
        // Odd-sized, unaligned reads to exercise block boundaries.
        let mut pos = 0usize;
        let mut step = 777usize;
        while pos < v.len() {
            let n = step.min(v.len() - pos);
            assert_eq!(src.read_at(pos as u64, &mut v[pos..pos + n]).unwrap(), n);
            pos += n;
            step = step * 3 % 300_007 + 1;
        }
        v
    }

    fn footer(disk_type: u32, size: u64, data_offset: u64) -> [u8; 512] {
        let mut f = [0u8; 512];
        f[0..8].copy_from_slice(b"conectix");
        f[8..12].copy_from_slice(&2u32.to_be_bytes());
        f[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        f[16..24].copy_from_slice(&data_offset.to_be_bytes());
        f[40..48].copy_from_slice(&size.to_be_bytes());
        f[48..56].copy_from_slice(&size.to_be_bytes());
        f[60..64].copy_from_slice(&disk_type.to_be_bytes());
        let sum: u32 = f.iter().map(|&b| b as u32).sum();
        f[64..68].copy_from_slice(&(!sum).to_be_bytes());
        f
    }

    /// A small MBR disk image: one FAT32-labelled partition at 1 MiB.
    fn mbr_disk(len: usize) -> Vec<u8> {
        let mut d = pattern(len, 7);
        d[..512].fill(0);
        let e = &mut d[446..462];
        e[4] = 0x0C;
        e[8..12].copy_from_slice(&2048u32.to_le_bytes());
        e[12..16].copy_from_slice(&(((len - (1 << 20)) / 512) as u32).to_le_bytes());
        d[510] = 0x55;
        d[511] = 0xAA;
        d
    }

    #[test]
    fn raw_and_split_images_read_back() {
        let data = mbr_disk(3 << 20);
        let t = TempFile::new("img");
        std::fs::write(&t.0, &data).unwrap();
        let src = open_image_source(&t.path()).unwrap();
        assert_eq!(src.len(), data.len() as u64);
        assert_eq!(read_all(src.as_ref()), data);
        let info = image_info(&t.path()).unwrap();
        assert_eq!((info.format.as_str(), info.partition_style.as_str()), ("raw", "MBR"));
        assert_eq!(info.partitions.len(), 1);
        assert_eq!((info.partitions[0].offset, info.partitions[0].type_name.as_str()), (1 << 20, "FAT32"));

        // Split set: .001 + .002 + .003 of uneven sizes.
        let base = TempFile::new("x");
        let p1 = TempFile(base.0.with_extension("001"));
        let p2 = TempFile(base.0.with_extension("002"));
        let p3 = TempFile(base.0.with_extension("003"));
        std::fs::write(&p1.0, &data[..1_000_000]).unwrap();
        std::fs::write(&p2.0, &data[1_000_000..2_500_000]).unwrap();
        std::fs::write(&p3.0, &data[2_500_000..]).unwrap();
        let src = open_image_source(&p1.path()).unwrap();
        assert_eq!(src.len(), data.len() as u64);
        assert_eq!(read_all(src.as_ref()), data);
        assert!(image_info(&p1.path()).unwrap().note.unwrap().contains("3 files"));
    }

    #[test]
    fn fixed_vhd_reads_back() {
        let data = mbr_disk(2 << 20);
        let t = TempFile::new("vhd");
        let mut f = File::create(&t.0).unwrap();
        f.write_all(&data).unwrap();
        f.write_all(&footer(2, data.len() as u64, u64::MAX)).unwrap();
        drop(f);
        let src = open_image_source(&t.path()).unwrap();
        assert_eq!(src.len(), data.len() as u64);
        assert_eq!(read_all(src.as_ref()), data);
        let info = image_info(&t.path()).unwrap();
        assert_eq!(info.format, "vhd-fixed");
        assert_eq!(info.file_size, data.len() as u64 + 512);
        assert_eq!(info.partition_style, "MBR");
    }

    #[test]
    fn dynamic_vhd_reads_back_with_holes_and_bitmaps() {
        const BS: usize = 2 << 20;
        let size = 2 * BS as u64; // block 0 allocated, block 1 not
        let data0 = pattern(BS, 3);
        let mut expected = data0.clone();
        expected.resize(2 * BS, 0);
        // Sector bitmap: every sector present except sectors 5 and 4095.
        let mut bitmap = vec![0xFFu8; 512];
        bitmap[0] &= !(0x80 >> 5);
        bitmap[511] &= !1;
        expected[5 * 512..6 * 512].fill(0);
        expected[4095 * 512..4096 * 512].fill(0);

        let mut file = Vec::new();
        file.extend_from_slice(&footer(3, size, 512));
        let mut dh = [0u8; 1024];
        dh[0..8].copy_from_slice(b"cxsparse");
        dh[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        dh[16..24].copy_from_slice(&1536u64.to_be_bytes());
        dh[24..28].copy_from_slice(&0x0001_0000u32.to_be_bytes());
        dh[28..32].copy_from_slice(&2u32.to_be_bytes());
        dh[32..36].copy_from_slice(&(BS as u32).to_be_bytes());
        file.extend_from_slice(&dh);
        let mut bat = [0xFFu8; 512];
        bat[0..4].copy_from_slice(&4u32.to_be_bytes()); // block 0 at sector 4 (byte 2048)
        file.extend_from_slice(&bat);
        assert_eq!(file.len(), 2048);
        file.extend_from_slice(&bitmap);
        file.extend_from_slice(&data0);
        file.extend_from_slice(&footer(3, size, 512));
        let t = TempFile::new("vhd");
        std::fs::write(&t.0, &file).unwrap();

        let src = open_image_source(&t.path()).unwrap();
        assert_eq!(src.len(), size);
        let got = read_all(src.as_ref());
        assert!(got == expected, "dynamic VHD content differs");
        // A read spanning both blocks.
        let mut b = vec![1u8; 8192];
        assert_eq!(src.read_at(BS as u64 - 4096, &mut b).unwrap(), 8192);
        assert_eq!(&b[..4096], &expected[BS - 4096..BS]);
        assert!(b[4096..].iter().all(|&x| x == 0));
        assert_eq!(image_info(&t.path()).unwrap().format, "vhd-dynamic");

        // Differencing is refused.
        let mut d = file.clone();
        let n = d.len();
        d[n - 512..].copy_from_slice(&footer(4, size, 512));
        d[..512].copy_from_slice(&footer(4, size, 512));
        let t2 = TempFile::new("vhd");
        std::fs::write(&t2.0, &d).unwrap();
        assert_eq!(open_image_source(&t2.path()).err().unwrap(), DIFFERENCING);
    }

    /// A minimal VHDX: 3 MiB virtual disk, 1 MiB blocks: block 0 present, 1 not present, 2 zero-state.
    pub(crate) fn build_vhdx(block0: &[u8], has_parent: bool) -> Vec<u8> {
        const MB: usize = 1 << 20;
        let mut f = vec![0u8; 4 * MB];
        f[0..8].copy_from_slice(b"vhdxfile");
        for (i, off) in [64 * 1024usize, 128 * 1024].into_iter().enumerate() {
            let h = &mut f[off..off + 4096];
            h[0..4].copy_from_slice(b"head");
            h[8..16].copy_from_slice(&(10 + i as u64).to_le_bytes());
            h[66..68].copy_from_slice(&1u16.to_le_bytes());
            let c = crc32c(h);
            h[4..8].copy_from_slice(&c.to_le_bytes());
        }
        for off in [192 * 1024usize, 256 * 1024] {
            let r = &mut f[off..off + 64 * 1024];
            r[0..4].copy_from_slice(b"regi");
            r[8..12].copy_from_slice(&2u32.to_le_bytes());
            r[16..32].copy_from_slice(&BAT_REGION);
            r[32..40].copy_from_slice(&(2 * MB as u64).to_le_bytes());
            r[40..44].copy_from_slice(&(MB as u32).to_le_bytes());
            r[44..48].copy_from_slice(&1u32.to_le_bytes());
            r[48..64].copy_from_slice(&META_REGION);
            r[64..72].copy_from_slice(&(MB as u64).to_le_bytes());
            r[72..76].copy_from_slice(&(MB as u32).to_le_bytes());
            r[76..80].copy_from_slice(&1u32.to_le_bytes());
            let c = crc32c(r);
            r[4..8].copy_from_slice(&c.to_le_bytes());
        }
        // Metadata region at 1 MiB, items at +64 KiB.
        let m = &mut f[MB..2 * MB];
        m[0..8].copy_from_slice(b"metadata");
        m[10..12].copy_from_slice(&3u16.to_le_bytes());
        let items: [(&[u8; 16], u32, Vec<u8>); 3] = [
            (&META_FILE_PARAMS, 65536, [(MB as u32).to_le_bytes(), (if has_parent { 2u32 } else { 0 }).to_le_bytes()].concat()),
            (&META_DISK_SIZE, 65536 + 8, (3 * MB as u64).to_le_bytes().to_vec()),
            (&META_LOGICAL_SECTOR, 65536 + 16, 512u32.to_le_bytes().to_vec()),
        ];
        for (i, (id, off, val)) in items.iter().enumerate() {
            let e = &mut m[32 + i * 32..64 + i * 32];
            e[0..16].copy_from_slice(*id);
            e[16..20].copy_from_slice(&off.to_le_bytes());
            e[20..24].copy_from_slice(&(val.len() as u32).to_le_bytes());
            m[*off as usize..*off as usize + val.len()].copy_from_slice(val);
        }
        // BAT at 2 MiB: block 0 FULLY_PRESENT at 3 MiB, block 1 NOT_PRESENT, block 2 ZERO.
        let bat = &mut f[2 * MB..3 * MB];
        bat[0..8].copy_from_slice(&((3u64 << 20) | 6).to_le_bytes());
        bat[16..24].copy_from_slice(&2u64.to_le_bytes());
        f[3 * MB..4 * MB].copy_from_slice(block0);
        f
    }

    #[test]
    fn vhdx_reads_back() {
        const MB: usize = 1 << 20;
        let mut block0 = mbr_disk(MB);
        block0[446 + 12..446 + 16].copy_from_slice(&2048u32.to_le_bytes()); // 1 MiB partition at 1 MiB
        let t = TempFile::new("vhdx");
        std::fs::write(&t.0, build_vhdx(&block0, false)).unwrap();
        let src = open_image_source(&t.path()).unwrap();
        assert_eq!(src.len(), 3 * MB as u64);
        let mut expected = block0.clone();
        expected.resize(3 * MB, 0);
        assert!(read_all(src.as_ref()) == expected, "VHDX content differs");
        let info = image_info(&t.path()).unwrap();
        assert_eq!((info.format.as_str(), info.partition_style.as_str(), info.sector_size), ("vhdx", "MBR", Some(512)));

        // Corrupt the newer header: the older one is used. Corrupt both: damaged.
        let mut f = build_vhdx(&block0, false);
        f[128 * 1024 + 100] ^= 1;
        std::fs::write(&t.0, &f).unwrap();
        assert!(open_image_source(&t.path()).is_ok());
        f[64 * 1024 + 100] ^= 1;
        std::fs::write(&t.0, &f).unwrap();
        assert_eq!(open_image_source(&t.path()).err().unwrap(), DAMAGED);

        std::fs::write(&t.0, build_vhdx(&block0, true)).unwrap();
        assert_eq!(open_image_source(&t.path()).err().unwrap(), DIFFERENCING);
    }

    #[test]
    fn tables_and_boot_sectors() {
        // Bare NTFS volume.
        let mut v = vec![0u8; 1 << 20];
        v[0] = 0xEB;
        v[3..11].copy_from_slice(b"NTFS    ");
        v[510] = 0x55;
        v[511] = 0xAA;
        let src: Source = Arc::new(super::super::source::MemSource::new(v));
        let (style, fs, parts) = describe_layout(&src);
        assert_eq!((style.as_str(), fs.as_deref(), parts.len()), ("None", Some("NTFS"), 0));

        // GPT with two entries (512-byte sectors).
        let mut d = vec![0u8; 4 << 20];
        d[446 + 4] = 0xEE;
        d[510] = 0x55;
        d[511] = 0xAA;
        d[512..520].copy_from_slice(b"EFI PART");
        d[512 + 72..512 + 80].copy_from_slice(&2u64.to_le_bytes());
        d[512 + 80..512 + 84].copy_from_slice(&128u32.to_le_bytes());
        d[512 + 84..512 + 88].copy_from_slice(&128u32.to_le_bytes());
        let e = &mut d[1024..1152];
        e[0..16].copy_from_slice(&guid_bytes(0xC12A7328_F81F_11D2_BA4B_00A0C93EC93B));
        e[16] = 1;
        e[32..40].copy_from_slice(&2048u64.to_le_bytes());
        e[40..48].copy_from_slice(&4095u64.to_le_bytes());
        for (i, c) in "EFI".encode_utf16().enumerate() {
            e[56 + i * 2..58 + i * 2].copy_from_slice(&c.to_le_bytes());
        }
        let e = &mut d[1152..1280];
        e[0..16].copy_from_slice(&guid_bytes(0xEBD0A0A2_B9E5_4433_87C0_68B6B72699C7));
        e[16] = 2;
        e[32..40].copy_from_slice(&4096u64.to_le_bytes());
        e[40..48].copy_from_slice(&8000u64.to_le_bytes());
        d[4096 * 512 + 3..4096 * 512 + 11].copy_from_slice(b"EXFAT   ");
        // Valid CRCs: partitions::analyze rejects a GPT whose header or entry array fails its CRC32.
        d[512 + 12..512 + 16].copy_from_slice(&92u32.to_le_bytes());
        d[512 + 24..512 + 32].copy_from_slice(&1u64.to_le_bytes()); // my LBA
        d[512 + 32..512 + 40].copy_from_slice(&8191u64.to_le_bytes()); // backup LBA
        d[512 + 40..512 + 48].copy_from_slice(&34u64.to_le_bytes()); // first usable
        d[512 + 48..512 + 56].copy_from_slice(&8158u64.to_le_bytes()); // last usable
        let ecrc = crc32fast::hash(&d[1024..1024 + 128 * 128]);
        d[512 + 88..512 + 92].copy_from_slice(&ecrc.to_le_bytes());
        let hcrc = crc32fast::hash(&d[512..512 + 92]);
        d[512 + 16..512 + 20].copy_from_slice(&hcrc.to_le_bytes());
        let src: Source = Arc::new(super::super::source::MemSource::new(d));
        let (style, _, parts) = describe_layout(&src);
        assert_eq!(style, "GPT");
        assert_eq!(parts.len(), 2);
        assert_eq!((parts[0].type_name.as_str(), parts[0].label.as_deref(), parts[0].offset, parts[0].size), ("EFI system", Some("EFI"), 1 << 20, 1 << 20));
        assert_eq!((parts[1].type_name.as_str(), parts[1].fs.as_deref(), parts[1].number), ("Basic data", Some("exFAT"), 2));

        // MBR with an extended partition holding two logical drives.
        let mut d = vec![0u8; 8 << 20];
        let put = |d: &mut Vec<u8>, at: usize, t: u8, start: u32, n: u32| {
            d[at + 4] = t;
            d[at + 8..at + 12].copy_from_slice(&start.to_le_bytes());
            d[at + 12..at + 16].copy_from_slice(&n.to_le_bytes());
        };
        put(&mut d, 446, 0x07, 2048, 2048);
        put(&mut d, 462, 0x0F, 4096, 8192);
        d[510] = 0x55;
        d[511] = 0xAA;
        let ebr1 = 4096 * 512;
        put(&mut d, ebr1 + 446, 0x07, 2048, 1024);
        put(&mut d, ebr1 + 462, 0x05, 4096, 4096);
        d[ebr1 + 510] = 0x55;
        d[ebr1 + 511] = 0xAA;
        let ebr2 = (4096 + 4096) * 512;
        put(&mut d, ebr2 + 446, 0x0B, 2048, 1024);
        d[ebr2 + 510] = 0x55;
        d[ebr2 + 511] = 0xAA;
        let src: Source = Arc::new(super::super::source::MemSource::new(d));
        let (style, parts) = parse_tables(src.as_ref());
        assert_eq!(style, "MBR");
        let got: Vec<(u32, u64, &str)> = parts.iter().map(|p| (p.number, p.offset / 512, p.type_name.as_str())).collect();
        assert_eq!(got, vec![(1, 2048, "Basic data"), (2, 4096, "Extended"), (5, 6144, "Basic data"), (6, 10240, "FAT32")]);
    }

    #[test]
    fn missing_and_odd_files_explain_themselves() {
        let e = open_image_source(r"C:\definitely\not\here.img").err().unwrap();
        assert!(e.contains("doesn't exist"), "{e}");
        let e = open_image_source(&std::env::temp_dir().to_string_lossy()).err().unwrap();
        assert!(e.contains("folder"), "{e}");
        let t = TempFile::new("img");
        std::fs::write(&t.0, [1u8; 100]).unwrap();
        assert!(open_image_source(&t.path()).err().unwrap().contains("too small"));
    }

    #[test]
    fn crc32c_known_value() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }
}
