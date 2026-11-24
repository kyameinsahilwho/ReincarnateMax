//! Read-only byte sources (owned by the orchestrator; the Windows/image openers live in sibling
//! modules owned by the device agent). Nothing in this crate ever opens a source for writing.

use crate::model::{MapKind, ScanCtx, SourceKind, SourceRef};
use std::sync::Arc;

/// A read-only, random-access byte device: a volume, a physical disk, an image file, a window on one
/// of those. Implementations must be safe to read from many threads at once.
pub trait BlockSource: Send + Sync {
    /// Size in bytes.
    fn len(&self) -> u64;
    /// Logical sector size (512 or 4096). Reads below are byte-addressed; implementations handle
    /// alignment internally.
    fn sector_size(&self) -> u32;
    /// Read up to `buf.len()` bytes at `offset`. Returns bytes read (short only at the end of the
    /// source). An `Err` means the range (or part of it) is unreadable.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize>;
    /// Short human description ("Disk 0 - INTEL SSDPEKNU512GZ", "C: (NTFS)", "card.img").
    fn describe(&self) -> String;
}

pub type Source = Arc<dyn BlockSource>;

/// Read exactly `buf.len()` bytes (fewer only at the end of the source).
pub fn read_full(src: &dyn BlockSource, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        let n = src.read_at(offset + got as u64, &mut buf[got..])?;
        if n == 0 {
            break;
        }
        got += n;
    }
    Ok(got)
}

/// Read a range, tolerating bad sectors: on an error the range is retried sector by sector (twice),
/// unreadable sectors are left zero-filled, marked [`MapKind::Bad`] in `ctx` (if given) and returned
/// as ranges. Returns (bytes read, bad ranges).
pub fn read_tolerant(src: &dyn BlockSource, offset: u64, buf: &mut [u8], ctx: Option<&ScanCtx>) -> (usize, Vec<(u64, u64)>) {
    let want = (buf.len() as u64).min(src.len().saturating_sub(offset)) as usize;
    if want == 0 {
        return (0, Vec::new());
    }
    if let Ok(n) = read_full(src, offset, &mut buf[..want]) {
        if n == want {
            return (n, Vec::new());
        }
    }
    let ss = src.sector_size().max(512) as usize;
    let mut bad: Vec<(u64, u64)> = Vec::new();
    let mut pos = 0usize;
    while pos < want {
        // Sector-aligned piece.
        let abs = offset + pos as u64;
        let to_boundary = ss - (abs % ss as u64) as usize;
        let len = to_boundary.min(want - pos);
        let piece = &mut buf[pos..pos + len];
        let mut ok = false;
        for _ in 0..2 {
            if let Ok(n) = read_full(src, abs, piece) {
                if n == len {
                    ok = true;
                    break;
                }
            }
        }
        if !ok {
            piece.fill(0);
            match bad.last_mut() {
                Some(last) if last.1 == abs => last.1 = abs + len as u64,
                _ => bad.push((abs, abs + len as u64)),
            }
        }
        pos += len;
    }
    if let Some(ctx) = ctx {
        for &(s, e) in &bad {
            ctx.mark(MapKind::Bad, s, e - s);
        }
    }
    (want, bad)
}

/// A window [offset, offset+len) on another source: a partition inside a disk or an image.
pub struct SubSource {
    pub inner: Source,
    pub offset: u64,
    pub len: u64,
}

impl BlockSource for SubSource {
    fn len(&self) -> u64 {
        self.len
    }
    fn sector_size(&self) -> u32 {
        self.inner.sector_size()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(self.len - offset) as usize;
        self.inner.read_at(self.offset + offset, &mut buf[..n])
    }
    fn describe(&self) -> String {
        format!("{} (from byte {})", self.inner.describe(), self.offset)
    }
}

/// An in-memory source for tests (and for small embedded images).
pub struct MemSource {
    pub data: Vec<u8>,
    pub sector: u32,
    /// Byte ranges that fail to read, to test bad-sector handling.
    pub bad: Vec<(u64, u64)>,
}

impl MemSource {
    pub fn new(data: Vec<u8>) -> Self {
        MemSource { data, sector: 512, bad: Vec::new() }
    }
}

impl BlockSource for MemSource {
    fn len(&self) -> u64 {
        self.data.len() as u64
    }
    fn sector_size(&self) -> u32 {
        self.sector
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = self.data.len() as u64;
        if offset >= len {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(len - offset) as usize;
        let end = offset + n as u64;
        if self.bad.iter().any(|&(s, e)| s < end && offset < e) {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "bad sector"));
        }
        buf[..n].copy_from_slice(&self.data[offset as usize..offset as usize + n]);
        Ok(n)
    }
    fn describe(&self) -> String {
        format!("memory ({} bytes)", self.data.len())
    }
}

/// Open any [`SourceRef`] read-only, applying its offset/length window.
pub fn open_source(r: &SourceRef) -> Result<Source, String> {
    let base: Source = match r.kind {
        SourceKind::Volume => super::win::open_volume(&r.path)?,
        SourceKind::Disk => super::win::open_disk(&r.path)?,
        SourceKind::Snapshot => super::win::open_snapshot(&r.path)?,
        SourceKind::Image => super::image::open_image_source(&r.path)?,
    };
    window(base, r.offset, r.length)
}

/// Narrow a source to [offset, offset+length).
pub fn window(base: Source, offset: u64, length: Option<u64>) -> Result<Source, String> {
    if offset == 0 && length.map_or(true, |l| l == base.len()) {
        return Ok(base);
    }
    let total = base.len();
    if offset >= total {
        return Err("That partition starts beyond the end of the drive. Pick another partition.".into());
    }
    let len = length.unwrap_or(total - offset).min(total - offset);
    Ok(Arc::new(SubSource { inner: base, offset, len }))
}

// ------------------------------------------------------------------------------- raw hex view

#[derive(serde::Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct RawBytes {
    pub offset: u64,
    /// Base64 of the bytes read (unreadable sectors are zeros, listed in `bad`).
    pub data: String,
    pub source_len: u64,
    pub sector_size: u32,
    pub bad: Vec<(u64, u64)>,
}

/// Raw bytes of a source for the hex viewer and the Recovery Map inspector. At most 64 KiB.
#[tauri::command]
pub async fn read_sectors(source: SourceRef, offset: u64, length: u32) -> Result<RawBytes, String> {
    use base64::Engine;
    tauri::async_runtime::spawn_blocking(move || {
        let src = open_source(&source)?;
        let len = (length.min(64 * 1024) as u64).min(src.len().saturating_sub(offset)) as usize;
        let mut buf = vec![0u8; len];
        let (n, bad) = read_tolerant(src.as_ref(), offset, &mut buf, None);
        buf.truncate(n);
        Ok(RawBytes {
            offset,
            data: base64::engine::general_purpose::STANDARD.encode(&buf),
            source_len: src.len(),
            sector_size: src.sector_size(),
            bad,
        })
    })
    .await
    .map_err(|_| "Reading the drive stopped unexpectedly.".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ScanOptions;

    #[test]
    fn tolerant_read_zero_fills_and_marks_bad_sectors() {
        let mut m = MemSource::new((0..8192u32).map(|i| (i % 251) as u8 + 1).collect());
        m.bad = vec![(1024, 1536)];
        let (ctx, t) = ScanCtx::for_test(ScanOptions::default(), 8192);
        let mut buf = vec![0u8; 4096];
        let (n, bad) = read_tolerant(&m, 0, &mut buf, Some(&ctx));
        assert_eq!(n, 4096);
        assert_eq!(bad, vec![(1024, 1536)]);
        assert!(buf[1024..1536].iter().all(|&b| b == 0));
        assert!(buf[1536] != 0 && buf[1023] != 0);
        assert_eq!(t.ranges.lock().unwrap()[0], (MapKind::Bad, 1024, 1536));
    }

    #[test]
    fn windows_clip_reads() {
        let m: Source = Arc::new(MemSource::new((0..4096u32).map(|i| (i / 16) as u8).collect()));
        let w = window(m, 1024, Some(1024)).unwrap();
        assert_eq!(w.len(), 1024);
        let mut b = [0u8; 16];
        assert_eq!(w.read_at(0, &mut b).unwrap(), 16);
        assert_eq!(b[0], 64);
        assert_eq!(w.read_at(1020, &mut b).unwrap(), 4);
    }
}
