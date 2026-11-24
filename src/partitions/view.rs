//! Borrowed views on a source: a window (a partition inside a disk), and a window whose first bytes
//! are replaced (to probe a partition through its backup boot sector).

use crate::device::source::BlockSource;

pub(crate) struct Win<'a> {
    pub inner: &'a dyn BlockSource,
    pub off: u64,
    pub len: u64,
}

impl<'a> Win<'a> {
    pub fn new(inner: &'a dyn BlockSource, off: u64, len: u64) -> Self {
        let avail = inner.len().saturating_sub(off);
        Win { inner, off, len: len.min(avail) }
    }
}

impl BlockSource for Win<'_> {
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
        self.inner.read_at(self.off + offset, &mut buf[..n])
    }
    fn describe(&self) -> String {
        format!("{} (from byte {})", self.inner.describe(), self.off)
    }
}

/// `inner` with its first `patch.len()` bytes replaced.
pub(crate) struct Patched<'a> {
    pub inner: &'a dyn BlockSource,
    pub patch: Vec<u8>,
}

impl BlockSource for Patched<'_> {
    fn len(&self) -> u64 {
        self.inner.len()
    }
    fn sector_size(&self) -> u32 {
        self.inner.sector_size()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let plen = self.patch.len() as u64;
        let total = self.inner.len();
        if offset >= total || buf.is_empty() {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(total - offset) as usize;
        if offset < plen {
            let k = ((plen - offset) as usize).min(want);
            buf[..k].copy_from_slice(&self.patch[offset as usize..offset as usize + k]);
            if k == want {
                return Ok(k);
            }
            let n = crate::device::source::read_full(self.inner, offset + k as u64, &mut buf[k..want])?;
            return Ok(k + n);
        }
        self.inner.read_at(offset, &mut buf[..want])
    }
    fn describe(&self) -> String {
        self.inner.describe()
    }
}
