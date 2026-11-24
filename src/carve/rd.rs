//! A windowed, bad-sector-aware reader over the scan source used by the structure parsers.
//! Positions are relative to the carved file's start.

use crate::device::source::{read_tolerant, BlockSource};

const WIN: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum E {
    /// Past the end of the source.
    Eof,
    /// An unreadable sector.
    Bad,
}
pub(crate) type R<T> = Result<T, E>;

pub(crate) struct Rd<'a> {
    src: &'a dyn BlockSource,
    /// Absolute offset of the file start.
    pub start: u64,
    pub src_len: u64,
    buf: Vec<u8>,
    wpos: u64,
    wlen: usize,
    bad: Vec<(u64, u64)>,
}

impl<'a> Rd<'a> {
    pub fn new(src: &'a dyn BlockSource, start: u64) -> Self {
        Rd { src, start, src_len: src.len(), buf: Vec::new(), wpos: 0, wlen: 0, bad: Vec::new() }
    }

    /// Bytes from the file start to the end of the source.
    pub fn avail(&self) -> u64 {
        self.src_len.saturating_sub(self.start)
    }

    fn load(&mut self, abs: u64) {
        let a = abs & !511;
        let n = (WIN as u64).min(self.src_len.saturating_sub(a)) as usize;
        if self.buf.len() < WIN {
            self.buf.resize(WIN, 0);
        }
        let (got, bad) = read_tolerant(self.src, a, &mut self.buf[..n], None);
        self.wpos = a;
        self.wlen = got;
        self.bad = bad;
    }

    fn abs(&self, pos: u64) -> R<u64> {
        self.start.checked_add(pos).ok_or(E::Eof)
    }

    /// Exactly `n` bytes at `pos` (n <= 128 KiB).
    pub fn bytes(&mut self, pos: u64, n: usize) -> R<&[u8]> {
        if n > WIN / 2 {
            return Err(E::Eof);
        }
        let a = self.abs(pos)?;
        if a.checked_add(n as u64).map_or(true, |e| e > self.src_len) {
            return Err(E::Eof);
        }
        if !(a >= self.wpos && a + n as u64 <= self.wpos + self.wlen as u64) {
            self.load(a);
            if a + n as u64 > self.wpos + self.wlen as u64 {
                return Err(E::Eof);
            }
        }
        let end = a + n as u64;
        if self.bad.iter().any(|&(s, e)| s < end && a < e) {
            return Err(E::Bad);
        }
        let o = (a - self.wpos) as usize;
        Ok(&self.buf[o..o + n])
    }

    /// The bytes available at `pos` up to the end of the current window or the next unreadable
    /// sector (at least 1 byte, usually >= 4 KiB).
    pub fn chunk(&mut self, pos: u64) -> R<&[u8]> {
        let a = self.abs(pos)?;
        if a >= self.src_len {
            return Err(E::Eof);
        }
        let wend = self.wpos + self.wlen as u64;
        if !(a >= self.wpos && a < wend) || (wend - a < 4096 && wend < self.src_len) {
            self.load(a);
        }
        let wend = self.wpos + self.wlen as u64;
        if a >= wend {
            return Err(E::Eof);
        }
        let mut end = wend;
        for &(s, e) in &self.bad {
            if s <= a && a < e {
                return Err(E::Bad);
            }
            if s > a && s < end {
                end = s;
            }
        }
        let o = (a - self.wpos) as usize;
        Ok(&self.buf[o..o + (end - a) as usize])
    }

    pub fn u8(&mut self, pos: u64) -> R<u8> {
        Ok(self.bytes(pos, 1)?[0])
    }
    pub fn u16le(&mut self, pos: u64) -> R<u16> {
        let b = self.bytes(pos, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    pub fn u16be(&mut self, pos: u64) -> R<u16> {
        let b = self.bytes(pos, 2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    pub fn u32le(&mut self, pos: u64) -> R<u32> {
        let b = self.bytes(pos, 4)?;
        Ok(u32::from_le_bytes(b.try_into().unwrap()))
    }
    pub fn u32be(&mut self, pos: u64) -> R<u32> {
        let b = self.bytes(pos, 4)?;
        Ok(u32::from_be_bytes(b.try_into().unwrap()))
    }
    pub fn u64le(&mut self, pos: u64) -> R<u64> {
        let b = self.bytes(pos, 8)?;
        Ok(u64::from_le_bytes(b.try_into().unwrap()))
    }
    pub fn u64be(&mut self, pos: u64) -> R<u64> {
        let b = self.bytes(pos, 8)?;
        Ok(u64::from_be_bytes(b.try_into().unwrap()))
    }

    /// Copy up to `buf.len()` bytes at `pos` (zeros for unreadable sectors). Returns
    /// (bytes copied, hit an unreadable sector).
    pub fn read(&mut self, pos: u64, buf: &mut [u8]) -> (usize, bool) {
        let Ok(a) = self.abs(pos) else { return (0, false) };
        let (n, bad) = read_tolerant(self.src, a, buf, None);
        (n, !bad.is_empty())
    }

    /// First occurrence of any of `pats` (all the same length) starting in [from, to): its
    /// position and which pattern matched.
    pub fn find_any(&mut self, from: u64, to: u64, pats: &[&[u8]]) -> R<Option<(u64, usize)>> {
        let Some(pl) = pats.first().map(|p| p.len() as u64).filter(|&l| l > 0) else { return Ok(None) };
        debug_assert!(pats.iter().all(|p| p.len() as u64 == pl));
        let mut pos = from;
        while pos < to {
            let c = match self.chunk(pos) {
                Ok(c) => c,
                Err(E::Eof) => return Ok(None),
                Err(e) => return Err(e),
            };
            let span = (c.len() as u64).min(to - pos + pl - 1) as usize;
            let best = pats.iter().enumerate().filter_map(|(k, p)| crate::formats::sniff::find(&c[..span], p).map(|i| (i, k))).min();
            if let Some((i, k)) = best {
                return Ok(Some((pos + i as u64, k)));
            }
            if (span as u64) < pl {
                // Not enough bytes before an unreadable sector or the end.
                match self.bytes(pos, pl as usize) {
                    Err(e) => return Err(e),
                    Ok(_) => pos += 1,
                }
            } else {
                pos += span as u64 - pl + 1;
            }
        }
        Ok(None)
    }

    /// First occurrence of `pat` starting in [from, to).
    pub fn find(&mut self, from: u64, to: u64, pat: &[u8]) -> R<Option<u64>> {
        let mut pos = from;
        let pl = pat.len() as u64;
        while pos < to {
            let c = match self.chunk(pos) {
                Ok(c) => c,
                Err(E::Eof) => return Ok(None),
                Err(e) => return Err(e),
            };
            let span = (c.len() as u64).min(to - pos + pl - 1) as usize;
            if let Some(i) = crate::formats::sniff::find(&c[..span], pat) {
                return Ok(Some(pos + i as u64));
            }
            if (span as u64) < pl {
                // Not enough bytes before an unreadable sector or the end.
                match self.bytes(pos, pat.len()) {
                    Err(e) => return Err(e),
                    Ok(_) => pos += 1,
                }
            } else {
                pos += span as u64 - pl + 1;
            }
        }
        Ok(None)
    }
}
