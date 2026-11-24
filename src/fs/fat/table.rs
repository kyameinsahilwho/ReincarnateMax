//! The file allocation table: reading (first copy, falling back to the second for unreadable
//! sectors), allocation tests and cluster chains.

use super::bpb::{FatKind, Geom};
use crate::device::source::{read_tolerant, BlockSource};
use crate::model::{MapKind, ScanCtx};

pub(crate) struct Fat {
    pub kind: FatKind,
    /// Entry per cluster number (index 0 and 1 are reserved).
    pub entries: Vec<u32>,
    /// Bytes that couldn't be read in any copy (treated as free).
    pub unreadable: u64,
    /// Bytes recovered from the second copy.
    pub from_second_copy: u64,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum ChainEnd {
    /// Ended with an end-of-chain mark.
    Eoc,
    /// Hit a free / bad / out-of-range entry.
    Broken,
    /// Stopped after `max` clusters.
    Limit,
}

impl Fat {
    pub fn get(&self, c: u32) -> u32 {
        self.entries.get(c as usize).copied().unwrap_or(0)
    }
    pub fn is_bad_value(&self, v: u32) -> bool {
        match self.kind {
            FatKind::Fat12 => v == 0xFF7,
            FatKind::Fat16 => v == 0xFFF7,
            FatKind::Fat32 => v == 0x0FFF_FFF7,
        }
    }
    pub fn is_eoc(&self, v: u32) -> bool {
        match self.kind {
            FatKind::Fat12 => v >= 0xFF8,
            FatKind::Fat16 => v >= 0xFFF8,
            FatKind::Fat32 => v >= 0x0FFF_FFF8,
        }
    }
    /// The cluster belongs to a live file or directory.
    pub fn is_used(&self, c: u32) -> bool {
        let v = self.get(c);
        v != 0 && !self.is_bad_value(v)
    }
    /// Follow a chain from `start`, at most `max` clusters.
    pub fn chain(&self, start: u32, max: usize) -> (Vec<u32>, ChainEnd) {
        let mut out = Vec::new();
        let n = self.entries.len() as u32;
        let mut c = start;
        loop {
            if c < 2 || c >= n {
                return (out, ChainEnd::Broken);
            }
            if out.len() >= max {
                return (out, ChainEnd::Limit);
            }
            out.push(c);
            let v = self.get(c);
            if self.is_eoc(v) {
                return (out, ChainEnd::Eoc);
            }
            if v == 0 || self.is_bad_value(v) {
                return (out, ChainEnd::Broken);
            }
            c = v;
        }
    }
    /// Directory chain with loop detection.
    pub fn dir_chain(&self, start: u32, max: usize) -> Vec<u32> {
        let mut seen = std::collections::HashSet::new();
        let (mut v, _) = self.chain(start, max);
        if let Some(i) = v.iter().position(|c| !seen.insert(*c)) {
            v.truncate(i);
        }
        v
    }
}

fn decode(kind: FatKind, raw: &[u8], first_entry: usize, out: &mut Vec<u32>, want: usize) {
    match kind {
        FatKind::Fat12 => {
            // Only called with the whole FAT in `raw` (first_entry == 0).
            let _ = first_entry;
            let mut i = out.len();
            while out.len() < want {
                let o = i * 3 / 2;
                if o + 1 >= raw.len() {
                    break;
                }
                let v = u16::from_le_bytes([raw[o], raw[o + 1]]) as u32;
                out.push(if i & 1 == 0 { v & 0xFFF } else { v >> 4 });
                i += 1;
            }
        }
        FatKind::Fat16 => {
            for c in raw.chunks_exact(2) {
                if out.len() >= want {
                    break;
                }
                out.push(u16::from_le_bytes([c[0], c[1]]) as u32);
            }
        }
        FatKind::Fat32 => {
            for c in raw.chunks_exact(4) {
                if out.len() >= want {
                    break;
                }
                out.push(u32::from_le_bytes([c[0], c[1], c[2], c[3]]) & 0x0FFF_FFFF);
            }
        }
    }
}

/// Read the FAT. Marks unreadable sectors Bad in `ctx` and checks for cancellation per MiB.
pub(crate) fn read_fat(src: &dyn BlockSource, g: &Geom, ctx: Option<&ScanCtx>) -> Result<Fat, String> {
    let want = g.cluster_count as usize + 2;
    let need_bytes = match g.kind {
        FatKind::Fat12 => (want * 3).div_ceil(2) as u64,
        FatKind::Fat16 => want as u64 * 2,
        FatKind::Fat32 => want as u64 * 4,
    }
    .min(g.fat_bytes);
    let mut fat = Fat { kind: g.kind, entries: Vec::with_capacity(want), unreadable: 0, from_second_copy: 0 };
    let chunk = 1u64 << 20;
    let mut whole12 = Vec::new();
    let mut pos = 0u64;
    while pos < need_bytes {
        if let Some(c) = ctx {
            c.check()?;
        }
        let len = chunk.min(need_bytes - pos) as usize;
        let mut buf = vec![0u8; len];
        let (_, bad) = read_tolerant(src, g.fat_offset + pos, &mut buf, ctx);
        for (s, e) in bad {
            let rel = s - g.fat_offset;
            let l = (e - s) as usize;
            let piece_start = (rel - pos) as usize;
            let mut ok = false;
            if g.nfats > 1 {
                let mut alt = vec![0u8; l];
                let (_, bad2) = read_tolerant(src, g.fat_offset + g.fat_bytes + rel, &mut alt, ctx);
                if bad2.is_empty() {
                    buf[piece_start..piece_start + l].copy_from_slice(&alt);
                    fat.from_second_copy += l as u64;
                    ok = true;
                }
            }
            if !ok {
                fat.unreadable += l as u64;
            }
        }
        if let Some(c) = ctx {
            c.mark(MapKind::Scanned, g.fat_offset + pos, len as u64);
            c.progress(len as u64);
        }
        if g.kind == FatKind::Fat12 {
            whole12.extend_from_slice(&buf);
        } else {
            decode(g.kind, &buf, 0, &mut fat.entries, want);
        }
        pos += len as u64;
    }
    if g.kind == FatKind::Fat12 {
        decode(g.kind, &whole12, 0, &mut fat.entries, want);
    }
    fat.entries.resize(want, 0);
    Ok(fat)
}
