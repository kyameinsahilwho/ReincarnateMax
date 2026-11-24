//! JPEG: marker walk (segments skipped by length, so EXIF thumbnails stay inside), entropy-coded
//! data scanned for the EOI after each SOS, and bifragment gap carving for baseline JPEGs whose
//! data breaks off: the continuation is searched in the following clusters and accepted only when
//! a Huffman decode of the joined data yields exactly the image's MCU count followed by EOI.

use super::parse::{clean, dmg, End, Env, Parsed};
use super::rd::{Rd, E};

const CAP: u64 = 128 << 20;
/// Max clusters between the two fragments.
const MAX_GAP: u64 = 64;
/// Candidate break points tried (cluster boundaries before the decode error).
const MAX_BREAKS: u32 = 16;
/// Bytes the fragment search may decode in total for one file.
const BUDGET: u64 = 96 << 20;

pub(crate) fn parse(rd: &mut Rd, env: &Env) -> Option<Parsed> {
    let mut pos = 2u64;
    let mut segs: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut seen_sof = false;
    let mut scans = 0u32;
    loop {
        if pos > CAP {
            return dmg(pos);
        }
        let early = |pos: u64| if scans > 0 || pos >= 4096 { dmg(pos) } else { None };
        match rd.u8(pos) {
            Ok(0xFF) => {}
            _ => return early(pos),
        }
        let mut m;
        loop {
            m = match rd.u8(pos + 1) {
                Ok(m) => m,
                Err(_) => return early(pos),
            };
            if m != 0xFF {
                break;
            }
            pos += 1;
        }
        match m {
            0xD9 => return if scans > 0 { clean(pos + 2) } else { None },
            0xD0..=0xD7 | 0x01 => {
                pos += 2;
                continue;
            }
            0x00 | 0xD8 | 0x02..=0xBF => return early(pos),
            _ => {}
        }
        let len = match rd.u16be(pos + 2) {
            Ok(l) if l >= 2 => l as u64,
            _ => return early(pos),
        };
        let is_sof = matches!(m, 0xC0..=0xCF) && !matches!(m, 0xC4 | 0xC8 | 0xCC);
        if (is_sof || matches!(m, 0xC4 | 0xDA | 0xDD)) && scans == 0 {
            match rd.bytes(pos + 4, len as usize - 2) {
                Ok(b) => segs.push((m, b.to_vec())),
                Err(_) => return early(pos),
            }
        }
        seen_sof |= is_sof;
        pos += 2 + len;
        if m == 0xDA {
            if !seen_sof {
                return None;
            }
            scans += 1;
            let scan_start = pos;
            match scan(rd, pos) {
                Scan::Marker(p) => pos = p,
                Scan::Break(p, fragmentable) => {
                    if fragmentable && scans == 1 {
                        if let Some(f) = bifragment(rd, env, &segs, scan_start, p) {
                            return Some(f);
                        }
                    }
                    return dmg(p);
                }
            }
        }
    }
}

enum Scan {
    /// A legal marker (EOI or a segment between progressive scans) at this position.
    Marker(u64),
    /// Entropy data broke off here (invalid marker or an all-zero sector: true; unreadable sector
    /// or end of source: false).
    Break(u64, bool),
}

fn scan(rd: &mut Rd, from: u64) -> Scan {
    let mut pos = from;
    loop {
        if pos > CAP {
            return Scan::Break(pos, false);
        }
        let abs = rd.start + pos;
        let c = match rd.chunk(pos) {
            Ok(c) => c,
            Err(_) => return Scan::Break(pos, false),
        };
        let n = c.len();
        let mut zero_at = None;
        let mut s = ((512 - abs % 512) % 512) as usize;
        while s + 512 <= n {
            if c[s] == 0 && c[s..s + 512].iter().all(|&b| b == 0) {
                zero_at = Some(s);
                break;
            }
            s += 512;
        }
        let lim = zero_at.unwrap_or(n);
        let mut j = 0usize;
        let mut need_more = false;
        while j < lim {
            match c[j..lim].iter().position(|&b| b == 0xFF) {
                None => {
                    j = lim;
                    break;
                }
                Some(k) => j += k,
            }
            if j + 1 >= n {
                need_more = true;
                break;
            }
            match c[j + 1] {
                0x00 | 0xD0..=0xD7 | 0xFF => j += 1,
                0xD9 | 0xC0..=0xCF | 0xDA..=0xDD | 0xE0..=0xEF | 0xFE => return Scan::Marker(pos + j as u64),
                _ => return Scan::Break(pos + j as u64, true),
            }
        }
        if need_more {
            if j == 0 {
                // A lone 0xFF at the end of what can be read.
                return Scan::Break(pos, false);
            }
            pos += j as u64;
            continue;
        }
        if let Some(z) = zero_at {
            return Scan::Break(pos + z as u64, true);
        }
        pos += n as u64;
    }
}

// ------------------------------------------------------------------------------ Huffman checker

struct Huff {
    maxcode: [i32; 17],
    valptr: [i32; 17],
    mincode: [i32; 17],
    vals: Vec<u8>,
}

impl Huff {
    fn new(counts: &[u8], vals: &[u8]) -> Huff {
        let mut h = Huff { maxcode: [-1; 17], valptr: [0; 17], mincode: [0; 17], vals: vals.to_vec() };
        let mut code = 0i32;
        let mut k = 0i32;
        for l in 1..=16 {
            let n = counts[l - 1] as i32;
            if n > 0 {
                h.valptr[l] = k;
                h.mincode[l] = code;
                code += n;
                k += n;
                h.maxcode[l] = code - 1;
            }
            code <<= 1;
        }
        h
    }
}

struct Spec {
    /// (component index, DC table, AC table) per block of an MCU.
    blocks: Vec<(usize, usize, usize)>,
    total_mcus: u64,
    dri: u32,
    dc: [Option<Huff>; 4],
    ac: [Option<Huff>; 4],
    max_dc_cat: u32,
    max_ac_size: u32,
    dc_limit: i32,
}

impl Spec {
    /// Baseline / extended sequential Huffman JPEG with one scan holding every component.
    fn new(segs: &[(u8, Vec<u8>)]) -> Option<Spec> {
        let mut dc: [Option<Huff>; 4] = Default::default();
        let mut ac: [Option<Huff>; 4] = Default::default();
        let mut dri = 0u32;
        let mut sof: Option<&[u8]> = None;
        for (m, b) in segs {
            match m {
                0xC0 | 0xC1 => sof = Some(b),
                0xC2..=0xCF if *m != 0xC4 && *m != 0xC8 && *m != 0xCC => return None,
                0xC4 => {
                    let mut i = 0;
                    while i + 17 <= b.len() {
                        let (tc, th) = (b[i] >> 4, (b[i] & 15) as usize);
                        let counts = &b[i + 1..i + 17];
                        let total: usize = counts.iter().map(|&c| c as usize).sum();
                        let vals = b.get(i + 17..i + 17 + total)?;
                        if th > 3 || tc > 1 {
                            return None;
                        }
                        let h = Some(Huff::new(counts, vals));
                        if tc == 0 {
                            dc[th] = h;
                        } else {
                            ac[th] = h;
                        }
                        i += 17 + total;
                    }
                }
                0xDD => dri = u16::from_be_bytes([*b.first()?, *b.get(1)?]) as u32,
                0xDA => {
                    let sof = sof?;
                    let p = sof[0] as u32;
                    let y = u16::from_be_bytes([sof[1], sof[2]]) as u64;
                    let x = u16::from_be_bytes([sof[3], sof[4]]) as u64;
                    let nf = sof[5] as usize;
                    if y == 0 || x == 0 || !(1..=4).contains(&nf) || sof.len() < 6 + 3 * nf || !(p == 8 || p == 12) {
                        return None;
                    }
                    let comps: Vec<(u8, u64, u64)> = (0..nf).map(|i| (sof[6 + 3 * i], (sof[7 + 3 * i] >> 4) as u64, (sof[7 + 3 * i] & 15) as u64)).collect();
                    let ns = b[0] as usize;
                    if ns != nf || b.len() < 1 + 2 * ns + 3 {
                        return None;
                    }
                    let (ss, se, a) = (b[1 + 2 * ns], b[2 + 2 * ns], b[3 + 2 * ns]);
                    if ss != 0 || se != 63 || a != 0 {
                        return None;
                    }
                    let hmax = comps.iter().map(|c| c.1).max()?.max(1);
                    let vmax = comps.iter().map(|c| c.2).max()?.max(1);
                    let mut blocks = Vec::new();
                    for i in 0..ns {
                        let id = b[1 + 2 * i];
                        let t = b[2 + 2 * i];
                        let ci = comps.iter().position(|c| c.0 == id)?;
                        let (td, ta) = ((t >> 4) as usize, (t & 15) as usize);
                        if td > 3 || ta > 3 || dc[td].is_none() || ac[ta].is_none() {
                            return None;
                        }
                        let n = if nf == 1 { 1 } else { comps[ci].1 * comps[ci].2 };
                        if n == 0 || n > 10 {
                            return None;
                        }
                        for _ in 0..n {
                            blocks.push((ci, td, ta));
                        }
                    }
                    let total_mcus = if nf == 1 { x.div_ceil(8) * y.div_ceil(8) } else { x.div_ceil(8 * hmax) * y.div_ceil(8 * vmax) };
                    return Some(Spec {
                        blocks,
                        total_mcus,
                        dri,
                        dc,
                        ac,
                        max_dc_cat: if p == 8 { 11 } else { 15 },
                        max_ac_size: if p == 8 { 10 } else { 14 },
                        dc_limit: if p == 8 { 2048 } else { 32768 },
                    });
                }
                _ => {}
            }
        }
        None
    }
}

#[derive(Clone)]
struct St {
    vpos: u64,
    acc: u32,
    nbits: u32,
    mcu: u64,
    dc: [i32; 4],
    since_rst: u32,
    rst_next: u8,
}

/// Virtual stream: bytes before `split` are at their own position, later ones `gap` further.
struct Map {
    split: u64,
    gap: u64,
    limit: u64,
}

struct Dec<'r, 'a> {
    rd: &'r mut Rd<'a>,
    map: Map,
    budget: u64,
}

impl Dec<'_, '_> {
    #[inline]
    fn byte(&mut self, v: u64) -> Result<u8, u64> {
        if v >= self.map.limit || self.budget == 0 {
            return Err(v);
        }
        self.budget -= 1;
        let p = if v < self.map.split { v } else { v + self.map.gap };
        self.rd.u8(p).map_err(|_: E| v)
    }
    #[inline]
    fn bit(&mut self, st: &mut St) -> Result<u32, u64> {
        if st.nbits == 0 {
            let b = self.byte(st.vpos)?;
            if b == 0xFF {
                if self.byte(st.vpos + 1)? != 0 {
                    return Err(st.vpos);
                }
                st.vpos += 2;
            } else {
                st.vpos += 1;
            }
            st.acc = b as u32;
            st.nbits = 8;
        }
        st.nbits -= 1;
        Ok((st.acc >> st.nbits) & 1)
    }
    fn sym(&mut self, st: &mut St, h: &Huff) -> Result<u8, u64> {
        let mut code = 0i32;
        for l in 1..=16 {
            code = (code << 1) | self.bit(st)? as i32;
            if code <= h.maxcode[l] {
                return h.vals.get((h.valptr[l] + code - h.mincode[l]) as usize).copied().ok_or(st.vpos);
            }
        }
        Err(st.vpos)
    }
    fn receive(&mut self, st: &mut St, s: u32) -> Result<i32, u64> {
        let mut v = 0i32;
        for _ in 0..s {
            v = (v << 1) | self.bit(st)? as i32;
        }
        Ok(if s > 0 && v < (1 << (s - 1)) { v - (1 << s) + 1 } else { v })
    }

    /// Decode MCUs from `st` to the end of the image; Ok(position after EOI) or Err(position of
    /// the first impossible bit pattern).
    fn run(&mut self, spec: &Spec, mut st: St, mut snaps: Option<(&mut Vec<St>, u64)>) -> Result<u64, u64> {
        while st.mcu < spec.total_mcus {
            if spec.dri > 0 && st.since_rst == spec.dri {
                st.nbits = 0;
                if self.byte(st.vpos)? != 0xFF || self.byte(st.vpos + 1)? != 0xD0 + st.rst_next {
                    return Err(st.vpos);
                }
                st.vpos += 2;
                st.rst_next = (st.rst_next + 1) & 7;
                st.dc = [0; 4];
                st.since_rst = 0;
            }
            if let Some((v, from)) = snaps.as_mut() {
                if st.vpos >= *from && v.len() < 1 << 20 {
                    v.push(st.clone());
                }
            }
            for &(c, td, ta) in &spec.blocks {
                let (dc, ac) = (spec.dc[td].as_ref().unwrap(), spec.ac[ta].as_ref().unwrap());
                let t = self.sym(&mut st, dc)? as u32;
                if t > spec.max_dc_cat {
                    return Err(st.vpos);
                }
                let d = self.receive(&mut st, t)?;
                st.dc[c] += d;
                if st.dc[c].abs() > spec.dc_limit {
                    return Err(st.vpos);
                }
                let mut k = 1u32;
                while k < 64 {
                    let rs = self.sym(&mut st, ac)? as u32;
                    let (r, s) = (rs >> 4, rs & 15);
                    if s == 0 {
                        if r == 15 {
                            k += 16;
                            if k > 63 {
                                return Err(st.vpos);
                            }
                            continue;
                        }
                        break;
                    }
                    k += r;
                    if k > 63 || s > spec.max_ac_size {
                        return Err(st.vpos);
                    }
                    self.receive(&mut st, s)?;
                    k += 1;
                }
            }
            st.mcu += 1;
            st.since_rst += 1;
        }
        let mut v = st.vpos;
        if self.byte(v)? != 0xFF {
            return Err(v);
        }
        let mut fills = 0;
        while self.byte(v + 1)? == 0xFF && fills < 16 {
            v += 1;
            fills += 1;
        }
        if self.byte(v + 1)? == 0xD9 {
            Ok(v + 2)
        } else {
            Err(v)
        }
    }
}

/// The JPEG's entropy data broke off at `p`: find where its first fragment ends (a cluster
/// boundary before the first undecodable bits) and where it continues (1..=64 clusters later).
fn bifragment(rd: &mut Rd, env: &Env, segs: &[(u8, Vec<u8>)], scan_start: u64, p: u64) -> Option<Parsed> {
    let spec = Spec::new(segs)?;
    let cs = env.cluster.max(512);
    let avail = rd.avail();
    let st0 = St { vpos: scan_start, acc: 0, nbits: 0, mcu: 0, dc: [0; 4], since_rst: 0, rst_next: 0 };
    let mut snaps = Vec::new();
    let from = p.saturating_sub((MAX_BREAKS as u64 + 2) * cs);
    let mut dec = Dec { rd, map: Map { split: u64::MAX, gap: 0, limit: p }, budget: BUDGET };
    let e = match dec.run(&spec, st0, Some((&mut snaps, from))) {
        Err(e) => e.min(p),
        Ok(_) => return None,
    };
    let mut b = e / cs * cs;
    let mut tried = 0;
    while b > scan_start && tried < MAX_BREAKS {
        if let Some(snap) = snaps.iter().rev().find(|s| s.vpos <= b) {
            for g in 1..=MAX_GAP {
                let gap = g * cs;
                if b + gap >= avail {
                    break;
                }
                dec.map = Map { split: b, gap, limit: avail - gap };
                if let Ok(end) = dec.run(&spec, snap.clone(), None) {
                    if end > b {
                        return Some(Parsed { ty: Some("jpg"), len: end, end: End::Clean, frags: vec![(0, b), (b + gap, end - b)], soft: false });
                    }
                }
                if dec.budget == 0 {
                    return None;
                }
            }
        }
        b -= cs;
        tried += 1;
    }
    None
}
