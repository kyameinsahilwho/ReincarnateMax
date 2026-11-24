//! Search for partitions no table lists: boot sectors (and backup boot sectors) in the space the
//! tables leave free. Dense (every sector) while the time budget lasts, then only at the usual
//! partition boundaries (1 MiB, 2048 sectors, 63x255-sector cylinders and the sectors after them).

use super::table::{analyze_inner, gaps, read, MIB};
use super::view::{Patched, Win};
use super::{FoundPartition, PartitionReport};
use crate::device::source::{read_tolerant, BlockSource};
use crate::fs::fat::util::{rd16, rd64};
use crate::model::{IntervalSet, MapKind, ScanCtx};
use std::collections::{BTreeSet, HashSet};
use std::time::{Duration, Instant};

/// How long the sector-by-sector pass may run before switching to boundary probes.
pub(crate) const DENSE_BUDGET: Duration = Duration::from_secs(60);
const CHUNK: u64 = 4 * MIB;
const CYL: u64 = 63 * 255;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Sig {
    Ntfs,
    Exfat,
    Fat,
}

fn quick_sig(s: &[u8]) -> Option<Sig> {
    if s.len() < 512 || s[510] != 0x55 || s[511] != 0xAA {
        return None;
    }
    if &s[3..11] == b"NTFS    " {
        return Some(Sig::Ntfs);
    }
    if &s[3..11] == b"EXFAT   " {
        return Some(Sig::Exfat);
    }
    if crate::fs::fat::bpb::parse_bpb(s).is_some() {
        return Some(Sig::Fat);
    }
    None
}

struct Searcher<'a> {
    src: &'a dyn BlockSource,
    ctx: &'a ScanCtx,
    listed: IntervalSet,
    listed_starts: HashSet<u64>,
    found: Vec<FoundPartition>,
    found_ranges: IntervalSet,
    examined: HashSet<u64>,
}

impl<'a> Searcher<'a> {
    fn ntfs_mft_at(&self, start: u64, s: &[u8]) -> bool {
        let bps = rd16(s, 11) as u64;
        let spc_raw = s[13];
        let spc = if spc_raw > 0x80 { 1u64 << (256 - spc_raw as u32).min(20) } else { spc_raw as u64 };
        let lcn = rd64(s, 48);
        let Some(off) = lcn.checked_mul(bps * spc).and_then(|x| x.checked_add(start)) else { return false };
        &read(self.src, off, 4)[..] == b"FILE"
    }

    /// The sector at `at` repeats exFAT boot sector `s` (volume flags and percent in use may differ).
    fn exfat_copy_at(&self, at: u64, s: &[u8]) -> bool {
        let c = read(self.src, at, 512);
        c.len() >= 512 && (0..512).filter(|&i| !matches!(i, 106 | 107 | 112)).all(|i| c[i] == s[i])
    }

    /// The root directory of an exFAT volume starting at `start` begins with its system entries:
    /// both the allocation bitmap (0x81) and the up-case table (0x82) entry.
    fn exfat_root_ok(&self, start: u64, g: &crate::fs::exfat::boot::XGeom) -> bool {
        let Some(at) = start.checked_add(g.cluster_offset(g.root_cluster)) else { return false };
        let b = read(self.src, at, 512);
        let (mut bitmap, mut upcase) = (false, false);
        for e in b.chunks_exact(32) {
            match e[0] {
                0x00 => break,
                0x81 => bitmap = true,
                0x82 => upcase = true,
                _ => {}
            }
        }
        bitmap && upcase
    }

    fn handle_hit(&mut self, q: u64, s: &[u8], sig: Sig) {
        match sig {
            Sig::Ntfs => {
                let bps = rd16(s, 11) as u64;
                let total = rd64(s, 40);
                let back = total.checked_mul(bps).and_then(|d| q.checked_sub(d));
                let primary_mft = self.ntfs_mft_at(q, s);
                match back {
                    Some(b) if b != q && self.ntfs_mft_at(b, s) && !primary_mft => self.consider(b, Some(s)),
                    _ => {
                        self.consider(q, None);
                        if let Some(b) = back {
                            if !primary_mft && b != q {
                                self.consider(b, Some(s));
                            }
                        }
                    }
                }
            }
            Sig::Fat => {
                let Some(g) = crate::fs::fat::bpb::parse_bpb(s) else { return };
                let ok_here = crate::fs::fat::bpb::fat_signature_ok(&Win::new(self.src, q, u64::MAX), &g);
                let back = if g.kind == crate::fs::fat::bpb::FatKind::Fat32 && rd16(s, 50) == 6 { q.checked_sub(6 * g.bps as u64) } else { None };
                if let Some(b) = back {
                    if !ok_here && crate::fs::fat::bpb::fat_signature_ok(&Win::new(self.src, b, u64::MAX), &g) {
                        self.consider(b, Some(s));
                        return;
                    }
                }
                if ok_here {
                    self.consider(q, None);
                }
            }
            Sig::Exfat => {
                let Some(g) = crate::fs::exfat::boot::parse_boot_sector(s) else { return };
                let ok_here = crate::fs::exfat::boot::fat_signature_ok(&Win::new(self.src, q, u64::MAX), &g);
                if ok_here {
                    self.consider(q, None);
                    return;
                }
                // The FAT start doesn't confirm this position: it may be the backup boot sector
                // (sector 12) of a volume whose main boot sector is gone.
                let back = q.checked_sub(12 * g.bps as u64);
                if let Some(b) = back {
                    if crate::fs::exfat::boot::fat_signature_ok(&Win::new(self.src, b, u64::MAX), &g) {
                        self.consider(b, Some(s));
                        return;
                    }
                }
                // A main boot sector has its backup copy 12 sectors later, and the root directory
                // (bitmap and up-case entries) sits where the geometry says relative to the start.
                if self.exfat_copy_at(q + 12 * g.bps as u64, s) || self.exfat_root_ok(q, &g) {
                    self.consider(q, None);
                } else if let Some(b) = back.filter(|&b| self.exfat_root_ok(b, &g)) {
                    self.consider(b, Some(s));
                }
            }
        }
    }

    /// Probe a partition start. `backup`: the boot sector that pointed here from elsewhere.
    fn consider(&mut self, start: u64, backup: Option<&[u8]>) {
        let len = self.src.len();
        if start >= len || !self.examined.insert(start) {
            return;
        }
        if self.listed_starts.contains(&start) || self.listed.contains(start) || self.found_ranges.contains(start) {
            return;
        }
        let win = Win::new(self.src, start, len - start);
        let mut fp = crate::fs::probe_any(&win);
        let mut via_backup = false;
        if let Some(p) = &fp {
            via_backup = p.used_backup_boot;
        } else if let Some(b) = backup {
            let patched = Patched { inner: &win, patch: b[..512].to_vec() };
            fp = crate::fs::probe_any(&patched);
            via_backup = fp.is_some();
        }
        let Some(p) = fp else { return };
        let mut size = p.total_size;
        if p.fs == "NTFS" {
            size += p.sector_size.max(512) as u64; // the backup boot sector after the volume
        }
        if size < 32 * 1024 || start.saturating_add(p.total_size) > len + 2 * MIB {
            return;
        }
        let (status, found_by, note) = if via_backup {
            ("backupOnly", "backupBootSector", "Only its backup boot sector survives; MAX rebuilt the partition from it.")
        } else {
            ("lost", "bootSector", "No partition table lists it; it was found by its boot sector.")
        };
        self.ctx.info(format!(
            "Found a lost {} partition at byte {start} ({}){}.",
            p.fs,
            crate::model::human_size(size),
            if via_backup { " through its backup boot sector" } else { "" }
        ));
        self.ctx.mark(MapKind::Metadata, start, 512);
        self.found_ranges.insert(start, start.saturating_add(size));
        self.found.push(FoundPartition {
            offset: start,
            size,
            fs: Some(p.fs.clone()),
            label: if p.label.is_empty() { None } else { Some(p.label.clone()) },
            type_name: p.fs.clone(),
            status: status.into(),
            found_by: found_by.into(),
            number: None,
            note: note.into(),
        });
    }

    /// End of the found partition containing `pos`, if any.
    fn skip_to(&self, pos: u64) -> Option<u64> {
        let i = self.found_ranges.ranges.partition_point(|&(_, e)| e <= pos);
        self.found_ranges.ranges.get(i).filter(|r| r.0 <= pos).map(|r| r.1)
    }

    fn dense(&mut self, pos: u64, end: u64) {
        let mut buf = vec![0u8; (end - pos) as usize];
        let (n, _) = read_tolerant(self.src, pos, &mut buf, Some(self.ctx));
        self.ctx.mark(MapKind::Scanned, pos, n as u64);
        let mut k = 0usize;
        while k + 512 <= n {
            let q = pos + k as u64;
            if let Some(sig) = quick_sig(&buf[k..k + 512]) {
                if self.skip_to(q).is_none() {
                    let s = buf[k..k + 512].to_vec();
                    self.handle_hit(q, &s, sig);
                }
            }
            k += 512;
        }
    }

    fn sparse(&mut self, pos: u64, end: u64, ss: u64) {
        let mut cands = BTreeSet::new();
        for step in [MIB, 2048 * ss, CYL * ss] {
            let mut p = pos.div_ceil(step) * step;
            while p < end {
                cands.insert(p);
                if step == CYL * ss {
                    for extra in [ss, 63 * ss] {
                        if p + extra < end {
                            cands.insert(p + extra);
                        }
                    }
                }
                p += step;
            }
        }
        for p in cands {
            if self.skip_to(p).is_some() {
                continue;
            }
            // One read covers: the sector before (an NTFS backup ending the previous partition),
            // the boot sector, the FAT32 backup (sector 6) and the exFAT backup region (sector 12).
            let base = p.saturating_sub(512);
            let before = (p - base) as usize;
            let b = read(self.src, base, before + 13 * 512);
            let sector = |i: usize| &b[before + i * 512..before + i * 512 + 512];
            if before == 512 {
                let s0 = &b[..512];
                if quick_sig(s0) == Some(Sig::Ntfs) {
                    let s = s0.to_vec();
                    self.handle_hit(base, &s, Sig::Ntfs);
                }
            }
            for (i, want) in [(0usize, None), (6, Some(Sig::Fat)), (12, Some(Sig::Exfat))] {
                let s = sector(i);
                if let Some(sig) = quick_sig(s) {
                    if want.is_none() || want == Some(sig) {
                        let s = s.to_vec();
                        self.handle_hit(p + i as u64 * 512, &s, sig);
                    }
                }
            }
        }
    }
}

pub(crate) fn search(src: &dyn BlockSource, ctx: &ScanCtx, budget: Duration) -> Result<PartitionReport, String> {
    let (mut rep, meta) = analyze_inner(src);
    for (s, e) in meta {
        ctx.mark(MapKind::Metadata, s, e.saturating_sub(s));
    }
    let len = src.len();
    let mut listed = IntervalSet::new();
    let mut listed_starts = HashSet::new();
    for e in &rep.entries {
        if e.type_name == "Extended" {
            continue;
        }
        listed.insert(e.offset, e.offset.saturating_add(e.size).min(len));
        listed_starts.insert(e.offset);
    }
    let mut free: Vec<(u64, u64)> = Vec::new();
    let mut at = 0u64;
    for &(s, e) in &listed.ranges {
        if s > at {
            free.push((at, s));
        }
        at = at.max(e);
    }
    if at < len {
        free.push((at, len));
    }
    let total: u64 = free.iter().map(|(s, e)| e - s).sum();
    ctx.set_stage("partitions", total);
    let ss = src.sector_size().max(512) as u64;
    let mut se = Searcher {
        src,
        ctx,
        listed,
        listed_starts,
        found: Vec::new(),
        found_ranges: IntervalSet::new(),
        examined: HashSet::new(),
    };
    let t0 = Instant::now();
    let mut dense_end: Option<u64> = None;
    let mut done = 0u64;
    for &(a, b) in &free {
        let mut pos = a / 512 * 512;
        while pos < b {
            ctx.check()?;
            if let Some(e) = se.skip_to(pos) {
                let next = e.min(b).max(pos + 512) / 512 * 512;
                done += next.saturating_sub(pos);
                ctx.set_progress(done.min(total));
                pos = next;
                continue;
            }
            let end = (pos + CHUNK).min(b);
            if dense_end.is_none() && t0.elapsed() < budget {
                se.dense(pos, end);
            } else {
                if dense_end.is_none() {
                    dense_end = Some(pos);
                }
                se.sparse(pos, end, ss);
            }
            done += end - pos;
            ctx.set_progress(done.min(total));
            pos = end;
        }
    }
    if let Some(p) = dense_end {
        let msg = format!(
            "Every sector was checked up to byte {p}; after that only the usual partition boundaries were checked, to keep the search short."
        );
        ctx.info(msg.clone());
        rep.notes.push(msg);
    }
    let n = se.found.len();
    rep.entries.extend(se.found);
    rep.entries.sort_by_key(|e| (e.offset, e.type_name == "Extended"));
    let (lo, hi) = (ss.min(len), len);
    rep.unallocated = gaps(&rep.entries, lo, hi);
    if n == 0 {
        rep.notes.push("No lost partitions were found.".into());
    } else {
        rep.notes.push(format!("Found {n} partition{} that no table lists.", if n == 1 { "" } else { "s" }));
    }
    Ok(rep)
}
