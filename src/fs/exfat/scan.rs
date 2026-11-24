//! exFAT quick scan: allocation bitmap, FAT, directory entry sets (live and deleted), tree walk.

use super::boot::XGeom;
use crate::device::source::{read_tolerant, BlockSource};
use crate::fs::fat::util::{dos_to_ms, local_offset_ms, rd16, rd32, rd64};
use crate::model::{flags, Condition, EngineSummary, Extent, FileStatus, FoundFile, IntervalSet, MapKind, Origin, ScanCtx, SPARSE};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Directory size limit (exFAT: 256 MiB).
const MAX_DIR_BYTES: u64 = 256 << 20;

#[derive(Clone, Debug, Default)]
pub(crate) struct XEnt {
    pub name: String,
    /// Fewer name characters were present than the stream entry announced.
    pub name_incomplete: bool,
    pub deleted: bool,
    pub attr: u16,
    pub first_cluster: u32,
    pub data_len: u64,
    pub valid_len: u64,
    pub no_fat_chain: bool,
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub accessed: Option<i64>,
    /// Absolute offset of the File entry.
    pub offset: u64,
    pub checksum_ok: bool,
}

impl XEnt {
    pub fn is_dir(&self) -> bool {
        self.attr & 0x10 != 0
    }
}

#[derive(Default)]
pub(crate) struct XParsed {
    pub entries: Vec<XEnt>,
    /// (first cluster, length) of the allocation bitmap / up-case table (root directory only).
    pub bitmap: Option<(u32, u64)>,
    pub upcase: Option<(u32, u64)>,
    pub label: Option<String>,
}

pub(crate) fn set_checksum(bytes: &[u8]) -> u16 {
    let mut c: u16 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if i == 2 || i == 3 {
            continue;
        }
        c = c.rotate_right(1).wrapping_add(b as u16);
    }
    c
}

fn ts(v: u32, ms10: u8, utc: u8, local_tz: i64) -> Option<i64> {
    let offset_ms = if utc & 0x80 != 0 {
        let raw = (utc & 0x7F) as i64;
        let q = if raw >= 64 { raw - 128 } else { raw };
        q * 15 * 60_000
    } else {
        local_tz
    };
    dos_to_ms((v >> 16) as u16, v as u16, ms10 as i64 * 10, offset_ms)
}

/// Parse the entry set whose File entry is at slot `i` of `buf`. Returns the entry (offset 0) and
/// the number of slots it spans. Deleted sets (in-use bits cleared) are checked with the bits
/// restored.
pub(crate) fn parse_set(buf: &[u8], i: usize, tz_ms: i64) -> Option<(XEnt, usize)> {
    let nslots = buf.len() / 32;
    let at = |k: usize| &buf[k * 32..k * 32 + 32];
    if i >= nslots {
        return None;
    }
    let f = at(i);
    let deleted = match f[0] {
        0x85 => false,
        0x05 => true,
        _ => return None,
    };
    let sc = f[1] as usize;
    if !(2..=18).contains(&sc) || i + sc >= nslots {
        return None;
    }
    let s = at(i + 1);
    if s[0] != if deleted { 0x40 } else { 0xC0 } {
        return None;
    }
    let name_len = s[3] as usize;
    if name_len == 0 {
        return None;
    }
    let need = name_len.div_ceil(15);
    let mut units: Vec<u16> = Vec::with_capacity(need * 15);
    let mut name_entries = 0;
    for k in 0..sc - 1 {
        let e = at(i + 2 + k);
        let t = e[0];
        let want = if deleted { 0x41 } else { 0xC1 };
        if k < need {
            if t != want {
                break;
            }
            name_entries += 1;
            for j in 0..15 {
                units.push(rd16(e, 2 + j * 2));
            }
        } else if t & 0x40 == 0 || (t & 0x80 != 0) == deleted {
            // Other secondaries must be secondary types with the same in-use state.
            return None;
        }
    }
    if name_entries == 0 {
        return None;
    }
    let incomplete = name_entries < need;
    units.truncate(name_len.min(units.len()));
    // Set checksum with in-use bits restored.
    let mut copy = buf[i * 32..(i + sc + 1) * 32].to_vec();
    if deleted {
        for k in 0..=sc {
            copy[k * 32] |= 0x80;
        }
    }
    let checksum_ok = set_checksum(&copy) == rd16(f, 2);
    let gen = s[1];
    let e = XEnt {
        name: String::from_utf16_lossy(&units).replace('\0', ""),
        name_incomplete: incomplete,
        deleted,
        attr: rd16(f, 4),
        first_cluster: rd32(s, 20),
        data_len: rd64(s, 24),
        valid_len: rd64(s, 8),
        no_fat_chain: gen & 0x02 != 0,
        created: ts(rd32(f, 8), f[20], f[22], tz_ms),
        modified: ts(rd32(f, 12), f[21], f[23], tz_ms),
        accessed: ts(rd32(f, 16), 0, f[24], tz_ms),
        offset: 0,
        checksum_ok,
    };
    Some((e, sc + 1))
}

/// Parse a directory buffer; `offsets[i]` = absolute offset of slot i.
pub(crate) fn parse_dir(buf: &[u8], offsets: &[u64], tz_ms: i64) -> XParsed {
    let mut p = XParsed::default();
    let nslots = (buf.len() / 32).min(offsets.len());
    let buf = &buf[..nslots * 32];
    let mut i = 0;
    while i < nslots {
        let b = &buf[i * 32..i * 32 + 32];
        match b[0] {
            0x00 => break,
            0x81 => {
                if p.bitmap.is_none() || b[1] & 1 == 0 {
                    p.bitmap = Some((rd32(b, 20), rd64(b, 24)));
                }
            }
            0x82 => p.upcase = Some((rd32(b, 20), rd64(b, 24))),
            0x83 => {
                let n = (b[1] as usize).min(11);
                let units: Vec<u16> = (0..n).map(|j| rd16(b, 2 + j * 2)).collect();
                p.label = Some(String::from_utf16_lossy(&units));
            }
            0x85 | 0x05 => {
                if let Some((mut e, n)) = parse_set(buf, i, tz_ms) {
                    e.offset = offsets[i];
                    p.entries.push(e);
                    i += n;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    p
}

/// A mounted (read-only) exFAT volume.
pub(crate) struct XVol<'a> {
    pub src: &'a dyn BlockSource,
    pub g: XGeom,
    pub fat: FatCache,
    pub bitmap: Option<Vec<u8>>,
    pub tz_ms: i64,
    pub notes: Vec<String>,
    pub label: Option<String>,
    pub meta: IntervalSet,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum End {
    Eoc,
    Broken,
    Limit,
}

impl<'a> XVol<'a> {
    pub fn next(&self, c: u32) -> u32 {
        self.fat.get(self.src, c)
    }
    /// Follow the FAT from `start` for at most `max` clusters. A loop (a cluster seen before) ends
    /// the chain as broken, so a damaged FAT can't repeat clusters.
    pub fn chain(&self, start: u32, max: usize) -> (Vec<u32>, End) {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut c = start;
        loop {
            if !self.g.valid_cluster(c) {
                return (out, End::Broken);
            }
            if out.len() >= max {
                return (out, End::Limit);
            }
            if !seen.insert(c) {
                return (out, End::Broken);
            }
            out.push(c);
            let v = self.next(c);
            if v >= 0xFFFF_FFF8 {
                return (out, End::Eoc);
            }
            if v == 0 || v == 0xFFFF_FFF7 {
                return (out, End::Broken);
            }
            c = v;
        }
    }
    /// Allocated in the bitmap (None when there is no bitmap).
    pub fn used(&self, c: u32) -> Option<bool> {
        let b = self.bitmap.as_ref()?;
        let i = c.checked_sub(2)? as usize;
        Some(b.get(i / 8).is_some_and(|x| x & (1 << (i % 8)) != 0))
    }
    pub fn read_clusters(&self, clusters: &[u32], ctx: Option<&ScanCtx>) -> (Vec<u8>, Vec<u64>) {
        let cs = self.g.cluster_size as usize;
        let mut buf = Vec::with_capacity(clusters.len() * cs);
        let mut offs = Vec::with_capacity(clusters.len() * cs / 32);
        for &c in clusters {
            let mut b = vec![0u8; cs];
            let off = self.g.cluster_offset(c);
            read_tolerant(self.src, off, &mut b, ctx);
            for k in 0..cs / 32 {
                offs.push(off + k as u64 * 32);
            }
            buf.extend_from_slice(&b);
        }
        (buf, offs)
    }
    pub fn contiguous(&self, start: u32, n: u64) -> Vec<u32> {
        let last = (start as u64 + n).min(self.g.cluster_count as u64 + 2);
        (start as u64..last).map(|c| c as u32).collect()
    }
    /// Clusters of a directory. `deleted`: freed, so validate and fall back to contiguous.
    pub fn dir_clusters(&self, first: u32, len: u64, no_fat_chain: bool, deleted: bool) -> Option<Vec<u32>> {
        if !self.g.valid_cluster(first) {
            return None;
        }
        let cs = self.g.cluster_size as u64;
        let n = (len.min(MAX_DIR_BYTES).div_ceil(cs)).max(1);
        let list = if no_fat_chain {
            self.contiguous(first, n)
        } else {
            let (ch, end) = self.chain(first, n as usize);
            let distinct = ch.iter().collect::<HashSet<_>>().len() == ch.len();
            if distinct && (ch.len() as u64 == n || (!deleted && end == End::Eoc)) {
                ch
            } else if deleted {
                self.contiguous(first, n)
            } else {
                ch
            }
        };
        if deleted {
            if self.used(first) == Some(true) {
                return None;
            }
            let mut big = vec![0u8; 32 * 20];
            read_tolerant(self.src, self.g.cluster_offset(first), &mut big, None);
            let ok = match big[0] {
                0x00 => big[..64].iter().all(|&x| x == 0),
                0x85 | 0x05 => parse_set(&big, 0, 0).is_some(),
                _ => false,
            };
            if !ok {
                return None;
            }
        }
        Some(list)
    }
}

/// The FAT, read on demand in 64 KiB pages (an exFAT FAT can be gigabytes; most files don't
/// need it because they are NoFatChain). Unreadable sectors fall back to the second FAT.
pub(crate) struct FatCache {
    off: u64,
    bytes: u64,
    alt: Option<u64>,
    entries: u64,
    pages: Mutex<HashMap<u64, Arc<Vec<u8>>>>,
    pub used_second: AtomicBool,
    pub unreadable: AtomicBool,
}

const PAGE: u64 = 64 * 1024;

impl FatCache {
    pub fn new(g: &XGeom) -> Self {
        FatCache {
            off: g.fat_offset,
            bytes: g.fat_bytes,
            alt: if g.nfats > 1 { Some(g.fat_offset + g.fat_bytes) } else { None },
            entries: (g.cluster_count as u64 + 2).min(g.fat_bytes / 4),
            pages: Mutex::new(HashMap::new()),
            used_second: AtomicBool::new(false),
            unreadable: AtomicBool::new(false),
        }
    }
    pub fn get(&self, src: &dyn BlockSource, c: u32) -> u32 {
        if c as u64 >= self.entries {
            return 0;
        }
        let byte = c as u64 * 4;
        let page = byte / PAGE;
        let mut map = self.pages.lock().unwrap_or_else(|e| e.into_inner());
        if !map.contains_key(&page) {
            let start = page * PAGE;
            let len = PAGE.min(self.bytes - start) as usize;
            let mut buf = vec![0u8; len];
            let (_, bad) = read_tolerant(src, self.off + start, &mut buf, None);
            for (s, e) in bad {
                let rel = (s - self.off - start) as usize;
                let l = (e - s) as usize;
                let mut ok = false;
                if let Some(alt) = self.alt {
                    let mut b2 = vec![0u8; l];
                    let (_, bad2) = read_tolerant(src, alt + start + rel as u64, &mut b2, None);
                    if bad2.is_empty() {
                        buf[rel..rel + l].copy_from_slice(&b2);
                        self.used_second.store(true, Ordering::Relaxed);
                        ok = true;
                    }
                }
                if !ok {
                    self.unreadable.store(true, Ordering::Relaxed);
                }
            }
            if map.len() >= 1024 {
                map.clear();
            }
            map.insert(page, Arc::new(buf));
        }
        let p = &map[&page];
        let o = (byte - page * PAGE) as usize;
        rd32(p, o)
    }
}

/// Mount: boot region, FAT, root directory (bitmap / up-case / label), allocation bitmap.
pub(crate) fn mount<'a>(src: &'a dyn BlockSource, ctx: Option<&ScanCtx>) -> Result<XVol<'a>, String> {
    let g = super::boot::read_xgeom(src).ok_or_else(|| "No exFAT file system was found here. Run a deep scan instead.".to_string())?;
    let mut notes = Vec::new();
    if g.used_backup {
        notes.push("Used the backup boot sector because the first one is damaged.".into());
    } else if !g.checksum_ok {
        notes.push("The boot region checksum doesn't match; its fields were used anyway.".into());
    }
    let fat = FatCache::new(&g);
    let mut v = XVol { src, g, fat, bitmap: None, tz_ms: local_offset_ms(), notes, label: None, meta: IntervalSet::new() };
    let bps = v.g.bps as u64;
    v.meta.insert(0, 24 * bps);
    v.meta.insert(v.g.fat_offset, v.g.fat_offset + v.g.nfats as u64 * v.g.fat_bytes);
    let root = v.dir_clusters(v.g.root_cluster, MAX_DIR_BYTES, false, false).unwrap_or_default();
    let (buf, offs) = v.read_clusters(&root, ctx);
    let p = parse_dir(&buf, &offs, v.tz_ms);
    v.label = p.label.clone();
    let cs = v.g.cluster_size as u64;
    for (what, loc) in [("bitmap", p.bitmap), ("upcase", p.upcase)] {
        let Some((first, len)) = loc else { continue };
        if !v.g.valid_cluster(first) || len == 0 {
            continue;
        }
        // A damaged length must not make it read the whole volume: the bitmap needs one bit per
        // cluster and the up-case table is at most 128 KiB.
        let cap = if what == "bitmap" { (v.g.cluster_count as u64).div_ceil(8) } else { 128 << 10 };
        let len = len.min(cap.max(1));
        let n = len.div_ceil(cs);
        let (ch, _) = v.chain(first, n as usize);
        let list = if ch.len() as u64 == n { ch } else { v.contiguous(first, n) };
        for &c in &list {
            let o = v.g.cluster_offset(c);
            v.meta.insert(o, o + cs);
        }
        if what == "bitmap" {
            let (mut b, _) = v.read_clusters(&list, ctx);
            b.truncate(len.min((v.g.cluster_count as u64).div_ceil(8)) as usize);
            v.bitmap = Some(b);
        }
    }
    if v.bitmap.is_none() {
        v.notes.push("The allocation bitmap couldn't be found, so file conditions couldn't be checked.".into());
    }
    Ok(v)
}

pub(crate) struct XAssess {
    pub extents: Vec<Extent>,
    pub condition: Condition,
    pub flags: u32,
    pub note: String,
    pub fragmented: bool,
}

fn extents_of(g: &XGeom, list: &[u32], size: u64, valid: u64, src_len: u64) -> Vec<Extent> {
    let cs = g.cluster_size as u64;
    let readable = valid.min(size);
    let mut out: Vec<Extent> = Vec::new();
    let mut left = readable;
    for &c in list {
        if left == 0 {
            break;
        }
        let off = g.cluster_offset(c);
        if off >= src_len {
            break;
        }
        let l = cs.min(left).min(src_len - off);
        match out.last_mut() {
            Some(x) if x.offset != SPARSE && x.offset + x.len == off => x.len += l,
            _ => out.push(Extent { offset: off, len: l }),
        }
        left -= l;
    }
    let got: u64 = out.iter().map(|e| e.len).sum();
    if got == readable && readable < size {
        // Past the valid data length exFAT reads zeros.
        out.push(Extent { offset: SPARSE, len: size - readable });
    }
    out
}

/// Where a file's data is and how intact it looks. `deleted` decides chain trust and condition.
pub(crate) fn assess(v: &XVol, e: &XEnt, deleted: bool) -> XAssess {
    let g = &v.g;
    let size = e.data_len;
    let named_ok = e.checksum_ok && !e.name_incomplete;
    let good = if named_ok { Condition::Excellent } else { Condition::Good };
    if size == 0 {
        return XAssess { extents: vec![], condition: good, flags: 0, note: "The file is empty.".into(), fragmented: false };
    }
    if !g.valid_cluster(e.first_cluster) {
        return XAssess {
            extents: vec![],
            condition: Condition::Partial,
            flags: 0,
            note: "Its start cluster is invalid, so its content can't be located.".into(),
            fragmented: false,
        };
    }
    let n = size.div_ceil(g.cluster_size as u64);
    let mut chain_used = false;
    let list = if e.no_fat_chain {
        v.contiguous(e.first_cluster, n)
    } else {
        let (ch, _) = v.chain(e.first_cluster, n as usize);
        if !deleted {
            ch
        } else if ch.len() as u64 == n && ch.iter().collect::<HashSet<_>>().len() == ch.len() {
            chain_used = ch.windows(2).any(|w| w[1] != w[0] + 1);
            ch
        } else {
            v.contiguous(e.first_cluster, n)
        }
    };
    let extents = extents_of(g, &list, size, e.valid_len, v.src.len());
    let fragmented = extents.iter().filter(|x| x.offset != SPARSE).count() > 1;
    let complete = (list.len() as u64) >= n;
    if !deleted {
        if !complete {
            return XAssess {
                extents,
                condition: Condition::Partial,
                flags: 0,
                note: "Its cluster chain is broken, so only part of it can be read.".into(),
                fragmented,
            };
        }
        return XAssess { extents, condition: Condition::Excellent, flags: 0, note: "It is still on the drive.".into(), fragmented };
    }
    let used: Vec<Option<bool>> = list.iter().map(|&c| v.used(c)).collect();
    let (condition, fl, mut note) = if used.first().copied().flatten().is_none() {
        (Condition::Unknown, 0, "MAX couldn't read the allocation bitmap to check its clusters.".to_string())
    } else if used[0] == Some(true) {
        (Condition::Partial, flags::OVERWRITTEN, "Its start has been overwritten.".to_string())
    } else if used.iter().any(|u| *u == Some(true)) {
        (Condition::Partial, flags::OVERWRITTEN, "Some of its clusters now belong to other files.".to_string())
    } else if !complete {
        (Condition::Partial, 0, "Part of it lies beyond the end of the volume.".to_string())
    } else if !named_ok {
        (Condition::Good, 0, "Its clusters are still free, but its directory entry is damaged.".to_string())
    } else {
        (good, 0, "Its clusters are still free.".to_string())
    };
    if chain_used && condition != Condition::Partial {
        note.push_str(" Its fragments were found through the cluster chain Windows left behind.");
    }
    XAssess { extents, condition, flags: fl, note, fragmented }
}

pub(crate) fn make_file(e: &XEnt, folder: &str, status: FileStatus, a: XAssess, extra: u32) -> FoundFile {
    let mut fl = a.flags | extra;
    let mut name = e.name.clone();
    if name.is_empty() {
        name = format!("file_{:x}", e.offset);
        fl |= flags::NAME_GUESSED;
    }
    if e.name_incomplete {
        fl |= flags::NAME_GUESSED;
    }
    let mut meta = std::collections::BTreeMap::new();
    meta.insert("startCluster".to_string(), e.first_cluster.to_string());
    if e.valid_len < e.data_len {
        meta.insert("validDataLength".to_string(), e.valid_len.to_string());
    }
    FoundFile {
        type_id: crate::fs::fat::scan::type_id_of(&name),
        name,
        folder: folder.to_string(),
        size: e.data_len,
        status,
        origin: Origin::ExFat,
        created: e.created,
        modified: e.modified,
        accessed: e.accessed,
        deleted: None,
        extents: a.extents,
        resident: None,
        live_path: None,
        condition: a.condition,
        note: a.note,
        fragmented: a.fragmented,
        flags: fl,
        fs_ref: Some(e.offset),
        meta,
    }
}

#[derive(Default)]
pub(crate) struct XWalk {
    pub dir_clusters: HashSet<u32>,
    pub names: HashMap<u32, String>,
    pub folders: u64,
    pub deleted_folders: u64,
    pub unreadable_folders: u64,
    pub deleted: u64,
    pub reported: u64,
}

struct Job {
    first: u32,
    len: u64,
    nfc: bool,
    path: String,
    deleted: bool,
}

pub(crate) fn walk(v: &mut XVol, ctx: &ScanCtx, report: bool) -> Result<XWalk, String> {
    let mut out = XWalk::default();
    let mut q = VecDeque::new();
    let mut visited = HashSet::new();
    let mut reused = HashSet::new();
    visited.insert(v.g.root_cluster);
    q.push_back(Job { first: v.g.root_cluster, len: MAX_DIR_BYTES, nfc: false, path: String::new(), deleted: false });
    let rctx = if report { Some(ctx) } else { None };
    let (mut queued, mut done) = (1u64, 0u64);
    let include_existing = ctx.include_existing();
    while let Some(job) = q.pop_front() {
        ctx.check()?;
        done += 1;
        if report {
            ctx.total.store(queued, std::sync::atomic::Ordering::Relaxed);
            ctx.set_progress(done);
        }
        let Some(list) = v.dir_clusters(job.first, job.len, job.nfc, job.deleted) else {
            out.unreadable_folders += 1;
            continue;
        };
        out.folders += 1;
        if job.deleted {
            out.deleted_folders += 1;
        }
        let cs = v.g.cluster_size as u64;
        for &c in &list {
            out.dir_clusters.insert(c);
            let o = v.g.cluster_offset(c);
            v.meta.insert(o, o + cs);
        }
        let (buf, offs) = v.read_clusters(&list, rctx);
        let p = parse_dir(&buf, &offs, v.tz_ms);
        for (k, e) in p.entries.iter().enumerate() {
            if k % 256 == 255 {
                ctx.check()?;
            }
            if e.is_dir() {
                if v.g.valid_cluster(e.first_cluster) {
                    let deleted = e.deleted || job.deleted;
                    if deleted && v.used(e.first_cluster) == Some(true) {
                        // Its start cluster was reused (maybe by a live folder reached later):
                        // don't claim it, or that live folder would never be walked.
                        if reused.insert(e.first_cluster) {
                            out.unreadable_folders += 1;
                        }
                        continue;
                    }
                    out.names.entry(e.first_cluster).or_insert_with(|| e.name.clone());
                    if visited.insert(e.first_cluster) {
                        q.push_back(Job {
                            first: e.first_cluster,
                            len: e.data_len,
                            nfc: e.no_fat_chain,
                            path: format!("{}\\{}", job.path, crate::model::safe_file_name(&e.name)),
                            deleted,
                        });
                        queued += 1;
                    }
                }
                continue;
            }
            let deleted = e.deleted || job.deleted;
            if deleted {
                out.deleted += 1;
            }
            if !report || (!deleted && !include_existing) {
                continue;
            }
            // A live-looking entry in a deleted folder: its chain may still be allocated.
            let chain_live = !e.deleted && v.used(e.first_cluster) == Some(true);
            let a = assess(v, e, deleted && !chain_live);
            let status = if deleted { FileStatus::Deleted } else { FileStatus::Existing };
            ctx.found(make_file(e, &job.path, status, a, 0));
            out.reported += 1;
        }
    }
    Ok(out)
}

pub(crate) fn quick_scan(src: &dyn BlockSource, ctx: &ScanCtx) -> Result<EngineSummary, String> {
    let stage = ctx.stage();
    ctx.set_stage(&stage, 0);
    let mut v = mount(src, Some(ctx))?;
    ctx.info(format!(
        "exFAT volume: {} clusters of {}, cluster heap at byte {}.",
        v.g.cluster_count,
        crate::model::human_size(v.g.cluster_size as u64),
        v.g.heap_offset
    ));
    // Allocated ranges from the bitmap.
    if let Some(b) = &v.bitmap {
        let mut run: Option<(u64, u64)> = None;
        let cs = v.g.cluster_size as u64;
        for i in 0..v.g.cluster_count as u64 {
            if i % (1 << 20) == 0 {
                ctx.check()?;
            }
            let used = b.get((i / 8) as usize).is_some_and(|x| x & (1 << (i % 8)) != 0);
            if !used {
                continue;
            }
            let o = v.g.heap_offset + i * cs;
            run = match run {
                Some((s, e)) if e == o => Some((s, o + cs)),
                Some((s, e)) => {
                    ctx.mark(MapKind::Allocated, s, e - s);
                    Some((o, o + cs))
                }
                None => Some((o, o + cs)),
            };
        }
        if let Some((s, e)) = run {
            ctx.mark(MapKind::Allocated, s, e - s);
        }
    }
    let w = walk(&mut v, ctx, true)?;
    for &(s, e) in &v.meta.ranges {
        ctx.mark(MapKind::Metadata, s, e - s);
        ctx.mark(MapKind::Scanned, s, e - s);
    }
    ctx.info(format!("Read {} folders ({} of them deleted); {} deleted files found.", w.folders, w.deleted_folders, w.deleted));
    if w.unreadable_folders > 0 {
        ctx.info(format!(
            "{} deleted folders couldn't be opened because their clusters were reused; a deep scan may find their files.",
            w.unreadable_folders
        ));
    }
    let mut notes = v.notes.clone();
    if v.fat.used_second.load(Ordering::Relaxed) {
        notes.push("Some sectors of the first FAT couldn't be read; the second copy was used for them.".into());
    }
    if v.fat.unreadable.load(Ordering::Relaxed) {
        notes.push("Parts of the FAT couldn't be read; fragmented files there may be incomplete.".into());
    }
    Ok(EngineSummary { files: w.reported, deleted: w.deleted, lost_folders: 0, notes })
}
