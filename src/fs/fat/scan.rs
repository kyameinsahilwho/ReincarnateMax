//! FAT quick scan: walk the directory tree from the root (live and deleted folders), report deleted
//! (and optionally existing) files with their reconstructed folders, extents and condition.

use super::bpb::{FatKind, Geom};
use super::dir::{dir_score, parse_dir, DirEnt, Parsed};
use super::table::{ChainEnd, Fat};
use crate::device::source::{read_tolerant, BlockSource};
use crate::model::{flags, Condition, EngineSummary, Extent, FileStatus, FoundFile, IntervalSet, MapKind, Origin, ScanCtx};
use std::collections::{HashMap, HashSet, VecDeque};

/// A mounted (read-only) view of a FAT volume.
pub(crate) struct Volume<'a> {
    pub src: &'a dyn BlockSource,
    pub g: Geom,
    pub fat: Fat,
    pub tz_ms: i64,
}

/// Directory bytes with the absolute offset of every 32-byte slot.
#[derive(Default)]
pub(crate) struct DirData {
    pub buf: Vec<u8>,
    pub offsets: Vec<u64>,
    pub clusters: Vec<u32>,
}

impl DirData {
    fn push_range(&mut self, data: Vec<u8>, abs: u64) {
        for i in 0..data.len() / 32 {
            self.offsets.push(abs + i as u64 * 32);
        }
        self.buf.extend_from_slice(&data[..data.len() / 32 * 32]);
    }
}

/// Max clusters a directory may span (FAT directories hold at most 65536 entries = 2 MiB).
pub(crate) fn max_dir_clusters(g: &Geom) -> usize {
    ((2u64 << 20) / g.cluster_size as u64).max(1) as usize
}

impl<'a> Volume<'a> {
    pub fn read_cluster(&self, c: u32, ctx: Option<&ScanCtx>) -> Vec<u8> {
        let mut b = vec![0u8; self.g.cluster_size as usize];
        let off = self.g.cluster_offset(c);
        let (n, _) = read_tolerant(self.src, off, &mut b, ctx);
        b.truncate(n);
        b
    }

    pub fn read_root16(&self, ctx: Option<&ScanCtx>) -> DirData {
        let mut d = DirData::default();
        let len = self.g.root_bytes.min(1 << 22) as usize;
        let mut b = vec![0u8; len];
        let (n, _) = read_tolerant(self.src, self.g.root_offset, &mut b, ctx);
        b.truncate(n);
        d.push_range(b, self.g.root_offset);
        d
    }

    pub fn read_chain_dir(&self, start: u32, ctx: Option<&ScanCtx>) -> DirData {
        let mut d = DirData::default();
        for c in self.fat.dir_chain(start, max_dir_clusters(&self.g)) {
            let b = self.read_cluster(c, ctx);
            d.push_range(b, self.g.cluster_offset(c));
            d.clusters.push(c);
        }
        d
    }

    /// A deleted directory: its chain is freed, so start at `start` (validated through its "." and
    /// ".." entries) and continue into following clusters while they are free and look like
    /// directory entries. `parent`: the expected ".." cluster (None = don't check).
    pub fn read_deleted_dir(&self, start: u32, parent: Option<u32>, check_fat: bool, ctx: Option<&ScanCtx>) -> Option<DirData> {
        if !self.g.valid_cluster(start) {
            return None;
        }
        if check_fat && self.fat.is_used(start) {
            return None;
        }
        let first = self.read_cluster(start, ctx);
        if first.len() < 64 {
            return None;
        }
        let fat32 = self.g.kind == FatKind::Fat32;
        let (dot, dotdot) = super::dir::find_dots(&first, fat32)?;
        if dot != start {
            return None;
        }
        if let Some(par) = parent {
            let is_root = |c: u32| c == 0 || (fat32 && c == self.g.root_cluster);
            if !(dotdot == par || (is_root(dotdot) && is_root(par))) {
                return None;
            }
        }
        let maxc = Some(self.g.entry_max_cluster());
        let mut d = DirData::default();
        let mut ended = dir_score(&first, maxc).map(|s| s.1).unwrap_or(true);
        d.push_range(first, self.g.cluster_offset(start));
        d.clusters.push(start);
        let mut c = start;
        while !ended && d.clusters.len() < max_dir_clusters(&self.g) {
            c += 1;
            if !self.g.valid_cluster(c) || (check_fat && self.fat.is_used(c)) {
                break;
            }
            let b = self.read_cluster(c, ctx);
            if super::dir::find_dots(&b, fat32).is_some() {
                // The first cluster of another directory, never a continuation of this one.
                break;
            }
            match dir_score(&b, maxc) {
                Some((_, e)) => {
                    ended = e;
                    d.push_range(b, self.g.cluster_offset(c));
                    d.clusters.push(c);
                }
                None => break,
            }
        }
        Some(d)
    }

    pub fn parse(&self, d: &DirData, strict: bool) -> Parsed {
        parse_dir(&d.buf, &d.offsets, self.g.kind == FatKind::Fat32, strict, Some(self.g.entry_max_cluster()), self.tz_ms)
    }
}

/// Where a file's content is, how intact it looks, and why.
pub(crate) struct Assessment {
    pub extents: Vec<Extent>,
    pub condition: Condition,
    pub flags: u32,
    pub note: String,
    pub fragmented: bool,
}

/// Deleted file: the chain is freed, so assume contiguous clusters and check them against the FAT.
pub(crate) fn assess_deleted(v: &Volume, e: &DirEnt, check_fat: bool) -> Assessment {
    let g = &v.g;
    let size = e.size as u64;
    let guessed_tail = if e.name_guessed { " The first letter of its name was lost." } else { "" };
    let good = if e.name_guessed { Condition::Good } else { Condition::Excellent };
    if size == 0 {
        return Assessment { extents: vec![], condition: good, flags: 0, note: format!("The file is empty.{guessed_tail}"), fragmented: false };
    }
    let hi_suspect = g.kind == FatKind::Fat32 && e.hi_zero && g.bpb_cluster_count.max(g.cluster_count) > 0xFFFF;
    let hi_note = " Its start cluster may also be wrong: some systems clear the high part of it when deleting.";
    if !g.valid_cluster(e.start) {
        let note = if hi_suspect && e.start == 0 {
            "Its start cluster was cleared when it was deleted, so its content can't be located.".to_string()
        } else if e.start >= 2 && e.start <= g.entry_max_cluster() {
            // Inside the volume the BPB describes, but past the end of this (shorter) source.
            "Its clusters lie beyond the end of the drive.".to_string()
        } else {
            "Its start cluster is invalid, so its content can't be located.".to_string()
        };
        return Assessment { extents: vec![], condition: Condition::Partial, flags: 0, note, fragmented: false };
    }
    let cs = g.cluster_size as u64;
    let n = size.div_ceil(cs);
    let avail = (g.cluster_count as u64 + 2 - e.start as u64).min(n);
    let off = g.cluster_offset(e.start);
    let mut len = size.min(avail * cs);
    let src_len = v.src.len();
    if off >= src_len {
        return Assessment {
            extents: vec![],
            condition: Condition::Partial,
            flags: 0,
            note: "Its clusters lie beyond the end of the drive.".into(),
            fragmented: false,
        };
    }
    len = len.min(src_len - off);
    let truncated = len < size;
    let extents = vec![Extent { offset: off, len }];
    if !check_fat {
        return Assessment {
            extents,
            condition: Condition::Unknown,
            flags: 0,
            note: "Its clusters were assumed to be contiguous; MAX couldn't check whether they were reused.".into(),
            fragmented: false,
        };
    }
    let first_used = v.fat.is_used(e.start);
    let used = (0..avail as u32).filter(|i| v.fat.is_used(e.start + i)).count();
    let (condition, fl, note) = if first_used {
        let mut note = "Its start has been overwritten.".to_string();
        if hi_suspect {
            note.push_str(hi_note);
        }
        (Condition::Partial, flags::OVERWRITTEN, note)
    } else if used > 0 {
        (Condition::Partial, flags::OVERWRITTEN, "Some of its clusters now belong to other files.".to_string())
    } else if truncated {
        (Condition::Partial, 0, "Part of it lies beyond the end of the volume.".to_string())
    } else {
        (good, 0, format!("Its clusters are still free.{guessed_tail}"))
    };
    Assessment { extents, condition, flags: fl, note, fragmented: false }
}

/// Merge a cluster list into byte extents covering `size` bytes.
pub(crate) fn chain_extents(g: &Geom, chain: &[u32], size: u64, src_len: u64) -> Vec<Extent> {
    let cs = g.cluster_size as u64;
    let mut out: Vec<Extent> = Vec::new();
    let mut left = size;
    for &c in chain {
        if left == 0 {
            break;
        }
        let off = g.cluster_offset(c);
        if off >= src_len {
            break;
        }
        let l = cs.min(left).min(src_len - off);
        match out.last_mut() {
            Some(last) if last.offset + last.len == off => last.len += l,
            _ => out.push(Extent { offset: off, len: l }),
        }
        left -= l;
    }
    out
}

/// A file that still has its chain.
pub(crate) fn assess_existing(v: &Volume, e: &DirEnt) -> Assessment {
    let g = &v.g;
    let size = e.size as u64;
    if size == 0 {
        return Assessment { extents: vec![], condition: Condition::Excellent, flags: 0, note: "The file is empty.".into(), fragmented: false };
    }
    let n = size.div_ceil(g.cluster_size as u64) as usize;
    let (chain, _end) = v.fat.chain(e.start, n);
    let extents = chain_extents(g, &chain, size, v.src.len());
    let got: u64 = extents.iter().map(|x| x.len).sum();
    let fragmented = extents.len() > 1;
    if got < size {
        return Assessment {
            extents,
            condition: Condition::Partial,
            flags: 0,
            note: "Its cluster chain is broken, so only part of it can be read.".into(),
            fragmented,
        };
    }
    Assessment { extents, condition: Condition::Excellent, flags: 0, note: "It is still on the drive.".into(), fragmented }
}

/// An entry in a deleted folder that wasn't itself marked deleted: use its chain if it is still
/// complete, otherwise treat it like any deleted file.
pub(crate) fn assess_orphan_live(v: &Volume, e: &DirEnt) -> Assessment {
    let size = e.size as u64;
    if size > 0 && v.g.valid_cluster(e.start) && v.fat.is_used(e.start) {
        let n = size.div_ceil(v.g.cluster_size as u64) as usize;
        let (chain, end) = v.fat.chain(e.start, n);
        if chain.len() == n && (end == ChainEnd::Eoc || end == ChainEnd::Limit) {
            let extents = chain_extents(&v.g, &chain, size, v.src.len());
            let fragmented = extents.len() > 1;
            return Assessment {
                extents,
                condition: Condition::Good,
                flags: 0,
                note: "Its folder was deleted, but its clusters are still allocated to it.".into(),
                fragmented,
            };
        }
    }
    assess_deleted(v, e, true)
}

pub(crate) fn type_id_of(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, e)) if !stem.is_empty() && !e.is_empty() && e.len() <= 8 => e.to_ascii_lowercase(),
        _ => String::new(),
    }
}

pub(crate) fn make_file(e: &DirEnt, folder: &str, status: FileStatus, a: Assessment, extra_flags: u32) -> FoundFile {
    let mut fl = a.flags | extra_flags;
    if e.name_guessed {
        fl |= flags::NAME_GUESSED;
    }
    let mut meta = std::collections::BTreeMap::new();
    if e.has_long_name {
        meta.insert("shortName".to_string(), e.short_name.clone());
    }
    meta.insert("startCluster".to_string(), e.start.to_string());
    let mut attrs = String::new();
    for (bit, ch) in [(0x01u8, 'R'), (0x02, 'H'), (0x04, 'S'), (0x20, 'A')] {
        if e.attr & bit != 0 {
            attrs.push(ch);
        }
    }
    if !attrs.is_empty() {
        meta.insert("attributes".to_string(), attrs);
    }
    FoundFile {
        name: e.name.clone(),
        folder: folder.to_string(),
        size: e.size as u64,
        status,
        origin: Origin::Fat,
        type_id: type_id_of(&e.name),
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Loc {
    Root16,
    Live(u32),
    Deleted(u32),
}

struct Job {
    loc: Loc,
    path: String,
    deleted_ctx: bool,
    /// The cluster ".." entries of this folder's subfolders point at (0 for the root).
    self_cluster: u32,
    parent: u32,
}

/// What the walk saw, for the sweep (reachable directory clusters, names of folders by cluster).
#[derive(Default)]
pub(crate) struct WalkOut {
    pub dir_clusters: HashSet<u32>,
    pub names: HashMap<u32, String>,
    pub files: u64,
    pub deleted: u64,
    pub folders: u64,
    pub deleted_folders: u64,
    pub unrecoverable_folders: u64,
    pub reported: u64,
    pub label: Option<String>,
}

/// Walk the tree from the root. With `report`, files go to `ctx.found` and metadata is marked.
pub(crate) fn walk(v: &Volume, ctx: &ScanCtx, report: bool) -> Result<WalkOut, String> {
    let mut out = WalkOut::default();
    let mut meta = IntervalSet::new();
    let mut visited: HashSet<u32> = HashSet::new();
    let mut reused: HashSet<u32> = HashSet::new();
    let mut q: VecDeque<Job> = VecDeque::new();
    let root = if v.g.kind == FatKind::Fat32 { Loc::Live(v.g.root_cluster) } else { Loc::Root16 };
    if let Loc::Live(c) = root {
        visited.insert(c);
    }
    q.push_back(Job { loc: root, path: String::new(), deleted_ctx: false, self_cluster: 0, parent: 0 });
    let mut queued = 1u64;
    let mut done = 0u64;
    let include_existing = ctx.include_existing();
    let rctx = if report { Some(ctx) } else { None };
    while let Some(job) = q.pop_front() {
        ctx.check()?;
        let data = match job.loc {
            Loc::Root16 => Some(v.read_root16(rctx)),
            Loc::Live(c) => Some(v.read_chain_dir(c, rctx)),
            Loc::Deleted(c) => v.read_deleted_dir(c, Some(job.parent), true, rctx),
        };
        done += 1;
        if report {
            ctx.total.store(queued, std::sync::atomic::Ordering::Relaxed);
            ctx.set_progress(done);
        }
        let Some(data) = data else {
            out.unrecoverable_folders += 1;
            continue;
        };
        out.folders += 1;
        if matches!(job.loc, Loc::Deleted(_)) {
            out.deleted_folders += 1;
        }
        for &c in &data.clusters {
            out.dir_clusters.insert(c);
            let o = v.g.cluster_offset(c);
            meta.insert(o, o + v.g.cluster_size as u64);
        }
        let parsed = v.parse(&data, false);
        if job.loc == root && out.label.is_none() {
            out.label = parsed.label.clone();
        }
        for (k, e) in parsed.entries.iter().enumerate() {
            if k % 256 == 255 {
                ctx.check()?;
            }
            if e.is_dir() {
                if v.g.valid_cluster(e.start) {
                    let deleted = e.deleted || job.deleted_ctx;
                    if deleted && v.fat.is_used(e.start) {
                        // Its start cluster was reused (maybe by a live folder reached later):
                        // don't claim it, or that live folder would never be walked.
                        if reused.insert(e.start) {
                            out.unrecoverable_folders += 1;
                        }
                        continue;
                    }
                    out.names.entry(e.start).or_insert_with(|| e.name.clone());
                    if visited.insert(e.start) {
                        let loc = if deleted { Loc::Deleted(e.start) } else { Loc::Live(e.start) };
                        q.push_back(Job {
                            loc,
                            path: format!("{}\\{}", job.path, e.name),
                            deleted_ctx: deleted,
                            self_cluster: e.start,
                            parent: job.self_cluster,
                        });
                        queued += 1;
                    }
                }
                continue;
            }
            let deleted = e.deleted || job.deleted_ctx;
            if deleted {
                out.deleted += 1;
            }
            out.files += 1;
            if !report || (!deleted && !include_existing) {
                continue;
            }
            let (status, a) = if e.deleted {
                (FileStatus::Deleted, assess_deleted(v, e, true))
            } else if job.deleted_ctx {
                (FileStatus::Deleted, assess_orphan_live(v, e))
            } else {
                (FileStatus::Existing, assess_existing(v, e))
            };
            ctx.found(make_file(e, &job.path, status, a, 0));
            out.reported += 1;
        }
    }
    if report {
        for &(s, e) in &meta.ranges {
            ctx.mark(MapKind::Metadata, s, e - s);
            ctx.mark(MapKind::Scanned, s, e - s);
        }
    }
    Ok(out)
}

/// Read the FAT for a volume, producing log notes for damaged copies.
pub(crate) fn mount<'a>(src: &'a dyn BlockSource, ctx: Option<&ScanCtx>) -> Result<Volume<'a>, String> {
    let g = super::bpb::read_geom(src).ok_or_else(|| "No FAT file system was found here. Run a deep scan instead.".to_string())?;
    let fat = super::table::read_fat(src, &g, ctx)?;
    Ok(Volume { src, g, fat, tz_ms: super::util::local_offset_ms() })
}

pub(crate) fn quick_scan(src: &dyn BlockSource, ctx: &ScanCtx) -> Result<EngineSummary, String> {
    let g0 = super::bpb::read_geom(src).ok_or_else(|| "No FAT file system was found here. Run a deep scan instead.".to_string())?;
    let stage = ctx.stage();
    ctx.set_stage(&stage, g0.fat_bytes);
    let v = mount(src, Some(ctx))?;
    let g = &v.g;
    let mut sum = EngineSummary::default();
    if g.used_backup {
        sum.notes.push("Used the backup boot sector because the first one is damaged.".into());
    }
    if v.fat.from_second_copy > 0 {
        sum.notes.push("Some sectors of the first FAT couldn't be read; the second copy was used for them.".into());
    }
    if v.fat.unreadable > 0 {
        sum.notes.push("Parts of both FAT copies couldn't be read; clusters described there are treated as free.".into());
    }
    ctx.info(format!(
        "{} volume: {} clusters of {}, data starts at byte {}.",
        g.kind.name(),
        g.cluster_count,
        crate::model::human_size(g.cluster_size as u64),
        g.data_offset
    ));
    // Metadata: reserved sectors (boot sector, FSInfo, backup), FATs, fixed root directory.
    let meta_end = g.data_offset.min(src.len());
    ctx.mark(MapKind::Metadata, 0, meta_end);
    ctx.mark(MapKind::Scanned, 0, g.fat_offset.min(meta_end));
    ctx.mark(MapKind::Scanned, g.root_offset.min(meta_end), meta_end.saturating_sub(g.root_offset));
    // Allocated: clusters in use, as merged byte ranges.
    let mut run: Option<(u32, u32)> = None;
    let flush = |r: (u32, u32)| {
        let s = g.cluster_offset(r.0);
        let e = g.cluster_offset(r.1) + g.cluster_size as u64;
        ctx.mark(MapKind::Allocated, s, e - s);
    };
    for c in 2..=g.cluster_count + 1 {
        if c % (1 << 20) == 0 {
            ctx.check()?;
        }
        if v.fat.is_used(c) {
            run = match run {
                Some((s, e)) if e + 1 == c => Some((s, c)),
                Some(r) => {
                    flush(r);
                    Some((c, c))
                }
                None => Some((c, c)),
            };
        }
    }
    if let Some(r) = run {
        flush(r);
    }
    let w = walk(&v, ctx, true)?;
    sum.files = w.reported;
    sum.deleted = w.deleted;
    ctx.info(format!(
        "Read {} folders ({} of them deleted); {} deleted files found.",
        w.folders, w.deleted_folders, w.deleted
    ));
    if w.unrecoverable_folders > 0 {
        ctx.info(format!(
            "{} deleted folders couldn't be opened because their clusters were reused; a deep scan may find their files.",
            w.unrecoverable_folders
        ));
    }
    let tz = "FAT stores local times without a time zone; they were converted using this PC's current time zone.";
    ctx.info(tz);
    sum.notes.push(tz.into());
    Ok(sum)
}
