//! Deep-scan sweep for FAT: find directory clusters the live tree doesn't reach (formatted,
//! damaged or orphaned folders) and report their files under "\Lost folders".

use super::bpb::{FatKind, Geom};
use super::dir::{dir_score, find_dots, Parsed};
use super::scan::{assess_deleted, assess_orphan_live, make_file, mount, walk, DirData, Volume, WalkOut};
use super::table::Fat;
use crate::device::source::BlockSource;
use crate::model::{flags, ChunkVisitor, EngineSummary, FileStatus, FsProbe, MapKind, ScanCtx};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Mutex;

#[derive(Clone, Copy, Debug)]
struct Hit {
    off: u64,
    /// ("." cluster, ".." cluster) for the first cluster of a directory; None for a sector that
    /// merely looks like directory entries.
    dot: Option<(u32, u32)>,
}

pub(crate) struct FatSweep {
    hits: Mutex<Vec<Hit>>,
}

pub(crate) fn new_sweep(_probe: Option<&FsProbe>) -> FatSweep {
    FatSweep { hits: Mutex::new(Vec::new()) }
}

/// Scan one buffer (sector granularity) for directory-looking sectors.
fn scan_buf(offset: u64, data: &[u8], out: &mut Vec<Hit>) {
    let mut p = ((512 - (offset % 512)) % 512) as usize;
    while p + 512 <= data.len() {
        let s = &data[p..p + 512];
        let off = offset + p as u64;
        p += 512;
        if s[0] == 0 || s[11] & 0xC0 != 0 {
            continue;
        }
        if s[0] == b'.' || s[11] & 0x3F == 0x0F {
            if let Some(d) = find_dots(s, true) {
                out.push(Hit { off, dot: Some(d) });
                continue;
            }
        }
        if let Some((used, _)) = dir_score(s, None) {
            if used >= 3 {
                out.push(Hit { off, dot: None });
            }
        }
    }
}

impl ChunkVisitor for FatSweep {
    fn name(&self) -> &'static str {
        "fat-sweep"
    }
    fn visit(&self, _src: &dyn BlockSource, offset: u64, data: &[u8], _ctx: &ScanCtx) {
        let mut local = Vec::new();
        scan_buf(offset, data, &mut local);
        if !local.is_empty() {
            self.hits.lock().unwrap_or_else(|e| e.into_inner()).extend(local);
        }
    }
    fn finish(&self, src: &dyn BlockSource, ctx: &ScanCtx) -> Result<EngineSummary, String> {
        let mut hits = std::mem::take(&mut *self.hits.lock().unwrap_or_else(|e| e.into_inner()));
        hits.sort_by_key(|h| h.off);
        hits.dedup_by_key(|h| h.off);
        rebuild(src, ctx, &hits)
    }
}

/// Guess (data region start, cluster size) from "." entries whose own cluster number and byte
/// offset must agree: data_start + (cluster - 2) * cluster_size == offset.
fn infer_layout(dots: &[(u64, u32)]) -> Option<(u64, u32)> {
    let mut votes: HashMap<(u64, u32), usize> = HashMap::new();
    for &(off, c) in dots.iter().take(20_000) {
        if c < 2 {
            continue;
        }
        for shift in 9..=18u32 {
            let cs = 1u64 << shift;
            let d = (c as u64 - 2).saturating_mul(cs);
            if d > off {
                continue;
            }
            let ds = off - d;
            if ds % 512 != 0 {
                continue;
            }
            *votes.entry((ds, cs as u32)).or_default() += 1;
        }
    }
    let best = votes.into_iter().max_by_key(|&((ds, cs), n)| (n, cs, u64::MAX - ds))?;
    if best.1 >= 2 {
        Some(best.0)
    } else {
        None
    }
}

fn synthetic_volume(src: &dyn BlockSource, data_offset: u64, cs: u32) -> Volume<'_> {
    let count = (src.len().saturating_sub(data_offset) / cs as u64).min(0x0FFF_FFF0) as u32;
    let g = Geom {
        kind: FatKind::Fat32,
        bps: 512,
        cluster_size: cs,
        nfats: 0,
        total_sectors: src.len() / 512,
        root_cluster: 0,
        fat_offset: 0,
        fat_bytes: 0,
        root_offset: data_offset,
        root_bytes: 0,
        data_offset,
        cluster_count: count,
        bpb_cluster_count: count,
        media: 0xF8,
        serial: None,
        bpb_label: String::new(),
        used_backup: false,
    };
    // An empty FAT: every cluster reads as free; `check_fat` is off for this layout anyway.
    let fat = Fat { kind: FatKind::Fat32, entries: Vec::new(), unreadable: 0, from_second_copy: 0 };
    Volume { src, g, fat, tz_ms: super::util::local_offset_ms() }
}

struct Orphan {
    cluster: u32,
    parent: Option<u32>,
    data: DirData,
    parsed: Parsed,
}

/// Lost folders of one layout (the live volume's, or one inferred from the found folders).
fn rebuild_layout(v: &Volume, live: bool, reach: &WalkOut, dots: &[Hit], runs: &[Hit], ctx: &ScanCtx, sum: &mut EngineSummary) -> Result<(), String> {
    let mut orphans: BTreeMap<u32, Orphan> = BTreeMap::new();
    let mut taken: HashSet<u32> = HashSet::new();
    for h in dots {
        ctx.check()?;
        let Some((me, parent)) = h.dot else { continue };
        if !v.g.valid_cluster(me) || v.g.cluster_offset(me) != h.off {
            continue;
        }
        if reach.dir_clusters.contains(&me) || orphans.contains_key(&me) || taken.contains(&me) {
            continue;
        }
        let Some(data) = v.read_deleted_dir(me, None, false, None) else { continue };
        for &c in &data.clusters {
            taken.insert(c);
        }
        let parsed = v.parse(&data, false);
        orphans.insert(me, Orphan { cluster: me, parent: Some(parent), data, parsed });
    }
    // Directory-looking clusters without "." entries: continuation clusters of lost folders.
    let mut loose: BTreeSet<u32> = BTreeSet::new();
    for h in runs {
        let Some(c) = v.g.cluster_of(h.off) else { continue };
        if reach.dir_clusters.contains(&c) || taken.contains(&c) || orphans.contains_key(&c) {
            continue;
        }
        if live && v.fat.is_used(c) {
            continue;
        }
        loose.insert(c);
    }
    let mut group: Vec<u32> = Vec::new();
    let mut groups: Vec<Vec<u32>> = Vec::new();
    for c in loose {
        if group.last().is_some_and(|&l| l + 1 != c) {
            groups.push(std::mem::take(&mut group));
        }
        group.push(c);
    }
    if !group.is_empty() {
        groups.push(group);
    }
    for gr in groups.into_iter().take(100_000) {
        ctx.check()?;
        let mut data = DirData::default();
        for &c in gr.iter().take(super::scan::max_dir_clusters(&v.g)) {
            let b = v.read_cluster(c, None);
            if dir_score(&b, Some(v.g.entry_max_cluster())).is_none() {
                // Only part of the cluster looked like entries; keep the sectors that do.
                let mut keep = Vec::new();
                for s in b.chunks(512) {
                    if s.len() == 512 && dir_score(s, Some(v.g.entry_max_cluster())).is_some() {
                        keep.extend_from_slice(s);
                    } else {
                        break;
                    }
                }
                let off = v.g.cluster_offset(c);
                for i in 0..keep.len() / 32 {
                    data.offsets.push(off + i as u64 * 32);
                }
                data.buf.extend_from_slice(&keep);
            } else {
                let off = v.g.cluster_offset(c);
                for i in 0..b.len() / 32 {
                    data.offsets.push(off + i as u64 * 32);
                }
                data.buf.extend_from_slice(&b[..b.len() / 32 * 32]);
            }
            data.clusters.push(c);
        }
        if data.buf.is_empty() {
            continue;
        }
        let parsed = v.parse(&data, true);
        let first = gr[0];
        orphans.entry(first).or_insert(Orphan { cluster: first, parent: None, data, parsed });
    }
    if orphans.is_empty() {
        return Ok(());
    }
    // Names of folders by start cluster, from every directory entry seen.
    let mut names: HashMap<u32, String> = if live { reach.names.clone() } else { HashMap::new() };
    for o in orphans.values() {
        for e in &o.parsed.entries {
            if e.is_dir() && v.g.valid_cluster(e.start) {
                names.entry(e.start).or_insert_with(|| e.name.clone());
            }
        }
    }
    let label = |c: u32| -> String {
        match names.get(&c) {
            Some(n) if !n.is_empty() => crate::model::safe_file_name(n),
            _ => format!("Folder {c}"),
        }
    };
    let mut paths: HashMap<u32, String> = HashMap::new();
    let keys: Vec<u32> = orphans.keys().copied().collect();
    let mut roots = 0u64;
    for &k in &keys {
        // Climb the ".." links while the parent is another lost folder.
        let mut chain = vec![k];
        let mut cur = k;
        while let Some(p) = orphans.get(&cur).and_then(|o| o.parent) {
            if p == cur || !orphans.contains_key(&p) || chain.contains(&p) || chain.len() > 64 {
                break;
            }
            if paths.contains_key(&p) {
                chain.push(p);
                break;
            }
            chain.push(p);
            cur = p;
        }
        let top = *chain.last().unwrap_or(&k);
        let mut path = match paths.get(&top) {
            Some(p) => p.clone(),
            None => {
                roots += 1;
                format!("\\Lost folders\\{}", label(top))
            }
        };
        paths.insert(top, path.clone());
        for &c in chain.iter().rev().skip(1) {
            path = format!("{}\\{}", path, label(c));
            paths.insert(c, path.clone());
        }
    }
    sum.lost_folders += roots;
    for o in orphans.values() {
        ctx.check()?;
        for &c in &o.data.clusters {
            let off = v.g.cluster_offset(c);
            ctx.mark(MapKind::Metadata, off, v.g.cluster_size as u64);
        }
        let folder = paths.get(&o.cluster).cloned().unwrap_or_else(|| format!("\\Lost folders\\Folder {}", o.cluster));
        for e in &o.parsed.entries {
            if e.is_dir() {
                continue;
            }
            let a = if !live {
                assess_deleted(v, e, false)
            } else if e.deleted {
                assess_deleted(v, e, true)
            } else {
                assess_orphan_live(v, e)
            };
            if let Some(first) = a.extents.first() {
                if ctx.known_starts.lock().unwrap_or_else(|x| x.into_inner()).contains(&first.offset) {
                    continue;
                }
            }
            if e.deleted {
                sum.deleted += 1;
            }
            sum.files += 1;
            ctx.found(make_file(e, &folder, FileStatus::Lost, a, flags::LOOSE_RECORD));
        }
    }
    Ok(())
}

fn rebuild(src: &dyn BlockSource, ctx: &ScanCtx, hits: &[Hit]) -> Result<EngineSummary, String> {
    let mut sum = EngineSummary::default();
    if hits.is_empty() {
        return Ok(sum);
    }
    let dots: Vec<Hit> = hits.iter().copied().filter(|h| h.dot.is_some()).collect();
    let runs: Vec<Hit> = hits.iter().copied().filter(|h| h.dot.is_none()).collect();
    let live = mount(src, None).ok();
    let mut rest: Vec<Hit> = dots.clone();
    if let Some(v) = &live {
        let reach = walk(v, ctx, false)?;
        let (mine, other): (Vec<Hit>, Vec<Hit>) = dots.iter().partition(|h| {
            let (me, _) = h.dot.unwrap_or((0, 0));
            v.g.valid_cluster(me) && v.g.cluster_offset(me) == h.off
        });
        rebuild_layout(v, true, &reach, &mine, &runs, ctx, &mut sum)?;
        rest = other;
    }
    // Folders that don't fit the current layout: an earlier file system with another geometry.
    if !rest.is_empty() {
        let pairs: Vec<(u64, u32)> = rest.iter().map(|h| (h.off, h.dot.map(|d| d.0).unwrap_or(0))).collect();
        if let Some((ds, cs)) = infer_layout(&pairs) {
            let v = synthetic_volume(src, ds, cs);
            ctx.info(format!(
                "Found folders of an earlier FAT file system (clusters of {}, data starting at byte {ds}).",
                crate::model::human_size(cs as u64)
            ));
            let runs_for = if live.is_none() { runs.clone() } else { Vec::new() };
            rebuild_layout(&v, false, &WalkOut::default(), &rest, &runs_for, ctx, &mut sum)?;
        } else if live.is_none() {
            sum.notes.push("Some FAT folders were found, but their layout couldn't be worked out.".into());
        }
    }
    if sum.lost_folders > 0 {
        let msg = format!("Rebuilt {} lost FAT folders with {} files.", sum.lost_folders, sum.files);
        ctx.info(msg.clone());
        sum.notes.push(msg);
    }
    Ok(sum)
}
