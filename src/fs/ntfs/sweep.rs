//! Deep scans: MFT records found anywhere on the source outside the live MFT (formatted volume,
//! damaged MFT, old copies, other partitions). `finish` works out each leftover table's volume
//! geometry, rebuilds folders among the loose records and reports their files.

use super::boot::find_boot;
use super::record::*;
use super::report::{assemble, make_file, Alloc, Item};
use super::runs::total_clusters;
use super::recycle::{i_id, InfoIndex, InfoRec};
use super::scan::{gather_pieces, mft_map, read_runs_bytes, seq_ok, ExtRec, FIRST_USER_RECORD, ROOT};
use super::tree::{component, Node, Tree};
use crate::device::source::{read_full, BlockSource};
use crate::model::*;
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

/// A record found by the sweep (compact).
#[derive(Clone, Debug)]
pub struct Loose {
    pub off: u64,
    pub size: u32,
    pub number: Option<u64>,
    pub rec: Rec,
    /// The record sits in the live MFT of a volume listed in the partition table (a whole-disk
    /// scan): its in-use flag is current, so an in-use file there still exists.
    pub live: bool,
}

/// A volume listed in the partition table with a working NTFS boot sector.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Mounted {
    start: u64,
    cluster: u64,
}

/// Live file tables on the source, worked out on the first visit.
#[derive(Clone, Debug, Default)]
struct Live {
    /// Byte ranges of the MFT and mirror of the volume the source itself is (its records were
    /// read by the quick scan, so they are not loose).
    skip: Vec<(u64, u64)>,
    /// Volumes in the partition table (whole-disk sources, no quick scan of their own).
    mounted: Vec<Mounted>,
    /// Byte ranges of their MFTs and mirrors, sorted.
    mounted_ranges: Vec<(u64, u64)>,
}

pub struct Sweep {
    probe: Option<FsProbe>,
    live: OnceLock<Live>,
    found: Mutex<Vec<Loose>>,
}

impl Sweep {
    pub fn new(probe: Option<&FsProbe>) -> Self {
        Sweep { probe: probe.cloned(), live: OnceLock::new(), found: Mutex::new(Vec::new()) }
    }
}

/// Byte ranges (sorted) of a volume's MFT and mirror; `at` = the volume's offset on the source.
fn mft_ranges(vol: &dyn BlockSource, at: u64) -> Option<(Vec<(u64, u64)>, u64)> {
    let (boot, _) = find_boot(vol)?;
    let map = mft_map(vol, &boot, &mut Vec::new());
    if map.guessed {
        return None;
    }
    let mut v: Vec<(u64, u64)> = map.extents.iter().map(|e| (at.saturating_add(e.phys), at.saturating_add(e.phys.saturating_add(e.len)))).collect();
    let m = at.saturating_add(boot.mftmirr_offset());
    v.push((m, m.saturating_add(4 * boot.record_size as u64)));
    v.sort_unstable();
    Some((v, boot.cluster_size as u64))
}

/// A window of another source (a partition), to read its boot sector and MFT.
struct At<'a> {
    src: &'a dyn BlockSource,
    off: u64,
    len: u64,
}

impl BlockSource for At<'_> {
    fn len(&self) -> u64 {
        self.len
    }
    fn sector_size(&self) -> u32 {
        self.src.sector_size()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(self.len - offset) as usize;
        self.src.read_at(self.off + offset, &mut buf[..n])
    }
    fn describe(&self) -> String {
        self.src.describe()
    }
}

fn live_info(src: &dyn BlockSource) -> Live {
    let mut live = Live::default();
    if find_boot(src).is_some() {
        // The source is an NTFS volume itself.
        live.skip = mft_ranges(src, 0).map(|(v, _)| v).unwrap_or_default();
        return live;
    }
    let Ok(rep) = crate::partitions::analyze(src) else { return live };
    for p in rep.entries.iter().filter(|p| p.offset > 0 && p.status == "ok" && p.fs.as_deref() == Some("NTFS")) {
        let w = At { src, off: p.offset, len: p.size.min(src.len().saturating_sub(p.offset)) };
        if find_boot(&w).map_or(true, |(_, backup)| backup) {
            continue; // Windows only mounts a volume whose first boot sector is good.
        }
        if let Some((ranges, cluster)) = mft_ranges(&w, p.offset) {
            live.mounted.push(Mounted { start: p.offset, cluster });
            live.mounted_ranges.extend(ranges);
        }
    }
    live.mounted_ranges.sort_unstable();
    live
}

/// `abs` lies inside one of the sorted ranges.
fn inside(ranges: &[(u64, u64)], abs: u64) -> bool {
    let j = ranges.partition_point(|r| r.1 <= abs);
    j < ranges.len() && ranges[j].0 <= abs
}

/// An existing user file's base record (not a folder, metadata file or Recycle Bin $I record).
fn existing_file(l: &Loose) -> bool {
    l.rec.in_use()
        && l.rec.hdr.base == 0
        && !l.rec.is_dir()
        && l.number.map_or(false, |n| n >= FIRST_USER_RECORD)
        && !l.rec.name.as_ref().map_or(false, |n| i_id(&n.name).is_some())
}

/// Parse a candidate record at `abs` (`data` = bytes from there on, possibly short).
fn parse_at(src: &dyn BlockSource, abs: u64, data: &[u8]) -> Option<Loose> {
    if data.len() < 8 {
        return None;
    }
    let usa_count = le16(data, 6) as usize;
    let size = usa_count.saturating_sub(1) * 512;
    let alloc = if data.len() >= 0x20 { le32(data, 0x1C) as usize } else { size };
    if !size.is_power_of_two() || !(512..=65536).contains(&size) || (alloc != 0 && alloc != size) {
        return None;
    }
    let mut b = if data.len() >= size {
        data[..size].to_vec()
    } else {
        let mut v = vec![0u8; size];
        if read_full(src, abs, &mut v).ok()? < size {
            return None;
        }
        v
    };
    let rec = parse_record(&mut b)?;
    if rec.name.is_none() && rec.data.is_empty() && rec.hdr.base == 0 {
        return None;
    }
    Some(Loose { off: abs, size: size as u32, number: rec.hdr.number.map(|n| n as u64), rec, live: false })
}

impl ChunkVisitor for Sweep {
    fn name(&self) -> &'static str {
        "ntfs-sweep"
    }

    fn visit(&self, src: &dyn BlockSource, offset: u64, data: &[u8], ctx: &ScanCtx) {
        let live = self.live.get_or_init(|| live_info(src));
        let keep_existing = ctx.include_existing();
        let mut out = Vec::new();
        let mut i = ((512 - offset % 512) % 512) as usize;
        while i + 0x30 <= data.len() {
            if &data[i..i + 4] == b"FILE" {
                let abs = offset + i as u64;
                if !inside(&live.skip, abs) {
                    if let Some(mut l) = parse_at(src, abs, &data[i..]) {
                        l.live = inside(&live.mounted_ranges, abs);
                        // Existing files of a mounted volume are only kept when they're wanted.
                        if keep_existing || !l.live || !existing_file(&l) {
                            out.push(l);
                        }
                    }
                }
            }
            i += 512;
        }
        if !out.is_empty() {
            self.found.lock().unwrap_or_else(|e| e.into_inner()).extend(out);
        }
    }

    fn finish(&self, src: &dyn BlockSource, ctx: &ScanCtx) -> Result<EngineSummary, String> {
        let mut loose = std::mem::take(&mut *self.found.lock().unwrap_or_else(|e| e.into_inner()));
        let mounted = self.live.get().map(|l| l.mounted.clone()).unwrap_or_default();
        finish_with(&mut loose, self.probe.as_ref(), &mounted, src, ctx)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Vol {
    start: u64,
    cluster: u64,
    /// Geometry is a guess (no leftover $MFT record found).
    assumed: bool,
}

/// Cluster size implied by a non-resident first piece: allocated size / clusters.
fn implied_cluster(p: &DataPiece) -> Option<u64> {
    let n = total_clusters(&p.runs);
    if p.resident.is_some() || p.start_vcn != 0 || n == 0 || p.alloc == 0 || p.alloc % n != 0 {
        return None;
    }
    let c = p.alloc / n;
    (c.is_power_of_two() && (512..=2 << 20).contains(&c)).then_some(c)
}

/// Volumes described by leftover `$MFT` records: the record sits at volume start + first LCN ×
/// cluster size, and the real table (not the 4-record mirror) has more records right after it.
fn infer_volumes(loose: &[Loose]) -> Vec<Vol> {
    let by_off: HashMap<u64, &Loose> = loose.iter().map(|l| (l.off, l)).collect();
    let mut vols: Vec<Vol> = Vec::new();
    for l in loose {
        if l.number != Some(0) || l.rec.hdr.base != 0 || l.rec.name.as_ref().map_or(true, |n| n.name != "$MFT") {
            continue;
        }
        let Some(p) = l.rec.data.iter().find(|p| p.name.is_empty() && p.start_vcn == 0 && p.resident.is_none()) else { continue };
        let Some(c) = implied_cluster(p) else { continue };
        let Some(lcn) = p.runs.first().and_then(|r| r.lcn) else { continue };
        let Some(start) = l.off.checked_sub(lcn.saturating_mul(c)) else { continue };
        if start % 512 != 0 {
            continue;
        }
        let rs = l.size as u64;
        let followed = (4..24u64).any(|k| by_off.get(&(l.off + k * rs)).map_or(false, |x| x.number.map_or(true, |n| n == k)));
        if !followed {
            continue;
        }
        if !vols.iter().any(|v| v.start == start) {
            vols.push(Vol { start, cluster: c, assumed: false });
        }
    }
    vols.sort_by_key(|v| v.start);
    vols
}

#[allow(dead_code)] // Without partition information; the visitor uses `finish_with`.
pub fn finish_loose(loose: &mut Vec<Loose>, probe: Option<&FsProbe>, src: &dyn BlockSource, ctx: &ScanCtx) -> Result<EngineSummary, String> {
    finish_with(loose, probe, &[], src, ctx)
}

fn finish_with(loose: &mut Vec<Loose>, probe: Option<&FsProbe>, mounted: &[Mounted], src: &dyn BlockSource, ctx: &ScanCtx) -> Result<EngineSummary, String> {
    let mut sum = EngineSummary::default();
    if loose.is_empty() {
        return Ok(sum);
    }
    loose.sort_by_key(|l| l.off);
    loose.dedup_by_key(|l| l.off);
    ctx.info(format!("Found {} file records outside the live file table.", loose.len()));

    let mut vols = infer_volumes(loose);
    for v in vols.iter().filter(|v| !mounted.iter().any(|m| m.start == v.start)) {
        sum.notes.push(format!(
            "A leftover file table shows a volume starting at byte {} with {} clusters.",
            v.start,
            human_size(v.cluster)
        ));
    }
    if let Some(p) = probe.filter(|p| p.fs == "NTFS" && p.cluster_size > 0) {
        if !vols.iter().any(|v| v.start == 0) {
            vols.insert(0, Vol { start: 0, cluster: p.cluster_size as u64, assumed: false });
        }
    }
    for m in mounted {
        if !vols.iter().any(|v| v.start == m.start) {
            vols.push(Vol { start: m.start, cluster: m.cluster, assumed: false });
        }
    }
    vols.sort_by_key(|v| v.start);
    if vols.is_empty() {
        let mut votes: HashMap<u64, usize> = HashMap::new();
        for l in loose.iter() {
            for p in &l.rec.data {
                if let Some(c) = implied_cluster(p) {
                    *votes.entry(c).or_default() += 1;
                }
            }
        }
        if let Some((&c, _)) = votes.iter().max_by_key(|(c, n)| (**n, **c)) {
            vols.push(Vol { start: 0, cluster: c, assumed: true });
            sum.notes.push(format!(
                "The leftover file records use {} clusters, but the volume's start couldn't be confirmed; file locations assume it begins at the start of this drive or image.",
                human_size(c)
            ));
        } else {
            sum.notes.push("The volume layout of the leftover file records couldn't be worked out, so only files stored inside the records can be recovered.".into());
        }
    }
    let multi = vols.len() > 1;
    // Volume of each record: the last one starting at or before it.
    let vol_of = |off: u64| -> Option<usize> { vols.iter().rposition(|v| v.start <= off) };

    // Per volume: extension records and directories by record number.
    let mut exts: Vec<HashMap<u64, ExtRec>> = vec![HashMap::new(); vols.len().max(1)];
    let mut dirs_by_no: HashMap<(usize, u64), Vec<usize>> = HashMap::new();
    for (i, l) in loose.iter().enumerate() {
        let (Some(v), Some(n)) = (vol_of(l.off), l.number) else { continue };
        if l.rec.hdr.base != 0 {
            exts[v].insert(n, ExtRec { base: l.rec.hdr.base, seq: l.rec.hdr.seq, in_use: l.rec.in_use(), data: l.rec.data.clone(), name: l.rec.name.clone() });
        } else if l.rec.is_dir() {
            dirs_by_no.entry((v, n)).or_default().push(i);
        }
    }

    // Folder tree keyed by loose index; synthetic roots per volume above that.
    let root_key = |v: usize| -> u64 { u64::MAX - v as u64 };
    let parent_of = |i: usize, pref: u64| -> Option<u64> {
        let l = &loose[i];
        let v = vol_of(l.off)?;
        let p = ref_rec(pref);
        if p == ROOT {
            return Some(root_key(v));
        }
        let c = dirs_by_no.get(&(v, p))?;
        c.iter()
            .copied()
            .filter(|&k| k != i && seq_ok(loose[k].rec.hdr.seq, ref_seq(pref), loose[k].rec.in_use()))
            .min_by_key(|&k| loose[k].off.abs_diff(l.off))
            .map(|k| k as u64)
    };
    let mut tree = Tree::new();
    for v in 0..vols.len().max(1) {
        let fixed = if multi { format!("\\Volume {} (NTFS)", v + 1) } else { String::new() };
        tree.insert(root_key(v), Node { name: String::new(), parent: None, label: ROOT, fixed: Some(fixed) });
    }
    for (i, l) in loose.iter().enumerate() {
        if l.rec.hdr.base != 0 || !l.rec.is_dir() || l.number == Some(ROOT) {
            continue;
        }
        let (name, parent) = match &l.rec.name {
            Some(n) => (n.name.clone(), parent_of(i, n.parent)),
            None => (String::new(), None),
        };
        tree.insert(i as u64, Node { name, parent, label: l.number.unwrap_or(0), fixed: None });
    }

    // Recycle Bin: `$R` names back from `$I` records, as in the quick scan.
    let n_roots = vols.len().max(1) as u64;
    let is_root = |k: u64| k > u64::MAX - n_roots;
    let bins: HashSet<u64> =
        tree.nodes.iter().filter(|(_, n)| n.name.eq_ignore_ascii_case("$Recycle.Bin") && n.parent.map_or(false, is_root)).map(|(&k, _)| k).collect();
    let sids: HashSet<u64> = tree.nodes.iter().filter(|(_, n)| n.parent.map_or(false, |p| bins.contains(&p))).map(|(&k, _)| k).collect();
    let mut infos = Vec::new();
    if !sids.is_empty() {
        for (i, l) in loose.iter().enumerate() {
            let Some(n) = l.rec.name.as_ref().filter(|n| l.rec.hdr.base == 0 && !l.rec.is_dir() && i_id(&n.name).is_some()) else { continue };
            let Some(parent) = parent_of(i, n.parent).filter(|p| sids.contains(p)) else { continue };
            let Some(s) = assemble(l.rec.data.clone()).into_iter().find(|s| s.name.is_empty()) else { continue };
            let data = match (&s.resident, vol_of(l.off)) {
                (Some(d), _) => d.clone(),
                (None, Some(v)) if s.real <= 64 * 1024 && !vols[v].assumed => read_runs_bytes(src, &s.runs, vols[v].cluster, vols[v].start, s.real, 64 * 1024),
                _ => continue,
            };
            infos.push(InfoRec { parent, id: i_id(&n.name).unwrap_or_default(), in_use: l.rec.in_use(), data });
        }
    }
    let info_index = InfoIndex::new(infos);
    let parse_info: &dyn Fn(&[u8]) -> Option<crate::recyclebin::RecycleInfo> = &crate::recyclebin::parse_info_file;
    if !info_index.is_empty() {
        let keys: Vec<u64> = tree.nodes.keys().copied().filter(|k| !is_root(*k)).collect();
        for k in keys {
            let n = &tree.nodes[&k];
            let Some(p) = n.parent.filter(|p| sids.contains(p)) else { continue };
            if let Some(r) = info_index.restore(&n.name, p, loose[k as usize].rec.in_use(), parse_info) {
                if let Some(n) = tree.nodes.get_mut(&k) {
                    n.fixed = Some(format!("{}\\{}", r.folder, component(&r.name)));
                }
            }
        }
    }

    // Report. Files reported earlier (by other engines / the quick scan) as of now are skipped;
    // the ones reported below don't hide each other (an overwritten file shares clusters).
    let known: HashSet<u64> = ctx.known_starts.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let allocated = ctx.allocated.read().unwrap_or_else(|e| e.into_inner());
    let alloc = if allocated.is_empty() { Alloc::None } else { Alloc::Ranges(&allocated) };
    let mut seen_starts: HashSet<(u64, String, u64)> = HashSet::new();
    let mut seen_resident: HashSet<(usize, u64, String, u64)> = HashSet::new();
    let src_len = src.len();
    let (mut skipped_known, mut lost_files) = (0u64, 0u64);
    for i in 0..loose.len() {
        if i % 512 == 511 {
            ctx.check()?;
        }
        let l = &loose[i];
        if l.rec.hdr.base != 0 || l.rec.is_dir() || l.number.map_or(false, |n| n < FIRST_USER_RECORD) {
            continue;
        }
        let vi = vol_of(l.off);
        let vol = vi.map(|v| vols[v]);
        let ext_map = vi.map(|v| &exts[v]);
        let empty = HashMap::new();
        let (pieces, ext_ok, ext_name) = gather_pieces(
            l.number.unwrap_or(u64::MAX),
            &l.rec,
            ext_map.unwrap_or(&empty),
            src,
            vol.map_or(4096, |v| v.cluster),
            vol.map_or(0, |v| v.start),
        );
        let fname = l.rec.name.clone().or(ext_name);
        let Some(fname) = fname else { continue };
        let p = parent_of(i, fname.parent);
        let (folder, lost) = tree.folder_for(p, ref_rec(fname.parent));
        if folder.contains("\\$Extend") {
            continue;
        }
        let in_bin = p.map_or(false, |k| sids.contains(&k));
        if in_bin && i_id(&fname.name).is_some() {
            continue; // Recycle Bin bookkeeping.
        }
        let restore = if in_bin { info_index.restore(&fname.name, p.unwrap_or(0), l.rec.in_use(), parse_info) } else { None };
        let lost = lost && restore.is_none();
        // A file still in use in a mounted volume's table exists; elsewhere the in-use flag is
        // stale (a formatted volume, an old copy of the table).
        let existing = l.live && l.rec.in_use();
        if existing && !ctx.include_existing() {
            continue;
        }
        let status = match (existing, &restore) {
            (true, Some(_)) => FileStatus::RecycleBin,
            (true, None) => FileStatus::Existing,
            (false, _) if lost => FileStatus::Lost,
            _ => FileStatus::Deleted,
        };
        for s in assemble(pieces) {
            let size = s.resident.as_ref().map_or(s.real, |r| r.len() as u64);
            if size == 0 || (!s.name.is_empty() && (existing || s.name.eq_ignore_ascii_case("Zone.Identifier"))) {
                continue;
            }
            if s.resident.is_none() && vol.is_none() {
                continue;
            }
            let shown = if s.name.is_empty() { fname.name.clone() } else { format!("{}:{}", fname.name, s.name) };
            let v = vol.unwrap_or(Vol { start: 0, cluster: 4096, assumed: true });
            let mut f = make_file(
                Item {
                    record: l.number.unwrap_or(0),
                    name: shown,
                    folder: folder.clone(),
                    status,
                    si: l.rec.si.as_ref(),
                    fname: Some(&fname),
                    stream: &s,
                    complete: l.rec.complete && ext_ok,
                    cluster: v.cluster,
                    base: v.start,
                    src_len,
                },
                if v.assumed { &Alloc::None } else { &alloc },
            );
            f.flags |= flags::LOOSE_RECORD;
            if l.number.is_none() {
                f.fs_ref = None;
                f.meta.remove("mftRecord");
            }
            f.meta.insert("recordOffset".into(), l.off.to_string());
            if let Some(r) = &restore {
                f.name = if s.name.is_empty() { r.name.clone() } else { format!("{}:{}", r.name, s.name) };
                f.folder = r.folder.clone();
                f.type_id = f.ext();
                f.deleted = r.deleted;
                f.flags |= flags::FROM_RECYCLE_INFO;
                f.meta.insert("originalPath".into(), r.original.clone());
                f.meta.insert("recycledAs".into(), r.recycled_as.clone());
            }
            if v.assumed && f.condition != Condition::Partial {
                f.condition = Condition::Unknown;
                f.note = "Found in a leftover file table; its location on the drive is a guess.".into();
            }
            match f.first_offset() {
                Some(o) => {
                    if known.contains(&o) || !seen_starts.insert((o, f.name.clone(), f.size)) {
                        skipped_known += 1;
                        continue;
                    }
                }
                None => {
                    if !seen_resident.insert((vi.unwrap_or(usize::MAX), l.number.unwrap_or(l.off), f.name.clone(), f.size)) {
                        continue;
                    }
                }
            }
            sum.files += 1;
            if !existing {
                sum.deleted += 1;
                if lost {
                    lost_files += 1;
                }
            }
            ctx.found(f);
        }
    }
    sum.lost_folders = tree.lost_roots.len() as u64;
    if skipped_known > 0 {
        ctx.info(format!("{skipped_known} files in leftover records were already found and weren't listed twice."));
    }
    sum.notes.push(format!(
        "Rebuilt {} files from leftover file records ({} of them in lost folders).",
        sum.files, lost_files
    ));
    for n in &sum.notes {
        ctx.info(n.clone());
    }
    Ok(sum)
}
