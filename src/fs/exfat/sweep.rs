//! Deep-scan sweep for exFAT: directory clusters holding entry sets that the live tree doesn't
//! reach (formatted volume, lost folders) are rebuilt under "\Lost folders".

use super::scan::{assess, make_file, mount, parse_dir, parse_set, walk, XParsed};
use crate::device::source::BlockSource;
use crate::model::{flags, ChunkVisitor, EngineSummary, FileStatus, FsProbe, MapKind, ScanCtx};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Mutex;

pub(crate) struct ExfatSweep {
    hits: Mutex<Vec<u64>>,
}

pub(crate) fn new_sweep(_probe: Option<&FsProbe>) -> ExfatSweep {
    ExfatSweep { hits: Mutex::new(Vec::new()) }
}

/// Offsets of File entries that start a valid entry set (checksum verified).
pub(crate) fn scan_buf(offset: u64, data: &[u8], out: &mut Vec<u64>) {
    let mut p = ((32 - (offset % 32)) % 32) as usize;
    while p + 96 <= data.len() {
        let t = data[p];
        if (t == 0x85 || t == 0x05) && (2..=18).contains(&data[p + 1]) && (data[p + 32] == 0xC0 || data[p + 32] == 0x40) {
            let end = (p + 19 * 32).min(data.len());
            if let Some((e, n)) = parse_set(&data[p..end], 0, 0) {
                if e.checksum_ok {
                    out.push(offset + p as u64);
                    p += n * 32;
                    continue;
                }
            }
        }
        p += 32;
    }
}

impl ChunkVisitor for ExfatSweep {
    fn name(&self) -> &'static str {
        "exfat-sweep"
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
        hits.sort_unstable();
        hits.dedup();
        rebuild(src, ctx, &hits)
    }
}

fn rebuild(src: &dyn BlockSource, ctx: &ScanCtx, hits: &[u64]) -> Result<EngineSummary, String> {
    let mut sum = EngineSummary::default();
    if hits.is_empty() {
        return Ok(sum);
    }
    let Ok(mut v) = mount(src, None) else {
        sum.notes.push("Some exFAT folders were found, but without a readable boot sector their files can't be located.".into());
        return Ok(sum);
    };
    let reach = walk(&mut v, ctx, false)?;
    let mut clusters: BTreeSet<u32> = BTreeSet::new();
    for &h in hits {
        let Some(c) = v.g.cluster_of(h) else { continue };
        let o = v.g.cluster_offset(c);
        if reach.dir_clusters.contains(&c) || v.meta.contains(o) {
            continue;
        }
        clusters.insert(c);
    }
    if clusters.is_empty() {
        return Ok(sum);
    }
    // Folder starts named by any directory entry (live tree or the lost clusters themselves).
    let mut names: HashMap<u32, String> = reach.names.clone();
    for &c in &clusters {
        ctx.check()?;
        let (buf, offs) = v.read_clusters(&[c], None);
        for e in parse_dir(&buf, &offs, v.tz_ms).entries {
            if e.is_dir() && v.g.valid_cluster(e.first_cluster) {
                names.entry(e.first_cluster).or_insert(e.name);
            }
        }
    }
    // Group adjacent clusters into folders, splitting where a known folder starts.
    let mut groups: Vec<Vec<u32>> = Vec::new();
    for &c in &clusters {
        match groups.last_mut() {
            Some(g) if g.last().is_some_and(|&l| l + 1 == c) && !names.contains_key(&c) && g.len() < 8192 => g.push(c),
            _ => groups.push(vec![c]),
        }
    }
    let mut parsed: BTreeMap<u32, (Vec<u32>, XParsed)> = BTreeMap::new();
    for g in groups {
        ctx.check()?;
        let (buf, offs) = v.read_clusters(&g, None);
        let p = parse_dir(&buf, &offs, v.tz_ms);
        parsed.insert(g[0], (g, p));
    }
    // Parent links: a directory entry inside one lost folder pointing at another's first cluster.
    let mut parent: HashMap<u32, u32> = HashMap::new();
    for (&id, (_, p)) in &parsed {
        for e in &p.entries {
            if e.is_dir() && e.first_cluster != id && parsed.contains_key(&e.first_cluster) {
                parent.entry(e.first_cluster).or_insert(id);
            }
        }
    }
    let label = |c: u32| match names.get(&c) {
        Some(n) if !n.is_empty() => crate::model::safe_file_name(n),
        _ => format!("Folder {c}"),
    };
    let mut paths: HashMap<u32, String> = HashMap::new();
    for &id in parsed.keys() {
        let mut chain = vec![id];
        let mut cur = id;
        while let Some(&p) = parent.get(&cur) {
            if chain.contains(&p) || chain.len() > 64 {
                break;
            }
            chain.push(p);
            if paths.contains_key(&p) {
                break;
            }
            cur = p;
        }
        let top = *chain.last().unwrap_or(&id);
        let mut path = match paths.get(&top) {
            Some(p) => p.clone(),
            None => {
                sum.lost_folders += 1;
                format!("\\Lost folders\\{}", label(top))
            }
        };
        paths.insert(top, path.clone());
        for &c in chain.iter().rev().skip(1) {
            path = format!("{}\\{}", path, label(c));
            paths.insert(c, path.clone());
        }
    }
    let mut seen: HashSet<u64> = HashSet::new();
    for (&id, (list, p)) in &parsed {
        ctx.check()?;
        let cs = v.g.cluster_size as u64;
        for &c in list {
            ctx.mark(MapKind::Metadata, v.g.cluster_offset(c), cs);
        }
        let folder = paths.get(&id).cloned().unwrap_or_else(|| format!("\\Lost folders\\Folder {id}"));
        for e in &p.entries {
            if e.is_dir() || !seen.insert(e.offset) {
                continue;
            }
            let live_chain = !e.deleted && v.used(e.first_cluster) == Some(true);
            let a = assess(&v, e, !live_chain);
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
    if sum.lost_folders > 0 {
        let msg = format!("Rebuilt {} lost exFAT folders with {} files.", sum.lost_folders, sum.files);
        ctx.info(msg.clone());
        sum.notes.push(msg);
    }
    Ok(sum)
}
