//! Quick scan: stream the live MFT, keep what matters (directories, deleted files, extension
//! records, Recycle Bin `$I` records), then rebuild folders and report files with allocation
//! evidence from the live $Bitmap.

use super::boot::{find_boot, Boot};
use super::record::*;
use super::recycle::{i_id, r_id, InfoIndex, InfoRec, Restore};
use super::report::{assemble, make_file, Alloc, Item};
use super::runs::{total_clusters, Run};
use super::tree::{Node, Tree};
use crate::device::source::{read_tolerant, BlockSource};
use crate::model::*;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};

/// Records below this number are NTFS's own metadata files.
pub const FIRST_USER_RECORD: u64 = 24;
pub const ROOT: u64 = 5;
const CHUNK: usize = 1 << 20;

/// A piece of the MFT: byte offset inside the MFT, byte offset on the source, length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MftExtent {
    pub vpos: u64,
    pub phys: u64,
    pub len: u64,
}

/// Where the MFT's bytes are.
#[derive(Clone, Debug, Default)]
pub struct MftMap {
    pub extents: Vec<MftExtent>,
    pub size: u64,
    /// Layout guessed (record 0 unreadable): one piece from the boot sector's MFT position.
    pub guessed: bool,
}

impl MftMap {
    pub fn from_runs(runs: &[Run], cluster: u64, size: u64) -> MftMap {
        let mut extents = Vec::new();
        let mut v = 0u64;
        for r in runs {
            let len = r.len.saturating_mul(cluster);
            if let Some(l) = r.lcn {
                extents.push(MftExtent { vpos: v, phys: l.saturating_mul(cluster), len });
            }
            v = v.saturating_add(len);
        }
        let size = size.min(v);
        MftMap { extents, size, guessed: false }
    }

    /// Read MFT bytes [vpos, vpos + buf.len()) (zeros where unmapped). Returns unreadable ranges
    /// in MFT coordinates.
    pub fn read(&self, src: &dyn BlockSource, vpos: u64, buf: &mut [u8], ctx: Option<&ScanCtx>) -> Vec<(u64, u64)> {
        buf.fill(0);
        let end = vpos.saturating_add(buf.len() as u64);
        let mut bad_v = Vec::new();
        for e in &self.extents {
            let (s, t) = (vpos.max(e.vpos), end.min(e.vpos.saturating_add(e.len)));
            if s >= t {
                continue;
            }
            let piece = &mut buf[(s - vpos) as usize..(t - vpos) as usize];
            let phys = e.phys.saturating_add(s - e.vpos);
            let (n, bad) = read_tolerant(src, phys, piece, ctx);
            if let Some(ctx) = ctx {
                let mut at = phys;
                for &(bs, be) in &bad {
                    ctx.mark(MapKind::Scanned, at, bs.saturating_sub(at));
                    at = be;
                }
                ctx.mark(MapKind::Scanned, at, (phys + n as u64).saturating_sub(at));
            }
            for (bs, be) in bad {
                bad_v.push((bs - phys + s, be - phys + s));
            }
        }
        bad_v
    }
}

/// Read up to `max` bytes of a small non-resident stream.
pub fn read_runs_bytes(src: &dyn BlockSource, runs: &[Run], cluster: u64, base: u64, size: u64, max: u64) -> Vec<u8> {
    let size = size.min(max);
    let mut out = vec![0u8; size as usize];
    let mut v = 0u64;
    for r in runs {
        if v >= size {
            break;
        }
        let len = r.len.saturating_mul(cluster).min(size - v);
        if let Some(l) = r.lcn {
            let piece = &mut out[v as usize..(v + len) as usize];
            read_tolerant(src, base.saturating_add(l.saturating_mul(cluster)), piece, None);
        }
        v += len;
    }
    out
}

/// Sequence-number check for a reference to a record. Windows bumps a record's sequence number
/// when it is freed, so a deleted record may be one ahead of the references to it.
pub fn seq_ok(actual: u16, expected: u16, in_use: bool) -> bool {
    expected == 0 || actual == expected || (!in_use && actual == expected.wrapping_add(1))
}

/// Compact directory facts.
#[derive(Clone, Debug)]
pub struct DirRec {
    pub name: String,
    pub parent: u64,
    pub seq: u16,
    pub in_use: bool,
}

/// An extension record's attributes.
#[derive(Clone, Debug)]
pub struct ExtRec {
    pub base: u64,
    pub seq: u16,
    pub in_use: bool,
    pub data: Vec<DataPiece>,
    pub name: Option<FileName>,
}

enum Parsed {
    Empty,
    Damaged,
    BadSector,
    Skip { torn: bool },
    Rec(Box<Rec>, bool),
}

fn classify(recno: u64, buf: &mut [u8], include_existing: bool) -> Parsed {
    if &buf[0..4] != b"FILE" {
        return if &buf[0..4] == b"BAAD" { Parsed::Damaged } else { Parsed::Empty };
    }
    let Some((h, fx)) = prepare(buf) else { return Parsed::Damaged };
    if recno >= FIRST_USER_RECORD && h.base == 0 && h.in_use() && !h.is_dir() && !include_existing && !name_starts_with(buf, &h, &fx, b"$I") {
        return Parsed::Skip { torn: fx.torn };
    }
    Parsed::Rec(Box::new(parse_prepared(buf, h, fx)), fx.torn)
}

/// The data pieces of a base record, with the ones living in extension records (through its
/// $ATTRIBUTE_LIST) added. Returns (pieces, all found, name from an extension if the base has none).
pub fn gather_pieces(
    recno: u64,
    rec: &Rec,
    exts: &HashMap<u64, ExtRec>,
    src: &dyn BlockSource,
    cluster: u64,
    base: u64,
) -> (Vec<DataPiece>, bool, Option<FileName>) {
    let mut pieces = rec.data.clone();
    let Some(al) = &rec.attr_list else { return (pieces, true, None) };
    let bytes = match al {
        AttrListSrc::Resident(b) => b.clone(),
        AttrListSrc::NonResident { runs, size } => read_runs_bytes(src, runs, cluster, base, *size, 4 << 20),
    };
    let entries = parse_attr_list(&bytes);
    let mut complete = !entries.is_empty();
    let mut name = None;
    for e in &entries {
        let r = ref_rec(e.rec);
        if r == recno || (e.ty != ATTR_DATA && e.ty != ATTR_FILE_NAME) {
            continue;
        }
        let x = match exts.get(&r) {
            Some(x) if ref_rec(x.base) == recno && seq_ok(x.seq, ref_seq(e.rec), x.in_use) => x,
            _ => {
                if e.ty == ATTR_DATA {
                    complete = false;
                }
                continue;
            }
        };
        if e.ty == ATTR_FILE_NAME {
            if rec.name.is_none() && name.is_none() {
                name = x.name.clone();
            }
            continue;
        }
        match x.data.iter().find(|p| p.name == e.name && p.start_vcn == e.start_vcn) {
            Some(p) => pieces.push(p.clone()),
            None => complete = false,
        }
    }
    (pieces, complete, name)
}

/// Bootstrap: where is the MFT? Record 0 ($MFT) from the MFT, else from $MFTMirr; follows its
/// attribute list for very fragmented MFTs. Falls back to one guessed piece.
pub fn mft_map(src: &dyn BlockSource, boot: &Boot, notes: &mut Vec<String>) -> MftMap {
    let rs = boot.record_size as usize;
    let cs = boot.cluster_size as u64;
    for (off, mirror) in [(boot.mft_offset(), false), (boot.mftmirr_offset(), true)] {
        let mut b = vec![0u8; rs];
        let (n, bad) = read_tolerant(src, off, &mut b, None);
        if n < rs || !bad.is_empty() {
            continue;
        }
        let Some(rec) = parse_record(&mut b) else { continue };
        let mut pieces: Vec<DataPiece> = rec.data.iter().filter(|p| p.name.is_empty() && p.resident.is_none()).cloned().collect();
        if !pieces.iter().any(|p| p.start_vcn == 0 && !p.runs.is_empty() && p.real >= rs as u64 * 16) {
            continue;
        }
        if let Some(al) = &rec.attr_list {
            // Extension records holding later pieces of $MFT's $DATA, read through what is known.
            let first = assemble(pieces.clone());
            let map0 = MftMap::from_runs(&first[0].runs, cs, u64::MAX);
            let bytes = match al {
                AttrListSrc::Resident(v) => v.clone(),
                AttrListSrc::NonResident { runs, size } => read_runs_bytes(src, runs, cs, 0, *size, 1 << 20),
            };
            let mut known = map0;
            for _round in 0..4 {
                let mut added = false;
                for e in parse_attr_list(&bytes) {
                    let r = ref_rec(e.rec);
                    if e.ty != ATTR_DATA || !e.name.is_empty() || r == 0 || pieces.iter().any(|p| p.start_vcn == e.start_vcn) {
                        continue;
                    }
                    let Some(vpos) = r.checked_mul(rs as u64) else { continue };
                    if !known.extents.iter().any(|x| vpos >= x.vpos && vpos.saturating_add(rs as u64) <= x.vpos.saturating_add(x.len)) {
                        continue;
                    }
                    let mut eb = vec![0u8; rs];
                    known.read(src, vpos, &mut eb, None);
                    if let Some(x) = parse_record(&mut eb) {
                        if ref_rec(x.hdr.base) == 0 {
                            for p in x.data.into_iter().filter(|p| p.name.is_empty() && p.start_vcn == e.start_vcn) {
                                pieces.push(p);
                                added = true;
                            }
                        }
                    }
                }
                let s = assemble(pieces.clone());
                known = MftMap::from_runs(&s[0].runs, cs, u64::MAX);
                if !added {
                    break;
                }
            }
        }
        let s = assemble(pieces);
        let map = MftMap::from_runs(&s[0].runs, cs, s[0].real);
        if mirror {
            notes.push("The file table's first record is damaged, so its copy in the mirror was used.".into());
        }
        if !s[0].complete || total_clusters(&s[0].runs).saturating_mul(cs) < s[0].real {
            notes.push("Part of the file table's own location list is missing, so some files may not be listed.".into());
        }
        return map;
    }
    notes.push("The file table's own record is damaged in both copies, so the table was read as one piece from where it starts; some files may be missing.".into());
    let start = boot.mft_offset();
    let size = src.len().saturating_sub(start).min(boot.volume_bytes().saturating_sub(start)).min(8 << 30);
    MftMap { extents: vec![MftExtent { vpos: 0, phys: start, len: size }], size, guessed: true }
}

/// Add bitmap bytes [from, to) to the unknown cluster ranges (kept sorted and merged; bytes come
/// in increasing order).
fn push_unknown(unknown: &mut Vec<(u64, u64)>, from: u64, to: u64, total_clusters: u64) {
    let (a, b) = (from.saturating_mul(8).min(total_clusters), to.saturating_mul(8).min(total_clusters));
    if a >= b {
        return;
    }
    match unknown.last_mut() {
        Some(l) if l.1 >= a => l.1 = l.1.max(b),
        _ => unknown.push((a, b)),
    }
}

/// Streams the live $Bitmap: marks Allocated runs and returns the bitmap (when it is small
/// enough to keep: up to 512 MiB, i.e. 16 TB volumes with 4 KiB clusters).
/// Parts that can't be known (unreadable sectors, runs that are missing or lie outside the
/// volume, a bitmap shorter than the volume) are set to "used", so nothing there is judged free
/// or carved as free space, and their cluster ranges are added to `unknown`.
fn load_bitmap(
    src: &dyn BlockSource,
    ctx: &ScanCtx,
    s: &super::report::Stream,
    cluster: u64,
    total_clusters: u64,
    unknown: &mut Vec<(u64, u64)>,
) -> Option<Vec<u8>> {
    let mut open: Option<u64> = None;
    let mut v = 0u64; // byte position in the bitmap
    let mut keep = true;
    let mut all = Vec::new();
    if let Some(b) = &s.resident {
        mark_bit_runs(ctx, b, 0, cluster, total_clusters, &mut open);
        all = b.clone();
        v = b.len() as u64;
    } else {
        let size = s.real.min(total_clusters.div_ceil(8) + 8);
        keep = size <= 512 << 20;
        if keep {
            all.reserve(size as usize);
        }
        let mut buf = vec![0u8; CHUNK];
        for r in &s.runs {
            let run_bytes = r.len.saturating_mul(cluster);
            // Byte offset and in-volume length of the run (None: outside the volume).
            let range = r.lcn.and_then(|l| run_range(l, r.len, cluster, total_clusters));
            let mut done = 0u64;
            while done < run_bytes && v < size {
                let n = (CHUNK as u64).min(run_bytes - done).min(size - v) as usize;
                let piece = &mut buf[..n];
                match range.filter(|&(_, l)| done < l).and_then(|(o, _)| o.checked_add(done)) {
                    Some(off) => {
                        piece.fill(0);
                        let (got, bad) = read_tolerant(src, off, piece, Some(ctx));
                        ctx.mark(MapKind::Scanned, off, got as u64);
                        ctx.mark(MapKind::Metadata, off, n as u64);
                        for (bs, be) in bad {
                            let (a, b) = ((bs - off) as usize, (be - off) as usize);
                            piece[a..b].fill(0xFF);
                            push_unknown(unknown, v + a as u64, v + b as u64, total_clusters);
                        }
                        if got < n {
                            piece[got..].fill(0xFF);
                            push_unknown(unknown, v + got as u64, v + n as u64, total_clusters);
                        }
                    }
                    None => {
                        piece.fill(0xFF);
                        push_unknown(unknown, v, v + n as u64, total_clusters);
                    }
                }
                mark_bit_runs(ctx, piece, v * 8, cluster, total_clusters, &mut open);
                if keep {
                    all.extend_from_slice(piece);
                }
                v += n as u64;
                done += n as u64;
            }
        }
    }
    if v.saturating_mul(8) < total_clusters {
        // The bitmap ends before the volume does (runs missing): the rest is unknown.
        push_unknown(unknown, v, total_clusters.div_ceil(8), total_clusters);
        open = open.or(Some(v * 8));
    }
    if let Some(s0) = open.take() {
        ctx.mark(MapKind::Allocated, s0 * cluster, (total_clusters.saturating_sub(s0)) * cluster);
    }
    if keep {
        Some(all)
    } else {
        None
    }
}

/// Mark the set runs of a bitmap piece whose first bit is cluster `first`. `open` carries a run
/// across pieces (None for a one-shot call, which closes its runs itself).
fn mark_bit_runs(ctx: &ScanCtx, bits: &[u8], first: u64, cluster: u64, total: u64, open: &mut Option<u64>) {
    let one_shot = open.is_none() && first == 0 && bits.len() as u64 * 8 >= total;
    let mut c = first;
    for &byte in bits {
        if c >= total {
            break;
        }
        match byte {
            0xFF => {
                if open.is_none() {
                    *open = Some(c);
                }
            }
            0x00 => {
                if let Some(s) = open.take() {
                    ctx.mark(MapKind::Allocated, s * cluster, (c - s) * cluster);
                }
            }
            _ => {
                for bit in 0..8 {
                    let cc = c + bit;
                    if cc >= total {
                        break;
                    }
                    if byte >> bit & 1 == 1 {
                        if open.is_none() {
                            *open = Some(cc);
                        }
                    } else if let Some(s) = open.take() {
                        ctx.mark(MapKind::Allocated, s * cluster, (cc - s) * cluster);
                    }
                }
            }
        }
        c += 8;
    }
    if one_shot {
        if let Some(s) = open.take() {
            ctx.mark(MapKind::Allocated, s * cluster, (total.min(c) - s) * cluster);
        }
    }
}

/// Byte range (offset, length) of a run of clusters on the volume, cut at the volume's end; None
/// when it starts beyond it (a corrupt run list can hold any LCN).
fn run_range(lcn: u64, len: u64, cluster: u64, total_clusters: u64) -> Option<(u64, u64)> {
    if lcn >= total_clusters {
        return None;
    }
    let len = len.min(total_clusters - lcn);
    Some((lcn.checked_mul(cluster)?, len.checked_mul(cluster)?))
}

/// Second pass: an existing (in-use) file's base record, fully parsed; None for anything else.
fn existing_file(recno: u64, buf: &mut [u8]) -> Option<Box<Rec>> {
    if recno < FIRST_USER_RECORD || &buf[0..4] != b"FILE" {
        return None;
    }
    let (h, fx) = prepare(buf)?;
    if h.base != 0 || !h.in_use() || h.is_dir() {
        return None;
    }
    Some(Box::new(parse_prepared(buf, h, fx)))
}

/// Read MFT bytes [vpos, vpos + buf.len()) around ranges already known to be unreadable (sorted,
/// MFT coordinates), which stay zero, so a second pass doesn't retry bad sectors.
fn read_skipping(map: &MftMap, src: &dyn BlockSource, vpos: u64, buf: &mut [u8], bad: &[(u64, u64)]) {
    buf.fill(0);
    let end = vpos + buf.len() as u64;
    let mut at = vpos;
    for &(s, e) in bad.iter().chain(std::iter::once(&(end, end))) {
        let s = s.clamp(vpos, end);
        if s > at {
            map.read(src, at, &mut buf[(at - vpos) as usize..(s - vpos) as usize], None);
        }
        at = at.max(e.min(end));
    }
}

pub fn quick_scan(src: &dyn BlockSource, ctx: &ScanCtx) -> Result<EngineSummary, String> {
    let (boot, used_backup) =
        find_boot(src).ok_or_else(|| "This drive doesn't have a readable NTFS boot sector. Run a deep scan instead.".to_string())?;
    let mut sum = EngineSummary::default();
    if used_backup {
        sum.notes.push("Used the backup boot sector because the first one is damaged.".into());
    }
    let cs = boot.cluster_size as u64;
    let rs = boot.record_size as usize;
    let bps = boot.bytes_per_sector as u64;
    let include_existing = ctx.include_existing();
    let src_len = src.len();
    let total_clusters = boot.volume_bytes() / cs;

    ctx.mark(MapKind::Metadata, 0, bps);
    ctx.mark(MapKind::Scanned, 0, bps);
    if boot.volume_bytes() + bps <= src_len {
        ctx.mark(MapKind::Metadata, boot.volume_bytes(), bps);
    }

    let map = mft_map(src, &boot, &mut sum.notes);
    for e in &map.extents {
        ctx.mark(MapKind::Metadata, e.phys, e.len.min(map.size.saturating_sub(e.vpos)));
    }
    // Existing files are reported by a second pass over the table.
    ctx.set_stage("filesystem", if include_existing { map.size.saturating_mul(2) } else { map.size });
    ctx.info(format!(
        "NTFS volume: {} clusters of {}, file records of {} bytes, file table {}.",
        total_clusters,
        human_size(cs),
        rs,
        human_size(map.size)
    ));

    // ---------------------------------------------------------------- pass over the MFT
    // Keeps what reporting needs: directories, deleted files, extension and system records and
    // Recycle Bin $I records. Existing files are not kept (a big volume has millions): the
    // second pass below streams them straight to the results.
    let mut dirs: HashMap<u64, DirRec> = HashMap::new();
    let mut sys: HashMap<u64, Box<Rec>> = HashMap::new();
    let mut exts: HashMap<u64, ExtRec> = HashMap::new();
    let mut cands: Vec<(u64, Box<Rec>)> = Vec::new();
    let mut info_recs: Vec<(u64, Box<Rec>)> = Vec::new();
    let mut bad_spans: Vec<(u64, u64)> = Vec::new();
    let (mut n_records, mut n_damaged, mut n_bad, mut n_torn) = (0u64, 0u64, 0u64, 0u64);

    let chunk = (CHUNK / rs).max(1) * rs;
    let mut buf = vec![0u8; chunk];
    let mut vpos = 0u64;
    let mut empty_chunks = 0;
    while vpos + rs as u64 <= map.size {
        ctx.check()?;
        let n = ((map.size - vpos).min(chunk as u64) as usize) / rs * rs;
        let b = &mut buf[..n];
        let bad = map.read(src, vpos, b, Some(ctx));
        let first = vpos / rs as u64;
        let base_v = vpos;
        let results: Vec<Parsed> = b
            .par_chunks_mut(rs)
            .enumerate()
            .map(|(i, r)| {
                let rv = base_v + (i * rs) as u64;
                if bad.iter().any(|&(s, e)| s < rv + rs as u64 && rv < e) {
                    return Parsed::BadSector;
                }
                classify(first + i as u64, r, false)
            })
            .collect();
        bad_spans.extend(bad);
        let mut any_valid = false;
        for (i, p) in results.into_iter().enumerate() {
            if i % 512 == 511 {
                ctx.check()?;
            }
            let recno = first + i as u64;
            match p {
                Parsed::Empty => {}
                Parsed::Damaged => n_damaged += 1,
                Parsed::BadSector => n_bad += 1,
                Parsed::Skip { torn } => {
                    any_valid = true;
                    n_records += 1;
                    n_torn += torn as u64;
                }
                Parsed::Rec(rec, torn) => {
                    any_valid = true;
                    n_records += 1;
                    n_torn += torn as u64;
                    if rec.hdr.base != 0 {
                        exts.insert(recno, ExtRec { base: rec.hdr.base, seq: rec.hdr.seq, in_use: rec.in_use(), data: rec.data, name: rec.name });
                        continue;
                    }
                    if rec.is_dir() {
                        if let Some(nm) = &rec.name {
                            dirs.insert(recno, DirRec { name: nm.name.clone(), parent: nm.parent, seq: rec.hdr.seq, in_use: rec.in_use() });
                        } else {
                            dirs.insert(recno, DirRec { name: String::new(), parent: 0, seq: rec.hdr.seq, in_use: rec.in_use() });
                        }
                        if rec.in_use() {
                            for r in &rec.index_alloc {
                                if let Some((o, l)) = r.lcn.and_then(|l| run_range(l, r.len, cs, total_clusters)) {
                                    ctx.mark(MapKind::Metadata, o, l);
                                }
                            }
                        }
                    }
                    if recno < FIRST_USER_RECORD {
                        sys.insert(recno, rec);
                        continue;
                    }
                    if rec.is_dir() {
                        continue;
                    }
                    let is_info = rec.name.as_ref().map_or(false, |n| i_id(&n.name).is_some());
                    if rec.in_use() {
                        // Only $I records get here (classify skips other existing files).
                        if is_info {
                            info_recs.push((recno, rec));
                        }
                        continue;
                    }
                    if is_info {
                        info_recs.push((recno, rec.clone()));
                    }
                    cands.push((recno, rec));
                }
            }
        }
        ctx.progress(n as u64);
        vpos += n as u64;
        if map.guessed {
            empty_chunks = if any_valid { 0 } else { empty_chunks + 1 };
            if empty_chunks >= 2 {
                break;
            }
        }
    }
    let scan_end = vpos;
    bad_spans.sort_unstable();
    ctx.info(format!("Read {n_records} file records."));
    if n_bad > 0 {
        sum.notes.push(format!("{n_bad} file records couldn't be read because of bad sectors."));
    }
    if n_damaged > 0 {
        sum.notes.push(format!("{n_damaged} file records are damaged and were skipped."));
    }
    if n_torn > 0 {
        sum.notes.push(format!("{n_torn} file records were only partly written (torn); what was consistent in them was used."));
    }

    // ------------------------------------------------------------ metadata files & bitmap
    for (&r, rec) in &sys {
        if r == 0 || r == 8 {
            continue; // $MFT marked above; $BadClus:$Bad spans the whole volume.
        }
        for p in &rec.data {
            for run in &p.runs {
                if let Some((o, l)) = run.lcn.and_then(|l| run_range(l, run.len, cs, total_clusters)) {
                    ctx.mark(MapKind::Metadata, o, l);
                }
            }
        }
    }
    let mut unknown_bits: Vec<(u64, u64)> = Vec::new();
    let bitmap = match sys.get(&6) {
        Some(rec) => {
            let (pieces, _, _) = gather_pieces(6, rec, &exts, src, cs, 0);
            assemble(pieces).into_iter().find(|s| s.name.is_empty()).and_then(|s| load_bitmap(src, ctx, &s, cs, total_clusters, &mut unknown_bits))
        }
        None => None,
    };
    if bitmap.is_none() {
        sum.notes.push("The volume's cluster bitmap couldn't be read, so the condition of deleted files is unknown until their content is checked.".into());
    } else if !unknown_bits.is_empty() {
        sum.notes.push("Part of the volume's cluster bitmap couldn't be read, so deleted files stored in that area are unknown until their content is checked.".into());
    }
    let alloc = match &bitmap {
        Some(b) => Alloc::Bitmap { bits: b, base: 0, cluster: cs, unknown: &unknown_bits },
        None => Alloc::None,
    };

    // ------------------------------------------------------------------- folder tree
    let parent_key = |dirs: &HashMap<u64, DirRec>, pref: u64| -> Option<u64> {
        let p = ref_rec(pref);
        if p == ROOT {
            return Some(ROOT);
        }
        let d = dirs.get(&p)?;
        if seq_ok(d.seq, ref_seq(pref), d.in_use) {
            Some(p)
        } else {
            None
        }
    };
    let mut tree = Tree::new();
    for (&k, d) in &dirs {
        let parent = if d.name.is_empty() { None } else { parent_key(&dirs, d.parent).filter(|&p| p != k) };
        tree.insert(k, Node { name: d.name.clone(), parent, label: k, fixed: None });
    }
    tree.insert(ROOT, Node { name: String::new(), parent: None, label: ROOT, fixed: Some(String::new()) });

    // ------------------------------------------------------------------- recycle bin
    let bins: HashSet<u64> =
        dirs.iter().filter(|(_, d)| d.name.eq_ignore_ascii_case("$Recycle.Bin") && parent_key(&dirs, d.parent) == Some(ROOT)).map(|(&k, _)| k).collect();
    let sid_dirs: HashSet<u64> =
        dirs.iter().filter(|(_, d)| parent_key(&dirs, d.parent).map_or(false, |p| bins.contains(&p))).map(|(&k, _)| k).collect();
    let mut infos = Vec::new();
    for (recno, rec) in &info_recs {
        let Some(nm) = &rec.name else { continue };
        let Some(parent) = parent_key(&dirs, nm.parent).filter(|p| sid_dirs.contains(p)) else { continue };
        let (pieces, _, _) = gather_pieces(*recno, rec, &exts, src, cs, 0);
        let Some(s) = assemble(pieces).into_iter().find(|s| s.name.is_empty()) else { continue };
        let data = match &s.resident {
            Some(d) => d.clone(),
            None if s.real <= 64 * 1024 => read_runs_bytes(src, &s.runs, cs, 0, s.real, 64 * 1024),
            None => continue,
        };
        infos.push(InfoRec { parent, id: i_id(&nm.name).unwrap_or_default(), in_use: rec.in_use(), data });
    }
    drop(info_recs);
    let info_index = InfoIndex::new(infos);
    let parse_info: &dyn Fn(&[u8]) -> Option<crate::recyclebin::RecycleInfo> = &crate::recyclebin::parse_info_file;
    let mut restored = 0u64;
    if !info_index.is_empty() {
        for (&k, d) in &dirs {
            let Some(p) = parent_key(&dirs, d.parent).filter(|p| sid_dirs.contains(p)) else { continue };
            if let Some(r) = info_index.restore(&d.name, p, d.in_use, parse_info) {
                if let Some(n) = tree.nodes.get_mut(&k) {
                    n.fixed = Some(format!("{}\\{}", r.folder, super::tree::component(&r.name)));
                    restored += 1;
                }
            }
        }
    }

    // ------------------------------------------------------------------- report files
    let mut report = |recno: u64, rec: &Rec, sum: &mut EngineSummary, lost_files: &mut u64| {
        let (pieces, ext_complete, ext_name) = gather_pieces(recno, rec, &exts, src, cs, 0);
        let fname = rec.name.clone().or(ext_name);
        let in_use = rec.in_use();
        let (name, parent, folder, lost) = match &fname {
            Some(n) => {
                let p = parent_key(&dirs, n.parent);
                let (folder, lost) = tree.folder_for(p, ref_rec(n.parent));
                (n.name.clone(), p, folder, lost)
            }
            None => (format!("File {recno}"), None, format!("{}\\Unknown folder", super::tree::LOST), true),
        };
        if folder.starts_with("\\$Extend") {
            return;
        }
        let in_bin = parent.map_or(false, |p| sid_dirs.contains(&p));
        if in_bin && i_id(&name).is_some() {
            return; // Recycle Bin bookkeeping.
        }
        let restore: Option<Restore> = if in_bin && r_id(&name).is_some() { info_index.restore(&name, parent.unwrap_or(0), in_use, parse_info) } else { None };
        let status = match (in_use, &restore, lost) {
            (true, Some(_), _) => FileStatus::RecycleBin,
            (true, None, _) => FileStatus::Existing,
            (false, _, true) if restore.is_none() => FileStatus::Lost,
            _ => FileStatus::Deleted,
        };
        let complete = rec.complete && ext_complete;
        let streams = assemble(pieces);
        for s in &streams {
            let size = s.resident.as_ref().map_or(s.real, |r| r.len() as u64);
            if size == 0 {
                continue;
            }
            if !s.name.is_empty() && (in_use || s.name.eq_ignore_ascii_case("Zone.Identifier")) {
                continue;
            }
            let shown = if s.name.is_empty() { name.clone() } else { format!("{}:{}", name, s.name) };
            let mut f = make_file(
                Item {
                    record: recno,
                    name: shown,
                    folder: folder.clone(),
                    status,
                    si: rec.si.as_ref(),
                    fname: fname.as_ref(),
                    stream: s,
                    complete,
                    cluster: cs,
                    base: 0,
                    src_len,
                },
                &alloc,
            );
            if fname.is_none() {
                f.flags |= flags::NAME_GUESSED;
            }
            if let Some(r) = &restore {
                f.name = if s.name.is_empty() { r.name.clone() } else { format!("{}:{}", r.name, s.name) };
                f.folder = r.folder.clone();
                f.type_id = f.ext();
                f.deleted = r.deleted;
                f.flags |= flags::FROM_RECYCLE_INFO;
                f.meta.insert("originalPath".into(), r.original.clone());
                f.meta.insert("recycledAs".into(), r.recycled_as.clone());
            }
            if !in_use {
                sum.deleted += 1;
                if status == FileStatus::Lost {
                    *lost_files += 1;
                }
            }
            sum.files += 1;
            ctx.found(f);
        }
    };
    ctx.check()?;
    let mut lost_files = 0u64;
    for (i, (recno, rec)) in cands.into_iter().enumerate() {
        if i % 512 == 511 {
            ctx.check()?;
        }
        report(recno, &rec, &mut sum, &mut lost_files);
    }

    // Existing files: a second pass over the table, reporting each record as it is parsed.
    if include_existing {
        let mut vpos = 0u64;
        while vpos + rs as u64 <= scan_end {
            ctx.check()?;
            let n = ((scan_end - vpos).min(chunk as u64) as usize) / rs * rs;
            let end = vpos + n as u64;
            let b = &mut buf[..n];
            let lo = bad_spans.partition_point(|x| x.1 <= vpos);
            let bad: Vec<(u64, u64)> = bad_spans[lo..].iter().take_while(|x| x.0 < end).copied().collect();
            read_skipping(&map, src, vpos, b, &bad);
            let first = vpos / rs as u64;
            let base_v = vpos;
            let recs: Vec<Option<Box<Rec>>> = b
                .par_chunks_mut(rs)
                .enumerate()
                .map(|(i, r)| {
                    let rv = base_v + (i * rs) as u64;
                    if bad.iter().any(|&(s, e)| s < rv + rs as u64 && rv < e) {
                        return None;
                    }
                    existing_file(first + i as u64, r)
                })
                .collect();
            for (i, r) in recs.into_iter().enumerate() {
                if i % 512 == 511 {
                    ctx.check()?;
                }
                if let Some(rec) = r {
                    report(first + i as u64, &rec, &mut sum, &mut lost_files);
                }
            }
            ctx.progress(n as u64);
            vpos = end;
        }
    }
    sum.lost_folders = tree.lost_roots.len() as u64;
    ctx.info(format!("Found {} deleted files ({} in lost folders) and {} folders.", sum.deleted, lost_files, dirs.len()));
    if sum.lost_folders > 0 {
        ctx.info(format!("{} folders couldn't be traced back to the root; their files are under \\Lost folders.", sum.lost_folders));
    }
    if restored > 0 {
        ctx.info(format!("Restored the original location of {restored} recycled folders."));
    }
    for n in &sum.notes {
        ctx.info(n.clone());
    }
    Ok(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_rules() {
        assert!(seq_ok(5, 5, true));
        assert!(!seq_ok(6, 5, true));
        assert!(seq_ok(6, 5, false), "freed records are one ahead");
        assert!(!seq_ok(7, 5, false));
        assert!(seq_ok(9, 0, true));
    }

    #[test]
    fn bitmap_runs_are_marked_as_byte_ranges() {
        let (ctx, t) = ScanCtx::for_test(ScanOptions::default(), 1 << 20);
        // Clusters 0-9 used, 10-15 free, 16-23 used, 24-29 free (30 clusters).
        let bits = [0xFF, 0x03, 0xFF, 0x00];
        let mut open = None;
        mark_bit_runs(&ctx, &bits[..2], 0, 512, 30, &mut open);
        mark_bit_runs(&ctx, &bits[2..], 16, 512, 30, &mut open);
        assert!(open.is_none());
        let r: Vec<_> = t.ranges.lock().unwrap().iter().filter(|x| x.0 == MapKind::Allocated).map(|x| (x.1, x.2)).collect();
        assert_eq!(r, vec![(0, 10 * 512), (16 * 512, 24 * 512)]);
        // Run open at the end of a one-shot call is closed at the volume end.
        let (ctx, t) = ScanCtx::for_test(ScanOptions::default(), 1 << 20);
        mark_bit_runs(&ctx, &[0x00, 0xF0], 0, 512, 14, &mut None);
        let r: Vec<_> = t.ranges.lock().unwrap().iter().map(|x| (x.1, x.2)).collect();
        assert_eq!(r, vec![(12 * 512, 14 * 512)]);
    }
}
