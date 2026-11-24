//! Turning parsed records into [`FoundFile`]s: joining a stream's pieces, mapping clusters to
//! byte extents, and judging the condition from allocation evidence. Shared by the MFT walk and
//! the loose-record sweep.

use super::record::{DataPiece, FileName, StdInfo, AF_COMPRESSED, AF_ENCRYPTED, AF_SPARSE, FA_ENCRYPTED, FA_SPARSE};
use super::runs::{total_clusters, Run};
use crate::model::{filetime_to_ms, flags, Condition, Extent, FileStatus, FoundFile, IntervalSet, Origin, SPARSE};

/// One whole data stream (all of its pieces joined in VCN order).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stream {
    pub name: String,
    pub resident: Option<Vec<u8>>,
    pub runs: Vec<Run>,
    pub real: u64,
    pub alloc: u64,
    pub init: u64,
    pub flags: u16,
    pub comp_unit: u8,
    /// All pieces were present and well-formed.
    pub complete: bool,
    /// VCN ranges [start, end) with no piece (a missing extension record): filled with runs
    /// without a location, but the data there is lost, not sparse.
    pub gaps: Vec<(u64, u64)>,
}

impl Stream {
    pub fn compressed(&self) -> bool {
        self.resident.is_none() && self.flags & AF_COMPRESSED != 0 && self.comp_unit > 0
    }
}

/// Join $DATA pieces into streams, the unnamed stream first.
pub fn assemble(pieces: Vec<DataPiece>) -> Vec<Stream> {
    let mut names: Vec<String> = Vec::new();
    for p in &pieces {
        if !names.contains(&p.name) {
            names.push(p.name.clone());
        }
    }
    names.sort_by_key(|n| !n.is_empty());
    let mut rest = pieces;
    let mut out = Vec::new();
    for name in names {
        let (mut ps, others): (Vec<DataPiece>, Vec<DataPiece>) = rest.into_iter().partition(|p| p.name == name);
        rest = others;
        if let Some(i) = ps.iter().position(|p| p.resident.is_some()) {
            let p = ps.swap_remove(i);
            out.push(Stream { name, real: p.real, alloc: p.alloc, init: p.init, flags: p.flags, resident: p.resident, complete: true, ..Default::default() });
            continue;
        }
        ps.sort_by_key(|p| p.start_vcn);
        ps.dedup_by_key(|p| p.start_vcn);
        let first = ps.iter().find(|p| p.start_vcn == 0).cloned();
        let mut s = Stream { name, complete: first.is_some(), ..Default::default() };
        if let Some(f) = &first {
            s.real = f.real;
            s.alloc = f.alloc;
            s.init = f.init;
            s.flags = f.flags;
            s.comp_unit = f.comp_unit;
        } else if let Some(p) = ps.first() {
            s.flags = p.flags;
            s.comp_unit = p.comp_unit;
        }
        let mut vcn = 0u64;
        for p in ps {
            if p.start_vcn > vcn {
                if p.start_vcn - vcn > (1 << 40) {
                    s.complete = false;
                    break;
                }
                s.runs.push(Run { len: p.start_vcn - vcn, lcn: None });
                s.gaps.push((vcn, p.start_vcn));
                s.complete = false;
                vcn = p.start_vcn;
            } else if p.start_vcn < vcn {
                continue;
            }
            vcn = vcn.saturating_add(total_clusters(&p.runs));
            s.complete &= p.runs_ok;
            s.runs.extend(p.runs);
        }
        out.push(s);
    }
    out
}

/// Byte extents of a non-resident stream on the source. `base` = byte offset of cluster 0.
/// Uncompressed streams are cut to the real size (bytes past the initialized size and missing
/// runs become sparse); compressed streams keep the raw unit layout. Returns (extents, runs
/// missing, fragmented). Runs count as missing when the run list ends early or when a piece in
/// the middle is gone (`Stream::gaps`) inside the part of the file that holds data.
pub fn extents_for(s: &Stream, cluster: u64, base: u64) -> (Vec<Extent>, bool, bool) {
    let mut raw: Vec<Extent> = Vec::with_capacity(s.runs.len());
    for r in &s.runs {
        let len = r.len.saturating_mul(cluster);
        let off = match r.lcn {
            Some(l) => l.checked_mul(cluster).and_then(|o| o.checked_add(base)).unwrap_or(SPARSE),
            None => SPARSE,
        };
        push_merge(&mut raw, Extent { offset: off, len });
    }
    let raw_total: u64 = raw.iter().fold(0u64, |a, e| a.saturating_add(e.len));
    let mut out;
    let missing;
    if s.compressed() {
        missing = raw_total < s.real || gap_before(&s.gaps, cluster, s.real);
        out = raw;
        // A middle gap is already counted in `raw_total` (as a run without a location), so only
        // a run list that ends early needs a sparse tail.
        if raw_total < s.real {
            push_merge(&mut out, Extent { offset: SPARSE, len: s.real - raw_total });
        }
    } else {
        let valid = s.init.min(s.real);
        missing = raw_total < valid || gap_before(&s.gaps, cluster, valid);
        out = Vec::with_capacity(raw.len());
        let mut left = valid;
        for e in raw {
            if left == 0 {
                break;
            }
            let n = e.len.min(left);
            push_merge(&mut out, Extent { offset: e.offset, len: n });
            left -= n;
        }
        let covered = valid - left;
        if covered < s.real {
            push_merge(&mut out, Extent { offset: SPARSE, len: s.real - covered });
        }
    }
    let frag = out.iter().filter(|e| e.offset != SPARSE).count() > 1;
    (out, missing, frag)
}

/// A missing-piece gap starts before byte `limit` of the stream.
fn gap_before(gaps: &[(u64, u64)], cluster: u64, limit: u64) -> bool {
    gaps.iter().any(|&(a, b)| b > a && a.saturating_mul(cluster) < limit)
}

fn push_merge(v: &mut Vec<Extent>, e: Extent) {
    if e.len == 0 {
        return;
    }
    if let Some(last) = v.last_mut() {
        let contiguous = if last.offset == SPARSE { e.offset == SPARSE } else { e.offset != SPARSE && last.offset.checked_add(last.len) == Some(e.offset) };
        if contiguous {
            last.len = last.len.saturating_add(e.len);
            return;
        }
    }
    v.push(e);
}

/// Where allocation evidence comes from.
pub enum Alloc<'a> {
    /// The live $Bitmap (bit per cluster), with the byte offset of cluster 0 and the cluster size.
    /// `unknown`: sorted cluster ranges [start, end) whose bits couldn't be read (set to 1 in
    /// `bits`, and clusters past the end of `bits`); files there get no verdict from the bitmap.
    Bitmap { bits: &'a [u8], base: u64, cluster: u64, unknown: &'a [(u64, u64)] },
    /// Byte ranges in use by live files (deep scans).
    Ranges(&'a IntervalSet),
    None,
}

/// Clusters of [lcn, lcn+n) that are set in the bitmap (clusters beyond it count as used).
pub fn used_clusters(bits: &[u8], lcn: u64, n: u64) -> u64 {
    let total_bits = bits.len() as u64 * 8;
    let end = lcn.saturating_add(n);
    let mut used = end.saturating_sub(total_bits.max(lcn)).min(n);
    let end = end.min(total_bits);
    let mut c = lcn;
    while c < end {
        if c % 8 == 0 && c + 8 <= end {
            used += bits[(c / 8) as usize].count_ones() as u64;
            c += 8;
        } else {
            used += ((bits[(c / 8) as usize] >> (c % 8)) & 1) as u64;
            c += 1;
        }
    }
    used
}

/// Clusters of [lcn, lcn+n) inside the sorted, non-overlapping ranges `r`.
pub fn clusters_in(r: &[(u64, u64)], lcn: u64, n: u64) -> u64 {
    let end = lcn.saturating_add(n);
    let i = r.partition_point(|x| x.1 <= lcn);
    r[i..].iter().take_while(|x| x.0 < end).map(|x| x.1.min(end) - x.0.max(lcn)).sum()
}

pub struct Verdict {
    pub condition: Condition,
    pub flags: u32,
    pub note: String,
}

/// Condition from allocation evidence only (the content agent refines it later).
pub fn judge(extents: &[Extent], resident: bool, encrypted: bool, complete: bool, missing: bool, alloc: &Alloc, src_len: u64) -> Verdict {
    let v = |c, f, n: &str| Verdict { condition: c, flags: f, note: n.to_string() };
    if encrypted {
        return v(Condition::Partial, flags::ENCRYPTED, "It was encrypted with Windows EFS and can't be read without the user's key.");
    }
    if resident {
        return v(Condition::Excellent, 0, "Stored inside the file table.");
    }
    if extents.iter().any(|e| e.offset != SPARSE && e.offset.saturating_add(e.len) > src_len) {
        return v(Condition::Partial, 0, "Part of it lies beyond the end of this drive or image.");
    }
    if missing {
        return v(Condition::Partial, 0, "Part of its location information is missing.");
    }
    let mut first = true;
    let mut used_any = false;
    let mut first_used = false;
    let mut known = true;
    let mut unsure = false;
    for e in extents.iter().filter(|e| e.offset != SPARSE) {
        let (u, first_u) = match alloc {
            Alloc::Bitmap { bits, base, cluster, unknown } => {
                if e.offset < *base {
                    (true, first)
                } else {
                    let lcn = (e.offset - base) / cluster;
                    let n = e.len.div_ceil(*cluster);
                    // Unknown clusters read as used in `bits`: leave them out of the count.
                    let unk = clusters_in(unknown, lcn, n);
                    unsure |= unk > 0;
                    let used = used_clusters(bits, lcn, n).saturating_sub(unk);
                    let first_used = clusters_in(unknown, lcn, 1) == 0 && used_clusters(bits, lcn, 1) > 0;
                    (used > 0, first && first_used)
                }
            }
            Alloc::Ranges(set) => {
                let used = set.overlap(e.offset, e.offset + e.len) > 0;
                (used, first && set.contains(e.offset))
            }
            Alloc::None => {
                known = false;
                (false, false)
            }
        };
        used_any |= u;
        first_used |= first_u;
        first = false;
    }
    if !known {
        return v(Condition::Unknown, 0, "");
    }
    if first_used {
        v(Condition::Partial, flags::OVERWRITTEN, "Its start has been overwritten.")
    } else if used_any {
        v(Condition::Partial, flags::OVERWRITTEN, "Part of it has been overwritten by other files.")
    } else if unsure {
        v(Condition::Unknown, 0, "Part of the volume's cluster bitmap couldn't be read, so it isn't known whether this file was overwritten.")
    } else if complete {
        v(Condition::Excellent, 0, "Its clusters are still free.")
    } else {
        v(Condition::Good, 0, "Its clusters are still free.")
    }
}

/// Everything needed to describe one reported stream.
pub struct Item<'a> {
    pub record: u64,
    pub name: String,
    pub folder: String,
    pub status: FileStatus,
    pub si: Option<&'a StdInfo>,
    pub fname: Option<&'a FileName>,
    pub stream: &'a Stream,
    /// The record (and its extension records) parsed cleanly.
    pub complete: bool,
    pub cluster: u64,
    pub base: u64,
    pub src_len: u64,
}

pub fn make_file(it: Item, alloc: &Alloc) -> FoundFile {
    let s = it.stream;
    let si_attrs = it.si.map_or(0, |s| s.attrs);
    let encrypted = s.flags & AF_ENCRYPTED != 0 || si_attrs & FA_ENCRYPTED != 0;
    let pick = |a: Option<u64>, b: Option<u64>| a.and_then(filetime_to_ms).or_else(|| b.and_then(filetime_to_ms));
    let mut f = FoundFile {
        name: it.name,
        folder: it.folder,
        status: it.status,
        origin: Origin::Ntfs,
        created: pick(it.si.map(|x| x.created), it.fname.map(|x| x.created)),
        modified: pick(it.si.map(|x| x.modified), it.fname.map(|x| x.modified)),
        accessed: pick(it.si.map(|x| x.accessed), it.fname.map(|x| x.accessed)),
        fs_ref: Some(it.record),
        ..Default::default()
    };
    f.type_id = f.ext();
    f.meta.insert("mftRecord".into(), it.record.to_string());
    let mut missing = false;
    if let Some(r) = &s.resident {
        f.size = r.len() as u64;
        f.resident = Some(r.clone());
    } else {
        f.size = s.real;
        let (ext, miss, frag) = extents_for(s, it.cluster, it.base);
        f.extents = ext;
        f.fragmented = frag;
        missing = miss;
        if s.compressed() {
            f.flags |= flags::COMPRESSED;
            f.meta.insert("clusterSize".into(), it.cluster.to_string());
            f.meta.insert("compressionUnit".into(), (1u64 << s.comp_unit).to_string());
        }
    }
    if s.flags & AF_SPARSE != 0 || si_attrs & FA_SPARSE != 0 {
        f.flags |= flags::SPARSE;
    }
    if encrypted {
        f.flags |= flags::ENCRYPTED;
    }
    if !s.name.is_empty() {
        f.meta.insert("stream".into(), s.name.clone());
    }
    if f.status == FileStatus::Existing || f.status == FileStatus::RecycleBin {
        f.condition = Condition::Excellent;
        f.note = "It still exists on the drive.".into();
        if encrypted {
            f.condition = Condition::Partial;
            f.note = "It was encrypted with Windows EFS and can't be read without the user's key.".into();
        }
        return f;
    }
    let v = judge(&f.extents, s.resident.is_some(), encrypted, it.complete && s.complete, missing, alloc, it.src_len);
    f.condition = v.condition;
    f.flags |= v.flags;
    f.note = v.note;
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    fn piece(name: &str, vcn: u64, runs: Vec<Run>, real: u64) -> DataPiece {
        DataPiece { name: name.into(), start_vcn: vcn, runs, runs_ok: true, real, alloc: real, init: real, ..Default::default() }
    }

    #[test]
    fn assembles_pieces_in_vcn_order_and_flags_gaps() {
        let a = piece("", 0, vec![Run { len: 2, lcn: Some(10) }], 6 * 512);
        let b = piece("", 2, vec![Run { len: 2, lcn: Some(20) }], 0);
        let c = piece("", 4, vec![Run { len: 2, lcn: Some(12) }], 0);
        let s = assemble(vec![c.clone(), a.clone(), b.clone()]);
        assert_eq!(s.len(), 1);
        assert!(s[0].complete);
        assert_eq!(s[0].runs.iter().map(|r| r.lcn.unwrap()).collect::<Vec<_>>(), vec![10, 20, 12]);
        // Missing middle piece -> sparse gap, incomplete.
        let s = assemble(vec![a, c]);
        assert!(!s[0].complete);
        assert_eq!(s[0].runs[1], Run { len: 2, lcn: None });
        assert_eq!(s[0].gaps, vec![(2, 4)]);
        let (ext, missing, frag) = extents_for(&s[0], 512, 0);
        assert!(missing && frag, "a missing middle piece is lost data, not a sparse hole");
        assert_eq!(ext[1].offset, SPARSE);
        // Judged Partial, not "clusters are still free".
        let bits = [0u8; 8];
        let alloc = Alloc::Bitmap { bits: &bits, base: 0, cluster: 512, unknown: &[] };
        let v = judge(&ext, false, false, s[0].complete, missing, &alloc, 1 << 30);
        assert_eq!((v.condition, v.note.as_str()), (Condition::Partial, "Part of its location information is missing."));
        // A gap past the initialized part holds no data: not missing.
        let mut t = s[0].clone();
        t.init = 2 * 512;
        assert!(!extents_for(&t, 512, 0).1);
        // Genuinely sparse runs inside a piece aren't gaps.
        let sp = piece("", 0, vec![Run { len: 2, lcn: Some(10) }, Run { len: 2, lcn: None }, Run { len: 2, lcn: Some(12) }], 6 * 512);
        let s = assemble(vec![sp]);
        assert!(s[0].gaps.is_empty());
        assert!(!extents_for(&s[0], 512, 0).1);
    }

    #[test]
    fn compressed_stream_with_middle_gap_is_missing_without_overflow() {
        // Compressed, 16-cluster units, real size below the allocated size (the usual case).
        let mk = |vcn: u64, lcn: u64, real: u64| DataPiece { flags: AF_COMPRESSED, comp_unit: 4, alloc: 48 * 512, ..piece("", vcn, vec![Run { len: 16, lcn: Some(lcn) }], real) };
        let a = mk(0, 100, 40 * 512);
        let c = mk(32, 300, 0);
        let s = assemble(vec![a.clone(), mk(16, 200, 0), c.clone()]);
        assert!(s[0].compressed() && s[0].gaps.is_empty());
        let (ext, missing, _) = extents_for(&s[0], 512, 0);
        assert!(!missing);
        assert_eq!(ext.iter().map(|e| e.len).sum::<u64>(), 48 * 512);
        // The middle extension record is gone: runs are lost, but there is no sparse tail.
        let s = assemble(vec![a, c]);
        assert_eq!(s[0].gaps, vec![(16, 32)]);
        let (ext, missing, _) = extents_for(&s[0], 512, 0);
        assert!(missing);
        assert_eq!(ext, vec![Extent { offset: 100 * 512, len: 16 * 512 }, Extent { offset: SPARSE, len: 16 * 512 }, Extent { offset: 300 * 512, len: 16 * 512 }]);
        // A run list that ends early still gets a sparse tail up to the real size.
        let mut t = s[0].clone();
        t.runs.truncate(1);
        t.gaps.clear();
        let (ext, missing, _) = extents_for(&t, 512, 0);
        assert!(missing);
        assert_eq!(ext.iter().map(|e| e.len).sum::<u64>(), 40 * 512);
    }

    #[test]
    fn extents_trim_to_size_and_initialized_part() {
        let mut s = Stream { runs: vec![Run { len: 4, lcn: Some(100) }, Run { len: 4, lcn: Some(104) }], real: 5000, init: 5000, alloc: 8 * 1024, complete: true, ..Default::default() };
        let (e, missing, frag) = extents_for(&s, 1024, 0);
        assert_eq!(e, vec![Extent { offset: 102_400, len: 5000 }]);
        assert!(!missing && !frag);
        s.init = 1000;
        let (e, _, _) = extents_for(&s, 1024, 0);
        assert_eq!(e, vec![Extent { offset: 102_400, len: 1000 }, Extent { offset: SPARSE, len: 4000 }]);
        s.init = 5000;
        s.runs.truncate(1);
        let (_, missing, _) = extents_for(&s, 1024, 0);
        assert!(missing);
    }

    #[test]
    fn bitmap_evidence() {
        // Clusters 0-7 used, 8-15 free, 16 used.
        let bits = [0xFFu8, 0x00, 0x01];
        assert_eq!(used_clusters(&bits, 0, 24), 9);
        assert_eq!(used_clusters(&bits, 8, 8), 0);
        assert_eq!(used_clusters(&bits, 15, 2), 1);
        assert_eq!(used_clusters(&bits, 20, 10), 6, "clusters past the bitmap count as used");
        let alloc = Alloc::Bitmap { bits: &bits, base: 0, cluster: 512, unknown: &[] };
        let free = [Extent { offset: 8 * 512, len: 4 * 512 }];
        assert_eq!(judge(&free, false, false, true, false, &alloc, 1 << 30).condition, Condition::Excellent);
        assert_eq!(judge(&free, false, false, false, false, &alloc, 1 << 30).condition, Condition::Good);
        let partly = [Extent { offset: 12 * 512, len: 512 }, Extent { offset: 16 * 512, len: 512 }];
        let v = judge(&partly, false, false, true, false, &alloc, 1 << 30);
        assert_eq!((v.condition, v.flags), (Condition::Partial, flags::OVERWRITTEN));
        assert!(v.note.contains("Part of it"));
        let start = [Extent { offset: 0, len: 512 }, Extent { offset: 8 * 512, len: 512 }];
        assert!(judge(&start, false, false, true, false, &alloc, 1 << 30).note.contains("start"));
        assert_eq!(judge(&[], true, false, true, false, &alloc, 0).note, "Stored inside the file table.");
        assert_eq!(judge(&free, false, true, true, false, &alloc, 1 << 30).flags, flags::ENCRYPTED);
    }

    #[test]
    fn unreadable_bitmap_parts_give_no_verdict() {
        // Clusters 0-7 used, 8-15 unreadable (filled with 1s), 16-23 free, 24+ past the bitmap.
        let bits = [0xFFu8, 0xFF, 0x00];
        let unknown = [(8u64, 16u64), (24, 32)];
        assert_eq!(clusters_in(&unknown, 0, 40), 16);
        assert_eq!(clusters_in(&unknown, 10, 15), 6 + 1);
        assert_eq!(clusters_in(&unknown, 16, 8), 0);
        let alloc = Alloc::Bitmap { bits: &bits, base: 0, cluster: 512, unknown: &unknown };
        let v = judge(&[Extent { offset: 9 * 512, len: 4 * 512 }], false, false, true, false, &alloc, 1 << 30);
        assert_eq!(v.condition, Condition::Unknown, "{}", v.note);
        assert!(v.note.contains("bitmap"));
        let v = judge(&[Extent { offset: 16 * 512, len: 2 * 512 }, Extent { offset: 25 * 512, len: 512 }], false, false, true, false, &alloc, 1 << 30);
        assert_eq!(v.condition, Condition::Unknown);
        // Known-used clusters still win.
        let v = judge(&[Extent { offset: 12 * 512, len: 512 }, Extent { offset: 2 * 512, len: 512 }], false, false, true, false, &alloc, 1 << 30);
        assert_eq!((v.condition, v.flags), (Condition::Partial, flags::OVERWRITTEN));
        let v = judge(&[Extent { offset: 16 * 512, len: 8 * 512 }], false, false, true, false, &alloc, 1 << 30);
        assert_eq!(v.condition, Condition::Excellent);
    }
}
