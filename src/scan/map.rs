//! Recovery Map: live per-kind range sets for running scans (buffered inserts merged in bulk, so
//! engines marking 100k scattered ranges stay O(n log n)), blob persistence, and the cell / region
//! computations behind `map_cells` and `map_region`.

use super::session::{self, k_ranges, meta_get, K_RANGES_AT};
use super::{MapData, RegionInfo};
use crate::model::{IntervalSet, MapKind};
use rusqlite::Connection;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

pub type Sets = [IntervalSet; 5];

/// Merge two start-sorted lists of half-open ranges into one merged (touching ranges joined) list.
pub fn merge_sorted(a: &[(u64, u64)], b: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(a.len() + b.len());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        let next = if j >= b.len() || (i < a.len() && a[i].0 <= b[j].0) {
            i += 1;
            a[i - 1]
        } else {
            j += 1;
            b[j - 1]
        };
        if next.1 <= next.0 {
            continue;
        }
        match out.last_mut() {
            Some(last) if next.0 <= last.1 => last.1 = last.1.max(next.1),
            _ => out.push(next),
        }
    }
    out
}

/// One kind's set plus not-yet-merged additions.
#[derive(Default)]
struct Acc {
    set: IntervalSet,
    pending: Vec<(u64, u64)>,
    /// Bumped by every addition, so checkpoints can skip sets that didn't change.
    ver: u64,
}

impl Acc {
    fn add(&mut self, s: u64, e: u64) {
        if e <= s {
            return;
        }
        self.ver += 1;
        // Sequential marks (the sweep) extend the last range without buffering.
        if self.pending.is_empty() {
            if let Some(last) = self.set.ranges.last_mut() {
                if s >= last.0 && s <= last.1 {
                    last.1 = last.1.max(e);
                    return;
                }
                if s > last.1 {
                    self.set.ranges.push((s, e));
                    return;
                }
            } else {
                self.set.ranges.push((s, e));
                return;
            }
        }
        self.pending.push((s, e));
        if self.pending.len() >= 1 << 16 {
            self.flush();
        }
    }
    fn flush(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let mut p = std::mem::take(&mut self.pending);
        p.sort_unstable();
        self.set.ranges = merge_sorted(&self.set.ranges, &p);
    }
}

/// The map of a running session, fed by the ScanCtx range sink.
#[derive(Default)]
pub struct LiveRanges {
    kinds: Mutex<[Acc; 5]>,
}

impl LiveRanges {
    pub fn new(initial: Sets) -> Self {
        let l = LiveRanges::default();
        {
            let mut k = l.kinds.lock().unwrap();
            for (i, s) in initial.into_iter().enumerate() {
                k[i].set = s;
            }
        }
        l
    }
    pub fn add(&self, kind: MapKind, s: u64, e: u64) {
        self.kinds.lock().unwrap_or_else(|e| e.into_inner())[kind.index()].add(s, e);
    }
    /// Run `f` on the merged sets (under the lock; keep it short).
    pub fn with<R>(&self, f: impl FnOnce(Refs) -> R) -> R {
        let mut k = self.kinds.lock().unwrap_or_else(|e| e.into_inner());
        for a in k.iter_mut() {
            a.flush();
        }
        f([&k[0].set, &k[1].set, &k[2].set, &k[3].set, &k[4].set])
    }
    #[allow(dead_code)]
    pub fn snapshot(&self) -> Sets {
        self.with(|s| s.map(|x| x.clone()))
    }
    /// Merged total of one kind (overlaps counted once); only that kind is flushed.
    pub fn total(&self, kind: MapKind) -> u64 {
        let mut k = self.kinds.lock().unwrap_or_else(|e| e.into_inner());
        let a = &mut k[kind.index()];
        a.flush();
        a.set.total()
    }
    /// Change counters per kind (see [`LiveRanges::changed_since`]).
    #[allow(dead_code)]
    pub fn versions(&self) -> [u64; 5] {
        let k = self.kinds.lock().unwrap_or_else(|e| e.into_inner());
        [k[0].ver, k[1].ver, k[2].ver, k[3].ver, k[4].ver]
    }
    /// (kind index, merged set, version) of each kind whose version differs from `seen`.
    pub fn changed_since(&self, seen: &[u64; 5]) -> Vec<(usize, IntervalSet, u64)> {
        let mut k = self.kinds.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        for (i, a) in k.iter_mut().enumerate() {
            if a.ver != seen[i] {
                a.flush();
                out.push((i, a.set.clone(), a.ver));
            }
        }
        out
    }
}

pub type Refs<'a> = [&'a IntervalSet; 5];

pub fn refs(s: &Sets) -> Refs<'_> {
    [&s[0], &s[1], &s[2], &s[3], &s[4]]
}

pub fn encode(set: &IntervalSet) -> Vec<u8> {
    let mut v = Vec::with_capacity(set.ranges.len() * 16);
    for &(s, e) in &set.ranges {
        v.extend_from_slice(&s.to_le_bytes());
        v.extend_from_slice(&e.to_le_bytes());
    }
    v
}

pub fn decode(b: &[u8]) -> IntervalSet {
    let ranges = b
        .chunks_exact(16)
        .map(|c| (u64::from_le_bytes(c[..8].try_into().unwrap()), u64::from_le_bytes(c[8..].try_into().unwrap())))
        .filter(|(s, e)| e > s)
        .collect();
    IntervalSet { ranges }
}

/// Persisted sets of a session (not running).
pub fn load_sets(c: &Connection) -> Sets {
    let mut out: Sets = Default::default();
    for (i, s) in out.iter_mut().enumerate() {
        if let Some(b) = meta_get::<Vec<u8>>(c, &k_ranges(i)) {
            *s = decode(&b);
        }
    }
    out
}

/// Cached persisted sets, keyed by their save time.
pub fn cached_sets(id: &str, c: &Connection) -> Arc<Sets> {
    static CACHE: OnceLock<Mutex<HashMap<String, (i64, Arc<Sets>)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let at = meta_get::<i64>(c, K_RANGES_AT).unwrap_or(0);
    if let Some((t, s)) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(id) {
        if *t == at {
            return s.clone();
        }
    }
    let sets = Arc::new(load_sets(c));
    let mut m = cache.lock().unwrap_or_else(|e| e.into_inner());
    if m.len() > 16 {
        m.clear();
    }
    m.insert(id.to_string(), (at, sets.clone()));
    sets
}

/// Rows for saving the sets (meta key, blob) plus the time key.
pub fn save_rows(sets: &Sets) -> Vec<(String, Vec<u8>)> {
    sets.iter().enumerate().map(|(i, s)| (k_ranges(i), encode(s))).collect()
}

/// Resolve [start, end) against the source and compute the cells.
pub fn cells(sets: Refs, source_len: u64, start: Option<u64>, end: Option<u64>, cells: u32) -> MapData {
    use base64::Engine;
    let end = end.unwrap_or(source_len).min(source_len);
    let start = start.unwrap_or(0).min(end);
    let span = end - start;
    let want = (cells.clamp(1, 65536)) as u64;
    if span == 0 {
        return MapData { start, end, cell_bytes: 0, cells: String::new(), source_len, totals: [0; 5] };
    }
    let cb = span.div_ceil(want).max(1);
    let n = span.div_ceil(cb) as usize;
    let mut buf = vec![0u8; n];
    let mut totals = [0u64; 5];
    for (k, set) in sets.iter().enumerate() {
        let bit = 1u8 << k;
        let r = &set.ranges;
        let mut i = r.partition_point(|&(_, e)| e <= start);
        let mut filled_to = 0usize; // cells below this already have the bit (ranges are sorted)
        while i < r.len() && r[i].0 < end {
            let s = r[i].0.max(start);
            let e = r[i].1.min(end);
            totals[k] += e - s;
            let first = ((s - start) / cb) as usize;
            let last = ((e - 1 - start) / cb) as usize;
            for c in buf.iter_mut().take(last + 1).skip(first.max(filled_to)) {
                *c |= bit;
            }
            filled_to = filled_to.max(last + 1);
            i += 1;
        }
    }
    MapData { start, end, cell_bytes: cb, cells: base64::engine::general_purpose::STANDARD.encode(&buf), source_len, totals }
}

/// Totals and bad ranges of a region (files are added by the caller).
pub fn region(sets: Refs, start: u64, end: u64, sector_size: u32) -> RegionInfo {
    let ss = sector_size.max(1) as u64;
    let mut totals = [0u64; 5];
    for (k, s) in sets.iter().enumerate() {
        totals[k] = s.overlap(start, end);
    }
    let mut bad = sets[MapKind::Bad.index()].clip(start, end);
    bad.truncate(1000);
    RegionInfo {
        start,
        end,
        sector_size: sector_size.max(1),
        first_sector: start / ss,
        last_sector: end.saturating_sub(1).max(start) / ss,
        totals,
        bad_ranges: bad,
        files: Vec::new(),
        file_count: 0,
    }
}

pub fn now_key() -> i64 {
    crate::model::now_ms()
}

/// Persist sets directly (sessions that aren't running: resume preparation, imports).
pub fn save_direct(c: &Connection, sets: &Sets) -> Result<(), String> {
    for (k, b) in save_rows(sets) {
        session::meta_set(c, &k, b)?;
    }
    session::meta_set(c, K_RANGES_AT, now_key())?;
    Ok(())
}
