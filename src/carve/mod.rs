//! Signature carving: finds files by their content in raw sectors (deep scans), works out where
//! each one ends, names it from embedded metadata, honours user-defined signatures.
//! OWNER: carve agent.
//!
//! `visit` checks every 512-byte boundary of each chunk with a first-bytes dispatch (`sig`) and
//! records compact hits. `finish` sorts the hits, parses each file's structure in parallel to find
//! its end (`parse` and the per-format modules), then resolves overlaps in offset order: hits inside
//! an earlier file are dropped (thumbnails, archive members), an earlier file whose end was only
//! estimated is cut at the next real header, hits at `known_starts` are claimed but not reported.

mod arc;
mod av;
mod custom;
mod doc;
mod img;
mod jpeg;
mod parse;
mod rd;
mod sig;
mod zip;
#[cfg(test)]
mod tests;

use crate::device::source::{read_tolerant, BlockSource};
use crate::model::{flags, Category, ChunkVisitor, Condition, CustomSignature, EngineSummary, Extent, FileStatus, FoundFile, IntervalSet, Origin, ScanCtx, CANCELLED};
use parse::{End, Env, Parsed};
use rayon::prelude::*;
use sig::{Fam, LOOK, NFAM};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

/// The carving visitor for a deep scan. Reads the type selection (`ctx.options.carve_types`),
/// `carve_free_only` (skip headers inside `ctx.allocated`) and `ctx.custom_signatures`.
pub fn visitor(ctx: &ScanCtx) -> Box<dyn ChunkVisitor> {
    Box::new(Carver::new(ctx))
}

/// Deep scans can find this type id by signature.
pub fn is_carvable(type_id: &str) -> bool {
    sig::ALL.iter().any(|f| f.types().contains(&type_id))
}

/// Check a custom signature before it is saved. Err = one sentence saying what to fix.
pub fn validate_custom(sig: &CustomSignature) -> Result<(), String> {
    custom::compile(sig).map(|_| ())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Hit {
    off: u64,
    /// < 256: a [`Fam`]; >= 256: custom signature index + 256.
    code: u16,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Builtin(&'static str),
    Custom(usize),
}

#[derive(Clone, Debug)]
struct Cand {
    off: u64,
    len: u64,
    end: End,
    frags: Vec<(u64, u64)>,
    kind: Kind,
    /// false: claim its space but don't list it (type not selected).
    report: bool,
    /// Its end can be cut by a later header (estimated or clipped).
    soft: bool,
}

struct Carver {
    fams: [bool; NFAM],
    /// Selected type ids (None = everything).
    selected: Option<HashSet<&'static str>>,
    customs: Vec<custom::Custom>,
    hits: Mutex<Vec<Hit>>,
}

impl Carver {
    fn new(ctx: &ScanCtx) -> Carver {
        let wanted: Option<Vec<String>> = ctx.options.carve_types.as_ref().map(|v| v.iter().map(|s| s.trim().to_ascii_lowercase()).collect());
        let selected = wanted.as_ref().map(|w| {
            let mut set = HashSet::new();
            for s in w {
                if let Some(c) = Category::parse(s) {
                    set.extend(crate::formats::all().iter().filter(|t| t.category == c).map(|t| t.id));
                } else if let Some(t) = crate::formats::by_id(s).or_else(|| crate::formats::by_ext(s)) {
                    set.insert(t.id);
                }
            }
            set
        });
        let mut fams = [false; NFAM];
        for f in sig::ALL {
            // Containers are always parsed so the files inside them (thumbnails, members, embedded
            // images) aren't reported on their own; they're only listed when selected.
            fams[f as usize] = f.is_container() || selected.as_ref().map_or(true, |s| f.types().iter().any(|t| s.contains(t)));
        }
        let mut customs = Vec::new();
        for c in ctx.custom_signatures.iter().filter(|c| c.enabled) {
            match custom::compile(c) {
                Ok(k) => {
                    let keep = wanted.as_ref().map_or(true, |w| w.iter().any(|s| s == k.category.as_str() || *s == k.ext || s.eq_ignore_ascii_case(&k.name) || *s == c.id));
                    if keep {
                        customs.push(k);
                    }
                }
                Err(e) => ctx.warn(format!("Skipped the custom signature \"{}\": {e}", c.name)),
            }
        }
        Carver { fams, selected, customs, hits: Mutex::new(Vec::new()) }
    }

    #[inline]
    fn sniff(&self, p: &[u8], abs: u64, out: &mut Vec<Hit>) {
        if let Some((f, d)) = sig::sniff(p) {
            if self.fams[f as usize] {
                let o = abs as i64 + d;
                if o >= 0 {
                    out.push(Hit { off: o as u64, code: f as u16 });
                }
            }
        }
        for (i, c) in self.customs.iter().enumerate() {
            if c.matches(p) {
                out.push(Hit { off: abs, code: 256 + i as u16 });
            }
        }
    }

    fn parse_hit(&self, src: &dyn BlockSource, h: Hit, env: &Env) -> Option<Cand> {
        let mut rd = rd::Rd::new(src, h.off);
        let avail = rd.avail();
        if h.code >= 256 {
            let i = (h.code - 256) as usize;
            let c = self.customs.get(i)?;
            let p = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.parse(&mut rd))).ok().flatten()?;
            return Some(Cand { off: h.off, len: p.len.min(avail), end: p.end, frags: Vec::new(), kind: Kind::Custom(i), report: true, soft: p.end != End::Clean });
        }
        let fam = Fam::from_u8(h.code as u8)?;
        let p: Parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| parse::run(fam, &mut rd, env))).ok().flatten()?;
        let ty = match p.ty {
            Some(t) => t,
            None => {
                let mut head = vec![0u8; if fam == Fam::Iso { 0x8800 } else { 4096 }];
                let (n, _) = rd.read(0, &mut head);
                head.truncate(n.min(p.len as usize));
                crate::formats::detect(&head).map(|t| t.id).filter(|t| fam.types().contains(t)).unwrap_or(fam.types()[0])
            }
        };
        let report = self.selected.as_ref().map_or(true, |s| s.contains(ty));
        let len = if p.frags.is_empty() { p.len.min(avail) } else { p.len };
        // An MPEG-PS walk stops where its pack chain stops, so the walked span is backed by the
        // structure even without an end code: headers inside it are payload and don't cut it.
        let walked = fam == Fam::MpegPs && p.end == End::Estimated;
        let soft = p.soft || (p.end != End::Clean && !walked);
        Some(Cand { off: h.off, len, end: p.end, frags: p.frags, kind: Kind::Builtin(ty), report, soft })
    }

    fn build(&self, src: &dyn BlockSource, c: &Cand) -> FoundFile {
        let extents: Vec<Extent> =
            if c.frags.is_empty() { vec![Extent { offset: c.off, len: c.len }] } else { c.frags.iter().map(|&(o, l)| Extent { offset: c.off + o, len: l }).collect() };
        let size: u64 = extents.iter().map(|e| e.len).sum();
        let (type_id, label, ext, tag) = match c.kind {
            Kind::Builtin(t) => {
                let ft = crate::formats::by_id(t);
                (t.to_string(), ft.map_or(t, |f| f.label).to_string(), t.to_string(), if t == "jpg" { "JPEG".to_string() } else { t.to_ascii_uppercase() })
            }
            Kind::Custom(i) => {
                let k = &self.customs[i];
                let id = crate::formats::by_ext(&k.ext).map_or(k.ext.clone(), |t| t.id.to_string());
                (id, k.name.clone(), k.ext.clone(), k.ext.to_ascii_uppercase())
            }
        };
        // First <= 1 MiB of content for metadata.
        let mut data = vec![0u8; size.min(1 << 20) as usize];
        let mut got = 0usize;
        let mut bad_any = false;
        for e in &extents {
            if got >= data.len() {
                break;
            }
            let n = (e.len as usize).min(data.len() - got);
            let (r, bad) = read_tolerant(src, e.offset, &mut data[got..got + n], None);
            bad_any |= !bad.is_empty();
            got += r;
            if r < n {
                break;
            }
        }
        data.truncate(got);
        let meta = crate::content::extract_meta(&type_id, &data);
        let name = crate::content::suggest_name(&type_id, &meta)
            .filter(|n| !n.trim().is_empty())
            .map(|n| crate::model::safe_file_name(&format!("{n}.{ext}")))
            .unwrap_or_else(|| format!("{tag}_{:010X}.{ext}", c.off));
        let fragmented = extents.len() > 1;
        let (condition, note) = match c.end {
            End::Clean if fragmented => (Condition::Good, format!("Rebuilt from {} fragments.", extents.len())),
            End::Clean => (Condition::Good, "Its structure is complete.".to_string()),
            End::Estimated => (Condition::Unknown, "The end of this file was estimated.".to_string()),
            End::Damaged => (Condition::Partial, "It looks incomplete or damaged.".to_string()),
        };
        FoundFile {
            name,
            folder: format!("\\Found by signature\\{label}"),
            size,
            status: FileStatus::Carved,
            origin: Origin::Carving,
            type_id,
            extents,
            condition,
            note,
            fragmented,
            flags: flags::NAME_GUESSED | if bad_any { flags::BAD_SECTORS } else { 0 },
            meta,
            ..Default::default()
        }
    }
}

/// One bit per hit, settable from several threads.
struct Bits(Vec<AtomicU64>);

impl Bits {
    fn new(n: usize) -> Bits {
        Bits((0..n.div_ceil(64)).map(|_| AtomicU64::new(0)).collect())
    }
    fn set(&self, i: usize) {
        self.0[i / 64].fetch_or(1 << (i % 64), Ordering::Relaxed);
    }
    fn get(&self, i: usize) -> bool {
        self.0[i / 64].load(Ordering::Relaxed) & (1 << (i % 64)) != 0
    }
    fn count(&self) -> usize {
        self.0.iter().map(|w| w.load(Ordering::Relaxed).count_ones() as usize).sum()
    }
}

/// What the stream pre-pass decided, kept compact (a few bits per hit): `drop` = inside an earlier
/// stream of the same family, not a file start; `done` = the first hit of a stream, already
/// parsed, with its file in `cands` (sorted by hit index) when the parse succeeded. Hits in
/// neither set are parsed with the rest.
struct Walked {
    drop: Bits,
    done: Bits,
    cands: Vec<(usize, Cand)>,
}

/// How far past its start a speculative stream parse may read. Most MP3/AAC files are smaller;
/// a longer stream is walked again by the in-order pass.
const SPEC_CAP: u64 = 32 << 20;
/// Stream hits per speculative segment.
const SPEC_SEG: usize = 256;

/// A view of the source that refuses reads at or past `cap` and remembers that one was asked
/// for. Its length is the real one, so a parse that never touched the cap read exactly the bytes
/// and made exactly the decisions an unlimited parse would have.
struct Capped<'a> {
    src: &'a dyn BlockSource,
    cap: u64,
    touched: AtomicBool,
}

impl BlockSource for Capped<'_> {
    fn len(&self) -> u64 {
        self.src.len()
    }
    fn sector_size(&self) -> u32 {
        self.src.sector_size()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.touched.load(Ordering::Relaxed) || offset.saturating_add(buf.len() as u64) > self.cap {
            // Fail every read from here on so the parse gives up quickly.
            self.touched.store(true, Ordering::Relaxed);
            return Err(std::io::Error::other("speculative read limit"));
        }
        self.src.read_at(offset, buf)
    }
    fn describe(&self) -> String {
        self.src.describe()
    }
}

impl Carver {
    /// Stream formats match on many sectors inside one file (every TS packet or MPEG-PS pack, MP3
    /// and AAC frames). Parsing each of those hits would walk the rest of the stream again and
    /// again, and soft ends would be cut at every pack. So each stream family is walked once, in
    /// offset order: a hit inside the stream an earlier hit of the same family walked is dropped,
    /// each byte is walked at most once per family, and a stream comes out as one file.
    fn walk_streams(&self, src: &dyn BlockSource, hits: &[Hit], env: &Env, ctx: &ScanCtx) -> Walked {
        self.walk_streams_with(src, hits, env, ctx, rayon::current_num_threads(), SPEC_SEG, SPEC_CAP)
    }

    /// `par` speculative segments of `seg` hits per window (1 = strictly in order); `cap` = [`SPEC_CAP`].
    fn walk_streams_with(&self, src: &dyn BlockSource, hits: &[Hit], env: &Env, ctx: &ScanCtx, par: usize, seg: usize, cap: u64) -> Walked {
        let fams: Vec<Fam> = sig::ALL.iter().copied().filter(|f| f.is_stream() && self.fams[*f as usize]).collect();
        let drop = Bits::new(hits.len());
        let done = Bits::new(hits.len());
        let mut cands: Vec<(usize, Cand)> = fams
            .par_iter()
            .map(|&f| self.walk_family(src, hits, f as u16, env, ctx, par.max(1), seg.max(1), cap, &drop, &done))
            .flatten()
            .collect();
        cands.sort_unstable_by_key(|c| c.0);
        Walked { drop, done, cands }
    }

    /// The in-order walk of one stream family, with the parses spread over threads: each window
    /// of hits is cut into segments that are walked speculatively in parallel (each segment as if
    /// it started right after the stream before it, each parse limited to `cap` bytes), then the
    /// window is walked in order, reusing a speculative parse wherever the in-order walk parses
    /// the same hit and parsing only the hits speculation missed. The result is exactly the plain
    /// in-order walk's. Long streams that overrun `cap` switch the family to in-order windows
    /// until short streams come back, so a long video isn't read once per thread.
    #[allow(clippy::too_many_arguments)]
    fn walk_family(&self, src: &dyn BlockSource, hits: &[Hit], code: u16, env: &Env, ctx: &ScanCtx, par: usize, seg: usize, cap: u64, drop: &Bits, done: &Bits) -> Vec<(usize, Cand)> {
        let mut out = Vec::new();
        let mut covered = 0u64;
        // Packet-stream families (MPEG-PS, TS, M2TS) hit every few KB inside one video, so parallel
        // segments would almost all start inside the same stream and each re-read it to its end
        // (a 20 MB AVCHD clip read ~13x, per the 2026-11-24 review). Only the sparse audio families
        // (one hit per file) speculate.
        let dense = matches!(Fam::from_u8(code as u8), Some(Fam::MpegPs | Fam::MpegTs | Fam::Mts));
        let par = if dense { 1 } else { par };
        let mut spec = par > 1;
        let mut ids = hits.iter().enumerate().filter(|(_, h)| h.code == code).map(|(i, _)| i);
        let mut win: Vec<usize> = Vec::new();
        loop {
            if ctx.is_cancelled() {
                break;
            }
            win.clear();
            let want = if spec { par * seg } else { seg };
            for i in ids.by_ref() {
                if hits[i].off < covered {
                    drop.set(i);
                    ctx.progress(1);
                    continue;
                }
                win.push(i);
                if win.len() >= want {
                    break;
                }
            }
            if win.is_empty() {
                break;
            }
            let mut overran = false;
            let mut guesses: Vec<Option<Option<Cand>>> = Vec::new();
            if spec {
                let segs: Vec<(Vec<Option<Option<Cand>>>, bool)> = win
                    .par_chunks(seg)
                    .map(|part| {
                        let mut g = Vec::with_capacity(part.len());
                        let mut cov = 0u64;
                        for &i in part {
                            let h = hits[i];
                            if h.off < cov || ctx.is_cancelled() {
                                g.push(None);
                                continue;
                            }
                            let view = Capped { src, cap: h.off.saturating_add(cap), touched: AtomicBool::new(false) };
                            let r = self.parse_hit(&view, h, env);
                            if view.touched.load(Ordering::Relaxed) {
                                // Where this stream ends is unknown, and so is the rest of the segment.
                                return (g, true);
                            }
                            if let Some(c) = &r {
                                cov = c.off.saturating_add(c.len);
                            }
                            g.push(Some(r));
                        }
                        (g, false)
                    })
                    .collect();
                for (mut g, over) in segs {
                    overran |= over;
                    g.resize_with(seg, || None);
                    guesses.extend(g);
                }
            }
            let (mut short, mut long) = (0u32, 0u32);
            for (k, &i) in win.iter().enumerate() {
                let h = hits[i];
                if h.off < covered {
                    drop.set(i);
                    ctx.progress(1);
                    continue;
                }
                if ctx.is_cancelled() {
                    break;
                }
                let r = match guesses.get_mut(k).and_then(Option::take) {
                    Some(r) => r,
                    None => self.parse_hit(src, h, env),
                };
                done.set(i);
                if let Some(c) = r {
                    covered = c.off.saturating_add(c.len);
                    if c.len < cap {
                        short += 1;
                    } else {
                        long += 1;
                    }
                    out.push((i, c));
                }
                ctx.progress(1);
            }
            spec = par > 1 && if spec { !overran } else { long == 0 && short >= 2 };
        }
        out
    }
}

/// Offset-ordered overlap resolution.
#[derive(Default)]
struct Resolver {
    claimed: IntervalSet,
    pending: Option<Cand>,
}

impl Resolver {
    fn finalize(&mut self, c: Cand, known: &HashSet<u64>, out: &mut Vec<Cand>) {
        if c.frags.is_empty() {
            self.claimed.insert(c.off, c.off + c.len);
        } else {
            for &(o, l) in &c.frags {
                self.claimed.insert(c.off + o, c.off + o + l);
            }
        }
        if c.report && !known.contains(&c.off) {
            out.push(c);
        }
    }

    fn take(&mut self, h: Hit, p: Option<Cand>, known: &HashSet<u64>, out: &mut Vec<Cand>) {
        if let Some(pend) = self.pending.as_mut() {
            if h.off < pend.off + pend.len {
                // A header that parses, or one inside another file's claimed space (not parsed
                // again), cuts the estimated end; a header that doesn't parse is payload.
                if h.off == pend.off || (p.is_none() && !self.claimed.contains(h.off)) {
                    return;
                }
                pend.len = h.off - pend.off;
            }
            let pend = self.pending.take().unwrap();
            self.finalize(pend, known, out);
        }
        if self.claimed.contains(h.off) {
            return;
        }
        let Some(c) = p else { return };
        if c.soft {
            self.pending = Some(c);
        } else {
            self.finalize(c, known, out);
        }
    }

    fn flush(&mut self, known: &HashSet<u64>, out: &mut Vec<Cand>) {
        if let Some(p) = self.pending.take() {
            self.finalize(p, known, out);
        }
    }
}

impl ChunkVisitor for Carver {
    fn name(&self) -> &'static str {
        "carver"
    }

    fn visit(&self, src: &dyn BlockSource, offset: u64, data: &[u8], _ctx: &ScanCtx) {
        if !self.fams.iter().any(|&f| f) && self.customs.is_empty() {
            return;
        }
        let n = data.len();
        let mut local = Vec::new();
        let mut s = ((512 - offset % 512) % 512) as usize;
        let tail = n.saturating_sub(LOOK);
        while s < tail {
            self.sniff(&data[s..], offset + s as u64, &mut local);
            s += 512;
        }
        if s < n {
            // The last sectors of the chunk see a little of the next one.
            let mut ext = data[s..].to_vec();
            let end = offset + n as u64;
            let more = (LOOK as u64).min(src.len().saturating_sub(end)) as usize;
            if more > 0 {
                let old = ext.len();
                ext.resize(old + more, 0);
                let (got, _) = read_tolerant(src, end, &mut ext[old..], None);
                ext.truncate(old + got);
            }
            let base = s;
            while s < n {
                self.sniff(&ext[s - base..], offset + s as u64, &mut local);
                s += 512;
            }
        }
        if !local.is_empty() {
            self.hits.lock().unwrap_or_else(|e| e.into_inner()).extend(local);
        }
    }

    fn finish(&self, src: &dyn BlockSource, ctx: &ScanCtx) -> Result<EngineSummary, String> {
        let mut hits = std::mem::take(&mut *self.hits.lock().unwrap_or_else(|e| e.into_inner()));
        hits.sort_unstable();
        hits.dedup();
        let probe = ctx.probe.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let free_only = ctx.options.carve_free_only.unwrap_or(probe.is_some());
        if free_only {
            let a = ctx.allocated.read().unwrap_or_else(|e| e.into_inner());
            if !a.is_empty() {
                hits.retain(|h| !a.contains(h.off));
            }
        }
        let known: HashSet<u64> = ctx.known_starts.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let cluster = probe.as_ref().map(|p| p.cluster_size as u64).filter(|&c| c >= 512 && c <= 1 << 21).unwrap_or(4096);
        ctx.set_stage("rebuild", hits.len() as u64);
        let walked = {
            let mut offsets: Vec<u64> = hits.iter().map(|h| h.off).collect();
            offsets.dedup();
            let env = Env { cluster, hits: &offsets };
            self.walk_streams(src, &hits, &env, ctx)
        };
        if ctx.is_cancelled() {
            return Err(CANCELLED.to_string());
        }
        // Stream hits inside an earlier stream of their family are gone; the streams themselves
        // carry their parse result. The batches are built from `hits` as they're needed.
        let Walked { drop: dropped, done, cands } = walked;
        let kept = hits.len() - dropped.count();
        let mut offsets: Vec<u64> = Vec::with_capacity(kept);
        offsets.extend(hits.iter().enumerate().filter(|&(i, _)| !dropped.get(i)).map(|(_, h)| h.off));
        offsets.dedup();
        let env = Env { cluster, hits: &offsets };
        if kept > 0 {
            ctx.info(format!("The signature search found {kept} possible file starts."));
        }
        let mut cands = cands.into_iter().peekable();
        let mut next = 0usize;
        let mut batch: Vec<(Hit, Option<Option<Cand>>)> = Vec::with_capacity(1024);

        let mut res = Resolver::default();
        let mut reported = 0u64;
        let mut fragmented = 0u64;
        let mut ready: Vec<Cand> = Vec::new();
        let emit = |ready: &mut Vec<Cand>, reported: &mut u64, fragmented: &mut u64| {
            let files: Vec<FoundFile> = ready.par_iter().map(|c| self.build(src, c)).collect();
            for f in files {
                *reported += 1;
                *fragmented += f.fragmented as u64;
                ctx.found(f);
            }
            ready.clear();
        };
        while next < hits.len() {
            ctx.check()?;
            batch.clear();
            while next < hits.len() && batch.len() < 1024 {
                let i = next;
                next += 1;
                if dropped.get(i) {
                    continue;
                }
                let pre = done.get(i).then(|| if cands.peek().is_some_and(|c| c.0 == i) { cands.next().map(|c| c.1) } else { None });
                batch.push((hits[i], pre));
            }
            let claimed = &res.claimed;
            let parsed: Vec<Option<Cand>> = batch
                .par_iter_mut()
                .map(|(h, pre)| {
                    if let Some(r) = pre.take() {
                        return r;
                    }
                    if ctx.is_cancelled() {
                        return None;
                    }
                    // Inside a file resolved in an earlier batch: not a file start, so not parsed
                    // (`take` still cuts an estimated end there).
                    let r = if claimed.contains(h.off) { None } else { self.parse_hit(src, *h, &env) };
                    ctx.progress(1);
                    r
                })
                .collect();
            if ctx.is_cancelled() {
                return Err(CANCELLED.to_string());
            }
            for (i, (&(h, _), p)) in batch.iter().zip(parsed).enumerate() {
                if i % 64 == 0 {
                    ctx.check()?;
                }
                res.take(h, p, &known, &mut ready);
            }
            emit(&mut ready, &mut reported, &mut fragmented);
        }
        res.flush(&known, &mut ready);
        emit(&mut ready, &mut reported, &mut fragmented);

        let mut notes = Vec::new();
        if reported > 0 {
            notes.push(format!("Found {reported} files by their signatures."));
        }
        if fragmented > 0 {
            notes.push(format!("Rebuilt {fragmented} fragmented files from their pieces."));
        }
        Ok(EngineSummary { files: reported, deleted: 0, lost_folders: 0, notes })
    }
}
