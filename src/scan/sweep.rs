//! The deep-scan sector sweep: one reader doing large sequential, sector-aligned, bad-sector
//! tolerant reads (HDD-friendly) into a bounded queue, a few worker threads handing every chunk to
//! every visitor, and a watermark of contiguously finished chunks (`sweep_pos`) for checkpoints.

use super::jobs::Job;
use crate::device::source::read_tolerant;
use crate::model::{ChunkVisitor, MapKind, CANCELLED};
use std::any::Any;
use std::collections::BTreeSet;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, sync_channel};
use std::sync::Mutex;

/// Sweep [start, len). Ok when everything was read and visited; Err(CANCELLED) when stopped
/// (`job.sweep_pos` then says how far it got). A visitor panic is re-raised on this thread after
/// the workers stopped.
pub fn run(job: &Job, chunk: u64, visitors: &[Box<dyn ChunkVisitor>], start: u64, skip_allocated: bool) -> Result<(), String> {
    let ctx = &*job.ctx;
    let src = job.src.as_ref();
    let len = src.len();
    let ss = src.sector_size().max(512) as u64;
    let chunk = (chunk / ss).max(1) * ss;
    ctx.set_stage("sweep", len);
    ctx.set_progress(start.min(len));
    job.sweep_pos.store(start.min(len), Ordering::Relaxed);
    if start >= len {
        return Ok(());
    }
    let n = (len - start).div_ceil(chunk);
    let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(2, 4);
    let (tx, rx) = sync_channel::<(u64, u64, Vec<u8>, usize)>(workers * 2);
    let rx = Mutex::new(rx);
    let (free_tx, free_rx) = channel::<Vec<u8>>();
    let tracker: Mutex<(u64, BTreeSet<u64>)> = Mutex::new((0, BTreeSet::new()));
    let abort = AtomicBool::new(false);
    let panicked: Mutex<Option<Box<dyn Any + Send>>> = Mutex::new(None);
    let complete = |idx: u64| {
        let mut t = tracker.lock().unwrap_or_else(|e| e.into_inner());
        t.1.insert(idx);
        loop {
            let next = t.0;
            if !t.1.remove(&next) {
                break;
            }
            t.0 += 1;
        }
        job.sweep_pos.store((start + t.0 * chunk).min(len), Ordering::Relaxed);
    };
    let mut cancelled = false;
    std::thread::scope(|s| {
        for w in 0..workers {
            let (rx, free_tx, complete, abort, panicked) = (&rx, free_tx.clone(), &complete, &abort, &panicked);
            let spawned = std::thread::Builder::new().name(format!("max-sweep-{w}")).spawn_scoped(s, move || loop {
                let item = rx.lock().unwrap_or_else(|e| e.into_inner()).recv();
                let Ok((idx, off, buf, got)) = item else { break };
                if !abort.load(Ordering::Relaxed) {
                    let r = catch_unwind(AssertUnwindSafe(|| {
                        for v in visitors {
                            v.visit(src, off, &buf[..got], ctx);
                        }
                    }));
                    match r {
                        Ok(()) => {
                            ctx.progress(got as u64);
                            complete(idx);
                        }
                        Err(p) => {
                            abort.store(true, Ordering::Relaxed);
                            panicked.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert(p);
                        }
                    }
                }
                let _ = free_tx.send(buf);
            });
            if spawned.is_err() {
                abort.store(true, Ordering::Relaxed);
            }
        }
        drop(free_tx);
        for idx in 0..n {
            if ctx.check().is_err() {
                cancelled = true;
                break;
            }
            if abort.load(Ordering::Relaxed) {
                break;
            }
            let off = start + idx * chunk;
            let clen = chunk.min(len - off);
            if skip_allocated && ctx.allocated.read().unwrap_or_else(|e| e.into_inner()).overlap(off, off + clen) == clen {
                // Live data only (already on the map as Allocated): nothing to carve here.
                ctx.progress(clen);
                complete(idx);
                continue;
            }
            let mut buf = free_rx.try_recv().unwrap_or_else(|_| vec![0u8; chunk as usize]);
            let (got, bad) = read_tolerant(src, off, &mut buf[..clen as usize], Some(ctx));
            let mut p = off;
            for (bs, be) in bad {
                if bs > p {
                    ctx.mark(MapKind::Scanned, p, bs - p);
                }
                p = p.max(be);
            }
            let end = off + got as u64;
            if end > p {
                ctx.mark(MapKind::Scanned, p, end - p);
            }
            if tx.send((idx, off, buf, got)).is_err() {
                break;
            }
        }
        drop(tx);
    });
    if let Some(p) = panicked.into_inner().unwrap_or_else(|e| e.into_inner()) {
        resume_unwind(p);
    }
    if cancelled || job.sweep_pos.load(Ordering::Relaxed) < len {
        return Err(CANCELLED.into());
    }
    Ok(())
}
