//! Duplicate detection: group by size, then a quick hash (size + first and last 64 KiB), then full
//! BLAKE3 only where quick hashes collide (stored hashes are reused). Group id = smallest file id.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

pub const EDGE: usize = 64 * 1024;

#[derive(Debug, Default, PartialEq)]
pub struct DupResult {
    /// (file id, group id) for every file in a group of two or more.
    pub groups: Vec<(i64, i64)>,
    /// Full hashes computed here (to store).
    pub computed: Vec<(i64, String)>,
    pub group_count: u64,
    pub files: u64,
    pub wasted_bytes: u64,
}

/// `quick(id, size)` and `full(id)` return None when the file can't be read (it is then left out).
pub fn group(
    entries: &[(i64, u64, Option<String>)],
    quick: &dyn Fn(i64, u64) -> Option<[u8; 32]>,
    full: &dyn Fn(i64) -> Option<String>,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<DupResult, String> {
    let mut by_size: HashMap<u64, Vec<(i64, Option<String>)>> = HashMap::new();
    for (id, size, h) in entries {
        if *size > 0 {
            by_size.entry(*size).or_default().push((*id, h.clone()));
        }
    }
    let mut sizes: Vec<(u64, Vec<(i64, Option<String>)>)> = by_size.into_iter().filter(|(_, v)| v.len() >= 2).collect();
    sizes.sort_by_key(|(s, _)| *s);
    let mut total: u64 = sizes.iter().map(|(_, v)| v.len() as u64).sum();
    let mut done = 0u64;
    let mut res = DupResult::default();
    let cancelled = || if cancel.load(Ordering::Relaxed) { Err(crate::model::CANCELLED.replace("scan", "search")) } else { Ok(()) };

    for (size, files) in sizes {
        // Final (full-hash) key per file.
        let mut full_of: Vec<(i64, String)> = Vec::new();
        let mut unknown: Vec<i64> = Vec::new();
        for (id, h) in files {
            match h {
                Some(h) => full_of.push((id, h)),
                None => unknown.push(id),
            }
        }
        let have_known = !full_of.is_empty();
        let mut buckets: HashMap<[u8; 32], Vec<i64>> = HashMap::new();
        for id in unknown {
            cancelled()?;
            if let Some(q) = quick(id, size) {
                buckets.entry(q).or_default().push(id);
            }
            done += 1;
            progress(done, total);
        }
        // Known hashes count as progress too.
        done += full_of.len() as u64;
        let need: Vec<i64> = buckets.into_values().filter(|b| b.len() >= 2 || have_known).flatten().collect();
        total += need.len() as u64;
        for id in need {
            cancelled()?;
            if let Some(h) = full(id) {
                res.computed.push((id, h.clone()));
                full_of.push((id, h));
            }
            done += 1;
            progress(done, total);
        }
        let mut by_hash: HashMap<String, Vec<i64>> = HashMap::new();
        for (id, h) in full_of {
            by_hash.entry(h).or_default().push(id);
        }
        for ids in by_hash.into_values().filter(|v| v.len() >= 2) {
            let gid = *ids.iter().min().unwrap();
            res.group_count += 1;
            res.files += ids.len() as u64;
            res.wasted_bytes += size * (ids.len() as u64 - 1);
            res.groups.extend(ids.into_iter().map(|id| (id, gid)));
        }
    }
    res.groups.sort();
    progress(total, total);
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn groups_identical_content_only() {
        // id -> content
        let content: HashMap<i64, Vec<u8>> = [
            (1, b"aaaa".to_vec()),
            (2, b"aaaa".to_vec()),
            (3, b"aaab".to_vec()),
            (4, b"bbbbbb".to_vec()),
            (5, b"cccccc".to_vec()),
            (6, b"aaaa".to_vec()),
            (7, b"x".to_vec()),
            (8, Vec::new()),
            (9, Vec::new()),
            (10, b"zzzzzz".to_vec()),
        ]
        .into_iter()
        .collect();
        let hex = |d: &[u8]| blake3::hash(d).to_hex().to_string();
        let mut entries: Vec<(i64, u64, Option<String>)> = content.iter().map(|(id, d)| (*id, d.len() as u64, None)).collect();
        entries.sort();
        // 6 already has a stored hash; 10 has a stored hash equal to 5's content? no: its own.
        entries[5].2 = Some(hex(b"aaaa"));
        entries[9].2 = Some(hex(b"zzzzzz"));
        let fulls = RefCell::new(Vec::new());
        let quick = |id: i64, _: u64| Some(*blake3::hash(&content[&id]).as_bytes());
        let full = |id: i64| {
            fulls.borrow_mut().push(id);
            Some(hex(&content[&id]))
        };
        let cancel = AtomicBool::new(false);
        let mut last = (0, 0);
        let r = group(&entries, &quick, &full, &cancel, &mut |d, t| last = (d, t)).unwrap();
        assert_eq!(r.groups, vec![(1, 1), (2, 1), (6, 1)]);
        assert_eq!((r.group_count, r.files, r.wasted_bytes), (1, 3, 8));
        // Size-4 group has a known hash, so 1,2,3 get full hashes; 4 and 5 differ in quick hash and
        // size-6 has a known hash (10) so they're fully hashed too; 7 is alone; 8/9 are empty.
        let mut f = fulls.borrow().clone();
        f.sort();
        assert_eq!(f, vec![1, 2, 3, 4, 5]);
        assert_eq!(r.computed.len(), 5);
        assert_eq!(last.0, last.1);
    }

    #[test]
    fn quick_hash_avoids_full_reads_without_collisions() {
        let entries = vec![(1, 10, None), (2, 10, None)];
        let full_calls = RefCell::new(0);
        let quick = |id: i64, _: u64| Some([id as u8; 32]);
        let full = |_: i64| {
            *full_calls.borrow_mut() += 1;
            Some(String::new())
        };
        let r = group(&entries, &quick, &full, &AtomicBool::new(false), &mut |_, _| {}).unwrap();
        assert!(r.groups.is_empty());
        assert_eq!(*full_calls.borrow(), 0);
        assert!(group(&entries, &quick, &full, &AtomicBool::new(true), &mut |_, _| {}).is_err());
    }
}
