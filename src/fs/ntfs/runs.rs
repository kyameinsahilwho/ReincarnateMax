//! NTFS data runs ("mapping pairs"): where a non-resident attribute's clusters are.

/// One run: `len` clusters at `lcn` (`None` = sparse: reads as zeros, nothing stored).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Run {
    pub len: u64,
    pub lcn: Option<u64>,
}

/// Decode a mapping-pairs array. Returns the runs decoded and whether the whole list was valid
/// (a damaged list yields the runs before the damage and `false`).
pub fn decode_runs(b: &[u8]) -> (Vec<Run>, bool) {
    let mut runs = Vec::new();
    let mut pos = 0usize;
    let mut lcn: i64 = 0;
    while pos < b.len() {
        let h = b[pos];
        if h == 0 {
            return (runs, true);
        }
        let ln = (h & 0x0F) as usize;
        let on = (h >> 4) as usize;
        if ln == 0 || ln > 8 || on > 8 || pos + 1 + ln + on > b.len() {
            return (runs, false);
        }
        let mut len: u64 = 0;
        for i in 0..ln {
            len |= (b[pos + 1 + i] as u64) << (8 * i);
        }
        if len == 0 || len > (1u64 << 48) {
            return (runs, false);
        }
        let run_lcn = if on == 0 {
            None
        } else {
            let mut d: u64 = 0;
            for i in 0..on {
                d |= (b[pos + 1 + ln + i] as u64) << (8 * i);
            }
            // Sign-extend.
            if on < 8 && b[pos + ln + on] & 0x80 != 0 {
                d |= !0u64 << (8 * on);
            }
            lcn = match lcn.checked_add(d as i64) {
                Some(v) if v >= 0 => v,
                _ => return (runs, false),
            };
            Some(lcn as u64)
        };
        runs.push(Run { len, lcn: run_lcn });
        pos += 1 + ln + on;
    }
    // Ran off the end without a terminator: keep what we have but flag it.
    (runs, false)
}

/// Total clusters covered.
pub fn total_clusters(runs: &[Run]) -> u64 {
    runs.iter().fold(0u64, |a, r| a.saturating_add(r.len))
}

/// Map a virtual cluster number to (lcn, clusters remaining in that run); `None` for sparse or
/// out-of-range VCNs.
#[allow(dead_code)]
pub fn vcn_to_lcn(runs: &[Run], vcn: u64) -> Option<(u64, u64)> {
    let mut v = 0u64;
    for r in runs {
        if vcn < v.saturating_add(r.len) {
            let within = vcn - v;
            return r.lcn.map(|l| (l.saturating_add(within), r.len - within));
        }
        v = v.saturating_add(r.len);
    }
    None
}

/// Encode runs (tests and the synthetic image builder).
#[cfg(test)]
pub fn encode_runs(runs: &[Run]) -> Vec<u8> {
    fn bytes_unsigned(v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut x = v;
        loop {
            out.push(x as u8);
            x >>= 8;
            if x == 0 {
                break;
            }
        }
        out
    }
    fn bytes_signed(v: i64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut x = v;
        loop {
            let b = x as u8;
            out.push(b);
            x >>= 8;
            let sign = b & 0x80 != 0;
            if (x == 0 && !sign) || (x == -1 && sign) {
                break;
            }
        }
        out
    }
    let mut out = Vec::new();
    let mut prev: i64 = 0;
    for r in runs {
        let l = bytes_unsigned(r.len);
        let o = match r.lcn {
            Some(lcn) => {
                let d = bytes_signed(lcn as i64 - prev);
                prev = lcn as i64;
                d
            }
            None => Vec::new(),
        };
        out.push((l.len() as u8) | ((o.len() as u8) << 4));
        out.extend_from_slice(&l);
        out.extend_from_slice(&o);
    }
    out.push(0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_known_bytes() {
        // 0x21 0x18 0x34 0x56: 0x18 clusters at LCN 0x5634.
        // 0x11 0x30 0xF0: 0x30 clusters, delta -16 -> 0x5624.
        // 0x01 0x10: 16 sparse clusters.
        // 0x31 0x08 0x00 0x00 0x01: 8 clusters, delta +0x10000.
        let b = [0x21, 0x18, 0x34, 0x56, 0x11, 0x30, 0xF0, 0x01, 0x10, 0x31, 0x08, 0x00, 0x00, 0x01, 0x00];
        let (r, ok) = decode_runs(&b);
        assert!(ok);
        assert_eq!(
            r,
            vec![
                Run { len: 0x18, lcn: Some(0x5634) },
                Run { len: 0x30, lcn: Some(0x5624) },
                Run { len: 0x10, lcn: None },
                Run { len: 8, lcn: Some(0x15624) },
            ]
        );
        assert_eq!(total_clusters(&r), 0x18 + 0x30 + 0x10 + 8);
        assert_eq!(vcn_to_lcn(&r, 0x19), Some((0x5625, 0x2F)));
        assert_eq!(vcn_to_lcn(&r, 0x18 + 0x30), None);
        assert_eq!(vcn_to_lcn(&r, 10_000), None);
    }

    #[test]
    fn roundtrips_and_rejects_damage() {
        let runs = vec![
            Run { len: 1, lcn: Some(1_000_000) },
            Run { len: 300, lcn: Some(5) },
            Run { len: 7, lcn: None },
            Run { len: 70_000, lcn: Some(0x1_0000_0000) },
            Run { len: 2, lcn: Some(0x7F) },
        ];
        let enc = encode_runs(&runs);
        assert_eq!(decode_runs(&enc), (runs.clone(), true));
        // Truncated list: the runs before the damage, not ok.
        let (part, ok) = decode_runs(&enc[..enc.len() - 3]);
        assert!(!ok);
        assert!(part.len() < runs.len());
        // Negative LCN overall is invalid.
        let (r, ok) = decode_runs(&[0x11, 0x05, 0xF0, 0x00]);
        assert!(!ok && r.is_empty());
        // Zero-length run is invalid.
        assert!(!decode_runs(&[0x11, 0x00, 0x05, 0x00]).1);
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..20_000 {
            let n = (x % 40) as usize;
            let mut b = Vec::with_capacity(n);
            for _ in 0..n {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                b.push(x as u8);
            }
            let (r, _) = decode_runs(&b);
            let _ = total_clusters(&r);
            let _ = vcn_to_lcn(&r, x % 1000);
        }
    }
}
