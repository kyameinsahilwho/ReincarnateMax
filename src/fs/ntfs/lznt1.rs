//! LZNT1 (NTFS compression) and reading compressed files.
//!
//! A compressed file is split into compression units (16 clusters by default). A unit is stored
//! either as LZNT1 data in its first clusters followed by sparse clusters, as plain data when all
//! of its clusters are allocated (compression didn't help), or not at all (all sparse = zeros).

use crate::device::source::{read_tolerant, BlockSource};
use crate::model::{FoundFile, SPARSE};
use std::cell::RefCell;

const CHUNK: usize = 4096;

/// Decompress one chunk's compressed payload, appending at most 4096 bytes to `out`.
/// Returns false on malformed input (whatever decoded so far stays in `out`).
fn decompress_chunk(data: &[u8], out: &mut Vec<u8>) -> bool {
    let start = out.len();
    let mut i = 0usize;
    while i < data.len() {
        let flags = data[i];
        i += 1;
        for bit in 0..8 {
            if i >= data.len() {
                return true;
            }
            let pos = out.len() - start;
            if pos >= CHUNK {
                return true;
            }
            if flags & (1 << bit) == 0 {
                out.push(data[i]);
                i += 1;
                continue;
            }
            if i + 2 > data.len() || pos == 0 {
                return false;
            }
            let t = u16::from_le_bytes([data[i], data[i + 1]]);
            i += 2;
            let mut l_mask: u16 = 0x0FFF;
            let mut o_shift = 12u32;
            let mut k = pos - 1;
            while k >= 0x10 {
                l_mask >>= 1;
                o_shift -= 1;
                k >>= 1;
            }
            let len = (t & l_mask) as usize + 3;
            let off = (t >> o_shift) as usize + 1;
            if off > pos {
                return false;
            }
            for _ in 0..len {
                if out.len() - start >= CHUNK {
                    break;
                }
                let b = out[out.len() - off];
                out.push(b);
            }
        }
    }
    true
}

/// Decompress an LZNT1 stream (one compression unit) into at most `max_out` bytes. Every chunk
/// stands for 4096 bytes of output; a short chunk followed by another one is zero-padded.
/// Returns false if the input was damaged (output keeps what could be decoded).
pub fn decompress(input: &[u8], out: &mut Vec<u8>, max_out: usize) -> bool {
    let mut p = 0usize;
    let mut ok = true;
    while p + 2 <= input.len() && out.len() < max_out {
        let h = u16::from_le_bytes([input[p], input[p + 1]]);
        if h == 0 {
            break;
        }
        let size = (h & 0x0FFF) as usize + 1;
        let end = (p + 2 + size).min(input.len());
        if p + 2 + size > input.len() {
            ok = false;
        }
        let data = &input[p + 2..end];
        let chunk_start = out.len();
        if h & 0x8000 != 0 {
            ok &= decompress_chunk(data, out);
        } else {
            out.extend_from_slice(&data[..data.len().min(CHUNK)]);
        }
        p = end;
        let more = p + 2 <= input.len() && (input[p] | input[p + 1]) != 0;
        if more && out.len() < chunk_start + CHUNK {
            out.resize(chunk_start + CHUNK, 0);
        }
    }
    out.truncate(max_out);
    ok
}

fn meta_u64(f: &FoundFile, key: &str) -> Option<u64> {
    f.meta.get(key).and_then(|v| v.parse().ok())
}

/// Physical pieces of the virtual byte range [start, start+len): (offset or SPARSE, len). Ranges
/// beyond the extents come back as SPARSE.
fn pieces(f: &FoundFile, start: u64, len: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let end = start + len;
    let mut v = 0u64;
    for e in &f.extents {
        let ve = v.saturating_add(e.len);
        if ve > start && v < end {
            let s = start.max(v);
            let t = end.min(ve);
            let phys = if e.offset == SPARSE { SPARSE } else { e.offset + (s - v) };
            out.push((phys, t - s));
        }
        v = ve;
        if v >= end {
            break;
        }
    }
    let covered: u64 = out.iter().map(|p| p.1).sum();
    if covered < len {
        out.push((SPARSE, len - covered));
    }
    out
}

thread_local! {
    /// Last decompressed unit: ((first extent offset, size, unit index), (bytes, hit bad sectors)).
    static CACHE: RefCell<Option<((u64, u64, u64), (Vec<u8>, bool))>> = const { RefCell::new(None) };
}

/// Produce compression unit `u` of the file (exactly `unit` bytes), and whether any of its stored
/// clusters were unreadable (zero-filled before decompressing).
fn load_unit(src: &dyn BlockSource, f: &FoundFile, unit: u64, u: u64) -> (Vec<u8>, bool) {
    let key = (f.first_offset().unwrap_or(SPARSE), f.size, u.wrapping_mul(unit));
    if let Some(v) = CACHE.with(|c| c.borrow().as_ref().filter(|(k, _)| *k == key).map(|(_, v)| v.clone())) {
        return v;
    }
    let ps = pieces(f, u * unit, unit);
    let stored: u64 = ps.iter().filter(|p| p.0 != SPARSE).map(|p| p.1).sum();
    let mut out = vec![0u8; unit as usize];
    let mut bad_any = false;
    if stored >= unit {
        // Stored uncompressed.
        let mut at = 0usize;
        for (off, len) in ps {
            let piece = &mut out[at..at + len as usize];
            if off != SPARSE {
                bad_any |= !read_tolerant(src, off, piece, None).1.is_empty();
            }
            at += len as usize;
        }
    } else if stored > 0 {
        // Compressed data in the stored clusters (they come first), then sparse.
        let mut comp = Vec::with_capacity(stored as usize);
        for (off, len) in ps {
            if off == SPARSE {
                break;
            }
            let n = comp.len();
            comp.resize(n + len as usize, 0);
            bad_any |= !read_tolerant(src, off, &mut comp[n..], None).1.is_empty();
        }
        let mut dec = Vec::with_capacity(unit as usize);
        decompress(&comp, &mut dec, unit as usize);
        out[..dec.len()].copy_from_slice(&dec);
    }
    CACHE.with(|c| *c.borrow_mut() = Some((key, (out.clone(), bad_any))));
    (out, bad_any)
}

/// See [`super::read_compressed`].
pub fn read_compressed(src: &dyn BlockSource, f: &FoundFile, pos: u64, buf: &mut [u8]) -> Result<usize, String> {
    read_compressed_checked(src, f, pos, buf).map(|(n, _)| n)
}

/// See [`super::read_compressed_checked`].
pub fn read_compressed_checked(src: &dyn BlockSource, f: &FoundFile, pos: u64, buf: &mut [u8]) -> Result<(usize, bool), String> {
    if pos >= f.size || buf.is_empty() {
        return Ok((0, false));
    }
    let cluster = meta_u64(f, "clusterSize").filter(|c| c.is_power_of_two() && (512..=65536).contains(c)).unwrap_or(4096);
    let cu = meta_u64(f, "compressionUnit").filter(|c| c.is_power_of_two() && (1..=256).contains(c)).unwrap_or(16);
    let unit = cluster * cu;
    let want = (buf.len() as u64).min(f.size - pos) as usize;
    let mut got = 0usize;
    let mut bad_any = false;
    while got < want {
        let p = pos + got as u64;
        let u = p / unit;
        let (data, bad) = load_unit(src, f, unit, u);
        bad_any |= bad;
        let within = (p - u * unit) as usize;
        let n = (data.len() - within).min(want - got);
        buf[got..got + n].copy_from_slice(&data[within..within + n]);
        got += n;
    }
    Ok((got, bad_any))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::device::source::MemSource;
    use crate::model::{flags, Extent};

    /// Reference compressor (greedy, brute-force matching) producing valid LZNT1.
    pub fn compress(input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in input.chunks(CHUNK) {
            let mut body = Vec::new();
            let mut pos = 0usize;
            while pos < chunk.len() {
                let flag_at = body.len();
                body.push(0u8);
                for bit in 0..8 {
                    if pos >= chunk.len() {
                        break;
                    }
                    let mut shifts = 0u32;
                    let mut k = pos.saturating_sub(1);
                    while k >= 0x10 {
                        shifts += 1;
                        k >>= 1;
                    }
                    let max_off = 1usize << (4 + shifts);
                    let max_len = (0x0FFFusize >> shifts) + 3;
                    let (mut best_len, mut best_off) = (0usize, 0usize);
                    if pos > 0 {
                        for off in 1..=pos.min(max_off) {
                            let mut l = 0;
                            while l < max_len && pos + l < chunk.len() && chunk[pos + l] == chunk[pos + l - off] {
                                l += 1;
                            }
                            if l > best_len {
                                best_len = l;
                                best_off = off;
                            }
                        }
                    }
                    if best_len >= 3 {
                        let t = (((best_off - 1) as u16) << (12 - shifts)) | ((best_len - 3) as u16);
                        body.extend_from_slice(&t.to_le_bytes());
                        body[flag_at] |= 1 << bit;
                        pos += best_len;
                    } else {
                        body.push(chunk[pos]);
                        pos += 1;
                    }
                }
            }
            if body.len() < chunk.len() {
                out.extend_from_slice(&(0xB000u16 | (body.len() as u16 - 1)).to_le_bytes());
                out.extend_from_slice(&body);
            } else {
                out.extend_from_slice(&(0x3000u16 | (chunk.len() as u16 - 1)).to_le_bytes());
                out.extend_from_slice(chunk);
            }
        }
        out
    }

    #[test]
    fn decodes_hand_made_vector() {
        // "abcabcabcabc!": literals a b c, then a back-reference (offset 3, length 9) and '!'.
        // At pos 3 the token has 12 length bits: offset-1 = 2 -> 0x2000 | (9-3) = 0x2006.
        let body = [0b0000_1000u8, b'a', b'b', b'c', 0x06, 0x20, b'!'];
        let mut s = vec![];
        s.extend_from_slice(&(0xB000u16 | (body.len() as u16 - 1)).to_le_bytes());
        s.extend_from_slice(&body);
        let mut out = Vec::new();
        assert!(decompress(&s, &mut out, 65536));
        assert_eq!(out, b"abcabcabcabc!");
    }

    #[test]
    fn roundtrips_with_reference_compressor() {
        let mut data = Vec::new();
        for i in 0..20_000u32 {
            data.extend_from_slice(format!("line {} of the test {}\n", i % 97, i % 13).as_bytes());
        }
        data.truncate(65536 + 1000);
        let mut x = 7u32;
        let noise: Vec<u8> = (0..5000)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                (x >> 16) as u8
            })
            .collect();
        for sample in [&data[..], &noise[..], &data[..100], &[7u8; 4096 * 3][..]] {
            let c = compress(sample);
            let mut out = Vec::new();
            assert!(decompress(&c, &mut out, sample.len() + 8192));
            assert_eq!(out, sample);
        }
    }

    #[test]
    fn damaged_input_never_panics() {
        let mut x = 99u64;
        for _ in 0..5000 {
            let n = (x % 300) as usize;
            let b: Vec<u8> = (0..n)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                })
                .collect();
            let mut out = Vec::new();
            decompress(&b, &mut out, 65536);
            assert!(out.len() <= 65536);
        }
    }

    #[test]
    fn reads_compressed_file_units() {
        // Cluster 512, unit 16 clusters = 8 KiB. File: unit 0 compressed (text), unit 1 stored
        // plain (noise), unit 2 sparse, unit 3 compressed and short (end of file).
        let cs = 512u64;
        let unit = 16 * cs;
        let mut content = Vec::new();
        for i in 0..unit {
            content.push(b"compressible text "[(i % 18) as usize]);
        }
        let mut x = 1u32;
        for _ in 0..unit {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            content.push((x >> 16) as u8);
        }
        content.extend(std::iter::repeat(0u8).take(unit as usize));
        for i in 0..3000u64 {
            content.push((i % 7) as u8 + b'0');
        }
        let size = content.len() as u64;

        let mut disk = vec![0u8; 200 * cs as usize];
        let c0 = compress(&content[..unit as usize]);
        let c0_clusters = (c0.len() as u64).div_ceil(cs);
        assert!(c0_clusters < 16);
        disk[10 * 512..10 * 512 + c0.len()].copy_from_slice(&c0);
        disk[40 * 512..40 * 512 + unit as usize].copy_from_slice(&content[unit as usize..2 * unit as usize]);
        let c3 = compress(&content[3 * unit as usize..]);
        let c3_clusters = (c3.len() as u64).div_ceil(cs);
        disk[100 * 512..100 * 512 + c3.len()].copy_from_slice(&c3);
        let extents = vec![
            Extent { offset: 10 * cs, len: c0_clusters * cs },
            Extent { offset: SPARSE, len: (16 - c0_clusters) * cs },
            Extent { offset: 40 * cs, len: unit },
            Extent { offset: SPARSE, len: unit },
            Extent { offset: 100 * cs, len: c3_clusters * cs },
            Extent { offset: SPARSE, len: (16 - c3_clusters) * cs },
        ];
        let mut f = FoundFile { size, extents, flags: flags::COMPRESSED, ..Default::default() };
        f.meta.insert("clusterSize".into(), "512".into());
        f.meta.insert("compressionUnit".into(), "16".into());
        let m = MemSource::new(disk);
        let mut all = vec![0u8; size as usize + 100];
        let n = read_compressed(&m, &f, 0, &mut all).unwrap();
        assert_eq!(n as u64, size);
        assert_eq!(&all[..n], &content[..]);
        // Small reads at odd positions.
        let mut b = [0u8; 777];
        for p in [0u64, 5000, unit - 3, 2 * unit + 100, size - 10] {
            let n = read_compressed(&m, &f, p, &mut b).unwrap();
            assert_eq!(&b[..n], &content[p as usize..p as usize + n]);
        }
        assert_eq!(read_compressed_checked(&m, &f, 0, &mut all).unwrap(), (size as usize, false));

        // Unreadable sectors are reported, for compressed (unit 0) and plain-stored (unit 1) units,
        // but not for units read from good sectors or sparse ones.
        let mut bad = MemSource::new(m.data.clone());
        bad.bad = vec![(10 * cs, 10 * cs + 512), (41 * cs, 41 * cs + 512)];
        for (p, want_bad) in [(100u64, true), (unit + 100, true), (2 * unit + 100, false), (3 * unit + 10, false)] {
            let (n, hit) = read_compressed_checked(&bad, &f, p, &mut b).unwrap();
            assert!(n > 0);
            assert_eq!(hit, want_bad, "read at {p}");
        }
        // The same unit again (from the per-thread cache) still says so.
        assert!(read_compressed_checked(&bad, &f, unit + 200, &mut b).unwrap().1);
        let (n, hit) = read_compressed_checked(&bad, &f, 0, &mut all).unwrap();
        assert_eq!((n as u64, hit), (size, true));
    }
}
