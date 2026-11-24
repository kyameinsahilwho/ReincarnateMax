//! JPEG thumbnails for the gallery: decoded images (input capped at 64 MiB), embedded previews of
//! camera RAW files (TIFF JPEG pointers / strips, RAF header, CR3 PRVW/THMB), EXIF orientation
//! applied. A small LRU cache (~48 MB), at most 4 concurrent decodes of at most 384 MiB each.

use super::exif::{jpeg_exif, jpeg_info, parse_tiff};
use super::util::*;
use super::validate::decode_limited;
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, OnceLock};

pub const MAX_INPUT: u64 = 64 << 20;
const CACHE_BYTES: usize = 48 << 20;
const MAX_DECODES: usize = 4;
/// The most one thumbnail decode may allocate (a 100-megapixel RGB photo); every decode also
/// shares one memory budget (`validate::decode_limited`).
const THUMB_ALLOC: u64 = 384 << 20;

/// A thumbnail of at most `px` × `px` (JPEG, quality 80), or None when the type has no preview.
pub fn make(type_id: &str, rr: &dyn RandomRead, px: u32) -> Option<Vec<u8>> {
    let k = kind(type_id);
    let (img_bytes, img_kind, orientation) = match k {
        Kind::Jpeg | Kind::Png | Kind::Gif | Kind::Webp | Kind::Bmp | Kind::Tiff | Kind::Ico => {
            if rr.size() > MAX_INPUT {
                return None;
            }
            let d = rr.read_vec(0, rr.size() as usize);
            let o = match k {
                Kind::Jpeg => jpeg_exif(&d).and_then(|e| e.orientation),
                Kind::Tiff => parse_tiff(&d).and_then(|e| e.orientation),
                _ => None,
            };
            (d, k, o)
        }
        Kind::Raw | Kind::Cr3 | Kind::Raf => {
            let (j, o) = raw_preview(k, rr)?;
            (j, Kind::Jpeg, o)
        }
        _ => return None,
    };
    let img = decode_limited(img_kind, &img_bytes, THUMB_ALLOC).ok()?;
    drop(img_bytes);
    let t = img.thumbnail(px, px);
    let t = orient(t, orientation.unwrap_or(1));
    encode_jpeg(&t, 80)
}

pub fn orient(i: image::DynamicImage, o: u32) -> image::DynamicImage {
    match o {
        2 => i.fliph(),
        3 => i.rotate180(),
        4 => i.flipv(),
        5 => i.rotate90().fliph(),
        6 => i.rotate90(),
        7 => i.rotate270().fliph(),
        8 => i.rotate270(),
        _ => i,
    }
}

pub fn encode_jpeg(i: &image::DynamicImage, q: u8) -> Option<Vec<u8>> {
    let rgb = if i.color().has_alpha() {
        // Composite on white so transparent areas don't turn black.
        let rgba = i.to_rgba8();
        let mut out = image::RgbImage::new(rgba.width(), rgba.height());
        for (o, p) in out.pixels_mut().zip(rgba.pixels()) {
            let a = p[3] as u32;
            for c in 0..3 {
                o[c] = ((p[c] as u32 * a + 255 * (255 - a)) / 255) as u8;
            }
        }
        out
    } else {
        i.to_rgb8()
    };
    let mut out = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, q).encode_image(&rgb).ok()?;
    Some(out)
}

/// The largest decodable embedded JPEG of a camera RAW file, and the RAW's orientation.
pub fn raw_preview(k: Kind, rr: &dyn RandomRead) -> Option<(Vec<u8>, Option<u32>)> {
    let size = rr.size();
    let usable = |j: &[u8]| -> bool {
        j.len() > 1024 && j.starts_with(&[0xFF, 0xD8]) && jpeg_info(j).is_some_and(|i| i.sof.is_some_and(|s| s != 0xC3 && s != 0xC7 && s != 0xCB && s != 0xCF))
    };
    match k {
        Kind::Raf => {
            let h = rr.read_vec(0, 100);
            let (o, l) = (be32(&h, 84)? as u64, be32(&h, 88)? as u64);
            if l == 0 || l > MAX_INPUT || o + l > size {
                return None;
            }
            let j = rr.read_vec(o, l as usize);
            let orient = jpeg_exif(&j).and_then(|e| e.orientation);
            usable(&j).then_some((j, orient))
        }
        Kind::Cr3 => {
            let head = rr.read_vec(0, 4 << 20);
            for tag in [&b"PRVW"[..], b"THMB"] {
                let mut p = 0;
                while let Some(i) = find_from(&head, tag, p) {
                    p = i + 4;
                    let win = &head[i..head.len().min(i + 64)];
                    let Some(s) = find(win, &[0xFF, 0xD8, 0xFF]) else { continue };
                    let at = i + s;
                    let Some(len) = be32(&head, at - 4).map(|l| l as usize) else { continue };
                    if len < 1024 || len as u64 > MAX_INPUT {
                        continue;
                    }
                    let j = rr.read_vec(at as u64, len);
                    if usable(&j) {
                        let o = find(&head, b"CMT1").and_then(|c| parse_tiff(&head[c + 4..])).and_then(|e| e.orientation);
                        return Some((j, o));
                    }
                }
            }
            None
        }
        _ => {
            let head = rr.read_vec(0, 1 << 20);
            let info = parse_tiff(&head)?;
            let mut cands = info.jpegs.clone();
            cands.sort_by_key(|&(_, l)| std::cmp::Reverse(l));
            cands.dedup();
            for (o, l) in cands.into_iter().take(4) {
                if l < 1024 || l as u64 > MAX_INPUT || o as u64 + l as u64 > size {
                    continue;
                }
                let j = rr.read_vec(o as u64, l);
                if usable(&j) && decode_limited(Kind::Jpeg, &j, THUMB_ALLOC).is_ok() {
                    return Some((j, info.orientation));
                }
            }
            None
        }
    }
}

// ---------------------------------------------------------------------------- cache + limiter

type Key = (String, i64, u32);

#[derive(Default)]
struct Lru {
    map: HashMap<Key, (Arc<Option<Vec<u8>>>, u64)>,
    bytes: usize,
    tick: u64,
}

fn cache() -> &'static Mutex<Lru> {
    static C: OnceLock<Mutex<Lru>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(Lru::default()))
}

fn entry_size(v: &Option<Vec<u8>>) -> usize {
    v.as_ref().map_or(0, |b| b.len()) + 64
}

pub fn cache_get(k: &Key) -> Option<Arc<Option<Vec<u8>>>> {
    let mut c = cache().lock().unwrap_or_else(|e| e.into_inner());
    c.tick += 1;
    let t = c.tick;
    let e = c.map.get_mut(k)?;
    e.1 = t;
    Some(e.0.clone())
}

pub fn cache_put(k: Key, v: Arc<Option<Vec<u8>>>) {
    let mut c = cache().lock().unwrap_or_else(|e| e.into_inner());
    c.tick += 1;
    let t = c.tick;
    c.bytes += entry_size(&v);
    if let Some(old) = c.map.insert(k, (v, t)) {
        c.bytes -= entry_size(&old.0);
    }
    while c.bytes > CACHE_BYTES && c.map.len() > 1 {
        let oldest = c.map.iter().min_by_key(|(_, (_, t))| *t).map(|(k, _)| k.clone());
        match oldest.and_then(|k| c.map.remove(&k)) {
            Some((v, _)) => c.bytes -= entry_size(&v),
            None => break,
        }
    }
}

struct Limiter {
    n: Mutex<usize>,
    cv: Condvar,
}

fn limiter() -> &'static Limiter {
    static L: OnceLock<Limiter> = OnceLock::new();
    L.get_or_init(|| Limiter { n: Mutex::new(0), cv: Condvar::new() })
}

pub struct Permit;

impl Permit {
    pub fn acquire() -> Permit {
        let l = limiter();
        let mut n = l.n.lock().unwrap_or_else(|e| e.into_inner());
        while *n >= MAX_DECODES {
            n = l.cv.wait(n).unwrap_or_else(|e| e.into_inner());
        }
        *n += 1;
        Permit
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let l = limiter();
        let mut n = l.n.lock().unwrap_or_else(|e| e.into_inner());
        *n = n.saturating_sub(1);
        l.cv.notify_one();
    }
}

/// Cached thumbnail: `make_fn` runs (at most 4 at a time) only on a cache miss.
pub fn cached(session: &str, id: i64, px: u32, make_fn: impl FnOnce() -> Option<Vec<u8>>) -> Arc<Option<Vec<u8>>> {
    let key = (session.to_string(), id, px);
    if let Some(v) = cache_get(&key) {
        return v;
    }
    let _p = Permit::acquire();
    // Another request may have made it while we waited.
    if let Some(v) = cache_get(&key) {
        return v;
    }
    let v = Arc::new(make_fn());
    cache_put(key, v.clone());
    v
}

#[cfg(test)]
mod tests {
    use super::super::validate::tests::{jpeg_bytes, png_bytes};
    use super::*;

    #[test]
    fn thumbs_images_and_raw_previews() {
        let j = jpeg_bytes(400, 200);
        let t = make("jpg", &j.as_slice(), 128).unwrap();
        let img = image::load_from_memory(&t).unwrap();
        assert_eq!((img.width(), img.height()), (128, 64));
        let p = png_bytes(50, 100);
        let t = make("png", &p.as_slice(), 64).unwrap();
        let img = image::load_from_memory(&t).unwrap();
        assert_eq!((img.width(), img.height()), (32, 64));
        assert!(make("heic", &p.as_slice(), 64).is_none());

        // A TIFF-style RAW with a JPEG preview pointed to by IFD0 0x0201/0x0202.
        let prev = jpeg_bytes(160, 120);
        let mut raw = b"II*\0\x08\0\0\0".to_vec();
        raw.extend_from_slice(&3u16.to_le_bytes());
        let ent = |d: &mut Vec<u8>, tag: u16, typ: u16, count: u32, val: u32| {
            d.extend_from_slice(&tag.to_le_bytes());
            d.extend_from_slice(&typ.to_le_bytes());
            d.extend_from_slice(&count.to_le_bytes());
            d.extend_from_slice(&val.to_le_bytes());
        };
        let at = 8 + 2 + 3 * 12 + 4;
        ent(&mut raw, 0x0112, 3, 1, 8);
        ent(&mut raw, 0x0201, 4, 1, at as u32);
        ent(&mut raw, 0x0202, 4, 1, prev.len() as u32);
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&prev);
        raw.extend_from_slice(&[0x42; 5000]);
        let t = make("nef", &raw.as_slice(), 100).unwrap();
        let img = image::load_from_memory(&t).unwrap();
        // Orientation 8 rotates 160x120 -> 75x100 thumbnail.
        assert_eq!((img.width(), img.height()), (75, 100));

        // RAF: preview offset/length at 84/88.
        let mut raf = b"FUJIFILMCCD-RAW 0201".to_vec();
        raf.resize(100, 0);
        raf[84..88].copy_from_slice(&100u32.to_be_bytes());
        raf[88..92].copy_from_slice(&(prev.len() as u32).to_be_bytes());
        raf.extend_from_slice(&prev);
        assert!(make("raf", &raf.as_slice(), 64).is_some());
    }

    #[test]
    fn cache_evicts_and_limits() {
        let k = ("s-test".to_string(), 1, 64);
        let mut calls = 0;
        let v = cached("s-test", 1, 64, || {
            calls += 1;
            Some(vec![1, 2, 3])
        });
        assert_eq!(v.as_ref().as_deref(), Some(&[1u8, 2, 3][..]));
        let v2 = cached("s-test", 1, 64, || panic!("should be cached"));
        assert!(Arc::ptr_eq(&v, &v2));
        assert_eq!(calls, 1);
        // Fill past the cap: the first entry goes.
        for i in 0..60 {
            cache_put(("s-fill".into(), i, 64), Arc::new(Some(vec![0u8; 1 << 20])));
        }
        assert!(cache_get(&k).is_none());
        let c = cache().lock().unwrap();
        assert!(c.bytes <= CACHE_BYTES);
    }
}
