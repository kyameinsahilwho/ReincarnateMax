//! `$I` records: the small metadata files Windows writes next to each `$R` item in the Recycle Bin.
//!
//! Version 1 (Vista - 8.1): `u64 version=1`, `u64 size`, `u64 FILETIME deleted`, 520 bytes of
//! UTF-16 path (260 chars, NUL-padded) = 544 bytes.
//! Version 2 (Windows 10+): `u64 version=2`, `u64 size`, `u64 FILETIME deleted`,
//! `u32 path length in UTF-16 units including the NUL`, then the UTF-16 path.

use super::RecycleInfo;
use crate::model::filetime_to_ms;

const V1_PATH_BYTES: usize = 520;
/// Longest path we accept (Windows' own limit is 32767 UTF-16 units).
const MAX_PATH_UNITS: usize = 32_767;

fn u64_at(d: &[u8], at: usize) -> Option<u64> {
    d.get(at..at + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}
fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    d.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

/// UTF-16LE up to the first NUL (or the end). None when the bytes are not valid UTF-16.
fn utf16_until_nul(bytes: &[u8]) -> Option<String> {
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
    String::from_utf16(&units).ok()
}

/// A plausible original path: "X:\..." or "\\server\share\...", no control characters.
fn plausible_path(p: &str) -> bool {
    let b = p.as_bytes();
    let drive = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
    let unc = p.starts_with("\\\\") && p.len() > 2;
    (drive || unc) && !p.chars().any(|c| c < ' ')
}

pub fn parse(data: &[u8]) -> Option<RecycleInfo> {
    let version = u64_at(data, 0)?;
    let size = u64_at(data, 8)?;
    let ft = u64_at(data, 16)?;
    let path = match version {
        1 => {
            let raw = data.get(24..24 + V1_PATH_BYTES)?;
            utf16_until_nul(raw)?
        }
        2 => {
            let units = u32_at(data, 24)? as usize;
            if units == 0 || units > MAX_PATH_UNITS {
                return None;
            }
            let raw = data.get(28..28 + units * 2)?;
            // The declared length includes the terminating NUL; tolerate records without it.
            utf16_until_nul(raw)?
        }
        _ => return None,
    };
    if path.is_empty() || !plausible_path(&path) {
        return None;
    }
    Some(RecycleInfo { original_path: path, size, deleted: filetime_to_ms(ft) })
}

#[cfg(test)]
pub(crate) fn build_v1(path: &str, size: u64, ft: u64) -> Vec<u8> {
    let mut d = Vec::with_capacity(544);
    d.extend_from_slice(&1u64.to_le_bytes());
    d.extend_from_slice(&size.to_le_bytes());
    d.extend_from_slice(&ft.to_le_bytes());
    let mut p: Vec<u8> = path.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    p.resize(V1_PATH_BYTES, 0);
    d.extend_from_slice(&p);
    d
}

#[cfg(test)]
pub(crate) fn build_v2(path: &str, size: u64, ft: u64) -> Vec<u8> {
    let units: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut d = Vec::new();
    d.extend_from_slice(&2u64.to_le_bytes());
    d.extend_from_slice(&size.to_le_bytes());
    d.extend_from_slice(&ft.to_le_bytes());
    d.extend_from_slice(&(units.len() as u32).to_le_bytes());
    for u in units {
        d.extend_from_slice(&u.to_le_bytes());
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2024-01-02 03:04:05 UTC
    const FT: u64 = 133_486_382_450_000_000;
    const MS: i64 = 1_704_164_645_000;

    #[test]
    fn parses_version_1() {
        let d = build_v1("C:\\Users\\Ann\\Pictures\\cat.jpg", 12345, FT);
        assert_eq!(d.len(), 544);
        let i = parse(&d).unwrap();
        assert_eq!(i.original_path, "C:\\Users\\Ann\\Pictures\\cat.jpg");
        assert_eq!(i.size, 12345);
        assert_eq!(i.deleted, Some(MS));
    }

    #[test]
    fn parses_version_2_with_unicode() {
        let p = "D:\\Fotos\\Ölberg 日本\\bild.png";
        let d = build_v2(p, 7, FT);
        let i = parse(&d).unwrap();
        assert_eq!(i.original_path, p);
        assert_eq!(i.size, 7);
        assert_eq!(i.deleted, Some(MS));
    }

    #[test]
    fn rejects_truncated_and_bogus_records() {
        let d = build_v2("C:\\a\\b.txt", 1, FT);
        for n in 0..d.len() - 2 {
            assert!(parse(&d[..n]).is_none(), "truncated at {n}");
        }
        // Without the trailing NUL unit the declared length runs past the end.
        assert!(parse(&d[..d.len() - 1]).is_none());
        let v1 = build_v1("C:\\x.txt", 1, FT);
        assert!(parse(&v1[..543]).is_none());
        // Unknown version.
        let mut bad = d.clone();
        bad[0] = 3;
        assert!(parse(&bad).is_none());
        // Absurd length.
        let mut huge = d.clone();
        huge[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse(&huge).is_none());
        let mut zero = d.clone();
        zero[24..28].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse(&zero).is_none());
        // Not a path.
        assert!(parse(&build_v2("garbage", 1, FT)).is_none());
        assert!(parse(&build_v1("", 1, FT)).is_none());
        // Zero FILETIME -> no date, still parsed.
        assert_eq!(parse(&build_v2("C:\\a.txt", 1, 0)).unwrap().deleted, None);
        // UNC origin.
        assert!(parse(&build_v2("\\\\nas\\share\\a.txt", 1, FT)).is_some());
    }
}
