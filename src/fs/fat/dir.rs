//! FAT directory entries: 8.3 entries, long-name (LFN) reconstruction including deleted LFN
//! entries, timestamps, plausibility checks used by the directory sweep.

use super::util::{dos_to_ms, oem_char, rd16, rd32};

pub(crate) const DOT: &[u8; 11] = b".          ";
pub(crate) const DOTDOT: &[u8; 11] = b"..         ";

#[derive(Clone, Debug, Default)]
pub(crate) struct DirEnt {
    pub name: String,
    pub short_name: String,
    pub has_long_name: bool,
    /// The first character of the name was lost and replaced by '_'.
    pub name_guessed: bool,
    pub deleted: bool,
    pub attr: u8,
    pub start: u32,
    /// The high word of the start cluster is zero (FAT32 only matters).
    pub hi_zero: bool,
    pub size: u32,
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub accessed: Option<i64>,
    /// Absolute byte offset of the 8.3 entry on the source.
    pub offset: u64,
}

impl DirEnt {
    pub fn is_dir(&self) -> bool {
        self.attr & 0x10 != 0
    }
}

/// Result of parsing a directory buffer.
#[derive(Default)]
pub(crate) struct Parsed {
    pub entries: Vec<DirEnt>,
    pub label: Option<String>,
    /// "." entry's cluster and ".." entry's cluster, when present at slots 0 and 1.
    pub dot: Option<(u32, u32)>,
    /// An end-of-directory (0x00) entry was seen.
    pub ended: bool,
}

struct Lfn {
    ord: u8,
    checksum: u8,
    chars: [u16; 13],
}

pub(crate) fn lfn_checksum(n: &[u8; 11]) -> u8 {
    let mut s: u8 = 0;
    for &c in n {
        s = (if s & 1 != 0 { 0x80u8 } else { 0 }).wrapping_add(s >> 1).wrapping_add(c);
    }
    s
}

fn lfn_chars(b: &[u8]) -> [u16; 13] {
    let mut out = [0u16; 13];
    let pos = [1usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
    for (i, p) in pos.iter().enumerate() {
        out[i] = rd16(b, *p);
    }
    out
}

fn lfn_valid(b: &[u8]) -> bool {
    b[11] & 0x3F == 0x0F && b[12] == 0 && rd16(b, 26) == 0 && b[0] != 0
}

const BAD_SHORT: &[u8] = b"\"*+,./:;<=>?[\\]|";

/// Plausibility of an 8.3 entry. `strict` (sweep / deleted-directory continuation) also rejects
/// lowercase letters, odd dates and non-empty directory sizes.
pub(crate) fn short_valid(b: &[u8], strict: bool, max_cluster: Option<u32>) -> bool {
    if b.len() < 32 {
        return false;
    }
    let attr = b[11];
    if attr & 0xC0 != 0 {
        return false;
    }
    if b[0] == b' ' {
        return false;
    }
    for (i, &c) in b[..11].iter().enumerate() {
        if i == 0 && (c == 0xE5 || c == 0x05) {
            continue;
        }
        if c < 0x20 || BAD_SHORT.contains(&c) {
            return false;
        }
        if strict && c.is_ascii_lowercase() {
            return false;
        }
    }
    if strict {
        if attr & 0x10 != 0 && rd32(b, 28) != 0 {
            return false;
        }
        let wdate = rd16(b, 24);
        if wdate != 0 {
            let m = (wdate >> 5) & 0x0F;
            let d = wdate & 0x1F;
            if !(1..=12).contains(&m) || d == 0 {
                return false;
            }
        }
        if rd16(b, 22) >> 11 > 23 {
            return false;
        }
        let start = (rd16(b, 20) as u32) << 16 | rd16(b, 26) as u32;
        if let Some(maxc) = max_cluster {
            if start == 1 || start > maxc {
                return false;
            }
        }
        if start == 0 && rd32(b, 28) != 0 && b[0] != 0xE5 {
            return false;
        }
    }
    true
}

fn short_name_string(n: &[u8; 11], nt_flags: u8) -> String {
    let base_lower = nt_flags & 0x08 != 0;
    let ext_lower = nt_flags & 0x10 != 0;
    let conv = |bytes: &[u8], lower: bool| -> String {
        let end = bytes.iter().rposition(|&c| c != b' ').map(|p| p + 1).unwrap_or(0);
        bytes[..end].iter().map(|&c| if lower { oem_char(c).to_ascii_lowercase() } else { oem_char(c) }).collect()
    };
    let base = conv(&n[..8], base_lower);
    let ext = conv(&n[8..], ext_lower);
    if ext.is_empty() {
        base
    } else {
        format!("{base}.{ext}")
    }
}

/// Characters Windows would put first in the short name generated for `long`.
fn first_char_candidates(long: &str) -> Vec<u8> {
    let mut v = Vec::new();
    if let Some(c) = long.chars().find(|&c| c != ' ' && c != '.') {
        if c.is_ascii() {
            let u = c.to_ascii_uppercase() as u8;
            if BAD_SHORT.contains(&u) || u < 0x20 {
                v.push(b'_');
            } else {
                v.push(u);
            }
        } else {
            // Non-ASCII: the OEM conversion of the character, or '_' when it has none.
            for b in 0x80u8..=0xFF {
                let oc = oem_char(b);
                if oc == c || oc.to_uppercase().next() == c.to_uppercase().next() {
                    v.push(b);
                }
            }
        }
    }
    v.push(b'_');
    v
}

fn assemble(lfns: &[&Lfn]) -> String {
    let mut units = Vec::with_capacity(lfns.len() * 13);
    for l in lfns {
        units.extend_from_slice(&l.chars);
    }
    let end = units.iter().position(|&u| u == 0 || u == 0xFFFF).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

/// Whether Windows could have made the 8.3 alias `n` from the long name `long`, ignoring the
/// first byte (lost on deletion). Only clear contradictions fail: without the volume's OEM code
/// page a non-ASCII character may be any high byte or '_' (or an ASCII letter by best fit for
/// Latin letters), and may take two bytes in a double-byte code page.
fn alias_fits(n: &[u8; 11], long: &str) -> bool {
    fn fits(long: &[char], short: &[u8], trunc: bool) -> bool {
        let Some((&b, srest)) = short.split_first() else {
            return long.is_empty() || trunc;
        };
        let Some((&c, lrest)) = long.split_first() else {
            return false;
        };
        if c.is_ascii() {
            let same = b == c.to_ascii_uppercase() as u8 || (b == b'_' && "+,;=[]".contains(c));
            same && fits(lrest, srest, trunc)
        } else if b >= 0x80 || b == b'_' || ((c as u32) < 0x250 && b.is_ascii_alphanumeric()) {
            fits(lrest, srest, trunc) || (b >= 0x81 && !srest.is_empty() && fits(lrest, &srest[1..], trunc))
        } else {
            false
        }
    }
    let stripped: Vec<char> = long.chars().skip_while(|&c| c == ' ' || c == '.').collect();
    let (base, ext) = match stripped.iter().rposition(|&c| c == '.') {
        Some(d) => (&stripped[..d], &stripped[d + 1..]),
        None => (&stripped[..], &stripped[..0]),
    };
    let base: Vec<char> = base.iter().copied().filter(|&c| c != ' ' && c != '.').collect();
    let ext: Vec<char> = ext.iter().copied().filter(|&c| c != ' ').collect();
    if base.is_empty() {
        return false;
    }
    // Extension: blank exactly when the long name has none; up to 3 bytes otherwise.
    let sext: &[u8] = {
        let e = &n[8..11];
        &e[..e.iter().rposition(|&c| c != b' ').map_or(0, |i| i + 1)]
    };
    if ext.is_empty() != sext.is_empty() || !fits(&ext, sext, sext.len() >= 2) {
        return false;
    }
    // Base: the long base (spaces and dots removed), cut short by a "~N" tail when there is one.
    let sbase = &n[..n[..8].iter().rposition(|&c| c != b' ').map_or(0, |i| i + 1)];
    let tail = sbase.iter().rposition(|&c| c == b'~').filter(|&p| p >= 1 && p + 1 < sbase.len() && sbase[p + 1..].iter().all(u8::is_ascii_digit));
    let (core, trunc) = match tail {
        Some(p) => {
            // Windows keeps min(len, 8 - tail) bytes before the tail (one less for a split DBCS character).
            if p + 1 < base.len().min(8 - (sbase.len() - p)) {
                return false;
            }
            (&sbase[1..p], true)
        }
        None => (&sbase[1..], false),
    };
    let rest = &base[1..];
    // The first character may be a double-byte one whose trail byte is core[0].
    let try_core = |c: &[u8]| fits(rest, c, trunc) || (!c.is_empty() && fits(rest, &c[1..], trunc));
    if try_core(core) {
        return true;
    }
    // Windows NT hashed aliases ("XY1A2B~5"): the bytes before the tail end in 4 hex digits.
    trunc && core.len() >= 4 && core[core.len() - 4..].iter().all(u8::is_ascii_hexdigit) && try_core(&core[..core.len() - 4])
}

/// Parse a directory buffer. `offsets[i]` is the absolute source offset of slot i (32 bytes each).
/// `strict` rejects implausible 8.3 entries (they are skipped instead of reported).
pub(crate) fn parse_dir(buf: &[u8], offsets: &[u64], fat32: bool, strict: bool, max_cluster: Option<u32>, tz_ms: i64) -> Parsed {
    let mut p = Parsed::default();
    let mut pending: Vec<Lfn> = Vec::new();
    let nslots = (buf.len() / 32).min(offsets.len());
    for i in 0..nslots {
        let b = &buf[i * 32..i * 32 + 32];
        if b[0] == 0 {
            p.ended = true;
            break;
        }
        if b[11] & 0x3F == 0x0F && b[0] != 0 {
            if lfn_valid(b) {
                pending.push(Lfn { ord: b[0], checksum: b[13], chars: lfn_chars(b) });
            } else {
                pending.clear();
            }
            continue;
        }
        if b[0] == b'.' {
            if p.dot.is_none() && i < 8 {
                p.dot = find_dots(buf, fat32);
            }
            pending.clear();
            continue;
        }
        if b[11] & 0x08 != 0 && b[11] & 0x10 == 0 {
            if b[0] != 0xE5 && p.label.is_none() {
                p.label = Some(super::bpb::label_from_bytes(&b[..11]));
            }
            pending.clear();
            continue;
        }
        if !short_valid(b, strict, max_cluster) {
            pending.clear();
            continue;
        }
        let deleted = b[0] == 0xE5;
        let mut n = [0u8; 11];
        n.copy_from_slice(&b[..11]);
        if n[0] == 0x05 {
            n[0] = 0xE5;
        }
        // Long name: the LFN entries just before this one, closest = sequence 1.
        let mut long: Option<String> = None;
        let mut first_known = !deleted;
        if !pending.is_empty() {
            let mut raw = [0u8; 11];
            raw.copy_from_slice(&b[..11]);
            let target = if deleted { pending.last().map(|l| l.checksum).unwrap_or(0) } else { lfn_checksum(&raw) };
            let mut set: Vec<&Lfn> = Vec::new();
            for (k, l) in pending.iter().rev().enumerate() {
                if l.checksum != target {
                    break;
                }
                if l.ord != 0xE5 {
                    let seq = (l.ord & 0x1F) as usize;
                    if seq != k + 1 {
                        break;
                    }
                }
                set.push(l);
                if l.ord != 0xE5 && l.ord & 0x40 != 0 {
                    break;
                }
            }
            if !set.is_empty() {
                let name = assemble(&set);
                if deleted {
                    // Find the lost first character: the checksum of the 8.3 name must match.
                    for cand in first_char_candidates(&name) {
                        let mut t = n;
                        t[0] = cand;
                        if lfn_checksum(&t) == target {
                            n[0] = cand;
                            first_known = true;
                            break;
                        }
                    }
                    if !first_known
                        && name.chars().find(|&c| c != ' ' && c != '.').is_some_and(|c| !c.is_ascii())
                        && alias_fits(&n, &name)
                    {
                        // A non-ASCII first character in an OEM code page other than 437 (Cyrillic,
                        // Greek, DBCS lead bytes): the checksum fixes the lost byte uniquely, so take
                        // it when it is a high OEM byte (0x05 stands for a stored 0xE5). Half of all
                        // bytes qualify, so the rest of the 8.3 name must also fit the long name.
                        let hit = (0x80u8..=0xFF).filter(|&c| c != 0xE5).chain([0x05]).find(|&cand| {
                            let mut t = n;
                            t[0] = cand;
                            lfn_checksum(&t) == target
                        });
                        if let Some(cand) = hit {
                            n[0] = if cand == 0x05 { 0xE5 } else { cand };
                            first_known = true;
                        }
                    }
                    if first_known && !name.is_empty() {
                        long = Some(name);
                    }
                } else if !name.is_empty() {
                    long = Some(name);
                }
            }
        }
        pending.clear();
        let mut guessed = false;
        if deleted && !first_known {
            n[0] = b'_';
            guessed = true;
        }
        let short = short_name_string(&n, b[12]);
        let hi = rd16(b, 20);
        let start = if fat32 { (hi as u32) << 16 | rd16(b, 26) as u32 } else { rd16(b, 26) as u32 };
        let tenths = b[13] as i64;
        let e = DirEnt {
            name: long.clone().unwrap_or_else(|| short.clone()),
            short_name: short,
            has_long_name: long.is_some(),
            name_guessed: guessed,
            deleted,
            attr: b[11],
            start,
            hi_zero: hi == 0,
            size: rd32(b, 28),
            created: dos_to_ms(rd16(b, 16), rd16(b, 14), tenths * 10, tz_ms),
            modified: dos_to_ms(rd16(b, 24), rd16(b, 22), 0, tz_ms),
            accessed: dos_to_ms(rd16(b, 18), 0, 0, tz_ms),
            offset: offsets[i],
        };
        p.entries.push(e);
    }
    p
}

/// The "." and ".." entries at the start of a directory cluster: the first two 8.3 entries
/// (some writers put long-name entries before them, so those are skipped).
/// Returns ("." cluster, ".." cluster).
pub(crate) fn find_dots(buf: &[u8], fat32: bool) -> Option<(u32, u32)> {
    let mut shorts: Vec<&[u8]> = Vec::with_capacity(2);
    for b in buf.chunks_exact(32).take(8) {
        if b[0] == 0 {
            return None;
        }
        if b[11] & 0x3F == 0x0F {
            if !lfn_valid(b) {
                return None;
            }
            continue;
        }
        shorts.push(b);
        if shorts.len() == 2 {
            break;
        }
    }
    if shorts.len() < 2 {
        return None;
    }
    let (a, d) = (shorts[0], shorts[1]);
    if &a[..11] == DOT && a[11] & 0x10 != 0 && &d[..11] == DOTDOT && d[11] & 0x10 != 0 {
        Some((cluster_of(a, fat32), cluster_of(d, fat32)))
    } else {
        None
    }
}

fn cluster_of(b: &[u8], fat32: bool) -> u32 {
    if fat32 {
        (rd16(b, 20) as u32) << 16 | rd16(b, 26) as u32
    } else {
        rd16(b, 26) as u32
    }
}

/// How much a buffer looks like directory entries: (valid slots, used slots, saw end marker).
/// Every non-zero slot must be a valid LFN or a strict 8.3 entry; otherwise None.
pub(crate) fn dir_score(buf: &[u8], max_cluster: Option<u32>) -> Option<(usize, bool)> {
    let mut used = 0usize;
    let mut shorts = 0usize;
    let mut ended = false;
    for b in buf.chunks_exact(32) {
        if ended {
            if b.iter().any(|&x| x != 0) {
                return None;
            }
            continue;
        }
        if b[0] == 0 {
            ended = true;
            if b.iter().any(|&x| x != 0) {
                return None;
            }
            continue;
        }
        if b[11] & 0x3F == 0x0F {
            if !lfn_valid(b) {
                return None;
            }
        } else if b[0] == b'.' {
            if &b[..11] != DOT && &b[..11] != DOTDOT {
                return None;
            }
            shorts += 1;
        } else {
            if !short_valid(b, true, max_cluster) {
                return None;
            }
            shorts += 1;
        }
        used += 1;
    }
    if shorts == 0 {
        return None;
    }
    Some((used, ended))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn short(name: &[u8; 11], attr: u8, start: u32, size: u32) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..11].copy_from_slice(name);
        b[11] = attr;
        b[20..22].copy_from_slice(&((start >> 16) as u16).to_le_bytes());
        b[26..28].copy_from_slice(&(start as u16).to_le_bytes());
        b[28..32].copy_from_slice(&size.to_le_bytes());
        b[24..26].copy_from_slice(&(((2020 - 1980) << 9 | 5 << 5 | 6) as u16).to_le_bytes());
        b
    }

    fn lfn(ord: u8, csum: u8, part: &[u16]) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = ord;
        b[11] = 0x0F;
        b[13] = csum;
        let pos = [1usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        for (i, p) in pos.iter().enumerate() {
            let u = if i < part.len() {
                part[i]
            } else if i == part.len() {
                0
            } else {
                0xFFFF
            };
            b[*p..*p + 2].copy_from_slice(&u.to_le_bytes());
        }
        b
    }

    #[test]
    fn deleted_lfn_restores_first_char() {
        let n = *b"HOLIDA~1JPG";
        let cs = lfn_checksum(&n);
        let long: Vec<u16> = "holiday photo.jpg".encode_utf16().collect();
        let mut buf = Vec::new();
        buf.extend_from_slice(&lfn(0xE5, cs, &long[13..]));
        buf.extend_from_slice(&lfn(0xE5, cs, &long[..13]));
        let mut s = short(&n, 0x20, 5, 1000);
        s[0] = 0xE5;
        buf.extend_from_slice(&s);
        // A deleted entry without long name.
        let mut s2 = short(b"README  TXT", 0x20, 9, 10);
        s2[0] = 0xE5;
        buf.extend_from_slice(&s2);
        let offs: Vec<u64> = (0..4).map(|i| i * 32).collect();
        let p = parse_dir(&buf, &offs, true, false, None, 0);
        assert_eq!(p.entries.len(), 2);
        assert_eq!(p.entries[0].name, "holiday photo.jpg");
        assert_eq!(p.entries[0].short_name, "HOLIDA~1.JPG");
        assert!(!p.entries[0].name_guessed && p.entries[0].deleted);
        assert_eq!(p.entries[1].name, "_EADME.TXT");
        assert!(p.entries[1].name_guessed);
        assert!(p.entries[0].modified.is_some());
    }

    #[test]
    fn deleted_lfn_kept_for_non_cp437_first_byte() {
        // A deleted entry: one LFN slot with checksum `cs`, then the 8.3 alias `n` with 0xE5 first.
        let parse = |n: &[u8; 11], cs: u8, long: &str| {
            let long: Vec<u16> = long.encode_utf16().collect();
            let mut buf = Vec::new();
            buf.extend_from_slice(&lfn(0xE5, cs, &long));
            let mut s = short(n, 0x20, 7, 500);
            s[0] = 0xE5;
            buf.extend_from_slice(&s);
            let offs: Vec<u64> = (0..2).map(|i| i * 32).collect();
            let p = parse_dir(&buf, &offs, true, false, None, 0);
            assert_eq!(p.entries.len(), 1);
            p.entries.into_iter().next().unwrap()
        };
        let kept = |n: &[u8; 11], long: &str| {
            let e = parse(n, lfn_checksum(n), long);
            assert_eq!(e.name, long);
            assert!(e.has_long_name && !e.name_guessed);
        };
        // CP866 "ДОКУМЕ~1.DOC": CP437 has no 'Д' (0x84), so only the checksum can restore it.
        kept(b"\x84\x8E\x8A\x93\x8C\x85~1DOC", "\u{414}\u{43e}\u{43a}\u{443}\u{43c}\u{435}\u{43d}\u{442}.docx");
        // CP866 "ЁЛКА20~1.TXT": spaces dropped, ASCII digits kept.
        kept(b"\xF0\x8B\x8A\x8020~1TXT", "\u{401}\u{43b}\u{43a}\u{430} 2024.txt");
        // Shift-JIS "テスト.TXT": two bytes per character, no tail.
        kept(b"\x83\x65\x83\x58\x83\x67  TXT", "\u{30c6}\u{30b9}\u{30c8}.txt");
        // A stale LFN set beside an unrelated deleted alias whose lost first byte happens to give
        // the same checksum (0x90 here): the rest of the alias doesn't fit, so the name is dropped.
        for alias in [b"\x90ACATI~1JPG", b"\x90ACATI~1DOC", b"\x84\x8E\x8A\x93\x8C\x85~1JPG"] {
            let e = parse(alias, lfn_checksum(alias), "Документ.docx");
            assert!(!e.has_long_name && e.name_guessed, "{alias:?}");
        }
        // The alias fits, but the checksum only works with an ASCII first byte, which a non-ASCII
        // first character never produces in an OEM code page: dropped as well.
        let e = parse(b"\x84\x8E\x8A\x93\x8C\x85~1DOC", lfn_checksum(b"A\x8E\x8A\x93\x8C\x85~1DOC"), "Документ.docx");
        assert!(!e.has_long_name && e.name_guessed);
        // An ASCII first letter that matches no candidate still drops the stale long name.
        let e = parse(b"QOLIDA~1JPG", lfn_checksum(b"QOLIDA~1JPG"), "holiday.jpg");
        assert!(!e.has_long_name && e.name_guessed);
    }

    #[test]
    fn garbage_never_panics() {
        let mut x: u32 = 12345;
        for _ in 0..200 {
            let buf: Vec<u8> = (0..4096)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect();
            let offs: Vec<u64> = (0..128).collect();
            let _ = parse_dir(&buf, &offs, true, false, Some(1000), 0);
            let _ = parse_dir(&buf, &offs[..3], false, true, None, 0);
            let _ = dir_score(&buf, Some(10));
        }
    }
}
