//! Tolerant MFT record parser. Works on records that are deleted, torn (a sector of the record was
//! written at another time), from a formatted volume or found loose on a disk: every offset and
//! length is checked against the record, and whatever is consistent is returned.

use super::runs::{decode_runs, Run};

pub const ATTR_STD_INFO: u32 = 0x10;
pub const ATTR_LIST: u32 = 0x20;
pub const ATTR_FILE_NAME: u32 = 0x30;
pub const ATTR_VOLUME_NAME: u32 = 0x60;
pub const ATTR_DATA: u32 = 0x80;
pub const ATTR_INDEX_ROOT: u32 = 0x90;
pub const ATTR_INDEX_ALLOC: u32 = 0xA0;

pub const REC_IN_USE: u16 = 0x0001;
pub const REC_DIRECTORY: u16 = 0x0002;

/// Attribute flags.
pub const AF_COMPRESSED: u16 = 0x0001;
pub const AF_ENCRYPTED: u16 = 0x4000;
pub const AF_SPARSE: u16 = 0x8000;

/// $STANDARD_INFORMATION file attributes.
pub const FA_SPARSE: u32 = 0x200;
#[allow(dead_code)]
pub const FA_COMPRESSED: u32 = 0x800;
pub const FA_ENCRYPTED: u32 = 0x4000;

/// The update-sequence stride: always 512 bytes, whatever the sector size.
const STRIDE: usize = 512;

#[inline]
pub fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
#[inline]
pub fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
#[inline]
pub fn le64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// Record number (low 48 bits) of a file reference.
#[inline]
pub fn ref_rec(r: u64) -> u64 {
    r & 0x0000_FFFF_FFFF_FFFF
}
/// Sequence number (high 16 bits) of a file reference.
#[inline]
pub fn ref_seq(r: u64) -> u16 {
    (r >> 48) as u16
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fixup {
    /// Bytes from the start of the record that are consistent (all of it unless torn).
    pub valid_len: usize,
    pub torn: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub usa_ofs: u16,
    pub usa_count: u16,
    pub seq: u16,
    pub links: u16,
    pub first_attr: u16,
    pub flags: u16,
    pub used: u32,
    pub alloc: u32,
    /// Base record reference; 0 for base records.
    pub base: u64,
    /// The record's own number (Windows XP and later write it into the header).
    pub number: Option<u32>,
}

impl Header {
    pub fn in_use(&self) -> bool {
        self.flags & REC_IN_USE != 0
    }
    pub fn is_dir(&self) -> bool {
        self.flags & REC_DIRECTORY != 0
    }
}

/// Read the header of something that looks like a FILE record. Checks the magic and that the
/// update-sequence array and first attribute fit in `len` bytes.
pub fn parse_header(b: &[u8]) -> Option<Header> {
    if b.len() < 0x30 || &b[0..4] != b"FILE" {
        return None;
    }
    let usa_ofs = le16(b, 4);
    let usa_count = le16(b, 6);
    let first_attr = le16(b, 0x14);
    if usa_ofs < 0x28 || usa_ofs % 2 != 0 || usa_count < 2 {
        return None;
    }
    if usa_ofs as usize + 2 * usa_count as usize > b.len() || (usa_count as usize - 1) * STRIDE > b.len() {
        return None;
    }
    if (first_attr as usize) < usa_ofs as usize + 2 * usa_count as usize || first_attr as usize + 8 > b.len() || first_attr % 8 != 0 {
        return None;
    }
    Some(Header {
        usa_ofs,
        usa_count,
        seq: le16(b, 0x10),
        links: le16(b, 0x12),
        first_attr,
        flags: le16(b, 0x16),
        used: le32(b, 0x18),
        alloc: le32(b, 0x1C),
        base: le64(b, 0x20),
        number: if usa_ofs >= 0x30 { Some(le32(b, 0x2C)) } else { None },
    })
}

/// Check and undo the update-sequence fixups in place. A stride whose last two bytes don't hold
/// the update-sequence number was not written with the rest (torn write): everything from that
/// stride on is excluded from `valid_len`.
pub fn apply_fixups(b: &mut [u8], h: &Header) -> Fixup {
    let usn = [b[h.usa_ofs as usize], b[h.usa_ofs as usize + 1]];
    let strides = h.usa_count as usize - 1;
    let mut valid = (strides * STRIDE).min(b.len());
    let mut torn = false;
    for i in 1..=strides {
        let end = i * STRIDE - 2;
        if end + 2 > b.len() {
            break;
        }
        if b[end] != usn[0] || b[end + 1] != usn[1] {
            valid = (i - 1) * STRIDE;
            torn = true;
            break;
        }
        let u = h.usa_ofs as usize + 2 * i;
        b[end] = b[u];
        b[end + 1] = b[u + 1];
    }
    Fixup { valid_len: valid, torn }
}

/// One attribute inside a record.
#[derive(Clone, Copy, Debug)]
pub struct AttrView<'a> {
    pub ty: u32,
    pub nonres: bool,
    /// UTF-16LE name bytes.
    pub name: &'a [u8],
    pub flags: u16,
    #[allow(dead_code)]
    pub id: u16,
    /// The whole attribute (header + content).
    pub raw: &'a [u8],
}

impl<'a> AttrView<'a> {
    /// Resident value bytes.
    pub fn value(&self) -> Option<&'a [u8]> {
        if self.nonres || self.raw.len() < 0x18 {
            return None;
        }
        let len = le32(self.raw, 0x10) as usize;
        let off = le16(self.raw, 0x14) as usize;
        if off < 0x18 || off.checked_add(len)? > self.raw.len() {
            return None;
        }
        Some(&self.raw[off..off + len])
    }
    pub fn name_string(&self) -> String {
        utf16(self.name)
    }
}

pub fn utf16(b: &[u8]) -> String {
    let units: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units)
}

/// Iterate the attributes in `b[first..limit]`; stops at the end marker or the first damaged one.
pub struct AttrIter<'a> {
    b: &'a [u8],
    pos: usize,
    limit: usize,
    /// Set when iteration stopped at a damaged attribute rather than at the end marker.
    pub damaged: bool,
}

pub fn attrs(b: &[u8], first: usize, limit: usize) -> AttrIter<'_> {
    AttrIter { b, pos: first, limit: limit.min(b.len()), damaged: false }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = AttrView<'a>;
    fn next(&mut self) -> Option<AttrView<'a>> {
        let b = self.b;
        let p = self.pos;
        if p + 4 > self.limit {
            // Ran into the end of the consistent part without an end marker.
            self.damaged = true;
            return None;
        }
        let ty = le32(b, p);
        if ty == 0xFFFF_FFFF {
            return None;
        }
        if p + 0x18 > self.limit {
            self.damaged = true;
            return None;
        }
        let len = le32(b, p + 4) as usize;
        let nonres = b[p + 8] != 0;
        let min = if nonres { 0x40 } else { 0x18 };
        if len < min || len % 8 != 0 || p + len > self.limit || ty == 0 || ty > 0x1000 || ty % 0x10 != 0 {
            self.damaged = true;
            return None;
        }
        let raw = &b[p..p + len];
        let name_len = raw[9] as usize * 2;
        let name_off = le16(raw, 0x0A) as usize;
        let name = if name_len == 0 {
            &raw[0..0]
        } else if name_off >= 0x10 && name_off + name_len <= len {
            &raw[name_off..name_off + name_len]
        } else {
            self.damaged = true;
            return None;
        };
        self.pos = p + len;
        Some(AttrView { ty, nonres, name, flags: le16(raw, 0x0C), id: le16(raw, 0x0E), raw })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StdInfo {
    pub created: u64,
    pub modified: u64,
    pub mft_changed: u64,
    pub accessed: u64,
    pub attrs: u32,
}

pub fn parse_std_info(v: &[u8]) -> Option<StdInfo> {
    if v.len() < 0x24 {
        return None;
    }
    Some(StdInfo { created: le64(v, 0), modified: le64(v, 8), mft_changed: le64(v, 0x10), accessed: le64(v, 0x18), attrs: le32(v, 0x20) })
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileName {
    pub parent: u64,
    pub created: u64,
    pub modified: u64,
    pub accessed: u64,
    pub real_size: u64,
    pub fn_flags: u32,
    /// 0 POSIX, 1 Win32, 2 DOS (8.3), 3 Win32 & DOS.
    pub namespace: u8,
    pub name: String,
}

impl FileName {
    /// Higher is better: long names over 8.3 aliases.
    pub fn rank(&self) -> u8 {
        match self.namespace {
            1 | 3 => 3,
            0 => 2,
            _ => 1,
        }
    }
}

pub fn parse_file_name(v: &[u8]) -> Option<FileName> {
    if v.len() < 0x42 {
        return None;
    }
    let n = v[0x40] as usize;
    if n == 0 || 0x42 + 2 * n > v.len() {
        return None;
    }
    Some(FileName {
        parent: le64(v, 0),
        created: le64(v, 8),
        modified: le64(v, 0x10),
        accessed: le64(v, 0x20),
        real_size: le64(v, 0x30),
        fn_flags: le32(v, 0x38),
        namespace: v[0x41],
        name: utf16(&v[0x42..0x42 + 2 * n]),
    })
}

/// One instance of a $DATA attribute (a non-resident stream can be split over several, each
/// covering a VCN range, in extension records).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DataPiece {
    /// Stream name ("" = the unnamed main stream).
    pub name: String,
    pub start_vcn: u64,
    pub last_vcn: u64,
    pub resident: Option<Vec<u8>>,
    pub runs: Vec<Run>,
    pub runs_ok: bool,
    pub alloc: u64,
    pub real: u64,
    pub init: u64,
    /// Attribute flags (AF_*).
    pub flags: u16,
    /// log2 of the compression unit in clusters (4 = 16 clusters).
    pub comp_unit: u8,
}

/// Parse a $DATA / $INDEX_ALLOCATION / $ATTRIBUTE_LIST attribute's location.
pub fn parse_data(a: &AttrView) -> Option<DataPiece> {
    let name = a.name_string();
    if !a.nonres {
        let v = a.value()?;
        return Some(DataPiece {
            name,
            resident: Some(v.to_vec()),
            alloc: v.len() as u64,
            real: v.len() as u64,
            init: v.len() as u64,
            flags: a.flags,
            runs_ok: true,
            ..Default::default()
        });
    }
    let r = a.raw;
    let start_vcn = le64(r, 0x10);
    let last_vcn = le64(r, 0x18);
    let runs_off = le16(r, 0x20) as usize;
    let comp_unit = le16(r, 0x22).min(16) as u8;
    if runs_off < 0x40 || runs_off > r.len() {
        return None;
    }
    let (runs, runs_ok) = decode_runs(&r[runs_off..]);
    Some(DataPiece {
        name,
        start_vcn,
        last_vcn,
        resident: None,
        runs,
        runs_ok,
        alloc: le64(r, 0x28),
        real: le64(r, 0x30),
        init: le64(r, 0x38),
        flags: a.flags,
        comp_unit,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttrListSrc {
    Resident(Vec<u8>),
    NonResident { runs: Vec<Run>, size: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttrListEntry {
    pub ty: u32,
    pub name: String,
    pub start_vcn: u64,
    /// File reference of the record holding the attribute.
    pub rec: u64,
    pub id: u16,
}

/// Parse $ATTRIBUTE_LIST content (stops at the first damaged entry).
pub fn parse_attr_list(b: &[u8]) -> Vec<AttrListEntry> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + 0x1A <= b.len() {
        let ty = le32(b, p);
        let len = le16(b, p + 4) as usize;
        if ty == 0 || ty == 0xFFFF_FFFF || len < 0x1A || p + len > b.len() {
            break;
        }
        let nlen = b[p + 6] as usize * 2;
        let noff = b[p + 7] as usize;
        let name = if nlen > 0 && noff >= 0x1A && noff + nlen <= len { utf16(&b[p + noff..p + noff + nlen]) } else { String::new() };
        out.push(AttrListEntry { ty, name, start_vcn: le64(b, p + 8), rec: le64(b, p + 0x10), id: le16(b, p + 0x18) });
        p += len;
    }
    out
}

/// Everything useful from one record.
#[derive(Clone, Debug, Default)]
pub struct Rec {
    pub hdr: Header,
    /// Fixups all matched and the attribute list ended cleanly.
    pub complete: bool,
    pub si: Option<StdInfo>,
    /// Best name (Win32 over POSIX over DOS).
    pub name: Option<FileName>,
    pub data: Vec<DataPiece>,
    pub attr_list: Option<AttrListSrc>,
    /// $I30 index allocation runs (directories).
    pub index_alloc: Vec<Run>,
    pub has_index_root: bool,
    pub volume_name: Option<String>,
}

impl Rec {
    pub fn in_use(&self) -> bool {
        self.hdr.in_use()
    }
    pub fn is_dir(&self) -> bool {
        self.hdr.is_dir()
    }
}

/// Validate the header and apply fixups in place; returns (header, fixup) or `None` when the
/// buffer isn't a usable FILE record.
pub fn prepare(b: &mut [u8]) -> Option<(Header, Fixup)> {
    let h = parse_header(b)?;
    let fx = apply_fixups(b, &h);
    if fx.valid_len < h.first_attr as usize + 8 {
        return None;
    }
    Some((h, fx))
}

/// Byte limit for attribute parsing: bytes in use, clipped to the consistent part.
pub fn attr_limit(h: &Header, fx: &Fixup, len: usize) -> usize {
    let used = h.used as usize;
    let lim = if used >= h.first_attr as usize + 4 && used <= len { used } else { len };
    lim.min(fx.valid_len)
}

/// Parse a record whose fixups were already applied by [`prepare`].
pub fn parse_prepared(b: &[u8], h: Header, fx: Fixup) -> Rec {
    let mut r = Rec { hdr: h, ..Default::default() };
    let limit = attr_limit(&h, &fx, b.len());
    let mut it = attrs(b, h.first_attr as usize, limit);
    for a in it.by_ref() {
        match a.ty {
            ATTR_STD_INFO => {
                if r.si.is_none() {
                    r.si = a.value().and_then(parse_std_info);
                }
            }
            ATTR_LIST => {
                if a.nonres {
                    if let Some(p) = parse_data(&a) {
                        r.attr_list = Some(AttrListSrc::NonResident { runs: p.runs, size: p.real });
                    }
                } else if let Some(v) = a.value() {
                    r.attr_list = Some(AttrListSrc::Resident(v.to_vec()));
                }
            }
            ATTR_FILE_NAME => {
                if let Some(f) = a.value().and_then(parse_file_name) {
                    if r.name.as_ref().map_or(true, |o| f.rank() > o.rank()) {
                        r.name = Some(f);
                    }
                }
            }
            ATTR_VOLUME_NAME => {
                if let Some(v) = a.value() {
                    r.volume_name = Some(utf16(v));
                }
            }
            ATTR_DATA => {
                if let Some(p) = parse_data(&a) {
                    r.data.push(p);
                }
            }
            ATTR_INDEX_ROOT => r.has_index_root = true,
            ATTR_INDEX_ALLOC => {
                if a.nonres {
                    if let Some(p) = parse_data(&a) {
                        r.index_alloc.extend(p.runs);
                    }
                }
            }
            _ => {}
        }
    }
    r.complete = !fx.torn && !it.damaged && r.data.iter().all(|d| d.runs_ok);
    r
}

/// Validate, fix up and parse a record in place.
pub fn parse_record(b: &mut [u8]) -> Option<Rec> {
    let (h, fx) = prepare(b)?;
    Some(parse_prepared(b, h, fx))
}

/// Does any $FILE_NAME of this (prepared) record start with `prefix` (ASCII, case-insensitive)?
/// Allocation-free, for skipping records quickly.
pub fn name_starts_with(b: &[u8], h: &Header, fx: &Fixup, prefix: &[u8]) -> bool {
    let limit = attr_limit(h, fx, b.len());
    for a in attrs(b, h.first_attr as usize, limit) {
        if a.ty > ATTR_FILE_NAME {
            break;
        }
        if a.ty != ATTR_FILE_NAME {
            continue;
        }
        let Some(v) = a.value() else { continue };
        if v.len() < 0x42 || (v[0x40] as usize) < prefix.len() || 0x42 + 2 * prefix.len() > v.len() {
            continue;
        }
        if prefix.iter().enumerate().all(|(i, &c)| v[0x43 + 2 * i] == 0 && v[0x42 + 2 * i].eq_ignore_ascii_case(&c)) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------------- building
// (record writer used by unit tests and the synthetic image builder)

#[cfg(test)]
pub mod build {
    use super::*;
    use crate::fs::ntfs::runs::encode_runs;

    pub fn attr_resident(ty: u32, name: &str, value: &[u8], flags: u16) -> Vec<u8> {
        let name16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let name_off = 0x18usize;
        let val_off = (name_off + name16.len() + 7) & !7;
        let len = (val_off + value.len() + 7) & !7;
        let mut a = vec![0u8; len];
        a[0..4].copy_from_slice(&ty.to_le_bytes());
        a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        a[8] = 0;
        a[9] = (name16.len() / 2) as u8;
        a[0x0A..0x0C].copy_from_slice(&(name_off as u16).to_le_bytes());
        a[0x0C..0x0E].copy_from_slice(&flags.to_le_bytes());
        a[0x10..0x14].copy_from_slice(&(value.len() as u32).to_le_bytes());
        a[0x14..0x16].copy_from_slice(&(val_off as u16).to_le_bytes());
        a[name_off..name_off + name16.len()].copy_from_slice(&name16);
        a[val_off..val_off + value.len()].copy_from_slice(value);
        a
    }

    #[allow(clippy::too_many_arguments)]
    pub fn attr_nonresident(ty: u32, name: &str, runs: &[Run], start_vcn: u64, alloc: u64, real: u64, init: u64, flags: u16, comp_unit: u16) -> Vec<u8> {
        let name16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let hdr = if comp_unit != 0 { 0x48 } else { 0x40 };
        let name_off = hdr;
        let runs_off = (name_off + name16.len() + 7) & !7;
        let rb = encode_runs(runs);
        let len = (runs_off + rb.len() + 7) & !7;
        let clusters: u64 = runs.iter().map(|r| r.len).sum();
        let mut a = vec![0u8; len];
        a[0..4].copy_from_slice(&ty.to_le_bytes());
        a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        a[8] = 1;
        a[9] = (name16.len() / 2) as u8;
        a[0x0A..0x0C].copy_from_slice(&(name_off as u16).to_le_bytes());
        a[0x0C..0x0E].copy_from_slice(&flags.to_le_bytes());
        a[0x10..0x18].copy_from_slice(&start_vcn.to_le_bytes());
        a[0x18..0x20].copy_from_slice(&(start_vcn + clusters).saturating_sub(1).to_le_bytes());
        a[0x20..0x22].copy_from_slice(&(runs_off as u16).to_le_bytes());
        a[0x22..0x24].copy_from_slice(&comp_unit.to_le_bytes());
        a[0x28..0x30].copy_from_slice(&alloc.to_le_bytes());
        a[0x30..0x38].copy_from_slice(&real.to_le_bytes());
        a[0x38..0x40].copy_from_slice(&init.to_le_bytes());
        a[name_off..name_off + name16.len()].copy_from_slice(&name16);
        a[runs_off..runs_off + rb.len()].copy_from_slice(&rb);
        a
    }

    pub fn std_info(created: u64, modified: u64, accessed: u64, fattrs: u32) -> Vec<u8> {
        let mut v = vec![0u8; 0x48];
        v[0..8].copy_from_slice(&created.to_le_bytes());
        v[8..16].copy_from_slice(&modified.to_le_bytes());
        v[16..24].copy_from_slice(&modified.to_le_bytes());
        v[24..32].copy_from_slice(&accessed.to_le_bytes());
        v[0x20..0x24].copy_from_slice(&fattrs.to_le_bytes());
        attr_resident(ATTR_STD_INFO, "", &v, 0)
    }

    pub fn file_name(parent: u64, name: &str, namespace: u8, size: u64, dir: bool) -> Vec<u8> {
        let n16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut v = vec![0u8; 0x42 + n16.len()];
        v[0..8].copy_from_slice(&parent.to_le_bytes());
        v[0x30..0x38].copy_from_slice(&size.to_le_bytes());
        v[0x38..0x3C].copy_from_slice(&(if dir { 0x1000_0000u32 } else { 0x20 }).to_le_bytes());
        v[0x40] = (n16.len() / 2) as u8;
        v[0x41] = namespace;
        v[0x42..].copy_from_slice(&n16);
        attr_resident(ATTR_FILE_NAME, "", &v, 0)
    }

    pub fn attr_list(entries: &[(u32, &str, u64, u64)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, &(ty, name, vcn, rec)) in entries.iter().enumerate() {
            let n16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            let len = (0x1A + n16.len() + 7) & !7;
            let mut e = vec![0u8; len];
            e[0..4].copy_from_slice(&ty.to_le_bytes());
            e[4..6].copy_from_slice(&(len as u16).to_le_bytes());
            e[6] = (n16.len() / 2) as u8;
            e[7] = 0x1A;
            e[8..16].copy_from_slice(&vcn.to_le_bytes());
            e[16..24].copy_from_slice(&rec.to_le_bytes());
            e[24..26].copy_from_slice(&(i as u16).to_le_bytes());
            e[0x1A..0x1A + n16.len()].copy_from_slice(&n16);
            out.extend_from_slice(&e);
        }
        attr_resident(ATTR_LIST, "", &out, 0)
    }

    pub fn mk_ref(rec: u64, seq: u16) -> u64 {
        rec | ((seq as u64) << 48)
    }

    /// A complete record with fixups applied (as it would be on disk).
    pub fn record(size: usize, number: u32, seq: u16, flags: u16, base: u64, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![0u8; size];
        b[0..4].copy_from_slice(b"FILE");
        let usa_ofs = 0x30u16;
        let usa_count = (size / 512 + 1) as u16;
        b[4..6].copy_from_slice(&usa_ofs.to_le_bytes());
        b[6..8].copy_from_slice(&usa_count.to_le_bytes());
        b[0x10..0x12].copy_from_slice(&seq.to_le_bytes());
        b[0x12..0x14].copy_from_slice(&1u16.to_le_bytes());
        let first = ((usa_ofs as usize + 2 * usa_count as usize) + 7) & !7;
        b[0x14..0x16].copy_from_slice(&(first as u16).to_le_bytes());
        b[0x16..0x18].copy_from_slice(&flags.to_le_bytes());
        b[0x1C..0x20].copy_from_slice(&(size as u32).to_le_bytes());
        b[0x20..0x28].copy_from_slice(&base.to_le_bytes());
        b[0x2C..0x30].copy_from_slice(&number.to_le_bytes());
        let mut p = first;
        for a in attrs {
            assert!(p + a.len() + 8 <= size, "record overflow");
            b[p..p + a.len()].copy_from_slice(a);
            p += a.len();
        }
        b[p..p + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        p += 8;
        b[0x18..0x1C].copy_from_slice(&(p as u32).to_le_bytes());
        // Update sequence: USN 0x0101 (any), originals saved in the array.
        let usn = [0x01u8, 0x01];
        b[usa_ofs as usize..usa_ofs as usize + 2].copy_from_slice(&usn);
        for i in 1..usa_count as usize {
            let end = i * 512 - 2;
            let u = usa_ofs as usize + 2 * i;
            b[u] = b[end];
            b[u + 1] = b[end + 1];
            b[end] = usn[0];
            b[end + 1] = usn[1];
        }
        b
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;

    #[test]
    fn fixups_restore_and_detect_torn_records() {
        let big = vec![0xABu8; 600];
        let attrs = vec![std_info(1, 2, 3, 0), attr_resident(ATTR_DATA, "", &big, 0)];
        let rec = record(1024, 40, 3, REC_IN_USE, 0, &attrs);
        // On disk the stride ends hold the USN, not the data.
        assert_eq!(&rec[510..512], &[1, 1]);
        let mut ok = rec.clone();
        let r = parse_record(&mut ok).unwrap();
        assert!(r.complete);
        assert_eq!(r.data[0].resident.as_deref(), Some(&big[..]));
        assert_eq!(r.hdr.number, Some(40));
        assert_eq!(r.hdr.seq, 3);

        // Tear the second stride: data spilling into it must not be trusted.
        let mut torn = rec.clone();
        torn[1022] = 0x55;
        let h = parse_header(&torn).unwrap();
        let fx = apply_fixups(&mut torn, &h);
        assert_eq!(fx, Fixup { valid_len: 512, torn: true });
        let mut torn2 = rec.clone();
        torn2[1022] = 0x55;
        let r = parse_record(&mut torn2).unwrap();
        assert!(!r.complete);
        assert!(r.si.is_some(), "attributes before the torn stride are kept");
        assert!(r.data.is_empty(), "the attribute crossing into the torn stride is dropped");
    }

    #[test]
    fn parses_names_preferring_long_ones() {
        let attrs = vec![
            std_info(130_000_000_000_000_000, 130_000_000_100_000_000, 0, FA_COMPRESSED),
            file_name(mk_ref(5, 5), "LONGFI~1.TXT", 2, 10, false),
            file_name(mk_ref(5, 5), "Long file name.txt", 1, 10, false),
            attr_resident(ATTR_DATA, "", b"0123456789", 0),
            attr_resident(ATTR_DATA, "Zone.Identifier", b"[ZoneTransfer]", 0),
        ];
        let mut rec = record(1024, 77, 1, 0, 0, &attrs);
        let r = parse_record(&mut rec).unwrap();
        assert!(!r.in_use());
        let n = r.name.unwrap();
        assert_eq!(n.name, "Long file name.txt");
        assert_eq!(ref_rec(n.parent), 5);
        assert_eq!(ref_seq(n.parent), 5);
        assert_eq!(r.si.unwrap().attrs, FA_COMPRESSED);
        assert_eq!(r.data.len(), 2);
        assert_eq!(r.data[1].name, "Zone.Identifier");
    }

    #[test]
    fn parses_nonresident_data_and_attr_list() {
        let runs = vec![Run { len: 4, lcn: Some(100) }, Run { len: 2, lcn: None }, Run { len: 3, lcn: Some(50) }];
        let attrs = vec![
            std_info(0, 0, 0, 0),
            attr_list(&[(ATTR_DATA, "", 0, mk_ref(30, 1)), (ATTR_DATA, "", 9, mk_ref(31, 2))]),
            file_name(mk_ref(5, 5), "a.bin", 1, 0, false),
            attr_nonresident(ATTR_DATA, "", &runs, 0, 9 * 4096, 9 * 4096 - 100, 9 * 4096 - 100, 0, 0),
        ];
        let mut rec = record(1024, 30, 1, REC_IN_USE, 0, &attrs);
        let r = parse_record(&mut rec).unwrap();
        let d = &r.data[0];
        assert_eq!(d.runs, runs);
        assert_eq!(d.real, 9 * 4096 - 100);
        assert_eq!(d.last_vcn, 8);
        let Some(AttrListSrc::Resident(l)) = &r.attr_list else { panic!() };
        let e = parse_attr_list(l);
        assert_eq!(e.len(), 2);
        assert_eq!(e[1].start_vcn, 9);
        assert_eq!(ref_rec(e[1].rec), 31);
        assert!(name_starts_with(&rec, &r.hdr, &Fixup { valid_len: 1024, torn: false }, b"A."));
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let base = record(
            1024,
            1,
            1,
            REC_IN_USE,
            0,
            &[std_info(1, 1, 1, 0), file_name(mk_ref(5, 5), "x.txt", 1, 3, false), attr_resident(ATTR_DATA, "", b"abc", 0)],
        );
        for i in 0..30_000 {
            let mut b = if i % 2 == 0 {
                // Mutate a valid record.
                let mut b = base.clone();
                for _ in 0..(next() % 12) {
                    let p = (next() % 1024) as usize;
                    b[p] = next() as u8;
                }
                b
            } else {
                let mut b: Vec<u8> = (0..1024).map(|_| next() as u8).collect();
                b[0..4].copy_from_slice(b"FILE");
                b[4] = 0x30;
                b[5] = 0;
                b[6] = 3;
                b[7] = 0;
                b
            };
            let len = [1024usize, 512, 100, 4096][(next() % 4) as usize].min(b.len());
            b.truncate(len);
            if let Some(r) = parse_record(&mut b) {
                if let Some(AttrListSrc::Resident(l)) = &r.attr_list {
                    let _ = parse_attr_list(l);
                }
            }
        }
    }
}
