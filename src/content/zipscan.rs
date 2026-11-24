//! ZIP access for damaged and partial archives: open with the `zip` crate when the central
//! directory is there, else walk local file headers (handles data descriptors and zip64 extras).

use super::util::{find_from, le16, le32, le64};
use flate2::{Decompress, FlushDecompress, Status};
use std::io::{Cursor, Read};

#[derive(Clone, Debug, Default)]
pub struct LocalEntry {
    pub name: String,
    pub header_at: usize,
    pub data_at: usize,
    pub method: u16,
    #[allow(dead_code)]
    pub flags: u16,
    pub crc: u32,
    pub csize: u64,
    pub usize: u64,
    /// End of the compressed data.
    pub data_end: usize,
    /// Bytes of the data descriptor after the data (0 when none).
    pub desc_len: usize,
    /// The data runs past the end of the bytes we have (or its stream never ends).
    pub truncated: bool,
    /// CRC (and inflate) checked out. Unverifiable methods count as ok.
    pub ok: bool,
}

pub const LOCAL_SIG: &[u8] = b"PK\x03\x04";

/// Inflate raw deflate data. Returns (consumed input, output length, CRC-32, stream ended).
/// Output beyond `max_out` is counted but not kept; `keep` collects up to `max_keep` bytes.
pub fn inflate(src: &[u8], max_out: u64, mut keep: Option<(&mut Vec<u8>, usize)>) -> (usize, u64, u32, bool) {
    let mut z = Decompress::new(false);
    let mut out = vec![0u8; 64 * 1024];
    let mut crc = crc32fast::Hasher::new();
    let mut total_out = 0u64;
    loop {
        let before_in = z.total_in() as usize;
        let before_out = z.total_out();
        let st = z.decompress(&src[before_in.min(src.len())..], &mut out, FlushDecompress::None);
        let produced = (z.total_out() - before_out) as usize;
        crc.update(&out[..produced]);
        if let Some((buf, max)) = keep.as_mut() {
            let room = max.saturating_sub(buf.len());
            buf.extend_from_slice(&out[..produced.min(room)]);
        }
        total_out += produced as u64;
        match st {
            Ok(Status::StreamEnd) => return (z.total_in() as usize, total_out, crc.finalize(), true),
            Ok(_) => {
                if produced == 0 && z.total_in() as usize == before_in {
                    return (z.total_in() as usize, total_out, crc.finalize(), false);
                }
            }
            Err(_) => return (z.total_in() as usize, total_out, crc.finalize(), false),
        }
        if total_out > max_out {
            return (z.total_in() as usize, total_out, crc.finalize(), false);
        }
    }
}

/// Walk local headers from the start. `verify`: CRC-check each entry (total inflated bytes capped
/// at `budget`; entries past the budget are assumed ok).
pub fn scan_local(d: &[u8], verify: bool, mut budget: u64, max_entries: usize) -> Vec<LocalEntry> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while out.len() < max_entries {
        let Some(h) = find_from(d, LOCAL_SIG, pos) else { break };
        let Some(mut e) = parse_local(d, h) else {
            pos = h + 4;
            continue;
        };
        if !e.truncated && verify && e.ok {
            if budget > 0 {
                let data = &d[e.data_at..e.data_end];
                let (crc, n) = match e.method {
                    0 => (crc32fast::hash(data), data.len() as u64),
                    8 => {
                        let (_, n, crc, ended) = inflate(data, budget, None);
                        if !ended {
                            e.ok = false;
                        }
                        (crc, n)
                    }
                    _ => (e.crc, 0),
                };
                budget = budget.saturating_sub(n);
                if crc != e.crc || (e.method == 8 && n != e.usize && e.usize != 0) {
                    e.ok = false;
                }
            }
        }
        let next = if e.truncated { d.len() } else { e.data_end + e.desc_len };
        out.push(e);
        pos = next.max(h + 4);
    }
    out
}

/// Parse one local header at `h`. None when it's not a plausible header.
pub fn parse_local(d: &[u8], h: usize) -> Option<LocalEntry> {
    if d.get(h..h + 4)? != LOCAL_SIG {
        return None;
    }
    let flags = le16(d, h + 6)?;
    let method = le16(d, h + 8)?;
    let mut crc = le32(d, h + 14)?;
    let mut csize = le32(d, h + 18)? as u64;
    let mut usize_ = le32(d, h + 22)? as u64;
    let nlen = le16(d, h + 26)? as usize;
    let xlen = le16(d, h + 28)? as usize;
    if nlen == 0 || nlen > 4096 || method > 99 {
        return None;
    }
    let name_at = h + 30;
    let mut e = LocalEntry { header_at: h, method, flags, ..Default::default() };
    let Some(name) = d.get(name_at..name_at + nlen) else {
        e.truncated = true;
        e.data_at = d.len();
        e.data_end = d.len();
        return Some(e);
    };
    e.name = if flags & 0x800 != 0 { String::from_utf8_lossy(name).into_owned() } else { name.iter().map(|&b| super::util::cp1252_char(b)).collect() };
    let extra_at = name_at + nlen;
    e.data_at = extra_at + xlen;
    if e.data_at > d.len() {
        e.truncated = true;
        e.data_end = d.len();
        return Some(e);
    }
    // zip64 extra field.
    let mut x = extra_at;
    while x + 4 <= extra_at + xlen {
        let id = le16(d, x)?;
        let sz = le16(d, x + 2)? as usize;
        if id == 1 {
            let mut p = x + 4;
            if usize_ == 0xFFFF_FFFF {
                usize_ = le64(d, p).unwrap_or(usize_);
                p += 8;
            }
            if csize == 0xFFFF_FFFF {
                csize = le64(d, p).unwrap_or(csize);
            }
        }
        x += 4 + sz;
    }
    let zip64 = csize > 0xFFFF_FFFF - 1 || usize_ > 0xFFFF_FFFE;
    e.ok = true;
    if flags & 8 != 0 && csize == 0 {
        // Sizes follow the data in a descriptor: find the data's end.
        let end = match method {
            8 => {
                let (used, _, _, ended) = inflate(&d[e.data_at..], 1 << 30, None);
                if !ended {
                    e.truncated = true;
                    e.data_end = d.len();
                    return Some(e);
                }
                e.data_at + used
            }
            0 => {
                // Stored with a descriptor: look for a signed descriptor whose size matches.
                let mut p = e.data_at;
                let mut found = None;
                while let Some(s) = find_from(d, b"PK\x07\x08", p) {
                    if le32(d, s + 8).map(|c| c as usize) == Some(s - e.data_at) {
                        found = Some(s);
                        break;
                    }
                    p = s + 1;
                }
                match found {
                    Some(s) => s,
                    None => {
                        e.truncated = true;
                        e.data_end = d.len();
                        return Some(e);
                    }
                }
            }
            _ => {
                e.truncated = true;
                e.data_end = d.len();
                return Some(e);
            }
        };
        e.data_end = end;
        let signed = d.get(end..end + 4) == Some(b"PK\x07\x08");
        let b = if signed { end + 4 } else { end };
        let wide = zip64 || (le32(d, b + 4).map(|v| v as usize) != Some(end - e.data_at) && le64(d, b + 4).map(|v| v as usize) == Some(end - e.data_at));
        crc = le32(d, b).unwrap_or(0);
        // The descriptor's compressed size is implied by where the data ended.
        usize_ = if wide { le64(d, b + 12).unwrap_or(0) } else { le32(d, b + 8).unwrap_or(0) as u64 };
        e.desc_len = (b - end) + if wide { 20 } else { 12 };
        if end + e.desc_len > d.len() {
            e.desc_len = d.len() - end;
        }
        csize = (end - e.data_at) as u64;
    } else {
        let end = (e.data_at as u64).saturating_add(csize);
        if end > d.len() as u64 {
            e.truncated = true;
            e.data_end = d.len();
        } else {
            e.data_end = end as usize;
            if flags & 8 != 0 {
                let signed = d.get(e.data_end..e.data_end + 4) == Some(b"PK\x07\x08");
                e.desc_len = (if signed { 4 } else { 0 } + if zip64 { 20 } else { 12 }).min(d.len() - e.data_end);
            }
        }
    }
    e.crc = crc;
    e.csize = csize;
    e.usize = usize_;
    Some(e)
}

/// A readable ZIP: through its central directory or, failing that, its local headers.
pub enum Container<'a> {
    Zip(zip::ZipArchive<Cursor<&'a [u8]>>),
    Local(&'a [u8], Vec<LocalEntry>),
}

impl<'a> Container<'a> {
    pub fn open(d: &'a [u8]) -> Option<Container<'a>> {
        if let Ok(z) = zip::ZipArchive::new(Cursor::new(d)) {
            return Some(Container::Zip(z));
        }
        let entries = scan_local(d, false, 0, 100_000);
        if entries.is_empty() {
            None
        } else {
            Some(Container::Local(d, entries))
        }
    }

    pub fn names(&self) -> Vec<String> {
        match self {
            Container::Zip(z) => z.file_names().map(str::to_string).collect(),
            Container::Local(_, es) => es.iter().map(|e| e.name.clone()).collect(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Container::Zip(z) => z.len(),
            Container::Local(_, es) => es.len(),
        }
    }

    /// Up to `max` bytes of the named entry (case-insensitive fallback). Partial entries return
    /// what could be inflated.
    pub fn read(&mut self, name: &str, max: usize) -> Option<Vec<u8>> {
        match self {
            Container::Zip(z) => {
                let real = if z.index_for_name(name).is_some() {
                    name.to_string()
                } else {
                    z.file_names().find(|n| n.eq_ignore_ascii_case(name))?.to_string()
                };
                let f = z.by_name(&real).ok()?;
                let mut v = Vec::new();
                let _ = f.take(max as u64).read_to_end(&mut v);
                Some(v)
            }
            Container::Local(d, es) => {
                let e = es.iter().find(|e| e.name == name).or_else(|| es.iter().find(|e| e.name.eq_ignore_ascii_case(name)))?;
                let data = &d[e.data_at.min(d.len())..e.data_end.min(d.len())];
                match e.method {
                    0 => Some(data[..data.len().min(max)].to_vec()),
                    8 => {
                        let mut v = Vec::new();
                        inflate(data, max as u64, Some((&mut v, max)));
                        Some(v)
                    }
                    _ => None,
                }
            }
        }
    }

    pub fn read_string(&mut self, name: &str, max: usize) -> Option<String> {
        self.read(name, max).map(|v| String::from_utf8_lossy(&v).into_owned())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::io::Write;

    pub fn make_zip(files: &[(&str, &[u8])], deflate: bool) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opt = zip::write::SimpleFileOptions::default().compression_method(if deflate { zip::CompressionMethod::Deflated } else { zip::CompressionMethod::Stored });
        for (n, d) in files {
            w.start_file(*n, opt).unwrap();
            w.write_all(d).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn local_scan_without_central_directory() {
        let big: Vec<u8> = (0..20_000u32).map(|i| (i * 7 % 13) as u8).collect();
        let z = make_zip(&[("a.txt", b"hello hello hello"), ("b.bin", &big), ("c.txt", b"end")], true);
        let cd = super::super::util::rfind(&z, b"PK\x01\x02").unwrap();
        let first_cd = super::super::util::find(&z, b"PK\x01\x02").unwrap();
        assert!(first_cd <= cd);
        let cut = &z[..first_cd];
        let es = scan_local(cut, true, 1 << 30, 100);
        assert_eq!(es.len(), 3);
        assert!(es.iter().all(|e| e.ok && !e.truncated));
        let mut c = Container::open(cut).unwrap();
        assert!(matches!(c, Container::Local(..)));
        assert_eq!(c.read_string("a.txt", 100).as_deref(), Some("hello hello hello"));
        // Truncated in the middle of b.bin.
        let mid = es[1].data_at + 10;
        let es2 = scan_local(&z[..mid], true, 1 << 30, 100);
        assert_eq!(es2.len(), 2);
        assert!(es2[1].truncated);
    }
}
