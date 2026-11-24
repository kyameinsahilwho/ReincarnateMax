//! User-defined carving rules (Settings -> File carving rules).

use super::parse::{clean, est, Parsed};
use super::rd::Rd;
use crate::model::{Category, CustomSignature};

pub(crate) struct Custom {
    pub name: String,
    pub ext: String,
    pub category: Category,
    pub header: Vec<Option<u8>>,
    pub hoff: usize,
    pub footer: Vec<Option<u8>>,
    pub max_size: u64,
    /// A literal byte of the header for a quick reject: (index, value).
    key: (usize, u8),
}

fn parse_hex(s: &str) -> Option<Vec<Option<u8>>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace() && *c != ',' && *c != '-').collect();
    if clean.len() % 2 != 0 {
        return None;
    }
    clean
        .as_bytes()
        .chunks(2)
        .map(|p| {
            let p = std::str::from_utf8(p).ok()?;
            if p == "??" {
                Some(None)
            } else {
                u8::from_str_radix(p, 16).ok().map(Some)
            }
        })
        .collect()
}

pub(crate) fn compile(sig: &CustomSignature) -> Result<Custom, String> {
    let ext = sig.ext.trim().trim_start_matches('.').to_ascii_lowercase();
    if ext.is_empty() || ext.len() > 8 || !ext.bytes().all(|c| c.is_ascii_alphanumeric()) {
        return Err("Give it a file extension of 1 to 8 letters or digits, without the dot.".into());
    }
    let category = Category::parse(sig.category.trim()).ok_or_else(|| "Pick a category: photo, video, audio, document, archive or other.".to_string())?;
    let header = parse_hex(&sig.header).ok_or_else(|| "Write the header as hex byte pairs like \"FF D8 FF\", using ?? for any byte.".to_string())?;
    if header.iter().filter(|b| b.is_some()).count() < 2 {
        return Err("The header needs at least 2 fixed bytes (not ??) so it doesn't match everywhere.".into());
    }
    if header.len() > 256 {
        return Err("Keep the header to 256 bytes or fewer.".into());
    }
    if sig.header_offset > 4096 {
        return Err("The header offset can be at most 4096 bytes.".into());
    }
    let footer = if sig.footer.trim().is_empty() {
        Vec::new()
    } else {
        let f = parse_hex(&sig.footer).ok_or_else(|| "Write the footer as hex byte pairs like \"FF D9\", using ?? for any byte.".to_string())?;
        if f.iter().all(|b| b.is_none()) || f.len() > 256 {
            return Err("The footer needs at least one fixed byte and at most 256 bytes.".into());
        }
        f
    };
    if !(1024..=16u64 << 30).contains(&sig.max_size) {
        return Err("Set the maximum size between 1 KB and 16 GB.".into());
    }
    let key = header.iter().enumerate().find_map(|(i, b)| b.map(|v| (i, v))).unwrap();
    Ok(Custom {
        name: if sig.name.trim().is_empty() { format!("{} file", ext.to_ascii_uppercase()) } else { sig.name.trim().to_string() },
        ext,
        category,
        header,
        hoff: sig.header_offset as usize,
        footer,
        max_size: sig.max_size,
        key,
    })
}

impl Custom {
    /// Does a file matching this rule start at `p[0]`?
    #[inline]
    pub fn matches(&self, p: &[u8]) -> bool {
        let h = self.hoff;
        if p.len() < h + self.header.len() || p[h + self.key.0] != self.key.1 {
            return false;
        }
        self.header.iter().enumerate().all(|(i, b)| b.map_or(true, |v| p[h + i] == v))
    }

    pub fn parse(&self, rd: &mut Rd) -> Option<Parsed> {
        let max = self.max_size.min(rd.avail());
        if self.footer.is_empty() {
            return est(max);
        }
        // Search the longest literal run of the footer, then check the whole footer around it.
        let (mut best, mut cur_start, mut cur_len, mut best_len) = (0usize, 0usize, 0usize, 0usize);
        for (i, b) in self.footer.iter().enumerate() {
            if b.is_some() {
                if cur_len == 0 {
                    cur_start = i;
                }
                cur_len += 1;
                if cur_len > best_len {
                    best_len = cur_len;
                    best = cur_start;
                }
            } else {
                cur_len = 0;
            }
        }
        let run: Vec<u8> = self.footer[best..best + best_len].iter().map(|b| b.unwrap()).collect();
        let flen = self.footer.len() as u64;
        let mut from = (self.hoff + self.header.len()) as u64 + best as u64;
        while let Ok(Some(q)) = rd.find(from, max, &run) {
            let start = q - best as u64;
            if start + flen > max {
                break;
            }
            if let Ok(f) = rd.bytes(start, flen as usize) {
                if self.footer.iter().zip(f).all(|(b, &x)| b.map_or(true, |v| v == x)) {
                    return clean(start + flen);
                }
            }
            from = q + 1;
        }
        est(max)
    }
}
