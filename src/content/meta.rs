//! Embedded metadata: EXIF, PNG text, image dimensions, PDF Info/XMP, Office/ODF/EPUB properties,
//! ID3, Vorbis comments, MP4 atoms, RIFF headers, Matroska, ZIP, SQLite and PE version info.
//! All parsers are bounded: they look at the bytes they are given and cap loops and string sizes.

use super::bmff;
use super::exif::{jpeg_exif, jpeg_info, parse_tiff};
use super::util::*;
use super::xml;
use super::zipscan::Container;
use std::collections::BTreeMap;

pub type Meta = BTreeMap<String, String>;

pub fn extract(type_id: &str, data: &[u8]) -> Meta {
    let mut m = Meta::new();
    let mut k = kind(type_id);
    if k == Kind::Other || sig_matches(k, data) == Some(false) {
        if let Some(t) = crate::formats::detect(data) {
            k = kind(t.id);
        }
    }
    match k {
        Kind::Jpeg => jpeg(data, &mut m),
        Kind::Png => png(data, &mut m),
        Kind::Gif => {
            if data.len() >= 10 && data.starts_with(b"GIF8") {
                dims(&mut m, le16(data, 6).unwrap_or(0) as u32, le16(data, 8).unwrap_or(0) as u32);
            }
        }
        Kind::Bmp => {
            if data.starts_with(b"BM") {
                let w = le32(data, 18).unwrap_or(0) as i32;
                let h = le32(data, 22).unwrap_or(0) as i32;
                dims(&mut m, w.unsigned_abs(), h.unsigned_abs());
            }
        }
        Kind::Webp => webp(data, &mut m),
        Kind::Psd => {
            if data.starts_with(b"8BPS") {
                dims(&mut m, be32(data, 18).unwrap_or(0), be32(data, 14).unwrap_or(0));
            }
        }
        Kind::Ico => {
            if data.len() >= 8 {
                let w = if data[6] == 0 { 256 } else { data[6] as u32 };
                let h = if data[7] == 0 { 256 } else { data[7] as u32 };
                dims(&mut m, w, h);
            }
        }
        Kind::Tiff => {
            if let Some(e) = parse_tiff(data) {
                e.fill(&mut m, true);
            }
        }
        Kind::Raw => {
            if let Some(e) = parse_tiff(data) {
                e.fill(&mut m, false);
            }
        }
        Kind::Cr3 => cr3(data, &mut m),
        Kind::Raf => {
            if let (Some(o), Some(l)) = (be32(data, 84), be32(data, 88)) {
                if let Some(j) = data.get(o as usize..(o as usize).saturating_add(l as usize).min(data.len())) {
                    if let Some(e) = jpeg_exif(j) {
                        e.fill(&mut m, false);
                    }
                }
            }
        }
        Kind::Heic | Kind::Avif => heif(data, &mut m),
        Kind::Pdf => pdf(data, &mut m),
        Kind::Ooxml => ooxml(data, &mut m),
        Kind::Odf => odf(data, &mut m),
        Kind::Epub => epub(data, &mut m),
        Kind::Zip => {
            if let Some(c) = Container::open(data) {
                put(&mut m, "entries", &c.len().to_string());
            }
        }
        Kind::Mp3 | Kind::Aac => {
            id3(data, &mut m);
            if k == Kind::Mp3 {
                if let Some(d) = mp3_vbr_duration(data) {
                    put(&mut m, "duration", &fmt_secs(d).unwrap_or_default());
                }
            }
        }
        Kind::Flac => flac(data, &mut m),
        Kind::Ogg => ogg(data, &mut m),
        Kind::Mp4 => {
            if let Some(moov) = bmff::find_moov(&data) {
                bmff::moov_info(&moov).fill(&mut m);
            }
        }
        Kind::Wav | Kind::Avi => riff(data, &mut m),
        Kind::Mkv => mkv(data, &mut m),
        Kind::Sqlite => {
            if data.starts_with(b"SQLite format 3\0") {
                let ps = match be16(data, 16).unwrap_or(0) {
                    1 => 65536,
                    p => p as u32,
                };
                put(&mut m, "pageSize", &ps.to_string());
                if let Some(pc) = be32(data, 28).filter(|&n| n > 0) {
                    put(&mut m, "dbPages", &pc.to_string());
                }
            }
        }
        Kind::Pe => pe(data, &mut m),
        Kind::Ole => ole(data, &mut m),
        _ => {}
    }
    m
}

fn dims(m: &mut Meta, w: u32, h: u32) {
    if w > 0 && h > 0 && w < 1_000_000 && h < 1_000_000 {
        put(m, "width", &w.to_string());
        put(m, "height", &h.to_string());
    }
}

// ----------------------------------------------------------------------------------- images

fn jpeg(d: &[u8], m: &mut Meta) {
    let Some(j) = jpeg_info(d) else { return };
    dims(m, j.width, j.height);
    if let Some((o, l)) = j.exif_at {
        if let Some(e) = parse_tiff(&d[o..o + l]) {
            e.fill(m, false);
        }
    }
}

fn png(d: &[u8], m: &mut Meta) {
    if !d.starts_with(b"\x89PNG\r\n\x1a\n") {
        return;
    }
    let mut p = 8;
    let mut n = 0;
    while p + 12 <= d.len() && n < 10_000 {
        n += 1;
        let len = be32(d, p).unwrap_or(0) as usize;
        let t = &d[p + 4..p + 8];
        let body = &d[(p + 8).min(d.len())..(p + 8).saturating_add(len).min(d.len())];
        match t {
            b"IHDR" => dims(m, be32(body, 0).unwrap_or(0), be32(body, 4).unwrap_or(0)),
            b"tEXt" => {
                if let Some(z) = body.iter().position(|&c| c == 0) {
                    png_text(m, &latin1(&body[..z]), &latin1(&body[z + 1..]));
                }
            }
            b"zTXt" => {
                if let Some(z) = body.iter().position(|&c| c == 0) {
                    let v = zlib(body.get(z + 2..).unwrap_or(&[]), 64 * 1024);
                    png_text(m, &latin1(&body[..z]), &latin1(&v));
                }
            }
            b"iTXt" => {
                if let Some(z) = body.iter().position(|&c| c == 0) {
                    let key = latin1(&body[..z]);
                    let comp = body.get(z + 1).copied().unwrap_or(0);
                    let mut r = body.get(z + 3..).unwrap_or(&[]);
                    for _ in 0..2 {
                        let q = r.iter().position(|&c| c == 0).unwrap_or(r.len());
                        r = r.get(q + 1..).unwrap_or(&[]);
                    }
                    let v = if comp == 1 { zlib(r, 64 * 1024) } else { r.to_vec() };
                    png_text(m, &key, &String::from_utf8_lossy(&v));
                }
            }
            b"eXIf" => {
                if let Some(e) = parse_tiff(body) {
                    e.fill(m, false);
                }
            }
            b"IEND" => break,
            _ => {}
        }
        p = p.saturating_add(12 + len);
    }
}

fn png_text(m: &mut Meta, key: &str, v: &str) {
    match key {
        "Title" => put(m, "title", v),
        "Author" => put(m, "author", v),
        "Software" => put(m, "software", v),
        "Creation Time" => {
            if let Some(d) = norm_date(v) {
                put(m, "created", &d)
            }
        }
        "XML:com.adobe.xmp" => xmp(v, m),
        _ => {}
    }
}

fn zlib(d: &[u8], max: usize) -> Vec<u8> {
    use std::io::Read;
    let mut v = Vec::new();
    let _ = flate2::read::ZlibDecoder::new(d).take(max as u64).read_to_end(&mut v);
    v
}

fn webp(d: &[u8], m: &mut Meta) {
    if !(d.starts_with(b"RIFF") && d.get(8..12) == Some(b"WEBP")) {
        return;
    }
    let mut p = 12;
    let mut n = 0;
    while p + 8 <= d.len() && n < 64 {
        n += 1;
        let t = &d[p..p + 4];
        let len = le32(d, p + 4).unwrap_or(0) as usize;
        let b = &d[p + 8..(p + 8).saturating_add(len).min(d.len())];
        match t {
            b"VP8X" if b.len() >= 10 => {
                let w = 1 + (b[4] as u32 | (b[5] as u32) << 8 | (b[6] as u32) << 16);
                let h = 1 + (b[7] as u32 | (b[8] as u32) << 8 | (b[9] as u32) << 16);
                dims(m, w, h);
            }
            b"VP8 " if b.len() >= 10 && b[3..6] == [0x9D, 0x01, 0x2A] => {
                dims(m, (le16(b, 6).unwrap_or(0) & 0x3FFF) as u32, (le16(b, 8).unwrap_or(0) & 0x3FFF) as u32);
            }
            b"VP8L" if b.len() >= 5 && b[0] == 0x2F => {
                let bits = le32(b, 1).unwrap_or(0);
                dims(m, (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1);
            }
            b"EXIF" => {
                let t = b.strip_prefix(b"Exif\0\0").unwrap_or(b);
                if let Some(e) = parse_tiff(t) {
                    e.fill(m, false);
                }
            }
            _ => {}
        }
        p = p.saturating_add(8 + len + (len & 1));
    }
}

fn cr3(d: &[u8], m: &mut Meta) {
    let lim = &d[..d.len().min(1 << 20)];
    if let Some(p) = find(lim, b"CMT1") {
        if let Some(e) = parse_tiff(&lim[p + 4..]) {
            e.fill(m, false);
        }
    }
    if let Some(p) = find(lim, b"CMT2") {
        // CMT2 is a TIFF whose first IFD holds the Exif tags.
        let t = &lim[p + 4..];
        if let Some(tf) = super::exif::Tiff::new(t) {
            if let Some(o) = tf.first_ifd() {
                let (es, _) = tf.ifd(o);
                if let Some(s) = es.iter().find(|e| e.tag == 0x9003).and_then(|e| tf.ascii(e)).and_then(|s| norm_date(&s)) {
                    put(m, "taken", &s);
                }
            }
        }
    }
}

fn heif(d: &[u8], m: &mut Meta) {
    let lim = &d[..d.len().min(1 << 20)];
    let mut best = (0u32, 0u32);
    let mut p = 0;
    let mut n = 0;
    while let Some(i) = find_from(lim, b"ispe", p) {
        n += 1;
        if n > 64 {
            break;
        }
        let (w, h) = (be32(lim, i + 8).unwrap_or(0), be32(lim, i + 12).unwrap_or(0));
        if (w as u64) * (h as u64) > (best.0 as u64) * (best.1 as u64) {
            best = (w, h);
        }
        p = i + 4;
    }
    dims(m, best.0, best.1);
    if let Some(p) = find(lim, b"Exif\0\0") {
        if let Some(e) = parse_tiff(&lim[p + 6..]) {
            e.fill(m, false);
        }
    }
}

// ----------------------------------------------------------------------------------- PDF

/// Decode a PDF string object starting at `d[0]` ('(' or '<'). Returns text.
pub fn pdf_string(d: &[u8]) -> Option<String> {
    let bytes: Vec<u8> = match d.first()? {
        b'(' => {
            let mut out = Vec::new();
            let mut depth = 1;
            let mut i = 1;
            while i < d.len() && out.len() < 4096 {
                let c = d[i];
                match c {
                    b'\\' => {
                        i += 1;
                        let Some(&e) = d.get(i) else { break };
                        match e {
                            b'n' => out.push(b'\n'),
                            b'r' => out.push(b'\r'),
                            b't' => out.push(b'\t'),
                            b'b' => out.push(8),
                            b'f' => out.push(12),
                            b'0'..=b'7' => {
                                let mut v = 0u32;
                                let mut k = 0;
                                while k < 3 && i < d.len() && (b'0'..=b'7').contains(&d[i]) {
                                    v = v * 8 + (d[i] - b'0') as u32;
                                    i += 1;
                                    k += 1;
                                }
                                out.push(v as u8);
                                continue;
                            }
                            b'\r' | b'\n' => {}
                            other => out.push(other),
                        }
                    }
                    b'(' => {
                        depth += 1;
                        out.push(c);
                    }
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                        out.push(c);
                    }
                    _ => out.push(c),
                }
                i += 1;
            }
            out
        }
        b'<' => {
            let end = d.iter().take(8192).position(|&c| c == b'>')?;
            let hex: Vec<u8> = d[1..end].iter().copied().filter(|c| c.is_ascii_hexdigit()).collect();
            hex.chunks(2)
                .map(|c| {
                    let s = std::str::from_utf8(c).unwrap_or("0");
                    u8::from_str_radix(&format!("{s:0<2}"), 16).unwrap_or(0)
                })
                .collect()
        }
        _ => return None,
    };
    Some(if bytes.starts_with(&[0xFE, 0xFF]) {
        utf16(&bytes[2..], false)
    } else if bytes.starts_with(&[0xFF, 0xFE]) {
        utf16(&bytes[2..], true)
    } else if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8_lossy(&bytes[3..]).into_owned()
    } else {
        bytes.iter().map(|&b| cp1252_char(b)).collect()
    })
}

fn skip_ws(d: &[u8], mut i: usize) -> usize {
    while i < d.len() && matches!(d[i], b' ' | b'\r' | b'\n' | b'\t' | 0 | 12) {
        i += 1;
    }
    i
}

/// Parse "n g R" at `d[i..]`.
fn pdf_ref(d: &[u8], i: usize) -> Option<(u32, u32)> {
    let i = skip_ws(d, i);
    let a = d[i..].iter().take(10).take_while(|c| c.is_ascii_digit()).count();
    let n: u32 = std::str::from_utf8(&d[i..i + a]).ok()?.parse().ok()?;
    let j = skip_ws(d, i + a);
    let b = d[j..].iter().take(5).take_while(|c| c.is_ascii_digit()).count();
    let g: u32 = std::str::from_utf8(&d[j..j + b]).ok()?.parse().ok()?;
    let k = skip_ws(d, j + b);
    if d.get(k) == Some(&b'R') {
        Some((n, g))
    } else {
        None
    }
}

/// Body of object `n g` (last definition wins), up to `endobj`, capped at 64 KiB.
pub fn pdf_object(d: &[u8], n: u32, g: u32) -> Option<&[u8]> {
    let pat = format!("{n} {g} obj");
    let mut p = 0;
    let mut last = None;
    while let Some(i) = find_from(d, pat.as_bytes(), p) {
        if i == 0 || !d[i - 1].is_ascii_digit() {
            last = Some(i);
        }
        p = i + 1;
    }
    let s = last? + pat.len();
    let lim = &d[s..d.len().min(s + 65536)];
    let e = find(lim, b"endobj").unwrap_or(lim.len());
    Some(&lim[..e])
}

/// String value of `/Key` in a dictionary body (direct string, or a reference to one).
fn pdf_dict_str(d: &[u8], dict: &[u8], key: &str) -> Option<String> {
    let mut p = 0;
    while let Some(i) = find_from(dict, key.as_bytes(), p) {
        let after = i + key.len();
        p = after;
        if dict.get(after).map_or(false, |c| c.is_ascii_alphanumeric()) {
            continue;
        }
        let j = skip_ws(dict, after);
        if matches!(dict.get(j), Some(b'(') | Some(b'<')) && dict.get(j + 1) != Some(&b'<') {
            return pdf_string(&dict[j..]);
        }
        if let Some((n, g)) = pdf_ref(dict, j) {
            let o = pdf_object(d, n, g)?;
            let k = skip_ws(o, 0);
            return pdf_string(&o[k..]);
        }
    }
    None
}

fn pdf(d: &[u8], m: &mut Meta) {
    if let Some(i) = rfind(d, b"/Info") {
        if let Some((n, g)) = pdf_ref(d, i + 5) {
            if let Some(dict) = pdf_object(d, n, g) {
                for (key, mk) in [("/Title", "title"), ("/Author", "author"), ("/Creator", "software"), ("/Producer", "software")] {
                    if let Some(v) = pdf_dict_str(d, dict, key) {
                        put(m, mk, &v);
                    }
                }
                for (key, mk) in [("/CreationDate", "created"), ("/ModDate", "modified")] {
                    if let Some(v) = pdf_dict_str(d, dict, key).and_then(|s| norm_date(&s)) {
                        put(m, mk, &v);
                    }
                }
            }
        }
    }
    if let Some(s) = find(d, b"<x:xmpmeta") {
        let e = find_from(d, b"</x:xmpmeta>", s).unwrap_or(d.len().min(s + 65536));
        xmp(&String::from_utf8_lossy(&d[s..e.min(s + 262_144)]), m);
    }
    if let Some(n) = pdf_pages(d) {
        put(m, "pages", &n.to_string());
    }
}

/// XMP packet: dc:title, dc:creator, xmp:CreateDate, xmp:CreatorTool.
fn xmp(x: &str, m: &mut Meta) {
    for (el, key) in [("dc:title", "title"), ("dc:creator", "author")] {
        if let Some(s) = x.find(&format!("<{el}")) {
            let e = x[s..].find(&format!("</{el}>")).map_or(x.len(), |e| s + e);
            if let Some(v) = xml::first_text(&x[s..e], "rdf:li") {
                put(m, key, &v);
            }
        }
    }
    for (el, key, date) in [("xmp:CreateDate", "created", true), ("xmp:CreatorTool", "software", false), ("photoshop:DateCreated", "created", true)] {
        let v = xml::first_text(x, el).or_else(|| x.find(&format!("{el}=\"")).map(|i| x[i + el.len() + 2..].split('"').next().unwrap_or("").to_string()));
        if let Some(v) = v {
            if date {
                if let Some(d) = norm_date(&v) {
                    put(m, key, &d);
                }
            } else {
                put(m, key, &v);
            }
        }
    }
}

/// Page count: the page tree root's /Count, else the number of `/Type /Page` objects.
pub fn pdf_pages(d: &[u8]) -> Option<u32> {
    let mut pages = 0u32;
    let mut root_count = 0u32;
    let mut p = 0;
    let mut iters = 0;
    while let Some(i) = find_from(d, b"/Type", p) {
        iters += 1;
        if iters > 2_000_000 {
            break;
        }
        p = i + 5;
        let j = skip_ws(d, p);
        if d.get(j..j + 5) == Some(b"/Page") {
            match d.get(j + 5) {
                Some(b's') => {
                    // Look around for /Count.
                    let lo = i.saturating_sub(400);
                    let hi = (j + 400).min(d.len());
                    let w = &d[lo..hi];
                    let mut q = 0;
                    while let Some(c) = find_from(w, b"/Count", q) {
                        let k = skip_ws(w, c + 6);
                        let len = w[k..].iter().take(9).take_while(|c| c.is_ascii_digit()).count();
                        if let Some(n) = std::str::from_utf8(&w[k..k + len]).ok().and_then(|s| s.parse::<u32>().ok()) {
                            root_count = root_count.max(n);
                        }
                        q = c + 6;
                    }
                }
                Some(c) if c.is_ascii_alphanumeric() => {}
                _ => pages += 1,
            }
        }
    }
    if (1..=200_000).contains(&root_count) {
        Some(root_count)
    } else if pages > 0 {
        Some(pages)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------------- Office

fn ooxml(d: &[u8], m: &mut Meta) {
    let Some(mut c) = Container::open(d) else { return };
    if let Some(x) = c.read_string("docProps/core.xml", 1 << 20) {
        for (el, key) in [("dc:title", "title"), ("dc:creator", "author"), ("cp:lastModifiedBy", "lastModifiedBy")] {
            if let Some(v) = xml::first_text(&x, el) {
                put(m, key, &v);
            }
        }
        for (el, key) in [("dcterms:created", "created"), ("dcterms:modified", "modified")] {
            if let Some(v) = xml::first_text(&x, el).and_then(|s| norm_date(&s)) {
                put(m, key, &v);
            }
        }
    }
    if let Some(x) = c.read_string("docProps/app.xml", 1 << 20) {
        for (el, key) in [("Pages", "pages"), ("Words", "words"), ("Slides", "slides"), ("Application", "software")] {
            if let Some(v) = xml::first_text(&x, el).filter(|v| v != "0") {
                put(m, key, &v);
            }
        }
    }
}

fn odf(d: &[u8], m: &mut Meta) {
    let Some(mut c) = Container::open(d) else { return };
    let Some(x) = c.read_string("meta.xml", 1 << 20) else { return };
    for (el, key) in [("dc:title", "title"), ("meta:initial-creator", "author"), ("dc:creator", "author"), ("meta:generator", "software")] {
        if let Some(v) = xml::first_text(&x, el) {
            put(m, key, &v);
        }
    }
    for (el, key) in [("meta:creation-date", "created"), ("dc:date", "modified")] {
        if let Some(v) = xml::first_text(&x, el).and_then(|s| norm_date(&s)) {
            put(m, key, &v);
        }
    }
    for t in xml::Scanner::new(&x) {
        if let xml::Tok::Start { name: "meta:document-statistic", attrs, .. } = t {
            for (a, key) in [("meta:page-count", "pages"), ("meta:word-count", "words")] {
                if let Some(v) = xml::attr(attrs, a) {
                    put(m, key, &v);
                }
            }
        }
    }
}

fn epub(d: &[u8], m: &mut Meta) {
    let Some(mut c) = Container::open(d) else { return };
    let opf = c
        .read_string("META-INF/container.xml", 1 << 16)
        .and_then(|x| {
            xml::Scanner::new(&x).find_map(|t| match t {
                xml::Tok::Start { name, attrs, .. } if xml::local(name) == "rootfile" => xml::attr(attrs, "full-path"),
                _ => None,
            })
        })
        .or_else(|| c.names().into_iter().find(|n| n.ends_with(".opf")));
    if let Some(x) = opf.and_then(|p| c.read_string(&p, 1 << 20)) {
        for (el, key) in [("dc:title", "title"), ("dc:creator", "author")] {
            if let Some(v) = xml::first_text(&x, el) {
                put(m, key, &v);
            }
        }
        if let Some(v) = xml::first_text(&x, "dc:date").and_then(|s| norm_date(&s)) {
            put(m, "created", &v);
        }
    }
}

/// Legacy Office (OLE): the SummaryInformation stream is hard to reach without a CFB parser; look
/// for its property set directly (title/author are stored as code-page strings).
fn ole(d: &[u8], m: &mut Meta) {
    // FMTID_SummaryInformation {F29F85E0-4FF9-1068-AB91-08002B27B3D9}
    const FMTID: [u8; 16] = [0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10, 0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9];
    let Some(f) = find(d, &FMTID) else { return };
    let Some(off) = le32(d, f + 16) else { return };
    // The section offset is relative to the property set stream start (28 bytes before FMTID).
    let base = f.saturating_sub(28);
    let sec = base + off as usize;
    let Some(n) = le32(d, sec + 4) else { return };
    for i in 0..(n as usize).min(64) {
        let (Some(id), Some(po)) = (le32(d, sec + 8 + i * 8), le32(d, sec + 12 + i * 8)) else { break };
        let p = sec + po as usize;
        let key = match id {
            2 => "title",
            4 => "author",
            18 => "software",
            _ => continue,
        };
        if le32(d, p) == Some(30) {
            if let Some(len) = le32(d, p + 4) {
                if let Some(b) = d.get(p + 8..p + 8 + (len as usize).min(512)) {
                    let b = &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())];
                    put(m, key, &utf8_or_1252(b));
                }
            }
        }
    }
}

// ----------------------------------------------------------------------------------- audio

fn id3_text(b: &[u8]) -> String {
    let Some((&enc, rest)) = b.split_first() else { return String::new() };
    let s = match enc {
        1 => {
            if rest.starts_with(&[0xFF, 0xFE]) {
                utf16(&rest[2..], true)
            } else if rest.starts_with(&[0xFE, 0xFF]) {
                utf16(&rest[2..], false)
            } else {
                utf16(rest, true)
            }
        }
        2 => utf16(rest, false),
        3 => String::from_utf8_lossy(rest).into_owned(),
        _ => latin1(rest),
    };
    // Multiple values are NUL-separated; keep the first.
    s.split('\0').find(|p| !p.trim().is_empty()).unwrap_or("").trim().to_string()
}

pub fn id3(d: &[u8], m: &mut Meta) {
    if d.len() >= 10 && d.starts_with(b"ID3") {
        let ver = d[3];
        let size = syncsafe(&d[6..10]) as usize;
        let end = (10 + size).min(d.len());
        let mut p = 10;
        if d[5] & 0x40 != 0 && ver >= 3 {
            // Extended header.
            let ext = if ver == 4 { syncsafe(&d[10..14.min(d.len())]) as usize } else { be32(d, 10).unwrap_or(0) as usize + 4 };
            p += ext;
        }
        let mut n = 0;
        while n < 512 {
            n += 1;
            let (id, len, hdr) = if ver == 2 {
                if p + 6 > end {
                    break;
                }
                let l = (d[p + 3] as usize) << 16 | (d[p + 4] as usize) << 8 | d[p + 5] as usize;
                (&d[p..p + 3], l, 6)
            } else {
                if p + 10 > end {
                    break;
                }
                let l = if ver == 4 { syncsafe(&d[p + 4..p + 8]) as usize } else { be32(d, p + 4).unwrap_or(0) as usize };
                (&d[p..p + 4], l, 10)
            };
            if id[0] == 0 || len == 0 {
                break;
            }
            let body = &d[(p + hdr).min(end)..(p + hdr).saturating_add(len).min(end)];
            let key = match id {
                b"TIT2" | b"TT2" => Some("title"),
                b"TPE1" | b"TP1" => Some("artist"),
                b"TALB" | b"TAL" => Some("album"),
                b"TYER" | b"TYE" | b"TDRC" => Some("year"),
                b"TLEN" | b"TLE" => Some("tlen"),
                _ => None,
            };
            match key {
                Some("tlen") => {
                    if let Ok(ms) = id3_text(body).trim().parse::<f64>() {
                        if let Some(s) = fmt_secs(ms / 1000.0) {
                            put(m, "duration", &s);
                        }
                    }
                }
                Some("year") => {
                    let t = id3_text(body);
                    put(m, "year", t.get(..4).unwrap_or(&t));
                }
                Some(k) => put(m, k, &id3_text(body)),
                None => {}
            }
            p = p.saturating_add(hdr + len);
        }
    }
    // ID3v1 at the very end (only meaningful when `d` is the whole file).
    if d.len() >= 128 {
        let t = &d[d.len() - 128..];
        if t.starts_with(b"TAG") {
            let f = |a: usize, b: usize| utf8_or_1252(&t[a..b]).trim_matches(|c: char| c == '\0' || c.is_whitespace()).to_string();
            put(m, "title", &f(3, 33));
            put(m, "artist", &f(33, 63));
            put(m, "album", &f(63, 93));
            let y = f(93, 97);
            if y.chars().all(|c| c.is_ascii_digit()) {
                put(m, "year", &y);
            }
        }
    }
}

/// Duration from a Xing/Info or VBRI header in the first frame.
pub fn mp3_vbr_duration(d: &[u8]) -> Option<f64> {
    let start = id3_skip(d).unwrap_or(0);
    let lim = d.len().min(start + 8192);
    let mut i = start;
    while i + 4 <= lim {
        if let Some(h) = super::validate::mpeg_header(&d[i..]) {
            let side = match (h.version == 1, h.channels == 1) {
                (true, false) => 32,
                (true, true) => 17,
                (false, false) => 17,
                (false, true) => 9,
            };
            let x = i + 4 + side;
            if matches!(d.get(x..x + 4), Some(b"Xing") | Some(b"Info")) {
                let flags = be32(d, x + 4)?;
                if flags & 1 != 0 {
                    let frames = be32(d, x + 8)?;
                    return Some(frames as f64 * h.samples as f64 / h.sample_rate as f64);
                }
                return None;
            }
            if d.get(i + 36..i + 40) == Some(b"VBRI") {
                let frames = be32(d, i + 36 + 14)?;
                return Some(frames as f64 * h.samples as f64 / h.sample_rate as f64);
            }
            return None;
        }
        i += 1;
    }
    None
}

fn vorbis_comments(b: &[u8], m: &mut Meta) {
    let vl = le32(b, 0).unwrap_or(0) as usize;
    let mut p = 4usize.saturating_add(vl);
    let n = le32(b, p).unwrap_or(0).min(1000);
    p += 4;
    for _ in 0..n {
        let Some(l) = le32(b, p) else { break };
        let l = l as usize;
        let Some(s) = b.get(p + 4..(p + 4).saturating_add(l)) else { break };
        let s = String::from_utf8_lossy(s);
        if let Some((k, v)) = s.split_once('=') {
            match k.to_ascii_uppercase().as_str() {
                "TITLE" => put(m, "title", v),
                "ARTIST" => put(m, "artist", v),
                "ALBUM" => put(m, "album", v),
                "DATE" | "YEAR" => put(m, "year", v.get(..4).unwrap_or(v)),
                _ => {}
            }
        }
        p += 4 + l;
    }
}

fn flac(d: &[u8], m: &mut Meta) {
    let mut p = id3_skip(d).unwrap_or(0);
    if d.get(p..p + 4) != Some(b"fLaC") {
        return;
    }
    p += 4;
    for _ in 0..128 {
        let Some(&h) = d.get(p) else { break };
        let len = (be32(d, p).unwrap_or(0) & 0x00FF_FFFF) as usize;
        let b = &d[(p + 4).min(d.len())..(p + 4).saturating_add(len).min(d.len())];
        match h & 0x7F {
            0 if b.len() >= 18 => {
                let rate = (be32(b, 10).unwrap_or(0) >> 12) as u64;
                let total = ((b[13] as u64 & 0x0F) << 32) | be32(b, 14).unwrap_or(0) as u64;
                if rate > 0 && total > 0 {
                    put(m, "duration", &fmt_secs(total as f64 / rate as f64).unwrap_or_default());
                }
            }
            4 => vorbis_comments(b, m),
            _ => {}
        }
        if h & 0x80 != 0 {
            break;
        }
        p = p.saturating_add(4 + len);
    }
}

/// OGG pages: (header offset, granule, flags, body range).
pub fn ogg_pages(d: &[u8], max: usize) -> Vec<(usize, u64, u8, usize, usize)> {
    let mut out = Vec::new();
    let mut p = 0;
    while p + 27 <= d.len() && out.len() < max {
        if &d[p..p + 4] != b"OggS" {
            break;
        }
        let segs = d[p + 26] as usize;
        if p + 27 + segs > d.len() {
            break;
        }
        let body: usize = d[p + 27..p + 27 + segs].iter().map(|&x| x as usize).sum();
        let bs = p + 27 + segs;
        out.push((p, le64(d, p + 6).unwrap_or(0), d[p + 5], bs, (bs + body).min(d.len())));
        p = bs + body;
    }
    out
}

fn ogg(d: &[u8], m: &mut Meta) {
    let pages = ogg_pages(d, 64);
    // Reassemble the first two packets of the first stream (they may span pages).
    let mut stream = Vec::new();
    for &(_, _, _, s, e) in &pages {
        stream.extend_from_slice(&d[s..e]);
        if stream.len() > 1 << 20 {
            break;
        }
    }
    let mut rate = 0u32;
    if stream.starts_with(b"\x01vorbis") {
        rate = le32(&stream, 12).unwrap_or(0);
    } else if stream.starts_with(b"OpusHead") {
        rate = 48_000;
    } else if stream.starts_with(b"\x7fFLAC") {
        rate = (be32(&stream, 27).unwrap_or(0) >> 12) as u32;
    }
    if let Some(i) = find(&stream[..stream.len().min(1 << 20)], b"\x03vorbis") {
        vorbis_comments(&stream[i + 7..], m);
    } else if let Some(i) = find(&stream[..stream.len().min(1 << 20)], b"OpusTags") {
        vorbis_comments(&stream[i + 8..], m);
    }
    // Duration from the last page when it ends the stream.
    if rate > 0 {
        let tail_at = d.len().saturating_sub(65536);
        if let Some(i) = rfind(&d[tail_at..], b"OggS") {
            let p = tail_at + i;
            if p + 27 <= d.len() && d[p + 5] & 4 != 0 {
                let g = le64(d, p + 6).unwrap_or(0);
                if g > 0 && g != u64::MAX {
                    put(m, "duration", &fmt_secs(g as f64 / rate as f64).unwrap_or_default());
                }
            }
        }
    }
}

// ------------------------------------------------------------------------------------ RIFF

pub fn riff_chunks(d: &[u8], start: usize, end: usize, max: usize) -> Vec<([u8; 4], usize, usize)> {
    let mut out = Vec::new();
    let mut p = start;
    while p + 8 <= end.min(d.len()) && out.len() < max {
        let mut id = [0u8; 4];
        id.copy_from_slice(&d[p..p + 4]);
        let len = le32(d, p + 4).unwrap_or(0) as usize;
        out.push((id, p + 8, len));
        p = p.saturating_add(8 + len + (len & 1));
    }
    out
}

fn riff(d: &[u8], m: &mut Meta) {
    if !d.starts_with(b"RIFF") || d.len() < 12 {
        return;
    }
    let form = &d[8..12];
    let top = riff_chunks(d, 12, d.len(), 256);
    let mut byte_rate = 0u32;
    for &(id, s, len) in &top {
        let b = &d[s.min(d.len())..s.saturating_add(len).min(d.len())];
        match &id {
            b"fmt " if b.len() >= 16 => byte_rate = le32(b, 8).unwrap_or(0),
            b"data" if form == b"WAVE" && byte_rate > 0 => {
                put(m, "duration", &fmt_secs(len as f64 / byte_rate as f64).unwrap_or_default());
            }
            b"LIST" if b.len() >= 4 => {
                if &b[..4] == b"INFO" {
                    for (sid, ss, sl) in riff_chunks(d, s + 4, s + len, 64) {
                        let v = d.get(ss..ss.saturating_add(sl).min(d.len())).unwrap_or(&[]);
                        let v = utf8_or_1252(&v[..v.iter().position(|&c| c == 0).unwrap_or(v.len())]);
                        match &sid {
                            b"INAM" => put(m, "title", &v),
                            b"IART" => put(m, "artist", &v),
                            b"IPRD" => put(m, "album", &v),
                            b"ICRD" => put(m, "year", v.get(..4).unwrap_or(&v)),
                            b"ISFT" => put(m, "software", &v),
                            _ => {}
                        }
                    }
                } else if &b[..4] == b"hdrl" {
                    if let Some((_, hs, _)) = riff_chunks(d, s + 4, s + len, 64).into_iter().find(|c| &c.0 == b"avih") {
                        let us = le32(d, hs).unwrap_or(0) as f64;
                        let frames = le32(d, hs + 16).unwrap_or(0) as f64;
                        if us > 0.0 && frames > 0.0 {
                            put(m, "duration", &fmt_secs(us * frames / 1e6).unwrap_or_default());
                        }
                        dims(m, le32(d, hs + 32).unwrap_or(0), le32(d, hs + 36).unwrap_or(0));
                    }
                }
            }
            _ => {}
        }
    }
}

// -------------------------------------------------------------------------------- Matroska

fn vint(d: &[u8], p: usize, strip: bool) -> Option<(u64, usize)> {
    let b = *d.get(p)?;
    if b == 0 {
        return None;
    }
    let len = b.leading_zeros() as usize + 1;
    let mut v = if strip { (b as u64) & (0xFF >> len) } else { b as u64 };
    for i in 1..len {
        v = (v << 8) | *d.get(p + i)? as u64;
    }
    if strip && v == (1u64 << (7 * len)) - 1 {
        v = u64::MAX; // unknown size
    }
    Some((v, len))
}

fn ebml_uint(b: &[u8]) -> u64 {
    b.iter().take(8).fold(0, |a, &x| (a << 8) | x as u64)
}

fn mkv(d: &[u8], m: &mut Meta) {
    let mut scale = 1_000_000u64;
    let mut duration = None;
    let mut stack: Vec<usize> = vec![d.len()];
    let mut p = 0;
    let mut n = 0;
    while p < d.len() && n < 20_000 {
        n += 1;
        while stack.len() > 1 && p >= *stack.last().unwrap() {
            stack.pop();
        }
        let Some((id, il)) = vint(d, p, false) else { break };
        let Some((size, sl)) = vint(d, p + il, true) else { break };
        let body = p + il + sl;
        let end = if size == u64::MAX { *stack.last().unwrap() } else { body.saturating_add(size as usize).min(d.len()) };
        let b = &d[body.min(d.len())..end.max(body).min(d.len())];
        match id {
            // Containers to descend into: EBML header, Segment, Info, Tracks, TrackEntry, Video.
            0x1A45DFA3 | 0x18538067 | 0x1549A966 | 0x1654AE6B | 0xAE | 0xE0 => {
                stack.push(end);
                p = body;
                continue;
            }
            0x2AD7B1 => scale = ebml_uint(b).max(1),
            0x4489 => {
                duration = match b.len() {
                    4 => Some(f32::from_be_bytes(b.try_into().unwrap()) as f64),
                    8 => Some(f64::from_be_bytes(b.try_into().unwrap())),
                    _ => None,
                }
            }
            0x7BA9 => put(m, "title", &String::from_utf8_lossy(b)),
            0x4D80 | 0x5741 => put(m, "software", &String::from_utf8_lossy(b)),
            0x4461 if b.len() == 8 => {
                let ns = i64::from_be_bytes(b.try_into().unwrap());
                if let Some(t) = fmt_unix(978_307_200 + ns / 1_000_000_000) {
                    put(m, "created", &t);
                }
            }
            0xB0 => put(m, "width", &ebml_uint(b).to_string()),
            0xBA => put(m, "height", &ebml_uint(b).to_string()),
            0x1F43B675 => break, // first Cluster: the header is over
            _ => {}
        }
        p = end.max(body);
    }
    if let Some(dur) = duration {
        if let Some(s) = fmt_secs(dur * scale as f64 / 1e9) {
            put(m, "duration", &s);
        }
    }
}

// -------------------------------------------------------------------------------------- PE

fn pe(d: &[u8], m: &mut Meta) {
    let pat: Vec<u8> = "StringFileInfo".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let Some(s) = find(d, &pat) else { return };
    let region = &d[s..d.len().min(s + 16384)];
    for (key, mk) in [("CompanyName", "company"), ("ProductName", "product"), ("FileDescription", "title"), ("FileVersion", "version")] {
        let k: Vec<u8> = key.encode_utf16().flat_map(|u| u.to_le_bytes()).chain([0, 0]).collect();
        let Some(i) = find(region, &k) else { continue };
        let mut p = i + k.len();
        // Value is 32-bit aligned (relative to the resource, which is itself aligned).
        while p + 1 < region.len() && region[p] == 0 && region[p + 1] == 0 && p < i + k.len() + 6 {
            p += 2;
        }
        let mut units = Vec::new();
        while p + 1 < region.len() && units.len() < 256 {
            let u = u16::from_le_bytes([region[p], region[p + 1]]);
            if u == 0 {
                break;
            }
            units.push(u);
            p += 2;
        }
        put(m, mk, &String::from_utf16_lossy(&units));
    }
    if let Some(p) = m.get("product").cloned() {
        put(m, "software", &p);
    }
}

// ----------------------------------------------------------------------------------- names

/// See `content::suggest_name`.
pub fn suggest_name(type_id: &str, meta: &Meta) -> Option<String> {
    let g = |k: &str| meta.get(k).map(|s| clean(s, 120)).filter(|s| !s.is_empty());
    let cat = crate::formats::category_of(type_id);
    let k = kind(type_id);
    let photo = matches!(k, Kind::Jpeg | Kind::Tiff | Kind::Raw | Kind::Cr3 | Kind::Raf | Kind::Heic | Kind::Avif | Kind::Png | Kind::Webp)
        || cat == crate::model::Category::Photo;
    let audio = matches!(k, Kind::Mp3 | Kind::Flac | Kind::Ogg | Kind::Wav | Kind::Aac) || cat == crate::model::Category::Audio;
    let video = matches!(k, Kind::Mkv | Kind::Avi) || cat == crate::model::Category::Video || (k == Kind::Mp4 && !audio);
    let doc = matches!(k, Kind::Pdf | Kind::Ooxml | Kind::Odf | Kind::Epub | Kind::Ole | Kind::Rtf) || cat == crate::model::Category::Document;
    let name = if photo {
        let taken = g("taken").map(|t| t.replace(':', "."));
        match (taken, g("camera")) {
            (Some(t), Some(c)) => Some(format!("{t} {c}")),
            (Some(t), None) => Some(t),
            (None, Some(c)) => Some(c),
            _ => None,
        }
    } else if audio || (k == Kind::Mp4 && g("artist").is_some()) {
        match (g("artist"), g("title")) {
            (Some(a), Some(t)) => Some(format!("{a} - {t}")),
            (None, Some(t)) => Some(t),
            _ => None,
        }
    } else if doc || video {
        g("title").filter(|t| t.chars().any(|c| c.is_alphanumeric()) && !is_placeholder_title(t))
    } else {
        None
    }?;
    let short: String = name.chars().take(80).collect();
    let short = short.trim().to_string();
    if short.is_empty() {
        return None;
    }
    Some(crate::model::safe_file_name(&short))
}

fn is_placeholder_title(t: &str) -> bool {
    let l = t.trim().to_ascii_lowercase();
    l == "untitled" || l.starts_with("microsoft word - ") && l.len() < 20 || l == "powerpoint presentation" || l == "slide 1" || l == "document"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jpeg_with_exif() -> Vec<u8> {
        let img = image::RgbImage::from_fn(32, 16, |x, y| image::Rgb([x as u8 * 8, y as u8 * 16, 128]));
        let mut j = Vec::new();
        image::codecs::jpeg::JpegEncoder::new_with_quality(&mut j, 90).encode_image(&img).unwrap();
        let tiff = super::super::exif::tests::sample_tiff();
        let mut app1 = vec![0xFF, 0xE1];
        app1.extend_from_slice(&((tiff.len() + 8) as u16).to_be_bytes());
        app1.extend_from_slice(b"Exif\0\0");
        app1.extend_from_slice(&tiff);
        [&j[..2], &app1[..], &j[2..]].concat()
    }

    #[test]
    fn jpeg_meta_and_name() {
        let m = extract("jpg", &jpeg_with_exif());
        assert_eq!(m.get("width").map(String::as_str), Some("32"));
        assert_eq!(m.get("height").map(String::as_str), Some("16"));
        assert_eq!(m.get("camera").map(String::as_str), Some("Canon EOS R6"));
        assert_eq!(m.get("taken").map(String::as_str), Some("2024-05-01 14:22:10"));
        assert!(m.get("gps").unwrap().starts_with("48.85"));
        assert_eq!(suggest_name("jpg", &m).as_deref(), Some("2024-05-01 14.22.10 Canon EOS R6"));
    }

    #[test]
    fn png_meta() {
        let img = image::RgbaImage::new(7, 5);
        let mut p = Vec::new();
        img.write_to(&mut std::io::Cursor::new(&mut p), image::ImageFormat::Png).unwrap();
        // Insert a tEXt chunk after IHDR.
        let body = b"Title\0Sunset";
        let mut ch = (body.len() as u32).to_be_bytes().to_vec();
        ch.extend_from_slice(b"tEXt");
        ch.extend_from_slice(body);
        ch.extend_from_slice(&crc32fast::hash(&[b"tEXt".as_slice(), body].concat()).to_be_bytes());
        let p = [&p[..33], &ch[..], &p[33..]].concat();
        let m = extract("png", &p);
        assert_eq!(m.get("width").map(String::as_str), Some("7"));
        assert_eq!(m.get("title").map(String::as_str), Some("Sunset"));
    }

    #[test]
    fn pdf_meta() {
        let pdf = b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >> endobj\n3 0 obj << /Type /Page /Parent 2 0 R >> endobj\n4 0 obj << /Type/Page /Parent 2 0 R >> endobj\n5 0 obj << /Title (Quarterly \\(Q1\\) report) /Author <FEFF0041006E006E> /CreationDate (D:20240501142210+02'00') /Producer (Writer) >> endobj\ntrailer << /Root 1 0 R /Info 5 0 R >>\n%%EOF";
        let m = extract("pdf", pdf);
        assert_eq!(m.get("title").map(String::as_str), Some("Quarterly (Q1) report"));
        assert_eq!(m.get("author").map(String::as_str), Some("Ann"));
        assert_eq!(m.get("created").map(String::as_str), Some("2024-05-01 14:22:10"));
        assert_eq!(m.get("pages").map(String::as_str), Some("2"));
        assert_eq!(m.get("software").map(String::as_str), Some("Writer"));
        assert_eq!(suggest_name("pdf", &m).as_deref(), Some("Quarterly (Q1) report"));
        // Without a page tree /Count, the /Page objects are counted.
        assert_eq!(pdf_pages(b"/Type /Page /Type /Pages /Type/Page /Type /PageLabel"), Some(2));
    }

    #[test]
    fn docx_meta() {
        let core = r#"<?xml version="1.0"?><cp:coreProperties xmlns:dc="x"><dc:title>Budget &amp; plan</dc:title><dc:creator>Ann Lee</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">2023-02-03T04:05:06Z</dcterms:created></cp:coreProperties>"#;
        let app = "<Properties><Pages>12</Pages><Words>3400</Words><Application>Microsoft Office Word</Application></Properties>";
        let z = super::super::zipscan::tests::make_zip(&[("[Content_Types].xml", b"<Types/>"), ("docProps/core.xml", core.as_bytes()), ("docProps/app.xml", app.as_bytes())], true);
        let m = extract("docx", &z);
        assert_eq!(m.get("title").map(String::as_str), Some("Budget & plan"));
        assert_eq!(m.get("author").map(String::as_str), Some("Ann Lee"));
        assert_eq!(m.get("created").map(String::as_str), Some("2023-02-03 04:05:06"));
        assert_eq!(m.get("pages").map(String::as_str), Some("12"));
        // Only the first half of the file (no central directory): local headers still work.
        let half = &z[..super::super::util::find(&z, b"PK\x01\x02").unwrap()];
        assert_eq!(extract("docx", half).get("title").map(String::as_str), Some("Budget & plan"));
    }

    #[test]
    fn id3_and_name() {
        let frame = |id: &[u8], txt: &str| {
            let mut b = vec![3u8];
            b.extend_from_slice(txt.as_bytes());
            let mut f = id.to_vec();
            f.extend_from_slice(&(b.len() as u32).to_be_bytes());
            f.extend_from_slice(&[0, 0]);
            f.extend_from_slice(&b);
            f
        };
        let frames = [frame(b"TIT2", "Song"), frame(b"TPE1", "Band"), frame(b"TALB", "Album"), frame(b"TYER", "2001"), frame(b"TLEN", "185000")].concat();
        let mut d = b"ID3\x03\x00\x00".to_vec();
        let s = frames.len() as u32;
        d.extend_from_slice(&[(s >> 21 & 0x7F) as u8, (s >> 14 & 0x7F) as u8, (s >> 7 & 0x7F) as u8, (s & 0x7F) as u8]);
        d.extend_from_slice(&frames);
        let m = extract("mp3", &d);
        assert_eq!(m.get("artist").map(String::as_str), Some("Band"));
        assert_eq!(m.get("duration").map(String::as_str), Some("185"));
        assert_eq!(m.get("year").map(String::as_str), Some("2001"));
        assert_eq!(suggest_name("mp3", &m).as_deref(), Some("Band - Song"));
    }

    #[test]
    fn mp4_wav_flac_meta() {
        let m = extract("mp4", &super::super::bmff::tests::sample_mp4(100));
        assert_eq!(m.get("duration").map(String::as_str), Some("10"));
        assert_eq!(m.get("width").map(String::as_str), Some("1920"));
        assert_eq!(suggest_name("mp4", &m).as_deref(), Some("Holiday clip"));

        let w = super::super::validate::tests::wav(44100, 2 * 44100 * 2);
        let m = extract("wav", &w);
        assert_eq!(m.get("duration").map(String::as_str), Some("1"));

        let mut f = b"fLaC".to_vec();
        let mut si = vec![0u8; 34];
        // sample rate 44100 (20 bits), channels 2, bps 16, total samples 441000
        let v: u64 = (44100u64 << 44) | (1u64 << 41) | (15u64 << 36) | 441_000;
        si[10..18].copy_from_slice(&v.to_be_bytes());
        f.push(0);
        f.extend_from_slice(&[0, 0, 34]);
        f.extend_from_slice(&si);
        let vc = [&7u32.to_le_bytes()[..], b"libFLAC", &1u32.to_le_bytes(), &10u32.to_le_bytes(), b"TITLE=Rain"].concat();
        f.push(0x84);
        f.extend_from_slice(&(vc.len() as u32).to_be_bytes()[1..]);
        f.extend_from_slice(&vc);
        let m = extract("flac", &f);
        assert_eq!(m.get("duration").map(String::as_str), Some("10"));
        assert_eq!(m.get("title").map(String::as_str), Some("Rain"));
    }

    #[test]
    fn hostile_inputs_dont_panic() {
        let junk: Vec<u8> = (0..5000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        for t in ["jpg", "png", "gif", "bmp", "webp", "psd", "tif", "cr2", "cr3", "raf", "heic", "pdf", "docx", "odt", "epub", "zip", "mp3", "flac", "ogg", "mp4", "wav", "avi", "mkv", "sqlite", "exe", "doc"] {
            for prefix in [&b""[..], b"ID3\x04\0\0\x7f\x7f\x7f\x7f", b"RIFF\xff\xff\xff\xffWAVE", b"fLaC", b"OggS", b"\x1a\x45\xdf\xa3\x01", b"II*\0\x08\0\0\0", b"%PDF-1.4 /Info 1 0 R"] {
                let d = [prefix, &junk[..]].concat();
                let _ = extract(t, &d);
                let _ = extract(t, &d[..d.len().min(40)]);
            }
        }
    }
}
