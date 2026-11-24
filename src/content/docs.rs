//! Document text for the preview pane: DOCX/PPTX/XLSX, ODT/ODS/ODP, EPUB, RTF, plain text
//! formats (BOM / UTF-16 detection), HTML (tags stripped), CSV (as a sheet), and approximate text
//! from legacy OLE Office files.

use super::util::*;
use super::xml::{self, Tok};
use super::zipscan::Container;
use super::{DocPreview, Sheet};

pub const MAX_TEXT: usize = 200 * 1024;
pub const MAX_ROWS: usize = 200;
pub const MAX_COLS: usize = 30;

struct Text {
    s: String,
    truncated: bool,
}

impl Text {
    fn new() -> Self {
        Text { s: String::new(), truncated: false }
    }
    fn push(&mut self, t: &str) -> bool {
        if self.truncated {
            return false;
        }
        if self.s.len() + t.len() > MAX_TEXT {
            let mut cut = MAX_TEXT.saturating_sub(self.s.len());
            while cut > 0 && !t.is_char_boundary(cut) {
                cut -= 1;
            }
            self.s.push_str(&t[..cut]);
            self.truncated = true;
            return false;
        }
        self.s.push_str(t);
        true
    }
    fn full(&self) -> bool {
        self.truncated
    }
    fn into_preview(self) -> DocPreview {
        let s = self.s.trim_end().to_string();
        DocPreview { kind: "text".into(), text: Some(s), sheets: Vec::new(), truncated: self.truncated, note: None }
    }
}

pub fn none(note: &str) -> DocPreview {
    DocPreview { kind: "none".into(), text: None, sheets: Vec::new(), truncated: false, note: Some(note.into()) }
}

/// Build a preview from the file's bytes (`complete` = all of the file is in `d`).
pub fn preview(type_id: &str, d: &[u8], complete: bool) -> DocPreview {
    let mut k = kind(type_id);
    if matches!(k, Kind::Other) || (sig_matches(k, d) == Some(false) && !matches!(k, Kind::Text | Kind::Html | Kind::Csv)) {
        if let Some(t) = crate::formats::detect(d) {
            k = kind(t.id);
        }
    }
    let mut p = match k {
        Kind::Ooxml | Kind::Zip => ooxml(type_id, d),
        Kind::Odf => odf(d),
        Kind::Epub => epub(d),
        Kind::Rtf => rtf(d),
        Kind::Html => html(&decode_text(d)),
        Kind::Csv => csv(&decode_text(d), type_id == "tsv"),
        Kind::Text | Kind::Other => {
            if looks_binary(d) {
                none("This file doesn't contain readable text.")
            } else {
                let mut t = Text::new();
                t.push(&decode_text(d));
                t.into_preview()
            }
        }
        Kind::Ole => ole_text(d),
        _ => none("MAX can't show the text of this file type."),
    };
    if !complete && p.kind != "none" {
        p.truncated = true;
    }
    p
}

// --------------------------------------------------------------------------------- plain text

/// BOM / UTF-16 detection, else UTF-8 (lossy, falling back to Windows-1252 when it isn't UTF-8).
pub fn decode_text(d: &[u8]) -> String {
    if let Some(r) = d.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(r).into_owned();
    }
    if let Some(r) = d.strip_prefix(&[0xFF, 0xFE]) {
        return utf16(r, true);
    }
    if let Some(r) = d.strip_prefix(&[0xFE, 0xFF]) {
        return utf16(r, false);
    }
    // UTF-16 without BOM: many zero bytes at odd (LE) or even (BE) positions.
    let n = d.len().min(4096);
    if n >= 16 {
        let odd = d[..n].iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
        let even = d[..n].iter().step_by(2).filter(|&&b| b == 0).count();
        if odd * 10 > n / 2 * 6 && even * 10 < n / 2 {
            return utf16(d, true);
        }
        if even * 10 > n / 2 * 6 && odd * 10 < n / 2 {
            return utf16(d, false);
        }
    }
    match std::str::from_utf8(d) {
        Ok(s) => s.to_string(),
        // A cut in the middle of a multi-byte sequence is still UTF-8.
        Err(e) if e.valid_up_to() + 4 >= d.len() => String::from_utf8_lossy(d).into_owned(),
        Err(e) if e.error_len().is_some() && non_utf8_ratio(d) > 0.01 => d.iter().map(|&b| cp1252_char(b)).collect(),
        Err(_) => String::from_utf8_lossy(d).into_owned(),
    }
}

fn non_utf8_ratio(d: &[u8]) -> f64 {
    let s = String::from_utf8_lossy(&d[..d.len().min(65536)]);
    s.chars().filter(|&c| c == '\u{FFFD}').count() as f64 / s.chars().count().max(1) as f64
}

fn looks_binary(d: &[u8]) -> bool {
    let n = d.len().min(8192);
    if n == 0 {
        return false;
    }
    let s = &d[..n];
    if s.starts_with(&[0xFF, 0xFE]) || s.starts_with(&[0xFE, 0xFF]) {
        return false;
    }
    let zeros = s.iter().filter(|&&b| b == 0).count();
    if zeros * 10 > n * 3 {
        // UTF-16 text has ~50% zeros in a regular pattern; decode_text handles it.
        let odd = s.iter().skip(1).step_by(2).filter(|&&b| b == 0).count();
        let even = s.iter().step_by(2).filter(|&&b| b == 0).count();
        return !(odd * 10 > n / 2 * 6 || even * 10 > n / 2 * 6);
    }
    let ctrl = s.iter().filter(|&&b| b < 0x20 && !matches!(b, b'\n' | b'\r' | b'\t' | 0x0C | 0x1B)).count();
    ctrl * 20 > n
}

// --------------------------------------------------------------------------------------- HTML

pub fn html_to_text(h: &str) -> String {
    let mut out = String::new();
    let mut skip: Option<String> = None;
    for t in xml::Scanner::new(h) {
        match t {
            Tok::Start { name, self_closing, .. } => {
                let n = name.to_ascii_lowercase();
                if skip.is_none() && !self_closing && matches!(n.as_str(), "script" | "style" | "head" | "noscript" | "svg") {
                    skip = Some(n.clone());
                }
                if matches!(n.as_str(), "br" | "p" | "div" | "li" | "tr" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "table" | "ul" | "ol" | "section" | "article") {
                    out.push('\n');
                }
                if n == "td" || n == "th" {
                    out.push('\t');
                }
                if n == "li" {
                    out.push_str("• ");
                }
            }
            Tok::End { name } => {
                let n = name.to_ascii_lowercase();
                if skip.as_deref() == Some(n.as_str()) {
                    skip = None;
                }
                if matches!(n.as_str(), "p" | "div" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "tr" | "table") {
                    out.push('\n');
                }
            }
            Tok::Text(t, _) if skip.is_none() => {
                let t = xml::unescape(t);
                let mut last_space = out.ends_with(|c: char| c.is_whitespace());
                for c in t.chars() {
                    if c.is_whitespace() {
                        if !last_space {
                            out.push(' ');
                            last_space = true;
                        }
                    } else {
                        out.push(c);
                        last_space = false;
                    }
                }
            }
            _ => {}
        }
        if out.len() > MAX_TEXT * 2 {
            break;
        }
    }
    // Collapse runs of blank lines and trim each line.
    let mut res = String::new();
    let mut blank = 0;
    for line in out.lines() {
        let l = line.trim();
        if l.is_empty() {
            blank += 1;
            if blank > 1 {
                continue;
            }
        } else {
            blank = 0;
        }
        res.push_str(l);
        res.push('\n');
    }
    res.trim().to_string()
}

fn html(h: &str) -> DocPreview {
    let mut t = Text::new();
    t.push(&html_to_text(h));
    t.into_preview()
}

// ---------------------------------------------------------------------------------------- CSV

fn csv(s: &str, tabs: bool) -> DocPreview {
    let first = s.lines().next().unwrap_or("");
    let sep = if tabs || first.matches('\t').count() > first.matches(',').count() {
        '\t'
    } else if first.matches(';').count() > first.matches(',').count() {
        ';'
    } else {
        ','
    };
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut cell = String::new();
    let mut q = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if rows.len() >= MAX_ROWS {
            break;
        }
        if q {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    cell.push('"');
                    chars.next();
                } else {
                    q = false;
                }
            } else if cell.len() < 4096 {
                cell.push(c);
            }
            continue;
        }
        match c {
            '"' if cell.is_empty() => q = true,
            c if c == sep => {
                if row.len() < MAX_COLS {
                    row.push(std::mem::take(&mut cell));
                } else {
                    cell.clear();
                }
            }
            '\r' => {}
            '\n' => {
                if row.len() < MAX_COLS {
                    row.push(std::mem::take(&mut cell));
                }
                cell.clear();
                rows.push(std::mem::take(&mut row));
            }
            c if cell.len() < 4096 => cell.push(c),
            _ => {}
        }
    }
    if (!cell.is_empty() || !row.is_empty()) && rows.len() < MAX_ROWS {
        if row.len() < MAX_COLS {
            row.push(cell);
        }
        rows.push(row);
    }
    let truncated = rows.len() >= MAX_ROWS;
    let mut t = Text::new();
    t.push(s);
    DocPreview { kind: "sheet".into(), text: Some(t.s), sheets: vec![Sheet { name: "Sheet1".into(), rows }], truncated: truncated || t.truncated, note: None }
}

// --------------------------------------------------------------------------------------- OOXML

/// Paragraph text from WordprocessingML / DrawingML: `t` runs, tabs, breaks, paragraph ends.
fn ooxml_text(x: &str, t: &mut Text, para: &str) {
    let mut in_t = false;
    let mut line = String::new();
    for tok in xml::Scanner::new(x) {
        match tok {
            Tok::Start { name, self_closing, .. } => match xml::local(name) {
                "t" if !self_closing => in_t = true,
                "tab" => line.push('\t'),
                "br" | "cr" => line.push('\n'),
                _ => {}
            },
            Tok::End { name } => {
                let l = xml::local(name);
                if l == "t" {
                    in_t = false;
                } else if name == para {
                    line.push('\n');
                    if !t.push(&line) {
                        return;
                    }
                    line.clear();
                }
            }
            Tok::Text(s, cdata) if in_t => line.push_str(&if cdata { s.to_string() } else { xml::unescape(s) }),
            _ => {}
        }
    }
    t.push(&line);
}

fn numbered(names: &[String], prefix: &str, suffix: &str) -> Vec<String> {
    let mut v: Vec<(u32, String)> = names
        .iter()
        .filter_map(|n| {
            let mid = n.strip_prefix(prefix)?.strip_suffix(suffix)?;
            Some((mid.parse().ok()?, n.clone()))
        })
        .collect();
    v.sort();
    v.into_iter().map(|(_, n)| n).collect()
}

fn ooxml(type_id: &str, d: &[u8]) -> DocPreview {
    let Some(mut c) = Container::open(d) else { return none("Its contents can't be read — the archive is damaged.") };
    let names = c.names();
    let has = |n: &str| names.iter().any(|x| x == n);
    if has("word/document.xml") || type_id.starts_with("doc") {
        let mut t = Text::new();
        if let Some(x) = c.read_string("word/document.xml", 64 << 20) {
            ooxml_text(&x, &mut t, "w:p");
        }
        return if t.s.trim().is_empty() { none("No text could be read from it.") } else { t.into_preview() };
    }
    if has("xl/workbook.xml") || type_id.starts_with("xl") {
        return xlsx(&mut c, &names);
    }
    if names.iter().any(|n| n.starts_with("ppt/slides/slide")) || type_id.starts_with("pp") || type_id.starts_with("po") {
        let mut t = Text::new();
        for (i, s) in numbered(&names, "ppt/slides/slide", ".xml").iter().enumerate() {
            if !t.push(&format!("— Slide {} —\n", i + 1)) {
                break;
            }
            if let Some(x) = c.read_string(s, 16 << 20) {
                ooxml_text(&x, &mut t, "a:p");
            }
            t.push("\n");
            if t.full() {
                break;
            }
        }
        return t.into_preview();
    }
    if names.iter().any(|n| n == "content.xml") {
        return odf(d);
    }
    let mut t = Text::new();
    t.push(&format!("{} items:\n", names.len()));
    for n in names.iter().take(2000) {
        if !t.push(&format!("{n}\n")) {
            break;
        }
    }
    t.into_preview()
}

/// "BC12" -> column 54 (0-based), row 11 (0-based).
pub fn cell_ref(r: &str) -> Option<(usize, usize)> {
    let mut col = 0usize;
    let mut i = 0;
    for ch in r.chars() {
        if ch.is_ascii_alphabetic() {
            col = col * 26 + (ch.to_ascii_uppercase() as usize - 'A' as usize + 1);
            i += 1;
            if i > 3 {
                return None;
            }
        } else {
            break;
        }
    }
    if col == 0 {
        return None;
    }
    let row: usize = r[i..].parse().ok()?;
    Some((col - 1, row.checked_sub(1)?))
}

fn xlsx(c: &mut Container, names: &[String]) -> DocPreview {
    // Shared strings.
    let mut shared: Vec<String> = Vec::new();
    if let Some(x) = c.read_string("xl/sharedStrings.xml", 64 << 20) {
        let mut cur = String::new();
        let mut in_t = false;
        let mut in_rph = false;
        for tok in xml::Scanner::new(&x) {
            match tok {
                Tok::Start { name, self_closing, .. } => match xml::local(name) {
                    "si" => cur.clear(),
                    "t" if !self_closing => in_t = true,
                    "rPh" => in_rph = true,
                    _ => {}
                },
                Tok::End { name } => match xml::local(name) {
                    "si" => {
                        shared.push(std::mem::take(&mut cur));
                        if shared.len() > 2_000_000 {
                            break;
                        }
                    }
                    "t" => in_t = false,
                    "rPh" => in_rph = false,
                    _ => {}
                },
                Tok::Text(s, _) if in_t && !in_rph => cur.push_str(&xml::unescape(s)),
                _ => {}
            }
        }
    }
    // Sheet names and their parts.
    let mut sheets_meta: Vec<(String, String)> = Vec::new();
    let rels: Vec<(String, String)> = c
        .read_string("xl/_rels/workbook.xml.rels", 1 << 20)
        .map(|x| {
            xml::Scanner::new(&x)
                .filter_map(|t| match t {
                    Tok::Start { name, attrs, .. } if xml::local(name) == "Relationship" => Some((xml::attr(attrs, "Id")?, xml::attr(attrs, "Target")?)),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    if let Some(x) = c.read_string("xl/workbook.xml", 4 << 20) {
        for t in xml::Scanner::new(&x) {
            if let Tok::Start { name, attrs, .. } = t {
                if xml::local(name) == "sheet" {
                    let nm = xml::attr(attrs, "name").unwrap_or_default();
                    let rid = xml::attr(attrs, "r:id").unwrap_or_default();
                    if let Some((_, target)) = rels.iter().find(|(id, _)| *id == rid) {
                        let path = if let Some(abs) = target.strip_prefix('/') { abs.to_string() } else { format!("xl/{}", target.trim_start_matches("./")) };
                        sheets_meta.push((nm, path));
                    }
                }
            }
        }
    }
    if sheets_meta.is_empty() {
        for (i, n) in numbered(names, "xl/worksheets/sheet", ".xml").into_iter().enumerate() {
            sheets_meta.push((format!("Sheet{}", i + 1), n));
        }
    }
    let mut sheets = Vec::new();
    let mut truncated = false;
    for (nm, path) in sheets_meta.into_iter().take(50) {
        let Some(x) = c.read_string(&path, 64 << 20) else { continue };
        let (rows, cut) = sheet_rows(&x, &shared);
        truncated |= cut;
        sheets.push(Sheet { name: nm, rows });
    }
    if sheets.is_empty() {
        return none("No sheets could be read from it.");
    }
    DocPreview { kind: "sheet".into(), text: None, sheets, truncated, note: None }
}

fn sheet_rows(x: &str, shared: &[String]) -> (Vec<Vec<String>>, bool) {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut truncated = false;
    let mut row_idx = 0usize;
    let mut col_idx = 0usize;
    let mut cell_type = String::new();
    let mut val = String::new();
    let mut in_v = false;
    let mut in_cell = false;
    for tok in xml::Scanner::new(x) {
        match tok {
            Tok::Start { name, attrs, self_closing } => match xml::local(name) {
                "row" => {
                    row_idx = xml::attr(attrs, "r").and_then(|r| r.parse::<usize>().ok()).map(|r| r.saturating_sub(1)).unwrap_or(row_idx);
                    col_idx = 0;
                    if row_idx >= MAX_ROWS {
                        truncated = true;
                        break;
                    }
                }
                "c" => {
                    if let Some((c, r)) = xml::attr(attrs, "r").and_then(|r| cell_ref(&r)) {
                        col_idx = c;
                        row_idx = r;
                    }
                    cell_type = xml::attr(attrs, "t").unwrap_or_default();
                    val.clear();
                    in_cell = !self_closing;
                    if self_closing {
                        col_idx += 1;
                    }
                }
                "v" | "t" if in_cell && !self_closing => in_v = true,
                _ => {}
            },
            Tok::End { name } => match xml::local(name) {
                "v" | "t" => in_v = false,
                "c" if in_cell => {
                    in_cell = false;
                    let text = match cell_type.as_str() {
                        "s" => val.trim().parse::<usize>().ok().and_then(|i| shared.get(i)).cloned().unwrap_or_default(),
                        "b" => if val.trim() == "1" { "TRUE".into() } else { "FALSE".into() },
                        _ => val.clone(),
                    };
                    if row_idx < MAX_ROWS && col_idx < MAX_COLS && !text.is_empty() {
                        if rows.len() <= row_idx {
                            rows.resize(row_idx + 1, Vec::new());
                        }
                        let r = &mut rows[row_idx];
                        if r.len() <= col_idx {
                            r.resize(col_idx + 1, String::new());
                        }
                        r[col_idx] = text.chars().take(2000).collect();
                    } else if col_idx >= MAX_COLS {
                        truncated = true;
                    }
                    col_idx += 1;
                }
                "row" => row_idx += 1,
                _ => {}
            },
            Tok::Text(s, _) if in_v => val.push_str(&xml::unescape(s)),
            _ => {}
        }
    }
    (rows, truncated)
}

// ----------------------------------------------------------------------------------------- ODF

fn odf(d: &[u8]) -> DocPreview {
    let Some(mut c) = Container::open(d) else { return none("Its contents can't be read — the archive is damaged.") };
    let Some(x) = c.read_string("content.xml", 64 << 20) else { return none("No text could be read from it.") };
    if x.contains("<table:table ") && x.contains("office:spreadsheet") {
        return ods(&x);
    }
    let mut t = Text::new();
    let mut depth_p = 0usize;
    let mut line = String::new();
    for tok in xml::Scanner::new(&x) {
        match tok {
            Tok::Start { name, attrs, self_closing } => match name {
                "text:p" | "text:h" if !self_closing => depth_p += 1,
                "text:p" | "text:h" => {
                    if !t.push("\n") {
                        break;
                    }
                }
                "text:s" if depth_p > 0 => {
                    let n = xml::attr(attrs, "text:c").and_then(|v| v.parse::<usize>().ok()).unwrap_or(1).min(100);
                    line.push_str(&" ".repeat(n));
                }
                "text:tab" if depth_p > 0 => line.push('\t'),
                "text:line-break" if depth_p > 0 => line.push('\n'),
                _ => {}
            },
            Tok::End { name: "text:p" | "text:h" } => {
                depth_p = depth_p.saturating_sub(1);
                if depth_p == 0 {
                    line.push('\n');
                    if !t.push(&line) {
                        break;
                    }
                    line.clear();
                }
            }
            Tok::Text(s, _) if depth_p > 0 => line.push_str(&xml::unescape(s)),
            _ => {}
        }
    }
    t.push(&line);
    if t.s.trim().is_empty() {
        return none("No text could be read from it.");
    }
    t.into_preview()
}

fn ods(x: &str) -> DocPreview {
    let mut sheets: Vec<Sheet> = Vec::new();
    let mut truncated = false;
    let mut row: Vec<String> = Vec::new();
    let mut cell = String::new();
    let mut in_cell = false;
    let mut col_repeat = 1usize;
    let mut row_repeat = 1usize;
    for tok in xml::Scanner::new(x) {
        match tok {
            Tok::Start { name, attrs, self_closing } => match name {
                "table:table" => sheets.push(Sheet { name: xml::attr(attrs, "table:name").unwrap_or_default(), rows: Vec::new() }),
                "table:table-row" => {
                    row.clear();
                    row_repeat = xml::attr(attrs, "table:number-rows-repeated").and_then(|v| v.parse().ok()).unwrap_or(1);
                }
                "table:table-cell" | "table:covered-table-cell" => {
                    col_repeat = xml::attr(attrs, "table:number-columns-repeated").and_then(|v| v.parse().ok()).unwrap_or(1);
                    cell.clear();
                    if self_closing {
                        for _ in 0..col_repeat.min(MAX_COLS) {
                            if row.len() < MAX_COLS {
                                row.push(String::new());
                            }
                        }
                    } else {
                        in_cell = true;
                    }
                }
                "text:p" if in_cell && !cell.is_empty() => cell.push('\n'),
                _ => {}
            },
            Tok::End { name } => match name {
                "table:table-cell" | "table:covered-table-cell" => {
                    in_cell = false;
                    for _ in 0..col_repeat.min(MAX_COLS) {
                        if row.len() < MAX_COLS {
                            row.push(cell.clone());
                        } else {
                            truncated |= !cell.is_empty();
                        }
                    }
                }
                "table:table-row" => {
                    while row.last().is_some_and(|c| c.is_empty()) {
                        row.pop();
                    }
                    if let Some(s) = sheets.last_mut() {
                        for _ in 0..row_repeat.min(MAX_ROWS) {
                            if s.rows.len() < MAX_ROWS {
                                s.rows.push(row.clone());
                            } else if !row.is_empty() {
                                truncated = true;
                            }
                        }
                    }
                }
                "table:table" => {
                    if let Some(s) = sheets.last_mut() {
                        while s.rows.last().is_some_and(|r| r.is_empty()) {
                            s.rows.pop();
                        }
                    }
                }
                _ => {}
            },
            Tok::Text(s, _) if in_cell => cell.push_str(&xml::unescape(s)),
            _ => {}
        }
        if sheets.len() > 50 {
            break;
        }
    }
    DocPreview { kind: "sheet".into(), text: None, sheets, truncated, note: None }
}

// ---------------------------------------------------------------------------------------- EPUB

fn epub(d: &[u8]) -> DocPreview {
    let Some(mut c) = Container::open(d) else { return none("Its contents can't be read — the archive is damaged.") };
    let mut names: Vec<String> = c.names().into_iter().filter(|n| n.ends_with(".xhtml") || n.ends_with(".html") || n.ends_with(".htm")).collect();
    names.sort();
    let mut t = Text::new();
    for n in names.iter().take(500) {
        if let Some(h) = c.read_string(n, 8 << 20) {
            if !t.push(&html_to_text(&h)) || !t.push("\n\n") {
                break;
            }
        }
    }
    t.into_preview()
}

// ----------------------------------------------------------------------------------------- RTF

pub fn rtf_to_text(d: &[u8]) -> String {
    const SKIP: [&str; 12] = ["fonttbl", "colortbl", "stylesheet", "info", "pict", "header", "footer", "listtable", "listoverridetable", "rsidtbl", "themedata", "xmlnstbl"];
    let mut out = String::new();
    // Stack of (skip, unicode-skip-count) per group.
    let mut stack: Vec<(bool, usize)> = vec![(false, 1)];
    let mut pending_skip = 0usize;
    let mut i = 0;
    let mut group_start = false;
    while i < d.len() && out.len() < MAX_TEXT * 2 {
        let c = d[i];
        let (skipping, uc) = *stack.last().unwrap();
        match c {
            b'{' => {
                stack.push((skipping, uc));
                if stack.len() > 512 {
                    stack.truncate(512);
                }
                group_start = true;
                i += 1;
                continue;
            }
            b'}' => {
                if stack.len() > 1 {
                    stack.pop();
                }
                i += 1;
            }
            b'\\' => {
                i += 1;
                let Some(&n) = d.get(i) else { break };
                if n.is_ascii_alphabetic() {
                    let s = i;
                    while i < d.len() && d[i].is_ascii_alphabetic() && i - s < 32 {
                        i += 1;
                    }
                    let word = std::str::from_utf8(&d[s..i]).unwrap_or("");
                    let ns = i;
                    if i < d.len() && (d[i] == b'-' || d[i].is_ascii_digit()) {
                        i += 1;
                        while i < d.len() && d[i].is_ascii_digit() && i - ns < 11 {
                            i += 1;
                        }
                    }
                    let param: Option<i64> = std::str::from_utf8(&d[ns..i]).ok().and_then(|s| s.parse().ok());
                    if i < d.len() && d[i] == b' ' {
                        i += 1;
                    }
                    if group_start && SKIP.contains(&word) {
                        stack.last_mut().unwrap().0 = true;
                    }
                    if skipping || stack.last().unwrap().0 {
                        group_start = false;
                        continue;
                    }
                    match word {
                        "par" | "line" | "row" | "sect" | "page" => out.push('\n'),
                        "tab" | "cell" => out.push('\t'),
                        "emdash" => out.push('—'),
                        "endash" => out.push('–'),
                        "bullet" => out.push('•'),
                        "lquote" => out.push('‘'),
                        "rquote" => out.push('’'),
                        "ldblquote" => out.push('“'),
                        "rdblquote" => out.push('”'),
                        "uc" => stack.last_mut().unwrap().1 = param.unwrap_or(1).clamp(0, 8) as usize,
                        "u" => {
                            if let Some(p) = param {
                                let v = if p < 0 { p + 65536 } else { p } as u32;
                                out.push(char::from_u32(v).unwrap_or('\u{FFFD}'));
                                pending_skip = uc;
                            }
                        }
                        _ => {}
                    }
                } else {
                    i += 1;
                    match n {
                        b'*' if group_start => stack.last_mut().unwrap().0 = true,
                        b'\'' => {
                            let h = d.get(i..i + 2).and_then(|h| std::str::from_utf8(h).ok()).and_then(|h| u8::from_str_radix(h, 16).ok());
                            i += 2;
                            if let Some(b) = h {
                                if pending_skip > 0 {
                                    pending_skip -= 1;
                                } else if !skipping {
                                    out.push(cp1252_char(b));
                                }
                            }
                        }
                        b'\\' | b'{' | b'}' if !skipping => out.push(n as char),
                        b'~' if !skipping => out.push('\u{a0}'),
                        b'\n' | b'\r' if !skipping => out.push('\n'),
                        _ => {}
                    }
                }
            }
            b'\r' | b'\n' => i += 1,
            _ => {
                if pending_skip > 0 {
                    pending_skip -= 1;
                } else if !skipping {
                    out.push(cp1252_char(c));
                }
                i += 1;
            }
        }
        group_start = false;
    }
    out
}

fn rtf(d: &[u8]) -> DocPreview {
    let mut t = Text::new();
    t.push(&rtf_to_text(d));
    t.into_preview()
}

// ----------------------------------------------------------------------------------------- OLE

/// Printable UTF-16LE and ASCII runs of at least 4 characters, in file order.
pub fn printable_runs(d: &[u8], max: usize) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < d.len() && out.len() < max {
        // UTF-16LE run? Characters from a few common scripts only, so binary data that happens
        // to decode as CJK or symbols isn't taken for text.
        let mut j = i;
        let mut u = String::new();
        let mut counts = [0usize; 4]; // latin, greek/cyrillic, cjk/hangul, punctuation
        // Misaligned ASCII UTF-16 reads as "CJK" units whose low byte is 0.
        let mut low_zero = 0usize;
        while j + 1 < d.len() && u.len() < 1 << 16 {
            let v = u16::from_le_bytes([d[j], d[j + 1]]);
            let class = match v {
                0x09 | 0x0A | 0x0D | 0x20..=0x7E | 0xA0..=0x24F => 0,
                0x370..=0x52F => 1,
                0x3000..=0x30FF | 0x4E00..=0x9FFF | 0xAC00..=0xD7A3 | 0xFF00..=0xFFEF => 2,
                0x2000..=0x206F | 0x20A0..=0x20BF | 0x2100..=0x215F => 3,
                _ => break,
            };
            counts[class] += 1;
            if v & 0xFF == 0 && v > 0xFF {
                low_zero += 1;
            }
            u.push(char::from_u32(v as u32).unwrap_or(' '));
            j += 2;
        }
        let n = u.chars().count();
        let dominant = counts[..3].iter().copied().max().unwrap_or(0) + counts[3];
        let wordy = u.chars().filter(|c| c.is_alphanumeric()).count() * 2 >= n;
        let ok = n >= 4 && wordy && low_zero * 4 < n && (counts[0] * 4 >= n * 3 && counts[0] >= 4 || n >= 8 && dominant * 4 >= n * 3 && (counts[1] + counts[2]) * 2 >= n);
        if ok {
            out.push_str(&u.replace('\r', "\n"));
            out.push('\n');
            i = j;
            continue;
        }
        // ASCII run?
        let mut k = i;
        while k < d.len() && (d[k] >= 0x20 && d[k] < 0x7F || d[k] == b'\r' || d[k] == b'\n' || d[k] == b'\t') {
            k += 1;
        }
        if k - i >= 4 {
            let s = &d[i..k];
            if s.iter().filter(|c| c.is_ascii_alphanumeric()).count() * 2 >= s.len() {
                out.push_str(&String::from_utf8_lossy(s).replace('\r', "\n"));
                out.push('\n');
            }
            i = k;
            continue;
        }
        i += 1;
    }
    out
}

fn ole_text(d: &[u8]) -> DocPreview {
    let mut t = Text::new();
    t.push(&printable_runs(d, MAX_TEXT));
    let mut p = t.into_preview();
    p.note = Some("This is approximate text pulled from an older Office file — formatting is lost and some fragments may be out of order.".into());
    p
}

#[cfg(test)]
mod tests {
    use super::super::zipscan::tests::make_zip;
    use super::*;

    #[test]
    fn docx_text() {
        let doc = r#"<w:document><w:body><w:p><w:r><w:t>Hello</w:t></w:r><w:r><w:tab/><w:t xml:space="preserve"> world &amp; co</w:t></w:r></w:p><w:p><w:r><w:t>Second</w:t></w:r></w:p></w:body></w:document>"#;
        let z = make_zip(&[("word/document.xml", doc.as_bytes())], true);
        let p = preview("docx", &z, true);
        assert_eq!(p.kind, "text");
        assert_eq!(p.text.as_deref(), Some("Hello\t world & co\nSecond"));
    }

    #[test]
    fn xlsx_cells() {
        let wb = r#"<workbook><sheets><sheet name="Budget" sheetId="1" r:id="rId1"/></sheets></workbook>"#;
        let rels = r#"<Relationships><Relationship Id="rId1" Type="x" Target="worksheets/sheet1.xml"/></Relationships>"#;
        let ss = r#"<sst><si><t>Item</t></si><si><r><t>Co</t></r><r><t>st</t></r></si></sst>"#;
        let sh = r#"<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="C1" t="s"><v>1</v></c></row><row r="3"><c r="A3"><v>42</v></c><c r="B3" t="inlineStr"><is><t>inline</t></is></c><c r="AE3"><v>9</v></c></row></sheetData></worksheet>"#;
        let z = make_zip(&[("xl/workbook.xml", wb.as_bytes()), ("xl/_rels/workbook.xml.rels", rels.as_bytes()), ("xl/sharedStrings.xml", ss.as_bytes()), ("xl/worksheets/sheet1.xml", sh.as_bytes())], true);
        let p = preview("xlsx", &z, true);
        assert_eq!(p.kind, "sheet");
        let s = &p.sheets[0];
        assert_eq!(s.name, "Budget");
        assert_eq!(s.rows[0], vec!["Item", "", "Cost"]);
        assert!(s.rows[1].is_empty());
        assert_eq!(s.rows[2], vec!["42", "inline"]);
        assert!(p.truncated); // AE3 is column 31
        assert_eq!(cell_ref("AE3"), Some((30, 2)));
        assert_eq!(cell_ref("A1"), Some((0, 0)));
    }

    #[test]
    fn pptx_and_odt() {
        let s1 = r#"<p:sld><a:p><a:r><a:t>Title one</a:t></a:r></a:p></p:sld>"#;
        let s2 = r#"<p:sld><a:p><a:r><a:t>Two</a:t></a:r></a:p></p:sld>"#;
        let z = make_zip(&[("ppt/slides/slide10.xml", s2.as_bytes()), ("ppt/slides/slide2.xml", s1.as_bytes())], true);
        let t = preview("pptx", &z, true).text.unwrap();
        assert!(t.find("Title one").unwrap() < t.find("Two").unwrap());

        let c = r#"<office:document-content><office:body><office:text><text:h>Head</text:h><text:p>a<text:s text:c="2"/>b<text:tab/>c</text:p></office:text></office:body></office:document-content>"#;
        let z = make_zip(&[("mimetype", b"application/vnd.oasis.opendocument.text"), ("content.xml", c.as_bytes())], false);
        assert_eq!(preview("odt", &z, true).text.as_deref(), Some("Head\na  b\tc"));

        let c = r#"<office:document-content><office:body><office:spreadsheet><table:table table:name="S1"><table:table-row><table:table-cell><text:p>x</text:p></table:table-cell><table:table-cell table:number-columns-repeated="2"/><table:table-cell><text:p>y</text:p></table:table-cell></table:table-row></table:table></office:spreadsheet></office:body></office:document-content>"#;
        let z = make_zip(&[("content.xml", c.as_bytes())], true);
        let p = preview("ods", &z, true);
        assert_eq!(p.sheets[0].rows[0], vec!["x", "", "", "y"]);
    }

    #[test]
    fn rtf_html_text_csv_ole() {
        let r = br"{\rtf1\ansi{\fonttbl{\f0 Arial;}}{\*\generator X;}\f0 Caf\'e9 \b bold\b0\par Line \u8364? two\tab x\}}";
        assert_eq!(rtf_to_text(r), "Café bold\nLine € two\tx}");
        let h = "<html><head><title>T</title><style>p{}</style></head><body><p>Hi &amp; <b>there</b></p><script>x()</script><ul><li>one</li></ul></body></html>";
        assert_eq!(html_to_text(h), "Hi & there\n\n• one");
        let u16le: Vec<u8> = [0xFF, 0xFE].into_iter().chain("héllo".encode_utf16().flat_map(|u| u.to_le_bytes())).collect();
        assert_eq!(decode_text(&u16le), "héllo");
        let nobom: Vec<u8> = "plain text here".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(decode_text(&nobom), "plain text here");
        assert_eq!(decode_text(b"caf\xe9 au lait"), "café au lait");
        let p = preview("csv", b"a,b,\"c,d\"\n1,\"x\"\"y\",3\n", true);
        assert_eq!(p.sheets[0].rows, vec![vec!["a", "b", "c,d"], vec!["1", "x\"y", "3"]]);
        let mut ole = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0, 0, 1, 2];
        ole.extend("Quarterly numbers".encode_utf16().flat_map(|u| u.to_le_bytes()));
        ole.extend_from_slice(&[0, 0, 5, 6, 7]);
        ole.extend_from_slice(b"Ascii text run");
        let p = preview("doc", &ole, true);
        let t = p.text.unwrap();
        assert!(t.contains("Quarterly numbers") && t.contains("Ascii text run"), "{t}");
        assert!(p.note.is_some());
        // Binary content in a .txt.
        assert_eq!(preview("txt", &[1u8, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9], true).kind, "none");
    }

    #[test]
    fn caps_text() {
        let big = "word ".repeat(100_000);
        let p = preview("txt", big.as_bytes(), true);
        assert!(p.truncated);
        assert!(p.text.unwrap().len() <= MAX_TEXT);
    }
}
