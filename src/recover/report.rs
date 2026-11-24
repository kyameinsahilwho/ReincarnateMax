//! Recovery and scan reports: one self-contained HTML page (light/dark, every value escaped, no
//! external assets) and an RFC 4180 CSV (UTF-8 with BOM so Excel reads it right).

use crate::model::{human_size, Condition};
use std::fmt::Write as _;

pub struct ReportMeta {
    /// "MAX Recovery Report" / "MAX Scan Report"
    pub title: String,
    /// (label, value) pairs shown at the top.
    pub summary: Vec<(String, String)>,
    /// Header of the result column: "Result" (recovery) or "Status" (scan).
    pub result_header: String,
}

#[derive(Clone, Debug, Default)]
pub struct ReportRow {
    pub name: String,
    pub folder: String,
    pub size: u64,
    pub type_label: String,
    pub condition: Condition,
    pub condition_note: String,
    /// "recovered" / "partial" / … or a scan status ("deleted").
    pub result: String,
    pub hash: String,
    pub notes: String,
}

pub fn condition_label(c: Condition) -> &'static str {
    match c {
        Condition::Excellent => "Excellent",
        Condition::Good => "Good",
        Condition::Partial => "Partial",
        Condition::Unknown => "Unknown",
    }
}

pub fn escape_html(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

/// RFC 4180 field: quoted when it contains a comma, quote, CR or LF (quotes doubled). Fields that
/// start with = + - @ get a leading apostrophe so spreadsheets don't run them as formulas.
pub fn csv_field(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@']) { format!("'{s}") } else { s.to_string() };
    if s.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

fn result_class(r: &str) -> &'static str {
    match r {
        "recovered" | "existing" => "ok",
        "partial" | "duplicate skipped" => "warn",
        "repaired" => "info",
        "failed" => "bad",
        _ => "",
    }
}

pub fn html(meta: &ReportMeta, rows: &[ReportRow]) -> String {
    let mut h = String::with_capacity(4096 + rows.len() * 400);
    html_head(&mut h, meta);
    for r in rows {
        html_row(&mut h, r);
    }
    h.push_str(HTML_TAIL);
    h
}

/// End of the HTML page, after the last row.
pub const HTML_TAIL: &str = "</tbody></table></div>\n<footer>Written by MAX File Recovery.</footer>\n</main></body></html>\n";

/// The HTML page up to the first table row (for streaming large reports).
pub fn html_head(h: &mut String, meta: &ReportMeta) {
    let title = escape_html(&meta.title);
    let _ = write!(
        h,
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
:root{{--bg:#f7f7f5;--fg:#1d1d1b;--muted:#66665f;--card:#fff;--line:#e2e2dc;--ok:#1f7a3a;--warn:#9a6200;--bad:#b3261e;--info:#1d5fa8;color-scheme:light dark}}
@media (prefers-color-scheme:dark){{:root{{--bg:#161615;--fg:#ececea;--muted:#a3a39c;--card:#1f1f1d;--line:#34342f;--ok:#6fcf8a;--warn:#f0b54a;--bad:#ff8a80;--info:#8ab8ff}}}}
*{{box-sizing:border-box}}body{{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:14px/1.45 "Segoe UI",system-ui,sans-serif}}
main{{max-width:1200px;margin:0 auto}}h1{{font-size:22px;margin:0 0 16px}}
dl{{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin:0 0 20px}}
dt{{color:var(--muted)}}dd{{margin:0;overflow-wrap:anywhere}}
.wrap{{overflow-x:auto;border:1px solid var(--line);border-radius:8px;background:var(--card)}}
table{{border-collapse:collapse;width:100%}}th,td{{padding:6px 10px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}}
th{{position:sticky;top:0;background:var(--card);font-weight:600;white-space:nowrap}}td.n{{text-align:right;white-space:nowrap}}
td.h{{font-family:Consolas,monospace;font-size:12px;color:var(--muted);overflow-wrap:anywhere;max-width:16em}}
.ok{{color:var(--ok)}}.warn{{color:var(--warn)}}.bad{{color:var(--bad)}}.info{{color:var(--info)}}.m{{color:var(--muted)}}
footer{{color:var(--muted);margin-top:16px;font-size:12px}}
</style></head><body><main>
<h1>{title}</h1>
<dl>
"#
    );
    for (k, v) in &meta.summary {
        let _ = writeln!(h, "<dt>{}</dt><dd>{}</dd>", escape_html(k), escape_html(v));
    }
    let _ = write!(
        h,
        "</dl>\n<div class=\"wrap\"><table>\n<thead><tr><th>File name</th><th>Original folder</th><th>Size</th><th>Type</th><th>Condition</th><th>{}</th><th>BLAKE3</th><th>Notes</th></tr></thead>\n<tbody>\n",
        escape_html(&meta.result_header)
    );
}

/// One HTML table row.
pub fn html_row(h: &mut String, r: &ReportRow) {
    let cond = if r.condition_note.is_empty() {
        escape_html(condition_label(r.condition))
    } else {
        format!("{}<br><span class=\"m\">{}</span>", escape_html(condition_label(r.condition)), escape_html(&r.condition_note))
    };
    let _ = writeln!(
        h,
        "<tr><td>{}</td><td>{}</td><td class=\"n\" title=\"{} bytes\">{}</td><td>{}</td><td>{}</td><td class=\"{}\">{}</td><td class=\"h\">{}</td><td>{}</td></tr>",
        escape_html(&r.name),
        escape_html(&r.folder),
        r.size,
        escape_html(&human_size(r.size)),
        escape_html(&r.type_label),
        cond,
        result_class(&r.result),
        escape_html(&r.result),
        escape_html(&r.hash),
        escape_html(&r.notes),
    );
}

pub fn csv(meta: &ReportMeta, rows: &[ReportRow]) -> Vec<u8> {
    let mut s = String::new();
    csv_head(&mut s, meta);
    for r in rows {
        csv_row(&mut s, r);
    }
    s.into_bytes()
}

fn csv_line(s: &mut String, fields: &[&str]) {
    let v: Vec<String> = fields.iter().map(|f| csv_field(f)).collect();
    s.push_str(&v.join(","));
    s.push_str("\r\n");
}

/// BOM, title, summary and the column header line (for streaming large reports).
pub fn csv_head(s: &mut String, meta: &ReportMeta) {
    s.push('\u{FEFF}');
    csv_line(s, &[&meta.title]);
    for (k, v) in &meta.summary {
        csv_line(s, &[k, v]);
    }
    s.push_str("\r\n");
    csv_line(s, &["File name", "Original folder", "Size (bytes)", "Type", "Condition", "Condition note", &meta.result_header, "BLAKE3", "Notes"]);
}

/// One CSV line.
pub fn csv_row(s: &mut String, r: &ReportRow) {
    let size = r.size.to_string();
    csv_line(s, &[&r.name, &r.folder, &size, &r.type_label, condition_label(r.condition), &r.condition_note, &r.result, &r.hash, &r.notes]);
}

// ------------------------------------------------------------------------------------- dates

#[repr(C)]
#[derive(Default)]
struct SystemTime16 {
    year: u16,
    month: u16,
    dow: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    ms: u16,
}

#[link(name = "kernel32")]
extern "system" {
    fn FileTimeToSystemTime(ft: *const u64, st: *mut SystemTime16) -> i32;
    fn SystemTimeToTzSpecificLocalTime(tz: *const std::ffi::c_void, utc: *const SystemTime16, local: *mut SystemTime16) -> i32;
}

/// "2026-11-24 14:05" in local time (UTC with a "UTC" suffix when the conversion fails).
pub fn local_time(ms: i64) -> String {
    let ft = (ms.max(0) as u64) * 10_000 + 116_444_736_000_000_000;
    let mut utc = SystemTime16::default();
    let mut loc = SystemTime16::default();
    unsafe {
        if FileTimeToSystemTime(&ft, &mut utc) == 0 {
            return String::new();
        }
        if SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut loc) == 0 {
            return format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", utc.year, utc.month, utc.day, utc.hour, utc.minute);
        }
    }
    format!("{:04}-{:02}-{:02} {:02}:{:02}", loc.year, loc.month, loc.day, loc.hour, loc.minute)
}

/// Stream a file atomically: `fill` writes into a temp file in the same folder, which then
/// replaces `path`. The temp file is removed on any error.
pub fn write_atomic_with(path: &std::path::Path, fill: impl FnOnce(&mut std::io::BufWriter<std::fs::File>) -> std::io::Result<()>) -> std::io::Result<()> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = std::path::PathBuf::from(tmp);
    let r = (|| {
        let mut w = std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(&tmp)?);
        fill(&mut w)?;
        w.flush()?;
        drop(w);
        std::fs::rename(&tmp, path)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

/// Write bytes atomically (temp file in the same folder, then replace).
pub fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = std::path::PathBuf::from(tmp);
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (ReportMeta, Vec<ReportRow>) {
        let meta = ReportMeta {
            title: "MAX Recovery Report".into(),
            summary: vec![("Source".into(), "<Drive C:> & \"friends\"".into())],
            result_header: "Result".into(),
        };
        let rows = vec![ReportRow {
            name: "<script>alert('x')</script>.jpg".into(),
            folder: "\\Users\\A&B".into(),
            size: 2048,
            type_label: "JPEG image".into(),
            condition: Condition::Partial,
            condition_note: "Some \"clusters\" are, now, used.".into(),
            result: "partial".into(),
            hash: "ab12".into(),
            notes: "line1\nline2".into(),
        }];
        (meta, rows)
    }

    #[test]
    fn html_escapes_everything() {
        let (m, r) = sample();
        let h = html(&m, &r);
        assert!(!h.contains("<script>"));
        assert!(h.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;.jpg"));
        assert!(h.contains("&lt;Drive C:&gt; &amp; &quot;friends&quot;"));
        assert!(h.contains("\\Users\\A&amp;B"));
        assert!(h.contains("prefers-color-scheme:dark"));
        assert!(!h.contains("http://") && !h.contains("https://"));
        assert!(h.contains("2.0 KB"));
    }

    #[test]
    fn csv_quotes_per_rfc4180() {
        let (m, r) = sample();
        let c = String::from_utf8(csv(&m, &r)).unwrap();
        assert!(c.starts_with('\u{FEFF}'));
        assert!(c.contains("\"Some \"\"clusters\"\" are, now, used.\""));
        assert!(c.contains("\"line1\nline2\""));
        assert!(c.contains("Source,\"<Drive C:> & \"\"friends\"\"\""));
        assert!(c.contains("\r\nFile name,Original folder,Size (bytes),Type,Condition,Condition note,Result,BLAKE3,Notes\r\n"));
        assert_eq!(csv_field("=1+2"), "'=1+2");
        assert_eq!(csv_field("plain"), "plain");
    }

    #[test]
    fn dates_format() {
        let s = local_time(1_704_164_645_000);
        assert!(s.starts_with("2024-01-0"), "{s}");
        assert_eq!(s.len(), 16);
    }
}
