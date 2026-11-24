//! The `maxfile` URI scheme: `/<sessionId>/<fileId>[?thumb=<px>]`. Streams a found file's bytes
//! (Range → 206 for media seeking) or a JPEG thumbnail. Work runs off the IPC thread.

use super::util::{kind, FileRead, Kind, RandomRead};
use crate::scan::store;
use tauri::http::{header, Response, StatusCode};

/// Largest body for a single response to a Range request (the media stack asks again).
pub const MAX_CHUNK: u64 = 8 << 20;
/// Largest body sent for a request without Range (images, PDFs, documents).
pub const MAX_FULL: u64 = 512 << 20;

#[derive(Debug, PartialEq)]
pub struct Req {
    pub session: String,
    pub id: i64,
    pub thumb: Option<u32>,
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| (c as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse the URL path and query.
pub fn parse_request(path: &str, query: Option<&str>) -> Result<Req, String> {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() != 2 {
        return Err("The address should be /<session>/<file>.".into());
    }
    let session = pct_decode(parts[0]);
    if session.is_empty() || session.contains("..") || session.chars().any(|c| matches!(c, '\\' | '/' | ':')) {
        return Err("That session id isn't valid.".into());
    }
    let id: i64 = pct_decode(parts[1]).parse().map_err(|_| "That file id isn't valid.".to_string())?;
    let mut thumb = None;
    for kv in query.unwrap_or("").split('&') {
        if let Some(v) = kv.strip_prefix("thumb=") {
            let px: u32 = v.parse().map_err(|_| "The thumbnail size isn't a number.".to_string())?;
            thumb = Some(px.clamp(64, 512));
        }
    }
    Ok(Req { session, id, thumb })
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Range {
    /// No (usable) Range header.
    Full,
    /// Inclusive byte range.
    Part(u64, u64),
    Unsatisfiable,
}

/// Parse a `Range` header against a file of `size` bytes (first range only; capped at MAX_CHUNK).
pub fn parse_range(h: Option<&str>, size: u64) -> Range {
    let Some(h) = h else { return Range::Full };
    let Some(spec) = h.trim().strip_prefix("bytes=") else { return Range::Full };
    let first = spec.split(',').next().unwrap_or("").trim();
    let Some((a, b)) = first.split_once('-') else { return Range::Full };
    let (a, b) = (a.trim(), b.trim());
    let (start, end) = if a.is_empty() {
        // Suffix: last n bytes.
        let Ok(n) = b.parse::<u64>() else { return Range::Full };
        if n == 0 || size == 0 {
            return Range::Unsatisfiable;
        }
        (size.saturating_sub(n), size - 1)
    } else {
        let Ok(s) = a.parse::<u64>() else { return Range::Full };
        if s >= size {
            return Range::Unsatisfiable;
        }
        let e = if b.is_empty() {
            size - 1
        } else {
            match b.parse::<u64>() {
                Ok(e) if e >= s => e.min(size - 1),
                _ => return Range::Full,
            }
        };
        (s, e)
    };
    Range::Part(start, end.min(start + MAX_CHUNK - 1))
}

pub fn content_range(start: u64, end: u64, size: u64) -> String {
    format!("bytes {start}-{end}/{size}")
}

/// MIME type for a found file's type id.
pub fn mime_for(type_id: &str) -> String {
    let id = type_id.to_ascii_lowercase();
    // Recovered markup is shown as text, never rendered as a page.
    if matches!(kind(&id), Kind::Html | Kind::Text) {
        return "text/plain; charset=utf-8".into();
    }
    match id.as_str() {
        // WebView2 plays H.264/AAC QuickTime files when they're served as MP4.
        "mov" | "qt" | "m4v" | "3gp" => return "video/mp4".into(),
        "m4a" | "m4b" => return "audio/mp4".into(),
        _ => {}
    }
    if let Some(t) = crate::formats::by_id(&id) {
        if !t.mime.is_empty() {
            return t.mime.to_string();
        }
    }
    match kind(&id) {
        Kind::Csv => "text/plain; charset=utf-8".into(),
        _ => "application/octet-stream".into(),
    }
}

fn base(status: StatusCode) -> tauri::http::response::Builder {
    Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(header::ACCESS_CONTROL_EXPOSE_HEADERS, "Content-Range, Content-Length, Accept-Ranges")
        .header("X-Content-Type-Options", "nosniff")
}

pub fn text(status: u16, msg: &str) -> Response<Vec<u8>> {
    base(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(msg.as_bytes().to_vec())
        .unwrap()
}

/// Serve one request. `head` = HEAD (no body).
pub fn handle(method: &str, path: &str, query: Option<&str>, range: Option<&str>) -> Response<Vec<u8>> {
    if method == "OPTIONS" {
        return base(StatusCode::NO_CONTENT)
            .header(header::ACCESS_CONTROL_ALLOW_METHODS, "GET, HEAD, OPTIONS")
            .header(header::ACCESS_CONTROL_ALLOW_HEADERS, "Range")
            .body(Vec::new())
            .unwrap();
    }
    let head = method == "HEAD";
    let req = match parse_request(path, query) {
        Ok(r) => r,
        Err(e) => return text(400, &e),
    };
    let f = match store::get_file(&req.session, req.id) {
        Ok(f) => f,
        Err(_) => return text(404, "That file isn't in this session."),
    };
    let src = if f.live_path.is_none() && f.resident.is_none() {
        match store::open_session_source(&req.session) {
            Ok(s) => Some(s),
            Err(e) => return text(503, &e),
        }
    } else {
        None
    };
    let rr = FileRead::new(src.as_deref(), &f);

    if let Some(px) = req.thumb {
        let t = super::thumb::cached(&req.session, req.id, px, || super::thumb::make(&f.type_id, &rr, px));
        return match t.as_ref() {
            Some(j) => base(StatusCode::OK)
                .header(header::CONTENT_TYPE, "image/jpeg")
                .header(header::CONTENT_LENGTH, j.len())
                .body(if head { Vec::new() } else { j.clone() })
                .unwrap(),
            None => text(404, "There's no preview for this file."),
        };
    }

    let size = f.size;
    let mime = mime_for(&f.type_id);
    let (status, start, end) = match parse_range(range, size) {
        Range::Unsatisfiable => {
            return base(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(header::CONTENT_RANGE, format!("bytes */{size}"))
                .header(header::ACCEPT_RANGES, "bytes")
                .body(Vec::new())
                .unwrap()
        }
        Range::Part(s, e) => (StatusCode::PARTIAL_CONTENT, s, e),
        Range::Full if size == 0 => (StatusCode::OK, 0, 0),
        Range::Full if size > MAX_FULL => (StatusCode::PARTIAL_CONTENT, 0, MAX_CHUNK.min(size) - 1),
        Range::Full => (StatusCode::OK, 0, size - 1),
    };
    let len = if size == 0 { 0 } else { end - start + 1 };
    let body = if head || len == 0 { Vec::new() } else { rr.read_vec(start, len as usize) };
    if !head && body.len() as u64 != len {
        return text(500, "Part of this file couldn't be read.");
    }
    let mut b = base(status).header(header::CONTENT_TYPE, mime).header(header::ACCEPT_RANGES, "bytes").header(header::CONTENT_LENGTH, len);
    if status == StatusCode::PARTIAL_CONTENT {
        b = b.header(header::CONTENT_RANGE, content_range(start, end, size));
    }
    if kind(&f.type_id) == Kind::Svg {
        // SVG may carry scripts: allow it as an image, never as an active document.
        b = b.header(header::CONTENT_SECURITY_POLICY, "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox");
    }
    if rr.bad.get() {
        b = b.header("X-Max-Bad-Sectors", "1");
    }
    b.body(body).unwrap()
}

/// Entry point registered in main.rs.
pub fn protocol<R: tauri::Runtime>(_ctx: tauri::UriSchemeContext<'_, R>, request: tauri::http::Request<Vec<u8>>, responder: tauri::UriSchemeResponder) {
    let method = request.method().as_str().to_string();
    let path = request.uri().path().to_string();
    let query = request.uri().query().map(str::to_string);
    let range = request.headers().get(header::RANGE).and_then(|v| v.to_str().ok()).map(str::to_string);
    tauri::async_runtime::spawn_blocking(move || {
        let resp = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle(&method, &path, query.as_deref(), range.as_deref())))
            .unwrap_or_else(|_| text(500, "MAX couldn't read this file."));
        responder.respond(resp);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests() {
        assert_eq!(parse_request("/abc-123/42", None), Ok(Req { session: "abc-123".into(), id: 42, thumb: None }));
        assert_eq!(parse_request("/s%201/7", Some("thumb=1000")).unwrap(), Req { session: "s 1".into(), id: 7, thumb: Some(512) });
        assert_eq!(parse_request("/s/7", Some("x=1&thumb=10")).unwrap().thumb, Some(64));
        assert!(parse_request("/s/x", None).is_err());
        assert!(parse_request("/s", None).is_err());
        assert!(parse_request("/../7", None).is_err());
        assert!(parse_request("/s/7", Some("thumb=big")).is_err());
    }

    #[test]
    fn ranges() {
        assert_eq!(parse_range(None, 100), Range::Full);
        assert_eq!(parse_range(Some("bytes=0-"), 100), Range::Part(0, 99));
        assert_eq!(parse_range(Some("bytes=10-19"), 100), Range::Part(10, 19));
        assert_eq!(parse_range(Some("bytes=90-200"), 100), Range::Part(90, 99));
        assert_eq!(parse_range(Some("bytes=-30"), 100), Range::Part(70, 99));
        assert_eq!(parse_range(Some("bytes=-300"), 100), Range::Part(0, 99));
        assert_eq!(parse_range(Some("bytes=100-"), 100), Range::Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=5-1"), 100), Range::Full);
        assert_eq!(parse_range(Some("items=0-1"), 100), Range::Full);
        assert_eq!(parse_range(Some("bytes=0-1, 5-6"), 100), Range::Part(0, 1));
        let big = 10 * MAX_CHUNK;
        assert_eq!(parse_range(Some("bytes=0-"), big), Range::Part(0, MAX_CHUNK - 1));
        assert_eq!(content_range(0, 9, 100), "bytes 0-9/100");
        assert_eq!(mime_for("mov"), "video/mp4");
        assert_eq!(mime_for("jpg"), "image/jpeg");
        assert_eq!(mime_for("weird"), "application/octet-stream");
        assert_eq!(mime_for("html"), "text/plain; charset=utf-8");
    }

    #[test]
    fn errors_are_short_texts() {
        let r = handle("GET", "/nope", None, None);
        assert_eq!(r.status(), 400);
        let r = handle("OPTIONS", "/s/1", None, None);
        assert_eq!(r.status(), 204);
    }
}
