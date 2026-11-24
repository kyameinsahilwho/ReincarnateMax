//! A tiny, tolerant XML tokenizer: enough for Office/ODF parts and XMP. Never fails; malformed
//! input just yields fewer or odd tokens. Names keep their prefix ("w:t").

#[derive(Debug, PartialEq)]
pub enum Tok<'a> {
    /// `<name attrs>` (self_closing for `<name/>`). `attrs` is the raw attribute text.
    Start { name: &'a str, attrs: &'a str, self_closing: bool },
    End { name: &'a str },
    /// Raw text between tags (entities not decoded), or CDATA content.
    Text(&'a str, bool),
}

pub struct Scanner<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Scanner<'a> {
    pub fn new(s: &'a str) -> Self {
        Scanner { s, pos: 0 }
    }
}

impl<'a> Iterator for Scanner<'a> {
    type Item = Tok<'a>;
    fn next(&mut self) -> Option<Tok<'a>> {
        let s = self.s;
        loop {
            if self.pos >= s.len() {
                return None;
            }
            let rest = &s[self.pos..];
            if !rest.starts_with('<') {
                let end = rest.find('<').unwrap_or(rest.len());
                self.pos += end;
                return Some(Tok::Text(&rest[..end], false));
            }
            if let Some(r) = rest.strip_prefix("<!--") {
                self.pos += 4 + r.find("-->").map_or(r.len(), |i| i + 3);
                continue;
            }
            if let Some(r) = rest.strip_prefix("<![CDATA[") {
                let end = r.find("]]>").unwrap_or(r.len());
                self.pos += 9 + (end + 3).min(r.len());
                return Some(Tok::Text(&r[..end], true));
            }
            if rest.starts_with("<?") || rest.starts_with("<!") {
                self.pos += rest.find('>').map_or(rest.len(), |i| i + 1);
                continue;
            }
            // A tag. Find its end, honouring quoted attribute values.
            let b = rest.as_bytes();
            let mut i = 1;
            let mut q = 0u8;
            while i < b.len() {
                let c = b[i];
                if q != 0 {
                    if c == q {
                        q = 0;
                    }
                } else if c == b'"' || c == b'\'' {
                    q = c;
                } else if c == b'>' {
                    break;
                }
                i += 1;
            }
            let inner = &rest[1..i.min(rest.len())];
            self.pos += (i + 1).min(rest.len());
            if let Some(n) = inner.strip_prefix('/') {
                return Some(Tok::End { name: n.trim() });
            }
            let self_closing = inner.ends_with('/');
            let inner = inner.trim_end_matches('/');
            let name_end = inner.find(|c: char| c.is_whitespace()).unwrap_or(inner.len());
            return Some(Tok::Start { name: &inner[..name_end], attrs: &inner[name_end..], self_closing });
        }
    }
}

/// Value of attribute `key` (exact, with prefix) in raw attribute text, entities decoded.
pub fn attr(attrs: &str, key: &str) -> Option<String> {
    let b = attrs.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let ns = i;
        while i < b.len() && b[i] != b'=' && !b[i].is_ascii_whitespace() {
            i += 1;
        }
        let name = &attrs[ns..i];
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() || b[i] != b'=' {
            if i == ns {
                i += 1;
            }
            continue;
        }
        i += 1;
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let q = b[i];
        let (vs, ve);
        if q == b'"' || q == b'\'' {
            vs = i + 1;
            let mut j = vs;
            while j < b.len() && b[j] != q {
                j += 1;
            }
            ve = j;
            i = j + 1;
        } else {
            vs = i;
            while i < b.len() && !b[i].is_ascii_whitespace() {
                i += 1;
            }
            ve = i;
        }
        if name == key {
            return Some(unescape(&attrs[vs..ve.min(attrs.len())]));
        }
    }
    None
}

/// Decode the five XML entities and numeric character references.
pub fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let end = rest.as_bytes()[..rest.len().min(12)].iter().position(|&c| c == b';');
        let Some(end) = end else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let ent = &rest[1..end];
        let ch = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some('\u{a0}'),
            _ if ent.starts_with("#x") || ent.starts_with("#X") => u32::from_str_radix(&ent[2..], 16).ok().and_then(char::from_u32),
            _ if ent.starts_with('#') => ent[1..].parse::<u32>().ok().and_then(char::from_u32),
            _ => None,
        };
        match ch {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Local part of a prefixed name ("w:t" -> "t").
pub fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

/// Text content of the first element named `name` (exact, with prefix); nested tags are skipped.
pub fn first_text(xml: &str, name: &str) -> Option<String> {
    let mut depth = 0usize;
    let mut out = String::new();
    for t in Scanner::new(xml) {
        match t {
            Tok::Start { name: n, self_closing, .. } => {
                if depth > 0 {
                    if !self_closing {
                        depth += 1;
                    }
                } else if n == name && !self_closing {
                    depth = 1;
                }
            }
            Tok::End { .. } if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    return Some(out.trim().to_string());
                }
            }
            Tok::Text(t, cdata) if depth > 0 => out.push_str(&if cdata { t.to_string() } else { unescape(t) }),
            _ => {}
        }
    }
    if depth > 0 && !out.trim().is_empty() {
        return Some(out.trim().to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_tags_attrs_and_text() {
        let x = r#"<?xml version="1.0"?><a:b x="1 &amp; 2" y='q>z'><!-- c --><c/>Hi &lt;there&gt;<![CDATA[<raw>]]></a:b>"#;
        let toks: Vec<Tok> = Scanner::new(x).collect();
        assert!(matches!(toks[0], Tok::Start { name: "a:b", self_closing: false, .. }));
        if let Tok::Start { attrs, .. } = &toks[0] {
            assert_eq!(attr(attrs, "x").as_deref(), Some("1 & 2"));
            assert_eq!(attr(attrs, "y").as_deref(), Some("q>z"));
            assert_eq!(attr(attrs, "z"), None);
        }
        assert!(matches!(toks[1], Tok::Start { name: "c", self_closing: true, .. }));
        assert_eq!(toks[2], Tok::Text("Hi &lt;there&gt;", false));
        assert_eq!(toks[3], Tok::Text("<raw>", true));
        assert_eq!(toks[4], Tok::End { name: "a:b" });
        assert_eq!(first_text(x, "a:b").as_deref(), Some("Hi <there><raw>"));
        assert_eq!(unescape("&#65;&#x42;&bogus;"), "AB&bogus;");
    }
}
