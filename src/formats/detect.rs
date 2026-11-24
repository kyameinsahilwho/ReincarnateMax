//! Content-based type recognition from the first bytes of a file.

use super::sniff::*;

/// Type id recognised from the first bytes of content (ideally >= 4 KiB).
pub(crate) fn detect_id(h: &[u8]) -> Option<&'static str> {
    if h.len() < 4 {
        return None;
    }
    if let Some(t) = binary(h) {
        return Some(t);
    }
    text(h)
}

fn binary(h: &[u8]) -> Option<&'static str> {
    // --- images
    if h.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("jpg");
    }
    if h.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("png");
    }
    if h.starts_with(b"GIF87a") || h.starts_with(b"GIF89a") {
        return Some("gif");
    }
    if h.starts_with(b"%PDF-") {
        return Some("pdf");
    }
    if h.starts_with(b"PK\x03\x04") {
        return Some(zip_detect(h));
    }
    if h.starts_with(b"PK\x05\x06") || h.starts_with(b"PK\x07\x08PK\x03\x04") {
        return Some("zip");
    }
    if h.starts_with(&OLE) {
        return Some(ole_detect(h));
    }
    if at(h, 4, b"ftyp") {
        if let Some(t) = ftyp_kind(h) {
            return Some(t);
        }
    }
    if (h.starts_with(b"RIFF") || h.starts_with(b"RF64")) && h.len() >= 12 {
        match &h[8..12] {
            b"AVI " => return Some("avi"),
            b"WAVE" => return Some("wav"),
            b"WEBP" => return Some("webp"),
            _ => {}
        }
    }
    if h.starts_with(b"FORM") && (at(h, 8, b"AIFF") || at(h, 8, b"AIFC")) {
        return Some("aiff");
    }
    if h.starts_with(b"II*\0") || h.starts_with(b"MM\0*") || h.starts_with(b"IIRO") || h.starts_with(b"IIRS") || h.starts_with(b"MMOR") || h.starts_with(b"IIU\0") {
        let (make, dng) = tiff_ifd0_facts(h);
        return Some(raw_kind(h, make.as_deref(), dng));
    }
    if h.starts_with(b"FUJIFILMCCD-RAW") {
        return Some("raf");
    }
    if h.starts_with(b"FOVb") {
        return Some("x3f");
    }
    if h.starts_with(b"8BPS") && matches!(be16(h, 4), Some(1 | 2)) {
        return Some("psd");
    }
    if h.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        let head = &h[..h.len().min(128)];
        return Some(if find(head, b"webm").is_some() { "webm" } else { "mkv" });
    }
    if h.starts_with(&ASF_HEADER) {
        return Some(asf_kind(h));
    }
    if h.starts_with(b"FLV\x01") {
        return Some("flv");
    }
    if mpeg_ps_ok(h) || h.starts_with(&[0, 0, 1, 0xB3]) {
        return Some("mpg");
    }
    if ts_ok(h, 0, 188, 4) {
        return Some("ts");
    }
    if ts_ok(h, 4, 192, 4) {
        return Some("mts");
    }
    if let Some(n) = id3_len(h) {
        // Some FLAC and AAC files carry an ID3 tag too.
        let n = n as usize;
        if at(h, n, b"fLaC") {
            return Some("flac");
        }
        if h.get(n..).is_some_and(|r| adts_frames(r, 2)) {
            return Some("aac");
        }
        return Some("mp3");
    }
    if h.starts_with(b"fLaC") {
        return Some("flac");
    }
    if h.starts_with(b"OggS") {
        let segs = *h.get(26).unwrap_or(&0) as usize;
        return Some(if at(h, 27 + segs, b"OpusHead") { "opus" } else { "ogg" });
    }
    if h.starts_with(b"#!AMR") {
        return Some("amr");
    }
    if h.starts_with(b"MThd") && be32(h, 4) == Some(6) {
        return Some("mid");
    }
    if h.starts_with(b"{\\rtf") {
        return Some("rtf");
    }
    if h.starts_with(b"!BDN") {
        return Some("pst");
    }
    if h.starts_with(&[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C]) {
        return Some("7z");
    }
    if h.starts_with(b"Rar!\x1a\x07") {
        return Some("rar");
    }
    if h.starts_with(&[0x1F, 0x8B, 0x08]) {
        return Some("gz");
    }
    if h.starts_with(b"BZh") && (b'1'..=b'9').contains(&h[3]) && (at(h, 4, &[0x31, 0x41, 0x59, 0x26, 0x53, 0x59]) || at(h, 4, &[0x17, 0x72, 0x45, 0x38, 0x50, 0x90])) {
        return Some("bz2");
    }
    if h.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0]) {
        return Some("xz");
    }
    if tar_ok(h) {
        return Some("tar");
    }
    if h.starts_with(b"MSCF") && le32(h, 4) == Some(0) {
        return Some("cab");
    }
    if at(h, 0x8001, b"CD001") {
        return Some("iso");
    }
    if h.starts_with(b"SQLite format 3\0") {
        return Some("sqlite");
    }
    if h.starts_with(b"MZ") {
        return match pe_ok(h) {
            Some(true) => Some("dll"),
            Some(false) => Some("exe"),
            // The PE header is beyond the bytes we have, or it's a DOS program.
            None if le32(h, 0x3C).is_some_and(|e| e as usize >= h.len()) => Some("exe"),
            None => None,
        };
    }
    if bmp_ok(h) {
        return Some("bmp");
    }
    if ico_ok(h) {
        return Some("ico");
    }
    if mp3_frames(h, 3) {
        return Some("mp3");
    }
    if adts_frames(h, 2) {
        return Some("aac");
    }
    None
}

fn zip_detect(h: &[u8]) -> &'static str {
    let mut names = Vec::new();
    let mut mimetype = None;
    let mut ct = None;
    let mut pos = 0usize;
    while at(h, pos, b"PK\x03\x04") && names.len() < 64 {
        let (Some(method), Some(csize), Some(nlen), Some(xlen)) = (le16(h, pos + 8), le32(h, pos + 18), le16(h, pos + 26), le16(h, pos + 28)) else { break };
        let (nlen, xlen) = (nlen as usize, xlen as usize);
        let Some(name) = h.get(pos + 30..pos + 30 + nlen) else { break };
        let name = String::from_utf8_lossy(name).into_owned();
        let data = pos + 30 + nlen + xlen;
        let avail = h.get(data..data + (csize as usize)).or_else(|| h.get(data..));
        if name == "mimetype" && method == 0 {
            mimetype = avail.map(|d| String::from_utf8_lossy(&d[..d.len().min(csize as usize).min(100)]).into_owned());
        }
        if name == "[Content_Types].xml" {
            if let Some(d) = avail {
                let text = if method == 8 { inflate_prefix(d, 64 << 10) } else { d.to_vec() };
                ct = Some(String::from_utf8_lossy(&text).into_owned());
            }
        }
        names.push(name);
        if le16(h, pos + 6).unwrap_or(0) & 8 != 0 && csize == 0 {
            break;
        }
        pos = data + csize as usize;
    }
    zip_kind(&names, mimetype.as_deref(), ct.as_deref())
}

fn ole_detect(h: &[u8]) -> &'static str {
    let shift = le16(h, 0x1E).unwrap_or(9);
    if !(7..=16).contains(&shift) {
        return "doc";
    }
    let ss = 1usize << shift;
    let Some(first) = le32(h, 0x30) else { return "doc" };
    let off = (first as usize + 1).saturating_mul(ss);
    match h.get(off..) {
        Some(dir) if dir.len() >= 128 => ole_kind_from_names(&ole_dir_names(&dir[..dir.len().min(ss)])),
        _ => "doc",
    }
}

// ----------------------------------------------------------------------------------------- text

fn text(h: &[u8]) -> Option<&'static str> {
    if h.starts_with(&[0xFF, 0xFE]) || h.starts_with(&[0xFE, 0xFF]) {
        return Some("txt");
    }
    let h = h.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(h);
    let sample = &h[..h.len().min(8192)];
    if sample.is_empty() || sample.contains(&0) {
        return None;
    }
    let s = match std::str::from_utf8(sample) {
        Ok(s) => s,
        // Cut in the middle of a character at the end of the sample.
        Err(e) if e.valid_up_to() + 4 >= sample.len() && e.error_len().is_none() => std::str::from_utf8(&sample[..e.valid_up_to()]).ok()?,
        Err(_) => return None,
    };
    let ctrl = s.chars().filter(|&c| c.is_control() && !matches!(c, '\n' | '\r' | '\t' | '\x0C')).count();
    if ctrl * 50 > s.len().max(1) {
        return None;
    }
    if is_eml(s) {
        return Some("eml");
    }
    let t = s.trim_start();
    let low: String = t.chars().take(1024).collect::<String>().to_ascii_lowercase();
    if low.starts_with("<!doctype html") || low.starts_with("<html") || low.starts_with("<head") || low.starts_with("<body") {
        return Some("html");
    }
    if low.starts_with('<') && low.contains("<svg") {
        return Some("svg");
    }
    if low.starts_with("<?xml") {
        if low.contains("<!doctype html") || low.contains("<html") {
            return Some("html");
        }
        return Some("xml");
    }
    if low.starts_with('<') && low[1..].starts_with(|c: char| c.is_ascii_alphabetic()) && low.contains("</") {
        return Some("xml");
    }
    if let Some(rest) = t.strip_prefix('{') {
        if rest.trim_start().starts_with(['"', '}']) {
            return Some("json");
        }
    }
    if let Some(rest) = t.strip_prefix('[') {
        if rest.trim_start().starts_with(|c: char| matches!(c, '{' | '[' | '"' | ']' | '-' | 't' | 'f' | 'n') || c.is_ascii_digit()) {
            return Some("json");
        }
    }
    if is_csv(s) {
        return Some("csv");
    }
    Some("txt")
}

fn is_eml(s: &str) -> bool {
    const KNOWN: [&str; 14] = [
        "received", "return-path", "from", "to", "subject", "date", "message-id", "mime-version", "delivered-to", "content-type", "dkim-signature", "reply-to",
        "sender", "x-mozilla-status",
    ];
    const STRONG: [&str; 6] = ["received", "return-path", "message-id", "delivered-to", "dkim-signature", "x-mozilla-status"];
    let mut headers = 0;
    let mut strong = false;
    let mut from_or_subject = false;
    for (i, line) in s.lines().take(60).enumerate() {
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            if i == 0 {
                return false;
            }
            continue;
        }
        let Some((name, _)) = line.split_once(':') else { return false };
        if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
            return false;
        }
        let n = name.to_ascii_lowercase();
        if KNOWN.contains(&n.as_str()) || n.starts_with("x-") {
            headers += 1;
        }
        strong |= STRONG.contains(&n.as_str()) || n.starts_with("x-");
        from_or_subject |= n == "from" || n == "subject" || n == "date";
    }
    headers >= 3 && (strong || from_or_subject)
}

fn is_csv(s: &str) -> bool {
    let lines: Vec<&str> = s.lines().take(6).collect();
    let lines = if lines.len() > 2 && !s.ends_with('\n') { &lines[..lines.len() - 1] } else { &lines[..] };
    if lines.len() < 2 {
        return false;
    }
    [',', ';', '\t'].iter().any(|&d| {
        let n = lines[0].matches(d).count();
        n >= 1 && lines.iter().all(|l| l.matches(d).count() == n)
    })
}

#[cfg(test)]
mod tests {
    use super::super::detect;
    use super::*;

    fn id(h: &[u8]) -> Option<&'static str> {
        detect(h).map(|t| t.id)
    }

    fn pad(mut v: Vec<u8>, n: usize) -> Vec<u8> {
        v.resize(n, 0);
        v
    }

    fn zip_with(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        use std::io::Write;
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, data, deflate) in entries {
            let o = zip::write::SimpleFileOptions::default().compression_method(if *deflate { zip::CompressionMethod::Deflated } else { zip::CompressionMethod::Stored });
            w.start_file(*name, o).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn detects_images_and_raw() {
        assert_eq!(id(b"\xFF\xD8\xFF\xE0\0\x10JFIF"), Some("jpg"));
        assert_eq!(id(b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR"), Some("png"));
        assert_eq!(id(b"GIF89a\x01\0\x01\0"), Some("gif"));
        assert_eq!(id(b"RIFF\0\0\0\0WEBPVP8 "), Some("webp"));
        assert_eq!(id(b"8BPS\0\x01\0\0\0\0\0\0"), Some("psd"));
        assert_eq!(id(b"FUJIFILMCCD-RAW 0201"), Some("raf"));
        assert_eq!(id(b"FOVb\0\0\x02\0"), Some("x3f"));
        assert_eq!(id(b"IIRO\x08\0\0\0"), Some("orf"));
        assert_eq!(id(b"IIU\0\x08\0\0\0"), Some("rw2"));
        assert_eq!(id(b"II*\0\x10\0\0\0CR\x02\0"), Some("cr2"));
        // TIFF with Make = NIKON in IFD0.
        let mut t = b"MM\0*\0\0\0\x08".to_vec();
        t.extend([0, 1, 1, 15, 0, 2, 0, 0, 0, 6, 0, 0, 0, 26, 0, 0, 0, 0]);
        t.extend(b"NIKON\0");
        assert_eq!(id(&t), Some("nef"));
        let mut d = b"II*\0\x08\0\0\0".to_vec();
        d.extend([1, 0, 0x12, 0xC6, 1, 0, 4, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0]);
        assert_eq!(id(&d), Some("dng"));
        assert_eq!(id(b"II*\0\x08\0\0\0\0\0\0\0\0\0"), Some("tiff"));
        let mut bmp = b"BM".to_vec();
        bmp.extend(70u32.to_le_bytes());
        bmp.extend([0; 4]);
        bmp.extend(54u32.to_le_bytes());
        bmp.extend(40u32.to_le_bytes());
        bmp.extend(2u32.to_le_bytes());
        bmp.extend(2u32.to_le_bytes());
        bmp.extend(1u16.to_le_bytes());
        bmp.extend(24u16.to_le_bytes());
        assert_eq!(id(&pad(bmp, 70)), Some("bmp"));
        let mut ico = vec![0, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0, 32, 0];
        ico.extend(1128u32.to_le_bytes());
        ico.extend(22u32.to_le_bytes());
        assert_eq!(id(&pad(ico, 64)), Some("ico"));
        assert_eq!(id(b"<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"), Some("svg"));
    }

    #[test]
    fn detects_bmff_brands() {
        let ftyp = |brand: &[u8], compat: &[u8]| {
            let mut v = ((16 + compat.len()) as u32).to_be_bytes().to_vec();
            v.extend(b"ftyp");
            v.extend(brand);
            v.extend([0, 0, 0, 0]);
            v.extend(compat);
            pad(v, 64)
        };
        assert_eq!(id(&ftyp(b"isom", b"isomavc1")), Some("mp4"));
        assert_eq!(id(&ftyp(b"mp42", b"")), Some("mp4"));
        assert_eq!(id(&ftyp(b"qt  ", b"qt  ")), Some("mov"));
        assert_eq!(id(&ftyp(b"M4A ", b"M4A mp42")), Some("m4a"));
        assert_eq!(id(&ftyp(b"M4V ", b"")), Some("m4v"));
        assert_eq!(id(&ftyp(b"3gp5", b"")), Some("3gp"));
        assert_eq!(id(&ftyp(b"heic", b"mif1heic")), Some("heic"));
        assert_eq!(id(&ftyp(b"mif1", b"avifmiaf")), Some("avif"));
        assert_eq!(id(&ftyp(b"avif", b"")), Some("avif"));
        assert_eq!(id(&ftyp(b"crx ", b"crx isom")), Some("cr3"));
    }

    #[test]
    fn detects_media() {
        assert_eq!(id(b"RIFF\0\0\0\0AVI LIST"), Some("avi"));
        assert_eq!(id(b"RIFF\0\0\0\0WAVEfmt "), Some("wav"));
        assert_eq!(id(b"FORM\0\0\0\0AIFFCOMM"), Some("aiff"));
        assert_eq!(id(b"\x1A\x45\xDF\xA3\x9F\x42\x86\x81\x01\x42\x82\x84webm"), Some("webm"));
        assert_eq!(id(b"\x1A\x45\xDF\xA3\xA3\x42\x86\x81\x01\x42\x82\x88matroska"), Some("mkv"));
        let mut asf = ASF_HEADER.to_vec();
        asf.extend(200u64.to_le_bytes());
        let mut a = pad(asf.clone(), 100);
        a.extend([0x40, 0x9E, 0x69, 0xF8, 0x4D, 0x5B, 0xCF, 0x11, 0xA8, 0xFD, 0x00, 0x80, 0x5F, 0x5C, 0x44, 0x2B]);
        assert_eq!(id(&pad(a, 200)), Some("wma"));
        assert_eq!(id(&pad(asf, 200)), Some("wmv"));
        assert_eq!(id(b"FLV\x01\x05\0\0\0\x09"), Some("flv"));
        assert_eq!(id(&pad(vec![0, 0, 1, 0xBA, 0x44, 0, 4, 0, 4, 1], 64)), Some("mpg"));
        let mut ts = vec![0u8; 188 * 4];
        let mut mts = vec![0u8; 192 * 4];
        for i in 0..4 {
            ts[i * 188] = 0x47;
            mts[4 + i * 192] = 0x47;
        }
        assert_eq!(id(&ts), Some("ts"));
        assert_eq!(id(&mts), Some("mts"));
        // Three MPEG-1 layer III frames, 128 kbit/s, 44.1 kHz: 417 bytes each.
        let mut mp3 = Vec::new();
        for _ in 0..3 {
            let mut f = vec![0xFF, 0xFB, 0x90, 0x00];
            f.resize(417, 0x55);
            mp3.extend(f);
        }
        assert_eq!(id(&mp3), Some("mp3"));
        assert_eq!(id(&mp3[..417 * 2]), None);
        assert_eq!(id(b"ID3\x03\0\0\0\0\0\x0aTIT2"), Some("mp3"));
        assert_eq!(id(b"fLaC\0\0\0\x22"), Some("flac"));
        let mut opus = b"OggS\0\x02".to_vec();
        opus.resize(26, 0);
        opus.push(1);
        opus.push(19);
        opus.extend(b"OpusHead");
        assert_eq!(id(&opus), Some("opus"));
        opus[27 + 1..27 + 9].copy_from_slice(b"\x01vorbis\0");
        assert_eq!(id(&opus), Some("ogg"));
        // Two ADTS frames of 100 bytes.
        let mut aac = Vec::new();
        for _ in 0..2 {
            let len = 100usize;
            let mut f = vec![0xFF, 0xF1, 0x50, 0x80 | ((len >> 11) & 3) as u8, ((len >> 3) & 0xFF) as u8, (((len & 7) << 5) as u8) | 0x1F, 0xFC];
            f.resize(len, 0x11);
            aac.extend(f);
        }
        assert_eq!(id(&aac), Some("aac"));
        assert_eq!(id(b"#!AMR\n\x3c"), Some("amr"));
        assert_eq!(id(b"MThd\0\0\0\x06\0\x01\0\x02"), Some("mid"));
    }

    #[test]
    fn detects_documents_and_archives() {
        let docx = zip_with(&[("[Content_Types].xml", b"<Types><Override ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>", true), ("word/document.xml", b"<w:document/>", true)]);
        assert_eq!(id(&docx), Some("docx"));
        let xlsx = zip_with(&[("[Content_Types].xml", b"<Types/>", true), ("xl/workbook.xml", b"<x/>", true)]);
        assert_eq!(id(&xlsx), Some("xlsx"));
        let pptx = zip_with(&[("[Content_Types].xml", b"<Types/>", true), ("ppt/presentation.xml", b"<x/>", true)]);
        assert_eq!(id(&pptx), Some("pptx"));
        let odt = zip_with(&[("mimetype", b"application/vnd.oasis.opendocument.text", false), ("content.xml", b"<x/>", true)]);
        assert_eq!(id(&odt), Some("odt"));
        let epub = zip_with(&[("mimetype", b"application/epub+zip", false)]);
        assert_eq!(id(&epub), Some("epub"));
        let plain = zip_with(&[("readme.txt", b"hello", true)]);
        assert_eq!(id(&plain), Some("zip"));

        // OLE with a directory sector right after the header (sector 0 at 512).
        let mut ole = OLE.to_vec();
        ole.resize(512, 0);
        ole[0x1E] = 9;
        ole[0x30..0x34].copy_from_slice(&0u32.to_le_bytes());
        let mut ent = vec![0u8; 128];
        for (i, c) in "Workbook".encode_utf16().enumerate() {
            ent[i * 2..i * 2 + 2].copy_from_slice(&c.to_le_bytes());
        }
        ent[64] = 18;
        ent[66] = 2;
        ole.extend(&ent);
        assert_eq!(id(&ole), Some("xls"));
        assert_eq!(id(&OLE), Some("doc"));

        assert_eq!(id(b"%PDF-1.7\n"), Some("pdf"));
        assert_eq!(id(b"{\\rtf1\\ansi"), Some("rtf"));
        assert_eq!(id(b"!BDN\0\0\0\0SM"), Some("pst"));
        assert_eq!(id(b"7z\xBC\xAF\x27\x1C\0\x04"), Some("7z"));
        assert_eq!(id(b"Rar!\x1a\x07\x01\0"), Some("rar"));
        assert_eq!(id(b"\x1F\x8B\x08\0\0\0\0\0"), Some("gz"));
        assert_eq!(id(b"BZh91AY&SY"), Some("bz2"));
        assert_eq!(id(b"\xFD7zXZ\0\0\x04"), Some("xz"));
        assert_eq!(id(b"MSCF\0\0\0\0\x10\0\0\0"), Some("cab"));
        assert_eq!(id(b"SQLite format 3\0\x10\0\x01\x01\0\x40\x20\x20"), Some("sqlite"));
        let mut iso = vec![0u8; 0x8010];
        iso[0x8000] = 1;
        iso[0x8001..0x8006].copy_from_slice(b"CD001");
        assert_eq!(id(&iso), Some("iso"));
        let mut tar = vec![0u8; 512];
        tar[..5].copy_from_slice(b"a.txt");
        tar[257..263].copy_from_slice(b"ustar\0");
        tar[148..156].fill(b' ');
        let sum: u32 = tar.iter().map(|&b| b as u32).sum();
        tar[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        assert_eq!(id(&tar), Some("tar"));
        // PE: exe vs dll.
        let mut pe = vec![0u8; 512];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3C] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x86] = 3;
        pe[0x80 + 24..0x80 + 26].copy_from_slice(&0x20Bu16.to_le_bytes());
        pe[0x80 + 22..0x80 + 24].copy_from_slice(&0x0022u16.to_le_bytes());
        assert_eq!(id(&pe), Some("exe"));
        pe[0x80 + 22..0x80 + 24].copy_from_slice(&0x2022u16.to_le_bytes());
        assert_eq!(id(&pe), Some("dll"));
    }

    #[test]
    fn detects_text_kinds() {
        assert_eq!(id(b"Return-Path: <a@b.c>\r\nReceived: from x\r\nFrom: A <a@b.c>\r\nSubject: hi\r\n\r\nbody"), Some("eml"));
        assert_eq!(id(b"<!DOCTYPE html>\n<html><body>hi</body></html>"), Some("html"));
        assert_eq!(id(b"<?xml version=\"1.0\"?><root><a>1</a></root>"), Some("xml"));
        assert_eq!(id(b"{\n  \"name\": \"x\"\n}"), Some("json"));
        assert_eq!(id(b"[1, 2, 3]"), Some("json"));
        assert_eq!(id(b"name,age\nann,3\nbob,4\n"), Some("csv"));
        assert_eq!(id(b"Hello there, this is a note.\nSecond line"), Some("txt"));
        assert_eq!(id(b"\x01\x02\x03\x04\x05\x06\x07\x08"), None);
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut x = 0x1234_5678_9abc_def0u64;
        for n in [0usize, 1, 3, 4, 7, 16, 100, 512, 4096, 40000] {
            for _ in 0..200 {
                let v: Vec<u8> = (0..n)
                    .map(|_| {
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        x as u8
                    })
                    .collect();
                let _ = detect(&v);
                for magic in [&b"PK\x03\x04"[..], &OLE, b"II*\0", b"MM\0*", b"ID3\x03\0", b"OggS", b"\x00\x00\x00\x18ftyp", b"MZ", b"RIFF"] {
                    let mut w = v.clone();
                    if w.len() >= magic.len() {
                        w[..magic.len()].copy_from_slice(magic);
                        let _ = detect(&w);
                    }
                }
            }
        }
    }
}
