//! Synthetic-disk tests: real files placed at sector boundaries in random filler, the visitor driven
//! over 4 MiB chunks in parallel, then `finish`.

use super::*;
use crate::device::source::MemSource;
use crate::model::{MapKind, ScanOptions};
use image::ImageEncoder;
use std::io::Write;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn fill(&mut self, b: &mut [u8]) {
        for c in b.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            c.copy_from_slice(&v[..c.len()]);
        }
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.fill(&mut v);
        v
    }
}

const CHUNK: usize = 4 << 20;

fn run(data: Vec<u8>, opts: ScanOptions, setup: impl FnOnce(&ScanCtx)) -> Vec<FoundFile> {
    run_with(data, opts, Vec::new(), setup)
}

fn run_with(data: Vec<u8>, opts: ScanOptions, customs: Vec<CustomSignature>, setup: impl FnOnce(&ScanCtx)) -> Vec<FoundFile> {
    let len = data.len() as u64;
    let src = MemSource::new(data);
    let (mut ctx, sinks) = ScanCtx::for_test(opts, len);
    ctx.custom_signatures = customs;
    setup(&ctx);
    let v = visitor(&ctx);
    let offs: Vec<usize> = (0..src.data.len()).step_by(CHUNK).collect();
    offs.par_iter().for_each(|&o| {
        let end = (o + CHUNK).min(src.data.len());
        v.visit(&src, o as u64, &src.data[o..end], &ctx);
    });
    v.finish(&src, &ctx).unwrap();
    let mut files = sinks.files.lock().unwrap().clone();
    files.sort_by_key(|f| f.extents[0].offset);
    for f in &files {
        for e in &f.extents {
            assert!(e.offset + e.len <= len, "{} runs past the end of the disk", f.name);
        }
        assert_eq!(f.size, f.extents.iter().map(|e| e.len).sum::<u64>());
        assert_eq!(f.status, FileStatus::Carved);
        assert_eq!(f.origin, Origin::Carving);
        assert!(f.flags & flags::NAME_GUESSED != 0);
    }
    files
}

fn at(files: &[FoundFile], off: u64) -> Option<&FoundFile> {
    files.iter().find(|f| f.extents[0].offset == off)
}

// ------------------------------------------------------------------------------- test files

fn pixels(w: u32, h: u32, ch: usize, rng: &mut Rng, noise: bool) -> Vec<u8> {
    let mut px = Vec::with_capacity((w * h) as usize * ch);
    for y in 0..h {
        for x in 0..w {
            for c in 0..ch {
                let base = ((x * 3 + y * 5 + c as u32 * 70) % 256) as u8;
                px.push(if noise { base.wrapping_add((rng.next() % 48) as u8) } else { base });
            }
        }
    }
    px
}

fn jpeg(w: u32, h: u32, rng: &mut Rng, noise: bool) -> Vec<u8> {
    let px = pixels(w, h, 3, rng, noise);
    let mut out = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 90).write_image(&px, w, h, image::ExtendedColorType::Rgb8).unwrap();
    out
}

/// A JPEG with an EXIF APP1 holding a thumbnail JPEG that starts at file offset 512.
fn jpeg_with_thumb(rng: &mut Rng) -> (Vec<u8>, usize) {
    let main = jpeg(320, 240, rng, true);
    let thumb = jpeg(64, 48, rng, false);
    let mut tiff = b"II*\0\x08\0\0\0".to_vec();
    tiff.extend([0, 0]); // IFD0: no entries
    tiff.extend(14u32.to_le_bytes()); // next IFD at 14
    let thumb_tiff_off = 512 - 12;
    tiff.extend(2u16.to_le_bytes());
    tiff.extend(513u16.to_le_bytes());
    tiff.extend(4u16.to_le_bytes());
    tiff.extend(1u32.to_le_bytes());
    tiff.extend((thumb_tiff_off as u32).to_le_bytes());
    tiff.extend(514u16.to_le_bytes());
    tiff.extend(4u16.to_le_bytes());
    tiff.extend(1u32.to_le_bytes());
    tiff.extend((thumb.len() as u32).to_le_bytes());
    tiff.extend(0u32.to_le_bytes());
    tiff.resize(thumb_tiff_off, 0);
    tiff.extend(&thumb);
    let mut f = vec![0xFF, 0xD8, 0xFF, 0xE1];
    f.extend(((2 + 6 + tiff.len()) as u16).to_be_bytes());
    f.extend(b"Exif\0\0");
    f.extend(&tiff);
    f.extend(&main[2..]);
    assert_eq!(&f[512..515], &[0xFF, 0xD8, 0xFF]);
    (f, 512)
}

fn encode_png(rng: &mut Rng) -> Vec<u8> {
    let px = pixels(100, 80, 3, rng, true);
    let mut out = Vec::new();
    image::codecs::png::PngEncoder::new(&mut out).write_image(&px, 100, 80, image::ExtendedColorType::Rgb8).unwrap();
    out
}

fn encode_gif(rng: &mut Rng) -> Vec<u8> {
    let px = pixels(60, 40, 4, rng, false);
    let mut out = Vec::new();
    image::codecs::gif::GifEncoder::new(&mut out).write_image(&px, 60, 40, image::ExtendedColorType::Rgba8).unwrap();
    out
}

fn encode_bmp(rng: &mut Rng) -> Vec<u8> {
    let px = pixels(50, 30, 3, rng, true);
    let mut out = Vec::new();
    image::codecs::bmp::BmpEncoder::new(&mut out).write_image(&px, 50, 30, image::ExtendedColorType::Rgb8).unwrap();
    out
}

fn zip_of(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut w = ::zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, data, deflate) in entries {
        let o = ::zip::write::SimpleFileOptions::default().compression_method(if *deflate { ::zip::CompressionMethod::Deflated } else { ::zip::CompressionMethod::Stored });
        w.start_file(*name, o).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// A ZIP whose stored JPEG member starts at offset 512 inside the archive.
fn zip_with_aligned_member(member: &[u8]) -> (Vec<u8>, usize) {
    for extra in 0..600 {
        let name = format!("{}.jpg", "p".repeat(400 + extra));
        let z = zip_of(&[(&name, member, false), ("notes.txt", b"some notes about the photo", true)]);
        let pos = crate::formats::sniff::find(&z, &member[..64]).unwrap();
        if pos == 512 {
            return (z, pos);
        }
    }
    panic!("couldn't align the member");
}

fn pdf_with_update() -> Vec<u8> {
    let mut p = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n100\n%%EOF\n".to_vec();
    p.extend(b"3 0 obj\n<< /Producer (MAX test) >>\nendobj\nxref\n3 1\n0000000200 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R /Prev 100 /Info 3 0 R >>\nstartxref\n260\n%%EOF\n");
    p
}

fn mp3_file(rng: &mut Rng) -> Vec<u8> {
    let mut v = b"ID3\x03\0\0\0\0\0\x64".to_vec(); // 100-byte tag body
    v.extend(b"TIT2\0\0\0\x05\0\0\0Song");
    v.resize(110, 0);
    for _ in 0..20 {
        let mut fr = vec![0xFF, 0xFB, 0x90, 0x00];
        fr.extend(rng.bytes(413));
        v.extend(fr);
    }
    v.extend(b"TAG");
    v.extend(vec![b' '; 125]);
    v
}

fn wav_file(rng: &mut Rng) -> Vec<u8> {
    let data = rng.bytes(20000);
    let mut v = b"RIFF".to_vec();
    v.extend(((4 + 8 + 16 + 8 + data.len()) as u32).to_le_bytes());
    v.extend(b"WAVEfmt ");
    v.extend(16u32.to_le_bytes());
    v.extend([1, 0, 2, 0, 0x44, 0xAC, 0, 0, 0x10, 0xB1, 2, 0, 4, 0, 16, 0]);
    v.extend(b"data");
    v.extend((data.len() as u32).to_le_bytes());
    v.extend(data);
    v
}

fn mp4_file(rng: &mut Rng) -> Vec<u8> {
    let mut v = 24u32.to_be_bytes().to_vec();
    v.extend(b"ftypisom\0\0\x02\0isommp41");
    let mut mvhd = 108u32.to_be_bytes().to_vec();
    mvhd.extend(b"mvhd");
    mvhd.resize(108, 0);
    v.extend(((8 + mvhd.len()) as u32).to_be_bytes());
    v.extend(b"moov");
    v.extend(mvhd);
    let data = rng.bytes(50000);
    v.extend(((8 + data.len()) as u32).to_be_bytes());
    v.extend(b"mdat");
    v.extend(data);
    v
}

fn sqlite_file(rng: &mut Rng) -> Vec<u8> {
    let mut v = rng.bytes(5 * 4096);
    let mut h = b"SQLite format 3\0".to_vec();
    h.extend(4096u16.to_be_bytes());
    h.extend([1, 1, 0, 64, 32, 32]);
    h.extend(7u32.to_be_bytes()); // change counter
    h.extend(5u32.to_be_bytes()); // pages
    h.resize(92, 0);
    h.extend(7u32.to_be_bytes()); // version-valid-for
    h.extend(3_045_000u32.to_be_bytes());
    v[..100].copy_from_slice(&h);
    v
}

struct Layout {
    disk: Vec<u8>,
    next: usize,
    placed: Vec<(&'static str, usize, usize)>,
}

impl Layout {
    fn new(size: usize, rng: &mut Rng) -> Layout {
        Layout { disk: rng.bytes(size), next: 64 * 1024, placed: Vec::new() }
    }
    /// Put `bytes` at the next 4 KiB boundary (plus `skew` sectors) after some filler.
    fn put(&mut self, name: &'static str, bytes: &[u8], skew: usize) -> usize {
        let off = self.next.div_ceil(4096) * 4096 + skew * 512;
        self.disk[off..off + bytes.len()].copy_from_slice(bytes);
        self.next = off + bytes.len() + 8192 + (self.placed.len() % 3) * 4096;
        self.placed.push((name, off, bytes.len()));
        off
    }
}

#[test]
fn carves_a_synthetic_disk() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut l = Layout::new(24 << 20, &mut rng);
    let (jpg, thumb_at) = jpeg_with_thumb(&mut rng);
    let jpg_off = l.put("jpg", &jpg, 0);
    let png = encode_png(&mut rng);
    let png_off = l.put("png", &png, 1);
    let gif = encode_gif(&mut rng);
    let gif_off = l.put("gif", &gif, 0);
    let bmp = encode_bmp(&mut rng);
    let bmp_off = l.put("bmp", &bmp, 3);
    let member = jpeg(80, 60, &mut rng, true);
    let (zip, member_at) = zip_with_aligned_member(&member);
    let zip_off = l.put("zip", &zip, 0);
    let docx = zip_of(&[
        ("[Content_Types].xml", b"<?xml version=\"1.0\"?><Types><Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>", true),
        ("word/document.xml", b"<w:document><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>", true),
    ]);
    let docx_off = l.put("docx", &docx, 2);
    let pdf = pdf_with_update();
    let pdf_off = l.put("pdf", &pdf, 0);
    let mp3 = mp3_file(&mut rng);
    let mp3_off = l.put("mp3", &mp3, 1);
    let wav = wav_file(&mut rng);
    let wav_off = l.put("wav", &wav, 0);
    let mp4 = mp4_file(&mut rng);
    // Straddle a 4 MiB chunk boundary.
    l.next = (8 << 20) - 20000;
    let mp4_off = l.put("mp4", &mp4, 0);
    let sq = sqlite_file(&mut rng);
    let sq_off = l.put("sqlite", &sq, 0);
    let mut cut_png = encode_png(&mut rng);
    cut_png.truncate(cut_png.len() / 2);
    let cut_off = l.put("cut png", &cut_png, 0);

    let files = run(l.disk.clone(), ScanOptions { mode: "deep".into(), ..Default::default() }, |_| {});
    let expect = |off: usize, len: usize, ty: &str| {
        let f = at(&files, off as u64).unwrap_or_else(|| panic!("no {ty} at {off:#x}; got {:?}", files.iter().map(|f| (&f.type_id, f.extents[0].offset)).collect::<Vec<_>>()));
        assert_eq!(f.type_id, ty, "type at {off:#x}");
        assert_eq!(f.size, len as u64, "{ty} size");
        assert_eq!(f.condition, Condition::Good, "{ty}: {}", f.note);
        assert_eq!(f.note, "Its structure is complete.");
        assert!(!f.fragmented);
        assert!(f.folder.starts_with("\\Found by signature\\"));
        assert!(f.name.ends_with(&format!(".{ty}")), "{}", f.name);
        f
    };
    let j = expect(jpg_off, jpg.len(), "jpg");
    assert_eq!(j.folder, "\\Found by signature\\JPEG image");
    if j.meta.is_empty() {
        assert_eq!(j.name, format!("JPEG_{:010X}.jpg", jpg_off));
    }
    expect(png_off, png.len(), "png");
    expect(gif_off, gif.len(), "gif");
    expect(bmp_off, bmp.len(), "bmp");
    expect(zip_off, zip.len(), "zip");
    expect(docx_off, docx.len(), "docx");
    expect(pdf_off, pdf.len(), "pdf");
    expect(mp3_off, mp3.len(), "mp3");
    expect(wav_off, wav.len(), "wav");
    expect(mp4_off, mp4.len(), "mp4");
    expect(sq_off, sq.len(), "sqlite");
    // Embedded thumbnail and archive member are part of their parents, not files of their own.
    assert!(at(&files, (jpg_off + thumb_at) as u64).is_none());
    assert!(at(&files, (zip_off + member_at) as u64).is_none());
    // The truncated PNG is reported as incomplete.
    let c = at(&files, cut_off as u64).expect("truncated png");
    assert_eq!(c.type_id, "png");
    assert_eq!(c.condition, Condition::Partial);
    assert_eq!(c.note, "It looks incomplete or damaged.");
    assert_eq!(files.len(), 12, "{:?}", files.iter().map(|f| (&f.type_id, f.extents[0].offset)).collect::<Vec<_>>());

    // known_starts, allocated + carve_free_only, carve_types.
    let opts = ScanOptions { mode: "deep".into(), carve_free_only: Some(true), ..Default::default() };
    let files2 = run(l.disk.clone(), opts, |ctx| {
        ctx.known_starts.lock().unwrap().insert(gif_off as u64);
        ctx.mark(MapKind::Allocated, bmp_off as u64, bmp.len() as u64);
    });
    assert!(at(&files2, gif_off as u64).is_none());
    assert!(at(&files2, bmp_off as u64).is_none());
    assert!(at(&files2, png_off as u64).is_some());
    assert_eq!(files2.len(), 10);

    let photos = run(l.disk.clone(), ScanOptions { mode: "deep".into(), carve_types: Some(vec!["photo".into()]), ..Default::default() }, |_| {});
    let kinds: HashSet<&str> = photos.iter().map(|f| f.type_id.as_str()).collect();
    assert_eq!(kinds, ["jpg", "png", "gif", "bmp"].into_iter().collect());
    // The JPEG inside the (unlisted) ZIP still isn't listed on its own.
    assert!(at(&photos, (zip_off + member_at) as u64).is_none());
    assert_eq!(photos.len(), 5);
    let docs = run(l.disk.clone(), ScanOptions { mode: "deep".into(), carve_types: Some(vec!["docx".into(), "pdf".into()]), ..Default::default() }, |_| {});
    assert_eq!(docs.iter().map(|f| f.type_id.as_str()).collect::<Vec<_>>(), vec!["docx", "pdf"]);
}

#[test]
fn custom_signature_with_wildcards_and_footer() {
    let mut rng = Rng(42);
    let mut l = Layout::new(2 << 20, &mut rng);
    let mut blob = vec![0xCA, 0xFE, 0x17, 0xBA, 0xBE];
    blob.extend(rng.bytes(30000).into_iter().map(|b| if b == 0xDE { 0 } else { b }));
    blob.extend([0xDE, 0xAD, 0xBE, 0xEF]);
    let off = l.put("blob", &blob, 1);
    let sig = CustomSignature {
        id: "t1".into(),
        name: "Test blob".into(),
        ext: "blob".into(),
        category: "other".into(),
        header: "CA FE ?? BA BE".into(),
        header_offset: 0,
        footer: "DEADBEEF".into(),
        max_size: 1 << 20,
        enabled: true,
    };
    // Without a footer the size is the maximum, cut at the next real file.
    let mut nofoot = sig.clone();
    nofoot.footer.clear();
    nofoot.max_size = 1 << 20;
    let files = run_with(l.disk.clone(), ScanOptions::default(), vec![sig], |_| {});
    let f = at(&files, off as u64).expect("custom hit");
    assert_eq!(f.size, blob.len() as u64);
    assert_eq!(f.type_id, "blob");
    assert_eq!(f.folder, "\\Found by signature\\Test blob");
    assert_eq!(f.condition, Condition::Good);
    let mut l2 = l.disk.clone();
    let png = encode_png(&mut rng);
    let png_at = off + 64 * 1024;
    l2[png_at..png_at + png.len()].copy_from_slice(&png);
    let files = run_with(l2, ScanOptions::default(), vec![nofoot], |_| {});
    let f = at(&files, off as u64).expect("custom hit");
    assert_eq!(f.size, 64 * 1024, "estimated end is cut at the next header");
    assert_eq!(f.condition, Condition::Unknown);
    assert_eq!(f.note, "The end of this file was estimated.");
    assert!(at(&files, png_at as u64).is_some());
}

#[test]
fn jpeg_bifragment_is_rebuilt() {
    let mut rng = Rng(7);
    let jpg = jpeg(512, 384, &mut rng, true);
    assert!(jpg.len() > 40000, "{}", jpg.len());
    let mut disk = rng.bytes(4 << 20);
    let off = 256 * 1024;
    let split = 3 * 4096;
    let gap = 5 * 4096;
    disk[off..off + split].copy_from_slice(&jpg[..split]);
    disk[off + split + gap..off + gap + jpg.len()].copy_from_slice(&jpg[split..]);
    let files = run(disk.clone(), ScanOptions::default(), |_| {});
    let f = at(&files, off as u64).expect("jpeg");
    assert!(f.fragmented, "{}", f.note);
    assert_eq!(f.note, "Rebuilt from 2 fragments.");
    assert_eq!(f.condition, Condition::Good);
    assert_eq!(f.extents, vec![Extent { offset: off as u64, len: split as u64 }, Extent { offset: (off + split + gap) as u64, len: (jpg.len() - split) as u64 }]);
    // The rebuilt bytes are the original file and decode.
    let mut joined = disk[off..off + split].to_vec();
    joined.extend(&disk[off + split + gap..off + gap + jpg.len()]);
    assert_eq!(joined, jpg);
    assert!(image::load_from_memory(&joined).is_ok());

    // Without a continuation it's reported as incomplete.
    let mut disk2 = rng.bytes(2 << 20);
    disk2[off..off + split].copy_from_slice(&jpg[..split]);
    let files = run(disk2, ScanOptions::default(), |_| {});
    let f = at(&files, off as u64).expect("jpeg");
    assert_eq!(f.condition, Condition::Partial);
    assert!(!f.fragmented);
}

#[test]
fn zip_gap_is_rebuilt() {
    let mut rng = Rng(99);
    let a = rng.bytes(30000);
    let text = "MAX recovers files. ".repeat(300);
    let z = zip_of(&[("a.bin", &a, false), ("b.txt", text.as_bytes(), true)]);
    let mut disk = rng.bytes(2 << 20);
    let off = 128 * 1024;
    let split = 2 * 4096;
    let gap = 3 * 4096;
    disk[off..off + split].copy_from_slice(&z[..split]);
    disk[off + split + gap..off + gap + z.len()].copy_from_slice(&z[split..]);
    let files = run(disk, ScanOptions::default(), |_| {});
    let f = at(&files, off as u64).expect("zip");
    assert_eq!(f.type_id, "zip");
    assert!(f.fragmented, "{} {:?}", f.note, f.extents);
    assert_eq!(f.extents, vec![Extent { offset: off as u64, len: split as u64 }, Extent { offset: (off + split + gap) as u64, len: (z.len() - split) as u64 }]);
    assert_eq!(f.condition, Condition::Good);
}

#[test]
fn random_bytes_and_hostile_headers_never_panic() {
    let mut rng = Rng(0xDEAD_BEEF);
    let mut disk = rng.bytes(6 << 20);
    let mut heads: Vec<Vec<u8>> = vec![
        b"\xFF\xD8\xFF\xE0\x00\x10JFIF\0".to_vec(),
        b"\xFF\xD8\xFF\xDB\xFF\xFF".to_vec(),
        b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec(),
        b"GIF89a\x10\0\x10\0\xF7\0\0".to_vec(),
        b"RIFF\xF0\xFF\xFF\xFFWAVEfmt ".to_vec(),
        b"RIFF\xF0\xFF\xFF\xFFAVI LIST".to_vec(),
        b"II*\0\x08\0\0\0\x05\0".to_vec(),
        b"MM\0*\0\0\0\x08\0\x03".to_vec(),
        b"\0\0\0\x18ftypisom\0\0\0\0isommp41\xFF\xFF\xFF\xFFmoov".to_vec(),
        b"\0\0\0\x18ftypheic\0\0\0\0mif1heic\0\0\0\x01mdat\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF".to_vec(),
        b"\x1A\x45\xDF\xA3\x9F\x42\x86\x81\x01\x42\x82\x84webm\x18\x53\x80\x67\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF".to_vec(),
        b"FLV\x01\x05\0\0\0\x09\0\0\0\0".to_vec(),
        b"\0\0\x01\xBA\x44\0\x04\0\x04\x01".to_vec(),
        b"ID3\x04\0\0\x7F\x7F\x7F\x7F".to_vec(),
        b"fLaC\0\0\0\x22\x10\0\x10\0".to_vec(),
        b"OggS\0\x02\0\0\0\0\0\0\0\0".to_vec(),
        b"#!AMR\n\x3C\x3C\x3C".to_vec(),
        b"FORM\xFF\xFF\xFF\xF0AIFFCOMM".to_vec(),
        b"MThd\0\0\0\x06\0\x01\xFF\xFF".to_vec(),
        b"%PDF-1.7\n".to_vec(),
        b"{\\rtf1{{{{".to_vec(),
        b"!BDN\0\0\0\0SM\x17\0".to_vec(),
        b"PK\x03\x04\x14\0\x08\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x05\0\0\0a.txt".to_vec(),
        b"7z\xBC\xAF\x27\x1C\0\x04".to_vec(),
        b"Rar!\x1a\x07\x01\0".to_vec(),
        b"Rar!\x1a\x07\0".to_vec(),
        b"\x1F\x8B\x08\0\0\0\0\0\0\x03".to_vec(),
        b"BZh91AY&SY".to_vec(),
        b"\xFD7zXZ\0\0\x04\xE6\xD6\xB4\x46".to_vec(),
        b"MSCF\0\0\0\0\xFF\xFF\xFF\xFF\0\0\0\0".to_vec(),
        b"SQLite format 3\0\x10\0\x01\x01\0\x40\x20\x20\0\0\0\x01\xFF\xFF\xFF\xFF".to_vec(),
        b"8BPS\0\x01\0\0\0\0\0\0\0\x03".to_vec(),
        b"FUJIFILMCCD-RAW 0201".to_vec(),
        b"FOVb\x00\x00\x02\x00".to_vec(),
        b"Return-Path: <a@b.c>\r\nReceived: x\r\nFrom: a\r\nSubject: b\r\n".to_vec(),
        b"!BDN\0\0\0\0SM\x0E\0".to_vec(),
    ];
    let mut ole = crate::formats::sniff::OLE.to_vec();
    ole.resize(0x1C, 0);
    ole.extend([0xFE, 0xFF, 9, 0]);
    heads.push(ole);
    let mut pe = b"MZ".to_vec();
    pe.resize(0x3C, 0);
    pe.extend(0x40u32.to_le_bytes());
    pe.extend(b"PE\0\0\x4C\x01\x03\0");
    pe.resize(0x40 + 24, 0);
    pe.extend(0x10Bu16.to_le_bytes());
    heads.push(pe);
    let mut tar = vec![0u8; 512];
    tar[..5].copy_from_slice(b"x.bin");
    tar[124..135].copy_from_slice(b"77777777777");
    tar[257..263].copy_from_slice(b"ustar\0");
    tar[148..156].fill(b' ');
    let sum: u32 = tar.iter().map(|&b| b as u32).sum();
    tar[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    heads.push(tar);
    let mut bmp = b"BM".to_vec();
    bmp.extend(0xFFFF_FFF0u32.to_le_bytes());
    bmp.extend([0; 4]);
    bmp.extend(54u32.to_le_bytes());
    bmp.extend(40u32.to_le_bytes());
    heads.push(bmp);
    for (i, h) in heads.iter().enumerate() {
        for k in 0..6 {
            let off = (i * 6 + k) * 16 * 1024 + 512 * (k % 3);
            disk[off..off + h.len()].copy_from_slice(h);
            if k % 2 == 1 {
                // Some with zeros after the header instead of noise.
                disk[off + h.len()..off + h.len() + 2048].fill(0);
            }
        }
    }
    // A RIFF claiming 4 GB at the end of the disk is clipped, not trusted.
    let end_off = disk.len() - 64 * 1024;
    let mut riff = b"RIFF\xF0\xFF\xFF\xFFWAVEfmt \x10\0\0\0".to_vec();
    riff.extend([1, 0, 2, 0, 0x44, 0xAC, 0, 0, 0x10, 0xB1, 2, 0, 4, 0, 16, 0]);
    riff.extend(b"data\xC0\xFF\xFF\xFF");
    disk[end_off..end_off + riff.len()].copy_from_slice(&riff);
    let len = disk.len() as u64;
    let files = run(disk, ScanOptions::default(), |_| {});
    for f in &files {
        assert!(f.size <= len);
    }
    let riff = at(&files, end_off as u64).expect("clipped riff");
    assert_eq!(riff.condition, Condition::Partial);
    assert_eq!(riff.size, 64 * 1024);
    // Pure noise.
    let noise = Rng(5).bytes(8 << 20);
    let _ = run(noise, ScanOptions::default(), |_| {});
}

#[test]
fn custom_signatures_are_validated() {
    let ok = CustomSignature { id: "a".into(), name: "Thing".into(), ext: "thg".into(), category: "other".into(), header: "54 48 ?? 47".into(), header_offset: 0, footer: "".into(), max_size: 1 << 20, enabled: true };
    assert!(validate_custom(&ok).is_ok());
    let bad = |f: &dyn Fn(&mut CustomSignature)| {
        let mut s = ok.clone();
        f(&mut s);
        let e = validate_custom(&s).unwrap_err();
        assert!(e.ends_with('.') && !e.contains('\n'), "{e}");
    };
    bad(&|s| s.header = "ZZ".into());
    bad(&|s| s.header = "54 ?? ??".into());
    bad(&|s| s.header = "5".into());
    bad(&|s| s.header_offset = 5000);
    bad(&|s| s.max_size = 100);
    bad(&|s| s.max_size = 17 << 30);
    bad(&|s| s.ext = "".into());
    bad(&|s| s.ext = "a/b".into());
    bad(&|s| s.category = "stuff".into());
    bad(&|s| s.footer = "??".into());
    assert!(is_carvable("jpg") && is_carvable("docx") && is_carvable("cr3") && is_carvable("dll"));
    assert!(!is_carvable("txt") && !is_carvable("svg") && !is_carvable("json"));
    let carvable = crate::formats::all().iter().filter(|t| is_carvable(t.id)).count();
    assert!(carvable >= 55, "{carvable}");
}

/// Dispatch throughput on random data (one thread).
/// `cargo test carve::tests::bench_dispatch -- --ignored --nocapture`
#[test]
#[ignore]
fn bench_dispatch() {
    let data = Rng(1).bytes(256 << 20);
    let src = MemSource::new(Vec::new());
    let (ctx, _) = ScanCtx::for_test(ScanOptions::default(), data.len() as u64);
    let v = Carver::new(&ctx);
    let t = std::time::Instant::now();
    for o in (0..data.len()).step_by(CHUNK) {
        v.visit(&src, o as u64, &data[o..(o + CHUNK).min(data.len())], &ctx);
    }
    let s = t.elapsed().as_secs_f64();
    let hits = v.hits.lock().unwrap().len();
    println!("dispatch: {:.2} GB/s per core ({} hits in 256 MiB)", (256u64 << 20) as f64 / s / 1e9, hits);
}

fn gzip_file(rng: &mut Rng) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all("A line of text that compresses well.\n".repeat(800).as_bytes()).unwrap();
    e.write_all(&rng.bytes(5000)).unwrap();
    e.finish().unwrap()
}

fn tar_file(rng: &mut Rng) -> Vec<u8> {
    let mut h = vec![0u8; 512];
    h[..5].copy_from_slice(b"a.txt");
    h[100..107].copy_from_slice(b"0000644");
    h[124..135].copy_from_slice(b"00000001750"); // 1000 bytes
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    let mut v = h;
    let mut data = rng.bytes(1000);
    data.resize(1024, 0);
    v.extend(data);
    v.resize(10240, 0);
    v
}

fn tiff_file(rng: &mut Rng) -> Vec<u8> {
    let px = pixels(64, 48, 3, rng, true);
    let mut c = std::io::Cursor::new(Vec::new());
    image::codecs::tiff::TiffEncoder::new(&mut c).write_image(&px, 64, 48, image::ExtendedColorType::Rgb8).unwrap();
    c.into_inner()
}

fn webp_file(rng: &mut Rng) -> Vec<u8> {
    let px = pixels(40, 30, 4, rng, false);
    let mut out = Vec::new();
    image::codecs::webp::WebPEncoder::new_lossless(&mut out).write_image(&px, 40, 30, image::ExtendedColorType::Rgba8).unwrap();
    out
}

fn mkv_file(rng: &mut Rng, unknown_size: bool) -> Vec<u8> {
    let mut v = vec![0x1A, 0x45, 0xDF, 0xA3, 0x8B, 0x42, 0x82, 0x88];
    v.extend(b"matroska");
    let mut seg = vec![0x15, 0x49, 0xA9, 0x66, 0x84, 1, 2, 3, 4]; // Info
    for _ in 0..3 {
        let block = rng.bytes(300);
        seg.extend([0x1F, 0x43, 0xB6, 0x75, 0x01, 0, 0, 0, 0, 0, 0x01, 0x32]); // Cluster, 8-byte size 306
        seg.extend([0xE7, 0x81, 0x00, 0xA3, 0x41, 0x2C]); // Timecode, SimpleBlock size 300
        seg.extend(block);
    }
    v.extend([0x18, 0x53, 0x80, 0x67]);
    if unknown_size {
        v.push(0xFF);
    } else {
        v.extend([0x01, 0, 0, 0, 0, 0, (seg.len() >> 8) as u8, seg.len() as u8]);
    }
    v.extend(seg);
    v
}

fn avi_file(rng: &mut Rng) -> Vec<u8> {
    let mut body = b"AVI LIST\x04\0\0\0hdrl".to_vec();
    body.extend(b"LIST");
    body.extend((4 + 8 + 1000u32).to_le_bytes());
    body.extend(b"movi00dc");
    body.extend(1000u32.to_le_bytes());
    body.extend(rng.bytes(1000));
    body.extend(b"idx1\x10\0\0\0");
    body.extend([0u8; 16]);
    let mut v = b"RIFF".to_vec();
    v.extend((body.len() as u32).to_le_bytes());
    v.extend(body);
    v
}

fn ts_file(rng: &mut Rng) -> Vec<u8> {
    let mut v = Vec::new();
    for _ in 0..50 {
        let mut p = rng.bytes(188);
        p[0] = 0x47;
        p[1] &= 0x7F;
        v.extend(p);
    }
    v
}

fn flv_file(rng: &mut Rng) -> Vec<u8> {
    let mut v = b"FLV\x01\x05\0\0\0\x09\0\0\0\0".to_vec();
    for i in 0..3u8 {
        v.extend([if i == 0 { 18 } else { 9 }, 0, 0, 100, 0, 0, i, 0, 0, 0, 0]);
        v.extend(rng.bytes(100));
        v.extend(111u32.to_be_bytes());
    }
    v
}

fn midi_file() -> Vec<u8> {
    let mut v = b"MThd\0\0\0\x06\0\x01\0\x02\0\x60".to_vec();
    v.extend(b"MTrk\0\0\0\x0a\0\xFF\x51\x03\x07\xA1\x20\0\xFF\x2F");
    v.extend(b"MTrk\0\0\0\x05\0\x90\x3C\x40\0");
    v
}

fn iso_file(rng: &mut Rng) -> Vec<u8> {
    let mut v = rng.bytes(20 * 2048);
    v[..0x8000].fill(0);
    let p = &mut v[0x8000..0x8800];
    p.fill(0x20);
    p[..7].copy_from_slice(b"\x01CD001\x01");
    p[80..84].copy_from_slice(&20u32.to_le_bytes());
    p[84..88].copy_from_slice(&20u32.to_be_bytes());
    p[128..130].copy_from_slice(&2048u16.to_le_bytes());
    v
}

fn cab_file(rng: &mut Rng) -> Vec<u8> {
    let mut v = rng.bytes(5000);
    v[..36].fill(0);
    v[..4].copy_from_slice(b"MSCF");
    v[8..12].copy_from_slice(&5000u32.to_le_bytes());
    v[16..20].copy_from_slice(&44u32.to_le_bytes());
    v[24] = 3;
    v[25] = 1;
    v
}

fn pe_file(rng: &mut Rng) -> Vec<u8> {
    let mut v = rng.bytes(0xE00);
    v[..0x400].fill(0);
    v[..2].copy_from_slice(b"MZ");
    v[0x3C] = 0x80;
    let e = 0x80;
    v[e..e + 4].copy_from_slice(b"PE\0\0");
    v[e + 4..e + 6].copy_from_slice(&0x14Cu16.to_le_bytes());
    v[e + 6] = 2;
    v[e + 20..e + 22].copy_from_slice(&224u16.to_le_bytes());
    v[e + 22..e + 24].copy_from_slice(&0x0102u16.to_le_bytes());
    let o = e + 24;
    v[o..o + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
    v[o + 60..o + 64].copy_from_slice(&0x400u32.to_le_bytes());
    v[o + 92..o + 96].copy_from_slice(&16u32.to_le_bytes());
    let s = o + 224;
    for (i, (name, ptr, size)) in [(b".text\0\0\0", 0x400u32, 0x800u32), (b".data\0\0\0", 0xC00, 0x200)].iter().enumerate() {
        let x = s + 40 * i;
        v[x..x + 8].copy_from_slice(*name);
        v[x + 16..x + 20].copy_from_slice(&size.to_le_bytes());
        v[x + 20..x + 24].copy_from_slice(&ptr.to_le_bytes());
    }
    v
}

fn ole_file(rng: &mut Rng) -> Vec<u8> {
    let mut v = vec![0u8; 512];
    v[..8].copy_from_slice(&crate::formats::sniff::OLE);
    v[0x18] = 0x3E;
    v[0x1A] = 3;
    v[0x1C..0x1E].copy_from_slice(&[0xFE, 0xFF]);
    v[0x1E] = 9;
    v[0x20] = 6;
    v[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes());
    v[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
    v[0x38..0x3C].copy_from_slice(&4096u32.to_le_bytes());
    v[0x3C..0x40].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
    v[0x44..0x48].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
    for i in 0..109 {
        v[0x4C + 4 * i..0x50 + 4 * i].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }
    v[0x4C..0x50].copy_from_slice(&0u32.to_le_bytes());
    let mut fat = vec![0xFFu8; 512];
    for (i, val) in [0xFFFF_FFFDu32, 0xFFFF_FFFE, 3, 0xFFFF_FFFE].iter().enumerate() {
        fat[4 * i..4 * i + 4].copy_from_slice(&val.to_le_bytes());
    }
    v.extend(fat);
    let mut dir = vec![0u8; 512];
    let ent = |d: &mut [u8], name: &str, ty: u8, start: u32, size: u32| {
        for (i, c) in name.encode_utf16().enumerate() {
            d[2 * i..2 * i + 2].copy_from_slice(&c.to_le_bytes());
        }
        d[64..66].copy_from_slice(&((name.len() as u16 + 1) * 2).to_le_bytes());
        d[66] = ty;
        d[68..80].fill(0xFF);
        d[116..120].copy_from_slice(&start.to_le_bytes());
        d[120..124].copy_from_slice(&size.to_le_bytes());
    };
    ent(&mut dir[..128], "Root Entry", 5, 0xFFFF_FFFE, 0);
    ent(&mut dir[128..256], "WordDocument", 2, 2, 1024);
    v.extend(dir);
    v.extend(rng.bytes(1024));
    v
}

fn pst_file(rng: &mut Rng) -> Vec<u8> {
    let mut v = rng.bytes(8192);
    v[..12].copy_from_slice(b"!BDN\0\0\0\0SM\x17\0");
    v[0xB8..0xC0].copy_from_slice(&8192u64.to_le_bytes());
    v
}

#[test]
fn carves_more_formats_exactly() {
    let mut rng = Rng(0x5151_7777);
    let mut l = Layout::new(8 << 20, &mut rng);
    let mut want: Vec<(usize, usize, &str)> = Vec::new();
    let mut add = |l: &mut Layout, ty: &'static str, bytes: Vec<u8>| {
        let off = l.put(ty, &bytes, 0);
        // Zeros after stream formats so the filler can't continue them by chance.
        let z = off + bytes.len();
        l.disk[z..z + 16].fill(0);
        want.push((off, bytes.len(), ty));
    };
    add(&mut l, "gz", gzip_file(&mut rng));
    add(&mut l, "tar", tar_file(&mut rng));
    add(&mut l, "tiff", tiff_file(&mut rng));
    add(&mut l, "webp", webp_file(&mut rng));
    add(&mut l, "mkv", mkv_file(&mut rng, false));
    add(&mut l, "mkv", mkv_file(&mut rng, true));
    add(&mut l, "avi", avi_file(&mut rng));
    add(&mut l, "ts", ts_file(&mut rng));
    add(&mut l, "flv", flv_file(&mut rng));
    add(&mut l, "mid", midi_file());
    add(&mut l, "iso", iso_file(&mut rng));
    add(&mut l, "cab", cab_file(&mut rng));
    add(&mut l, "exe", pe_file(&mut rng));
    add(&mut l, "doc", ole_file(&mut rng));
    add(&mut l, "pst", pst_file(&mut rng));
    let files = run(l.disk.clone(), ScanOptions::default(), |_| {});
    for (off, len, ty) in want {
        let f = at(&files, off as u64).unwrap_or_else(|| panic!("no {ty} at {off:#x}"));
        assert_eq!((f.type_id.as_str(), f.size, f.condition), (ty, len as u64, Condition::Good), "{ty}: {}", f.note);
    }
}

/// Real files, truncated and with random bytes flipped, through every parser directly (no
/// panic guard): nothing may panic and no length may exceed the source.
#[test]
fn parsers_survive_mutations() {
    let mut rng = Rng(0xF00D);
    let (jpg, _) = jpeg_with_thumb(&mut rng);
    let seeds: Vec<(Fam, Vec<u8>)> = vec![
        (Fam::Jpeg, jpg),
        (Fam::Png, encode_png(&mut rng)),
        (Fam::Gif, encode_gif(&mut rng)),
        (Fam::Bmp, encode_bmp(&mut rng)),
        (Fam::Zip, zip_of(&[("a.txt", b"hello hello hello", true), ("b.bin", &[1, 2, 3, 4], false)])),
        (Fam::Pdf, pdf_with_update()),
        (Fam::Mp3, mp3_file(&mut rng)),
        (Fam::Riff, wav_file(&mut rng)),
        (Fam::Riff, avi_file(&mut rng)),
        (Fam::Bmff, mp4_file(&mut rng)),
        (Fam::Sqlite, sqlite_file(&mut rng)),
        (Fam::Gzip, gzip_file(&mut rng)),
        (Fam::Tar, tar_file(&mut rng)),
        (Fam::Tiff, tiff_file(&mut rng)),
        (Fam::Ebml, mkv_file(&mut rng, true)),
        (Fam::MpegTs, ts_file(&mut rng)),
        (Fam::Flv, flv_file(&mut rng)),
        (Fam::Midi, midi_file()),
        (Fam::Iso, iso_file(&mut rng)),
        (Fam::Cab, cab_file(&mut rng)),
        (Fam::Pe, pe_file(&mut rng)),
        (Fam::Ole, ole_file(&mut rng)),
        (Fam::Pst, pst_file(&mut rng)),
    ];
    let hits = [0u64, 4096, 1 << 20];
    let env = Env { cluster: 4096, hits: &hits };
    for (fam, seed) in &seeds {
        for round in 0..150 {
            let mut v = seed.clone();
            let cut = if round % 3 == 0 { (rng.next() as usize % v.len()).max(16) } else { v.len() };
            v.truncate(cut);
            for _ in 0..(round % 7) {
                let i = 8 + rng.next() as usize % (v.len().saturating_sub(8).max(1));
                if i < v.len() {
                    v[i] = rng.next() as u8;
                }
            }
            if round % 2 == 0 {
                let n = rng.next() as usize % 9000;
                v.extend(rng.bytes(n));
            }
            let src = MemSource::new(v);
            let mut rd = rd::Rd::new(&src, 0);
            if let Some(p) = parse::run(*fam, &mut rd, &env) {
                assert!(p.len <= src.data.len() as u64 || !p.frags.is_empty(), "{fam:?} len {} > {}", p.len, src.data.len());
            }
        }
    }
    // Every family on noise and on zeros behind (part of) its signature.
    for f in sig::ALL {
        for round in 0..40 {
            let mut v = if round % 2 == 0 { rng.bytes(70000) } else { vec![0u8; 70000] };
            if let Some((_, s)) = seeds.iter().find(|(g, _)| *g == f) {
                let n = (round * 7 + 4).min(s.len());
                v[..n].copy_from_slice(&s[..n]);
            }
            let src = MemSource::new(v);
            let mut rd = rd::Rd::new(&src, 0);
            let _ = parse::run(f, &mut rd, &env);
        }
    }
}

// ------------------------------------------------------------------- streams, sizes, limits

fn m2ts_stream(rng: &mut Rng, packets: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(packets * 192);
    for i in 0..packets {
        let mut p = rng.bytes(192);
        p[..4].copy_from_slice(&(i as u32).to_be_bytes());
        p[4] = 0x47;
        p[5] &= 0x7F;
        v.extend(p);
    }
    v
}

fn ts_stream(rng: &mut Rng, packets: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(packets * 188);
    for _ in 0..packets {
        let mut p = rng.bytes(188);
        p[0] = 0x47;
        p[1] &= 0x7F;
        v.extend(p);
    }
    v
}

/// DVD-style MPEG-2 program stream: 2048-byte packs, no program end code.
fn vob_stream(rng: &mut Rng, packs: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(packs * 2048);
    for _ in 0..packs {
        let mut p = vec![0, 0, 1, 0xBA, 0x44, 0, 4, 0, 4, 1, 1, 0x89, 0xC3, 0xF8];
        p.extend([0, 0, 1, 0xE0]);
        p.extend(2028u16.to_be_bytes());
        p.extend(rng.bytes(2028).into_iter().map(|b| if b == 0 { 1 } else { b }));
        v.extend(p);
    }
    v
}

fn mp3_stream(rng: &mut Rng, frames: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(frames * 417);
    for _ in 0..frames {
        v.extend([0xFF, 0xFB, 0x90, 0x00]);
        v.extend(rng.bytes(413));
    }
    v
}

/// Each stream is walked once from its first hit; the hits inside it are dropped, and each one
/// comes out as a single file (an MPEG-PS with no end code isn't cut at every pack).
#[test]
fn streams_are_walked_once_and_come_out_whole() {
    let mut rng = Rng(0x57AE_A11);
    let mut l = Layout::new(10 << 20, &mut rng);
    let mut want: Vec<(usize, usize, &str, Condition)> = Vec::new();
    let mut add = |l: &mut Layout, ty: &'static str, bytes: Vec<u8>, cond: Condition| {
        let off = l.put(ty, &bytes, 0);
        let z = off + bytes.len();
        l.disk[z..z + 16].fill(0);
        want.push((off, bytes.len(), ty, cond));
    };
    add(&mut l, "mts", m2ts_stream(&mut rng, 8000), Condition::Good);
    add(&mut l, "ts", ts_stream(&mut rng, 8000), Condition::Good);
    add(&mut l, "mpg", vob_stream(&mut rng, 700), Condition::Unknown);
    add(&mut l, "mp3", mp3_stream(&mut rng, 3000), Condition::Good);
    let png = encode_png(&mut rng);
    let png_off = l.put("png", &png, 0);

    // The pre-pass: many hits per stream, one parse each.
    let src = MemSource::new(l.disk.clone());
    let (ctx, _sinks) = ScanCtx::for_test(ScanOptions::default(), src.data.len() as u64);
    let carver = Carver::new(&ctx);
    for o in (0..src.data.len()).step_by(CHUNK) {
        let end = (o + CHUNK).min(src.data.len());
        carver.visit(&src, o as u64, &src.data[o..end], &ctx);
    }
    let mut hits = std::mem::take(&mut *carver.hits.lock().unwrap());
    hits.sort_unstable();
    hits.dedup();
    let offsets: Vec<u64> = hits.iter().map(|h| h.off).collect();
    let env = Env { cluster: 4096, hits: &offsets };
    for par in [1, 4] {
        let pre = carver.walk_streams_with(&src, &hits, &env, &ctx, par, SPEC_SEG, SPEC_CAP);
        for &(off, len, ty, _) in &want {
            let inside: Vec<usize> = (0..hits.len()).filter(|&i| hits[i].off >= off as u64 && hits[i].off < (off + len) as u64).collect();
            let parsed = inside.iter().filter(|&&i| pre.done.get(i)).count();
            let dropped = inside.iter().filter(|&&i| pre.drop.get(i)).count();
            assert!(inside.len() > 3, "{ty}: only {} hits", inside.len());
            assert_eq!((parsed, dropped), (1, inside.len() - 1), "{ty} par {par}");
        }
    }

    let files = run(l.disk.clone(), ScanOptions::default(), |_| {});
    for (off, len, ty, cond) in want {
        let f = at(&files, off as u64).unwrap_or_else(|| panic!("no {ty} at {off:#x}"));
        assert_eq!((f.type_id.as_str(), f.size, f.condition), (ty, len as u64, cond), "{ty}: {}", f.note);
        let others = files.iter().filter(|g| g.extents[0].offset > off as u64 && g.extents[0].offset < (off + len) as u64).count();
        assert_eq!(others, 0, "{ty} was split");
    }
    assert!(at(&files, png_off as u64).is_some());
}

/// The parallel, speculative walk decides exactly what the in-order walk decides, whether the
/// speculative parses fit in their read limit or overrun it.
#[test]
fn speculative_stream_walk_matches_the_in_order_walk() {
    let mut rng = Rng(0x5BEC_0001);
    let mut l = Layout::new(16 << 20, &mut rng);
    for k in 0..120 {
        let frames = 40 + (k * 37) % 90;
        let bytes = mp3_stream(&mut rng, frames);
        l.put("mp3", &bytes, k % 5);
        if k % 20 == 7 {
            // Short and long M2TS clips: a hit every 1536 bytes.
            let clip = m2ts_stream(&mut rng, 300 + k * 40);
            l.put("mts", &clip, 0);
        }
    }
    let src = MemSource::new(l.disk.clone());
    let (ctx, _sinks) = ScanCtx::for_test(ScanOptions::default(), src.data.len() as u64);
    let carver = Carver::new(&ctx);
    for o in (0..src.data.len()).step_by(CHUNK) {
        let end = (o + CHUNK).min(src.data.len());
        carver.visit(&src, o as u64, &src.data[o..end], &ctx);
    }
    let mut hits = std::mem::take(&mut *carver.hits.lock().unwrap());
    hits.sort_unstable();
    hits.dedup();
    let offsets: Vec<u64> = hits.iter().map(|h| h.off).collect();
    let env = Env { cluster: 4096, hits: &offsets };
    let sum = |w: &Walked| {
        let bits: Vec<(bool, bool)> = (0..hits.len()).map(|i| (w.drop.get(i), w.done.get(i))).collect();
        let files: Vec<(usize, u64, u64)> = w.cands.iter().map(|(i, c)| (*i, c.off, c.len)).collect();
        (bits, files)
    };
    let base = sum(&carver.walk_streams_with(&src, &hits, &env, &ctx, 1, SPEC_SEG, SPEC_CAP));
    assert!(base.1.len() >= 120, "only {} streams", base.1.len());
    let inside = base.0.iter().filter(|b| b.0).count();
    assert!(inside > 1000, "only {inside} hits inside streams");
    for (par, seg, cap) in [(4, SPEC_SEG, SPEC_CAP), (4, 8, SPEC_CAP), (3, 5, 64 << 10), (8, 3, 4 << 10), (2, 16, 300 << 10), (6, 1, 1 << 20)] {
        assert_eq!(sum(&carver.walk_streams_with(&src, &hits, &env, &ctx, par, seg, cap)), base, "par {par} seg {seg} cap {cap}");
    }
}

/// An estimated end is cut at a header inside space another file already claimed, even though
/// that header isn't parsed again.
#[test]
fn pending_file_is_cut_at_a_claimed_hit() {
    let cand = |off: u64, len: u64, soft: bool| Cand { off, len, end: End::Estimated, frags: Vec::new(), kind: Kind::Builtin("mpg"), report: true, soft };
    let known = HashSet::new();
    let mut out = Vec::new();
    let mut res = Resolver::default();
    res.claimed.insert(5000, 6000);
    res.take(Hit { off: 1000, code: 0 }, Some(cand(1000, 9000, true)), &known, &mut out);
    // A header that doesn't parse is payload.
    res.take(Hit { off: 3000, code: 0 }, None, &known, &mut out);
    assert!(out.is_empty());
    // A claimed one cuts it.
    res.take(Hit { off: 5000, code: 0 }, None, &known, &mut out);
    res.flush(&known, &mut out);
    assert_eq!(out.iter().map(|c| (c.off, c.len)).collect::<Vec<_>>(), vec![(1000, 4000)]);
}

fn wav_with_sizes(rng: &mut Rng, riff: u32, data: u32, samples: usize) -> Vec<u8> {
    let mut v = b"RIFF".to_vec();
    v.extend(riff.to_le_bytes());
    v.extend(b"WAVEfmt ");
    v.extend(16u32.to_le_bytes());
    v.extend([1, 0, 2, 0, 0x44, 0xAC, 0, 0, 0x10, 0xB1, 2, 0, 4, 0, 16, 0]);
    v.extend(b"data");
    v.extend(data.to_le_bytes());
    v.extend(rng.bytes(samples));
    v
}

/// Placeholder RIFF sizes from recordings that were never finalized are not trusted as ends.
#[test]
fn riff_placeholder_sizes_are_estimated() {
    let mut rng = Rng(0xA0D1);
    for (riff, data) in [(0xFFFF_FFFFu32, 0xFFFF_FFFFu32), (36, 0), (36, 0xFFFF_FFFF)] {
        let mut l = Layout::new(4 << 20, &mut rng);
        let wav = wav_with_sizes(&mut rng, riff, data, 60000);
        let off = l.put("wav", &wav, 0);
        let png = encode_png(&mut rng);
        let png_off = l.put("png", &png, 0);
        let files = run(l.disk.clone(), ScanOptions::default(), |_| {});
        let f = at(&files, off as u64).expect("wav");
        assert_eq!((f.type_id.as_str(), f.size, f.condition), ("wav", (png_off - off) as u64, Condition::Unknown), "{riff:#x}/{data:#x}");
        assert!(at(&files, png_off as u64).is_some(), "the PNG after a placeholder WAV is listed");
    }
    // Only the RIFF size is a placeholder: the data chunk's size ends the file.
    let mut l = Layout::new(2 << 20, &mut rng);
    let wav = wav_with_sizes(&mut rng, 0xFFFF_FFFF, 60000, 60000);
    let off = l.put("wav", &wav, 0);
    let files = run(l.disk.clone(), ScanOptions::default(), |_| {});
    let f = at(&files, off as u64).expect("wav");
    assert_eq!((f.size, f.condition), (wav.len() as u64, Condition::Good));
}

/// A PDF whose %%EOF is gone ends before the next file, not at a later PDF's %%EOF.
#[test]
fn pdf_without_eof_stops_at_the_next_file() {
    let mut rng = Rng(0x9DF);
    let full = pdf_with_update();
    let cut = crate::formats::sniff::find(&full, b"%%EOF").unwrap();
    let mut l = Layout::new(2 << 20, &mut rng);
    let a_off = l.put("pdf", &full[..cut], 0);
    let png = encode_png(&mut rng);
    let png_off = l.put("png", &png, 0);
    let b_off = l.put("pdf", &full, 0);
    let z = b_off + full.len();
    l.disk[z..z + 16].fill(0);
    let files = run(l.disk.clone(), ScanOptions::default(), |_| {});
    let a = at(&files, a_off as u64).expect("first pdf");
    assert_eq!((a.size, a.condition), ((png_off - a_off) as u64, Condition::Partial));
    assert!(at(&files, png_off as u64).is_some(), "the PNG between the PDFs is listed");
    let b = at(&files, b_off as u64).expect("second pdf");
    assert_eq!((b.size, b.condition), (full.len() as u64, Condition::Good));

    // With no file in between, it still stops at the next PDF's header.
    let mut l = Layout::new(2 << 20, &mut rng);
    let a_off = l.put("pdf", &full[..cut], 0);
    let b_off = l.put("pdf", &full, 0);
    let files = run(l.disk.clone(), ScanOptions::default(), |_| {});
    assert_eq!(at(&files, a_off as u64).expect("first pdf").size, (b_off - a_off) as u64);
    assert_eq!(at(&files, b_off as u64).expect("second pdf").size, full.len() as u64);
}

/// Hostile headers that used to loop forever (ASF size wrap) or reserve gigabytes (OLE FAT).
#[test]
fn hostile_asf_and_ole_headers_are_bounded() {
    let env = Env { cluster: 4096, hits: &[] };
    // ASF: object at 30 of size 24, object at 54 whose size wraps back to 30.
    let mut v = vec![0u8; 4096];
    v[..16].copy_from_slice(&crate::formats::sniff::ASF_HEADER);
    v[16..24].copy_from_slice(&200u64.to_le_bytes());
    v[30..46].fill(0x11);
    v[46..54].copy_from_slice(&24u64.to_le_bytes());
    v[54..70].fill(0x22);
    v[70..78].copy_from_slice(&0xFFFF_FFFF_FFFF_FFE8u64.to_le_bytes());
    let src = MemSource::new(v);
    let mut rd = rd::Rd::new(&src, 0);
    let _ = parse::run(Fam::Asf, &mut rd, &env);

    // OLE v4 claiming 2^20 FAT sectors through a DIFAT sector that points at itself.
    let mut v = vec![0u8; 64 * 1024];
    v[..8].copy_from_slice(&crate::formats::sniff::OLE);
    v[0x1A..0x1C].copy_from_slice(&4u16.to_le_bytes());
    v[0x1C..0x1E].copy_from_slice(&[0xFE, 0xFF]);
    v[0x1E..0x20].copy_from_slice(&12u16.to_le_bytes());
    v[0x2C..0x30].copy_from_slice(&(1u32 << 20).to_le_bytes());
    v[0x30..0x34].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
    v[0x44..0x48].copy_from_slice(&0u32.to_le_bytes());
    v[0x48..0x4C].copy_from_slice(&1100u32.to_le_bytes());
    v[0x4C..0x200].fill(0xFF);
    let src = MemSource::new(v);
    let mut rd = rd::Rd::new(&src, 0);
    let t = std::time::Instant::now();
    assert_eq!(parse::run(Fam::Ole, &mut rd, &env), None);
    assert!(t.elapsed() < std::time::Duration::from_secs(20), "{:?}", t.elapsed());
}

fn crc8(b: &[u8]) -> u8 {
    b.iter().fold(0u8, |mut c, &x| {
        c ^= x;
        for _ in 0..8 {
            c = if c & 0x80 != 0 { (c << 1) ^ 0x07 } else { c << 1 };
        }
        c
    })
}

fn crc16(b: &[u8]) -> u16 {
    b.iter().fold(0u16, |mut c, &x| {
        c ^= (x as u16) << 8;
        for _ in 0..8 {
            c = if c & 0x8000 != 0 { (c << 1) ^ 0x8005 } else { c << 1 };
        }
        c
    })
}

/// A FLAC frame: header (block size code, optional explicit size), body, CRC-16 footer.
fn flac_frame_bytes(num: u8, bs: u8, explicit: Option<u16>, body: &[u8]) -> Vec<u8> {
    let mut h = vec![0xFF, 0xF8, (bs << 4) | 9, 0x18, num];
    if let Some(n) = explicit {
        h.extend((n - 1).to_be_bytes());
    }
    h.push(crc8(&h));
    h.extend(body);
    let c = crc16(&h);
    h.extend(c.to_be_bytes());
    h
}

/// Five 4096-sample frames and a 1000-sample last frame whose running CRC-16 hits zero by chance
/// 300 bytes in. Returns the stream and the length of its last frame.
fn flac_with_false_zero(rng: &mut Rng, min_frame: u32, max_frame: u32) -> (Vec<u8>, usize) {
    let mut v = b"fLaC".to_vec();
    v.extend([0x80, 0, 0, 34]);
    let mut si = vec![0x10, 0, 0x10, 0];
    si.extend(&min_frame.to_be_bytes()[1..]);
    si.extend(&max_frame.to_be_bytes()[1..]);
    si.extend([0x0A, 0xC4, 0x42, 0xF0]);
    si.extend((5 * 4096 + 1000u32).to_be_bytes());
    si.extend([0u8; 16]);
    v.extend(si);
    for n in 0..5u8 {
        v.extend(flac_frame_bytes(n, 12, None, &rng.bytes(3000)));
    }
    // Last frame: header + 300 bytes, then the two bytes that zero the running CRC, then more.
    let mut head = vec![0xFF, 0xF8, (7 << 4) | 9, 0x18, 5];
    head.extend(999u16.to_be_bytes());
    head.push(crc8(&head));
    let mut body = rng.bytes(300);
    let mut pre = head.clone();
    pre.extend(&body);
    body.extend(crc16(&pre).to_be_bytes());
    body.extend(rng.bytes(430));
    let last = flac_frame_bytes(5, 7, Some(1000), &body);
    assert_eq!(&last[..head.len()], &head[..]);
    v.extend(&last);
    (v, last.len())
}

/// The last FLAC frame ends at its real end, not at the first chance zero of the running CRC.
#[test]
fn flac_last_frame_is_not_cut_at_a_chance_crc_zero() {
    let mut rng = Rng(0xF1AC);
    for (min, max, end) in [(700, 3100, End::Clean), (0, 0, End::Estimated)] {
        let (mut v, _) = flac_with_false_zero(&mut rng, min, max);
        let len = v.len() as u64;
        v.extend([0u8; 4096]);
        v.extend(rng.bytes(8192));
        let src = MemSource::new(v);
        let mut rd = rd::Rd::new(&src, 0);
        let env = Env { cluster: 4096, hits: &[] };
        let p = parse::run(Fam::Flac, &mut rd, &env).expect("flac");
        assert_eq!((p.len, p.end), (len, end), "min {min} max {max}");
    }
}
