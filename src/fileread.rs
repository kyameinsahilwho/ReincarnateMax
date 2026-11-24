//! Reading a found file's content, wherever it lives: extents on the scan source (with sparse
//! holes and unreadable sectors as zeros), resident bytes kept in the metadata, NTFS-compressed
//! runs, or a file Windows can still open (Recycle Bin items). Used by preview, validation,
//! duplicate detection and recovery. Owned by the orchestrator.

use crate::device::source::{read_tolerant, BlockSource, Source};
use crate::model::{flags, FoundFile, SPARSE};
use std::io::{Read, Seek, SeekFrom};

/// Read up to `buf.len()` bytes at file position `pos`. Returns bytes read (0 at end of file) and
/// whether any of them came from unreadable sectors (zero-filled).
pub fn read_at(src: Option<&dyn BlockSource>, f: &FoundFile, pos: u64, buf: &mut [u8]) -> Result<(usize, bool), String> {
    if pos >= f.size || buf.is_empty() {
        return Ok((0, false));
    }
    let want = (buf.len() as u64).min(f.size - pos) as usize;
    let buf = &mut buf[..want];

    if let Some(p) = &f.live_path {
        let mut file = std::fs::File::open(p).map_err(|e| format!("Windows couldn't open {p} ({e})."))?;
        file.seek(SeekFrom::Start(pos)).map_err(|e| e.to_string())?;
        let mut got = 0;
        while got < want {
            match file.read(&mut buf[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) => return Err(format!("Windows couldn't read {p} ({e}).")),
            }
        }
        return Ok((got, false));
    }
    if let Some(r) = &f.resident {
        let start = (pos as usize).min(r.len());
        let n = want.min(r.len() - start);
        buf[..n].copy_from_slice(&r[start..start + n]);
        return Ok((n, false));
    }
    let src = src.ok_or_else(|| "The drive this file was found on isn't available.".to_string())?;
    if f.flags & flags::COMPRESSED != 0 {
        return crate::fs::ntfs::read_compressed_checked(src, f, pos, buf);
    }

    let mut got = 0usize;
    let mut bad_any = false;
    let mut file_pos = 0u64; // file offset at the start of the current extent
    for e in &f.extents {
        if got == want {
            break;
        }
        let ext_end = file_pos + e.len;
        let cur = pos + got as u64;
        if cur < ext_end && cur >= file_pos {
            let within = cur - file_pos;
            let n = ((e.len - within) as usize).min(want - got);
            let piece = &mut buf[got..got + n];
            if e.offset == SPARSE {
                piece.fill(0);
            } else {
                let (r, bad) = read_tolerant(src, e.offset + within, piece, None);
                if r < n {
                    piece[r..].fill(0);
                }
                bad_any |= !bad.is_empty();
            }
            got += n;
        }
        file_pos = ext_end;
    }
    Ok((got, bad_any))
}

/// Up to `max` bytes from the start of the file.
pub fn read_prefix(src: Option<&dyn BlockSource>, f: &FoundFile, max: usize) -> Result<Vec<u8>, String> {
    let n = (f.size.min(max as u64)) as usize;
    let mut buf = vec![0u8; n];
    let (got, _) = read_at(src, f, 0, &mut buf)?;
    buf.truncate(got);
    Ok(buf)
}

/// `Read + Seek` over a found file, for decoders (zip, image) that want a stream.
pub struct FileReader {
    pub src: Option<Source>,
    pub file: FoundFile,
    pub pos: u64,
    /// Set when any byte came from an unreadable sector.
    pub hit_bad_sectors: bool,
}

impl FileReader {
    pub fn new(src: Option<Source>, file: FoundFile) -> Self {
        FileReader { src, file, pos: 0, hit_bad_sectors: false }
    }
}

impl Read for FileReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let (n, bad) = read_at(self.src.as_deref(), &self.file, self.pos, buf).map_err(std::io::Error::other)?;
        self.pos += n as u64;
        self.hit_bad_sectors |= bad;
        Ok(n)
    }
}

impl Seek for FileReader {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        let size = self.file.size as i128;
        let p: i128 = match to {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(d) => size + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if p < 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek before start"));
        }
        self.pos = p as u64;
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::source::MemSource;
    use crate::model::Extent;

    #[test]
    fn reads_across_fragments_and_sparse_holes() {
        let data: Vec<u8> = (0..4096u32).map(|i| (i % 256) as u8).collect();
        let m = MemSource::new(data);
        let f = FoundFile {
            size: 1200,
            extents: vec![Extent { offset: 1024, len: 512 }, Extent { offset: SPARSE, len: 512 }, Extent { offset: 0, len: 512 }],
            ..Default::default()
        };
        let mut buf = vec![9u8; 2000];
        let (n, bad) = read_at(Some(&m), &f, 0, &mut buf).unwrap();
        assert_eq!((n, bad), (1200, false));
        assert_eq!(buf[0], 0); // 1024 % 256
        assert_eq!(buf[511], 255);
        assert!(buf[512..1024].iter().all(|&b| b == 0));
        assert_eq!(buf[1024], 0);
        assert_eq!(buf[1199], 175);
        // Mid-file read starting inside the second fragment.
        let mut b2 = [0u8; 4];
        let (n2, _) = read_at(Some(&m), &f, 1100, &mut b2).unwrap();
        assert_eq!(n2, 4);
        assert_eq!(b2, [76, 77, 78, 79]);
    }

    #[test]
    fn resident_and_reader() {
        let f = FoundFile { size: 5, resident: Some(b"hello".to_vec()), ..Default::default() };
        let mut r = FileReader::new(None, f);
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello");
        r.seek(SeekFrom::End(-2)).unwrap();
        let mut t = String::new();
        r.read_to_string(&mut t).unwrap();
        assert_eq!(t, "lo");
    }
}
