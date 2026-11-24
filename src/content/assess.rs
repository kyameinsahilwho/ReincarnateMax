//! Quick condition assessment after a scan: one read of at most 4 KiB per file.
//!
//! | Evidence in the first ≤ 4 KiB                         | Result                                                   |
//! |-------------------------------------------------------|----------------------------------------------------------|
//! | file still exists / is in the Recycle Bin             | Excellent, "It still exists." / "It's in the Recycle Bin." (no read) |
//! | the read hit unreadable sectors                       | Partial + BAD_SECTORS                                    |
//! | prefix is all zeros (type normally non-zero)          | Partial + ZEROED, "Its data reads as zeros — …TRIM."     |
//! | extension's own signature matches                     | engine verdict kept; Unknown with no engine note → Good "The header matches its type." |
//! | content detected as another type (not same family)    | EXT_MISMATCH, type_id = detected, "Its content is a <label>, not a .<ext> file." |
//! | extension type has a signature, content doesn't match | Partial "Its start doesn't look like a <label> any more…" (kept as is if the engine already said OVERWRITTEN) |
//! | content detected, same family as the extension        | as "signature matches"                                   |
//! | no signature known, nothing detected                  | engine verdict kept                                      |
//!
//! The engine's Partial is never upgraded, nor an Unknown the engine explained (an estimated end,
//! a guessed location). Notes are one sentence and never claim certainty.

use super::util::*;
use crate::device::source::BlockSource;
use crate::model::{flags, Condition, FileStatus, FoundFile};

pub const NOTE_EXISTS: &str = "It still exists.";
pub const NOTE_RECYCLE: &str = "It's in the Recycle Bin.";
pub const NOTE_ZEROED: &str = "Its data reads as zeros — the drive has probably erased it (SSD TRIM).";
pub const NOTE_HEADER_OK: &str = "The header matches its type.";
pub const NOTE_BAD_SECTORS: &str = "Some of its sectors can't be read, so parts of it will be missing.";

/// Types whose content legitimately starts with zeros.
fn zero_start_ok(type_id: &str) -> bool {
    matches!(type_id, "iso" | "img" | "bin" | "dat" | "dmp" | "vhd" | "vhdx" | "vmdk" | "vdi" | "mdf" | "raw" | "sys" | "tmp" | "pf" | "etl" | "evtx" | "edb" | "pst" | "ost")
}

pub fn assess(src: Option<&dyn BlockSource>, f: &mut FoundFile) {
    match f.status {
        FileStatus::Existing => {
            f.condition = Condition::Excellent;
            f.note = NOTE_EXISTS.into();
            return;
        }
        FileStatus::RecycleBin => {
            f.condition = Condition::Excellent;
            f.note = NOTE_RECYCLE.into();
            return;
        }
        _ => {}
    }
    if f.size == 0 || f.flags & flags::ENCRYPTED != 0 {
        return;
    }
    let mut buf = vec![0u8; f.size.min(4096) as usize];
    let (n, bad) = match crate::fileread::read_at(src, f, 0, &mut buf) {
        Ok(r) => r,
        Err(_) => return,
    };
    buf.truncate(n);
    assess_prefix(f, &buf, bad);
}

/// The decision table above, on bytes already read.
pub fn assess_prefix(f: &mut FoundFile, p: &[u8], bad: bool) {
    if p.is_empty() {
        return;
    }
    let ext = f.ext();
    let ext_type = crate::formats::by_ext(&ext).map(|t| t.id.to_string());
    let claimed = ext_type.clone().unwrap_or_else(|| f.type_id.clone());
    let overwritten = f.flags & flags::OVERWRITTEN != 0;
    let set_partial = |f: &mut FoundFile, note: &str, flag: u32| {
        f.flags |= flag;
        f.condition = Condition::Partial;
        f.note = note.to_string();
    };

    if bad {
        set_partial(f, NOTE_BAD_SECTORS, flags::BAD_SECTORS);
    }
    if p.iter().all(|&b| b == 0) && !zero_start_ok(&claimed) && !zero_start_ok(&ext) {
        if !(overwritten && f.condition == Condition::Partial) {
            set_partial(f, NOTE_ZEROED, flags::ZEROED);
        } else {
            f.flags |= flags::ZEROED;
        }
        return;
    }
    let k = kind(&claimed);
    let own_sig = sig_matches(k, p);
    let detected = crate::formats::detect(p);
    // A matching header says nothing about an engine's own doubt (an estimated end, a guessed
    // location, clusters it couldn't check): Unknown with the engine's note stays as it is.
    let upgrade = |f: &mut FoundFile| {
        if f.note.is_empty() {
            if f.condition == Condition::Unknown {
                f.condition = Condition::Good;
            }
            f.note = NOTE_HEADER_OK.into();
        }
    };

    if own_sig == Some(true) {
        if f.type_id.is_empty() || ext_type.is_some() && family(&f.type_id) != family(&claimed) {
            f.type_id = claimed.clone();
        }
        upgrade(f);
        return;
    }
    // Text detection is weak evidence: a binary type whose start now reads as text was most
    // likely overwritten, not misnamed.
    let detected = detected.filter(|t| !(own_sig == Some(false) && family(t.id) == "text"));
    if let Some(t) = detected {
        if claimed.is_empty() || family(t.id) == family(&claimed) {
            if f.type_id.is_empty() {
                f.type_id = t.id.to_string();
            }
            // Text that reads as text proves little; keep the engine's verdict.
            if family(t.id) != "text" {
                upgrade(f);
            }
            return;
        }
        // The content is something else.
        f.type_id = t.id.to_string();
        if !ext.is_empty() {
            f.flags |= flags::EXT_MISMATCH;
            f.note = format!("Its content is a {}, not a .{} file.", t.label, ext);
        } else if f.condition == Condition::Unknown && f.note.is_empty() {
            f.condition = Condition::Good;
            f.note = NOTE_HEADER_OK.into();
        }
        return;
    }
    if own_sig == Some(false) && !overwritten {
        let label = crate::formats::by_id(&claimed).map(|t| t.label.to_string()).unwrap_or_else(|| format!(".{} file", claimed));
        set_partial(f, &format!("Its start doesn't look like a {label} any more — it was probably overwritten."), 0);
    } else if own_sig == Some(false) && overwritten {
        f.condition = Condition::Partial;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::source::MemSource;
    use crate::model::Extent;

    fn file(name: &str, content: &[u8], cond: Condition) -> (MemSource, FoundFile) {
        let mut data = vec![0u8; 512];
        data.extend_from_slice(content);
        let f = FoundFile {
            name: name.into(),
            size: content.len() as u64,
            type_id: crate::formats::by_ext(name.rsplit('.').next().unwrap()).map(|t| t.id.to_string()).unwrap_or_default(),
            extents: vec![Extent { offset: 512, len: content.len() as u64 }],
            condition: cond,
            note: "From the engine.".into(),
            ..Default::default()
        };
        (MemSource::new(data), f)
    }

    #[test]
    fn rules() {
        let jpg = [0xFF, 0xD8, 0xFF, 0xE0, 0, 16, b'J', b'F', b'I', b'F', 0];
        // Header matches: Unknown with no engine note -> Good; Excellent stays.
        let (m, mut f) = file("a.jpg", &jpg, Condition::Unknown);
        f.note.clear();
        assess(Some(&m), &mut f);
        assert_eq!((f.condition, f.note.as_str()), (Condition::Good, NOTE_HEADER_OK));
        // The carver estimated the end: the header doesn't settle that, so it stays Unknown.
        for (name, content) in [("a.jpg", &jpg[..]), ("a.sqlite", b"SQLite format 3\0\x10\0\x01\x01\0\x40\x20\x20".as_slice())] {
            let (m, mut f) = file(name, content, Condition::Unknown);
            f.status = FileStatus::Carved;
            f.note = "The end of this file was estimated.".into();
            assess(Some(&m), &mut f);
            assert_eq!((f.condition, f.note.as_str()), (Condition::Unknown, "The end of this file was estimated."), "{name}");
        }
        let (m, mut f) = file("a.jpg", &jpg, Condition::Excellent);
        assess(Some(&m), &mut f);
        assert_eq!(f.condition, Condition::Excellent);
        assert_eq!(f.note, "From the engine.");

        // Zeros.
        let (m, mut f) = file("a.jpg", &[0u8; 3000], Condition::Excellent);
        assess(Some(&m), &mut f);
        assert_eq!((f.condition, f.flags & flags::ZEROED), (Condition::Partial, flags::ZEROED));
        assert_eq!(f.note, NOTE_ZEROED);

        // Mismatch: a PDF named .jpg.
        let (m, mut f) = file("scan.jpg", b"%PDF-1.7\n%....", Condition::Good);
        assess(Some(&m), &mut f);
        assert_eq!(f.type_id, "pdf");
        assert!(f.flags & flags::EXT_MISMATCH != 0);
        assert_eq!(f.note, "Its content is a PDF document, not a .jpg file.");
        assert_eq!(f.name, "scan.jpg");

        // Signature gone, not zeros: overwritten.
        let (m, mut f) = file("a.png", b"random words here", Condition::Excellent);
        assess(Some(&m), &mut f);
        assert_eq!(f.condition, Condition::Partial);
        assert!(f.note.starts_with("Its start doesn't look like a PNG image any more"));

        // Engine said overwritten: keep its note, stay Partial.
        let (m, mut f) = file("a.png", b"random words here", Condition::Partial);
        f.flags |= flags::OVERWRITTEN;
        assess(Some(&m), &mut f);
        assert_eq!((f.condition, f.note.as_str()), (Condition::Partial, "From the engine."));

        // No signature known: keep.
        let (m, mut f) = file("notes.txt", b"hello", Condition::Unknown);
        assess(Some(&m), &mut f);
        assert_eq!(f.condition, Condition::Unknown);

        // Engine Partial with a good header stays Partial.
        let (m, mut f) = file("a.jpg", &jpg, Condition::Partial);
        assess(Some(&m), &mut f);
        assert_eq!(f.condition, Condition::Partial);

        // Bad sectors.
        let (mut m, mut f) = file("a.jpg", &jpg, Condition::Excellent);
        m.bad = vec![(512, 1024)];
        assess(Some(&m), &mut f);
        assert!(f.flags & flags::BAD_SECTORS != 0);
        assert_eq!(f.condition, Condition::Partial);

        // Existing files are not read.
        let mut f = FoundFile { status: FileStatus::Existing, size: 10, ..Default::default() };
        assess(None, &mut f);
        assert_eq!((f.condition, f.note.as_str()), (Condition::Excellent, NOTE_EXISTS));
    }
}
