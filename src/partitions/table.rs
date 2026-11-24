//! MBR (with the extended/logical chain) and GPT (primary + backup, CRC-checked) parsing, file
//! system detection per entry, unallocated gaps.

use super::view::{Patched, Win};
use super::{FoundPartition, GptHealth, PartitionReport};
use crate::device::source::{read_tolerant, BlockSource};
use crate::fs::fat::util::{rd16, rd32, rd64};
use std::collections::HashSet;

pub(crate) const MIB: u64 = 1 << 20;

pub(crate) fn read(src: &dyn BlockSource, off: u64, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len];
    if off < src.len() {
        read_tolerant(src, off, &mut b, None);
    }
    b
}

pub(crate) fn mbr_type_name(t: u8) -> &'static str {
    match t {
        0x01 => "FAT12",
        0x04 | 0x06 | 0x0E => "FAT16",
        0x07 => "NTFS / exFAT",
        0x0B | 0x0C => "FAT32",
        0x05 | 0x0F | 0x85 => "Extended",
        0x11 | 0x14 | 0x16 | 0x1B | 0x1C | 0x1E => "Hidden FAT",
        0x17 => "Hidden NTFS",
        0x27 => "Recovery",
        0x42 => "Dynamic disk",
        0x82 => "Linux swap",
        0x83 => "Linux",
        0x8E => "Linux LVM",
        0xA5 | 0xA6 | 0xA9 => "BSD",
        0xAF => "Apple HFS+",
        0xDE => "OEM utility",
        0xEE => "GPT protective",
        0xEF => "EFI system",
        0xFD => "Linux RAID",
        _ => "Unknown",
    }
}

/// Partition types that should hold a file system MAX reads (so an unrecognised boot sector
/// means "damaged" rather than "another kind of partition").
fn mbr_expects_fs(t: u8) -> bool {
    matches!(t, 0x01 | 0x04 | 0x06 | 0x07 | 0x0B | 0x0C | 0x0E | 0x11 | 0x14 | 0x16 | 0x17 | 0x1B | 0x1C | 0x1E | 0x27 | 0xEF)
}

pub(crate) fn guid_str(b: &[u8]) -> String {
    if b.len() < 16 {
        return String::new();
    }
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        rd32(b, 0),
        rd16(b, 4),
        rd16(b, 6),
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

/// (display name, expects a Windows-readable file system)
pub(crate) fn gpt_type_name(guid: &str) -> (&'static str, bool) {
    match guid {
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => ("EFI system", true),
        "E3C9E316-0B5C-4DB8-817D-F92DF00215AE" => ("Microsoft reserved", false),
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => ("Basic data", true),
        "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC" => ("Recovery", true),
        "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3" | "AF9B60A0-1431-4F62-BC68-3311714A69AD" => ("Dynamic disk", false),
        "E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D" => ("Storage Spaces", false),
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
        | "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709"
        | "933AC7E1-2EB4-4F13-B844-0E14E2AEF915"
        | "44479540-F297-41B2-9AF7-D131D5F0458A"
        | "3B8F8425-20E0-4F3B-907F-1A25A76F98E8" => ("Linux filesystem", false),
        "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => ("Linux swap", false),
        "E6D6D379-F507-44C2-A23C-238F2A3DF928" => ("Linux LVM", false),
        "A19D880F-05FC-4D3B-A006-743F0F84911E" => ("Linux RAID", false),
        "BC13C2FF-59E6-4262-A352-B275FD6F7172" => ("Linux boot", false),
        "21686148-6449-6E6F-744E-656564454649" => ("BIOS boot", false),
        "48465300-0000-11AA-AA11-00306543ECAC" => ("Apple HFS+", false),
        "7C3457EF-0000-11AA-AA11-00306543ECAC" => ("Apple APFS", false),
        "426F6F74-0000-11AA-AA11-00306543ECAC" => ("Apple boot", false),
        "55465300-0000-11AA-AA11-00306543ECAC" => ("Apple UFS", false),
        "52414944-0000-11AA-AA11-00306543ECAC" => ("Apple RAID", false),
        "516E7CB4-6ECF-11D6-8FF8-00022D09712B" | "83BD6B9D-7F41-11DC-BE0B-001560B84F0F" => ("FreeBSD", false),
        "37AFFC90-EF7D-4E96-91C3-2D7AE055B174" => ("IBM GPFS", false),
        _ => ("Unknown", false),
    }
}

/// Recognise the file system of a table entry and set fs/label/status/note.
pub(crate) fn detect(src: &dyn BlockSource, p: &mut FoundPartition, expects_fs: bool) {
    let len = src.len();
    if p.offset >= len {
        p.status = "damaged".into();
        p.note = "It starts beyond the end of the disk.".into();
        return;
    }
    let win = Win::new(src, p.offset, p.size);
    let mut found = crate::fs::probe_any(&win);
    let mut via_patch = false;
    if found.is_none() && win.len >= 1024 {
        // NTFS keeps its backup boot sector in the partition's last sector.
        let ss = src.sector_size().max(512) as u64;
        for at in [win.len - ss, win.len - 512] {
            let b = read(&win, at, 512);
            if &b[3..11] == b"NTFS    " && b[510] == 0x55 && b[511] == 0xAA {
                let patched = Patched { inner: &win, patch: b };
                if let Some(fp) = crate::fs::probe_any(&patched) {
                    found = Some(fp);
                    via_patch = true;
                    break;
                }
            }
        }
    }
    match found {
        Some(fp) => {
            if !fp.label.is_empty() {
                p.label = Some(fp.label.clone());
            }
            if fp.used_backup_boot || via_patch {
                p.status = "damaged".into();
                p.note = "Its first boot sector is damaged; the backup copy is intact.".into();
            } else {
                p.status = "ok".into();
                p.note = format!("Its {} file system is intact.", fp.fs);
            }
            if fp.total_size > p.size + MIB {
                p.note.push_str(" Its file system claims more space than the partition has.");
            }
            p.fs = Some(fp.fs);
        }
        None if expects_fs => {
            p.status = "damaged".into();
            p.note = "Its boot sector isn't recognised; it may be damaged or hold a file system MAX can't read.".into();
        }
        None => {
            p.status = "ok".into();
            p.note = if p.type_name == "Microsoft reserved" {
                "Windows reserves this space; it holds no files.".into()
            } else if p.type_name == "Extended" {
                "It holds the logical partitions.".into()
            } else {
                "MAX can't read this kind of partition.".into()
            };
        }
    }
    if p.offset + p.size > len {
        p.note.push_str(" It extends beyond the end of the disk.");
    }
}

struct MbrEntry {
    boot: u8,
    ptype: u8,
    start: u64,
    count: u64,
}

fn mbr_entries(s: &[u8]) -> [MbrEntry; 4] {
    std::array::from_fn(|i| {
        let e = &s[446 + i * 16..462 + i * 16];
        MbrEntry { boot: e[0], ptype: e[4], start: rd32(e, 8) as u64, count: rd32(e, 12) as u64 }
    })
}

fn mbr_valid(s: &[u8]) -> bool {
    if s[510] != 0x55 || s[511] != 0xAA {
        return false;
    }
    let es = mbr_entries(s);
    let mut any = false;
    for e in &es {
        if e.ptype == 0 {
            continue;
        }
        if !(e.boot == 0 || e.boot == 0x80) || e.start == 0 || e.count == 0 {
            return false;
        }
        any = true;
    }
    any
}

fn is_extended(t: u8) -> bool {
    matches!(t, 0x05 | 0x0F | 0x85)
}

fn parse_mbr(src: &dyn BlockSource, s: &[u8], ss: u64, rep: &mut PartitionReport, meta: &mut Vec<(u64, u64)>) {
    rep.style = "MBR".into();
    meta.push((0, ss));
    for (i, e) in mbr_entries(s).iter().enumerate() {
        if e.ptype == 0 {
            continue;
        }
        let mut p = FoundPartition {
            offset: e.start * ss,
            size: e.count * ss,
            type_name: mbr_type_name(e.ptype).into(),
            found_by: "mbr".into(),
            number: Some(i as u32 + 1),
            ..Default::default()
        };
        if is_extended(e.ptype) {
            p.status = "ok".into();
            p.note = "It holds the logical partitions.".into();
            rep.entries.push(p);
            walk_ebrs(src, e.start, e.count, ss, rep, meta);
            continue;
        }
        detect(src, &mut p, mbr_expects_fs(e.ptype));
        rep.entries.push(p);
    }
}

fn walk_ebrs(src: &dyn BlockSource, ext_start: u64, ext_count: u64, ss: u64, rep: &mut PartitionReport, meta: &mut Vec<(u64, u64)>) {
    let mut cur = ext_start;
    let mut seen = HashSet::new();
    let mut number = 5u32;
    for _ in 0..256 {
        if !seen.insert(cur) {
            rep.notes.push("The chain of logical partitions loops back on itself; it was followed once.".into());
            return;
        }
        if cur * ss >= src.len() {
            rep.notes.push("The chain of logical partitions points past the end of the disk.".into());
            return;
        }
        let s = read(src, cur * ss, 512);
        meta.push((cur * ss, cur * ss + ss));
        if s[510] != 0x55 || s[511] != 0xAA {
            if cur != ext_start {
                rep.notes.push("The chain of logical partitions is damaged; a partition search may find the rest.".into());
            }
            return;
        }
        let es = mbr_entries(&s);
        let l = &es[0];
        if l.ptype != 0 && l.count > 0 && !is_extended(l.ptype) {
            let mut p = FoundPartition {
                offset: (cur + l.start) * ss,
                size: l.count * ss,
                type_name: mbr_type_name(l.ptype).into(),
                found_by: "mbr".into(),
                number: Some(number),
                ..Default::default()
            };
            number += 1;
            detect(src, &mut p, mbr_expects_fs(l.ptype));
            if cur + l.start + l.count > ext_start + ext_count {
                p.note.push_str(" It reaches past the end of its extended partition.");
            }
            rep.entries.push(p);
        }
        let n = &es[1];
        if is_extended(n.ptype) && n.count > 0 {
            cur = ext_start + n.start;
        } else {
            return;
        }
    }
}

struct GptHdr {
    my_lba: u64,
    alt: u64,
    first_usable: u64,
    last_usable: u64,
    entries_lba: u64,
    n: u32,
    esz: u32,
}

/// A CRC-valid header at `lba` with CRC-valid entries.
fn read_gpt(src: &dyn BlockSource, lba: u64, ss: u64) -> Option<(GptHdr, Vec<u8>)> {
    let off = lba.checked_mul(ss)?;
    if off + 512 > src.len() {
        return None;
    }
    let h = read(src, off, ss as usize);
    if &h[0..8] != b"EFI PART" {
        return None;
    }
    let hsize = rd32(&h, 12) as usize;
    if !(92..=ss as usize).contains(&hsize) {
        return None;
    }
    let mut c = h[..hsize].to_vec();
    c[16..20].fill(0);
    if crc32fast::hash(&c) != rd32(&h, 16) {
        return None;
    }
    if rd64(&h, 24) != lba {
        return None;
    }
    let hdr = GptHdr {
        my_lba: lba,
        alt: rd64(&h, 32),
        first_usable: rd64(&h, 40),
        last_usable: rd64(&h, 48),
        entries_lba: rd64(&h, 72),
        n: rd32(&h, 80),
        esz: rd32(&h, 84),
    };
    if hdr.esz < 128 || hdr.esz % 8 != 0 || hdr.esz > 4096 || hdr.n == 0 || hdr.n as u64 * hdr.esz as u64 > 4 * MIB {
        return None;
    }
    let bytes = hdr.n as usize * hdr.esz as usize;
    let eoff = hdr.entries_lba.checked_mul(ss)?;
    if eoff.checked_add(bytes as u64)? > src.len() {
        return None;
    }
    let entries = read(src, eoff, bytes);
    if crc32fast::hash(&entries) != rd32(&h, 88) {
        return None;
    }
    Some((hdr, entries))
}

/// GPT at sector size `ss`: (primary, backup).
fn find_gpt(src: &dyn BlockSource, ss: u64) -> (Option<(GptHdr, Vec<u8>)>, Option<(GptHdr, Vec<u8>)>) {
    let primary = read_gpt(src, 1, ss);
    let last = src.len() / ss;
    let mut backup = None;
    if let Some((h, _)) = &primary {
        if h.alt > 1 {
            backup = read_gpt(src, h.alt, ss);
        }
    }
    if backup.is_none() && last > 1 {
        backup = read_gpt(src, last - 1, ss);
    }
    (primary, backup)
}

fn parse_gpt_entries(src: &dyn BlockSource, hdr: &GptHdr, entries: &[u8], ss: u64, from_backup: bool, rep: &mut PartitionReport) {
    for i in 0..hdr.n as usize {
        let e = &entries[i * hdr.esz as usize..(i + 1) * hdr.esz as usize];
        if e[..16].iter().all(|&b| b == 0) {
            continue;
        }
        let first = rd64(e, 32);
        let last = rd64(e, 40);
        if last < first {
            rep.notes.push(format!("Partition {} has an invalid size in the GPT and was skipped.", i + 1));
            continue;
        }
        let guid = guid_str(&e[..16]);
        let (tn, expects) = gpt_type_name(&guid);
        let units: Vec<u16> = (0..36).map(|k| rd16(e, 56 + k * 2)).collect();
        let name = crate::fs::fat::util::utf16_until_nul(&units);
        let mut p = FoundPartition {
            offset: first.saturating_mul(ss),
            size: (last - first + 1).saturating_mul(ss),
            type_name: tn.into(),
            found_by: if from_backup { "gptBackup".into() } else { "gpt".into() },
            number: Some(i as u32 + 1),
            ..Default::default()
        };
        detect(src, &mut p, expects);
        if p.label.is_none() && !name.trim().is_empty() {
            p.label = Some(name.trim().to_string());
        }
        rep.entries.push(p);
    }
}

/// Gaps ≥ 16 MiB inside [lo, hi) not covered by any entry (extended containers don't count).
pub(crate) fn gaps(entries: &[FoundPartition], lo: u64, hi: u64) -> Vec<(u64, u64)> {
    let mut cov = crate::model::IntervalSet::new();
    for e in entries {
        if e.type_name == "Extended" {
            continue;
        }
        cov.insert(e.offset, e.offset.saturating_add(e.size));
    }
    let mut out = Vec::new();
    let mut pos = lo;
    for &(s, e) in &cov.ranges {
        if s > pos && s.min(hi) > pos && s.min(hi) - pos >= 16 * MIB {
            out.push((pos, s.min(hi)));
        }
        pos = pos.max(e);
        if pos >= hi {
            break;
        }
    }
    if hi > pos && hi - pos >= 16 * MIB {
        out.push((pos, hi));
    }
    out
}

/// Tables only. Also returns the byte ranges of table structures (for Metadata marks).
pub(crate) fn analyze_inner(src: &dyn BlockSource) -> (PartitionReport, Vec<(u64, u64)>) {
    let len = src.len();
    let ss0 = src.sector_size().max(512) as u64;
    let mut rep = PartitionReport { style: "None".into(), sector_size: ss0 as u32, disk_size: len, ..Default::default() };
    let mut meta = Vec::new();
    if len < 512 {
        rep.notes.push("The drive is too small to hold a partition table.".into());
        return (rep, meta);
    }
    let s0 = read(src, 0, 512);
    let protective = s0[510] == 0x55 && s0[511] == 0xAA && mbr_entries(&s0).iter().any(|e| e.ptype == 0xEE);
    // GPT, at the source's sector size first (images of 4K-sector disks may report 512).
    let other = if ss0 == 512 { 4096 } else { 512 };
    for ss in [ss0, other] {
        let (pri, bak) = find_gpt(src, ss);
        if pri.is_none() && bak.is_none() {
            continue;
        }
        rep.style = "GPT".into();
        rep.sector_size = ss as u32;
        rep.gpt = Some(GptHealth { primary_ok: pri.is_some(), backup_ok: bak.is_some() });
        meta.push((0, ss));
        let mut lo = 34 * ss;
        let mut hi = len;
        if let Some((h, _)) = pri.as_ref().or(bak.as_ref()) {
            lo = h.first_usable.saturating_mul(ss).min(len);
            hi = (h.last_usable.saturating_add(1)).saturating_mul(ss).min(len);
        }
        for (h, e) in [&pri, &bak].into_iter().flatten() {
            meta.push((h.my_lba * ss, h.my_lba * ss + ss));
            meta.push((h.entries_lba * ss, h.entries_lba * ss + e.len() as u64));
        }
        match (&pri, &bak) {
            (Some((h, e)), _) => parse_gpt_entries(src, h, e, ss, false, &mut rep),
            (None, Some((h, e))) => {
                rep.notes.push("The primary GPT is damaged; the backup copy was used.".into());
                parse_gpt_entries(src, h, e, ss, true, &mut rep)
            }
            _ => {}
        }
        if pri.is_some() && bak.is_none() {
            rep.notes.push("The backup GPT is damaged; the primary copy is intact.".into());
        }
        if !protective {
            rep.notes.push("The disk has a GPT but no protective MBR.".into());
        }
        rep.unallocated = gaps(&rep.entries, lo, hi);
        return (rep, meta);
    }
    if protective {
        rep.style = "GPT".into();
        rep.gpt = Some(GptHealth { primary_ok: false, backup_ok: false });
        rep.notes.push("The disk is marked as GPT, but both GPT copies are damaged. Search for lost partitions.".into());
        meta.push((0, ss0));
        rep.unallocated = gaps(&rep.entries, ss0, len);
        return (rep, meta);
    }
    if let Some(fp) = crate::fs::probe_any(src) {
        rep.style = "None".into();
        rep.entries.push(FoundPartition {
            offset: 0,
            size: len,
            fs: Some(fp.fs.clone()),
            label: if fp.label.is_empty() { None } else { Some(fp.label.clone()) },
            type_name: fp.fs.clone(),
            status: if fp.used_backup_boot { "damaged".into() } else { "ok".into() },
            found_by: "bootSector".into(),
            number: None,
            note: if fp.used_backup_boot {
                "Its first boot sector is damaged; the backup copy is intact.".into()
            } else {
                "There is no partition table; the whole drive is one volume.".into()
            },
        });
        return (rep, meta);
    }
    if mbr_valid(&s0) {
        parse_mbr(src, &s0, ss0, &mut rep, &mut meta);
        rep.unallocated = gaps(&rep.entries, ss0, len);
        return (rep, meta);
    }
    rep.notes.push("No partition table was found. Search for lost partitions.".into());
    rep.unallocated = gaps(&rep.entries, 0, len);
    (rep, meta)
}
