# MAX File Recovery

**MAX File Recovery is a free Windows data recovery app that finds deleted, lost and formatted files on NTFS, FAT and exFAT drives, memory cards and disk images, shows how intact each file is, previews it, and copies it to another drive without ever writing to the source.**

<p align="center">
  <img alt="Platform: Windows" src="https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white">
  <img alt="Built with Rust" src="https://img.shields.io/badge/Rust-2021-000000?logo=rust&logoColor=white">
  <img alt="Tauri v2" src="https://img.shields.io/badge/Tauri-v2-24C8DB?logo=tauri&logoColor=white">
  <img alt="SQLite sessions" src="https://img.shields.io/badge/sessions-SQLite-003B57?logo=sqlite&logoColor=white">
  <img alt="Version 0.1.0" src="https://img.shields.io/badge/version-0.1.0-5b3fd0">
</p>

<p align="center">
  <img src="icons/128x128@2x.png" alt="MAX File Recovery app icon: a grid of disk sectors with recovered cells highlighted" width="112">
</p>

MAX File Recovery (repo name: ReincarnateMax) is a native Windows desktop app written in Rust with Tauri v2. It undeletes files from the file system, carves files by signature after a format, finds lost partitions, restores emptied Recycle Bin items with their original names, and verifies every recovered file with BLAKE3.

## Why MAX File Recovery

- **Read-only by design.** Every source drive, disk, image and shadow copy is opened with `GENERIC_READ` only, and recovering onto the source's physical disk is refused, not just warned about.
- **79 file types recognised, 73 recoverable by signature carving**, including 13 camera RAW formats (Canon, Nikon, Sony, Fujifilm, Olympus, Panasonic, Pentax, Sigma, DNG), Office files, video, audio and archives.
- **Honest condition ratings.** Each file is rated Excellent, Good, Partial or Unknown with a one-sentence reason (clusters reused, data zeroed by SSD TRIM, decodes completely). Never a made-up percentage.
- **Every recovered file is verified.** MAX re-reads each copy and checks it with BLAKE3, skips identical duplicates, and writes an HTML and CSV report.
- **Built for big scans.** In debug-build benchmarks with I/O excluded, NTFS deleted-record parsing took 1.2 µs per MFT record (about 1.8 s for 1.5 M records), and a name search over a synthetic 1 M-file scan took 235 ms. Scan speed on a real drive has not been measured yet.
- **Scans you can pause and resume.** Each scan is a single SQLite `.maxscan` file that survives closing the app or a crash and can be opened on another PC.

## Features

### Scanning

- **Quick scan**: reads the NTFS MFT and FAT12/16/32 and exFAT directories for deleted files with their names, folders and dates. Rebuilds the folders of deleted folders and puts files whose folder is gone under **Lost folders**.
- **Folder scan**: pick a folder in Explorer's folder dialog and list only the deleted files from that folder and its subfolders, including Recycle Bin items deleted from there. Junctions, `subst` and mapped drives are resolved first. If the folder itself was deleted, pick its parent.
- **Deep scan**: reads every sector once in 4 MiB chunks, tolerates bad sectors, and runs three engines at the same time: signature carving, loose NTFS MFT records left after a quick format (cluster size and volume start inferred), and orphaned FAT/exFAT directory clusters.
- **Emptied Recycle Bin**: restores the original names and folders of `$R` files from their `$I` records, also when both were deleted, and lists what is still in the bin.
- **Lost partitions**: reads MBR (including logical drives) and GPT (CRC-checked, with backup header fallback), searches the whole disk for boot sectors of deleted partitions, and scans any partition it finds.
- **Fragmented files**: follows NTFS run lists and FAT/exFAT chains; carving rebuilds 2-piece JPEGs (decode-verified) and gapped ZIP and Office files (CRC-verified).

### Reviewing results

- **Workspace**: reconstructed folder tree, list view and photo gallery, wildcard search (`*.jpg`), filters by kind, condition, how it was found, size and date, multi-select and select-all-matching.
- **Preview**: images (camera RAW through embedded previews), video and audio with seeking, PDF, DOCX, XLSX, PPTX, ODF, RTF and text, plus a hex viewer, header inspection and an integrity check. Incomplete previews are marked.
- **Recovery Map**: the whole source as a zoomable grid. Green is files in use, blue is file-system structures, yellow is recoverable data, red is unreadable and grey is not read yet. Click or drag to see sector ranges, the files there and raw sectors.
- **Duplicate detection** with BLAKE3 hashes.

### Recovering

- Batch or single-file recovery with original folders recreated and timestamps restored.
- Every file re-read and BLAKE3-verified after copying.
- Repair attempts are written as separate "(repaired)" copies, so the original recovered file is never altered.
- Identical copies are skipped, and each recovery produces an HTML and CSV report.

### Power tools

- **Disk imaging** with bad-sector retries, a BLAKE3 hash and a log.
- **Disk images as sources**: raw (`.img`, `.dd`, `.raw`, `.bin`, `.iso`, split `.001`), VHD (fixed and dynamic) and VHDX.
- **Volume Shadow Copies** (restore points) as sources.
- **Drive health**: SMART, NVMe health log and Windows storage reliability counters.
- **Custom carving rules**: hex headers with `??` wildcards, an optional footer and a size limit.

### App

- Dark, light or system theme.
- Portable mode: put a `portable` file or a `MAXData` folder next to the exe.
- Administrator prompt at start (with an opt-out), single instance, NSIS installer.
- Scan history and recovery history.

## How it works and privacy

1. **Pick a source**: a drive, a physical disk, a disk image, a shadow copy or a single folder.
2. **Scan**: a quick scan reads file-system metadata; a deep scan also reads every sector. Results stream into a SQLite session file.
3. **Review**: sort, filter and preview files, and check each one's condition and reason.
4. **Recover to another drive**: MAX checks the destination first. It refuses any destination that resolves to the source's physical disk, including through junctions, symlinks, loopback shares, mapped drives and VHDs stored on the source.

Privacy and safety facts from the code:

- Sources are never written to, formatted, repaired or mounted. No write `DeviceIoControl` or state-changing `FSCTL` calls are used on a source.
- If the app's data folder is on the drive being scanned, the scan session is moved to another fixed drive so MAX does not overwrite the data you are trying to save. When that is impossible, it warns you before the scan starts.
- MAX has no account and no telemetry. Its only network request is an optional update check, which does nothing until you enter an `https://` release feed in Settings. It never downloads or runs an update; it only opens the release page.
- Fonts and UI assets ship inside the app, so the interface loads nothing from the internet.

## Quick start

There are no published release binaries yet, so build MAX from source on Windows.

### Requirements

- Windows 10 or 11 with the WebView2 runtime (the installer bootstraps it if missing).
- Rust stable with the GNU toolchain (`x86_64-pc-windows-gnu`) and MinGW-w64 (`gcc`, `windres`) on `PATH`. Visual Studio is not needed; bundled SQLite compiles with MinGW `gcc`.
- Node.js, for the Tauri CLI that builds the installer.

### Build and run

```sh
git clone https://github.com/kyameinsahilwho/ReincarnateMax.git
cd ReincarnateMax
cargo build        # debug build
cargo test         # unit and integration tests
cargo run          # start the app
npx -y @tauri-apps/cli@2 build --bundles nsis   # release exe + NSIS installer
```

Notes:

- `.cargo/config.toml` sets `target-dir = "D:/maxrecovery-target"` (outside the project) because MinGW `windres` fails when the target path contains a space. Change it to a space-free path on a drive you have, or delete the setting if your clone path has no spaces.
- MAX asks for administrator rights at startup because Windows only lets administrators read drives directly. Disk images can be scanned without elevation.
- The installer is unsigned, so SmartScreen will warn on other PCs. It installs per user to `%LOCALAPPDATA%\MAX File Recovery` without a UAC prompt. For shared PCs, set `bundle.windows.nsis.installMode` to `perMachine` in `tauri.conf.json` and rebuild.

### UI without Rust

Open `ui/index.html` in Chrome started with `--allow-file-access-from-files`. The browser mock backend in `ui/mock.js` takes over. Hash hooks open specific screens, for example:

- `#view=session&idx=1&tab=files&mode=gallery&cat=photo&file=3`
- `#startscan=deep:volume:F&tab=map`
- `#view=drive&source=volume:E&folder=Users/Ann`
- `#theme=dark`

## Measured performance

Measured on one laptop with an Intel NVMe SSD, debug builds unless noted.

| What | Result |
| --- | --- |
| Drive list at launch (unelevated) | 54 to 80 ms |
| NTFS MFT parse, deleted files only | 1.2 µs per record (about 1.8 s for 1.5 M records, I/O excluded) |
| Carving signature dispatch | 15.1 GB/s per core on random data |
| Session store, 1 M files: insert / index build | 11.2 s / 8.5 s |
| First page / name search / recursive folder filter (1 M files) | 0.7 to 43 ms / 235 ms / 12 ms |
| Recovery Map, 16,384 cells over 100 k ranges per kind | 25 ms warm, 86 ms cold |
| Deep scan of DFTT #7 (NTFS undelete) plus recovery of all 9 answer-key files | 0.23 s, 9 of 9 MD5 matches |
| Release exe (fat LTO) / installer | 12.8 MB / 4.2 MB |

Not measured yet: launch time and memory of the release build, and raw-device scan throughput on a real drive.

## Project status

Version 0.1.0. Verified with 280+ unit and integration tests (FAT images built with `fatfs`, hand-built exFAT, synthetic and public NTFS images, synthetic disks for carving, partition tables with valid and corrupt CRCs), the DFTT end-to-end test through the real pipeline, store and recovery engine, and a per-user install of the NSIS installer.

Not exercised yet, because it needs administrator rights or hardware that was not available: scanning a real volume or physical disk (including folder scans), Volume Shadow Copies, ATA SMART over WMI, the UAC accept and decline paths, a real FAT32/exFAT memory card or USB stick, a failing drive, imaging a real disk, and clicking through a full recovery in the installed app's UI. RAID reconstruction is out of scope.

## Tech stack

| Layer | Technology |
| --- | --- |
| Language | Rust (edition 2021), GNU toolchain, no Visual Studio |
| App shell | Tauri v2 with WebView2, `tauri-plugin-dialog` |
| Windows APIs | `windows-sys` 0.59 (raw volume and disk reads, WMI, COM, registry) |
| Scan sessions | SQLite through `rusqlite` (bundled) |
| Hashing and parallelism | BLAKE3, `crc32fast`, `rayon` |
| Previews | `image` (JPEG, PNG, GIF, WebP, BMP, TIFF), `zip`, `flate2` |
| UI | Vanilla HTML, CSS and JavaScript, no framework |
| Installer | NSIS (via the Tauri CLI) |

### Project layout

- `src/fs/{ntfs,fat,exfat}`: file-system engines (quick scan and deep-scan sweep visitors).
- `src/carve/` and `src/formats/`: signature carving and the file-type table.
- `src/partitions/`: MBR/GPT parsing and lost-partition search.
- `src/device/`: raw volumes and disks, shadow copies, disk images, SMART, imaging.
- `src/content/`: condition assessment, metadata, validation, repair, previews and the `maxfile://` protocol.
- `src/scan/`: jobs, pipeline, sweep, SQLite store, Recovery Map and queries.
- `src/recover/` and `src/recyclebin/`: recovery engine, destination checks, reports, Recycle Bin parsing.
- `ui/`: the front end, plus `mock.js` for running the UI in a browser.

Commands, events and module ownership are documented in [CONTRACT.md](CONTRACT.md).

## FAQ

### Is MAX File Recovery free?

It is free to download and use: no account, no payment and no paid tier. The source is on GitHub so you can read it and build it yourself, but no license has been chosen yet, so it is not open source and reuse or redistribution is not granted.

### Does MAX File Recovery upload my files?

No. Scanning, previewing and recovery all happen locally on your PC. The only network request is an optional update check, and it stays off until you enter a release feed address in Settings.

### Can MAX File Recovery recover files after formatting a drive?

Yes, with a deep scan. It finds loose NTFS MFT records left after a quick format, orphaned FAT and exFAT directory clusters, and files by signature for 73 file types, and it also searches for deleted partitions.

### Can I recover deleted files from an SSD?

Sometimes. If the SSD has already erased the data with TRIM, the file reads as zeros, and MAX marks it Partial with the note that the drive has probably erased it, instead of pretending it is intact.

### How do I recover files from an emptied Recycle Bin on Windows?

Run a quick scan of the drive the files were deleted from. MAX reads the Recycle Bin's `$I` records to restore each `$R` file's original name and folder, even when both records were deleted.

### Does MAX File Recovery need administrator rights?

To scan a real drive, yes, because Windows only lets administrators read drives directly, so MAX asks for elevation at startup. You can turn the prompt off and still open disk images without it.

## Part of CodingMarvel

MAX File Recovery is part of [CodingMarvel](https://codingmarvel.com), a collection of small, focused apps and tools.

More from CodingMarvel:

- [Platter](https://github.com/kyameinsahilwho/platter): Windows disk utility built in Rust
- [Love for PDF](https://pdf.codingmarvel.com): 35+ PDF tools that run in your browser
- [Video Grid Maker](https://video-grid-maker.codingmarvel.com): video contact sheets
- [Ehmatrix](https://ehmatrix.codingmarvel.com): Eisenhower matrix to-do list
- [Pollytasks](https://pollytasks.codingmarvel.com): gamified tasks and habits
- [HabitGrid](https://habitgrid.codingmarvel.com): printable habit tracker PDFs
- [Chrome extensions](https://github.com/kyameinsahilwho/cool-chrome-extensions)
