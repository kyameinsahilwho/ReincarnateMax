# MAX File Recovery

Find lost files on Windows, see how intact each one is, preview it, and copy it to another drive —
without ever writing to the drive it came from. Tauri v2 + Rust (GNU toolchain, no Visual Studio) +
vanilla HTML/CSS/JS.

## What it does

| Area | What MAX does |
| --- | --- |
| Quick scan | Reads the file system (NTFS MFT, FAT12/16/32 and exFAT directories) for deleted files with their names, folders and dates; rebuilds folders of deleted folders; parks files whose folder is gone under **Lost folders** |
| Folder scan | Pick a folder in Explorer's folder dialog (Start page → **Scan a folder**, or a drive's page → **Scan one folder only**): a quick scan of its drive that lists only deleted files from that folder and its subfolders, including Recycle Bin items deleted from there. Junctions, `subst` and mapped drives are resolved first. If the folder itself was deleted, pick its parent. Files whose folder record is gone and files found only by content need a whole-drive scan |
| Emptied Recycle Bin | Restores original names and folders of `$R…` files from their `$I` records (also when both were deleted), and lists what's still in the bin |
| Deep scan | Reads every sector once (4 MiB chunks, tolerant of bad sectors) and feeds three engines at the same time: signature carving (79 types, 73 carvable incl. camera RAW, Office, video, audio, archives), loose MFT records left after a quick format (cluster size and volume start inferred), and orphaned FAT/exFAT directory clusters |
| Partitions | MBR (incl. logical drives) and GPT (CRC-checked, backup header fallback); searches the whole disk for boot sectors of deleted/lost partitions (also backup boot sectors); scan any found partition directly |
| Fragments | NTFS run lists and FAT/exFAT chains; carving rebuilds 2-piece JPEGs (decode-verified) and gapped ZIP/Office files (CRC-verified) |
| Confidence | Excellent / Good / Partial / Unknown with a one-sentence reason (clusters free or reused, header matches, data zeroed by TRIM, decodes completely…). Never a percentage |
| Workspace | Reconstructed folder tree, list and photo gallery, search (`*.jpg`, wildcards), filters (kind, condition, found-as, size, date), sort, multi-select, select-all-matching, duplicate detection (BLAKE3) |
| Preview | Images (camera RAW via embedded previews), video/audio with seeking (`maxfile://` with HTTP Range), PDF, DOCX/XLSX/PPTX/ODF/RTF/text, hex viewer, header inspection, integrity check; incomplete previews are marked |
| Recovery Map | The whole source as a zoomable grid: green files in use, blue file-system structures, yellow recoverable data, red unreadable, grey not read yet. Click or drag for sector ranges, contents, files there and raw sectors |
| Recovery | Batch or single, original folders recreated, timestamps restored, every file re-read and BLAKE3-verified, repair attempts written as separate “(repaired)” copies, identical copies skipped, HTML + CSV report |
| Safety | Sources opened read-only (`GENERIC_READ`); destination refused when it resolves (junctions, symlinks, loopback shares, mapped drives, VHDs backed by the source) to the source's physical disk; scan results moved to another fixed drive when the data folder shares the scanned drive, with a warning before the scan when that's impossible |
| Power tools | Disk imaging with bad-sector retries, BLAKE3 and a log; disk images as sources (raw, split `.001`, VHD fixed/dynamic, VHDX); Volume Shadow Copies (restore points) as sources; SMART / NVMe health; custom carving rules (hex with `??` wildcards, footer, size limit) |
| Sessions | Every scan is a SQLite `.maxscan` file: pause, resume after closing or a crash (checkpointed sweep position), save to a file, open on another PC, history of scans and recoveries |
| App | Dark/light/system theme, portable mode (`portable` file or `MAXData` folder next to the exe), daily update check against a configurable release feed (notify only), admin prompt at start with opt-out, single instance, NSIS installer |

Not included by the owner's decision: RAID reconstruction.

## Layout

`src/` — `model.rs` (shared types), `device/` (raw volumes/disks/snapshots, images, inventory, SMART, imaging), `fs/{ntfs,fat,exfat}`, `partitions/`, `carve/` + `formats/`, `content/` (assess, metadata, validate, repair, previews, `maxfile://`), `scan/` (jobs, pipeline, sweep, SQLite store, map, queries), `recover/` + `recyclebin/`, shell (`main.rs`, `util.rs`, `paths.rs`, `settings.rs`, `updates.rs`). `ui/` — `app.js`, `start.js`, `session.js`, `tools.js`, `map.js`, `core.js`, `styles.css`, `mock.js` (browser mock backend). Commands, events and ownership: [CONTRACT.md](CONTRACT.md).

## Build

```sh
export PATH="$HOME/.cargo/bin:$PATH"           # Git Bash
cargo build                                     # debug (target dir D:/maxrecovery-target, see .cargo/config.toml)
cargo test                                      # 282 tests, ~10 s after the build
npx -y @tauri-apps/cli@2 build --bundles nsis   # release exe + installer -> D:/maxrecovery-target/release/bundle/nsis
```

The project path has a space, which breaks MinGW `windres`, hence the space-free target dir.
UI without Rust: open `ui/index.html` in Chrome with `--allow-file-access-from-files`; `mock.js`
takes over. Hash hooks for screenshots: `#view=session&idx=1&tab=files&mode=gallery&cat=photo&file=3`,
`#startscan=deep:volume:F&tab=map`, `#view=drive&source=disk:1&admin=0`, `#view=drive&source=volume:E&folder=Users/Ann`, `#theme=dark`.

## Measured (2026-11-24, this laptop: Intel NVMe SSD, debug builds unless noted)

| What | Result |
| --- | --- |
| Drive list at launch (`list_devices`, unelevated, real machine) | 54–80 ms |
| NTFS MFT parse, deleted files only | 1.2 µs per record (≈1.8 s for 1.5 M records, I/O excluded) |
| Carving signature dispatch | 15.1 GB/s per core on random data |
| Session store, 1 M files: insert / index build | 11.2 s / 8.5 s |
| First page / name search / recursive folder filter (1 M files) | 0.7–43 ms / 235 ms / 12 ms |
| Recovery Map, 16,384 cells over 100 k ranges per kind | 25 ms warm, 86 ms cold |
| End to end: deep scan of DFTT #7 (NTFS undelete) + recovery of all 9 answer-key files, MD5-verified | 0.23 s, 9/9 MD5 match |
| Release exe (fat LTO) / installer | 12.8 MB / 4.2 MB |

Not measured yet: launch time and memory of the release build (the launch benchmark opens the window
repeatedly and was skipped while the PC was in use), and real raw-device scan throughput (needs
administrator rights — see below).

## Verification status

Verified: 282 unit/integration tests (FAT images built with `fatfs`, hand-built exFAT, synthetic and
public NTFS images, synthetic disks for carving, partition tables with valid/corrupt CRCs); the DFTT
end-to-end test through the real pipeline, store and recovery engine; a 59-finding adversarial
multi-agent review (two refuting verifiers per finding), three fix rounds, each fix independently
re-verified; the real app on this machine (drive inventory, opening a real scan session, inspector,
Recovery Map, destination check); the NSIS installer silently installed per-user and launched from the
install folder.

**Not exercised** (needs administrator rights or hardware this PC doesn't have; never run unattended):
scanning a real volume or physical disk (raw reads, including a folder scan), Volume Shadow Copies, ATA SMART over WMI, the UAC
accept/decline paths at startup, a real FAT32/exFAT memory card or USB stick, a failing drive, imaging
a real disk, and clicking through a full recovery in the installed app's UI.

## Install

`dist/MAX File Recovery_0.1.0_x64-setup.exe` (unsigned, so SmartScreen will warn on other PCs).
Per-user install to `%LOCALAPPDATA%\MAX File Recovery` (no UAC for the installer). Because MAX asks for
administrator rights at startup, a per-machine install (Program Files) is the safer choice for shared
PCs: set `bundle.windows.nsis.installMode` to `perMachine` and rebuild.
