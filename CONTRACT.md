# MAX File Recovery — contract

Tauri v2 + vanilla JS, Rust on the **GNU toolchain** (no MSVC). Every agent shell:
`export PATH="$HOME/.cargo/bin:$PATH"` (bash; never `$USERPROFILE`). Target dir is
`D:/maxrecovery-target` (set in `.cargo/config.toml`; the project path has a space, which breaks windres).
Build: `cargo build`; tests: `cargo test <filter>`. **Debug builds only** for agents. Never run
`cargo fmt` on the crate — only `rustfmt --edition 2021 src/<your files>`.

## Non-negotiable safety rules

1. Sources are opened **read-only** (`GENERIC_READ`, share read|write). No code path writes to a
   source volume, disk, image or snapshot. No `FSCTL_*` that changes anything. No `DeviceIoControl`
   that writes.
2. Never recover onto the source's physical disk (refuse, don't warn).
3. Never format, repair, mount or modify a source automatically.
4. Physical disks (`\\.\PhysicalDriveN`) and volumes (`\\.\C:`) are separate source kinds.
5. Warn about SSD TRIM and BitLocker; report incomplete recovery honestly (condition + note).
6. During development: **never** run anything that writes to a real drive other than files under
   `%TEMP%` or the project folder. Don't change system settings. Don't try to elevate (no UAC).
   Raw device opens fail unelevated — that's expected; test with images / in-memory sources.

## Conventions

- JSON camelCase (`#[serde(rename_all = "camelCase")]`). JS passes camelCase arg keys.
- Sizes `u64` bytes; times **Unix ms** (`i64`). Offsets are bytes on the scan source.
- `Err(String)` = **one plain sentence that says what to do**. Admin failures contain the word
  "administrator" ("Windows only lets administrators read drives directly. Restart MAX as administrator.").
- Blocking work: `async fn` + `tauri::async_runtime::spawn_blocking`. Long jobs return an id at once
  and stream events (`use tauri::Emitter; app.emit(...)`). Every event carries its job/session id.
  Throttle progress to ~4/s.
- Child processes: absolute System32 paths, `CREATE_NO_WINDOW`, `stdin(null)`.
- Module state in statics (`OnceLock<Mutex<..>>`, `AtomicBool`); recover poisoned locks with
  `.lock().unwrap_or_else(|e| e.into_inner())`.
- windows-sys **0.59**; enabled features are in Cargo.toml. Need another crate or feature? Don't edit
  Cargo.toml — say so in your final summary (or ask the orchestrator); declare missing Win32 functions
  with `#[link(name = "kernel32")] extern "system" { … }`.
- Contract changes are additive only (new `Option<T>` fields/args). Report them in your summary.

## Shared core (orchestrator-owned; read, don't edit)

- `src/model.rs` — `SourceRef`, `FoundFile`, `Extent` (+`SPARSE`), `FileStatus`, `Origin`,
  `Condition` (Excellent/Good/Partial/Unknown — never a percentage), `Category`, `flags::*`,
  `MapKind`, `IntervalSet`, `FsProbe`, `EngineSummary`, `ScanOptions`, `CustomSignature`,
  `ChunkVisitor`, `ScanCtx` (`check()`, `found()`, `mark()`, `info/warn`, `set_stage`, `progress`,
  `allocated`, `known_starts`, `probe`, `custom_signatures`, `for_test()`), helpers
  (`filetime_to_ms`, `human_size`, `safe_file_name`, `now_ms`).
- `src/device/source.rs` — `BlockSource` trait (`len`, `sector_size`, `read_at` byte-addressed, any
  alignment — implementations align internally; `describe`), `Source = Arc<dyn BlockSource>`,
  `read_full`, `read_tolerant` (bad sectors → zeros + `MapKind::Bad`), `SubSource`, `MemSource`
  (tests; `.bad` ranges simulate unreadable sectors), `open_source(&SourceRef)`, `window()`,
  command `read_sectors`.
- `src/fileread.rs` — `read_at(src, &FoundFile, pos, buf) -> (n, hit_bad)`, `read_prefix`,
  `FileReader` (Read+Seek). Handles extents, SPARSE, resident, live_path, COMPRESSED (→ ntfs).
- `src/paths.rs` (portable mode), `src/settings.rs` (`settings::custom_signatures()`), `main.rs`.

## Engine interface

File-system engines (`fs::ntfs`, `fs::fat`, `fs::exfat`):
```rust
pub fn probe(src: &dyn BlockSource) -> Option<FsProbe>;            // primary boot sector, then backup
pub fn quick_scan(src: &dyn BlockSource, ctx: &ScanCtx) -> Result<EngineSummary, String>;
pub fn sweep_visitor(probe: Option<&FsProbe>) -> Box<dyn ChunkVisitor>;   // deep scans
```
- `quick_scan` reports every deleted file (and existing ones when `ctx.include_existing()`), with
  reconstructed `folder` (`\Users\Ann\Pictures`), `status` Deleted / Lost (parent gone →
  `\Lost folders\Folder <id>\…`), timestamps, extents (bytes on the source), `fragmented`,
  `condition` + `note` from allocation evidence (all clusters free → Excellent/Good; some now used
  by live files → Partial + `flags::OVERWRITTEN`), `fs_ref`. It marks on the map: `Metadata` (boot
  sectors, MFT/FAT/dir clusters, bitmaps), `Allocated` (live data, from the bitmap/FAT) and `Scanned`
  for the metadata it read. Call `ctx.check()?` every few hundred records; `ctx.set_stage`/`progress`
  for progress (the orchestrator names the stage; engines may refine with `set_stage`).
- `sweep_visitor` finds structures outside the live metadata (formatted / damaged / RAW volumes):
  NTFS `FILE` records, FAT/exFAT directory clusters; `finish()` rebuilds their folders and reports
  them with `flags::LOOSE_RECORD`, skipping anything already reported (`ctx.known_starts`).
- Carving: `carve::visitor(ctx)` (deep scans); hits whose start is in `ctx.known_starts` are skipped,
  and with `carve_free_only` (default true when a file system was recognised) headers inside
  `ctx.allocated` are skipped. Carved files: status Carved, origin Carving, folder
  `\Found by signature\<type label>`, name from `content::suggest_name` or `<type>_<offset hex>.<ext>`
  with `flags::NAME_GUESSED`.
- Partitions: `partitions::analyze(src)` (tables), `partitions::search_lost(src, ctx)` (sweep for boot
  sectors on 1 MiB / 63-sector / 2048-sector boundaries + NTFS backup boot sectors).
- Content: `content::assess(src, &mut f)` (one ≤4 KiB read), `extract_meta`, `suggest_name`,
  `validate`, `repair`, the `maxfile://` protocol.
- Recycle Bin: `recyclebin::parse_info_file`, `recyclebin::scan_volume`.
- Store (`scan::store`): `session_source_ref`, `open_session_source`, `get_file`, `query_ids`,
  `update_condition`, `update_meta`, `set_hash`, `set_dup_groups`, `sizes_and_hashes`, `log`.

## Scan pipeline (scan agent)

Mode **quick**: `filesystem` (probe_any → that engine's quick_scan; none recognised → note "No file
system was recognised. Run a deep scan.") → `recyclebin` (volume sources only) → `condition`
(`content::assess` for every non-existing file, progress per file).
Mode **deep**: quick stages → `sweep` (read every sector of the source in 4 MiB chunks, parallel,
tolerant reads, mark Scanned/Bad, feed: carve visitor + the recognised FS's sweep visitor, or all
three FS sweep visitors when none was recognised; checkpoint the sweep position every few seconds so
a resumed session continues from there) → `rebuild` (visitors' `finish`) → `condition`.
Mode **partitions**: `partitions` (search_lost over the whole disk/image) → result stored in the
session (`SessionDetail.partitions`). The UI can then start a quick/deep scan of a found partition:
`SourceRef { kind: same, path: same, offset, length }`.
`include_existing` default: true for Image/Snapshot sources, windows (offset > 0), RAW volumes and
when the boot sector backup was used; false otherwise.

## Commands

| Command | Args | Returns |
| --- | --- | --- |
| `system_info` | — | `{elevated, askAdminAtStart?, computerName, systemDrive, userProfile, downloads, version, portable, dataDir, portableWarning?, dataNote?}` — `askAdminAtStart` is absent when elevated as another account; `portableWarning`: portable mode on read-only media, data kept in `%TEMP%\com.maxrecovery.app-portable`; `dataNote`: elevated as another account (that account's own profile is used, never the desktop user's): "MAX is running as a different Windows account, so this scan list and these settings belong to that account." |
| `app_ready`, `perf_mark(name)`, `perf_enabled` | | |
| `set_theme_pref` | `theme: "light"\|"dark"\|"system"` | — |
| `cache_get_many` | `keys: string[]` | `{key: {savedAt, version, data}}` |
| `relaunch_elevated` | — | `bool` (false = declined) |
| `set_ask_admin` | `enabled` | — |
| `reveal_path` | `path` (an existing path on a drive or network share) | — (Explorer) |
| `open_url` | `url` (`https://` only) | — (default browser) |
| `exit_app` | — | — (stops scans (resumable), recoveries and imaging, waits up to 10 s, exits; the answer to `confirm-exit`) |
| `get_settings` / `save_settings` | `settings` | `Settings` (settings.rs), with `loadWarning?`: output only, never read from input or saved — set when settings.json was damaged (moved aside to `settings.json.bad-<ms>`) or couldn't be read |
| `check_for_updates` | — | `UpdateInfo` |
| `list_file_types` | — | `[{id, label, category, exts, carvable}]` |
| `list_devices` | — | `DeviceList` (device/list.rs) |
| `smart_info` | `disk: u32` | `SmartInfo` |
| `open_image` | `path` | `ImageInfo` (+ `sectorSize?`: logical sector size of the virtual disk, `note?`: one sentence worth showing, e.g. "This image is split into 3 files.") |
| `read_sectors` | `source: SourceRef, offset, length` (≤64 KiB) | `RawBytes {offset, data(base64), sourceLen, sectorSize, bad}` |
| `start_imaging` | `source, dest, options?: {retries?, hash?}` | `{job, path}` |
| `pause_imaging` / `cancel_imaging` | `job[, paused]` | — |
| `analyze_partitions` | `source` | `PartitionReport` |
| `start_scan` | `source, options: ScanOptions` | `{sessionId, job}` — `options.folder` ("\Users\Ann", below the volume root) makes it a folder scan: quick mode on a volume only; `ScanCtx::found` keeps files whose folder is that one or below it (case-insensitive); the root means no scope |
| `folder_source` | `path: string` (a folder the user picked) | `FolderSource {source: SourceRef (volume), folder, display}` — after junctions/subst/mapped drives; refused off a lettered local volume or for a volume mounted into another drive's folder. Read-only |
| `scan_location` | `source: SourceRef` | `LocationPreview {sameDrive, movedTo?, message?, refuse?}` — read-only preview, before a scan starts, of where its results would be kept (see Session location); `refuse` = why `start_scan` would refuse right now |
| `pause_scan` | `sessionId, paused` | — |
| `cancel_scan` | `sessionId` | — |
| `resume_session` | `sessionId` | `{sessionId, job}` |
| `list_sessions` | — | `SessionSummary[]` (newest first) |
| `get_session` | `sessionId` | `SessionDetail` |
| `delete_session` / `export_session(path)` / `import_session(path)` | | |
| `query_files` | `sessionId, query: FileQuery` | `FilePage {total, totalSize, items: FileRow[]}` |
| `query_ids` | `sessionId, query` | `i64[]` (at most 1,000,000; more → `Err(TOO_MANY_IDS)`: "There are more than 1,000,000 files here, too many to select one by one. Use Recover all instead, or narrow the list with a filter.") |
| `folder_children` | `sessionId, parent, query?` | `FolderNode[]` |
| `file_detail` | `sessionId, id` | `FileDetail` |
| `map_cells` | `sessionId, start?, end?, cells` | `MapData` (cells base64, bit per MapKind index) |
| `map_region` | `sessionId, start, end` | `RegionInfo` |
| `session_log` | `sessionId, offset?, limit?` | `LogLine[]` |
| `inspect_file` | `sessionId, id` | `Inspection` (+ `thumbOnly`: the WebView can't show the original (TIFF, camera RAW), show `maxfile://…?thumb=512` instead) |
| `preview_document` | `sessionId, id` | `DocPreview` (+ `note?`: a caveat to show with the preview, or why there is nothing to show) |
| `read_file_bytes` | `sessionId, id, offset, length` | `FileBytes` |
| `check_destination` | `sessionId, dest, ids?, query?` | `DestCheck` (Image sources: only the image file itself is refused as a destination, matched by its path and its real path after links; its drive is allowed) |
| `start_recovery` | `sessionId, dest, ids?, query?, options?` | `job` |
| `cancel_recovery` | `job` | — |
| `recovery_history` | — | `RecoveryRecord[]` |
| `find_duplicates` | `sessionId` | `job` |
| `export_report` | `sessionId, path, format: "html"\|"csv", query?` | written path |

## Events

| Event | Payload |
| --- | --- |
| `devices-changed` | drive-letter bitmask |
| `scan-progress` | `{sessionId, job, state: "running"\|"paused", stage, stageLabel, stageIndex, stageCount, done, total, filesFound, bytesPerSec, etaSeconds?, badBytes, sweepPos?, stopping?}` — `stopping: true` once Stop was pressed, while the scan finishes saving |
| `scan-done` | `{sessionId, job, state: "done"\|"cancelled"\|"failed", error?, files}` |
| `imaging-progress` | `{job, state, bytesDone, bytesTotal, badBytes, bytesPerSec, etaSeconds?}` |
| `imaging-done` | `{job, state: "done"\|"cancelled"\|"failed", error?, path, bytesWritten, badRanges, blake3?, logPath, note?}` — `note`: one sentence to show (unreadable bytes, a partial image) |
| `recovery-progress` | `{job, sessionId, filesDone, filesTotal, bytesDone, bytesTotal, current, bytesPerSec, etaSeconds?}` |
| `recovery-done` | `{job, sessionId, state, recovered, partial, failed, repaired, skippedDuplicates, bytes, dest, reportPath?, errors: string[] (first 20)}` |
| `dupes-progress` | `{job, sessionId, done, total}` |
| `dupes-done` | `{job, sessionId, state, groups, files, wastedBytes}` |
| `confirm-exit` | `{scans, recoveries, imaging}` (counts) — closing was held back because jobs run; the UI asks and calls `exit_app` to quit anyway (the installer's close message stops them and exits without asking) |

The UI must buffer a `*-done` event that arrives before the start command returned its id.

## Data folder and session location

| Case | Where |
| --- | --- |
| Normal | `%LOCALAPPDATA%\com.maxrecovery.app` (`sessions\`, `logs\`, `cache\`, `settings.json`, `external-sessions.json`) |
| Portable (`portable` file or `MAXData` folder next to the exe, or `--portable`) | `<exe folder>\MAXData`; on read-only media `%TEMP%\com.maxrecovery.app-portable` + `system_info.portableWarning` |
| Elevated as another account | that (elevated) account's own `%LOCALAPPDATA%\com.maxrecovery.app`, never the desktop user's; `system_info.dataNote` says so and `askAdminAtStart` is absent |
| A new scan whose source is on the data folder's drive (a snapshot counts as its original volume) | its session file goes to `<X>:\MAX Recovery\sessions` on another fixed local drive with ≥ 1 GiB free (the most free space) that no running scan reads; it is listed in the registry `<data folder>\external-sessions.json` so `list_sessions` etc. find it. No such drive → the sessions folder, with a warning (`scan_location.message`) |
| Optional writes (app log, cache) while a scan reads the data folder's drive | held in memory from the scan's first progress event and written once no such scan runs, or on exit |

## `maxfile://` protocol (content agent)

`maxfile://localhost/<sessionId>/<fileId>` → the file's bytes with its MIME type, `Range` support
(206), `Cache-Control: no-store`. `?thumb=256` → a JPEG thumbnail (images, embedded previews of
camera RAW files, `image` crate); 404 when none. In the WebView the URL is
`http://maxfile.localhost/<sessionId>/<fileId>` (Tauri maps custom schemes that way on Windows).

## Module ownership

| Owner | Files |
| --- | --- |
| orchestrator | Cargo.toml, tauri.conf.json, main.rs, util.rs, perf.rs, cache.rs, other_account.rs, paths.rs, settings.rs, updates.rs, model.rs, fileread.rs, device/mod.rs, device/source.rs, fs/mod.rs, CONTRACT.md, ui/* (except mock.js) |
| device agent | device/win.rs, device/image.rs, device/list.rs, device/smart.rs, device/imaging.rs (+ new files under device/) |
| ntfs agent | fs/ntfs/** |
| fat agent | fs/fat/**, fs/exfat/**, partitions/** |
| carve agent | carve/**, formats/** |
| content agent | content/** |
| scan agent | scan/** |
| recover agent | recover/**, recyclebin/** |
| mock agent | ui/mock.js |

## Status

All modules implemented (2026-11-24): 280 tests pass; adversarial review (59 findings) fixed and re-verified in three rounds. RAID is out of scope by the owner's decision. See README.md "Verification status" for what was not exercised.
