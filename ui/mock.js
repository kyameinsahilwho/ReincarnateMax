// MAX File Recovery — in-browser fake of the Tauri backend (see CONTRACT.md).
// Lets the vanilla-JS UI run in a plain browser for design work and screenshots.
//
//   import { installMock } from "./mock.js";
//   installMock();   // sets window.__TAURI__ and window.__MAX_MOCK__
//
// window.__MAX_MOCK__ = { state, emit(event, payload), fileUrl(sessionId, id, thumbPx) }
//
// Toggles on `state` (all read at call time, so flip them any time):
//   elevated        (true)  false -> snapshotsNeedAdmin, and start_scan / scan_location on volumes/disks, read_sectors,
//                           smart_info, start_imaging reject with the "administrator" sentence
//   noSessions      (false) list_sessions returns []
//   noDevices       (false) list_devices returns no disks / volumes / snapshots
//   slowScan        (false) live scans take 4x longer
//   failScan        (false) the next scans fail at ~30% with an error sentence
//   ssdTrim         (true)  TRIM enabled on the C: SSD (device list + the TRIM note in C: sessions)
//   bitlockerLocked (false) E: reports BitLocker "locked" and scanning it is refused
//   speed           (1)     divides every simulated duration (self-check uses 25)
//   askAdmin / themePref    remembered by set_ask_admin / set_theme_pref
//   exited          (false) set by exit_app (and by closeWindow() when nothing runs)
//   portableWarning (null)  sentence system_info returns as portableWarning (portable data kept elsewhere)
//   dataNote        (null)  sentence system_info returns as dataNote
//   settingsWarning (null)  sentence get_settings returns as loadWarning until settings are saved
//   scanRefuse      (null)  sentence scan_location returns as refuse (Start is disabled)
//   maxIds          (1e6)   query_ids refuses with the TOO_MANY_IDS sentence when more files match
//   stopMs          (300)   how long a stopped scan reports "stopping" before scan-done (divided by speed)
//
// window.__MAX_MOCK__.closeWindow() acts like the window's close button: with jobs running it emits
// confirm-exit {scans, recoveries, imaging}; the page answers with exit_app.
//
// Notes on shapes the Rust docs leave open: ranges such as badRanges / unallocated are [start, end]
// pairs; the interrupted session reports stage state "interrupted" on the sweep stage.
// Errors are rejected as plain strings, exactly like Tauri's Err(String).

export const state = {
  elevated: true,
  noSessions: false,
  noDevices: false,
  slowScan: false,
  failScan: false,
  ssdTrim: true,
  bitlockerLocked: false,
  speed: 1,
  askAdmin: true,
  themePref: "system",
  portableWarning: null,
  dataNote: null,
  settingsWarning: null,
  scanRefuse: null,
  maxIds: 1000000,
  stopMs: 300,
};

/* ───────────────────────────── helpers ───────────────────────────── */

const KiB = 1024;
const MiB = 1048576;
const GiB = 1073741824;
const DAY = 86400000;
const NOW = Date.UTC(2026, 10, 24, 9, 30, 0);
const UNIT = 65536; // granularity of the synthetic disk layout
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const clamp = (x, a, b) => Math.min(b, Math.max(a, x));
const iso = (ms) => new Date(ms).toISOString();
const fmtDT = (ms) => iso(ms).slice(0, 19).replace("T", " ");
const hex = (n, w = 8) => Math.floor(n).toString(16).toUpperCase().padStart(w, "0");

function fnv(s) {
  let h = 2166136261;
  s = String(s);
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}
function mulberry32(a) {
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function rng(seed) {
  const f = mulberry32(typeof seed === "number" ? seed >>> 0 : fnv(seed));
  const r = {
    f,
    int: (a, b) => a + Math.floor(f() * (b - a + 1)),
    pick: (arr) => arr[Math.floor(f() * arr.length)],
    chance: (p) => f() < p,
    norm: () => Math.sqrt(-2 * Math.log(1 - f())) * Math.cos(2 * Math.PI * f()),
    logn: (med, sig) => med * Math.exp(sig * r.norm()),
    expo: (mean) => -Math.log(1 - f()) * mean,
    weighted(list) {
      let tot = 0;
      for (const [, w] of list) tot += w;
      let x = f() * tot;
      for (const [v, w] of list) {
        x -= w;
        if (x < 0) return v;
      }
      return list[list.length - 1][0];
    },
  };
  return r;
}
function b64(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}
function randHex(r, n) {
  let s = "";
  for (let i = 0; i < n; i++) s += "0123456789abcdef"[Math.floor(r.f() * 16)];
  return s;
}
const clone = (x) => (x === undefined ? undefined : JSON.parse(JSON.stringify(x)));

const ADMIN = "Windows only lets administrators read drives directly. Restart MAX as administrator.";
const needAdmin = () => {
  if (!state.elevated) throw ADMIN;
};
const LOCKED_MSG = "This drive is locked by BitLocker. Unlock it in Windows, then scan it again.";
const SRC_DISK_MSG = "This folder is on the drive you are recovering from. Pick a folder on another drive.";

/* ─────────────────────────── interval sets ─────────────────────────── */

class Iv {
  constructor(pairs) {
    const p = (pairs || []).filter((x) => x[1] > x[0]).sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    this.s = [];
    this.e = [];
    for (const [a, b] of p) {
      const n = this.s.length;
      if (n && a <= this.e[n - 1]) this.e[n - 1] = Math.max(this.e[n - 1], b);
      else {
        this.s.push(a);
        this.e.push(b);
      }
    }
  }
  get length() {
    return this.s.length;
  }
  first(a) {
    // first index with e > a
    let lo = 0,
      hi = this.e.length;
    while (lo < hi) {
      const m = (lo + hi) >> 1;
      if (this.e[m] > a) hi = m;
      else lo = m + 1;
    }
    return lo;
  }
  hits(a, b) {
    if (b <= a) return false;
    const i = this.first(a);
    return i < this.s.length && this.s[i] < b;
  }
  bytes(a, b) {
    if (b <= a) return 0;
    let n = 0;
    for (let i = this.first(a); i < this.s.length && this.s[i] < b; i++) n += Math.min(this.e[i], b) - Math.max(this.s[i], a);
    return n;
  }
  clip(a, b) {
    const out = [];
    if (b <= a) return out;
    for (let i = this.first(a); i < this.s.length && this.s[i] < b; i++) out.push([Math.max(this.s[i], a), Math.min(this.e[i], b)]);
    return out;
  }
  pairs() {
    return this.s.map((s, i) => [s, this.e[i]]);
  }
  total() {
    let n = 0;
    for (let i = 0; i < this.s.length; i++) n += this.e[i] - this.s[i];
    return n;
  }
  gaps(a, b) {
    const out = [];
    let pos = a;
    for (let i = this.first(a); i < this.s.length && this.s[i] < b; i++) {
      if (this.s[i] > pos) out.push([pos, this.s[i]]);
      pos = Math.max(pos, this.e[i]);
    }
    if (pos < b) out.push([pos, b]);
    return out;
  }
}
/** A layer that only knows about bytes below `lim`. */
function limited(iv, lim) {
  return {
    hits: (a, b) => a < lim && iv.hits(a, Math.min(b, lim)),
    bytes: (a, b) => (a < lim ? iv.bytes(a, Math.min(b, lim)) : 0),
    clip: (a, b) => (a < lim ? iv.clip(a, Math.min(b, lim)) : []),
  };
}

/* ───────────────────────────── events ───────────────────────────── */

const listeners = new Map(); // event -> Set<cb>
let eventSeq = 0;
function emit(event, payload) {
  const set = listeners.get(event);
  if (!set) return;
  const id = ++eventSeq;
  for (const cb of [...set]) {
    try {
      cb({ event, id, payload: clone(payload) });
    } catch (e) {
      console.error("[mock] listener for", event, "threw", e);
    }
  }
}
function listen(event, cb) {
  if (!listeners.has(event)) listeners.set(event, new Set());
  listeners.get(event).add(cb);
  return Promise.resolve(() => listeners.get(event)?.delete(cb));
}

/* ───────────────────────────── file types ───────────────────────────── */

// id, label, category, extensions, carvable, mime
const TYPE_ROWS = [
  ["jpg", "JPEG image", "photo", ["jpg", "jpeg", "jpe", "jfif"], true, "image/jpeg"],
  ["png", "PNG image", "photo", ["png"], true, "image/png"],
  ["gif", "GIF image", "photo", ["gif"], true, "image/gif"],
  ["bmp", "Bitmap image", "photo", ["bmp"], true, "image/bmp"],
  ["tiff", "TIFF image", "photo", ["tif", "tiff"], true, "image/tiff"],
  ["webp", "WebP image", "photo", ["webp"], true, "image/webp"],
  ["heic", "HEIC image", "photo", ["heic", "heif"], true, "image/heic"],
  ["cr2", "Canon CR2 raw photo", "photo", ["cr2"], true, "image/x-canon-cr2"],
  ["cr3", "Canon CR3 raw photo", "photo", ["cr3"], true, "image/x-canon-cr3"],
  ["nef", "Nikon raw photo", "photo", ["nef"], true, "image/x-nikon-nef"],
  ["arw", "Sony raw photo", "photo", ["arw"], true, "image/x-sony-arw"],
  ["dng", "Adobe DNG raw photo", "photo", ["dng"], true, "image/x-adobe-dng"],
  ["psd", "Photoshop document", "photo", ["psd"], true, "image/vnd.adobe.photoshop"],
  ["svg", "SVG image", "photo", ["svg"], false, "image/svg+xml"],
  ["mp4", "MP4 video", "video", ["mp4", "m4v"], true, "video/mp4"],
  ["mov", "QuickTime video", "video", ["mov"], true, "video/quicktime"],
  ["avi", "AVI video", "video", ["avi"], true, "video/x-msvideo"],
  ["mkv", "Matroska video", "video", ["mkv"], true, "video/x-matroska"],
  ["wmv", "Windows Media video", "video", ["wmv"], true, "video/x-ms-wmv"],
  ["mts", "AVCHD video", "video", ["mts", "m2ts"], true, "video/mp2t"],
  ["3gp", "3GP video", "video", ["3gp"], true, "video/3gpp"],
  ["flv", "Flash video", "video", ["flv"], true, "video/x-flv"],
  ["webm", "WebM video", "video", ["webm"], true, "video/webm"],
  ["mp3", "MP3 audio", "audio", ["mp3"], true, "audio/mpeg"],
  ["wav", "WAV audio", "audio", ["wav"], true, "audio/wav"],
  ["flac", "FLAC audio", "audio", ["flac"], true, "audio/flac"],
  ["m4a", "M4A audio", "audio", ["m4a"], true, "audio/mp4"],
  ["ogg", "Ogg audio", "audio", ["ogg"], true, "audio/ogg"],
  ["wma", "Windows Media audio", "audio", ["wma"], true, "audio/x-ms-wma"],
  ["mid", "MIDI music", "audio", ["mid", "midi"], true, "audio/midi"],
  ["pdf", "PDF document", "document", ["pdf"], true, "application/pdf"],
  ["docx", "Word document", "document", ["docx"], true, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
  ["xlsx", "Excel workbook", "document", ["xlsx"], true, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
  ["pptx", "PowerPoint presentation", "document", ["pptx"], true, "application/vnd.openxmlformats-officedocument.presentationml.presentation"],
  ["doc", "Word 97-2003 document", "document", ["doc"], true, "application/msword"],
  ["xls", "Excel 97-2003 workbook", "document", ["xls"], true, "application/vnd.ms-excel"],
  ["ppt", "PowerPoint 97-2003 presentation", "document", ["ppt"], true, "application/vnd.ms-powerpoint"],
  ["odt", "OpenDocument text", "document", ["odt"], true, "application/vnd.oasis.opendocument.text"],
  ["ods", "OpenDocument spreadsheet", "document", ["ods"], true, "application/vnd.oasis.opendocument.spreadsheet"],
  ["rtf", "Rich text document", "document", ["rtf"], true, "application/rtf"],
  ["txt", "Text file", "document", ["txt", "log"], false, "text/plain"],
  ["csv", "CSV table", "document", ["csv"], false, "text/csv"],
  ["html", "Web page", "document", ["html", "htm"], true, "text/html"],
  ["xml", "XML file", "document", ["xml"], false, "application/xml"],
  ["eml", "Email message", "document", ["eml"], true, "message/rfc822"],
  ["pst", "Outlook data file", "document", ["pst"], true, "application/vnd.ms-outlook"],
  ["zip", "ZIP archive", "archive", ["zip"], true, "application/zip"],
  ["rar", "RAR archive", "archive", ["rar"], true, "application/vnd.rar"],
  ["7z", "7-Zip archive", "archive", ["7z"], true, "application/x-7z-compressed"],
  ["gz", "Gzip archive", "archive", ["gz"], true, "application/gzip"],
  ["tar", "TAR archive", "archive", ["tar"], true, "application/x-tar"],
  ["iso", "Disc image", "archive", ["iso"], true, "application/x-iso9660-image"],
  ["cab", "Cabinet archive", "archive", ["cab"], true, "application/vnd.ms-cab-compressed"],
  ["exe", "Windows program", "other", ["exe"], true, "application/vnd.microsoft.portable-executable"],
  ["dll", "Windows library", "other", ["dll"], true, "application/vnd.microsoft.portable-executable"],
  ["msi", "Windows installer", "other", ["msi"], true, "application/x-msi"],
  ["sqlite", "SQLite database", "other", ["sqlite", "db"], true, "application/vnd.sqlite3"],
  ["lnk", "Windows shortcut", "other", ["lnk"], true, "application/x-ms-shortcut"],
  ["ico", "Icon", "other", ["ico"], true, "image/vnd.microsoft.icon"],
  ["dat", "Unknown data", "other", ["dat", "bin", "tmp"], false, "application/octet-stream"],
];
const TY = {};
const TY_BY_EXT = {};
for (const [id, label, cat, exts, carvable, mime] of TYPE_ROWS) {
  TY[id] = { id, label, cat, exts, carvable, mime };
  for (const e of exts) TY_BY_EXT[e] = TY[id];
}
const extOf = (name) => {
  const i = name.lastIndexOf(".");
  return i > 0 && name.length - i <= 9 ? name.slice(i + 1).toLowerCase() : "";
};
const catOf = (typeId) => TY[typeId]?.cat || "other";

/* ───────────────────────────── devices ───────────────────────────── */

const pt = (number, offset, size, typeName, letter, fs, label) => ({ number, offset, size, typeName, letter, fs, label });
const floorMiB = (n) => Math.floor(n / MiB) * MiB;
const DISK_SIZES = [1000204886016, 2000398934016, 63864569856, 31914983424];
const LOST_OFFSET = Math.ceil(1.81e12 / MiB) * MiB;
const LOST_SIZE = floorMiB(120e9);

const DISK_DEFS = [
  {
    index: 0, model: "Samsung SSD 980 PRO 1TB", serial: "S6B0NL0W412345X", bus: "NVMe", media: "SSD", removable: false,
    partitionStyle: "GPT", health: "Healthy", isSystem: true,
    parts: [
      pt(1, MiB, 100 * MiB, "EFI system", null, "FAT32", "SYSTEM"),
      pt(2, 101 * MiB, 16 * MiB, "Microsoft reserved", null, null, null),
      pt(3, 117 * MiB, 930 * GiB, "Basic data", "C", "NTFS", "Windows"),
      pt(4, 117 * MiB + 930 * GiB, 650 * MiB, "Recovery", null, "NTFS", "Recovery"),
    ],
  },
  {
    index: 1, model: "WD Elements 25A2", serial: "575834314138394E", bus: "USB", media: "HDD", removable: false,
    partitionStyle: "MBR", health: "Warning",
    parts: [pt(1, MiB, floorMiB(1.8e12), "Basic data", "E", "NTFS", "Backup")],
  },
  {
    index: 2, model: "Generic SD/MMC", serial: "000000000820", bus: "SD", media: "Unknown", removable: true,
    partitionStyle: "MBR", health: null,
    parts: [pt(1, 4 * MiB, floorMiB(DISK_SIZES[2] - 4 * MiB), "Basic data", "F", "exFAT", "CANON_EOS")],
  },
  {
    index: 3, model: "SanDisk Ultra", serial: "4C530001170415103015", bus: "USB", media: "Unknown", removable: true,
    partitionStyle: "MBR", health: "Healthy",
    parts: [pt(1, MiB, floorMiB(DISK_SIZES[3] - MiB), "Basic data", "G", "RAW", null)],
  },
];
DISK_DEFS.forEach((d, i) => (d.size = DISK_SIZES[i]));

const VOL_DEFS = {
  C: { letter: "C", label: "Windows", fs: "NTFS", size: 930 * GiB, free: 372 * GiB, driveType: "fixed", diskIndex: 0, offset: 117 * MiB, isSystem: true, ssd: true, state: "ready", bps: 2.8e9 },
  E: { letter: "E", label: "Backup", fs: "NTFS", size: floorMiB(1.8e12), free: 612e9, driveType: "fixed", diskIndex: 1, offset: MiB, isSystem: false, ssd: false, state: "ready", bps: 1.45e8 },
  F: { letter: "F", label: "CANON_EOS", fs: "exFAT", size: floorMiB(DISK_SIZES[2] - 4 * MiB), free: 58.4e9, driveType: "removable", diskIndex: 2, offset: 4 * MiB, isSystem: false, ssd: false, state: "ready", bps: 9e7 },
  G: { letter: "G", label: "", fs: "RAW", size: floorMiB(DISK_SIZES[3] - MiB), free: 0, driveType: "removable", diskIndex: 3, offset: MiB, isSystem: false, ssd: false, state: "raw", bps: 3.5e7 },
};
const DISK_BPS = [2.8e9, 1.45e8, 9e7, 3.5e7];

function buildDevices() {
  if (state.noDevices) return { disks: [], volumes: [], snapshots: [], snapshotsNeedAdmin: !state.elevated, elevated: state.elevated };
  const disks = DISK_DEFS.map((d) => ({
    index: d.index, model: d.model, serial: d.serial, size: d.size, sectorSize: 512, bus: d.bus, media: d.media,
    removable: d.removable, trimEnabled: d.media === "SSD" ? state.ssdTrim : null, partitionStyle: d.partitionStyle,
    partitions: d.parts.map((p) => ({ number: p.number, offset: p.offset, size: p.size, typeName: p.typeName, letter: p.letter, fs: p.fs, label: p.label })),
    health: d.health, isSystem: !!d.isSystem,
  }));
  const volumes = Object.values(VOL_DEFS).map((v) => {
    const locked = v.letter === "E" && state.bitlockerLocked;
    return {
      letter: v.letter, label: locked ? "" : v.label, fs: locked ? "" : v.fs, size: v.size, free: locked ? 0 : v.free, driveType: v.driveType,
      diskIndex: v.diskIndex, offset: v.offset, bitlocker: locked ? "locked" : "none", isSystem: v.isSystem,
      ssd: v.letter === "C" ? true : v.diskIndex === 1 ? false : null, trimEnabled: v.letter === "C" ? state.ssdTrim : null,
      state: locked ? "locked" : v.state,
    };
  });
  const snapshots = state.elevated
    ? [
        { id: "{3F9C1B8E-0A52-4D6B-9C3E-5B1D77E0A4F2}", devicePath: "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy3", volume: "C", created: NOW - 2 * DAY - 3 * 3600000 },
        { id: "{A71D20C4-6B9E-41F7-8D05-2C93E1B6F8A0}", devicePath: "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy2", volume: "C", created: NOW - 9 * DAY - 7 * 3600000 },
      ]
    : [];
  return { disks, volumes, snapshots, snapshotsNeedAdmin: !state.elevated, elevated: state.elevated };
}

function smartFor(disk) {
  const d = DISK_DEFS[disk];
  if (!d) throw "That drive isn't connected anymore. Pick a drive from the list.";
  needAdmin();
  const base = { disk, available: false, needsAdmin: false, health: "Unknown", temperatureC: null, powerOnHours: null, powerCycles: null, percentUsed: null,
    mediaErrors: null, reallocatedSectors: null, pendingSectors: null, unsafeShutdowns: null, dataRead: null, dataWritten: null, attributes: [], warnings: [], source: "Windows storage reliability" };
  if (disk === 0) {
    return { ...base, available: true, health: "Healthy", temperatureC: 41, powerOnHours: 2350, powerCycles: 612, percentUsed: 3, mediaErrors: 0, unsafeShutdowns: 18,
      dataRead: 21.4e12, dataWritten: 14.9e12, source: "NVMe health log",
      attributes: [
        { id: 1, name: "Critical warning", current: 0, worst: 0, threshold: 0, raw: 0, status: "ok" },
        { id: 2, name: "Composite temperature", current: 41, worst: 68, threshold: 85, raw: 41, status: "ok" },
        { id: 3, name: "Available spare", current: 100, worst: 100, threshold: 10, raw: 100, status: "ok" },
        { id: 5, name: "Percentage used", current: 3, worst: 3, threshold: 100, raw: 3, status: "ok" },
        { id: 14, name: "Media and data integrity errors", current: 0, worst: 0, threshold: 0, raw: 0, status: "ok" },
        { id: 15, name: "Unsafe shutdowns", current: 18, worst: 18, threshold: 0, raw: 18, status: "ok" },
      ] };
  }
  if (disk === 1) {
    return { ...base, available: true, health: "Warning", temperatureC: 36, powerOnHours: 31205, powerCycles: 1480, mediaErrors: 0, reallocatedSectors: 8, pendingSectors: 2,
      unsafeShutdowns: null, dataRead: 38.2e12, dataWritten: 22.7e12, source: "ATA SMART",
      warnings: ["This drive has 8 reallocated and 2 pending sectors, so it has started to fail. Make an image of it before scanning, and don't write anything to it."],
      attributes: [
        { id: 1, name: "Read error rate", current: 200, worst: 200, threshold: 51, raw: 0, status: "ok" },
        { id: 3, name: "Spin-up time", current: 187, worst: 185, threshold: 21, raw: 1650, status: "ok" },
        { id: 5, name: "Reallocated sector count", current: 192, worst: 192, threshold: 140, raw: 8, status: "warn" },
        { id: 9, name: "Power-on hours", current: 66, worst: 66, threshold: 0, raw: 31205, status: "ok" },
        { id: 12, name: "Power cycle count", current: 99, worst: 99, threshold: 0, raw: 1480, status: "ok" },
        { id: 194, name: "Temperature", current: 114, worst: 98, threshold: 0, raw: 36, status: "ok" },
        { id: 196, name: "Reallocation event count", current: 192, worst: 192, threshold: 0, raw: 8, status: "warn" },
        { id: 197, name: "Current pending sector count", current: 199, worst: 199, threshold: 0, raw: 2, status: "warn" },
        { id: 198, name: "Offline uncorrectable sector count", current: 200, worst: 200, threshold: 0, raw: 0, status: "ok" },
        { id: 199, name: "UDMA CRC error count", current: 200, worst: 200, threshold: 0, raw: 0, status: "ok" },
      ] };
  }
  return { ...base, health: disk === 3 ? "Healthy" : "Unknown", warnings: ["This device doesn't report health data."] };
}

/* ───────────────────────────── source resolution ───────────────────────────── */

const images = new Map(); // path -> ImageInfo

function guessImage(path) {
  const ext = extOf(path);
  const r = rng("img:" + path.toLowerCase());
  const sd = /sdcard|canon/i.test(path);
  const size = sd ? DISK_SIZES[2] : ext === "iso" ? Math.round(4.7 * GiB) : [16, 32, 64, 128, 256][r.int(0, 4)] * GiB;
  const format = ext === "vhdx" ? "vhdx" : ext === "vhd" ? (r.chance(0.5) ? "vhd-dynamic" : "vhd-fixed") : "raw";
  const fileSize = format === "raw" || format === "vhd-fixed" ? size : Math.round(size * (0.12 + r.f() * 0.3));
  if (ext === "iso") return { path, size, fileSize: size, format: "raw", partitionStyle: "None", fs: "FAT32", partitions: [] };
  if (sd) {
    return { path, size, fileSize, format, partitionStyle: "MBR", fs: null,
      partitions: [{ number: 1, offset: 4 * MiB, size: floorMiB(size - 4 * MiB), typeName: "Basic data", letter: null, fs: "exFAT", label: "CANON_EOS" }] };
  }
  const style = r.chance(0.6) ? "GPT" : "MBR";
  const off = style === "GPT" ? 1 * MiB : 63 * 512;
  return { path, size, fileSize, format, partitionStyle: style, fs: null,
    partitions: [{ number: 1, offset: off, size: floorMiB(size - off - 2 * MiB), typeName: "Basic data", letter: null, fs: "NTFS", label: "Data" }] };
}
function imageInfo(path) {
  if (!images.has(path)) images.set(path, guessImage(path));
  return images.get(path);
}

// CONTRACT: volume path = "C", disk path = "0" (older device-path forms accepted too).
const parseLetter = (p) => /^(?:\\\\\.\\)?([A-Za-z]):?\\?$/.exec(p || "")?.[1]?.toUpperCase() || null;
const parseDisk = (p) => {
  const m = /^(?:\\\\\.\\PhysicalDrive)?(\d+)$/i.exec(p || "");
  return m ? +m[1] : null;
};

/** Describes a SourceRef: length, fs, profile (which synthetic data set), speed. */
function resolveSource(ref) {
  if (!ref || !ref.kind) throw "MAX doesn't know which drive to read. Pick a drive from the list.";
  const gone = "That drive isn't connected anymore. Pick a drive from the list.";
  const res = { kind: ref.kind, ref, window: ref.offset || 0, label: ref.label || "", disk: null, letter: null, partitions: [], diskStyle: null };
  if (ref.kind === "volume") {
    const l = parseLetter(ref.path);
    const v = l && VOL_DEFS[l];
    if (!v) throw gone;
    Object.assign(res, { letter: l, fs: v.fs, len: ref.length ?? v.size, profile: "CEFG".indexOf(l) >= 0 ? { C: "c", E: "e", F: "sd", G: "usb" }[l] : "gen",
      ssd: !!v.ssd, bps: v.bps, volLabel: v.label, disk: v.diskIndex, diskOffset: v.offset, locked: l === "E" && state.bitlockerLocked });
    res.label = res.label || `${v.label ? v.label + " " : ""}(${l}:)`;
  } else if (ref.kind === "disk") {
    const n = parseDisk(ref.path);
    const d = DISK_DEFS[n];
    if (!d) throw gone;
    const part = d.parts.find((p) => p.offset === (ref.offset || 0));
    const lost = n === 1 && (ref.offset || 0) === LOST_OFFSET;
    const whole = !ref.offset && ref.length == null;
    const main = d.parts[d.parts.length > 2 ? 2 : 0];
    const pp = lost ? { fs: "NTFS", letter: null, label: "" } : part || main;
    const profile = lost ? "gen" : pp.letter ? { C: "c", E: "e", F: "sd", G: "usb" }[pp.letter] : "gen";
    Object.assign(res, { disk: n, letter: pp.letter, fs: whole ? pp.fs : pp.fs, len: ref.length ?? d.size - (ref.offset || 0), profile, ssd: d.media === "SSD",
      bps: DISK_BPS[n], volLabel: pp.label || "", diskStyle: d.partitionStyle, partitions: d.parts, lost, whole, locked: pp.letter === "E" && state.bitlockerLocked });
    res.label = res.label || `${d.model}${lost ? " — lost partition" : ""}`;
  } else if (ref.kind === "image") {
    const info = imageInfo(ref.path || "");
    const sd = /sdcard|canon/i.test(ref.path);
    Object.assign(res, { fs: info.partitions[0]?.fs || info.fs || null, len: ref.length ?? info.size, profile: sd ? "sd" : "gen", ssd: false, bps: 4.5e8, volLabel: info.partitions[0]?.label || "", image: info, locked: false });
    res.label = res.label || (ref.path || "").split("\\").pop();
  } else if (ref.kind === "snapshot") {
    const v = VOL_DEFS.C;
    Object.assign(res, { letter: "C", fs: "NTFS", len: ref.length ?? v.size, profile: "c", ssd: true, bps: 1.6e9, volLabel: v.label, locked: false });
    res.label = res.label || "Snapshot of Windows (C:)";
  } else throw gone;
  if (res.fs === "RAW" || res.fs == null || res.fs === "") res.fsKnown = false;
  else res.fsKnown = true;
  return res;
}

/* ───────────────────────────── synthetic disk layout ───────────────────────────── */

function subtractPairs(run, holes) {
  const out = [];
  let pos = run[0];
  for (const h of holes) {
    if (h[0] > pos) out.push([pos, Math.min(h[0], run[1])]);
    pos = Math.max(pos, h[1]);
  }
  if (pos < run[1]) out.push([pos, run[1]]);
  return out;
}

/** Deterministic map of a source: metadata at the start, long allocated runs, free gaps, remnants, bad sectors. */
function buildGeo(spec, r) {
  const L = spec.len;
  const snap = (x) => Math.round(x / UNIT) * UNIT;
  let head = 0;
  if (spec.fs === "NTFS") head = snap(Math.max(16 * MiB, L * 0.006));
  else if (spec.fs && spec.fs !== "RAW") head = snap(Math.max(8 * MiB, Math.min(L * 0.0008, 64 * MiB)));
  head = Math.min(head, L / 4);
  const meta = [];
  if (head) {
    meta.push([0, head]);
  }
  const allocPairs = [];
  if (spec.fill > 0 && spec.fsKnown !== false) {
    const cycles = spec.fill < 0.2 ? 120 : 750;
    const cycle = L / cycles;
    let pos = head;
    while (pos < L) {
      const a = Math.max(2 * UNIT, r.expo(cycle * spec.fill));
      const f = Math.max(2 * UNIT, r.expo(cycle * (1 - spec.fill)));
      const run = [snap(pos), Math.min(L, snap(pos + a))];
      if (run[1] > run[0]) {
        // chew a few holes into long runs so zooming in shows texture
        const spacing = Math.max(L / 30000, 8 * UNIT);
        const n = Math.floor((run[1] - run[0]) / spacing);
        const holes = [];
        for (let k = 0; k < n; k++) {
          const hs = snap(run[0] + r.f() * (run[1] - run[0]));
          holes.push([hs, hs + r.int(1, 6) * UNIT]);
        }
        holes.sort((x, y) => x[0] - y[0]);
        for (const p of subtractPairs(run, holes)) allocPairs.push(p);
      }
      pos += a + f;
    }
    // small allocated islands inside free space
    const nIsl = Math.round(cycles * 0.6);
    for (let k = 0; k < nIsl; k++) {
      const s = snap(head + r.f() * (L - head));
      allocPairs.push([s, Math.min(L, s + r.int(1, 5) * UNIT)]);
    }
  }
  const alloc = new Iv(allocPairs);
  // scattered directory / metadata clusters inside allocated space
  const dirPairs = [];
  if (alloc.length && spec.fs !== "RAW") {
    const n = clamp(Math.round(L / (10 * GiB)), 12, 100);
    for (let k = 0; k < n; k++) {
      const i = r.int(0, alloc.length - 1);
      const s = snap(alloc.s[i] + r.f() * (alloc.e[i] - alloc.s[i]));
      dirPairs.push([s, s + r.int(1, 2) * UNIT]);
    }
  }
  const metaIv = new Iv(meta.concat(dirPairs));
  const used = new Iv(allocPairs.concat(meta));
  const free = used.gaps(0, L).filter((g) => g[1] - g[0] >= 2 * UNIT);
  // remnants of deleted data scattered through free space
  const remPairs = [];
  if (free.length) {
    const n = clamp(Math.round(L / (5 * GiB)), 24, 220);
    for (let k = 0; k < n; k++) {
      const g = free[r.int(0, free.length - 1)];
      const s = snap(g[0] + r.f() * (g[1] - g[0]));
      remPairs.push([s, Math.min(g[1], s + r.int(1, 24) * UNIT)]);
    }
  }
  const badPairs = [];
  if (spec.bad) {
    for (let k = 0; k < 6; k++) {
      const s = Math.floor((L * (0.06 + r.f() * 0.38)) / 4096) * 4096;
      badPairs.push([s, s + 4096 * r.int(1, 4)]);
    }
  }
  return { L, head, alloc, meta: metaIv, free, rem: new Iv(remPairs), bad: new Iv(badPairs) };
}

/* ───────────────────────────── file generation ───────────────────────────── */

const SIZE = {
  jpg: [4.6e6, 0.32], png: [1.4e6, 0.8], gif: [0.8e6, 1], bmp: [3e6, 0.6], tiff: [20e6, 0.4], webp: [0.5e6, 0.6], heic: [2.4e6, 0.35],
  cr2: [24e6, 0.15], cr3: [27e6, 0.18], nef: [28e6, 0.15], arw: [26e6, 0.15], dng: [30e6, 0.3], psd: [40e6, 0.9], svg: [30e3, 1],
  mp4: [120e6, 0.9], mov: [200e6, 0.8], avi: [250e6, 0.8], mkv: [700e6, 0.7], mts: [150e6, 0.7], "3gp": [20e6, 0.8], wmv: [60e6, 0.8],
  mp3: [4.2e6, 0.45], wav: [30e6, 0.8], flac: [25e6, 0.5], m4a: [4e6, 0.5], ogg: [3.5e6, 0.5], mid: [30e3, 0.8],
  docx: [58e3, 0.9], xlsx: [110e3, 1], pptx: [3.5e6, 0.9], pdf: [420e3, 1.1], txt: [4e3, 1.4], csv: [60e3, 1.4], zip: [12e6, 1.5], rar: [20e6, 1.4],
  "7z": [30e6, 1.4], iso: [900e6, 0.7], exe: [3.5e6, 1.2], msi: [18e6, 0.8], dll: [600e3, 1], sqlite: [2e6, 1.2], dat: [80e3, 1.5], lnk: [2e3, 0.3],
  html: [40e3, 1.2], eml: [30e3, 1.2], rtf: [90e3, 1], doc: [120e3, 1], xls: [140e3, 1], ppt: [2.5e6, 1], pst: [400e6, 0.8], ico: [20e3, 0.6],
};
function sizeFor(r, typeId, spec) {
  let [med, sig] = SIZE[typeId] || [500e3, 1];
  if (spec.profile === "sd" && typeId === "mp4") [med, sig] = [88e6, 0.7];
  if (spec.profile === "c" && typeId === "mp4") [med, sig] = [45e6, 1];
  const v = r.logn(med, sig);
  return Math.round(clamp(v, typeId === "txt" || typeId === "lnk" ? 120 : 1500, 2 * GiB));
}

const DOC_BASES = ["Tax return", "Budget", "Meeting notes", "Invoice", "CV", "Cover letter", "Project plan", "Lease agreement", "Insurance policy", "Quarterly report",
  "Recipe collection", "Thesis draft", "Travel itinerary", "Household accounts", "Presentation", "Contract", "Minutes", "Proposal", "Research notes", "Receipts",
  "Timesheet", "Workout plan", "Letter to landlord", "Mortgage statement", "School newsletter", "Garden plan"];
const DOC_SUFFIX = ["", "", " 2023", " 2024", " 2025", " (final)", " v2", " - draft", " copy", " March", " Q3", " Ann"];
const ARTISTS = ["Fleetwood Mac", "Daft Punk", "Adele", "Radiohead", "Norah Jones", "Coldplay", "Bon Iver", "Florence + The Machine"];
const TITLES = ["Dreams", "Digital Love", "Hometown Glory", "Karma Police", "Come Away With Me", "Fix You", "Holocene", "Shake It Out", "Skinny Love", "Instant Crush"];
const CAMERAS = [["iPhone 14 Pro", 4032, 3024], ["Pixel 7", 4080, 3072], ["Canon EOS 80D", 6000, 4000], ["NIKON D5600", 6000, 4000], ["SM-S911B", 4000, 3000]];
const T0 = Date.UTC(2023, 0, 3);
const T1 = Date.UTC(2026, 9, 28);
const rdate = (r, a = T0, b = T1) => Math.floor(a + r.f() * (b - a));
const docName = (r, ext) => r.pick(DOC_BASES) + r.pick(DOC_SUFFIX) + "." + ext;
const musicName = (r) => `${r.pick(ARTISTS)} - ${r.pick(TITLES)}.mp3`;
const D = (name, folder, typeId, o = {}) => ({ name, folder, typeId, status: "deleted", origin: "ntfs", ...o });
const pad2 = (n) => String(n).padStart(2, "0");

function draftsSD(r, spec) {
  const out = [];
  let t = Date.UTC(2024, 2, 2, 10, 15, 0);
  let img = 4801;
  let mvi = 912;
  const del = Date.UTC(2025, 0, 12, 19, 4, 0);
  for (let i = 0; i < spec.nFs; i++) {
    if (r.chance(0.025)) t += r.int(3, 12) * DAY + r.int(0, 8) * 3600000;
    t += r.int(8, 240) * 1000;
    const folder = i < spec.nFs * 0.55 ? "\\DCIM\\100CANON" : "\\DCIM\\101CANON";
    const k = r.weighted([["jpg", 0.84], ["cr3", 0.05], ["mp4", 0.08], ["dat", 0.03]]);
    let name, typeId = k;
    if (k === "jpg") name = `IMG_${img++}.JPG`;
    else if (k === "cr3") name = `IMG_${img++}.CR3`;
    else if (k === "mp4") name = `MVI_${mvi++}.MP4`;
    else (name = r.pick(["AUTPRINT.MRK", "CANON.THM", "STARTUP.BIN"])), (typeId = "dat");
    out.push(D(name, typeId === "dat" ? "\\MISC" : folder, typeId, { origin: "exfat", modified: t, created: t, deleted: del, taken: t }));
  }
  for (let i = 0; i < spec.nCarved; i++) {
    const typeId = r.weighted([["jpg", 0.88], ["mp4", 0.06], ["cr3", 0.06]]);
    out.push(D("", `\\Found by signature\\${TY[typeId].label}`, typeId, { status: "carved", origin: "carving", carved: true, taken: rdate(r, Date.UTC(2024, 2, 1), Date.UTC(2025, 0, 8)) }));
  }
  return out;
}

function draftsC(r, spec) {
  const out = [];
  const U = "\\Users\\Ann";
  const add = (folder, n, types, namer, o = {}) => {
    for (let i = 0; i < n; i++) {
      const typeId = r.weighted(types);
      out.push(D(namer(r, typeId, i), folder, typeId, o));
    }
  };
  const phone = (r2, ty) => `IMG_${r2.int(1000, 9999)}.${ty === "heic" ? "HEIC" : ty}`;
  const pixel = (r2, ty) => `PXL_2024${pad2(r2.int(6, 8))}${pad2(r2.int(1, 28))}_${pad2(r2.int(8, 20))}${pad2(r2.int(0, 59))}${pad2(r2.int(0, 59))}.${ty === "jpg" ? "jpg" : ty}`;
  add(U + "\\Documents", 480, [["docx", 35], ["xlsx", 20], ["pdf", 25], ["txt", 8], ["pptx", 7], ["csv", 5]], (r2, ty) => docName(r2, ty));
  add(U + "\\Pictures\\Holiday 2024", 300, [["jpg", 80], ["heic", 12], ["png", 3], ["mp4", 5]], (r2, ty, i) => (i % 2 ? phone(r2, ty) : pixel(r2, ty)));
  add(U + "\\Pictures", 120, [["jpg", 70], ["png", 25], ["gif", 5]], (r2, ty) => (ty === "png" ? `Screenshot ${fmtDT(rdate(r2)).slice(0, 10)} ${r2.int(100000, 235959)}.png` : phone(r2, ty)));
  add(U + "\\Downloads", 300, [["pdf", 30], ["zip", 20], ["exe", 15], ["jpg", 10], ["png", 8], ["msi", 5], ["docx", 8], ["mp4", 4]], (r2, ty) => {
    const n = r2.int(100, 99999);
    if (ty === "exe") return r2.pick(["setup-x64", "VSCodeSetup", "Zoom_installer", "7z2301-x64", "OneDriveSetup", "Steam_Setup"]) + ".exe";
    if (ty === "msi") return r2.pick(["AcroRdrDC", "vc_redist", "git-install"]) + ".msi";
    if (ty === "zip") return r2.pick(["report-", "photos-", "project_files_"]) + n + ".zip";
    if (ty === "pdf") return r2.pick(["invoice_", "boarding-pass-", "statement_", "manual-"]) + n + ".pdf";
    if (ty === "mp4") return `VID-${n}.mp4`;
    if (ty === "docx") return r2.pick(["Application form", "Reference letter", "Rental agreement"]) + ".docx";
    return `${r2.pick(["image", "download", "photo"])} (${r2.int(1, 40)}).${ty}`;
  });
  add(U + "\\Desktop", 120, [["docx", 30], ["pdf", 25], ["png", 20], ["xlsx", 10], ["txt", 10], ["lnk", 5]], (r2, ty) => (ty === "png" ? `Screenshot ${r2.int(1, 300)}.png` : ty === "lnk" ? r2.pick(["Steam", "Chrome", "Spotify"]) + ".lnk" : docName(r2, ty)));
  add(U + "\\Music", 70, [["mp3", 90], ["m4a", 10]], (r2, ty) => musicName(r2).replace(".mp3", "." + ty));
  add(U + "\\Videos", 30, [["mp4", 70], ["mov", 20], ["mkv", 10]], (r2, ty) => `${r2.pick(["Family", "Birthday", "Clip", "Screen recording"])} ${r2.int(1, 60)}.${ty}`);
  add(U + "\\AppData\\Local\\Temp", 40, [["dat", 70], ["sqlite", 30]], (r2, ty) => (ty === "dat" ? `~WRL${hex(r2.int(0, 65535), 4)}.tmp` : `thumbcache_${r2.int(16, 2560)}.db`));
  add("\\Lost folders\\Folder 18342", 150, [["docx", 25], ["jpg", 30], ["pdf", 20], ["xlsx", 10], ["png", 10], ["mp3", 5]], (r2, ty) => (ty === "jpg" || ty === "png" ? phone(r2, ty) : ty === "mp3" ? musicName(r2) : docName(r2, ty)), { status: "lost" });
  add("\\Lost folders\\Folder 20977", 70, [["jpg", 50], ["docx", 25], ["pdf", 25]], (r2, ty) => (ty === "jpg" ? phone(r2, ty) : docName(r2, ty)), { status: "lost" });
  add("\\$Recycle.Bin\\S-1-5-21-3459127811-1127356004-3214398841-1001", spec.nFs - out.length, [["docx", 30], ["pdf", 25], ["jpg", 25], ["xlsx", 10], ["zip", 5], ["txt", 5]], (r2, ty) => (ty === "jpg" ? phone(r2, ty) : docName(r2, ty)), { status: "recycleBin", origin: "recycleBin" });
  for (const d of out) {
    d.modified = rdate(r, T0, T1 - 30 * DAY);
    d.created = d.modified - r.int(0, 200) * DAY;
    d.deleted = Math.min(NOW - 2 * DAY, d.modified + r.int(1, 90) * DAY);
  }
  return out;
}

function draftsE(r, spec) {
  const out = [];
  const add = (folder, n, types, namer, o = {}) => {
    for (let i = 0; i < n; i++) {
      const typeId = r.weighted(types);
      out.push(D(namer(r, typeId, i), folder, typeId, o));
    }
  };
  let dsc = 1000;
  add("\\Backup\\Documents\\2022", 120, [["docx", 40], ["pdf", 40], ["xlsx", 20]], (r2, ty) => docName(r2, ty));
  add("\\Backup\\Documents\\2023", 150, [["docx", 40], ["pdf", 40], ["xlsx", 20]], (r2, ty) => docName(r2, ty));
  add("\\Backup\\Documents\\2024", 150, [["docx", 35], ["pdf", 40], ["xlsx", 15], ["pptx", 10]], (r2, ty) => docName(r2, ty));
  add("\\Backup\\Photos\\2023\\Lake District", 260, [["jpg", 90], ["nef", 10]], (r2, ty) => `DSC_${dsc++}.${ty === "jpg" ? "JPG" : "NEF"}`);
  add("\\Backup\\Photos\\2024\\Birthday", 260, [["jpg", 94], ["heic", 6]], (r2, ty) => `IMG_${r2.int(1000, 9999)}.${ty === "jpg" ? "JPG" : "HEIC"}`);
  add("\\Backup\\Projects\\Website redesign", 200, [["zip", 15], ["psd", 15], ["png", 40], ["txt", 20], ["pdf", 10]], (r2, ty) => `${r2.pick(["logo", "homepage", "wireframes", "banner", "notes", "brief", "assets"])}_v${r2.int(1, 9)}.${ty}`);
  add("\\Backup\\Videos\\Family", 80, [["mp4", 60], ["mov", 30], ["avi", 10]], (r2, ty) => `${r2.pick(["Christmas", "Wedding", "Holiday", "Birthday", "Garden"])} ${r2.int(2019, 2024)} part ${r2.int(1, 6)}.${ty}`);
  add("\\Backup\\Music", 140, [["mp3", 100]], (r2) => musicName(r2));
  add("\\Archive\\Old laptop", 40, [["zip", 50], ["rar", 30], ["iso", 20]], (r2, ty) => `${r2.pick(["old-laptop-backup", "drivers", "windows10", "documents-2019", "installers"])}${r2.int(1, 9)}.${ty}`);
  const rest = spec.nFs - out.length;
  add("\\Lost folders\\Folder 4410", Math.max(0, rest), [["docx", 40], ["jpg", 40], ["pdf", 20]], (r2, ty) => (ty === "jpg" ? `IMG_${r2.int(1000, 9999)}.JPG` : docName(r2, ty)), { status: "lost", loose: true });
  for (let i = 0; i < spec.nCarved; i++) {
    const typeId = r.weighted([["jpg", 0.55], ["pdf", 0.15], ["zip", 0.1], ["mp3", 0.12], ["mp4", 0.08]]);
    out.push(D("", `\\Found by signature\\${TY[typeId].label}`, typeId, { status: "carved", origin: "carving", carved: true, taken: rdate(r, Date.UTC(2022, 0, 1), Date.UTC(2024, 10, 1)) }));
  }
  for (const d of out) {
    if (d.carved) continue;
    d.modified = rdate(r, Date.UTC(2023, 0, 5), Date.UTC(2025, 5, 1));
    d.created = d.modified - r.int(0, 300) * DAY;
    d.deleted = Math.min(NOW - 30 * DAY, d.modified + r.int(5, 200) * DAY);
  }
  return out;
}

/** Carved-only data sets: a RAW USB stick, or a generic source. */
function draftsCarved(r, spec, weights) {
  const out = [];
  for (let i = 0; i < spec.nCarved; i++) {
    const typeId = r.weighted(weights);
    out.push(D("", `\\Found by signature\\${TY[typeId].label}`, typeId, { status: "carved", origin: "carving", carved: true, taken: rdate(r) }));
  }
  return out;
}
function draftsGen(r, spec) {
  const out = [];
  const folders = [["\\Documents", [["docx", 35], ["pdf", 30], ["xlsx", 20], ["txt", 15]]], ["\\Pictures", [["jpg", 80], ["png", 20]]], ["\\Downloads", [["zip", 30], ["pdf", 30], ["exe", 20], ["jpg", 20]]]];
  for (let i = 0; i < spec.nFs; i++) {
    const [folder, types] = folders[i % 3 === 0 ? 0 : i % 3 === 1 ? 1 : 2];
    const typeId = r.weighted(types);
    const modified = rdate(r);
    out.push(D(typeId === "jpg" ? `IMG_${r.int(1000, 9999)}.JPG` : docName(r, typeId), folder, typeId, { origin: spec.fs === "exFAT" ? "exfat" : spec.fs && spec.fs.startsWith("FAT") ? "fat" : "ntfs", modified, created: modified - r.int(0, 90) * DAY, deleted: Math.min(NOW - DAY, modified + r.int(1, 60) * DAY) }));
  }
  return out.concat(draftsCarved(r, spec, [["jpg", 0.5], ["png", 0.1], ["pdf", 0.15], ["docx", 0.1], ["zip", 0.1], ["mp3", 0.05]]));
}
const DRAFTS = {
  sd: draftsSD,
  c: draftsC,
  e: draftsE,
  usb: (r, spec) => draftsCarved(r, spec, [["jpg", 0.55], ["png", 0.1], ["pdf", 0.1], ["docx", 0.08], ["mp3", 0.07], ["zip", 0.05], ["mp4", 0.05]]),
  gen: draftsGen,
};

function metaFor(r, typeId, d, spec) {
  const cat = catOf(typeId);
  const m = {};
  const when = d.taken || d.modified || rdate(r);
  if (cat === "photo" && !["svg", "ico", "psd"].includes(typeId)) {
    if (typeId === "png" && !d.carved) {
      m.width = String(r.pick([1920, 2560, 1366]));
      m.height = String(m.width === "1920" ? 1080 : m.width === "2560" ? 1440 : 768);
      return m;
    }
    const cam = spec.profile === "sd" ? ["Canon EOS R6", 5472, 3648] : r.pick(CAMERAS);
    m.camera = cam[0];
    m.taken = fmtDT(when);
    m.width = String(cam[1]);
    m.height = String(cam[2]);
  } else if (cat === "video") {
    const s = r.int(6, 540);
    m.duration = `${Math.floor(s / 60)}:${pad2(s % 60)}`;
    m.width = r.chance(0.7) ? "1920" : "3840";
    m.height = m.width === "1920" ? "1080" : "2160";
    if (spec.profile === "sd") m.camera = "Canon EOS R6";
    m.taken = fmtDT(when);
  } else if (cat === "audio") {
    m.artist = r.pick(ARTISTS);
    m.title = r.pick(TITLES);
    const s = r.int(110, 360);
    m.duration = `${Math.floor(s / 60)}:${pad2(s % 60)}`;
  } else if (cat === "document") {
    m.title = d.title || r.pick(DOC_BASES) + r.pick(DOC_SUFFIX);
    if (["pdf", "docx", "pptx", "odt", "doc"].includes(typeId)) m.pages = String(r.int(1, 24));
    if (["docx", "xlsx", "pptx"].includes(typeId)) m.author = "Ann Miller";
  }
  return m;
}

const NOTE = {
  excellent: ["Its clusters are still free.", "Its clusters are still free and the file opens cleanly."],
  good: ["Its clusters are free, but the file is stored in several pieces."],
  partial: ["Part of it has been overwritten by other files.", "Part of it has been overwritten by other files, so it may not open."],
  unknown: ["MAX can't tell whether this file is intact."],
};
const NOTE_ZERO = "Its data reads as zeros — the drive has probably erased it (SSD TRIM).";

function finishDraft(r, d, spec) {
  const typeId = d.typeId;
  const ty = TY[typeId];
  const f = {
    name: d.name, folder: d.folder, size: d.size ?? sizeFor(r, typeId, spec), status: d.status, origin: d.origin, typeId, category: ty.cat,
    created: d.created ?? null, modified: d.modified ?? null, accessed: null, deleted: d.deleted ?? null, extents: [], condition: "excellent", note: "",
    fragmented: false, flags: 0, fsRef: null, meta: {}, dupGroup: null, livePath: null, _carved: !!d.carved,
  };
  f.meta = metaFor(r, typeId, d, spec);
  // condition mix
  const weights = f.status === "recycleBin" ? [["excellent", 0.9], ["good", 0.07], ["unknown", 0.03]] : [["excellent", 0.55], ["good", 0.2], ["partial", 0.15], ["unknown", 0.1]];
  f.condition = r.weighted(weights);
  if (f.condition === "excellent") f.note = f.status === "recycleBin" ? "It is still in the Recycle Bin, so it can be restored as it is." : f._carved ? "Its header and footer were both found, and it opens cleanly." : r.pick(NOTE.excellent);
  else if (f.condition === "good") {
    f.fragmented = true;
    f.note = f._carved ? "It was found by its content and looks complete, but nothing confirms every piece is intact." : NOTE.good[0];
  } else if (f.condition === "partial") {
    f.flags |= 64;
    f.fragmented = r.chance(0.4);
    f.note = f._carved ? "It stops early — the rest of the file was probably overwritten." : r.pick(NOTE.partial);
  } else if (spec.ssd && f.status !== "recycleBin" && r.chance(0.75)) {
    f.flags |= 32;
    f.note = NOTE_ZERO;
  } else f.note = NOTE.unknown[0];
  // names, flags
  if (f._carved) {
    f.flags |= 16;
    const dots = f.meta.taken ? f.meta.taken.replace(/:/g, ".") : null;
    const ext = ty.exts[0];
    if (f.category === "photo" && dots && f.meta.camera && r.chance(0.82)) f.name = `${dots} ${f.meta.camera}.${ext}`;
    else if (f.category === "video" && dots && f.meta.camera && r.chance(0.6)) f.name = `${dots} ${f.meta.camera}.${ext}`;
    else if (f.category === "document" && f.meta.title && r.chance(0.7)) f.name = `${f.meta.title}.${ext}`;
    else if (f.category === "audio" && r.chance(0.7)) f.name = `${f.meta.artist} - ${f.meta.title}.${ext}`;
    else f._hexName = true;
    f.created = f.modified = null;
    f.deleted = null;
  } else {
    if (d.status === "lost" || d.loose) f.flags |= d.loose ? 1024 : 0;
    if (r.chance(0.012) && (f.category === "photo" || f.category === "document") && ty.exts.length) {
      // the content says something other than the extension
      const alt = f.category === "photo" ? (typeId === "jpg" ? "png" : "jpg") : typeId === "docx" ? "zip" : "docx";
      f.typeId = alt;
      f.flags |= 8;
    }
    f.accessed = f.modified ? Math.min(NOW - DAY, f.modified + r.int(0, 40) * DAY) : null;
    f.fsRef = f.origin === "ntfs" || f.origin === "recycleBin" ? r.int(40000, 900000) : r.int(2, 480000);
    if (f.status === "recycleBin") {
      f.flags |= 256;
      f.livePath = `C:\\$Recycle.Bin\\S-1-5-21-3459127811-1127356004-3214398841-1001\\$R${randHex(r, 6).toUpperCase()}${f.name.slice(f.name.lastIndexOf("."))}`;
    }
  }
  return f;
}

function assignDups(r, files, spec) {
  const pool = files.filter((f) => (f.category === "photo" || f.category === "document") && !f._carved && f.status !== "recycleBin");
  const groups = Math.round(clamp(pool.length / 40, 3, 45));
  for (let g = 1; g <= groups && pool.length > 4; g++) {
    const a = pool[r.int(0, pool.length - 1)];
    const n = r.int(1, 2);
    if (a.dupGroup) continue;
    a.dupGroup = g;
    for (let k = 0; k < n; k++) {
      const b = pool[r.int(0, pool.length - 1)];
      if (b === a || b.dupGroup || b.category !== a.category) continue;
      b.dupGroup = g;
      b.size = a.size;
      b.meta = { ...a.meta };
      const dot = a.name.lastIndexOf(".");
      b.name = `${a.name.slice(0, dot)}${r.pick([" (1)", " - Copy", " (2)"])}${a.name.slice(dot)}`;
      b.typeId = a.typeId;
      b.flags = (b.flags & ~8) | (a.flags & 8);
      b.condition = a.condition;
      b.note = a.note;
      b.flags = (b.flags & ~(32 | 64)) | (a.flags & (32 | 64));
    }
  }
  // singletons are not duplicates
  const count = new Map();
  for (const f of files) if (f.dupGroup) count.set(f.dupGroup, (count.get(f.dupGroup) || 0) + 1);
  for (const f of files) if (f.dupGroup && count.get(f.dupGroup) < 2) f.dupGroup = null;
}

function placeFiles(r, files, geo, spec) {
  const cl = spec.cluster;
  const free = geo.free
    .map(([s, e]) => [Math.ceil(s / cl) * cl, Math.floor(e / cl) * cl])
    .filter((g) => g[1] - g[0] >= cl * 2);
  if (!free.length) free.push([Math.ceil(geo.head / cl) * cl, Math.floor(geo.L / cl) * cl]);
  const cursor = free.map((g) => g[0]);
  let need = 0;
  for (const f of files) need += Math.ceil(f.size / cl) * cl;
  need *= 1.6;
  const order = free.map((_, i) => i);
  for (let i = order.length - 1; i > 0; i--) {
    const j = r.int(0, i);
    [order[i], order[j]] = [order[j], order[i]];
  }
  let cap = 0;
  const hot = [];
  for (const i of order) {
    hot.push(i);
    cap += free[i][1] - free[i][0];
    if (cap >= need) break;
  }
  hot.sort((a, b) => a - b);
  let hp = 0;
  const fit = (i, len) => {
    if (free[i][1] - cursor[i] < len) return null;
    const e = { offset: cursor[i], len };
    cursor[i] += len + (r.chance(0.12) ? cl * r.int(1, 3) : 0);
    return e;
  };
  const spill = (len) => {
    // spread over successive runs (a file bigger than any one gap)
    const out = [];
    let left = len;
    let i = r.int(0, free.length - 1);
    for (let n = 0; n < free.length && left > 0; n++, i = (i + 1) % free.length) {
      const room = free[i][1] - cursor[i];
      if (room < cl) continue;
      const take = Math.min(room, left);
      out.push({ offset: cursor[i], len: take });
      cursor[i] += take;
      left -= take;
    }
    return out;
  };
  const placeOne = (len, sequential, jump) => {
    if (jump) hp = (hp + r.int(1, 3)) % hot.length;
    if (sequential && r.chance(0.97)) {
      for (let k = 0; k < hot.length; k++) {
        const e = fit(hot[(hp + k) % hot.length], len);
        if (e) {
          hp = (hp + k) % hot.length;
          return [e];
        }
      }
    }
    for (let n = 0; n < 60; n++) {
      const e = fit(r.int(0, free.length - 1), len);
      if (e) return [e];
    }
    return spill(len);
  };
  for (const f of files) {
    if (f.status === "recycleBin" && !f.fragmented) {
      // intact files sit on their own, still-allocated clusters; show them in free space anyway for the map
    }
    const len = Math.max(cl, Math.ceil(f.size / cl) * cl);
    if (f.fragmented && len >= cl * 4) {
      const parts = r.int(2, 3);
      const each = Math.ceil(len / parts / cl) * cl;
      let ext = [];
      for (let p = 0; p < parts; p++) ext = ext.concat(placeOne(each, true, p > 0));
      f.extents = ext;
    } else {
      f.extents = placeOne(len, true);
      if (f.extents.length > 1) f.fragmented = true;
    }
    f.extents.sort((a, b) => a.offset - b.offset);
  }
}

function genSession(spec) {
  const r = rng(spec.seed);
  const drafts = (DRAFTS[spec.profile] || draftsGen)(r, spec);
  const geo = buildGeo(spec, r);
  const files = drafts.map((d) => finishDraft(r, d, spec));
  assignDups(r, files, spec);
  placeFiles(r, files, geo, spec);
  if (spec.bad) {
    const cands = files.filter((f) => !f._carved && f.extents.length);
    const bads = geo.bad.pairs();
    for (let k = 0; k < Math.min(4, bads.length, cands.length); k++) {
      const f = cands[r.int(0, cands.length - 1)];
      f.extents[0] = { offset: bads[k][0] - (bads[k][0] % spec.cluster), len: f.extents[0].len };
      f.flags |= 128;
      f.condition = "partial";
      f.note = "Some sectors of this file couldn't be read from the drive.";
    }
  }
  const fs = files.filter((f) => !f._carved);
  const carved = files.filter((f) => f._carved).sort((a, b) => a.extents[0].offset - b.extents[0].offset);
  const all = fs.concat(carved);
  all.forEach((f, i) => {
    f.id = i + 1;
    f._nk = f.name.toLowerCase();
    if (f._hexName) f.name = `${f.typeId}_${hex(f.extents[0].offset)}.${TY[f.typeId].exts[0]}`;
    if (f._hexName) f._nk = f.name.toLowerCase();
    if (f.name === "") f.name = `${f.typeId}_${f.id}`;
  });
  all.forEach((f) => {
    f._nk = f.name.toLowerCase();
    f._ext = extOf(f.name);
    const bad = f.flags & 8;
    if (bad) {
      // the extension doesn't match the detected type
      const dot = f.name.lastIndexOf(".");
      const other = TY[f.typeId].exts[0] === f._ext ? (f.category === "photo" ? "dat" : "bin") : null;
      if (other && dot > 0) {
        f.name = f.name.slice(0, dot + 1) + other;
        f._nk = f.name.toLowerCase();
        f._ext = other;
      }
    }
  });
  return { all, nc: fs.length, geo };
}

/* ───────────────────────────── sessions ───────────────────────────── */

const sessions = new Map(); // id -> session
let jobSeq = 100;
let sessionSeq = 0;

const PLAN = {
  quick: [["filesystem", 0.5], ["recyclebin", 0.15], ["condition", 0.35]],
  deep: [["filesystem", 0.12], ["recyclebin", 0.04], ["sweep", 0.65], ["rebuild", 0.06], ["condition", 0.13]],
  partitions: [["partitions", 1]],
};
const STAGE_LABEL = {
  filesystem: "Reading the file system", recyclebin: "Checking the Recycle Bin", sweep: "Reading every sector", rebuild: "Rebuilding folders",
  condition: "Checking what can be recovered", partitions: "Looking for lost partitions",
};
const DURATION = { quick: 6000, deep: 25000, partitions: 8000 };

function humanSize(n) {
  if (n < 1000) return `${n} B`;
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do {
    n /= 1000;
    i++;
  } while (n >= 1000 && i < 3);
  return `${n >= 100 ? Math.round(n) : n.toFixed(1)} ${u[i]}`;
}
const fmtNum = (n) => Math.round(n).toLocaleString("en-US");

function clusterFor(fs, len) {
  if (fs === "exFAT") return len > 32 * GiB ? 131072 : 32768;
  if (fs && fs.startsWith("FAT")) return 32768;
  return 4096;
}

const BASE = {
  c: { fill: 0.6, nQuick: 1100, nDeep: 260 },
  sd: { fill: 0.08, nQuick: 600, nDeep: 800 },
  e: { fill: 0.7, nQuick: 700, nDeep: 150 },
  usb: { fill: 0, nQuick: 0, nDeep: 700 },
  gen: { fill: 0.5, nQuick: 400, nDeep: 200 },
};

function specFor(res, mode, id) {
  const b = BASE[res.profile] || BASE.gen;
  const fsKnown = res.fsKnown;
  const spec = {
    seed: "sess:" + id + ":" + res.profile, profile: res.profile, fs: res.fs || "RAW", fsKnown, len: res.len, fill: b.fill, ssd: !!res.ssd, bad: res.disk === 1,
    nFs: mode === "partitions" || !fsKnown ? 0 : b.nQuick, nCarved: mode === "deep" ? b.nDeep : 0,
  };
  if (!fsKnown) spec.fs = "RAW";
  spec.cluster = clusterFor(spec.fs, spec.len);
  return spec;
}

function probeOf(s) {
  const r = s.res;
  if (!r.fsKnown || s.mode === "partitions") return null;
  const serial = { C: "4A1C-9E27-B3D0-5F68", E: "9D02-77AB-3E41-C0F5", F: "B7E2-19D4" }[r.letter] || hex(fnv(s.id), 8).replace(/(....)(....)/, "$1-$2");
  return { fs: r.fs, clusterSize: s.spec.cluster, sectorSize: 512, totalSize: s.spec.len, label: r.volLabel || "", serial, usedBackupBoot: false };
}

function makeSession(o) {
  const res = o.res;
  const spec = o.spec || specFor(res, o.mode, o.id);
  const g = genSession(spec);
  const s = {
    id: o.id, label: o.label, source: o.source, mode: o.mode, state: o.state, created: o.created, updated: o.updated ?? o.created,
    options: o.options || { mode: o.mode, includeExisting: false, carveTypes: null, carveFreeOnly: true, customSignatures: false, label: null },
    res, spec, all: g.all, nc: g.nc, carvedN: g.all.length - g.nc, geo: g.geo, t: o.t ?? 1, run: null, error: null, partitions: null,
    dupesDone: !!o.dupesDone, job: null, extraLog: [], hashes: new Map(),
  };
  if (s.mode === "partitions" && s.state === "done") s.partitions = partitionReport(res, true);
  s.probe = probeOf(s);
  sessions.set(s.id, s);
  return s;
}

function ensureSeed() {
  if (sessions.size || ensureSeed.done) return;
  ensureSeed.done = true;
  const mk = (id, letter, mode, state, t, created, nFs, nCarved, extra = {}) => {
    const v = VOL_DEFS[letter];
    const res = resolveSource({ kind: "volume", path: letter, offset: 0, length: null, label: null });
    const spec = { ...specFor(res, mode, id), nFs, nCarved, ...extra };
    return makeSession({
      id, label: `${v.label || "Unnamed"} (${letter}:)`, mode, state, t, created, updated: created + 4 * 60000, res, spec, dupesDone: extra.dupesDone,
      source: { kind: "volume", path: letter, offset: 0, length: null, label: null },
    });
  };
  mk("s-9a41c7d2", "F", "deep", "done", 1, NOW - 3 * DAY - 5 * 3600000, 1500, 900, { dupesDone: true });
  mk("s-3be0f518", "C", "quick", "done", 1, NOW - 2 * 3600000 - 14 * 60000, 1800, 0);
  mk("s-c2d77e06", "E", "deep", "interrupted", 0.12 + 0.04 + 0.65 * 0.46, NOW - 9 * DAY - 2 * 3600000, 1425, 160);
}

const getSession = (id) => {
  ensureSeed();
  const s = sessions.get(id);
  if (!s) throw "That scan session no longer exists. Pick another one from the list.";
  return s;
};

/* progress → what is visible */

function progressInfo(s) {
  const plan = PLAN[s.mode];
  const keys = plan.map((p) => p[0]);
  const t = clamp(s.t, 0, 1);
  let idx = plan.length - 1;
  let frac = 1;
  if (t < 1) {
    let cum = 0;
    for (let i = 0; i < plan.length; i++) {
      if (t < cum + plan[i][1]) {
        idx = i;
        frac = (t - cum) / plan[i][1];
        break;
      }
      cum += plan[i][1];
    }
  }
  const sweepIdx = keys.indexOf("sweep");
  const condIdx = keys.indexOf("condition");
  const L = s.geo.L;
  const done = t >= 1;
  let sweepPos = null;
  if (s.mode === "deep") sweepPos = idx < sweepIdx ? 0 : idx === sweepIdx ? Math.floor((frac * L) / (4 * MiB)) * 4 * MiB : L;
  else if (s.mode === "partitions") sweepPos = done ? L : Math.floor((frac * L) / (4 * MiB)) * 4 * MiB;
  const ncFrac = s.mode === "partitions" ? 0 : idx === 0 ? frac * 0.85 : idx === 1 ? 0.85 + 0.15 * frac : 1;
  const carvedFrac = s.mode === "deep" ? (idx < sweepIdx ? 0 : idx === sweepIdx ? frac : 1) : 0;
  const visA = Math.round(s.nc * ncFrac);
  const visB = Math.round(s.carvedN * carvedFrac);
  const assessFrac = condIdx < 0 ? 0 : idx < condIdx ? 0 : idx === condIdx ? frac : 1;
  return { t, idx, frac, key: keys[idx], keys, sweepPos, fsFrac: idx === 0 ? frac : 1, visA, visB, assessed: Math.floor(assessFrac * (visA + visB)), done };
}

function visible(s) {
  const p = progressInfo(s);
  const key = `${p.visA}|${p.visB}|${p.assessed}`;
  if (s._vk === key) return s._v;
  let arr = s.all.slice(0, p.visA).concat(s.all.slice(s.nc, s.nc + p.visB));
  if (p.assessed < arr.length) {
    arr = arr.map((f, i) => (i < p.assessed ? f : { ...f, condition: "unknown", note: "Not checked yet.", flags: f.flags & ~(32 | 64) }));
  }
  s._vk = key;
  s._v = arr;
  return arr;
}

/* Recovery Map layers */

function layers(s) {
  const p = progressInfo(s);
  const g = s.geo;
  const L = g.L;
  const sweep = p.sweepPos ?? 0;
  const metaLim = s.mode === "partitions" ? 0 : L * p.fsFrac;
  const key = `${p.visA}|${p.visB}|${Math.floor(sweep / MiB)}|${Math.floor(metaLim / MiB)}|${s.mode}`;
  if (s._lk === key) return s._l;
  const fpairs = [];
  for (const f of visible(s)) if (f.status !== "existing") for (const e of f.extents) fpairs.push([e.offset, e.offset + e.len]);
  const filesIv = new Iv(fpairs);
  const metaL = limited(g.meta, metaLim);
  const allocL = limited(g.alloc, metaLim);
  const remL = limited(g.rem, s.mode === "deep" ? sweep : 0);
  const badL = limited(g.bad, s.mode === "quick" ? 0 : sweep);
  const rec = new Iv(fpairs.concat(remL.clip(0, L)));
  let scanned;
  if (s.mode === "quick") scanned = new Iv(metaL.clip(0, L).concat(fpairs));
  else if (s.mode === "deep") scanned = new Iv([[0, sweep]].concat(metaL.clip(0, L), fpairs));
  else scanned = new Iv([[0, sweep]]);
  const l = { scanned, meta: metaL, alloc: allocL, rec, bad: badL, filesIv };
  s._lk = key;
  s._l = l;
  return l;
}
const layerList = (l) => [l.scanned, l.meta, l.alloc, l.rec, l.bad];

function mapCells(s, start, end, cells) {
  const L = s.geo.L;
  start = clamp(Math.floor(start ?? 0), 0, L - 1);
  end = clamp(Math.floor(end ?? L), start + 1, L);
  cells = clamp(Math.floor(cells || 1024), 1, 65536);
  const span = end - start;
  const cellBytes = Math.max(512, Math.ceil(span / cells / 512) * 512);
  const n = Math.ceil(span / cellBytes);
  const ls = layerList(layers(s));
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    const a = start + i * cellBytes;
    const b = Math.min(end, a + cellBytes);
    let bits = 0;
    for (let k = 0; k < 5; k++) if (ls[k].hits(a, b)) bits |= 1 << k;
    out[i] = bits;
  }
  return { start, end, cellBytes, cells: b64(out), sourceLen: L, totals: ls.map((x) => Math.round(x.bytes(start, end))) };
}

/* rows and queries */

function rowOf(f, s) {
  return {
    id: f.id, name: f.name, folder: f.folder, size: f.size, typeId: f.typeId, category: f.category, status: f.status, origin: f.origin, condition: f.condition,
    note: f.note, created: f.created, modified: f.modified, deleted: f.deleted, fragmented: f.fragmented, flags: f.flags, dupGroup: s.dupesDone ? f.dupGroup : null, meta: f.meta,
  };
}

function normFolder(p) {
  let x = String(p ?? "").replace(/\//g, "\\");
  if (!x.startsWith("\\")) x = "\\" + x;
  if (x.length > 1) x = x.replace(/\\+$/, "");
  return x || "\\";
}

function makePred(q, s, withFolder = true) {
  q = q || {};
  const folder = withFolder && q.folder != null ? normFolder(q.folder) : null;
  const rec = q.recursive === true;
  const cats = q.categories?.length ? new Set(q.categories) : null;
  const types = q.typeIds?.length ? new Set(q.typeIds) : null;
  const sts = q.statuses?.length ? new Set(q.statuses) : null;
  const conds = q.conditions?.length ? new Set(q.conditions) : null;
  const field = q.dateField === "created" || q.dateField === "deleted" ? q.dateField : "modified";
  let search = null;
  const raw = (q.search || "").trim().toLowerCase();
  if (raw) {
    if (/[*?]/.test(raw)) {
      const re = new RegExp("^" + raw.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$", "i");
      search = (f) => re.test(f.name);
    } else if (raw.startsWith(".")) search = (f) => f._ext === raw.slice(1);
    else search = (f) => f._nk.includes(raw);
  }
  return (f) => {
    if (folder != null) {
      const ff = f.folder;
      if (folder === "\\") {
        if (!rec && ff !== "\\") return false;
      } else if (rec ? !(ff === folder || ff.startsWith(folder + "\\")) : ff !== folder) return false;
    }
    if (cats && !cats.has(f.category)) return false;
    if (types && !types.has(f.typeId)) return false;
    if (sts && !sts.has(f.status)) return false;
    if (conds && !conds.has(f.condition)) return false;
    if (q.minSize != null && f.size < q.minSize) return false;
    if (q.maxSize != null && f.size > q.maxSize) return false;
    if (q.dateFrom != null || q.dateTo != null) {
      const d = f[field];
      if (d == null) return false;
      if (q.dateFrom != null && d < q.dateFrom) return false;
      if (q.dateTo != null && d > q.dateTo) return false;
    }
    if (q.duplicatesOnly && !(s.dupesDone && f.dupGroup)) return false;
    if (search && !search(f)) return false;
    return true;
  };
}

function sortFiles(arr, q) {
  const key = q?.sort || "name";
  const dir = q?.desc ? -1 : 1;
  const cmpStr = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  const val = {
    name: (a, b) => cmpStr(a._nk, b._nk),
    size: (a, b) => a.size - b.size,
    modified: (a, b) => (a.modified ?? -1) - (b.modified ?? -1),
    created: (a, b) => (a.created ?? -1) - (b.created ?? -1),
    deleted: (a, b) => (a.deleted ?? -1) - (b.deleted ?? -1),
    condition: (a, b) => CRANK[a.condition] - CRANK[b.condition],
    type: (a, b) => cmpStr(a.typeId, b.typeId),
    folder: (a, b) => cmpStr(a.folder.toLowerCase(), b.folder.toLowerCase()),
  }[key] || ((a, b) => cmpStr(a._nk, b._nk));
  return arr.sort((a, b) => dir * val(a, b) || a.id - b.id);
}
const CRANK = { excellent: 0, good: 1, unknown: 2, partial: 3 };

function matches(s, q) {
  return visible(s).filter(makePred(q, s));
}

function folderChildren(s, parent, q) {
  const par = normFolder(parent);
  const pred = makePred(q, s, false);
  const prefix = par === "\\" ? "\\" : par + "\\";
  const kids = new Map();
  for (const f of visible(s)) {
    if (!pred(f)) continue;
    const ff = f.folder;
    if (ff === par || !(par === "\\" ? ff.length > 1 : ff.startsWith(prefix))) continue;
    const rest = ff.slice(prefix.length);
    const seg = rest.split("\\")[0];
    let k = kids.get(seg);
    if (!k) kids.set(seg, (k = { path: prefix + seg, name: seg, files: 0, size: 0, hasChildren: false }));
    k.files++;
    k.size += f.size;
    if (rest.length > seg.length) k.hasChildren = true;
  }
  return [...kids.values()].sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
}

function hashOf(s, f) {
  if (!(f.dupGroup || f.id % 4 === 0)) return null;
  const key = f.dupGroup ? "g" + f.dupGroup + s.id : "f" + f.id + s.id;
  const r = rng(key);
  return randHex(r, 64);
}

/* summaries, stages, notes, log */

function foldersOf(files) {
  const set = new Set();
  for (const f of files) set.add(f.folder);
  return set.size;
}

function summaryOf(s) {
  const vis = visible(s);
  let bytes = 0;
  for (const f of vis) bytes += f.size;
  const p = progressInfo(s);
  const l = layers(s);
  const scannedBytes = s.mode === "quick" ? Math.round(l.scanned.total()) : Math.round(p.sweepPos ?? 0);
  return {
    id: s.id, label: s.label, source: s.source, mode: s.mode, state: s.state, created: s.created, updated: s.updated, files: vis.length, bytes,
    scannedBytes, sourceLen: s.geo.L, badBytes: Math.round(l.bad.bytes(0, s.geo.L)), fileSize: 180000 + vis.length * 640,
  };
}

function stagesOf(s) {
  const p = progressInfo(s);
  const vis = visible(s);
  const fsFiles = vis.filter((f) => !f._carved);
  const skipBin = !(s.res.kind === "volume" || s.res.kind === "snapshot") || !s.res.fsKnown;
  return p.keys.map((key, i) => {
    let st;
    if (s.state === "done") st = key === "recyclebin" && skipBin ? "skipped" : "done";
    else if (i < p.idx) st = key === "recyclebin" && skipBin ? "skipped" : "done";
    else if (i === p.idx) st = s.state === "failed" ? "failed" : s.state === "interrupted" ? "interrupted" : s.state === "cancelled" ? "pending" : "running";
    else st = "pending";
    let note = null;
    if (key === "filesystem" && (st === "done" || st === "running")) note = !s.res.fsKnown ? "No file system was recognised. Run a deep scan." : `Found ${fmtNum(fsFiles.length)} files in ${foldersOf(fsFiles)} folders.`;
    if (key === "recyclebin" && st === "done") note = `${fmtNum(fsFiles.filter((f) => f.status === "recycleBin").length)} items in the Recycle Bin.`;
    if (key === "sweep" && (st === "done" || st === "interrupted")) note = st === "done" ? `Read ${humanSize(s.geo.L)} and found ${fmtNum(vis.length - fsFiles.length)} files by their content.` : `Stopped at ${Math.round((p.sweepPos / s.geo.L) * 100)}%. Resume to continue.`;
    if (key === "rebuild" && st === "done") note = `Rebuilt ${foldersOf(fsFiles)} folders.`;
    if (key === "condition" && st === "done") note = `Checked ${fmtNum(vis.length)} files.`;
    if (key === "partitions" && st === "done") note = s.partitions ? `Found ${s.partitions.entries.filter((e) => e.status === "lost").length} partition(s) that aren't in the table.` : null;
    return { key, label: STAGE_LABEL[key], state: st, note };
  });
}

function notesOf(s) {
  const n = [];
  const L = s.geo.L;
  if (s.res.ssd && state.ssdTrim && s.mode !== "partitions") {
    n.push("This drive is an SSD with TRIM turned on, so Windows may already have erased the contents of some deleted files. Files marked \"unknown\" may only contain zeros.");
    if (s.res.letter === "C") n.push("Recover to a different drive. Writing to this one could overwrite what is left.");
  }
  if (s.res.profile === "sd" && s.mode === "deep") n.push("The card was formatted after these files were deleted, so many were found by their content rather than by name.");
  if (!s.res.fsKnown && s.mode !== "partitions") n.push("No file system was recognised on this drive. Files are found by their content, so folder names and dates are not available.");
  if (s.state === "interrupted") n.push(`The scan stopped at ${Math.round(((progressInfo(s).sweepPos ?? 0) / L) * 100)}%. Resume it to read the rest of the drive.`);
  const bad = Math.round(layers(s).bad.bytes(0, L));
  if (bad) n.push(`${fmtNum(bad / 4096)} unreadable clusters (${humanSize(bad)}) were skipped. This drive reports failing sectors, so make an image of it before scanning it again.`);
  if (s.mode === "partitions" && s.partitions) n.push(s.partitions.notes[0] || "");
  return n.filter(Boolean);
}

function countsOf(s) {
  const c = { byCategory: {}, byStatus: {}, byCondition: {} };
  const add = (m, k, size) => {
    const e = (m[k] ||= [0, 0]);
    e[0]++;
    e[1] += size;
  };
  for (const f of visible(s)) {
    add(c.byCategory, f.category, f.size);
    add(c.byStatus, f.status, f.size);
    add(c.byCondition, f.condition, f.size);
  }
  return c;
}

function logOf(s) {
  const out = [];
  let at = s.created;
  const add = (level, message, dt = 700) => {
    at += dt;
    out.push({ at, level, message });
  };
  const p = progressInfo(s);
  const vis = visible(s);
  const fsN = vis.filter((f) => !f._carved).length;
  add("info", `Opened ${s.source.path} read-only (${humanSize(s.geo.L)}).`);
  if (s.mode === "partitions") {
    add("info", "Searching every 1 MiB boundary for NTFS, FAT and exFAT boot sectors.");
    if (s.state === "done") add("info", s.partitions?.notes[0] || "Finished.");
  } else if (s.res.fsKnown) {
    add("info", `${s.res.fs} volume recognised: ${s.spec.cluster} byte clusters, label "${s.res.volLabel}".`);
    if (p.idx > 0 || s.state === "done") add("info", `Read the file records. Found ${fmtNum(fsN)} files that can be recovered.`, 2400);
  } else add("warn", "No file system was recognised. Run a deep scan.");
  if (p.keys.includes("sweep") && (p.idx >= 2 || s.state === "done")) {
    add("info", "Started the sector sweep (4 MiB chunks).", 600);
    if (s.geo.bad.length && p.sweepPos > 0) add("warn", `Could not read ${fmtNum(layers(s).bad.bytes(0, s.geo.L) / 512)} sectors; they were filled with zeros and marked as bad.`, 4000);
    if (s.state === "interrupted") add("warn", "MAX was closed while the scan was running. The sweep position was saved.", 3000);
  }
  if (s.state === "done") add("info", `Finished. ${fmtNum(vis.length)} files found.`, 3000);
  if (s.state === "failed") add("error", s.error || "The scan failed.", 1500);
  if (s.state === "cancelled") add("warn", "The scan was cancelled.", 1500);
  return out.concat(s.extraLog);
}

/* ───────────────────────────── partitions ───────────────────────────── */

function partitionReport(res, withLost) {
  let parts, style, size;
  if (res.kind === "disk") {
    const d = DISK_DEFS[res.disk];
    style = d.partitionStyle;
    size = d.size;
    parts = d.parts.map((p) => ({ ...p }));
  } else if (res.kind === "image") {
    style = res.image.partitionStyle;
    size = res.image.size;
    parts = res.image.partitions.map((p) => ({ ...p }));
  } else {
    return { style: "None", sectorSize: 512, diskSize: res.len, entries: [], gpt: null, unallocated: [], notes: ["This is a single volume, so it has no partition table."] };
  }
  const entries = parts.map((p) => ({
    offset: p.offset, size: p.size, fs: p.fs || null, label: p.label || null, typeName: p.typeName, status: "ok", foundBy: style === "GPT" ? "gpt" : "mbr", number: p.number, note: "",
  }));
  const notes = [];
  if (style === "GPT") notes.push("The primary and backup GPT are both intact.");
  if (withLost && res.kind === "disk" && res.disk === 1) {
    entries.push({ offset: LOST_OFFSET, size: LOST_SIZE, fs: "NTFS", label: null, typeName: "Basic data", status: "lost", foundBy: "bootSector", number: null,
      note: "Found by its NTFS boot sector. It isn't in the partition table, so Windows doesn't show it." });
    notes.unshift("Found 1 partition that isn't in the partition table (NTFS, 120 GB). Scan it to look for its files.");
  } else if (withLost) notes.unshift("No lost partitions were found.");
  const cover = new Iv(entries.map((e) => [e.offset, e.offset + e.size]));
  const unallocated = cover.gaps(0, size).filter((g) => g[1] - g[0] >= 16 * MiB);
  if (!withLost && res.kind === "disk" && res.disk === 1 && unallocated.length) notes.push(`About ${humanSize(unallocated.reduce((a, g) => a + g[1] - g[0], 0))} of this disk isn't in any partition. A deleted partition may be hiding there; run a partition search.`);
  return { style, sectorSize: 512, diskSize: size, entries, gpt: style === "GPT" ? { primaryOk: true, backupOk: true } : null, unallocated, notes };
}

/* ───────────────────────────── scan engine ───────────────────────────── */

function emitProgress(s, stateName) {
  const p = progressInfo(s);
  const run = s.run;
  const L = s.geo.L;
  const vis = visible(s);
  const noise = 0.92 + 0.16 * mulberry32(run.job * 977 + Math.floor(p.t * 400))();
  const nominal = s.mode === "deep" ? L / s.res.bps + 45 : s.mode === "partitions" ? L / s.res.bps * 0.4 + 20 : 40;
  let done, total;
  const k = p.key;
  if (k === "sweep" || k === "partitions") [done, total] = [p.sweepPos, L];
  else if (k === "filesystem") [done, total] = [Math.round(p.frac * (s.nc || 1)), s.nc || 1];
  else if (k === "recyclebin") [done, total] = [Math.round(p.frac * 120), 120];
  else if (k === "rebuild") [done, total] = [Math.round(p.frac * 40), 40];
  else [done, total] = [Math.round(p.frac * vis.length), Math.max(vis.length, 1)];
  const sweeping = k === "sweep" || k === "partitions";
  emit("scan-progress", {
    sessionId: s.id, job: run.job, state: stateName, stage: k, stageLabel: STAGE_LABEL[k], stageIndex: p.idx, stageCount: p.keys.length, done, total,
    filesFound: k === "partitions" ? (p.frac > 0.7 && s.res.disk === 1 ? 1 : 0) : vis.length,
    bytesPerSec: stateName === "paused" ? 0 : Math.round((sweeping ? s.res.bps : Math.min(s.res.bps, 3e7)) * noise),
    etaSeconds: stateName === "paused" ? null : Math.max(1, Math.round((1 - p.t) * nominal)),
    badBytes: Math.round(layers(s).bad.bytes(0, L)), sweepPos: p.sweepPos ?? undefined, ...(run.stopping ? { stopping: true } : {}),
  });
}

function startRun(s) {
  const job = ++jobSeq;
  s.job = job;
  const D = (DURATION[s.mode] * (state.slowScan ? 4 : 1)) / Math.max(0.01, state.speed);
  if (s.t >= 1) s.t = 0;
  const run = { job, D, paused: false, last: Date.now(), fail: state.failScan, timer: null };
  s.run = run;
  s.state = "running";
  s.error = null;
  run.timer = setInterval(() => tick(s), Math.max(15, 250 / Math.max(0.01, state.speed)));
  return job;
}

function tick(s) {
  const run = s.run;
  if (!run) return;
  const now = Date.now();
  const dt = now - run.last;
  run.last = now;
  if (!run.paused && !run.stopping) s.t = Math.min(1, s.t + dt / run.D);
  s.updated = now;
  if (run.fail && s.t >= 0.3) return finishRun(s, "failed", "MAX lost contact with the drive. Check the cable or card reader, then run the scan again.");
  if (s.t >= 1) return finishRun(s, "done");
  emitProgress(s, run.paused ? "paused" : "running");
}

function finishRun(s, st, error) {
  const run = s.run;
  if (!run) return;
  clearInterval(run.timer);
  s.run = null;
  s.state = st;
  s.error = error || null;
  s.updated = Date.now();
  if (st === "done") {
    s.t = 1;
    if (s.mode === "partitions") s.partitions = partitionReport(s.res, true);
  }
  emit("scan-done", { sessionId: s.id, job: run.job, state: st, error: error || undefined, files: visible(s).length });
}

function checkScanAllowed(res) {
  if ((res.kind === "volume" || res.kind === "disk") && res.kind !== "snapshot") needAdmin();
  if (res.locked) throw LOCKED_MSG;
}

function newSessionFromSource(source, options) {
  const res = resolveSource(source);
  checkScanAllowed(res);
  const mode = ["quick", "deep", "partitions"].includes(options?.mode) ? options.mode : "quick";
  const id = "s-" + hex(fnv(JSON.stringify(source) + mode + ++sessionSeq + Date.now()), 8).toLowerCase();
  const word = { quick: "Quick scan", deep: "Deep scan", partitions: "Partition search" }[mode];
  const folder = mode === "quick" && source.kind === "volume" && options?.folder ? options.folder : null;
  const label = options?.label || (folder ? `${res.letter}:${folder}` : res.label);
  const s = makeSession({
    id, label, mode, state: "running", t: 0, created: Date.now(), res, source: { ...source, label: source.label ?? res.label },
    options: { mode, includeExisting: options?.includeExisting ?? null, carveTypes: options?.carveTypes ?? null, carveFreeOnly: options?.carveFreeOnly ?? null, customSignatures: options?.customSignatures ?? null, label: options?.label ?? null, folder },
  });
  s.label = label;
  s.word = word;
  return s;
}

/* ───────────────────────────── file content ───────────────────────────── */

const enc = new TextEncoder();
const ascii = (s) => enc.encode(s);
const PARAS = [
  "Thank you for your message. I have attached the updated figures for the quarter and highlighted the lines that changed since the last version.",
  "The meeting is scheduled for Thursday at 10:30 in the small conference room. Please bring your notes and the signed forms.",
  "Total monthly outgoings come to roughly 2,140, of which 1,150 is rent and 310 is groceries. The remainder covers utilities, transport and subscriptions.",
  "We agreed to move the launch by two weeks so that the testing can finish. Ann will confirm the new date with the supplier on Monday.",
  "Ingredients: 250 g flour, 2 eggs, 300 ml milk, a pinch of salt, butter for the pan. Whisk until smooth and rest the batter for half an hour.",
  "Please find the signed agreement enclosed. The deposit was paid on the first of the month and the receipt is attached for your records.",
  "Next steps: collect quotes from three contractors, compare the schedules, and book the survey before the end of the month.",
  "The garden plan includes raised beds along the south fence, a compost bay by the shed, and a small pond near the patio.",
  "Draft conclusion: the results suggest a modest but consistent improvement, although the sample is too small to be certain.",
];
function textFor(f) {
  const r = rng("txt:" + f.id);
  const t = f.meta.title || f.name.replace(/\.[^.]+$/, "");
  const lines = [t, "=".repeat(Math.min(40, t.length)), "Prepared by Ann Miller", ""];
  for (let i = 0; i < 9; i++) lines.push(r.pick(PARAS), "");
  return lines.join("\r\n");
}

function headerBytes(f) {
  const h = new Uint8Array(512);
  const r = rng("hdr:" + f.id);
  for (let i = 0; i < 512; i++) h[i] = Math.floor(r.f() * 256);
  const put = (at, arr) => h.set(typeof arr === "string" ? ascii(arr) : arr, at);
  const t = f.typeId;
  if (t === "jpg") {
    put(0, [0xff, 0xd8, 0xff, 0xe1, 0x1f, 0xfe]);
    put(6, "Exif\0\0");
    put(12, [0x49, 0x49, 0x2a, 0, 8, 0, 0, 0, 0x0b, 0]);
    put(0x40, "Canon\0");
    put(0x60, (f.meta.camera || "Canon EOS R6") + "\0");
    put(0x90, (f.meta.taken || "2024:05:01 14:22:10").replace(/-/g, ":") + "\0");
    put(0x120, [0xff, 0xdb, 0x00, 0x43, 0x00]);
  } else if (t === "png") {
    put(0, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d]);
    put(12, "IHDR");
  } else if (t === "pdf") put(0, "%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
  else if (["docx", "xlsx", "pptx", "zip", "odt", "ods"].includes(t)) {
    put(0, [0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0x06, 0, 0x08, 0, 0, 0]);
    put(30, t === "zip" ? "archive/readme.txt" : "[Content_Types].xml");
  } else if (["mp4", "mov", "cr3", "heic", "m4a"].includes(t)) {
    put(0, [0, 0, 0, 0x20]);
    put(4, t === "cr3" ? "ftypcrx " : t === "mov" ? "ftypqt  " : t === "heic" ? "ftypheic" : t === "m4a" ? "ftypM4A " : "ftypmp42");
  } else if (t === "mp3") put(0, [0x49, 0x44, 0x33, 0x03, 0, 0, 0, 0, 0x0f, 0x76]);
  else if (t === "gif") put(0, "GIF89a");
  else if (t === "exe" || t === "dll" || t === "msi") put(0, "MZ\x90\0\x03\0\0\0\x04\0\0\0\xff\xff\0\0");
  else if (t === "sqlite") put(0, "SQLite format 3\0");
  else if (t === "rar") put(0, [0x52, 0x61, 0x72, 0x21, 0x1a, 7, 0]);
  else if (t === "7z") put(0, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]);
  else if (t === "iso") put(0, "");
  return h;
}
const TEXT_TYPES = new Set(["txt", "csv", "html", "xml", "rtf", "eml"]);

function fileBytes(f, off, len) {
  const size = f.size;
  len = Math.max(0, Math.min(len, size - off));
  const out = new Uint8Array(len);
  if (!len || f.flags & 32) return out;
  const text = TEXT_TYPES.has(f.typeId) ? ascii(textFor(f)) : null;
  const head = text ? null : headerBytes(f);
  let blockNo = -1;
  let block = null;
  const cut = f.condition === "partial" ? Math.floor(size * 0.7) : size;
  for (let i = 0; i < len; i++) {
    const pos = off + i;
    if (pos >= cut) break;
    if (text) {
      out[i] = text[pos % text.length];
      continue;
    }
    if (pos < 512) {
      out[i] = head[pos];
      continue;
    }
    const b = pos >> 9;
    if (b !== blockNo) {
      blockNo = b;
      const r = mulberry32(fnv(f.id + ":" + b));
      block = new Uint8Array(512);
      for (let k = 0; k < 512; k++) block[k] = Math.floor(r() * 256);
    }
    out[i] = block[pos & 511];
  }
  return out;
}

function fileOf(s, id) {
  const idx = Number(id) - 1;
  const p = progressInfo(s);
  const ok = Number.isInteger(idx) && idx >= 0 && (idx < p.visA || (idx >= s.nc && idx < s.nc + p.visB));
  if (!ok) throw "That file isn't part of this scan.";
  return visible(s)[idx < s.nc ? idx : p.visA + (idx - s.nc)];
}

const PREVIEW_KIND = { photo: "image", video: "video", audio: "audio", document: "document", archive: "hex", other: "hex" };

function inspectOf(s, f) {
  const bytes = fileBytes(f, 0, 64);
  const headerHex = [...bytes].map((b) => hex(b, 2)).join(" ");
  const ty = TY[f.typeId];
  const e = extOf(f.name);
  const extType = TY_BY_EXT[e]?.id || null;
  const m = f.meta;
  const fields = [["Format", ty.label]];
  if (f.typeId === "jpg") fields[0][1] = "JPEG (Exif)";
  if (m.width) fields.push(["Dimensions", `${m.width} × ${m.height}`]);
  if (m.camera) fields.push(["Camera", m.camera]);
  if (m.taken) fields.push(["Taken", m.taken]);
  if (m.duration) fields.push(["Duration", m.duration]);
  if (m.artist) fields.push(["Artist", m.artist]);
  if (m.title) fields.push([f.category === "audio" ? "Track" : "Title", m.title]);
  if (m.pages) fields.push(["Pages", m.pages]);
  if (m.author) fields.push(["Author", m.author]);
  if (f.typeId === "pdf") fields.push(["PDF version", "1.7"]);
  if (["mp4", "mov", "cr3"].includes(f.typeId)) fields.push(["Brand", f.typeId === "cr3" ? "crx" : f.typeId === "mov" ? "qt" : "mp42"]);
  if (["zip", "docx", "xlsx", "pptx"].includes(f.typeId)) fields.push(["Entries", String(f.typeId === "zip" ? 14 + (f.id % 40) : 9 + (f.id % 6))]);
  let validation;
  if (f.flags & 32) validation = { condition: "unknown", note: "The first sectors are all zeros, so there is nothing to check.", complete: false };
  else if (f.condition === "excellent") validation = { condition: "excellent", note: "The whole file decodes without errors.", complete: true };
  else if (f.condition === "good") validation = { condition: "good", note: "The file decodes, but it is stored in several pieces.", complete: true };
  else if (f.condition === "partial") validation = { condition: "partial", note: "The file stops early. About 70% of it can be shown.", complete: false };
  else validation = { condition: "unknown", note: "This file type can't be checked.", complete: true };
  return {
    detectedType: f.typeId, detectedLabel: ty.label, extType, mismatch: !!(f.flags & 8) || (extType != null && extType !== f.typeId && !ty.exts.includes(e)), headerHex, fields,
    validation, meta: f.meta, previewKind: PREVIEW_KIND[f.category] || "hex", badSectors: !!(f.flags & 128),
  };
}

function previewOf(s, f) {
  const r = rng("prev:" + s.id + f.id);
  if (["xlsx", "xls", "ods", "csv"].includes(f.typeId)) {
    const cats = ["Rent", "Groceries", "Utilities", "Transport", "Insurance", "Subscriptions", "Savings", "Eating out", "Health", "Clothing", "Gifts", "Other"];
    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun"];
    const rows = [["Category", ...months, "Total"]];
    for (const c of cats) {
      const base = c === "Rent" ? 1150 : r.int(30, 380);
      const vals = months.map(() => Math.round(base * (0.9 + r.f() * 0.25)));
      rows.push([c, ...vals.map(String), String(vals.reduce((a, b) => a + b, 0))]);
    }
    const sheets = [{ name: f.typeId === "csv" ? "Sheet1" : "Summary", rows }];
    if (f.typeId !== "csv") {
      const det = [["Date", "Description", "Amount"]];
      for (let i = 0; i < 18; i++) det.push([`2024-0${r.int(1, 6)}-${pad2(r.int(1, 28))}`, r.pick(["Tesco", "Council tax", "Gas & electric", "Train ticket", "Spotify", "Pharmacy", "Pizza Express", "Water bill"]), (r.f() * 220 + 5).toFixed(2)]);
      sheets.push({ name: "Details", rows: det });
    }
    return { kind: "sheet", text: null, sheets, truncated: false };
  }
  if (["docx", "pdf", "txt", "doc", "rtf", "odt", "html", "eml", "pptx"].includes(f.typeId)) {
    const text = textFor(f).split("\r\n").slice(0, 22).join("\n");
    return { kind: "text", text, sheets: [], truncated: f.size > 20000 };
  }
  return { kind: "none", text: null, sheets: [], truncated: false };
}

/* ───────────────────────────── raw sectors ───────────────────────────── */

function le(n, bytes) {
  const out = [];
  for (let i = 0; i < bytes; i++) out.push(Math.floor(n / 2 ** (8 * i)) & 0xff);
  return out;
}
function bootSector(fs, partSize, hidden) {
  const b = new Uint8Array(512);
  const put = (at, a) => b.set(typeof a === "string" ? ascii(a) : a, at);
  if (fs === "NTFS") {
    put(0, [0xeb, 0x52, 0x90]);
    put(3, "NTFS    ");
    put(11, [0x00, 0x02, 0x08, 0, 0, 0, 0, 0, 0, 0xf8, 0, 0, 0x3f, 0, 0xff, 0]);
    put(28, le(hidden / 512, 4));
    put(36, [0x80, 0, 0x80, 0]);
    put(40, le(partSize / 512 - 1, 8));
    put(48, le(786432, 8));
    put(56, le(2, 8));
    put(64, [0xf6, 0, 0, 0, 1, 0, 0, 0]);
    put(72, [0x4a, 0x1c, 0x9e, 0x27, 0xb3, 0xd0, 0x5f, 0x68]);
    put(0x54, [0x33, 0xc0, 0x8e, 0xd0, 0xbc, 0x00, 0x7c]);
    put(0x15a, "A disk read error occurred\r\n");
  } else if (fs === "exFAT") {
    put(0, [0xeb, 0x76, 0x90]);
    put(3, "EXFAT   ");
    put(64, le(hidden / 512, 8));
    put(72, le(partSize / 512, 8));
    put(80, le(2048, 4));
    put(84, le(Math.round(partSize / 131072 / 8), 4));
    put(88, le(8192, 4));
    put(96, le(4, 4));
    put(100, [0x07, 0x1e, 0xd4, 0xb7, 0x00, 0x01, 0x09, 0x08, 0x01]);
  } else if (fs === "FAT32") {
    put(0, [0xeb, 0x58, 0x90]);
    put(3, "MSDOS5.0");
    put(11, [0x00, 0x02, 0x40, 0x20, 0x00, 0x02]);
    put(82, "FAT32   ");
  } else return null;
  b[510] = 0x55;
  b[511] = 0xaa;
  return b;
}

function mbrSector(parts, style) {
  const b = new Uint8Array(512);
  b.set([0x33, 0xc0, 0x8e, 0xd0, 0xbc, 0x00, 0x7c, 0x8e, 0xc0, 0x8e, 0xd8, 0xbe, 0x00, 0x7c, 0xbf, 0x00, 0x06, 0xb9, 0x00, 0x02, 0xfc, 0xf3, 0xa4], 0);
  b.set([0x5d, 0x31, 0x9a, 0x6e], 440);
  const list = style === "GPT" ? [{ type: 0xee, off: 512, size: 0xffffffff, boot: 0 }] : parts.slice(0, 4).map((p, i) => ({ type: p.fs === "NTFS" ? 0x07 : p.fs === "exFAT" ? 0x07 : p.fs === "FAT32" ? 0x0c : 0x07, off: p.offset, size: p.size, boot: i === 0 ? 0x80 : 0 }));
  list.forEach((p, i) => {
    const at = 446 + i * 16;
    b.set([p.boot, 0xfe, 0xff, 0xff, p.type, 0xfe, 0xff, 0xff, ...le(p.off / 512, 4), ...le(Math.min(p.size / 512, 0xffffffff), 4)], at);
  });
  b[510] = 0x55;
  b[511] = 0xaa;
  return b;
}

function sectorBlock(res, abs) {
  // abs: byte offset (512-aligned) on the underlying disk/volume/image
  const style = res.diskStyle || res.image?.partitionStyle || null;
  const parts = res.partitions?.length ? res.partitions : res.image?.partitions || [];
  if (res.kind === "disk" || res.kind === "image") {
    if (abs === 0 && (style === "MBR" || style === "GPT")) return mbrSector(parts, style);
    if (abs === 512 && style === "GPT") {
      const b = new Uint8Array(512);
      b.set(ascii("EFI PART"), 0);
      b.set([0, 0, 1, 0, 0x5c, 0, 0, 0], 8);
      b.set(le(1, 8), 24);
      b.set(le(res.len / 512 - 1, 8), 32);
      b.set(le(128, 4), 80);
      b.set(le(128, 4), 84);
      return b;
    }
    const p = parts.find((q) => q.offset === abs);
    if (p) return bootSector(p.fs, p.size, p.offset) || null;
    if (res.lost && abs === LOST_OFFSET) return bootSector("NTFS", LOST_SIZE, LOST_OFFSET);
    if (res.kind === "disk" && res.disk === 1 && abs === LOST_OFFSET) return bootSector("NTFS", LOST_SIZE, LOST_OFFSET);
    if (res.kind === "image" && !style && abs === 0) return bootSector(res.fs, res.len, 0);
    return null;
  }
  if (abs === 0) return bootSector(res.fs, res.len, res.diskOffset || 0) || (res.fs === "RAW" ? new Uint8Array(512) : null);
  if (res.fs === "NTFS" && abs >= 786432 * 4096 && abs < 786432 * 4096 + 8192 && (abs - 786432 * 4096) % 1024 === 0) {
    const b = new Uint8Array(512);
    b.set(ascii("FILE"), 0);
    b.set([0x30, 0, 3, 0], 4);
    b.set([0x38, 0, 0x01, 0], 20);
    return b;
  }
  return null;
}

function sectorData(res, offset, length) {
  const key = (res.ref.path || "") + "|" + res.window;
  const out = new Uint8Array(length);
  const first = Math.floor(offset / 512);
  const last = Math.floor((offset + length - 1) / 512);
  for (let bi = first; bi <= last; bi++) {
    const abs = bi * 512 + (res.kind === "volume" ? 0 : res.window);
    let blk = sectorBlock(res, abs);
    if (!blk) {
      const r = mulberry32(fnv(key + ":" + bi));
      const x = r();
      blk = new Uint8Array(512);
      if (x < 0.4) {
        /* free space reads as zeros */
      } else if (x < 0.52) {
        const line = `[${fmtDT(NOW - Math.floor(r() * 400) * DAY)}] ${["Session started", "Update applied", "Disk check passed", "Sync completed"][Math.floor(r() * 4)]}\r\n`;
        for (let k = 0; k < 512; k++) blk[k] = line.charCodeAt(k % line.length);
      } else for (let k = 0; k < 512; k++) blk[k] = Math.floor(r() * 256);
    }
    for (let k = 0; k < 512; k++) {
      const pos = bi * 512 + k - offset;
      if (pos >= 0 && pos < length) out[pos] = blk[k];
    }
  }
  return out;
}

/* ───────────────────────────── placeholder photos ───────────────────────────── */

const PALETTES = [
  { sky: ["#8fc3ee", "#f7e6cd"], sun: "#fff4c9", far: "#91b2cb", mid: "#5f8f7a", near: "#2f5d4b" },
  { sky: ["#2d3b6b", "#f0905f"], sun: "#ffd9a6", far: "#7a5a86", mid: "#473462", near: "#1f1a3a" },
  { sky: ["#cde6f5", "#ffffff"], sun: "#ffffff", far: "#b9c8d8", mid: "#8296ad", near: "#4d637c" },
  { sky: ["#f6d7a9", "#f0a58a"], sun: "#fff0cf", far: "#d08a7a", mid: "#9c5f61", near: "#59353f" },
  { sky: ["#a9d9c5", "#eaf4d8"], sun: "#fffbe0", far: "#7fb59a", mid: "#4d8a6d", near: "#27513f" },
  { sky: ["#1c2b44", "#34506a"], sun: "#e8eefc", far: "#2f4560", mid: "#1d2d45", near: "#0e1726" },
  { sky: ["#dac7f1", "#f7e3ef"], sun: "#fff7fb", far: "#b79ccf", mid: "#8c70ad", near: "#4f3c6e" },
  { sky: ["#b8d4e9", "#eaf0e1"], sun: "#fffdf0", far: "#9fb98c", mid: "#6f9461", near: "#3c5f3a" },
];
function ridge(r, y, amp, n) {
  const pts = [];
  for (let i = 0; i <= n; i++) pts.push([(i * 400) / n, y + (r.f() - 0.5) * 2 * amp]);
  let d = `M0,300 L0,${pts[0][1].toFixed(1)}`;
  for (let i = 1; i < pts.length; i++) {
    const mx = (pts[i - 1][0] + pts[i][0]) / 2;
    const my = (pts[i - 1][1] + pts[i][1]) / 2;
    d += ` Q${pts[i - 1][0].toFixed(1)},${pts[i - 1][1].toFixed(1)} ${mx.toFixed(1)},${my.toFixed(1)}`;
  }
  return d + ` L400,${pts[n][1].toFixed(1)} L400,300 Z`;
}
function artSvg(seed, kind, partial, w) {
  const r = rng("art:" + seed);
  const pal = r.pick(PALETTES);
  const h = Math.round((w * 3) / 4);
  let body = "";
  const comp = kind === "video" ? r.int(0, 1) : r.int(0, 3);
  const sunX = r.int(60, 340);
  const sunY = r.int(55, 130);
  body += `<rect width="400" height="300" fill="url(#sky)"/>`;
  if (kind === "video") {
    // bokeh lights over dark water / city
    body += `<rect width="400" height="300" fill="url(#vig)"/>`;
    for (let i = 0; i < 26; i++) {
      const c = r.pick([pal.sun, "#ffd27a", "#8fd3ff", "#ff9f80", "#ffffff"]);
      body += `<circle cx="${r.int(0, 400)}" cy="${r.int(70, 250)}" r="${r.int(5, 20)}" fill="${c}" opacity="${(0.12 + r.f() * 0.35).toFixed(2)}"/>`;
    }
    body += `<path d="${ridge(r, 220, 14, 14)}" fill="${pal.near}" opacity="0.9"/>`;
    for (let i = 0; i < 14; i++) body += `<rect x="${i * 30 + r.int(0, 18)}" y="${r.int(165, 200)}" width="${r.int(12, 26)}" height="90" fill="${pal.near}" opacity="0.85"/>`;
    body += `<rect y="0" width="400" height="34" fill="#000"/><rect y="266" width="400" height="34" fill="#000"/>`;
    body += `<circle cx="200" cy="150" r="22" fill="#000" opacity="0.38"/><path d="M193,138 L193,162 L214,150 Z" fill="#fff" opacity="0.85"/>`;
  } else {
    body += `<circle cx="${sunX}" cy="${sunY}" r="70" fill="url(#halo)"/><circle cx="${sunX}" cy="${sunY}" r="${r.int(14, 24)}" fill="${pal.sun}"/>`;
    for (let i = 0; i < r.int(2, 4); i++) {
      const cx = r.int(20, 380);
      const cy = r.int(30, 110);
      body += `<ellipse cx="${cx}" cy="${cy}" rx="${r.int(40, 80)}" ry="${r.int(7, 13)}" fill="#fff" opacity="${(0.25 + r.f() * 0.3).toFixed(2)}"/>`;
    }
    if (comp === 0 || comp === 2) {
      body += `<path d="${ridge(r, comp === 2 ? 150 : 175, comp === 2 ? 55 : 25, comp === 2 ? 8 : 10)}" fill="${pal.far}"/>`;
      if (comp === 2) body += `<path d="${ridge(r, 125, 30, 8)}" fill="#ffffff" opacity="0.35"/>`;
      body += `<path d="${ridge(r, 215, 22, 12)}" fill="${pal.mid}"/>`;
      body += `<path d="${ridge(r, 258, 14, 14)}" fill="${pal.near}"/>`;
      if (comp === 0) for (let i = 0; i < 9; i++) {
        const tx = r.int(10, 390);
        const ty = r.int(232, 270);
        body += `<path d="M${tx},${ty} l-9,26 h18 Z" fill="${pal.near}"/><path d="M${tx},${ty - 14} l-7,20 h14 Z" fill="${pal.near}"/>`;
      }
    } else if (comp === 1) {
      body += `<path d="${ridge(r, 170, 10, 12)}" fill="${pal.far}"/>`;
      body += `<rect y="176" width="400" height="124" fill="url(#sea)"/>`;
      for (let i = 0; i < 14; i++) body += `<rect x="${sunX - 30 + r.int(-8, 8)}" y="${182 + i * 8}" width="${r.int(20, 60) - i}" height="2.5" rx="1.2" fill="${pal.sun}" opacity="${(0.55 - i * 0.03).toFixed(2)}"/>`;
      body += `<path d="${ridge(r, 276, 8, 10)}" fill="${pal.near}"/>`;
    } else {
      // portrait-ish: bokeh closeup
      for (let i = 0; i < 18; i++) body += `<circle cx="${r.int(0, 400)}" cy="${r.int(60, 280)}" r="${r.int(14, 46)}" fill="${r.pick([pal.sun, pal.far, pal.mid])}" opacity="${(0.2 + r.f() * 0.35).toFixed(2)}"/>`;
      body += `<ellipse cx="${r.int(150, 250)}" cy="200" rx="46" ry="60" fill="${pal.near}" opacity="0.88"/><circle cx="200" cy="130" r="30" fill="${pal.mid}" opacity="0.95"/>`;
    }
  }
  if (partial) {
    body += `<rect y="232" width="400" height="68" fill="#8d8d90"/>`;
    for (let i = 0; i < 9; i++) body += `<rect x="${r.int(0, 360)}" y="${236 + i * 7}" width="${r.int(30, 120)}" height="2" fill="#7a7a7e"/>`;
  }
  const defs = `<defs><linearGradient id="sky" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${pal.sky[0]}"/><stop offset="1" stop-color="${pal.sky[1]}"/></linearGradient>` +
    `<radialGradient id="halo"><stop offset="0" stop-color="${pal.sun}" stop-opacity="0.85"/><stop offset="1" stop-color="${pal.sun}" stop-opacity="0"/></radialGradient>` +
    `<radialGradient id="vig" cx="0.5" cy="0.5" r="0.75"><stop offset="0.4" stop-color="#000" stop-opacity="0"/><stop offset="1" stop-color="#000" stop-opacity="0.55"/></radialGradient>` +
    `<linearGradient id="sea" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${pal.mid}"/><stop offset="1" stop-color="${pal.near}"/></linearGradient></defs>`;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 300" width="${w}" height="${h}" preserveAspectRatio="xMidYMid slice">${defs}${body}</svg>`;
}
function iconSvg(label, w) {
  const h = Math.round((w * 3) / 4);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 300" width="${w}" height="${h}"><rect width="400" height="300" fill="#eef0f3"/><path d="M140,60 h90 l40,40 v140 h-130 Z" fill="#fff" stroke="#b7bdc7" stroke-width="4"/><path d="M230,60 v40 h40" fill="#dfe3e8" stroke="#b7bdc7" stroke-width="4"/><rect x="156" y="190" width="98" height="26" rx="5" fill="#6f7f95"/><text x="205" y="209" font-family="Segoe UI,Arial,sans-serif" font-size="17" font-weight="700" fill="#fff" text-anchor="middle">${label}</text></svg>`;
}
const urlCache = new Map();
function fileUrl(sessionId, id, thumbPx) {
  const w = clamp(Math.round(thumbPx || 256), 32, 1024);
  const key = `${sessionId}:${id}:${w}`;
  if (urlCache.has(key)) return urlCache.get(key);
  let f = null;
  try {
    ensureSeed();
    f = sessions.get(sessionId)?.all[Number(id) - 1] || null;
  } catch (_) {
    /* fall through */
  }
  const cat = f?.category || "photo";
  let svg;
  if (cat === "photo") svg = artSvg(`${sessionId}/${id}`, "photo", f?.condition === "partial", w);
  else if (cat === "video") svg = artSvg(`${sessionId}/${id}`, "video", f?.condition === "partial", w);
  else svg = iconSvg((f ? TY[f.typeId].exts[0] : "file").toUpperCase().slice(0, 5), w);
  const url = "data:image/svg+xml;utf8," + encodeURIComponent(svg);
  urlCache.set(key, url);
  return url;
}

/* ───────────────────────────── recovery / duplicates / imaging ───────────────────────────── */

let recSeq = 500;
const recJobs = new Map();
const imgJobs = new Map();
const history = [
  { job: 41, sessionId: "s-9a41c7d2", sessionLabel: "CANON_EOS (F:)", dest: "D:\\Recovered\\CANON_EOS", started: NOW - 2 * DAY - 21 * 3600000, finished: NOW - 2 * DAY - 21 * 3600000 + 11 * 60000,
    state: "done", recovered: 1834, partial: 96, failed: 12, repaired: 21, skippedDuplicates: 34, bytes: 16.4e9, reportPath: "D:\\Recovered\\CANON_EOS\\MAX Recovery Report.html" },
  { job: 38, sessionId: "s-3be0f518", sessionLabel: "Windows (C:)", dest: "E:\\Rescue\\Ann Documents", started: NOW - 6 * DAY - 3 * 3600000, finished: NOW - 6 * DAY - 3 * 3600000 + 90000,
    state: "done", recovered: 212, partial: 9, failed: 3, repaired: 2, skippedDuplicates: 5, bytes: 412e6, reportPath: "E:\\Rescue\\Ann Documents\\MAX Recovery Report.html" },
];

function selectFiles(s, ids, query) {
  const vis = visible(s);
  if (ids?.length) {
    const want = new Set(ids);
    return vis.filter((f) => want.has(f.id));
  }
  if (query) return vis.filter(makePred(query, s));
  return vis.slice();
}

function destCheck(s, dest, ids, query) {
  const files = selectFiles(s, ids, query);
  const need = files.reduce((a, f) => a + f.size, 0);
  const norm = String(dest || "").trim().replace(/\//g, "\\").replace(/\\+$/, "");
  const m = /^([A-Za-z]):(\\|$)/.exec(norm);
  const base = { ok: false, error: null, warnings: [], freeBytes: 0, needBytes: need, path: norm || String(dest || ""), onSourceDisk: false };
  if (!m) return { ...base, error: "Choose a folder on a local drive, for example D:\\Recovered." };
  const letter = m[1].toUpperCase();
  const vol = VOL_DEFS[letter];
  const onSource = letter === s.res.letter || (vol && s.res.disk != null && vol.diskIndex === s.res.disk);
  const free = vol ? (vol.letter === "G" ? 0 : vol.free) : 214e9;
  base.freeBytes = free;
  base.path = norm.length === 2 ? norm + "\\" : norm;
  if (onSource) return { ...base, onSourceDisk: true, error: SRC_DISK_MSG };
  if (state.bitlockerLocked && letter === "E") return { ...base, error: LOCKED_MSG };
  if (vol && vol.fs === "RAW") return { ...base, error: `Drive ${letter}: isn't formatted. Pick a drive Windows can write to.` };
  if (need > free) return { ...base, error: `There isn't enough free space on ${letter}: (${humanSize(need)} needed, ${humanSize(free)} free). Pick another drive or select fewer files.` };
  const warnings = [];
  if (need > free * 0.85) warnings.push(`${letter}: will be nearly full after this recovery.`);
  const partial = files.filter((f) => f.condition === "partial").length;
  if (partial) warnings.push(`${fmtNum(partial)} files are only partly recoverable. They will be saved as far as they can be read.`);
  const zeroed = files.filter((f) => f.flags & 32).length;
  if (zeroed) warnings.push(`${fmtNum(zeroed)} files read as zeros (SSD TRIM). They can't be recovered.`);
  if (vol && vol.driveType === "removable") warnings.push("This is a removable drive. Keep it connected until the recovery has finished.");
  return { ...base, ok: true, warnings };
}

function startRecovery(s, dest, ids, query, options) {
  const chk = destCheck(s, dest, ids, query);
  if (!chk.ok) throw chk.error;
  const files = selectFiles(s, ids, query);
  if (!files.length) throw "Select at least one file to recover.";
  const job = ++recSeq;
  const total = files.length;
  const bytesTotal = files.reduce((a, f) => a + f.size, 0);
  const D = 4000 / Math.max(0.01, state.speed);
  const job_ = { job, t: 0, last: Date.now(), timer: null };
  recJobs.set(job, job_);
  const keep = options?.keepFolders !== false;
  const finish = (st) => {
    clearInterval(job_.timer);
    recJobs.delete(job);
    const n = st === "done" ? total : Math.floor(total * job_.t);
    const sel = files.slice(0, n);
    const failedList = sel.filter((f) => f.flags & 32 || (f.id * 2654435761) % 97 === 0);
    const failedSet = new Set(failedList);
    const partial = sel.filter((f) => f.condition === "partial" && !failedSet.has(f)).length;
    const repaired = options?.repair === false ? 0 : Math.round(partial * 0.2);
    let skipped = 0;
    if (options?.skipDuplicates !== false && s.dupesDone) {
      const seen = new Set();
      for (const f of sel) if (f.dupGroup) (seen.has(f.dupGroup) ? skipped++ : seen.add(f.dupGroup));
    }
    const okFiles = sel.filter((f) => !failedSet.has(f));
    const bytes = okFiles.reduce((a, f) => a + f.size, 0);
    const reportPath = options?.report === false ? null : chk.path.replace(/\\$/, "") + "\\MAX Recovery Report.html";
    const errors = failedList.slice(0, 20).map((f) => `${f.name}: ${f.flags & 32 ? "its data reads as zeros, so there is nothing to recover." : "a sector could not be read."}`);
    const payload = { job, sessionId: s.id, state: st, recovered: okFiles.length - partial - skipped, partial, failed: failedList.length, repaired, skippedDuplicates: skipped, bytes, dest: chk.path, reportPath, errors };
    history.unshift({ job, sessionId: s.id, sessionLabel: s.label, dest: chk.path, started: Date.now() - Math.round(D * job_.t), finished: Date.now(), state: st, recovered: payload.recovered, partial, failed: payload.failed, repaired, skippedDuplicates: skipped, bytes, reportPath });
    emit("recovery-done", payload);
  };
  job_.finish = finish;
  job_.timer = setInterval(() => {
    const now = Date.now();
    job_.t = Math.min(1, job_.t + (now - job_.last) / D);
    job_.last = now;
    if (job_.t >= 1) return finish("done");
    const idx = Math.min(total - 1, Math.floor(job_.t * total));
    const f = files[idx];
    emit("recovery-progress", {
      job, sessionId: s.id, filesDone: Math.floor(job_.t * total), filesTotal: total, bytesDone: Math.round(job_.t * bytesTotal), bytesTotal,
      current: (keep ? f.folder.replace(/\\$/, "") : "") + "\\" + f.name, bytesPerSec: Math.round(82e6 * (0.9 + 0.2 * mulberry32(idx)())), etaSeconds: Math.max(1, Math.round(((1 - job_.t) * bytesTotal) / 82e6)),
    });
  }, Math.max(15, 250 / Math.max(0.01, state.speed)));
  return job;
}

function startDupes(s) {
  const job = ++recSeq;
  const vis = visible(s);
  const total = vis.length;
  let step = 0;
  const steps = 6;
  const timer = setInterval(() => {
    step++;
    if (step < steps) return emit("dupes-progress", { job, sessionId: s.id, done: Math.round((step / steps) * total), total });
    clearInterval(timer);
    s.dupesDone = true;
    const groups = new Map();
    for (const f of vis) if (f.dupGroup) (groups.get(f.dupGroup) || groups.set(f.dupGroup, []).get(f.dupGroup)).push(f);
    let files = 0;
    let wasted = 0;
    for (const g of groups.values()) {
      files += g.length;
      wasted += g.slice(1).reduce((a, f) => a + f.size, 0);
    }
    emit("dupes-progress", { job, sessionId: s.id, done: total, total });
    emit("dupes-done", { job, sessionId: s.id, state: "done", groups: groups.size, files, wastedBytes: wasted });
  }, Math.max(15, 250 / Math.max(0.01, state.speed)));
  return job;
}

let imgSeq = 900;
function startImaging(source, dest, options) {
  const res = resolveSource(source);
  if (res.kind === "volume" || res.kind === "disk") needAdmin();
  if (res.locked) throw LOCKED_MSG;
  const norm = String(dest || "").trim().replace(/\//g, "\\");
  const m = /^([A-Za-z]):/.exec(norm);
  if (!m) throw "Choose where to save the image, for example D:\\Images.";
  const vol = VOL_DEFS[m[1].toUpperCase()];
  if (m[1].toUpperCase() === res.letter || (vol && res.disk != null && vol.diskIndex === res.disk)) throw "The image would be written onto the drive you are copying. Pick a folder on another drive.";
  const total = res.len;
  const name = (res.label || "disk").replace(/[^A-Za-z0-9 _()-]/g, "").trim().replace(/\s+/g, "_");
  const path = /\.(img|dd|raw)$/i.test(norm) ? norm : norm.replace(/\\+$/, "") + "\\" + name + ".img";
  const job = ++imgSeq;
  const D = 8000 / Math.max(0.01, state.speed);
  const j = { job, t: 0, last: Date.now(), paused: false, timer: null };
  imgJobs.set(job, j);
  const badRanges = res.disk === 1 ? [[Math.floor(total * 0.41 / 4096) * 4096, Math.floor(total * 0.41 / 4096) * 4096 + 8192], [Math.floor(total * 0.63 / 4096) * 4096, Math.floor(total * 0.63 / 4096) * 4096 + 4096]] : [];
  const badSoFar = () => badRanges.reduce((a, [s0, e0]) => a + (j.t * total > s0 ? Math.min(e0 - s0, j.t * total - s0) : 0), 0);
  const done = (st) => {
    clearInterval(j.timer);
    imgJobs.delete(job);
    const bad = st === "done" ? badRanges.reduce((a, [s0, e0]) => a + e0 - s0, 0) : badSoFar();
    emit("imaging-done", {
      job, state: st, path, bytesWritten: Math.round(st === "done" ? total : j.t * total), badRanges: st === "done" ? badRanges : badRanges.filter(([s0]) => s0 < j.t * total),
      blake3: st === "done" && options?.hash !== false ? randHex(rng("b3:" + path + total), 64) : undefined, logPath: path.replace(/\.[^.\\]+$/, "") + ".log",
      note: st === "cancelled" ? "The partial image was kept. Scanning it finds files in the part that was copied." : bad ? `${humanSize(bad)} couldn't be read and were filled with zeros; the log lists where.` : undefined,
    });
  };
  j.done = done;
  j.timer = setInterval(() => {
    const now = Date.now();
    if (!j.paused) j.t = Math.min(1, j.t + (now - j.last) / D);
    j.last = now;
    if (j.t >= 1) return done("done");
    emit("imaging-progress", {
      job, state: j.paused ? "paused" : "running", bytesDone: Math.round(j.t * total), bytesTotal: total, badBytes: Math.round(badSoFar()),
      bytesPerSec: j.paused ? 0 : Math.round(res.bps * 0.8), etaSeconds: j.paused ? null : Math.max(1, Math.round(((1 - j.t) * total) / (res.bps * 0.8))),
    });
  }, Math.max(15, 250 / Math.max(0.01, state.speed)));
  return { job, path };
}

/* ───────────────────────────── settings ───────────────────────────── */

const settings = {
  customSignatures: [], defaultDestination: null, checkUpdates: true, updateFeed: "", keepFolders: true, verifyRecovered: true, repairDamaged: true, skipDuplicates: true,
};
function saveSettings(input) {
  const s = { ...settings, ...clone(input) };
  delete s.loadWarning; // never read from the page (skip_deserializing); a save clears it
  const seen = new Set();
  s.customSignatures = (s.customSignatures || []).map((sig, i) => {
    const out = { header: "", headerOffset: 0, footer: "", enabled: true, category: "other", ...sig };
    out.name = String(out.name || "").trim();
    out.ext = String(out.ext || "").trim().replace(/^\./, "").toLowerCase();
    const who = out.name || "A custom signature";
    if (!out.id) out.id = `custom-${Date.now()}-${i}`;
    while (seen.has(out.id)) out.id += "-" + seen.size;
    seen.add(out.id);
    const hexOk = (h) => /^([0-9a-f]{2}\s*)+$/i.test(h.trim()) && h.replace(/\s+/g, "").length <= 128;
    if (!out.name) throw `${who}: Give the signature a name.`;
    if (!out.ext || !/^[a-z0-9]{1,8}$/.test(out.ext)) throw `${who}: The extension must be 1 to 8 letters or digits.`;
    if (!out.header || !hexOk(out.header)) throw `${who}: The header must be hex bytes, for example 25 50 44 46.`;
    if (out.footer && !hexOk(out.footer)) throw `${who}: The footer must be hex bytes, for example FF D9.`;
    if (!(out.maxSize > 0)) throw `${who}: Set a maximum size greater than zero.`;
    return out;
  });
  s.updateFeed = String(s.updateFeed || "").trim();
  if (s.updateFeed && !s.updateFeed.startsWith("https://")) throw "The update feed must be an https:// address.";
  Object.assign(settings, s);
  state.settingsWarning = null;
  return clone(settings);
}

/* ───────────────────────────── command table ───────────────────────────── */

const COMMANDS = {};
const def = (name, delay, fn) => (COMMANDS[name] = { delay, fn });
const asNum = (x) => (x == null ? null : Number(x));

def("system_info", 40, () => ({
  elevated: state.elevated, askAdminAtStart: state.askAdmin, computerName: "ANN-LAPTOP", systemDrive: "C:", userProfile: "C:\\Users\\Ann",
  downloads: "C:\\Users\\Ann\\Downloads", version: "0.1.0", portable: false, dataDir: "C:\\Users\\Ann\\AppData\\Roaming\\MAX File Recovery",
  ...(state.portableWarning ? { portableWarning: state.portableWarning } : {}),
  ...(state.dataNote ? { dataNote: state.dataNote } : {}),
}));
def("app_ready", 20, () => null);
def("perf_mark", 20, () => null);
def("perf_enabled", 20, () => false);
def("set_theme_pref", 20, ({ theme }) => {
  if (!["light", "dark", "system"].includes(theme)) throw "The theme must be light, dark or system.";
  state.themePref = theme;
  return null;
});
def("cache_get_many", 25, () => ({}));
def("relaunch_elevated", 300, () => false);
def("set_ask_admin", 30, ({ enabled }) => {
  state.askAdmin = !!enabled;
  return null;
});
def("reveal_path", 40, ({ path }) => {
  if (!path) throw "There is no path to show.";
  return null;
});
def("open_url", 40, ({ url }) => {
  if (!/^https:\/\/[^\s]+$/i.test(String(url || ""))) throw "MAX only opens https:// links. Copy the link into your browser instead.";
  return null;
});
def("exit_app", 20, () => {
  state.exited = true;
  return null;
});
def("get_settings", 40, () => ({ ...clone(settings), ...(state.settingsWarning ? { loadWarning: state.settingsWarning } : {}) }));
def("save_settings", 120, ({ settings: s }) => saveSettings(s));
def("check_for_updates", 380, () => {
  const feed = settings.updateFeed;
  return { current: "0.1.0", latest: feed ? "v0.1.0" : null, url: null, updateAvailable: false, checkedAt: Date.now(), notConfigured: !feed };
});
def("list_file_types", 60, () => TYPE_ROWS.map(([id, label, category, exts, carvable]) => ({ id, label, category, exts, carvable })));
def("list_devices", 260, () => buildDevices());
def("smart_info", 320, ({ disk }) => smartFor(Number(disk)));
def("open_image", 340, ({ path }) => {
  const p = String(path || "");
  if (!/\.(img|vhd|vhdx|dd|iso|raw|bin|001)$/i.test(p)) throw "MAX doesn't recognise this file as a disk image.";
  return imageInfo(p);
});
def("read_sectors", 90, ({ source, offset, length }) => {
  const res = resolveSource(source);
  if (res.kind === "volume" || res.kind === "disk") needAdmin();
  if (res.locked) throw LOCKED_MSG;
  offset = Math.max(0, Math.floor(offset || 0));
  if (offset >= res.len) throw "That position is past the end of the drive.";
  const len = Math.max(0, Math.min(Math.floor(length || 512), 65536, res.len - offset));
  return { offset, data: b64(sectorData(res, offset, len)), sourceLen: res.len, sectorSize: 512, bad: [] };
});
def("start_imaging", 140, ({ source, dest, options }) => startImaging(source, dest, options));
def("pause_imaging", 30, ({ job, paused }) => {
  const j = imgJobs.get(job);
  if (!j) throw "That imaging job isn't running.";
  j.paused = !!paused;
  return null;
});
def("cancel_imaging", 30, ({ job }) => {
  const j = imgJobs.get(job);
  if (!j) throw "That imaging job isn't running.";
  setTimeout(() => j.done("cancelled"), 60);
  return null;
});
def("analyze_partitions", 300, ({ source }) => {
  const res = resolveSource(source);
  if (res.kind === "volume" || res.kind === "disk") needAdmin();
  return partitionReport(res, false);
});

// Where a scan's results would go: C: (and its disk / snapshots) moves them to D:, G: has nowhere
// else to go (sameDrive), other drives use the default data folder on C:, images say nothing.
const SAME_DRIVE_WARNING = "MAX will have to keep this scan's results on the drive being scanned, which can overwrite deleted files. Connect another drive with at least 1 GB free (or run MAX in portable mode from a USB stick) before you scan, if you can.";
// Like folder_on_volume: the folder's drive letter and its path below the root.
def("folder_source", 40, ({ path }) => {
  const m = /^([A-Za-z]):[\\/]?(.*)$/.exec(String(path || "").trim());
  if (!m) throw "MAX can only scan folders on a local drive with a drive letter. Pick that drive instead and scan all of it.";
  const letter = m[1].toUpperCase();
  const rest = m[2].replace(/[\\/]+$/, "");
  const folder = rest ? "\\" + rest.replace(/\//g, "\\") : "";
  return { source: { kind: "volume", path: letter }, folder, display: `${letter}:${folder || "\\"}` };
});
def("scan_location", 60, ({ source }) => {
  const res = resolveSource(source);
  if (res.kind === "volume" || res.kind === "disk") needAdmin();
  const out = { sameDrive: false, movedTo: null, message: null, refuse: null };
  if (state.scanRefuse) return { ...out, refuse: state.scanRefuse };
  const l = res.letter;
  if (!l || res.kind === "image") return out;
  if (l === "C") return { ...out, movedTo: "D:", message: "This scan's results will be saved in D:\\MAX Recovery\\sessions, so nothing is written to C:." };
  if (l === "G") return { ...out, sameDrive: true, message: SAME_DRIVE_WARNING };
  return { ...out, message: `This scan's results will be saved in MAX's data folder on C:, so nothing is written to ${l}:.` };
});
def("start_scan", 160, ({ source, options }) => {
  const s = newSessionFromSource(source, options);
  const job = startRun(s);
  return { sessionId: s.id, job };
});
def("pause_scan", 30, ({ sessionId, paused }) => {
  const s = getSession(sessionId);
  if (!s.run) throw "That scan isn't running.";
  s.run.paused = !!paused;
  s.state = paused ? "paused" : "running";
  return null;
});
def("cancel_scan", 40, ({ sessionId }) => {
  const s = getSession(sessionId);
  if (!s.run) throw "That scan isn't running.";
  // Like the backend: progress keeps coming with stopping: true while the found files are saved.
  const run = s.run;
  run.stopping = true;
  run.paused = false;
  setTimeout(() => s.run === run && finishRun(s, "cancelled"), Math.max(60, state.stopMs / Math.max(0.01, state.speed)));
  return null;
});
def("resume_session", 150, ({ sessionId }) => {
  const s = getSession(sessionId);
  if (s.run) throw "That scan is already running.";
  if (!["interrupted", "cancelled", "failed", "paused"].includes(s.state)) throw "That scan is complete, so there is nothing to resume.";
  checkScanAllowed(s.res);
  return { sessionId: s.id, job: startRun(s) };
});
def("list_sessions", 120, () => {
  ensureSeed();
  if (state.noSessions) return [];
  return [...sessions.values()].sort((a, b) => b.created - a.created).map(summaryOf);
});
def("get_session", 120, ({ sessionId }) => {
  const s = getSession(sessionId);
  return {
    summary: summaryOf(s), options: s.options, stages: stagesOf(s), probe: s.probe, partitions: s.partitions, counts: countsOf(s), sectorSize: 512, error: s.error, notes: notesOf(s),
  };
});
def("delete_session", 90, ({ sessionId }) => {
  const s = getSession(sessionId);
  if (s.run) finishRun(s, "cancelled");
  sessions.delete(s.id);
  return null;
});
def("export_session", 260, ({ sessionId, path }) => {
  getSession(sessionId);
  if (!path) throw "Choose where to save the session file.";
  return null;
});
def("import_session", 300, ({ path }) => {
  ensureSeed();
  if (!/\.maxscan$/i.test(String(path || ""))) throw "MAX doesn't recognise this file as a saved scan.";
  const src = sessions.get("s-9a41c7d2");
  const id = "s-" + hex(fnv(path + ++sessionSeq), 8).toLowerCase();
  const s = makeSession({ id, label: "Imported — " + src.label, mode: "deep", state: "done", t: 1, created: Date.now(), res: src.res, spec: { ...src.spec, seed: "sess:" + id }, source: { ...src.source }, dupesDone: false });
  return s.id;
});

def("query_files", 70, ({ sessionId, query }) => {
  const s = getSession(sessionId);
  const q = query || {};
  const arr = sortFiles(matches(s, q), q);
  let totalSize = 0;
  for (const f of arr) totalSize += f.size;
  const offset = Math.max(0, asNum(q.offset) || 0);
  const limit = clamp(asNum(q.limit) || 200, 1, 2000);
  return { total: arr.length, totalSize, items: arr.slice(offset, offset + limit).map((f) => rowOf(f, s)) };
});
def("query_ids", 60, ({ sessionId, query }) => {
  const s = getSession(sessionId);
  const arr = matches(s, query);
  if (arr.length > state.maxIds) throw `There are more than ${fmtNum(state.maxIds)} files here, too many to select one by one. Use Recover all instead, or narrow the list with a filter.`;
  return sortFiles(arr, query).map((f) => f.id);
});
def("folder_children", 60, ({ sessionId, parent, query }) => folderChildren(getSession(sessionId), parent ?? "", query));
def("file_detail", 50, ({ sessionId, id }) => {
  const s = getSession(sessionId);
  const f = fileOf(s, id);
  return {
    row: rowOf(f, s), extents: f.extents, accessed: f.accessed, fsRef: f.fsRef, hasResident: f.size < 700 && f.origin === "ntfs", livePath: f.livePath, hash: hashOf(s, f),
    source: s.source, sectorSize: 512,
  };
});
def("map_cells", 80, ({ sessionId, start, end, cells }) => mapCells(getSession(sessionId), start, end, cells));
def("map_region", 90, ({ sessionId, start, end }) => {
  const s = getSession(sessionId);
  const L = s.geo.L;
  start = clamp(Math.floor(start || 0), 0, L - 1);
  end = clamp(Math.floor(end ?? L), start + 1, L);
  const ls = layers(s);
  const inRange = [];
  for (const f of visible(s)) {
    if (f.status === "existing") continue;
    if (f.extents.some((e) => e.offset < end && e.offset + e.len > start)) inRange.push(f);
  }
  inRange.sort((a, b) => a.extents[0].offset - b.extents[0].offset);
  return {
    start, end, sectorSize: 512, firstSector: Math.floor(start / 512), lastSector: Math.ceil(end / 512) - 1, totals: layerList(ls).map((x) => Math.round(x.bytes(start, end))),
    badRanges: ls.bad.clip(start, end), files: inRange.slice(0, 100).map((f) => rowOf(f, s)), fileCount: inRange.length,
  };
});
def("session_log", 60, ({ sessionId, offset, limit }) => {
  const all = logOf(getSession(sessionId));
  const o = Math.max(0, offset || 0);
  return all.slice(o, o + clamp(limit || 500, 1, 5000));
});
def("inspect_file", 110, ({ sessionId, id }) => {
  const s = getSession(sessionId);
  return inspectOf(s, fileOf(s, id));
});
def("preview_document", 160, ({ sessionId, id }) => {
  const s = getSession(sessionId);
  return previewOf(s, fileOf(s, id));
});
def("read_file_bytes", 70, ({ sessionId, id, offset, length }) => {
  const s = getSession(sessionId);
  const f = fileOf(s, id);
  offset = Math.max(0, Math.floor(offset || 0));
  const len = clamp(Math.floor(length || 4096), 0, 65536);
  const data = fileBytes(f, offset, len);
  return { offset, size: f.size, data: b64(data), badSectors: !!(f.flags & 128) };
});

def("check_destination", 130, ({ sessionId, dest, ids, query }) => destCheck(getSession(sessionId), dest, ids, query));
def("start_recovery", 150, ({ sessionId, dest, ids, query, options }) => startRecovery(getSession(sessionId), dest, ids, query, options));
def("cancel_recovery", 30, ({ job }) => {
  const j = recJobs.get(job);
  if (!j) throw "That recovery isn't running.";
  setTimeout(() => j.finish("cancelled"), 60);
  return null;
});
def("recovery_history", 100, () => history.slice());
def("find_duplicates", 100, ({ sessionId }) => startDupes(getSession(sessionId)));
def("export_report", 380, ({ sessionId, path, format }) => {
  getSession(sessionId);
  if (!["html", "csv"].includes(format)) throw "The report format must be html or csv.";
  if (!path) throw "Choose where to save the report.";
  return String(path);
});

/* ───────────────────────────── invoke / dialogs / install ───────────────────────────── */

async function invoke(cmd, args = {}) {
  const c = COMMANDS[cmd];
  if (!c) throw `Unknown command ${cmd}`;
  await sleep(Math.max(15, Math.round(c.delay * (0.8 + Math.random() * 0.4) / Math.max(1, state.speed > 1 ? state.speed / 2 : 1))));
  try {
    return clone(await c.fn(args || {}));
  } catch (e) {
    if (typeof e === "string") throw e;
    console.error(`[mock] ${cmd} failed`, e);
    throw `The mock backend failed in ${cmd}: ${e?.message || e}`;
  }
}

const dialog = {
  async open(opts = {}) {
    await sleep(120);
    let p;
    if (opts.directory) p = /files in/.test(opts.title || "") ? "E:\\Users\\Ann\\Pictures\\Holiday 2024" : "D:\\Recovered";
    else {
      const ex = (opts.filters || []).flatMap((f) => f.extensions || []).map((x) => String(x).toLowerCase());
      p = ex.includes("maxscan") ? "D:\\Reports\\CANON_EOS.maxscan" : "D:\\Images\\sdcard.img";
    }
    return opts.multiple ? [p] : p;
  },
  async save(opts = {}) {
    await sleep(120);
    const base = String(opts.defaultPath || "").split("\\").pop();
    return "D:\\Reports\\" + (base || "report.html");
  },
};

export function installMock() {
  if (typeof window === "undefined") return;
  if (window.__TAURI__ && !window.__TAURI__.__mock) return;
  const tauri = { core: { invoke, convertFileSrc: (p) => p }, event: { listen }, dialog, __mock: true };
  window.__TAURI__ = tauri;
  window.__MAX_MOCK__ = { state, emit, fileUrl, closeWindow };
}

// The window's close button: like the backend, ask the page first while jobs run (confirm-exit).
// Returns true when the window would close right away.
function closeWindow() {
  const scans = [...sessions.values()].filter((s) => s.run).length;
  const recoveries = recJobs.size;
  const imaging = imgJobs.size > 0;
  if (!scans && !recoveries && !imaging) {
    state.exited = true;
    return true;
  }
  emit("confirm-exit", { scans, recoveries, imaging });
  return false;
}
export { invoke, listen, emit, fileUrl, dialog };
