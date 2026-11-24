// Core of the MAX UI: state, IPC wrappers, formatting, rendering helpers, toasts, dialogs.
// No framework: string templates + patch() so hover, focus and scroll survive re-renders.
import { ICONS } from "./icons.js";

export const S = {
  sys: null, // system_info
  devices: null, // DeviceList
  devicesError: null,
  images: [], // [{path, info}] opened this session (persisted in localStorage)
  sessions: [], // SessionSummary[]
  types: [], // list_file_types
  settings: null,
  view: { name: "home" }, // home | drive | session | imaging | rules | history | settings
  live: {}, // sessionId -> last scan-progress payload
  sessionCache: {}, // sessionId -> SessionDetail
  recoveries: {}, // job -> {progress, done, sessionId}
  imaging: null, // {job, progress, done, path, source}
  dupes: {}, // sessionId -> {job, done, total, result}
  scanDone: {}, // sessionId -> last scan-done payload (it can arrive before start_scan returns)
};

export const isMock = () => !!window.__MAX_MOCK__;

// Shared hooks filled in by app.js; views register their click actions in App.actions.
export const App = {
  render: () => {},
  renderMain: () => {},
  renderRail: () => {},
  navigate: (_view) => {},
  actions: {},
  refreshDevices: async () => {},
  refreshSessions: async () => {},
  imagingDone: (_payload) => {},
};

// ------------------------------------------------------------------------------------ IPC
export function invoke(cmd, args) {
  return window.__TAURI__.core.invoke(cmd, args);
}
export function listen(event, cb) {
  return window.__TAURI__.event.listen(event, cb);
}
export function errText(e) {
  if (typeof e === "string") return e;
  if (e && typeof e.message === "string") return e.message;
  return "Something went wrong. Try again.";
}
export const needsAdmin = (e) => /administrator/i.test(errText(e)) && !(S.sys && S.sys.elevated);

// URL of a found file's bytes (or a thumbnail) served by the backend's maxfile:// protocol.
export function fileUrl(sessionId, id, thumb) {
  if (isMock()) return window.__MAX_MOCK__.fileUrl(sessionId, id, thumb);
  const base = `http://maxfile.localhost/${encodeURIComponent(sessionId)}/${id}`;
  return thumb ? `${base}?thumb=${thumb}` : base;
}

// ------------------------------------------------------------------------------- formatting
export function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
export function icon(name, cls = "") {
  const inner = ICONS[name] || ICONS["file"];
  return `<svg class="i ${cls}" viewBox="0 0 24 24" aria-hidden="true">${inner}</svg>`;
}
export function bytes(n) {
  if (n == null || isNaN(n)) return "–";
  if (n === 1) return "1 byte";
  if (n < 1024) return `${n} bytes`;
  const u = ["KB", "MB", "GB", "TB", "PB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 ? Math.round(v) : v.toFixed(1).replace(/\.0$/, "")} ${u[i]}`;
}
export const int = (n) => (n ?? 0).toLocaleString("en-US");
export function plural(n, one, many) {
  return `${int(n)} ${n === 1 ? one : many || one + "s"}`;
}
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
export function date(ms, withTime = false) {
  if (!ms) return "–";
  const d = new Date(ms);
  const now = new Date();
  let s = `${MONTHS[d.getMonth()]} ${d.getDate()}`;
  if (d.getFullYear() !== now.getFullYear()) s += `, ${d.getFullYear()}`;
  if (withTime) s += ` ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  return s;
}
export function ago(ms) {
  if (!ms) return "";
  const s = (Date.now() - ms) / 1000;
  const f = s < 0;
  const a = Math.abs(s);
  let t;
  if (a < 90) return "just now";
  else if (a < 3600) t = `${Math.round(a / 60)} min`;
  else if (a < 86400) t = `${Math.round(a / 3600)} h`;
  else if (a < 14 * 86400) t = plural(Math.round(a / 86400), "day");
  else if (a < 70 * 86400) t = plural(Math.round(a / (7 * 86400)), "week");
  else t = plural(Math.round(a / (30 * 86400)), "month");
  return f ? `in ${t}` : `${t} ago`;
}
export function duration(sec) {
  if (sec == null || !isFinite(sec)) return "";
  sec = Math.max(0, Math.round(sec));
  if (sec < 60) return `${sec} s`;
  if (sec < 3600) return `${Math.floor(sec / 60)} min ${sec % 60 ? `${sec % 60} s` : ""}`.trim();
  const h = Math.floor(sec / 3600);
  const m = Math.round((sec % 3600) / 60);
  return `${h} h ${m} min`;
}
export function rate(bps) {
  return bps ? `${bytes(bps)}/s` : "";
}
export function list(items, max = 3) {
  if (items.length <= max) return items.length > 1 ? `${items.slice(0, -1).join(", ")} and ${items.at(-1)}` : items[0] || "";
  return `${items.slice(0, max).join(", ")} and ${items.length - max} more`;
}

export const COND_LABEL = { excellent: "Excellent", good: "Good", partial: "Partial", unknown: "Unknown" };
export function cond(c, withLabel = true) {
  const k = COND_LABEL[c] ? c : "unknown";
  return `<span class="cond ${k}" title="${esc(COND_LABEL[k])} condition"><span class="bars" aria-hidden="true"><i></i><i></i><i></i></span>${withLabel ? esc(COND_LABEL[k]) : `<span class="sr">${COND_LABEL[k]}</span>`}</span>`;
}
export const CAT = {
  photo: { label: "Photos", one: "photo", icon: "image" },
  video: { label: "Videos", one: "video", icon: "film" },
  audio: { label: "Audio", one: "audio file", icon: "music" },
  document: { label: "Documents", one: "document", icon: "file-text" },
  archive: { label: "Archives", one: "archive", icon: "file-archive" },
  other: { label: "Other", one: "file", icon: "file" },
};
export const STATUS_LABEL = { deleted: "Deleted", existing: "Still exists", lost: "Lost folder", carved: "Found by content", recycleBin: "In Recycle Bin" };
export const ORIGIN_LABEL = { ntfs: "NTFS file table", fat: "FAT directory", exFat: "exFAT directory", carving: "Signature search", recycleBin: "Recycle Bin" };
export const FLAGS = { COMPRESSED: 1, ENCRYPTED: 2, SPARSE: 4, EXT_MISMATCH: 8, NAME_GUESSED: 16, ZEROED: 32, OVERWRITTEN: 64, BAD_SECTORS: 128, FROM_RECYCLE_INFO: 256, SNAPSHOT: 512, LOOSE_RECORD: 1024 };

export function sourceLabel(src) {
  if (!src) return "";
  if (src.label) return src.label;
  switch (src.kind) {
    case "volume":
      return `${src.path}:`;
    case "disk":
      return `Disk ${src.path}`;
    case "image":
      return src.path.split(/[\\/]/).pop();
    case "snapshot":
      return "Restore point";
    default:
      return src.path;
  }
}
export function sourceIcon(src, dev) {
  if (!src) return "hard-drive";
  if (src.kind === "image") return "disc-3";
  if (src.kind === "snapshot") return "history";
  const bus = dev?.bus || "";
  if (bus === "USB") return "usb";
  if (bus === "SD") return "memory-stick";
  return "hard-drive";
}
export const sameSource = (a, b) => !!a && !!b && a.kind === b.kind && String(a.path).toLowerCase() === String(b.path).toLowerCase() && (a.offset || 0) === (b.offset || 0);

// Record a scan that start_scan / resume_session just started. scan-done can reach the page before
// the command's reply: then the scan is already over and must not be shown as running.
// Returns true when the scan is still running.
export function scanStarted(r, filesFound = 0) {
  const done = S.scanDone[r.sessionId];
  if (done && done.job === r.job) {
    delete S.live[r.sessionId];
    delete S.sessionCache[r.sessionId];
    return false;
  }
  S.live[r.sessionId] = { sessionId: r.sessionId, job: r.job, state: "running", stage: "", stageIndex: 0, stageCount: 1, done: 0, total: 0, filesFound };
  return true;
}

// What would stop if MAX closed now: {scans, recoveries, imaging}.
export function runningJobs() {
  return {
    scans: Object.values(S.live).filter((l) => l && (l.state === "running" || l.state === "paused")).length,
    recoveries: Object.values(S.recoveries).filter((r) => !r.done).length,
    imaging: !!(S.imaging && !S.imaging.done),
  };
}
// Plain sentences about the jobs that stop when MAX closes or restarts ("" when nothing runs).
export function busyText({ scans = 0, recoveries = 0, imaging = false } = {}, lead = "MAX is still working on") {
  const parts = [];
  if (scans) parts.push(scans === 1 ? "a scan" : `${int(scans)} scans`);
  if (recoveries) parts.push(recoveries === 1 ? "a recovery" : `${int(recoveries)} recoveries`);
  if (imaging) parts.push("a disk image");
  if (!parts.length) return "";
  const out = [`${lead} ${list(parts)}.`];
  if (scans) out.push(scans === 1 ? "The scan keeps what it found so far and can be resumed later." : "The scans keep what they found so far and can be resumed later.");
  if (recoveries) out.push(recoveries === 1 ? "The recovery stops; files already copied stay where they are." : "The recoveries stop; files already copied stay where they are.");
  if (imaging) out.push("Imaging stops; the part copied so far is kept as a partial image.");
  return out.join(" ");
}

// ---------------------------------------------------------------------------- DOM helpers
export const $ = (sel, root = document) => root.querySelector(sel);
export function patch(el, html) {
  if (!el || el._h === html) return false;
  el.innerHTML = html;
  el._h = html;
  return true;
}
// Re-render a region while keeping keyboard focus (and the caret) on the equivalent control.
export function restoringFocus(fn) {
  const a = document.activeElement;
  let sel = null;
  let caret = null;
  if (a && a !== document.body && a.closest("#app")) {
    if (a.id) sel = `#${CSS.escape(a.id)}`;
    else if (a.dataset.action) {
      const keys = ["id", "tab", "path", "key", "mode", "letter", "value", "kind"];
      const k = keys.find((x) => a.dataset[x] != null);
      sel = k ? `[data-action="${a.dataset.action}"][data-${k}="${CSS.escape(a.dataset[k])}"]` : `[data-action="${a.dataset.action}"]`;
    } else if (a.name) sel = `[name="${CSS.escape(a.name)}"]`;
    if ("selectionStart" in a) {
      try {
        caret = [a.selectionStart, a.selectionEnd];
      } catch {}
    }
  }
  fn();
  if (sel && document.activeElement !== a) {
    const n = document.querySelector(sel);
    if (n) {
      n.focus({ preventScroll: true });
      if (caret && "setSelectionRange" in n) {
        try {
          n.setSelectionRange(caret[0], caret[1]);
        } catch {}
      }
    }
  }
}

// --------------------------------------------------------------------------------- storage
export function load(key, fallback) {
  try {
    const v = localStorage.getItem("maxrec." + key);
    return v == null ? fallback : JSON.parse(v);
  } catch {
    return fallback;
  }
}
export function save(key, value) {
  try {
    localStorage.setItem("maxrec." + key, JSON.stringify(value));
  } catch {}
}

// ---------------------------------------------------------------------------------- toasts
export function toast(msg, opts = {}) {
  const box = document.getElementById("toasts");
  const t = document.createElement("div");
  t.className = "toast" + (opts.error ? " err" : "");
  t.innerHTML = `${icon(opts.error ? "circle-alert" : opts.icon || "circle-check")}<div class="grow">${esc(msg)}</div>${
    opts.action ? `<button class="btn small" type="button">${esc(opts.action)}</button>` : ""
  }<button class="btn small icon ghost" type="button" aria-label="Dismiss" style="color:inherit">${icon("x", "s")}</button>`;
  const close = () => t.remove();
  const btns = t.querySelectorAll("button");
  if (opts.action) btns[0].onclick = () => (close(), opts.onAction?.());
  btns[btns.length - 1].onclick = close;
  box.appendChild(t);
  setTimeout(close, opts.ms || (opts.error ? 8000 : 5200));
}
export const toastError = (e) => toast(errText(e), { error: true });

// --------------------------------------------------------------------------------- dialogs
// showDialog(html) -> Promise<returnValue>. Buttons: <button value="ok"> / value="cancel".
export function showDialog(html, { wide = false, onOpen } = {}) {
  const d = document.getElementById("dlg");
  d.className = "dlg" + (wide ? " wide" : "");
  d.innerHTML = html;
  d.returnValue = "";
  return new Promise((resolve) => {
    d.addEventListener("close", () => resolve(d.returnValue), { once: true });
    d.showModal();
    onOpen?.(d);
  });
}
export async function confirmDialog({ title, body, ok = "OK", cancel = "Cancel", danger = false }) {
  const r = await showDialog(`<form method="dialog">
    <header><h2>${esc(title)}</h2></header>
    <div class="body"><p style="margin:0">${body}</p></div>
    <footer><button class="btn ghost" value="cancel">${esc(cancel)}</button><button class="btn ${danger ? "danger" : "primary"}" value="ok" autofocus>${esc(ok)}</button></footer>
  </form>`);
  return r === "ok";
}

// ------------------------------------------------------------------------------- tooltips
let ttTimer = 0;
let ttWarm = 0;
export function initTooltips() {
  const tip = document.getElementById("tooltip");
  document.addEventListener("pointerover", (e) => {
    const el = e.target.closest?.("[data-tip]");
    if (!el) return;
    clearTimeout(ttTimer);
    const show = () => {
      tip.textContent = el.dataset.tip;
      tip.hidden = false;
      const r = el.getBoundingClientRect();
      const tr = tip.getBoundingClientRect();
      let x = r.left + r.width / 2 - tr.width / 2;
      x = Math.max(8, Math.min(window.innerWidth - tr.width - 8, x));
      let y = r.bottom + 6;
      if (y + tr.height > window.innerHeight - 8) y = r.top - tr.height - 6;
      tip.style.left = `${x}px`;
      tip.style.top = `${y}px`;
      ttWarm = Date.now();
    };
    ttTimer = setTimeout(show, Date.now() - ttWarm < 800 ? 0 : 600);
  });
  document.addEventListener("pointerout", (e) => {
    if (!e.target.closest?.("[data-tip]")) return;
    clearTimeout(ttTimer);
    tip.hidden = true;
    ttWarm = Date.now();
  });
}
// Free-floating tooltip for the map canvas.
export function floatTip(html, x, y) {
  const tip = document.getElementById("tooltip");
  if (html == null) {
    tip.hidden = true;
    return;
  }
  tip.innerHTML = html;
  tip.hidden = false;
  const tr = tip.getBoundingClientRect();
  let left = x + 14;
  if (left + tr.width > window.innerWidth - 8) left = x - tr.width - 14;
  let top = y + 14;
  if (top + tr.height > window.innerHeight - 8) top = y - tr.height - 14;
  tip.style.left = `${left}px`;
  tip.style.top = `${top}px`;
}

// --------------------------------------------------------------------------------- popover
let openPop = null;
export function popover(anchor, html, onChange) {
  closePopover();
  const p = document.createElement("div");
  p.className = "popover";
  p.innerHTML = html;
  document.body.appendChild(p);
  const r = anchor.getBoundingClientRect();
  const pr = p.getBoundingClientRect();
  p.style.left = `${Math.min(r.left, window.innerWidth - pr.width - 8)}px`;
  p.style.top = `${Math.min(r.bottom + 4, window.innerHeight - pr.height - 8)}px`;
  p.addEventListener("change", (e) => onChange?.(e, p));
  openPop = { p, anchor };
  setTimeout(() => {
    p.querySelector("input,button")?.focus();
  });
  return p;
}
export function closePopover() {
  if (openPop) {
    openPop.p.remove();
    openPop = null;
  }
}
document.addEventListener("pointerdown", (e) => {
  if (openPop && !openPop.p.contains(e.target) && !openPop.anchor.contains(e.target)) closePopover();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && openPop) {
    const a = openPop.anchor;
    closePopover();
    a.focus();
  }
});

// Base64 -> Uint8Array
export function b64(s) {
  const bin = atob(s || "");
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Hex dump lines (16 bytes per row) as HTML.
export function hexDump(bytesArr, baseOffset, highlightZeros = true) {
  const rows = [];
  for (let i = 0; i < bytesArr.length; i += 16) {
    const off = (baseOffset + i).toString(16).toUpperCase().padStart(10, "0");
    let hex = "";
    let asc = "";
    for (let j = 0; j < 16; j++) {
      if (i + j < bytesArr.length) {
        const b = bytesArr[i + j];
        const h = b.toString(16).toUpperCase().padStart(2, "0");
        hex += (highlightZeros && b === 0 ? `<span class="z">${h}</span>` : h) + (j === 7 ? "  " : " ");
        asc += b >= 32 && b < 127 ? esc(String.fromCharCode(b)) : ".";
      } else {
        hex += "   " + (j === 7 ? " " : "");
      }
    }
    rows.push(`<span class="off">${off}</span>  ${hex} <span class="asc">${asc}</span>`);
  }
  return rows.join("\n");
}
