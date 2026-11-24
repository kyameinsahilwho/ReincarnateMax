// A scan session: live progress, the recovery workspace (reconstructed folder tree, list or
// gallery, filters, inspector with previews/details/hex), the Recovery Map tab with the region
// inspector, found partitions, the scan log, and the recover dialog.
import {
  S, App, esc, icon, bytes, int, date, ago, plural, duration, rate, cond, CAT, STATUS_LABEL, ORIGIN_LABEL, FLAGS, invoke, toast, toastError,
  errText, needsAdmin, showDialog, confirmDialog, popover, closePopover, patch, restoringFocus, b64, hexDump, fileUrl, save, load, $, list as listText, scanStarted, runningJobs,
} from "./core.js";
import { RecoveryMap, KIND_TEXT } from "./map.js";
import { describeSource, legend, mapStats, modeLabel, stateLabel, stagePct, adminToast } from "./start.js";

const PAGE = 200;
let G = 0; // query generation
let wsMap = null;
let liveTimer = 0;

function ws() {
  const id = S.view.id;
  if (!S.ws || S.ws.id !== id) {
    const prefs = load("ws", {});
    S.ws = {
      id,
      tab: S.view.tab || "files",
      folder: null,
      search: "",
      cats: [],
      statuses: [],
      conds: [],
      size: "any",
      dateField: "modified",
      dateFrom: null,
      dateTo: null,
      dupOnly: false,
      sort: prefs.sort || "condition",
      desc: prefs.desc ?? false,
      mode: prefs.mode || "list",
      items: [],
      total: 0,
      totalSize: 0,
      loaded: false,
      sel: new Map(), // id -> size
      focus: null,
      detail: null,
      insp: null,
      inspTab: "preview",
      open: new Set([""]),
      kids: new Map(),
      mapStack: [],
      region: null,
      hexOff: 0,
    };
  }
  if (S.view.tab && S.view.tab !== S.ws.tab) S.ws.tab = S.view.tab;
  return S.ws;
}

export function sessionDetail(id) {
  return S.sessionCache[id];
}
export async function loadSession(id, force) {
  if (!force && S.sessionCache[id]) return S.sessionCache[id];
  const d = await invoke("get_session", { sessionId: id });
  S.sessionCache[id] = d;
  return d;
}

function query(extra = {}) {
  const w = S.ws;
  const q = { sort: w.sort, desc: w.desc };
  if (w.folder != null) {
    q.folder = w.folder;
    q.recursive = true;
  }
  if (w.search.trim()) q.search = w.search.trim();
  if (w.cats.length) q.categories = w.cats;
  if (w.statuses.length) q.statuses = w.statuses;
  if (w.conds.length) q.conditions = w.conds;
  const MB = 1024 * 1024;
  if (w.size === "small") q.maxSize = MB - 1;
  if (w.size === "medium") Object.assign(q, { minSize: MB, maxSize: 100 * MB });
  if (w.size === "large") q.minSize = 100 * MB + 1;
  if (w.dateFrom) q.dateFrom = w.dateFrom;
  if (w.dateTo) q.dateTo = w.dateTo;
  if (w.dateFrom || w.dateTo) q.dateField = w.dateField;
  if (w.dupOnly) q.duplicatesOnly = true;
  return Object.assign(q, extra);
}
function filterQuery() {
  // Same filters without the folder (for the tree counts).
  const q = query();
  delete q.folder;
  delete q.recursive;
  delete q.sort;
  delete q.desc;
  return q;
}

async function runQuery({ append = false, keepCount = false } = {}) {
  const w = S.ws;
  const g = ++G;
  const limit = keepCount ? Math.min(2000, Math.max(PAGE, w.items.length)) : PAGE;
  try {
    const page = await invoke("query_files", { sessionId: w.id, query: query({ offset: append ? w.items.length : 0, limit }) });
    if (g !== G || S.ws !== w) return;
    w.items = append ? w.items.concat(page.items) : page.items;
    w.total = page.total;
    w.totalSize = page.totalSize;
    w.loaded = true;
    w.error = null;
  } catch (e) {
    if (g !== G || S.ws !== w) return;
    w.error = errText(e);
    w.loaded = true;
  }
  renderCenter();
}

async function loadKids(path) {
  const w = S.ws;
  try {
    const kids = await invoke("folder_children", { sessionId: w.id, parent: path, query: filterQuery() });
    if (S.ws !== w) return;
    w.kids.set(path, kids);
    renderTree();
  } catch (e) {
    w.kids.set(path, []);
    renderTree();
  }
}

// ------------------------------------------------------------------------------------ render
export function renderSession() {
  const w = ws();
  const d = sessionDetail(w.id);
  if (!d) {
    loadSession(w.id)
      .then(() => App.renderMain())
      .catch((e) => {
        toastError(e);
        App.navigate({ name: "home" });
      });
    return { head: `<header class="page-head"><h1>Loading scan…</h1></header>`, body: "" };
  }
  const s = d.summary;
  const live = S.live[w.id];
  const state = live?.state || s.state;
  const running = state === "running" || state === "paused";
  const info = describeSource(s.source);

  const tabs = [
    ["files", `Files <span class="n" id="files-count">${int(live?.filesFound ?? s.files)}</span>`],
    ["map", "Recovery Map"],
  ];
  if (d.partitions) tabs.push(["partitions", `Partitions <span class="n">${d.partitions.entries.length}</span>`]);
  tabs.push(["log", "Log"]);

  const head = `<header class="page-head">
    <span class="head-icon">${icon(info.icon || "hard-drive", "l")}</span>
    <div class="ellipsis" style="max-width:340px"><h1 class="ellipsis">${esc(s.label)}</h1><div class="sub ellipsis">${esc(d.options?.folder ? "Folder scan" : modeLabel(s.mode))} · ${esc(info.title)} · ${esc(date(s.created, true))}</div></div>
    <div id="sess-progress" class="sess-head-progress">${progressHtml(d, live)}</div>
    <div class="actions" id="sess-actions">${actionsHtml(d, state, live)}</div>
  </header>
  <div class="tabs" role="tablist">${tabs.map(([k, l]) => `<button role="tab" data-action="ws-tab" data-tab="${k}" aria-selected="${w.tab === k}">${l}</button>`).join("")}</div>`;

  let body = "";
  if (state === "interrupted")
    body += `<div class="callout warn" style="margin:12px 24px 0">${icon("circle-alert")}<div class="grow"><b>This scan stopped before it finished</b> — MAX was closed or the PC restarted. Everything found so far is kept; resuming continues where it stopped.</div><button class="btn small primary" data-action="resume-scan">Resume scan</button></div>`;
  if (state === "failed" && d.error) body += `<div class="callout danger" style="margin:12px 24px 0">${icon("circle-x")}<div>${esc(d.error)}</div></div>`;
  const notes = (d.notes || []).slice(0, 4);
  if (notes.length && w.tab !== "log")
    body += `<div class="callout notes" style="margin:10px 24px 0">${icon("info")}<div class="grow">${notes.map((n) => `<div>${esc(n)}</div>`).join("")}</div></div>`;

  if (w.tab === "files") body += filesTab(d);
  else if (w.tab === "map") body += `<div class="maptab"><div class="map-wrap"><div class="map-top"><div class="map-crumbs" id="map-crumbs"></div><div class="legend">${legend()}</div></div><div class="map-canvas-box" id="ws-map"></div><div class="map-stats" id="ws-map-stats"></div><p class="map-hint">Click a square to see what's there; drag across squares to select a range. Double-click or Ctrl + scroll to zoom in.</p></div><aside class="region" id="region">${regionHtml()}</aside></div>`;
  else if (w.tab === "partitions") body += partitionsTab(d);
  else if (w.tab === "log") body += `<div class="log" id="log">Loading the log…</div>`;
  return {
    head,
    body: `<div style="display:flex;flex-direction:column;flex:1;min-height:0">${body}</div>`,
    after: () => afterSession(d),
    leave: () => {
      wsMap?.destroy();
      wsMap = null;
      clearInterval(liveTimer);
      liveTimer = 0;
    },
  };
}

function progressHtml(d, live) {
  const s = d.summary;
  const state = live?.state || s.state;
  if (state !== "running" && state !== "paused") {
    if (state === "done")
      return `<div class="prog-line"><span><b>${int(s.files)}</b> files found, <b>${bytes(s.bytes)}</b></span>${s.badBytes ? `<span class="tag danger">${bytes(s.badBytes)} unreadable</span>` : ""}<span class="faint">Finished ${esc(ago(s.updated))}</span></div>`;
    return `<div class="prog-line"><span>${esc(stateLabel(state))}</span><span><b>${int(s.files)}</b> files found</span></div>`;
  }
  const stages = d.stages.length ? d.stages : [];
  const idx = live?.stageIndex ?? 0;
  const pct = live ? stagePct(live) : 0;
  const stageLine = stages
    .map((st, i) => {
      const cls = i < idx || st.state === "done" ? "done" : i === idx ? "running" : "";
      return `${i ? '<span class="sep"></span>' : ""}<span class="st ${cls}">${cls === "done" ? icon("check", "s") : ""}${esc(st.label)}</span>`;
    })
    .join("");
  const within = live && live.total ? `${int(Math.min(100, Math.floor((live.done / live.total) * 100)))}% of this step` : "";
  return `<div class="stages">${stageLine}</div>
    <div class="pbar${state === "paused" ? " paused" : ""}" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${pct}"><i style="width:${pct}%"></i></div>
    <div class="prog-line"><span><b>${pct}%</b>${live?.stopping ? " · Stopping… saving what was found" : state === "paused" ? " · Paused" : ""}</span><span><b>${int(live?.filesFound ?? s.files)}</b> files found</span>${
      live?.bytesPerSec && state === "running" ? `<span>${rate(live.bytesPerSec)}</span>` : ""
    }${live?.etaSeconds != null && state === "running" ? `<span>About ${duration(live.etaSeconds)} left</span>` : within ? `<span>${within}</span>` : ""}${live?.badBytes ? `<span class="tag danger">${bytes(live.badBytes)} unreadable</span>` : ""}</div>`;
}

function actionsHtml(d, state, live) {
  // Stop was pressed: the scan is saving what it found. Nothing more to press until scan-done.
  if ((state === "running" || state === "paused") && live?.stopping)
    return `<button class="btn ghost" data-action="stop-scan" disabled aria-disabled="true">${icon("loader-circle", "s spin")} Stopping…</button>`;
  if (state === "running")
    return `<button class="btn" data-action="pause-scan">${icon("pause", "s")} Pause</button><button class="btn ghost" data-action="stop-scan">${icon("square", "s")} Stop</button>`;
  if (state === "paused") return `<button class="btn primary" data-action="unpause-scan">${icon("play", "s")} Continue</button><button class="btn ghost" data-action="stop-scan">${icon("square", "s")} Stop</button>`;
  const more = `<button class="btn icon ghost" data-action="sess-more" data-tip="More" aria-label="More actions">${icon("ellipsis")}</button>`;
  const resume = state === "cancelled" || state === "interrupted" ? `<button class="btn" data-action="resume-scan">${icon("play", "s")} Resume scan</button>` : "";
  return `${resume}<button class="btn" data-action="export-report">${icon("file-text", "s")} Report</button>${more}`;
}

function filesTab(d) {
  const w = S.ws;
  const insp = w.focus != null;
  return `<div class="ws${insp ? "" : " no-insp"}" id="ws">
    <nav class="tree" id="tree" aria-label="Reconstructed folders"></nav>
    <section class="center">
      <div class="toolbar" id="toolbar">${toolbarHtml(d)}</div>
      <div class="result-line" id="result-line"></div>
      <div id="listbox" style="flex:1;min-height:0;display:flex;flex-direction:column"></div>
      <div class="selbar" id="selbar"></div>
    </section>
    ${insp ? `<aside class="insp" id="insp" aria-label="File details"></aside>` : ""}
  </div>`;
}

function catCounts(d) {
  return d.counts?.byCategory || {};
}
// The search box sits outside #ws-chips so re-rendering the filters never replaces the input the
// user is typing in.
function toolbarHtml(d) {
  const w = S.ws;
  return `<div class="search"><input type="search" id="ws-search" placeholder="Search names, or *.jpg" value="${esc(w.searchDraft ?? w.search)}" aria-label="Search files" autocomplete="off" spellcheck="false">${icon("search", "s")}</div>
    <div id="ws-chips" class="contents">${chipsHtml(d)}</div>`;
}
function chipsHtml(d) {
  const w = S.ws;
  const cc = catCounts(d);
  const total = Object.values(cc).reduce((a, [n]) => a + n, 0);
  const catBtn = (k, label, n) => `<button data-action="ws-cat" data-key="${k}" aria-pressed="${k === "" ? !w.cats.length : w.cats.includes(k)}">${label}${n != null ? ` <span class="n">${int(n)}</span>` : ""}</button>`;
  const cats = ["photo", "video", "audio", "document", "archive", "other"].filter((k) => (cc[k]?.[0] || 0) > 0);
  const active = (b) => (b ? ' aria-pressed="true"' : "");
  const condN = w.conds.length;
  const statN = w.statuses.length;
  return `<div class="seg" role="group" aria-label="Kind">${catBtn("", "All", total)}${cats.map((k) => catBtn(k, CAT[k].label, cc[k][0])).join("")}</div>
    <button class="chip" data-action="ws-pop" data-key="cond"${active(condN)}>${icon("activity", "s")}Condition${condN ? ` <span class="n">${condN}</span>` : ""}${icon("chevron-down", "s")}</button>
    <button class="chip" data-action="ws-pop" data-key="status"${active(statN)}>${icon("layers", "s")}Found as${statN ? ` <span class="n">${statN}</span>` : ""}${icon("chevron-down", "s")}</button>
    <button class="chip" data-action="ws-pop" data-key="size"${active(w.size !== "any")}>${icon("ruler", "s")}${esc({ any: "Size", small: "Under 1 MB", medium: "1–100 MB", large: "Over 100 MB" }[w.size])}${icon("chevron-down", "s")}</button>
    <button class="chip" data-action="ws-pop" data-key="date"${active(w.dateFrom || w.dateTo)}>${icon("calendar", "s")}${w.dateFrom || w.dateTo ? esc(dateRangeLabel()) : "Date"}${icon("chevron-down", "s")}</button>
    <button class="chip" data-action="ws-dups"${active(w.dupOnly)} data-tip="Show only files with identical content">${icon("copy", "s")}Duplicates</button>
`;
}
function dateRangeLabel() {
  const w = S.ws;
  const f = w.dateFrom ? date(w.dateFrom) : "…";
  const t = w.dateTo ? date(w.dateTo) : "…";
  return `${{ modified: "Modified", created: "Created", deleted: "Deleted" }[w.dateField]} ${f} – ${t}`;
}

function renderCenter() {
  const w = S.ws;
  if (!w || S.view.name !== "session" || w.tab !== "files") return;
  const rl = document.getElementById("result-line");
  const box = document.getElementById("listbox");
  if (!box) return;
  const filtered = w.search || w.cats.length || w.statuses.length || w.conds.length || w.size !== "any" || w.dateFrom || w.dateTo || w.dupOnly;
  if (rl)
    patch(
      rl,
      w.loaded
        ? `<span><b>${plural(w.total, "file")}</b> · ${bytes(w.totalSize)}${w.folder != null ? ` in <b>${esc(folderName(w.folder))}</b>` : ""}</span>${
            filtered ? `<button class="btn small ghost" data-action="ws-clear">${icon("x", "s")} Clear filters</button>` : ""
          }<span class="grow" style="flex:1"></span>${sortHtml()}`
        : "",
    );
  let h;
  if (!w.loaded) h = `<div class="empty"><p>${icon("loader-circle", "spin")} Loading files…</p></div>`;
  else if (w.error) h = `<div class="empty"><h3>Couldn't load the files</h3><p>${esc(w.error)}</p></div>`;
  else if (!w.items.length) h = emptyHtml(filtered);
  else if (w.mode === "gallery") h = galleryHtml();
  else h = listHtml();
  restoringFocus(() => {
    if (patch(box, h)) observeVideos(box);
  });
  renderSelbar();
}

function emptyHtml(filtered) {
  const d = sessionDetail(S.ws.id);
  const live = S.live[S.ws.id];
  if (filtered)
    return `<div class="empty"><h3>No files match${S.ws.search ? ` “${esc(S.ws.search)}”` : ""}</h3><p>Try fewer filters, another folder, or search part of the name.</p><button class="btn" data-action="ws-clear">Clear filters</button></div>`;
  if (live && (live.state === "running" || live.state === "paused")) return `<div class="empty"><h3>Nothing found yet</h3><p>Files appear here as the scan finds them.</p></div>`;
  return `<div class="empty"><h3>No recoverable files were found</h3><p>${
    d?.summary.mode === "quick" ? "The file system has no records of deleted files left. A deep scan reads every sector and can still find files by their content." : "Nothing recognisable was left on this source."
  }</p>${d?.summary.mode === "quick" ? `<button class="btn primary" data-action="deep-from-session">${icon("radar", "s")} Run a deep scan</button>` : ""}</div>`;
}

function sortHtml() {
  const w = S.ws;
  const opts = [
    ["condition", "Condition"],
    ["name", "Name"],
    ["size", "Size"],
    ["modified", "Modified"],
    ["deleted", "Deleted"],
    ["type", "Type"],
    ["folder", "Folder"],
  ];
  return `<label class="row" style="gap:6px;font-size:var(--fs-s)">Sort <select id="ws-sort" aria-label="Sort by" style="height:28px">${opts
    .map(([k, l]) => `<option value="${k}" ${w.sort === k ? "selected" : ""}>${l}</option>`)
    .join("")}</select></label><button class="btn small icon ghost" data-action="ws-desc" data-tip="${w.desc ? "Descending" : "Ascending"}" aria-label="Reverse order">${icon(w.desc ? "arrow-down" : "arrow-up", "s")}</button>
    <div class="seg" role="group" aria-label="View">
      <button data-action="ws-mode" data-mode="list" aria-pressed="${w.mode === "list"}" data-tip="List">${icon("list", "s")}<span class="sr">List</span></button>
      <button data-action="ws-mode" data-mode="gallery" aria-pressed="${w.mode === "gallery"}" data-tip="Gallery">${icon("layout-grid", "s")}<span class="sr">Gallery</span></button>
    </div>`;
}

function rowFlags(f) {
  const t = [];
  if (f.flags & FLAGS.EXT_MISMATCH) t.push(`<span class="tag uv" data-tip="Its content is a different type than its extension says.">${esc((f.typeId || "").toUpperCase())}</span>`);
  if (f.dupGroup != null) t.push(`<span class="tag" data-tip="Identical content to other files">Duplicate</span>`);
  if (f.status === "recycleBin") t.push(`<span class="tag ok">Recycle Bin</span>`);
  return t.join("");
}
function catIcon(f) {
  return CAT[f.category]?.icon || "file";
}
function listHtml() {
  const w = S.ws;
  const th = (k, l, cls = "") =>
    `<span class="${cls}"><button data-action="ws-sortby" data-key="${k}">${l}${w.sort === k ? icon(w.desc ? "arrow-down" : "arrow-up", "s") : ""}</button></span>`;
  const allSel = w.items.length && w.items.every((f) => w.sel.has(f.id));
  let h = `<div class="list" id="list" role="grid" aria-label="Found files" aria-rowcount="${w.total}"><div class="lrow head" role="row"><span><input type="checkbox" data-action="ws-selpage" aria-label="Select all shown" ${allSel ? "checked" : ""}></span>${th("name", "Name")}${th("folder", "Original folder")}${th("size", "Size", "sz")}${th(dateSort(), dateHead())}${th("condition", "Condition")}</div>`;
  for (const f of w.items) {
    const sel = w.sel.has(f.id);
    const dt = f[dateSort()] ?? f.modified;
    h += `<div class="lrow${w.focus === f.id ? " focus" : ""}" role="row" data-action="ws-row" data-id="${f.id}" aria-selected="${sel}" tabindex="-1">
      <span><input type="checkbox" data-action="ws-check" data-id="${f.id}" ${sel ? "checked" : ""} aria-label="Select ${esc(f.name)}"></span>
      <span class="nm">${icon(catIcon(f))}<span class="t" title="${esc(f.name)}">${esc(f.name)}</span>${rowFlags(f)}</span>
      <span class="fold" title="${esc(f.folder || "\\")}"><bdi>${esc(f.folder || "\\")}</bdi></span>
      <span class="sz">${bytes(f.size)}</span>
      <span class="dt">${esc(date(dt))}</span>
      <span title="${esc(f.note)}">${cond(f.condition)}</span></div>`;
  }
  h += `</div>`;
  if (w.items.length < w.total) h += `<div class="list-more"><button class="btn" data-action="ws-more">Show ${int(Math.min(PAGE, w.total - w.items.length))} more of ${int(w.total - w.items.length)}</button></div>`;
  return h;
}
function dateSort() {
  return S.ws.sort === "deleted" || S.ws.sort === "created" ? S.ws.sort : "modified";
}
function dateHead() {
  return { modified: "Modified", deleted: "Deleted", created: "Created" }[dateSort()];
}

function galleryHtml() {
  const w = S.ws;
  let h = `<div class="gallery" id="list" role="grid" aria-label="Found files">`;
  for (const f of w.items) {
    const sel = w.sel.has(f.id);
    let th;
    if (f.category === "photo") th = `<img loading="lazy" decoding="async" alt="" src="${esc(fileUrl(w.id, f.id, 256))}" data-fallback="${catIcon(f)}">`;
    else if (f.category === "video" && /^(mp4|m4v|mov|webm)$/.test(f.typeId)) th = `<video muted preload="none" data-src="${esc(fileUrl(w.id, f.id))}#t=1"></video><span class="play">${icon("play", "s")}</span>`;
    else th = icon(catIcon(f), "xl");
    h += `<div class="tile${w.focus === f.id ? " focus" : ""}" role="gridcell" data-action="ws-row" data-id="${f.id}" aria-selected="${sel}" tabindex="-1">
      <input type="checkbox" class="cb" data-action="ws-check" data-id="${f.id}" ${sel ? "checked" : ""} aria-label="Select ${esc(f.name)}">
      <div class="thumb">${th}${f.condition === "partial" ? `<span class="badge tag warn">Partial</span>` : ""}</div>
      <div class="cap"><span class="t" title="${esc(f.name)}">${esc(f.name)}</span>${cond(f.condition, false)}<small>${bytes(f.size)}${f.meta?.width ? ` · ${esc(f.meta.width)}×${esc(f.meta.height)}` : ""}</small></div></div>`;
  }
  h += `</div>`;
  if (w.items.length < w.total) h += `<div class="list-more"><button class="btn" data-action="ws-more">Show ${int(Math.min(PAGE, w.total - w.items.length))} more of ${int(w.total - w.items.length)}</button></div>`;
  return h;
}

// Videos load their first frame only when scrolled into view.
let vidObs = null;
function observeVideos(root) {
  vidObs?.disconnect();
  const vids = root.querySelectorAll("video[data-src]");
  root.querySelectorAll("img[data-fallback]").forEach((img) => {
    img.onerror = () => {
      const p = img.parentElement;
      if (p) p.innerHTML = icon(img.dataset.fallback, "xl");
    };
  });
  if (!vids.length) return;
  vidObs = new IntersectionObserver((ents) => {
    for (const e of ents)
      if (e.isIntersecting) {
        const v = e.target;
        v.src = v.dataset.src;
        v.preload = "metadata";
        v.removeAttribute("data-src");
        vidObs.unobserve(v);
      }
  });
  vids.forEach((v) => vidObs.observe(v));
}

function renderSelbar() {
  const w = S.ws;
  const el = document.getElementById("selbar");
  if (!el) return;
  const n = w.sel.size;
  let size = 0;
  for (const v of w.sel.values()) size += v || 0;
  const h = n
    ? `<span><b>${plural(n, "file")}</b> selected · ${bytes(size)}</span>${
        n < w.total ? `<button class="btn small ghost" data-action="ws-selall">Select all ${int(w.total)} matching</button>` : ""
      }<button class="btn small ghost" data-action="ws-selnone">Clear selection</button><span class="grow"></span><button class="btn primary" data-action="recover-selected">${icon("download", "s")} Recover ${plural(n, "file")}</button>`
    : `<span class="muted">Select files to recover them${w.total ? ", or recover everything shown" : ""}.</span><span class="grow"></span>${
        w.total ? `<button class="btn" data-action="recover-all">${icon("download", "s")} Recover all ${int(w.total)} (${bytes(w.totalSize)})</button>` : ""
      }`;
  restoringFocus(() => patch(el, h));
}

function folderName(p) {
  if (!p) return "All files";
  return p.split("\\").filter(Boolean).pop() || "\\";
}

function renderTree() {
  const w = S.ws;
  const el = document.getElementById("tree");
  if (!el) return;
  const d = sessionDetail(w.id);
  const top = `<button class="tree-node" data-action="ws-folder" data-path=""${w.folder == null ? ' aria-current="true"' : ""}><span class="tw">${icon("files", "s")}</span><span class="nm">All files</span><span class="ct">${int(d?.summary.files || 0)}</span></button>`;
  const node = (n, depth) => {
    const open = w.open.has(n.path);
    const kids = w.kids.get(n.path);
    const label = iconFor(n.path);
    let h = `<button class="tree-node${open ? " open" : ""}" data-action="ws-folder" data-path="${esc(n.path)}"${w.folder === n.path ? ' aria-current="true"' : ""} title="${esc(n.path)}">${
      n.hasChildren ? `<span class="tw" data-action="ws-twisty" data-path="${esc(n.path)}" role="button" aria-label="${open ? "Collapse" : "Expand"}">${icon("chevron-right")}</span>` : `<span class="tw">${icon(label, "s")}</span>`
    }<span class="nm">${esc(n.name || n.path)}</span><span class="ct">${int(n.files)}</span></button>`;
    if (open && n.hasChildren) {
      h += `<div class="tree-kids">${kids ? kids.map((k) => node(k, depth + 1)).join("") : `<div class="tree-node faint">${icon("loader-circle", "spin s")} Loading…</div>`}</div>`;
    }
    return h;
  };
  const roots = w.kids.get("");
  const h = top + (roots ? roots.map((n) => node(n, 0)).join("") : `<div class="tree-node faint">${icon("loader-circle", "spin s")}</div>`);
  restoringFocus(() => patch(el, h));
}
function iconFor(path) {
  if (/^\\Found by signature/i.test(path)) return "binary";
  if (/^\\Lost folders/i.test(path)) return "folder-search";
  if (/Recycle/i.test(path)) return "trash-2";
  return "folder";
}

// --------------------------------------------------------------------------------- inspector
async function focusFile(id, { scroll = false } = {}) {
  const w = S.ws;
  const had = w.focus != null;
  w.focus = id;
  w.detail = null;
  w.insp = null;
  w.doc = null;
  w.hexOff = 0;
  w.hexHtml = null;
  document.querySelectorAll("#list .focus").forEach((n) => n.classList.remove("focus"));
  const row = document.querySelector(`#list [data-id="${id}"]`);
  row?.classList.add("focus");
  if (scroll) row?.scrollIntoView({ block: "nearest" });
  // The first focus adds the inspector column: re-render the page, then fill it.
  if (!had) App.renderMain();
  else renderInsp();
  try {
    const detail = await invoke("file_detail", { sessionId: w.id, id });
    if (w.focus !== id) return;
    w.detail = detail;
    renderInsp();
    const insp = await invoke("inspect_file", { sessionId: w.id, id }).catch((e) => ({ error: errText(e) }));
    if (w.focus !== id) return;
    w.insp = insp;
    if (!insp.error && (insp.previewKind === "document" || insp.previewKind === "text")) {
      w.doc = await invoke("preview_document", { sessionId: w.id, id }).catch((e) => ({ kind: "none", error: errText(e) }));
      if (w.focus !== id) return;
    } else w.doc = null;
    renderInsp();
  } catch (e) {
    if (w.focus === id) {
      w.detail = { error: errText(e) };
      renderInsp();
    }
  }
}

function renderInsp() {
  const w = S.ws;
  const el = document.getElementById("insp");
  if (!el) return;
  const row = w.items.find((f) => f.id === w.focus) || w.detail?.row;
  if (!row) {
    patch(el, `<div class="insp-scroll"><p class="muted">${w.detail?.error ? esc(w.detail.error) : "Loading…"}</p></div>`);
    return;
  }
  const tabs = ["preview", "details", "hex"].map((k) => `<button data-action="insp-tab" data-tab="${k}" aria-selected="${w.inspTab === k}">${{ preview: "Preview", details: "Details", hex: "Hex" }[k]}</button>`).join("");
  let body = "";
  const tags = [];
  if (row.flags & FLAGS.EXT_MISMATCH) tags.push(`<span class="tag uv">Content is ${esc((row.typeId || "").toUpperCase())}</span>`);
  if (row.flags & FLAGS.NAME_GUESSED) tags.push(`<span class="tag">Name rebuilt</span>`);
  if (row.flags & FLAGS.FROM_RECYCLE_INFO) tags.push(`<span class="tag ok">Name from Recycle Bin record</span>`);
  if (row.flags & FLAGS.OVERWRITTEN) tags.push(`<span class="tag warn">Partly overwritten</span>`);
  if (row.flags & FLAGS.ZEROED) tags.push(`<span class="tag warn">Erased by TRIM</span>`);
  if (row.flags & FLAGS.ENCRYPTED) tags.push(`<span class="tag warn">EFS encrypted</span>`);
  if (row.flags & FLAGS.BAD_SECTORS) tags.push(`<span class="tag danger">Unreadable sectors</span>`);
  if (row.fragmented) tags.push(`<span class="tag">Fragmented</span>`);
  if (row.flags & FLAGS.SNAPSHOT) tags.push(`<span class="tag">From a restore point</span>`);
  if (row.dupGroup != null) tags.push(`<span class="tag">Duplicate</span>`);

  const head = `<div><h2>${esc(row.name)}</h2><div class="row" style="margin-top:6px;flex-wrap:wrap;gap:6px">${cond(row.condition)}${tags.join("")}</div><p class="note" style="margin:6px 0 0">${esc(w.insp?.validation?.condition === "partial" && row.condition !== "partial" ? w.insp.validation.note : row.note)}</p></div>`;
  if (w.inspTab === "preview") body = head + `<div class="preview" id="preview">${previewHtml(row)}</div>` + quickFacts(row);
  else if (w.inspTab === "details") body = head + detailsHtml(row);
  else body = head + `<div id="hexbox">${w.hexHtml || `<p class="muted">Loading bytes…</p>`}</div>`;
  const h = `<div class="insp-tabs" role="tablist">${tabs}<span style="flex:1"></span><button class="btn small icon ghost" data-action="insp-close" aria-label="Close details" data-tip="Close">${icon("x", "s")}</button></div>
    <div class="insp-scroll">${body}</div>
    <div class="insp-foot"><button class="btn primary" data-action="recover-one">${icon("download", "s")} Recover this file</button><button class="btn icon" data-action="file-on-map" data-tip="Show on the Recovery Map" aria-label="Show on the Recovery Map">${icon("map")}</button></div>`;
  restoringFocus(() => {
    if (patch(el, h)) {
      const img = el.querySelector("#preview img");
      if (img)
        img.onerror = () => {
          const p = document.getElementById("preview");
          if (p) p.innerHTML = noPreview("This image can't be shown — its data may be damaged or erased.");
        };
    }
  });
  if (w.inspTab === "hex" && !w.hexHtml) loadHex();
}

function noPreview(text) {
  return `<div class="none">${icon("eye", "l")}<span>${esc(text)}</span></div>`;
}
function previewHtml(row) {
  const w = S.ws;
  const kind = w.insp?.previewKind || guessKind(row);
  const url = fileUrl(w.id, row.id);
  const incomplete = w.insp?.validation && !w.insp.validation.complete ? `<span class="preview-flag tag warn">Preview incomplete</span>` : "";
  if (row.flags & FLAGS.ZEROED) return noPreview("This file's data reads as zeros, so there is nothing to show.");
  const thumbOnly = w.insp?.thumbOnly ?? /^(cr2|cr3|nef|nrw|arw|dng|orf|rw2|raf|pef|srf|sr2|x3f|tif|tiff|psd)$/.test(row.typeId);
  if (kind === "image") return `<img alt="" src="${esc(thumbOnly ? fileUrl(w.id, row.id, 512) : url)}">${incomplete}`;
  if (kind === "video") return `<video controls preload="metadata" src="${esc(url)}"></video>${incomplete}`;
  if (kind === "audio") return `<div style="padding:24px 12px;width:100%;display:grid;gap:10px;justify-items:center">${icon("music", "xl")}<audio controls preload="metadata" src="${esc(url)}"></audio></div>${incomplete}`;
  if (kind === "pdf") return `<iframe title="PDF preview" src="${esc(url)}"></iframe>`;
  if (kind === "document" || kind === "text") {
    if (!w.insp) return noPreview("Loading preview…");
    const doc = w.doc;
    if (!doc || doc.kind === "none") return noPreview(doc?.error || "No text could be extracted from this document.");
    if (doc.kind === "sheet")
      return `<div class="sheet">${doc.sheets
        .map((sh) => `<div class="faint" style="padding:6px 8px;font-size:var(--fs-xs)">${esc(sh.name)}</div><table>${sh.rows.map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`).join("")}</table>`)
        .join("")}</div>`;
    return `${doc.note ? `<span class="preview-flag tag">${esc(doc.note)}</span>` : ""}<div class="doc"${doc.note ? ' style="padding-top:34px"' : ""}>${esc(doc.text || "")}${doc.truncated ? "\n…" : ""}</div>`;
  }
  if (!w.insp) return noPreview("Loading preview…");
  return noPreview("There's no preview for this type. The Hex tab shows its raw bytes.");
}
function guessKind(row) {
  if (row.category === "photo") return "image";
  if (row.category === "video") return /^(mp4|m4v|mov|webm)$/.test(row.typeId) ? "video" : "hex";
  if (row.category === "audio") return /^(mp3|wav|flac|ogg|m4a|aac|opus)$/.test(row.typeId) ? "audio" : "hex";
  if (row.typeId === "pdf") return "pdf";
  if (row.category === "document") return "document";
  return "hex";
}
function quickFacts(row) {
  const m = row.meta || {};
  const rows = [
    ["Size", bytes(row.size)],
    ["Folder", row.folder || "\\"],
    m.width ? ["Dimensions", `${m.width} × ${m.height}`] : null,
    m.camera ? ["Camera", m.camera] : null,
    m.taken ? ["Taken", m.taken] : null,
    m.title ? ["Title", m.title] : null,
    m.artist ? ["Artist", m.artist] : null,
    m.duration ? ["Duration", duration(Number(m.duration))] : null,
    m.pages ? ["Pages", m.pages] : null,
    ["Modified", date(row.modified, true)],
    row.deleted ? ["Deleted", date(row.deleted, true)] : null,
  ].filter(Boolean);
  return `<dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>`;
}
function detailsHtml(row) {
  const w = S.ws;
  const d = w.detail;
  const i = w.insp && !w.insp.error ? w.insp : null;
  const ss = d?.sectorSize || 512;
  const ext = d?.extents || [];
  const first = ext.find((e) => e.offset !== 18446744073709551615);
  const rows = [
    ["Size", `${bytes(row.size)} (${int(row.size)} bytes)`],
    ["Type", i?.detectedLabel ? `${i.detectedLabel}${i.mismatch ? ` — the name says .${esc(i.extType || "?")}` : ""}` : row.typeId.toUpperCase() || "Unknown"],
    ["Found as", STATUS_LABEL[row.status] || row.status],
    ["Found by", ORIGIN_LABEL[row.origin] || row.origin],
    ["Original folder", row.folder || "\\"],
    ["Created", date(row.created, true)],
    ["Modified", date(row.modified, true)],
    d?.accessed ? ["Accessed", date(d.accessed, true)] : null,
    row.deleted ? ["Deleted", date(row.deleted, true)] : null,
    first ? ["Starts at", `Sector ${int(Math.floor(first.offset / ss))} (byte ${int(first.offset)})`] : d?.hasResident ? ["Stored", "Inside the file table (resident)"] : null,
    ext.length ? ["Fragments", `${ext.length}${row.fragmented ? "" : ""}`] : null,
    d?.fsRef != null ? ["Record", `#${int(d.fsRef)}`] : null,
    d?.hash ? ["BLAKE3", d.hash.slice(0, 32) + "…"] : null,
    d?.livePath ? ["Windows path", d.livePath] : null,
  ].filter(Boolean);
  for (const [k, v] of Object.entries(row.meta || {})) if (!["width", "height"].includes(k)) rows.push([k.replace(/([A-Z])/g, " $1").replace(/^./, (c) => c.toUpperCase()), v]);
  let h = `<dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>`;
  if (i) {
    h += `<div><h3 class="side-h">File header</h3><dl class="kv">${i.fields.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl><div class="hex" style="margin-top:8px">${esc(i.headerHex)}</div></div>`;
    h += `<div class="callout${i.validation.condition === "partial" ? " warn" : ""}">${icon(i.validation.condition === "partial" ? "file-warning" : "file-check")}<div><b>Integrity check:</b> ${esc(i.validation.note)}</div></div>`;
  } else if (w.insp?.error) h += `<div class="callout warn">${icon("circle-alert")}<div>${esc(w.insp.error)}</div></div>`;
  if (ext.length > 1)
    h += `<div><h3 class="side-h">Fragments</h3><table class="table"><tbody>${ext
      .slice(0, 12)
      .map((e, n) => `<tr><td>${n + 1}</td><td>${e.offset === 18446744073709551615 ? "Sparse (zeros)" : `Sector ${int(Math.floor(e.offset / ss))}`}</td><td class="r">${bytes(e.len)}</td></tr>`)
      .join("")}</tbody></table>${ext.length > 12 ? `<p class="faint" style="font-size:var(--fs-xs)">and ${ext.length - 12} more</p>` : ""}</div>`;
  return h;
}

async function loadHex() {
  const w = S.ws;
  const id = w.focus;
  const off = w.hexOff;
  // renderInsp runs several times while a file loads: read these bytes from the source only once.
  const key = `${id}:${off}`;
  if (w.hexLoading === key) return;
  w.hexLoading = key;
  let html;
  try {
    const r = await invoke("read_file_bytes", { sessionId: w.id, id, offset: off, length: 4096 });
    const data = b64(r.data);
    html = `<div class="hex-nav"><button class="btn small" data-action="hex-prev" ${off ? "" : "disabled"}>${icon("chevron-left", "s")}</button><span>Bytes ${int(off)}–${int(off + data.length)} of ${int(r.size)}</span><button class="btn small" data-action="hex-next" ${off + data.length < r.size ? "" : "disabled"}>${icon("chevron-right", "s")}</button>${r.badSectors ? `<span class="tag danger">Includes unreadable sectors</span>` : ""}</div><div class="hex" style="margin-top:8px">${hexDump(data, off)}</div>`;
  } catch (e) {
    html = `<div class="callout warn">${icon("circle-alert")}<div>${esc(errText(e))}</div></div>`;
  } finally {
    if (w.hexLoading === key) w.hexLoading = null;
  }
  // Another file or page was picked meanwhile: its own load shows it.
  if (w.focus !== id || w.hexOff !== off) return;
  w.hexHtml = html;
  renderInsp();
}

// --------------------------------------------------------------------------------- map tab
function regionHtml() {
  const w = S.ws;
  const r = w.region;
  if (!r) return `<h3>Inspect a region</h3><p class="muted" style="margin:0">Click any square on the map to see its sector range, what it contains and which files live there.</p>`;
  if (r.loading) return `<h3>${esc(bytes(r.start))} – ${esc(bytes(r.end))}</h3><p class="muted">${icon("loader-circle", "spin s")} Reading…</p>`;
  if (r.error) return `<h3>Region</h3><div class="callout warn">${icon("circle-alert")}<div>${esc(r.error)}</div></div>`;
  const span = Math.max(1, r.end - r.start);
  const [scanned, meta, live, rec, bad] = r.totals;
  const seg = (v, c) => (v ? `<i style="width:${((v / span) * 100).toFixed(2)}%;background:var(${c})"></i>` : "");
  return `<div><h3>Sectors ${int(r.firstSector)} – ${int(r.lastSector)}</h3><p class="muted" style="margin:2px 0 0">${bytes(r.start)} – ${bytes(r.end)} · ${bytes(span)}</p></div>
    <div class="compo" aria-hidden="true">${seg(bad, "--map-bad")}${seg(rec, "--map-rec")}${seg(meta, "--map-meta")}${seg(live, "--map-live")}${seg(Math.max(0, scanned - rec - meta - live - bad), "--map-empty")}</div>
    <dl class="kv"><dt>${KIND_TEXT.rec}</dt><dd>${bytes(rec)}</dd><dt>${KIND_TEXT.live}</dt><dd>${bytes(live)}</dd><dt>${KIND_TEXT.meta}</dt><dd>${bytes(meta)}</dd><dt>${KIND_TEXT.bad}</dt><dd>${bytes(bad)}</dd><dt>Read so far</dt><dd>${bytes(scanned)}</dd></dl>
    ${r.badRanges.length ? `<div class="callout danger">${icon("triangle-alert")}<div>${plural(r.badRanges.length, "unreadable range")} here. Recovered files that touch them get zeros in those sectors.</div></div>` : ""}
    <div><h3 class="side-h">Files here <span class="faint" style="font-weight:450">${int(r.fileCount)}</span></h3>${
      r.files.length
        ? r.files.map((f) => `<button class="rfile" data-action="region-file" data-id="${f.id}">${icon(catIcon(f), "s")}<span class="ellipsis">${esc(f.name)}</span>${cond(f.condition, false)}</button>`).join("")
        : `<p class="muted" style="margin:0;font-size:var(--fs-s)">No found files start or continue in this range.</p>`
    }</div>
    <div class="row"><button class="btn small" data-action="region-zoom">${icon("zoom-in", "s")} Zoom in</button><button class="btn small" data-action="region-hex">${icon("binary", "s")} Raw sectors</button></div>
    <div id="region-hex">${r.hexHtml || ""}</div>`;
}

function mapCrumbs() {
  const w = S.ws;
  const el = document.getElementById("map-crumbs");
  if (!el) return;
  const parts = [`<button data-action="map-crumb" data-key="-1">Whole source</button>`];
  w.mapStack.forEach((v, i) => {
    parts.push(icon("chevron-right", "s"));
    parts.push(i === w.mapStack.length - 1 ? `<b>${bytes(v.start)} – ${bytes(v.end)}</b>` : `<button data-action="map-crumb" data-key="${i}">${bytes(v.start)} – ${bytes(v.end)}</button>`);
  });
  if (!w.mapStack.length) parts[0] = `<b>Whole source</b>`;
  patch(el, parts.join(""));
}

async function selectRegion(r) {
  const w = S.ws;
  w.region = { ...r, loading: true };
  patch(document.getElementById("region"), regionHtml());
  try {
    const info = await invoke("map_region", { sessionId: w.id, start: r.start, end: r.end });
    if (S.ws !== w) return;
    w.region = info;
  } catch (e) {
    w.region = { ...r, error: errText(e) };
  }
  const el = document.getElementById("region");
  if (el) restoringFocus(() => patch(el, regionHtml()));
}

// ------------------------------------------------------------------------------- partitions
function partitionsTab(d) {
  const p = d.partitions;
  if (!p) return `<div class="empty"><p>No partition information.</p></div>`;
  const statusTag = (s) => ({ ok: `<span class="tag ok">In the table</span>`, lost: `<span class="tag uv">Lost — found by its boot sector</span>`, damaged: `<span class="tag warn">Damaged</span>`, backupOnly: `<span class="tag warn">Only the backup copy is left</span>` })[s] || esc(s);
  const lost = p.entries.some((e) => e.status === "lost");
  const loc = S.ws.partLoc?.id === S.ws.id ? S.ws.partLoc.loc : null;
  return `<div class="page"><div class="tool" style="max-width:1040px">
    <div><h2>${p.style === "None" ? "No partition table" : `${esc(p.style)} partition table`}</h2><p class="lede">${plural(p.entries.length, "partition")} on ${bytes(p.diskSize)}.${lost ? " Lost partitions can be scanned like a drive." : ""}</p></div>
    <div id="part-loc">${partLocHtml(loc)}</div>
    ${p.notes.map((n) => `<div class="callout">${icon("info")}<div>${esc(n)}</div></div>`).join("")}
    <div class="panel"><table class="table"><thead><tr><th>Partition</th><th>File system</th><th class="r">Size</th><th class="r">Starts at</th><th>Status</th><th></th></tr></thead><tbody>${p.entries
      .map(
        (e, i) => `<tr><td><b>${esc(e.label || e.typeName)}</b>${e.number != null ? ` <span class="faint">#${e.number}</span>` : ""}<div class="faint" style="font-size:var(--fs-xs)">${esc(e.note)}</div></td><td>${esc(e.fs || "Unknown")}</td><td class="r">${bytes(e.size)}</td><td class="r">${bytes(e.offset)}</td><td>${statusTag(e.status)}</td><td class="r nowrap"><button class="btn small" data-action="scan-part" data-key="${i}" data-mode="quick">Quick scan</button> <button class="btn small" data-action="scan-part" data-key="${i}" data-mode="deep">Deep scan</button></td></tr>`,
      )
      .join("")}</tbody></table></div>
    ${p.unallocated.length ? `<p class="muted">Unallocated space: ${p.unallocated.map(([a, b]) => `${bytes(b - a)} at ${bytes(a)}`).join(", ")}.</p>` : ""}
  </div></div>`;
}
// Where a partition scan's results would be kept (scan_location for this disk), shown above the table.
function partLocHtml(loc) {
  if (!loc) return "";
  if (loc.refuse) return `<div class="callout danger">${icon("circle-x")}<div>${esc(loc.refuse)}</div></div>`;
  if (!loc.message) return "";
  if (loc.sameDrive) return `<div class="callout warn">${icon("triangle-alert")}<div>${esc(loc.message)}</div></div>`;
  return `<p class="loc-note">${icon("hard-drive", "s")}<span>${esc(loc.message)}</span></p>`;
}
async function partLocation(d) {
  const w = S.ws;
  const key = `${w.id}|${runningJobs().scans}`;
  if (!d.partitions || w.partLoc?.key === key) return;
  const id = w.id;
  w.partLoc = { id, key, loc: w.partLoc?.id === id ? w.partLoc.loc : null };
  let loc = null;
  try {
    loc = await invoke("scan_location", { source: { kind: d.summary.source.kind, path: d.summary.source.path } });
  } catch (e) {
    if (!needsAdmin(e)) console.warn("scan_location failed:", errText(e));
  }
  if (S.ws !== w || w.partLoc?.key !== key) return;
  w.partLoc = { id, key, loc };
  const el = document.getElementById("part-loc");
  if (el) patch(el, partLocHtml(loc));
}

// ------------------------------------------------------------------------------------ after
function afterSession(d) {
  const w = S.ws;
  if (w.tab === "files") {
    const box = document.getElementById("toolbar");
    renderTree();
    if (!w.kids.has("")) loadKids("");
    if (!w.loaded) runQuery();
    else renderCenter();
    if (w.focus != null) renderInsp();
    void box;
  } else if (w.tab === "map") {
    const box = document.getElementById("ws-map");
    if (box && (!wsMap || wsMap.box !== box)) {
      wsMap?.destroy();
      const s = d.summary;
      const v = w.mapStack.at(-1);
      wsMap = new RecoveryMap(box, {
        sourceLen: s.sourceLen,
        sectorSize: d.sectorSize,
        fetch: (start, end, cells) => invoke("map_cells", { sessionId: w.id, start, end, cells }),
        onData: (md) => {
          const el = document.getElementById("ws-map-stats");
          if (el) patch(el, mapStats(md));
        },
        onSelect: (r) => selectRegion(r),
        onZoom: (r) => {
          w.mapStack.push(r);
          mapCrumbs();
          wsMap.setView(r.start, r.end);
        },
        onZoomOut: () => {
          w.mapStack.pop();
          const t = w.mapStack.at(-1) || { start: 0, end: s.sourceLen };
          mapCrumbs();
          wsMap.setView(t.start, t.end);
        },
      });
      if (v) wsMap.setView(v.start, v.end);
      mapCrumbs();
    }
  } else if (w.tab === "log") loadLog();
  else if (w.tab === "partitions") partLocation(d);
  startLive();
}

// While a scan runs, refresh what's on screen every 2.5 s. A tick is skipped while the previous
// refresh is still waiting for the backend (on a big scan a query can take longer than a tick), and
// the folder tree, which is expensive to rebuild, is refreshed at most every 10 s.
const LIVE_MS = 2500;
const LIVE_TREE_MS = 10000;
let liveBusy = false;
let liveTreeAt = 0;
function startLive() {
  clearInterval(liveTimer);
  liveTimer = setInterval(liveTick, LIVE_MS);
}
function liveTick() {
  const w = S.ws;
  if (liveBusy || !w || S.view.name !== "session" || document.hidden) return;
  const live = S.live[w.id];
  if (!live || live.state !== "running") return;
  const jobs = [];
  if (w.tab === "map" && wsMap) jobs.push(wsMap.refresh());
  if (w.tab === "files") {
    jobs.push(runQuery({ keepCount: true }));
    if (Date.now() - liveTreeAt >= LIVE_TREE_MS) {
      // Closed folders reload when opened again; open ones are replaced as their new counts arrive.
      // One folder_children call at a time (each is a full grouping query on the backend), and the
      // next tree refresh waits 10 s from the end of this one.
      for (const k of [...w.kids.keys()]) if (!w.open.has(k)) w.kids.delete(k);
      const paths = ["", ...[...w.open].filter(Boolean)];
      jobs.push(
        (async () => {
          for (const p of paths) {
            if (S.ws !== w) break;
            await loadKids(p);
          }
          liveTreeAt = Date.now();
        })(),
      );
    }
  }
  if (w.tab === "log") jobs.push(loadLog());
  if (!jobs.length) return;
  liveBusy = true;
  Promise.allSettled(jobs).then(() => {
    liveBusy = false;
  });
}

async function loadLog() {
  const w = S.ws;
  try {
    const lines = await invoke("session_log", { sessionId: w.id, offset: 0, limit: 2000 });
    const el = document.getElementById("log");
    if (!el) return;
    patch(
      el,
      lines.length
        ? lines.map((l) => `<div class="${l.level === "warn" ? "w" : l.level === "error" ? "e" : ""}"><span class="t">${esc(new Date(l.at).toLocaleTimeString())}</span>  ${esc(l.message)}</div>`).join("")
        : `<span class="muted">The log is empty.</span>`,
    );
  } catch (e) {
    const el = document.getElementById("log");
    if (el) el.textContent = errText(e);
  }
}

function resetResults() {
  const w = S.ws;
  w.items = [];
  w.loaded = false;
  w.kids = new Map();
  w.open = new Set([""]);
  renderCenter();
  runQuery();
  loadKids("");
  const chips = document.getElementById("ws-chips");
  const d = sessionDetail(w.id);
  if (chips && d) restoringFocus(() => patch(chips, chipsHtml(d)));
}

// Search: one delegated listener, so it keeps working whenever the toolbar is re-rendered.
let searchTimer = 0;
document.addEventListener("input", (e) => {
  if (e.target?.id !== "ws-search") return;
  const w = S.ws;
  if (!w) return;
  // What's typed but not searched yet survives a re-render of the page.
  w.searchDraft = e.target.value;
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    if (S.ws !== w) return;
    // What was typed, even if the box is gone because another tab is open now.
    const v = w.searchDraft ?? w.search;
    if (v === w.search) return;
    w.search = v;
    resetResults();
  }, 220);
});

// Live progress from the backend (called by app.js on scan-progress).
export function onScanProgress(p) {
  if (S.view.name !== "session" || S.ws?.id !== p.sessionId) return;
  const d = sessionDetail(p.sessionId);
  if (!d) return;
  const el = document.getElementById("sess-progress");
  if (el) patch(el, progressHtml(d, p));
  const fc = document.getElementById("files-count");
  if (fc && p.filesFound != null) fc.textContent = int(p.filesFound);
  const a = document.getElementById("sess-actions");
  if (a) restoringFocus(() => patch(a, actionsHtml(d, p.state, p)));
}

// ----------------------------------------------------------------------------------- recover
export async function recoverDialog(sessionId, ids, queryObj, count, size) {
  const settings = S.settings || {};
  const d = sessionDetail(sessionId);
  let dest = settings.defaultDestination || "";
  const opts = {
    keepFolders: settings.keepFolders ?? true,
    verify: settings.verifyRecovered ?? true,
    repair: settings.repairDamaged ?? true,
    skipDuplicates: settings.skipDuplicates ?? true,
    report: true,
  };
  let check = null; // result of the last finished check
  let checkedDest = null; // the path that result is for
  let checking = 0;
  const html = `<form method="dialog" id="recform">
    <header><h2>Recover ${plural(count, "file")}</h2><p>${bytes(size)} from ${esc(d ? describeSource(d.summary.source).title : "this scan")}. MAX copies them to the folder you pick and ${d?.summary.source.kind === "image" ? "never writes into the disk image they came from" : "never saves recovered files onto the drive they came from"}.</p></header>
    <div class="body">
      <div class="field"><label for="dest">Save to</label><div class="row"><input type="text" id="dest" style="flex:1" placeholder="D:\\Recovered" value="${esc(dest)}" spellcheck="false"><button type="button" class="btn" data-dlg="browse">${icon("folder-open", "s")} Browse…</button></div><div id="destmsg"></div></div>
      <div style="display:grid;gap:10px">
        <label class="check"><input type="checkbox" name="keepFolders" ${opts.keepFolders ? "checked" : ""}><span>Recreate the original folders<small>Files go into their reconstructed folders instead of one flat folder.</small></span></label>
        <label class="check"><input type="checkbox" name="verify" ${opts.verify ? "checked" : ""}><span>Verify every file after writing it<small>Reads each recovered file back and compares its checksum.</small></span></label>
        <label class="check"><input type="checkbox" name="repair" ${opts.repair ? "checked" : ""}><span>Try to repair damaged files<small>Writes a separate “(repaired)” copy next to the original; the original is kept as found.</small></span></label>
        <label class="check"><input type="checkbox" name="skipDuplicates" ${opts.skipDuplicates ? "checked" : ""}><span>Skip identical copies<small>Files with exactly the same content are written once.</small></span></label>
        <label class="check"><input type="checkbox" name="report" checked><span>Write a recovery report<small>An HTML and a CSV report listing every file, its condition and checksum.</small></span></label>
      </div>
    </div>
    <footer><span class="left" id="destfree"></span><button type="button" class="btn ghost" data-dlg="cancel">Cancel</button><button class="btn primary" value="ok" id="recgo" disabled>${icon("download", "s")} Recover</button></footer>
  </form>`;
  const doCheck = async () => {
    const my = ++checking;
    const msg = document.getElementById("destmsg");
    const go = document.getElementById("recgo");
    const inp = document.getElementById("dest");
    if (!msg || !go || !inp) return;
    dest = inp.value.trim();
    // Recover stays off until this path is checked, so it can't start with an older path.
    check = null;
    checkedDest = null;
    go.disabled = true;
    if (!dest) {
      msg.innerHTML = `<span class="hint">Pick a folder on a different drive than the one you're recovering from.</span>`;
      go.disabled = true;
      return;
    }
    msg.innerHTML = `<span class="hint">${icon("loader-circle", "spin s")} Checking…</span>`;
    try {
      const c = await invoke("check_destination", { sessionId, dest, ids: ids || undefined, query: ids ? undefined : queryObj });
      if (my !== checking) return;
      check = c;
      checkedDest = dest;
      inp.setAttribute("aria-invalid", check.ok ? "false" : "true");
      msg.innerHTML = check.ok
        ? check.warnings.map((x) => `<div class="callout warn">${icon("triangle-alert")}<div>${esc(x)}</div></div>`).join("") || `<span class="hint">${icon("circle-check", "s")} Looks good.</span>`
        : `<div class="callout danger">${icon("circle-x")}<div>${esc(check.error)}</div></div>`;
      document.getElementById("destfree").textContent = check.ok ? `${bytes(check.freeBytes)} free there` : "";
      go.disabled = !check.ok;
    } catch (e) {
      if (my !== checking) return;
      msg.innerHTML = `<div class="callout danger">${icon("circle-x")}<div>${esc(errText(e))}</div></div>`;
      go.disabled = true;
    }
  };
  const result = showDialog(html, {
    onOpen: (dlg) => {
      const inp = dlg.querySelector("#dest");
      let t = 0;
      inp.addEventListener("input", () => {
        // Enter or a quick click must not recover to the previously checked folder.
        checking++;
        check = null;
        checkedDest = null;
        dlg.querySelector("#recgo").disabled = true;
        clearTimeout(t);
        t = setTimeout(doCheck, 350);
      });
      // Cancel is not a submit button, so Enter in "Save to" never cancels the dialog.
      dlg.querySelector('[data-dlg="cancel"]').addEventListener("click", () => dlg.close("cancel"));
      dlg.querySelector('[data-dlg="browse"]').addEventListener("click", async () => {
        try {
          const p = await window.__TAURI__.dialog.open({ directory: true, multiple: false, title: "Where should the recovered files go?" });
          if (p) {
            inp.value = p;
            doCheck();
          }
        } catch (e) {
          toastError(e);
        }
      });
      doCheck();
    },
  });
  const form = document.getElementById("recform");
  const shown = () => (form.querySelector("#dest")?.value || "").trim();
  const r = await result;
  if (r !== "ok" || !check?.ok || checkedDest !== shown()) return;
  dest = checkedDest;
  const fd = new FormData(form);
  for (const k of Object.keys(opts)) opts[k] = fd.get(k) === "on";
  try {
    const job = await invoke("start_recovery", { sessionId, dest, ids: ids || undefined, query: ids ? undefined : queryObj, options: opts });
    S.recoveries[job] = S.recoveries[job] || { job, sessionId, count, size, dest };
    Object.assign(S.recoveries[job], { job, sessionId, count, size, dest });
    App.renderDock();
    if (S.settings && S.settings.defaultDestination !== dest) {
      S.settings = await invoke("save_settings", { settings: { ...S.settings, defaultDestination: dest, keepFolders: opts.keepFolders, verifyRecovered: opts.verify, repairDamaged: opts.repair, skipDuplicates: opts.skipDuplicates } }).catch(() => S.settings);
    }
  } catch (e) {
    toastError(e);
  }
}

// ----------------------------------------------------------------------------------- actions
function toggleSel(id, on) {
  const w = S.ws;
  const f = w.items.find((x) => x.id === id);
  if (on ?? !w.sel.has(id)) w.sel.set(id, f?.size || 0);
  else w.sel.delete(id);
  const row = document.querySelector(`#list [data-id="${id}"]`);
  if (row) {
    row.setAttribute("aria-selected", w.sel.has(id));
    const cb = row.querySelector('input[type="checkbox"]');
    if (cb) cb.checked = w.sel.has(id);
  }
  renderSelbar();
}

Object.assign(App.actions, {
  "open-session": (el) => App.navigate({ name: "session", id: el.dataset.id }),
  "ws-tab": (el) => {
    S.ws.tab = el.dataset.tab;
    S.view.tab = el.dataset.tab;
    App.renderMain();
  },
  "ws-cat": (el) => {
    const w = S.ws;
    const k = el.dataset.key;
    if (!k) w.cats = [];
    else w.cats = w.cats.includes(k) ? w.cats.filter((x) => x !== k) : [...w.cats, k];
    if (k === "photo" && w.cats.length === 1 && w.mode === "list" && !load("wsModeChosen", false)) w.mode = "gallery";
    resetResults();
  },
  "ws-mode": (el) => {
    S.ws.mode = el.dataset.mode;
    save("wsModeChosen", true);
    save("ws", { sort: S.ws.sort, desc: S.ws.desc, mode: S.ws.mode });
    const chips = document.getElementById("ws-chips");
    if (chips) restoringFocus(() => patch(chips, chipsHtml(sessionDetail(S.ws.id))));
    renderCenter();
  },
  "ws-dups": () => {
    const w = S.ws;
    const d = sessionDetail(w.id);
    if (!w.dupOnly && !S.dupes[w.id]?.result && !d?.summary.dupesChecked && !dupesCheckedBefore(d)) {
      findDuplicates(w.id);
    }
    w.dupOnly = !w.dupOnly;
    resetResults();
  },
  "ws-clear": () => {
    Object.assign(S.ws, { search: "", searchDraft: null, cats: [], statuses: [], conds: [], size: "any", dateFrom: null, dateTo: null, dupOnly: false });
    const inp = document.getElementById("ws-search");
    if (inp) inp.value = "";
    resetResults();
  },
  "ws-sortby": (el) => {
    const w = S.ws;
    if (w.sort === el.dataset.key) w.desc = !w.desc;
    else {
      w.sort = el.dataset.key;
      w.desc = ["size", "modified", "deleted", "created"].includes(w.sort);
    }
    save("ws", { sort: w.sort, desc: w.desc, mode: w.mode });
    w.items = [];
    runQuery();
  },
  "ws-desc": () => {
    S.ws.desc = !S.ws.desc;
    save("ws", { sort: S.ws.sort, desc: S.ws.desc, mode: S.ws.mode });
    runQuery();
  },
  "ws-more": () => runQuery({ append: true }),
  "ws-row": (el, e) => {
    const id = Number(el.dataset.id);
    if (e.target.closest('input[type="checkbox"]')) return;
    if (e.ctrlKey || e.metaKey) return toggleSel(id);
    if (e.shiftKey && S.ws.focus != null) {
      const ids = S.ws.items.map((f) => f.id);
      const a = ids.indexOf(S.ws.focus);
      const b = ids.indexOf(id);
      if (a >= 0 && b >= 0) for (let i = Math.min(a, b); i <= Math.max(a, b); i++) toggleSel(ids[i], true);
      return;
    }
    focusFile(id);
  },
  "ws-check": (el) => toggleSel(Number(el.dataset.id), el.checked),
  "ws-selpage": (el) => {
    for (const f of S.ws.items) toggleSel(f.id, el.checked);
  },
  "ws-selnone": () => {
    S.ws.sel.clear();
    renderCenter();
  },
  "ws-selall": async () => {
    const w = S.ws;
    try {
      const ids = await invoke("query_ids", { sessionId: w.id, query: query() });
      w.sel.clear();
      // Sizes for files not loaded are unknown here; the total of the query is exact.
      const per = ids.length ? w.totalSize / ids.length : 0;
      const known = new Map(w.items.map((f) => [f.id, f.size]));
      for (const id of ids) w.sel.set(id, known.get(id) ?? per);
      renderCenter();
    } catch (e) {
      toastError(e);
    }
  },
  "ws-folder": (el, e) => {
    if (e.target.closest('[data-action="ws-twisty"]')) return App.actions["ws-twisty"](e.target.closest('[data-action="ws-twisty"]'));
    const p = el.dataset.path;
    S.ws.folder = p === "" ? null : p;
    if (p && !S.ws.open.has(p)) {
      S.ws.open.add(p);
      if (!S.ws.kids.has(p)) loadKids(p);
    }
    renderTree();
    S.ws.items = [];
    S.ws.loaded = false;
    renderCenter();
    runQuery();
  },
  "ws-twisty": (el) => {
    const p = el.dataset.path;
    const w = S.ws;
    if (w.open.has(p)) w.open.delete(p);
    else {
      w.open.add(p);
      if (!w.kids.has(p)) loadKids(p);
    }
    renderTree();
  },
  "ws-pop": (el) => {
    const w = S.ws;
    const k = el.dataset.key;
    const d = sessionDetail(w.id);
    if (k === "cond") {
      const counts = d?.counts?.byCondition || {};
      popover(
        el,
        `<div class="ph">Condition</div>${["excellent", "good", "partial", "unknown"]
          .map((c) => `<label><input type="checkbox" value="${c}" ${w.conds.includes(c) ? "checked" : ""}>${cond(c)}<span class="faint" style="margin-left:auto">${int(counts[c]?.[0] || 0)}</span></label>`)
          .join("")}<p class="faint" style="font-size:var(--fs-xs);margin:6px 8px 2px;max-width:240px">An estimate from the evidence MAX found — never a guarantee.</p>`,
        (e, p) => {
          w.conds = [...p.querySelectorAll("input:checked")].map((i) => i.value);
          resetResults();
        },
      );
    } else if (k === "status") {
      const counts = d?.counts?.byStatus || {};
      const keys = Object.keys(STATUS_LABEL).filter((s) => counts[s]?.[0]);
      popover(
        el,
        `<div class="ph">Found as</div>${keys.map((s) => `<label><input type="checkbox" value="${s}" ${w.statuses.includes(s) ? "checked" : ""}>${esc(STATUS_LABEL[s])}<span class="faint" style="margin-left:auto">${int(counts[s][0])}</span></label>`).join("")}`,
        (e, p) => {
          w.statuses = [...p.querySelectorAll("input:checked")].map((i) => i.value);
          resetResults();
        },
      );
    } else if (k === "size") {
      popover(
        el,
        `<div class="ph">Size</div>${[
          ["any", "Any size"],
          ["small", "Under 1 MB"],
          ["medium", "1 MB – 100 MB"],
          ["large", "Over 100 MB"],
        ]
          .map(([v, l]) => `<label><input type="radio" name="sz" value="${v}" ${w.size === v ? "checked" : ""}>${l}</label>`)
          .join("")}`,
        (e) => {
          w.size = e.target.value;
          closePopover();
          resetResults();
        },
      );
    } else if (k === "date") {
      const iso = (ms) => (ms ? new Date(ms).toISOString().slice(0, 10) : "");
      const p = popover(
        el,
        `<div class="ph">Date</div><div style="display:grid;gap:8px;padding:4px 8px">
          <select name="field">${["modified", "created", "deleted"].map((f) => `<option value="${f}" ${w.dateField === f ? "selected" : ""}>${{ modified: "Modified", created: "Created", deleted: "Deleted" }[f]}</option>`).join("")}</select>
          <label style="padding:0">From <input type="date" name="from" value="${iso(w.dateFrom)}"></label>
          <label style="padding:0">To <input type="date" name="to" value="${iso(w.dateTo)}"></label>
          <div class="row"><button class="btn small" type="button" data-k="clear">Any date</button><button class="btn small primary" type="button" data-k="apply">Apply</button></div></div>`,
      );
      p.addEventListener("click", (e) => {
        const b = e.target.closest("button[data-k]");
        if (!b) return;
        if (b.dataset.k === "clear") {
          w.dateFrom = w.dateTo = null;
        } else {
          w.dateField = p.querySelector('[name="field"]').value;
          const f = p.querySelector('[name="from"]').value;
          const t = p.querySelector('[name="to"]').value;
          w.dateFrom = f ? new Date(f + "T00:00:00").getTime() : null;
          w.dateTo = t ? new Date(t + "T23:59:59").getTime() : null;
        }
        closePopover();
        resetResults();
      });
    }
  },
  "insp-tab": (el) => {
    S.ws.inspTab = el.dataset.tab;
    if (el.dataset.tab === "hex") S.ws.hexHtml = null;
    renderInsp();
  },
  "insp-close": () => {
    S.ws.focus = null;
    App.renderMain();
  },
  "hex-prev": () => {
    S.ws.hexOff = Math.max(0, S.ws.hexOff - 4096);
    loadHex();
  },
  "hex-next": () => {
    S.ws.hexOff += 4096;
    loadHex();
  },
  "recover-one": () => {
    const w = S.ws;
    const f = w.items.find((x) => x.id === w.focus) || w.detail?.row;
    if (f) recoverDialog(w.id, [f.id], null, 1, f.size);
  },
  "recover-selected": () => {
    const w = S.ws;
    let size = 0;
    for (const v of w.sel.values()) size += v || 0;
    recoverDialog(w.id, [...w.sel.keys()], null, w.sel.size, size);
  },
  "recover-all": () => {
    const w = S.ws;
    const q = query();
    delete q.offset;
    delete q.limit;
    recoverDialog(w.id, null, q, w.total, w.totalSize);
  },
  "file-on-map": () => {
    const w = S.ws;
    const ext = w.detail?.extents?.find((e) => e.offset !== 18446744073709551615);
    if (!ext) return toast("This file has no location on the drive (it's stored in the file table or comes from the Recycle Bin).", { icon: "info" });
    const d = sessionDetail(w.id);
    const span = Math.max(ext.len * 64, 64 * 1024 * 1024);
    const start = Math.max(0, ext.offset - span / 2);
    w.mapStack = [{ start, end: Math.min(d.summary.sourceLen, start + span) }];
    w.region = null;
    w.tab = "map";
    S.view.tab = "map";
    App.renderMain();
    selectRegion({ start: ext.offset, end: ext.offset + ext.len });
  },
  "region-file": (el) => {
    const w = S.ws;
    w.tab = "files";
    S.view.tab = "files";
    w.focus = Number(el.dataset.id);
    App.renderMain();
    focusFile(Number(el.dataset.id));
  },
  "region-zoom": () => {
    const r = S.ws.region;
    if (!r || !wsMap) return;
    S.ws.mapStack.push({ start: r.start, end: r.end });
    mapCrumbs();
    wsMap.setView(r.start, r.end);
  },
  "region-hex": async () => {
    const w = S.ws;
    const r = w.region;
    const d = sessionDetail(w.id);
    if (!r || !d) return;
    try {
      const raw = await invoke("read_sectors", { source: d.summary.source, offset: r.start, length: 512 });
      w.region.hexHtml = `<div class="hex">${hexDump(b64(raw.data), r.start)}</div>`;
    } catch (e) {
      w.region.hexHtml = `<div class="callout warn">${icon("circle-alert")}<div>${esc(errText(e))}</div></div>`;
    }
    const el = document.getElementById("region");
    if (el) restoringFocus(() => patch(el, regionHtml()));
  },
  "map-crumb": (el) => {
    const w = S.ws;
    const i = Number(el.dataset.key);
    w.mapStack = i < 0 ? [] : w.mapStack.slice(0, i + 1);
    const d = sessionDetail(w.id);
    const t = w.mapStack.at(-1) || { start: 0, end: d.summary.sourceLen };
    mapCrumbs();
    wsMap?.setView(t.start, t.end);
  },
  "pause-scan": async () => {
    try {
      await invoke("pause_scan", { sessionId: S.ws.id, paused: true });
    } catch (e) {
      toastError(e);
    }
  },
  "unpause-scan": async () => {
    try {
      await invoke("pause_scan", { sessionId: S.ws.id, paused: false });
    } catch (e) {
      toastError(e);
    }
  },
  "stop-scan": async () => {
    const ok = await confirmDialog({ title: "Stop this scan?", body: "Everything found so far is kept, and you can resume the scan later from where it stopped.", ok: "Stop scan", cancel: "Keep scanning" });
    if (!ok) return;
    const id = S.ws.id;
    try {
      await invoke("cancel_scan", { sessionId: id });
      // Shown at once; the next scan-progress event (stopping: true) or scan-done follows.
      const live = S.live[id];
      if (live && (live.state === "running" || live.state === "paused")) {
        live.stopping = true;
        onScanProgress(live);
        App.renderRail();
      }
    } catch (e) {
      toastError(e);
    }
  },
  "resume-scan": async () => {
    const id = S.ws.id;
    try {
      const r = await invoke("resume_session", { sessionId: id });
      scanStarted(r, sessionDetail(id)?.summary.files || 0);
      await loadSession(id, true);
      App.renderMain();
      App.renderRail();
    } catch (e) {
      if (needsAdmin(e)) adminToast(e);
      else toastError(e);
    }
  },
  "deep-from-session": async () => {
    const d = sessionDetail(S.ws.id);
    if (!d) return;
    S.drive = { source: d.summary.source, mode: "deep", cats: null, existing: null };
    App.navigate({ name: "drive", source: d.summary.source });
  },
  "scan-part": async (el) => {
    const d = sessionDetail(S.ws.id);
    const e = d.partitions.entries[Number(el.dataset.key)];
    const src = { kind: d.summary.source.kind, path: d.summary.source.path, offset: e.offset, length: e.size, label: `${e.label || e.fs || "Partition"} at ${bytes(e.offset)}` };
    try {
      const r = await invoke("start_scan", { source: src, options: { mode: el.dataset.mode, includeExisting: true } });
      scanStarted(r);
      await App.refreshSessions();
      App.navigate({ name: "session", id: r.sessionId, tab: "map" });
    } catch (err) {
      if (needsAdmin(err)) adminToast(err);
      else toastError(err);
    }
  },
  "export-report": async () => {
    const w = S.ws;
    let path;
    try {
      path = await window.__TAURI__.dialog.save({ title: "Save scan report", defaultPath: "MAX scan report.html", filters: [{ name: "Web page", extensions: ["html"] }, { name: "Spreadsheet (CSV)", extensions: ["csv"] }] });
    } catch (e) {
      return toastError(e);
    }
    if (!path) return;
    try {
      const out = await invoke("export_report", { sessionId: w.id, path, format: /\.csv$/i.test(path) ? "csv" : "html", query: query() });
      toast("Report saved.", { action: "Show", onAction: () => invoke("reveal_path", { path: out }).catch(toastError) });
    } catch (e) {
      toastError(e);
    }
  },
  "sess-more": (el) => {
    const p = popover(
      el,
      `<button class="btn ghost small" data-k="dups" style="justify-content:flex-start">${icon("copy", "s")} Find duplicate files</button>
       <button class="btn ghost small" data-k="save" style="justify-content:flex-start">${icon("save", "s")} Save scan to a file…</button>
       <button class="btn ghost small" data-k="deep" style="justify-content:flex-start">${icon("radar", "s")} Deep scan this source</button>
       <button class="btn ghost small" data-k="del" style="justify-content:flex-start;color:var(--danger)">${icon("trash-2", "s")} Delete this scan</button>`,
    );
    p.addEventListener("click", async (e) => {
      const b = e.target.closest("button[data-k]");
      if (!b) return;
      closePopover();
      const id = S.ws.id;
      if (b.dataset.k === "dups") findDuplicates(id);
      if (b.dataset.k === "deep") App.actions["deep-from-session"]();
      if (b.dataset.k === "save") {
        try {
          const path = await window.__TAURI__.dialog.save({ title: "Save scan", defaultPath: `${sessionDetail(id)?.summary.label || "scan"}.maxscan`, filters: [{ name: "MAX scan", extensions: ["maxscan"] }] });
          if (!path) return;
          await invoke("export_session", { sessionId: id, path });
          toast("Scan saved. Open it later from Recovery history → Open a saved scan.");
        } catch (err) {
          toastError(err);
        }
      }
      if (b.dataset.k === "del") {
        const ok = await confirmDialog({ title: "Delete this scan?", body: "Only MAX's record of the scan is deleted — nothing on your drives changes. Files you already recovered stay where they are.", ok: "Delete scan", danger: true });
        if (!ok) return;
        try {
          await invoke("delete_session", { sessionId: id });
          delete S.sessionCache[id];
          await App.refreshSessions();
          App.navigate({ name: "home" });
          toast("Scan deleted.");
        } catch (err) {
          toastError(err);
        }
      }
    });
  },
});

// A finished duplicate search of this session (remembered across restarts) that still matches its
// file count: the groups are stored in the session, so there's nothing to hash again.
function dupesCheckedBefore(d) {
  if (!d || d.summary.state !== "done") return false;
  return load("dupesChecked", {})[d.summary.id] === d.summary.files;
}

export async function findDuplicates(id) {
  const cur = S.dupes[id];
  if (cur?.job != null && !cur.result) return; // one is already running
  try {
    const job = await invoke("find_duplicates", { sessionId: id });
    const prev = S.dupes[id];
    // dupes-progress / dupes-done can arrive before the command returns: keep what they brought.
    // A result is kept only when it is this job's; an older run's result is dropped.
    const early = prev && (prev.job === job || prev.result?.job === job);
    if (early) {
      const { result, ...rest } = prev;
      S.dupes[id] = result?.job === job ? { ...rest, job, result } : { ...rest, job };
    } else S.dupes[id] = { job, done: 0, total: 0 };
    if (!S.dupes[id].result) toast("Looking for duplicate files…", { icon: "copy" });
  } catch (e) {
    toastError(e);
  }
}

// Keyboard navigation inside the file list.
export function wsKey(e) {
  const w = S.ws;
  if (!w || S.view.name !== "session" || w.tab !== "files") return false;
  if (e.target.closest("input,select,textarea,dialog")) return false;
  const ids = w.items.map((f) => f.id);
  if (!ids.length) return false;
  let i = ids.indexOf(w.focus);
  const step = w.mode === "gallery" ? Math.max(1, Math.floor((document.getElementById("list")?.clientWidth || 600) / 168)) : 1;
  if (e.key === "ArrowDown" || (w.mode === "gallery" && e.key === "ArrowRight")) i = Math.min(ids.length - 1, i + (e.key === "ArrowDown" ? step : 1));
  else if (e.key === "ArrowUp" || (w.mode === "gallery" && e.key === "ArrowLeft")) i = Math.max(0, i - (e.key === "ArrowUp" ? step : 1));
  else if (e.key === " " && w.focus != null) {
    e.preventDefault();
    toggleSel(w.focus);
    return true;
  } else if (e.key === "Escape" && w.focus != null) {
    w.focus = null;
    App.renderMain();
    return true;
  } else return false;
  e.preventDefault();
  if (i < 0) i = 0;
  focusFile(ids[i], { scroll: true });
  return true;
}

export function onSortChange(el) {
  S.ws.sort = el.value;
  save("ws", { sort: S.ws.sort, desc: S.ws.desc, mode: S.ws.mode });
  runQuery();
}
export { runQuery, renderCenter, listText };
export const focusFileById = (id) => {
  const target = Number.isFinite(id) && S.ws?.items.some((f) => f.id === id) ? id : S.ws?.items[Math.max(0, Number.isFinite(id) ? Math.min(id, S.ws.items.length - 1) : 0)]?.id;
  if (target != null) focusFile(target, { scroll: true });
};
