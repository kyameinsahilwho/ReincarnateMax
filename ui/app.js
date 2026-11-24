// MAX File Recovery — UI entry. Boot, routing, backend events, the progress dock, theme and
// keyboard. Views live in start.js (rail, start page, drive page), session.js (scan workspace) and
// tools.js (imaging, carving rules, history, settings).
if (!window.__TAURI__) {
  const m = await import("./mock.js");
  m.installMock();
}

import { S, App, invoke, listen, esc, icon, bytes, int, plural, duration, rate, toast, toastError, errText, load, save, patch, restoringFocus, initTooltips, closePopover, isMock, scanStarted, busyText, confirmDialog } from "./core.js";
import { renderRail, renderHome, renderDrive, describeSource, stagePct } from "./start.js";
import { renderSession, loadSession, onScanProgress, wsKey, onSortChange, focusFileById } from "./session.js";
import { renderImaging, renderRules, renderHistory, renderSettings, onToolChange } from "./tools.js";

const perf = (name) => invoke("perf_mark", { name }).catch(() => {});
perf("js:script-start");

let current = null; // {leave, after}

// ---------------------------------------------------------------------------------- routing
function viewKey(v) {
  return JSON.stringify(v);
}
App.navigate = (view) => {
  closePopover();
  if (view.name === "session" && S.view.name === "session" && S.view.id === view.id && view.tab) {
    S.view.tab = view.tab;
  } else S.view = view;
  save("lastView", view.name === "session" || view.name === "drive" ? view : { name: view.name });
  App.render();
  document.getElementById("main").focus({ preventScroll: true });
};
App.render = () => {
  renderRail();
  App.renderMain();
  App.renderDock();
};
App.renderRail = renderRail;
App.renderMain = () => {
  const main = document.getElementById("main");
  const v = S.view;
  let out;
  if (v.name === "drive") out = renderDrive();
  else if (v.name === "session") out = renderSession();
  else if (v.name === "imaging") out = renderImaging();
  else if (v.name === "rules") out = renderRules();
  else if (v.name === "history" || v.name === "scans") out = renderHistory();
  else if (v.name === "settings") out = renderSettings();
  else out = renderHome();
  const key = viewKey({ name: v.name, id: v.id, src: v.source });
  if (current && current.key !== key) current.leave?.();
  const html = (out.head || "") + (out.body || "");
  restoringFocus(() => patch(main, html));
  current = { key, leave: out.leave, after: out.after };
  out.after?.();
};

// ------------------------------------------------------------------------------- data loads
App.refreshDevices = async (manual) => {
  try {
    S.devices = await invoke("list_devices");
    S.devicesError = null;
  } catch (e) {
    S.devicesError = errText(e);
    if (manual) toastError(e);
  }
  App.render();
};
App.refreshSessions = async () => {
  try {
    S.sessions = await invoke("list_sessions");
  } catch (e) {
    // Keep what we had; the session list is a convenience.
  }
  renderRail();
};

// ----------------------------------------------------------------------------------- theme
App.setTheme = (t) => {
  save("theme", t);
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
  invoke("set_theme_pref", { theme: t }).catch(() => {});
  App.render();
  retheme();
};
function retheme() {
  // Canvases read colours from CSS: redraw them.
  document.querySelectorAll(".map-canvas-box").forEach(() => {});
  window.dispatchEvent(new Event("max-retheme"));
}
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", retheme);

// ------------------------------------------------------------------------------------ dock
// Recovery jobs and imaging show a small progress card at the bottom right on every page.
App.renderDock = () => {
  let el = document.getElementById("dock");
  if (!el) {
    el = document.createElement("div");
    el.id = "dock";
    el.className = "dock";
    document.body.appendChild(el);
  }
  let h = "";
  for (const r of Object.values(S.recoveries)) {
    if (r.dismissed) continue;
    const p = r.progress;
    const d = r.done;
    if (d) {
      const bad = d.failed + d.partial;
      h += `<div role="status"><span class="ic">${icon(d.state === "done" ? (bad ? "file-warning" : "circle-check") : "circle-alert")}</span>
        <span class="t">${d.state === "done" ? `Recovered ${plural(d.recovered, "file")}` : d.state === "cancelled" ? `Recovery stopped after ${plural(d.recovered, "file")}` : "Recovery failed"}</span>
        <span class="row" style="grid-row:span 2">${d.reportPath ? `<button class="btn small" data-action="reveal" data-path="${esc(d.reportPath)}">Report</button>` : ""}<button class="btn small primary" data-action="reveal" data-path="${esc(d.dest)}">Open folder</button><button class="btn small icon ghost" data-action="dock-dismiss" data-key="${r.job}" aria-label="Dismiss">${icon("x", "s")}</button></span>
        <small>${[
          d.partial ? `${int(d.partial)} partial` : "",
          d.failed ? `${int(d.failed)} failed` : "",
          d.repaired ? `${int(d.repaired)} repaired copies` : "",
          d.skippedDuplicates ? `${int(d.skippedDuplicates)} duplicates skipped` : "",
          bytes(d.bytes),
        ]
          .filter(Boolean)
          .join(" · ")}${d.errors?.length ? ` — ${esc(d.errors[0])}` : ""}</small></div>`;
    } else {
      const pct = p && p.bytesTotal ? Math.floor((p.bytesDone / p.bytesTotal) * 100) : 0;
      h += `<div role="status"><span class="ic">${icon("download")}</span><span class="t">Recovering ${p ? `${int(p.filesDone)} of ${plural(p.filesTotal, "file")}` : plural(r.count || 0, "file")}</span>
        <span class="row" style="grid-row:span 2"><button class="btn small ghost" data-action="dock-cancel" data-key="${r.job}">Stop</button></span>
        <small class="ellipsis">${p?.current ? esc(p.current) : "Starting…"}${p?.bytesPerSec ? ` · ${rate(p.bytesPerSec)}` : ""}${p?.etaSeconds != null ? ` · about ${duration(p.etaSeconds)} left` : ""}</small>
        <div class="pbar"><i style="width:${pct}%"></i></div></div>`;
    }
  }
  if (S.imaging && !S.imaging.done && S.view.name !== "imaging") {
    const p = S.imaging.progress || {};
    const pct = p.bytesTotal ? Math.floor((p.bytesDone / p.bytesTotal) * 100) : 0;
    h += `<div role="status"><span class="ic">${icon("hard-drive-download")}</span><span class="t">Imaging ${esc(describeSource(S.imaging.source).title)} · ${pct}%</span><span class="row" style="grid-row:span 2"><button class="btn small" data-action="go" data-view="imaging">Show</button></span><small>${bytes(p.bytesDone || 0)} of ${bytes(p.bytesTotal || 0)}${p.badBytes ? ` · ${bytes(p.badBytes)} unreadable` : ""}</small><div class="pbar"><i style="width:${pct}%"></i></div></div>`;
  }
  restoringFocus(() => patch(el, h));
};
Object.assign(App.actions, {
  "dock-dismiss": (el) => {
    const r = S.recoveries[el.dataset.key];
    if (r) r.dismissed = true;
    App.renderDock();
  },
  "dock-cancel": async (el) => {
    try {
      await invoke("cancel_recovery", { job: Number(el.dataset.key) });
    } catch (e) {
      toastError(e);
    }
  },
});

// ---------------------------------------------------------------------------------- events
let railTick = 0;
async function bindEvents() {
  await listen("devices-changed", () => App.refreshDevices());
  await listen("scan-progress", (e) => {
    const p = e.payload;
    const prev = S.live[p.sessionId];
    // Stopping can't be undone: an event sent just before Stop was pressed doesn't clear it.
    if (prev?.stopping && prev.job === p.job) p.stopping = true;
    S.live[p.sessionId] = p;
    onScanProgress(p);
    // The rail's percentages change slowly: repaint it at most every 2 s.
    const now = Date.now();
    if (!prev || prev.state !== p.state || prev.stageIndex !== p.stageIndex || !!prev.stopping !== !!p.stopping || now - railTick > 2000) {
      railTick = now;
      renderRail();
    }
    if (prev && prev.stageIndex !== p.stageIndex && S.view.name === "session" && S.view.id === p.sessionId) {
      loadSession(p.sessionId, true).then(() => App.renderMain()).catch(() => {});
    }
  });
  await listen("scan-done", async (e) => {
    const p = e.payload;
    // Kept so a start_scan / resume_session reply that arrives after this event doesn't mark it running.
    S.scanDone[p.sessionId] = p;
    const live = S.live[p.sessionId];
    S.live[p.sessionId] = { ...(live || {}), sessionId: p.sessionId, state: p.state, filesFound: p.files };
    delete S.sessionCache[p.sessionId];
    await App.refreshSessions();
    if (S.view.name === "session" && S.view.id === p.sessionId) {
      await loadSession(p.sessionId, true).catch(() => {});
      if (S.ws) {
        S.ws.loaded = false;
        S.ws.kids = new Map();
      }
      delete S.live[p.sessionId];
      App.renderMain();
    } else {
      delete S.live[p.sessionId];
      // A finished scan can change where a new one would be kept (scan_location): ask again.
      if (S.view.name === "drive" || (S.view.name === "session" && S.ws?.tab === "partitions")) App.renderMain();
    }
    const s = S.sessions.find((x) => x.id === p.sessionId);
    const name = s?.label || "The scan";
    if (p.state === "done") toast(`${name} finished: ${plural(p.files, "file")} found.`, { action: S.view.id === p.sessionId ? null : "Open", onAction: () => App.navigate({ name: "session", id: p.sessionId, tab: "files" }) });
    else if (p.state === "failed") toast(p.error || `${name} failed.`, { error: true });
    else if (p.state === "cancelled") toast(`${name} stopped. Everything found so far is kept.`, { icon: "info" });
  });
  await listen("recovery-progress", (e) => {
    const p = e.payload;
    const r = (S.recoveries[p.job] = S.recoveries[p.job] || { job: p.job, sessionId: p.sessionId });
    r.progress = p;
    App.renderDock();
  });
  await listen("recovery-done", (e) => {
    const p = e.payload;
    const r = (S.recoveries[p.job] = S.recoveries[p.job] || { job: p.job, sessionId: p.sessionId });
    r.done = p;
    S.history = null;
    App.renderDock();
  });
  await listen("imaging-progress", (e) => {
    const p = e.payload;
    if (!S.imaging || S.imaging.job !== p.job) return;
    S.imaging.progress = p;
    if (S.view.name === "imaging") App.renderMain();
    else App.renderDock();
  });
  await listen("imaging-done", (e) => {
    const p = e.payload;
    if (!S.imaging || S.imaging.job !== p.job) {
      // Arrived before start_imaging returned its id.
      S.pendingImagingDone = p;
      return;
    }
    App.imagingDone(p);
  });
  await listen("dupes-progress", (e) => {
    const p = e.payload;
    const { result, ...prev } = S.dupes[p.sessionId] || {};
    // Progress of a new run: an older run's result no longer says the search is finished.
    S.dupes[p.sessionId] = result && result.job === p.job ? { ...prev, ...p, result } : { ...prev, ...p };
  });
  await listen("dupes-done", async (e) => {
    const p = e.payload;
    S.dupes[p.sessionId] = { ...(S.dupes[p.sessionId] || {}), result: p };
    if (p.state === "done") markDupesChecked(p.sessionId);
    if (p.state === "done") toast(p.groups ? `Found ${plural(p.groups, "group")} of identical files (${plural(p.files, "file")}, ${bytes(p.wastedBytes)} in extra copies).` : "No duplicate files found.", { icon: "copy" });
    else toast("Duplicate detection stopped.", { icon: "info" });
    if (S.view.name === "session" && S.view.id === p.sessionId && S.ws) {
      S.ws.loaded = false;
      App.renderMain();
    }
  });
  // The window's close button while jobs run: the backend keeps the window open and asks first.
  await listen("confirm-exit", (e) => confirmExit(e.payload || {}));
}

let exitAsking = false;
async function confirmExit(jobs) {
  if (exitAsking) return;
  exitAsking = true;
  try {
    closePopover();
    // Only one dialog can be open: whatever was open is cancelled. The 'close' event fires
    // later (a task, not at once), so wait for it before reusing the dialog; otherwise the
    // new dialog's listener would receive the stale event and resolve as cancelled.
    const dlg = document.getElementById("dlg");
    if (dlg?.open) {
      await new Promise((resolve) => {
        dlg.addEventListener("close", resolve, { once: true });
        dlg.close("cancel");
      });
    }
    const ok = await confirmDialog({
      title: "MAX is still working",
      body: esc(busyText(jobs) || "MAX is still working.") + " Close MAX anyway?",
      ok: "Close MAX",
      cancel: "Keep working",
      danger: true,
    });
    if (ok) await invoke("exit_app").catch(toastError);
  } finally {
    exitAsking = false;
  }
}

// One-time warnings from the backend at start: portable data kept elsewhere, data folder of another
// account, settings file that couldn't be used. Settings keeps showing them as callouts.
function startupNotices() {
  const notes = [S.sys?.portableWarning, S.settings?.loadWarning].filter(Boolean);
  for (const n of notes) toast(n, { icon: "circle-alert", action: "Settings", onAction: () => App.navigate({ name: "settings" }), ms: 12000 });
  // Where the data folder is when it isn't the signed-in user's: information, shown once per start.
  if (S.sys?.dataNote) toast(S.sys.dataNote, { icon: "info", action: "Settings", onAction: () => App.navigate({ name: "settings" }), ms: 12000 });
}

// imaging-done, also when it arrived before start_imaging returned its id (tools.js).
App.imagingDone = (p) => {
  if (!S.imaging || S.imaging.job !== p.job) return;
  S.imaging.done = p;
  App.render();
  if (p.state === "done") {
    const what = p.note || (p.badRanges?.length ? `${plural(p.badRanges.length, "range")} couldn't be read and were filled with zeros.` : "");
    toast(`Disk image finished.${what ? ` ${what}` : ""}`, { icon: what ? "file-warning" : "circle-check", action: "Scan it", onAction: () => App.actions["img-scan"]() });
  } else if (p.state === "failed") toast([p.error || "Imaging failed.", p.note].filter(Boolean).join(" "), { error: true });
  else if (p.state === "cancelled") toast(p.note || "Imaging stopped. The partial image is kept.", { icon: "info" });
};

// Duplicate detection ran to the end for this many files: no need to hash them again after a restart.
function markDupesChecked(sessionId) {
  const files = S.sessionCache[sessionId]?.summary.files ?? S.sessions.find((x) => x.id === sessionId)?.files;
  if (files == null) return;
  const m = load("dupesChecked", {});
  m[sessionId] = files;
  save("dupesChecked", m);
}

// ------------------------------------------------------------------------------- DOM events
document.addEventListener("click", (e) => {
  const el = e.target.closest("[data-action]");
  if (!el || el.disabled || el.getAttribute("aria-disabled") === "true") return;
  // Checkboxes/radios with actions are handled on change.
  if ((el.type === "checkbox" || el.type === "radio") && el.tagName === "INPUT") return;
  const fn = App.actions[el.dataset.action];
  if (!fn) return;
  e.stopPropagation();
  fn(el, e);
});
document.addEventListener("change", (e) => {
  const el = e.target;
  if (el.matches?.('input[data-action][type="checkbox"], input[data-action][type="radio"]')) {
    App.actions[el.dataset.action]?.(el, e);
    return;
  }
  if (el.id === "ws-sort") return onSortChange(el);
  onToolChange(e);
});
document.addEventListener("keydown", (e) => {
  // F5 / Ctrl+R would reload the whole WebView and lose state: refresh data instead.
  if (e.key === "F5" || ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "r")) {
    e.preventDefault();
    if (e.repeat || document.querySelector("dialog[open]")) return;
    App.refreshDevices(true);
    App.refreshSessions();
    if (S.view.name === "session" && S.ws) {
      S.ws.loaded = false;
      S.ws.kids = new Map();
      loadSession(S.view.id, true).then(() => App.renderMain());
    }
    return;
  }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "f" && S.view.name === "session") {
    const s = document.getElementById("ws-search");
    if (s) {
      e.preventDefault();
      s.focus();
      s.select();
    }
    return;
  }
  if (wsKey(e)) return;
  if (e.key === "Enter" || e.key === " ") {
    const row = e.target.closest?.('[role="row"][data-action], .tile[data-action], .drive-card');
    if (row && e.target === row) {
      e.preventDefault();
      row.click();
    }
  }
});

// ------------------------------------------------------------------------- mock hash hooks
// Only under the browser mock: put the UI into a given state from the URL, for screenshots.
async function applyHashHooks() {
  if (!isMock()) return;
  const h = new URLSearchParams(location.hash.slice(1));
  const m = window.__MAX_MOCK__;
  if (h.get("admin") === "0") m.state.elevated = false;
  if (h.get("nosessions") === "1") m.state.noSessions = true;
  if (h.get("warnings") === "1") {
    m.state.portableWarning = "MAX can't write next to its program on this drive, so its data is kept in your user profile this time.";
    m.state.settingsWarning = "Your settings file couldn't be read, so MAX started with its default settings. Check them in Settings.";
  }
  const t = h.get("theme");
  if (t === "dark" || t === "light") document.documentElement.dataset.theme = t;
  return h;
}
async function routeFromHash(h) {
  if (!h) return false;
  const view = h.get("view");
  if (h.get("startscan")) {
    // e.g. #startscan=deep:volume:F — start a live mock scan and open it.
    const [mode, kind, path] = h.get("startscan").split(":");
    const r = await invoke("start_scan", { source: { kind, path }, options: { mode } });
    scanStarted(r);
    S.sessions = await invoke("list_sessions");
    S.view = { name: "session", id: r.sessionId, tab: h.get("tab") || "map" };
    await loadSession(r.sessionId, true).catch(() => {});
    return true;
  }
  if (!view) return false;
  if (view === "session") {
    const id = h.get("session") || S.sessions[Number(h.get("idx") || 0)]?.id;
    if (!id) return false;
    S.view = { name: "session", id, tab: h.get("tab") || "files" };
    await loadSession(id, true).catch(() => {});
    renderSessionState(h);
  } else if (view === "drive") {
    const [kind, path] = (h.get("source") || "volume:C").split(":");
    S.view = { name: "drive", source: { kind, path } };
    if (h.get("mode")) S.drive = { source: S.view.source, mode: h.get("mode"), cats: null, existing: null };
    // #view=drive&source=volume:D&folder=Photos/Trip — a folder scan, as picked with "Scan a folder".
    if (h.get("folder")) {
      const folder = "\\" + h.get("folder").replace(/\//g, "\\");
      S.drive = { source: S.view.source, mode: "quick", cats: null, existing: null, folder: { source: S.view.source, folder, display: `${path}:${folder}` } };
    }
  } else S.view = { name: view };
  if (view === "home" && h.get("pick")) {
    const [kind, path] = h.get("pick").split(":");
    S.home = { scenario: h.get("scenario") || "deleted", pick: { kind, path } };
  }
  return true;
}
function renderSessionState(h) {
  App.renderMain();
  if (h.get("mode") && S.ws) S.ws.mode = h.get("mode");
  if (h.get("cat") && S.ws) S.ws.cats = [h.get("cat")];
  if (h.get("file") && S.ws) {
    S.ws.inspTab = h.get("insp") || "preview";
    setTimeout(() => focusFileById(Number(h.get("file"))), 400);
  }
  if (h.get("dialog") === "recover") setTimeout(() => App.actions["recover-all"]?.(), 600);
}

// ------------------------------------------------------------------------------------ boot
async function boot() {
  initTooltips();
  const imgPaths = load("images", []);
  const hooks = await applyHashHooks();
  const [sys, , sessions, types, settings] = await Promise.all([
    invoke("system_info").catch(() => null),
    App.refreshDevices(),
    invoke("list_sessions").catch(() => []),
    invoke("list_file_types").catch(() => []),
    invoke("get_settings").catch(() => null),
  ]);
  S.sys = sys;
  S.sessions = sessions;
  S.types = types;
  S.settings = settings;
  // Re-open the images used last time (silently drop the ones that went away).
  const imgs = await Promise.all(imgPaths.map((p) => invoke("open_image", { path: p }).then((info) => ({ path: p, info })).catch(() => null)));
  S.images = imgs.filter(Boolean);
  await bindEvents();

  // Running scans (e.g. after a reload) show live progress again on their first event.
  const routed = await routeFromHash(hooks);
  if (!routed) {
    const last = load("lastView", null);
    if (last?.name === "session" && S.sessions.some((s) => s.id === last.id)) S.view = { name: "session", id: last.id };
    else if (last?.name === "drive" && last.source) S.view = last;
    else if (last && ["imaging", "rules", "history", "settings"].includes(last.name)) S.view = { name: last.name };
  }
  App.render();
  perf("js:first-render");
  requestAnimationFrame(() =>
    requestAnimationFrame(() => {
      perf("js:first-paint");
      invoke("app_ready").catch(() => {});
    }),
  );
  if (document.visibilityState === "hidden") invoke("app_ready").catch(() => {});

  startupNotices();

  // Interrupted scans (MAX closed or crashed mid-scan) get one gentle reminder.
  const interrupted = S.sessions.filter((s) => s.state === "interrupted");
  if (interrupted.length && !hooks?.get("view"))
    toast(`${plural(interrupted.length, "scan")} stopped before finishing last time. Open ${interrupted.length === 1 ? "it" : "one"} to resume.`, {
      icon: "history",
      action: "Open",
      onAction: () => App.navigate({ name: "session", id: interrupted[0].id }),
      ms: 9000,
    });

  // Daily update check (only when a feed is set up).
  if (S.settings?.checkUpdates && S.settings.updateFeed && Date.now() - load("updateCheckedAt", 0) > 86400000) {
    setTimeout(async () => {
      try {
        S.update = await invoke("check_for_updates");
        save("updateCheckedAt", Date.now());
        if (S.update.updateAvailable) toast(`MAX ${S.update.latest} is available.`, { icon: "download", action: "Details", onAction: () => App.navigate({ name: "settings" }) });
      } catch {}
    }, 8000);
  }
  // Refresh relative times in the rail now and then.
  setInterval(() => !document.hidden && renderRail(), 60000);
}

boot().catch((e) => {
  document.getElementById("main").innerHTML = `<div class="empty"><h3>MAX couldn't start its interface</h3><p>${esc(errText(e))}</p></div>`;
  invoke("app_ready").catch(() => {});
});
void stagePct;
