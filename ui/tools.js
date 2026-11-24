// Tool pages: Disk imaging, Carving rules (custom signatures), Recovery history + all scans,
// Settings.
import { S, App, esc, icon, bytes, int, date, ago, plural, duration, rate, invoke, toast, toastError, errText, needsAdmin, patch, restoringFocus, confirmDialog, save, load } from "./core.js";
import { describeSource, modeLabel, stateLabel, adminToast, relaunchAdmin, openImage, busLabel } from "./start.js";

// ---------------------------------------------------------------------------------- imaging
export function renderImaging() {
  const im = S.imaging;
  const sources = [];
  if (S.devices) {
    for (const d of S.devices.disks) sources.push({ v: `disk:${d.index}`, label: `${d.model || `Disk ${d.index}`} — whole disk (${bytes(d.size)}, ${busLabel(d)})`, src: { kind: "disk", path: String(d.index) } });
    for (const v of S.devices.volumes.filter((x) => x.driveType !== "network" && x.driveType !== "cdrom")) sources.push({ v: `volume:${v.letter}`, label: `${v.letter}: ${v.label || v.fs || ""} (${bytes(v.size)})`, src: { kind: "volume", path: v.letter } });
  }
  S.imgForm = S.imgForm || { source: "", dest: "", retries: 2 };
  // "Image this drive" asks for a specific drive: it replaces whatever was picked here before.
  const pre = S.imagingPrefill;
  if (pre) {
    S.imgForm.source = `${pre.kind}:${pre.path}`;
    S.imagingPrefill = null;
  }
  const sel = S.imgForm.source || sources[0]?.v || "";
  S.imgForm.source = sel;
  // A drive that isn't in the list (e.g. a restore point) is still shown, so the list matches what
  // will be copied.
  if (sel && !sources.some((s) => s.v === sel)) {
    const [kind, ...rest] = sel.split(":");
    sources.unshift({ v: sel, label: describeSource({ kind, path: rest.join(":") }).title || sel });
  }
  const running = im && !im.done;
  let status = "";
  if (im) {
    const p = im.progress || {};
    const pct = p.bytesTotal ? Math.floor((p.bytesDone / p.bytesTotal) * 100) : 0;
    if (!im.done)
      status = `<div class="panel"><h3>${esc({ paused: "Paused", retrying: "Retrying unreadable sectors of", hashing: "Checking the image of" }[p.state] || "Imaging")} ${esc(describeSource(im.source).title)}</h3>
        <div class="pbar${p.state === "paused" ? " paused" : ""}"><i style="width:${pct}%"></i></div>
        <div class="prog-line"><span><b>${pct}%</b> · ${bytes(p.bytesDone || 0)} of ${bytes(p.bytesTotal || 0)}</span>${p.bytesPerSec ? `<span>${rate(p.bytesPerSec)}</span>` : ""}${p.etaSeconds != null ? `<span>About ${duration(p.etaSeconds)} left</span>` : ""}${p.badBytes ? `<span class="tag danger">${bytes(p.badBytes)} unreadable so far</span>` : ""}</div>
        <div class="row"><button class="btn" data-action="img-pause">${icon(p.state === "paused" ? "play" : "pause", "s")} ${p.state === "paused" ? "Continue" : "Pause"}</button><button class="btn ghost" data-action="img-cancel">${icon("square", "s")} Stop</button><span class="faint" style="font-size:var(--fs-s)">Writing to ${esc(im.path)}</span></div></div>`;
    else {
      const d = im.done;
      status = `<div class="panel"><h3>${d.state === "done" ? "Image finished" : d.state === "cancelled" ? "Imaging stopped" : "Imaging failed"}</h3>
        ${d.error ? `<div class="callout danger">${icon("circle-x")}<div>${esc(d.error)}</div></div>` : ""}
        <dl class="kv"><dt>Image file</dt><dd>${esc(d.path)}</dd><dt>Written</dt><dd>${bytes(d.bytesWritten)}</dd><dt>Unreadable</dt><dd>${d.badRanges?.length ? `${plural(d.badRanges.length, "range")}, ${bytes(d.badRanges.reduce((a, [s, e]) => a + (e - s), 0))} (filled with zeros)` : "None"}</dd>${d.blake3 ? `<dt>BLAKE3</dt><dd class="mono">${esc(d.blake3)}</dd>` : ""}</dl>
        ${d.note ? `<p class="muted" style="margin:0">${esc(d.note)}</p>` : d.state === "cancelled" ? `<p class="muted" style="margin:0">The partial image is kept. Scanning it finds files in the part that was copied.</p>` : ""}
        <div class="row">${d.state !== "failed" ? `<button class="btn primary" data-action="img-scan">${icon("scan-search", "s")} Scan the image</button>` : ""}<button class="btn" data-action="img-show">${icon("folder-open", "s")} Show in Explorer</button><button class="btn ghost" data-action="img-new">Make another image</button></div></div>`;
    }
  }
  const form = `<div class="panel"><h3>New disk image</h3>
    ${!S.sys?.elevated ? `<div class="callout warn">${icon("shield-alert")}<div class="grow">Reading a drive sector by sector needs administrator rights.</div><button class="btn small" data-action="relaunch-admin">Restart as administrator</button></div>` : ""}
    <div class="field"><label for="img-src">Drive to copy</label><select id="img-src" ${running ? "disabled" : ""}>${sources.map((s) => `<option value="${esc(s.v)}" ${s.v === sel ? "selected" : ""}>${esc(s.label)}</option>`).join("")}</select><span class="hint">Copy the whole disk to also keep deleted partitions and unallocated space.</span></div>
    <div class="field"><label for="img-dest">Save the image as</label><div class="row"><input type="text" id="img-dest" style="flex:1" placeholder="E:\\Images\\disk.img" value="${esc(S.imgForm.dest)}" ${running ? "disabled" : ""} spellcheck="false"><button class="btn" data-action="img-browse" ${running ? "disabled" : ""}>${icon("folder-open", "s")} Choose…</button></div><span class="hint">Must be on a different drive, with enough free space for the whole copy.</span></div>
    <div class="field"><label for="img-retries">Retries for unreadable sectors</label><select id="img-retries" style="width:120px" ${running ? "disabled" : ""}>${[1, 2, 4, 8].map((n) => `<option ${S.imgForm.retries === n ? "selected" : ""}>${n}</option>`).join("")}</select><span class="hint">More retries recover more of a failing drive but take longer. Unreadable sectors become zeros in the image and are listed in its log.</span></div>
    <div><button class="btn primary" data-action="img-start" ${running ? "disabled" : ""}>${icon("hard-drive-download", "s")} Start imaging</button></div></div>`;
  const body = `<div class="page"><div class="tool"><div><h2>Disk imaging</h2><p class="lede">Copy a drive sector by sector into an image file, then recover from the copy. Do this first when a drive is failing: every extra read can damage it further, and the image can be scanned as often as you like.</p></div>${status}${running || (im && !im.done) ? "" : form}</div></div>`;
  return { head: "", body };
}

// ------------------------------------------------------------------------------ carving rules
export function renderRules() {
  const st = S.settings;
  if (!st) return { head: "", body: `<div class="page"><div class="tool"><p class="muted">Loading…</p></div></div>` };
  S.rulesDraft = S.rulesDraft || structuredClone(st.customSignatures || []);
  const rows = S.rulesDraft;
  const cats = ["photo", "video", "audio", "document", "archive", "other"];
  const catName = { photo: "Photo", video: "Video", audio: "Audio", document: "Document", archive: "Archive", other: "Other" };
  const body = `<div class="page"><div class="tool" style="max-width:1080px">
    <div><h2>Carving rules</h2><p class="lede">Teach deep scans a file format MAX doesn't know: the bytes it starts with (and optionally ends with). Use <span class="mono">??</span> for any byte. Rules apply to the next deep scan.</p></div>
    <div class="panel">
      ${rows.length ? `<div class="sig-row faint" style="font-size:var(--fs-xs)"><span></span><span>Name</span><span>Extension</span><span>Starts with (hex)</span><span>Ends with (hex, optional)</span><span>Largest size</span><span></span></div>` : ""}
      ${rows
        .map(
          (r, i) => `<div class="sig-row" data-row="${i}">
        <input type="checkbox" data-rule="enabled" ${r.enabled !== false ? "checked" : ""} aria-label="Use this rule">
        <input type="text" data-rule="name" value="${esc(r.name)}" placeholder="Pentax PEF" aria-label="Name">
        <input type="text" data-rule="ext" value="${esc(r.ext)}" placeholder="pef" aria-label="Extension">
        <input type="text" class="mono" data-rule="header" value="${esc(r.header)}" placeholder="49 49 2A 00 ?? ?? 00 00" aria-label="Header bytes" spellcheck="false">
        <input type="text" class="mono" data-rule="footer" value="${esc(r.footer || "")}" placeholder="FF D9" aria-label="Footer bytes" spellcheck="false">
        <select data-rule="maxSize" aria-label="Largest size">${[1, 10, 50, 100, 500, 2048, 4096].map((mb) => `<option value="${mb * 1048576}" ${r.maxSize === mb * 1048576 ? "selected" : ""}>${mb >= 1024 ? `${mb / 1024} GB` : `${mb} MB`}</option>`).join("")}</select>
        <button class="btn icon ghost" data-action="rule-del" data-key="${i}" aria-label="Delete rule" data-tip="Delete rule">${icon("trash-2", "s")}</button>
        <span></span><select data-rule="category" style="grid-column:2 / 4" aria-label="Kind">${cats.map((c) => `<option value="${c}" ${r.category === c ? "selected" : ""}>${catName[c]}</option>`).join("")}</select>
        <label class="row faint" style="grid-column:4;font-size:var(--fs-s)">Header at byte <input type="number" data-rule="headerOffset" min="0" max="4096" value="${r.headerOffset || 0}" style="width:80px"></label></div>`,
        )
        .join('<hr style="border:0;border-top:1px solid var(--line);margin:4px 0">')}
      ${rows.length ? "" : `<div class="empty" style="padding:24px"><h3>No custom rules</h3><p>MAX already knows about 60 formats (photos, camera RAW, video, audio, Office, archives…). Add a rule for anything else.</p></div>`}
      <div class="row"><button class="btn" data-action="rule-add">${icon("plus", "s")} Add a rule</button><span style="flex:1"></span><button class="btn primary" data-action="rule-save">Save rules</button></div>
    </div>
    <div class="panel"><h3>Formats MAX knows</h3><p class="muted" style="margin:0">${S.types.length ? esc(S.types.filter((t) => t.carvable).map((t) => t.label).join(", ")) : "…"}</p></div>
  </div></div>`;
  return { head: "", body };
}
function readRules() {
  document.querySelectorAll(".sig-row[data-row]").forEach((row) => {
    const r = S.rulesDraft[Number(row.dataset.row)];
    row.querySelectorAll("[data-rule]").forEach((inp) => {
      const k = inp.dataset.rule;
      if (k === "enabled") r.enabled = inp.checked;
      else if (k === "maxSize" || k === "headerOffset") r[k] = Number(inp.value) || 0;
      else r[k] = inp.value;
    });
  });
}

// ---------------------------------------------------------------------------------- history
export function renderHistory() {
  if (!S.history) {
    invoke("recovery_history")
      .then((h) => {
        S.history = h;
        App.renderMain();
      })
      .catch((e) => {
        S.history = [];
        toastError(e);
        App.renderMain();
      });
  }
  const h = S.history || [];
  const sess = S.sessions;
  const body = `<div class="page"><div class="tool" style="max-width:1080px">
    <div><h2>Recovery history</h2><p class="lede">Every recovery and every scan MAX has kept. Scans can be reopened, resumed, saved to a file or deleted.</p></div>
    <div class="panel"><h3>Recoveries</h3>${
      h.length
        ? `<table class="table"><thead><tr><th>When</th><th>From</th><th>To</th><th class="r">Recovered</th><th class="r">Partial</th><th class="r">Failed</th><th class="r">Size</th><th></th></tr></thead><tbody>${h
            .map(
              (r) => `<tr><td class="nowrap">${esc(date(r.finished || r.started, true))}</td><td>${esc(r.sessionLabel)}</td><td class="ellipsis" style="max-width:240px" title="${esc(r.dest)}">${esc(r.dest)}</td><td class="r">${int(r.recovered)}</td><td class="r">${int(r.partial)}</td><td class="r">${int(r.failed)}</td><td class="r">${bytes(r.bytes)}</td><td class="r nowrap">${
                r.reportPath ? `<button class="btn small" data-action="reveal" data-path="${esc(r.reportPath)}">Report</button>` : ""
              } <button class="btn small ghost" data-action="reveal" data-path="${esc(r.dest)}">Folder</button></td></tr>`,
            )
            .join("")}</tbody></table>`
        : `<p class="muted" style="margin:0">Nothing recovered yet.</p>`
    }</div>
    <div class="panel"><div class="row"><h3 style="flex:1">Scans</h3><button class="btn small" data-action="import-session">${icon("upload", "s")} Open a saved scan…</button></div>${
      sess.length
        ? `<table class="table"><thead><tr><th>Scan</th><th>Type</th><th>State</th><th class="r">Files</th><th class="r">Size</th><th>Started</th><th class="r">Stored</th></tr></thead><tbody>${sess
            .map(
              (s) => `<tr><td><button class="btn small ghost" style="padding:0 4px" data-action="open-session" data-id="${esc(s.id)}">${esc(s.label)}</button></td><td>${esc(modeLabel(s.mode))}</td><td>${
                s.state === "interrupted" ? `<span class="tag warn">Interrupted</span>` : s.state === "failed" ? `<span class="tag danger">Failed</span>` : esc(stateLabel(s.state))
              }</td><td class="r">${int(s.files)}</td><td class="r">${bytes(s.bytes)}</td><td class="nowrap">${esc(date(s.created, true))}</td><td class="r">${bytes(s.fileSize)}</td></tr>`,
            )
            .join("")}</tbody></table>`
        : `<p class="muted" style="margin:0">No scans yet.</p>`
    }</div></div></div>`;
  return { head: "", body };
}

// --------------------------------------------------------------------------------- settings
export function renderSettings() {
  const st = S.settings;
  const sys = S.sys || {};
  const theme = load("theme", "system");
  if (!st) return { head: "", body: `<div class="page"><div class="tool"><p class="muted">Loading…</p></div></div>` };
  const u = S.update;
  const body = `<div class="page"><div class="tool">
    <div><h2>Settings</h2></div>
    <div class="panel"><h3>Appearance</h3>
      <div class="seg" role="radiogroup" aria-label="Theme">${["system", "light", "dark"].map((t) => `<button data-action="set-theme" data-key="${t}" aria-pressed="${theme === t}">${icon({ system: "monitor", light: "sun", dark: "moon" }[t], "s")}${{ system: "Match Windows", light: "Light", dark: "Dark" }[t]}</button>`).join("")}</div></div>
    <div class="panel"><h3>Administrator rights</h3>
      <p class="muted" style="margin:0">Windows only lets administrators read drive sectors, which nearly every scan needs. ${sys.elevated ? "MAX is running as administrator now." : "MAX is running without administrator rights now."}</p>
      ${
        sys.askAdminAtStart == null
          ? `<p class="faint" style="margin:0">This instance runs as a different Windows account, so this setting can only be changed in standard mode.</p>`
          : `<label class="check"><input type="checkbox" data-action="set-ask-admin" ${sys.askAdminAtStart ? "checked" : ""}><span>Ask for administrator rights when MAX starts<small>Turn off to start without the Windows prompt; you can still restart as administrator when needed.</small></span></label>`
      }
      ${sys.elevated ? "" : `<div><button class="btn" data-action="relaunch-admin">${icon("shield", "s")} Restart as administrator</button></div>`}</div>
    <div class="panel"><h3>Recovering files</h3>
      ${[
        ["keepFolders", "Recreate the original folders", "Recovered files go into their reconstructed folders."],
        ["verifyRecovered", "Verify every file after writing it", "Reads each file back and compares checksums."],
        ["repairDamaged", "Try to repair damaged files", "Adds a “(repaired)” copy; the original is kept as found."],
        ["skipDuplicates", "Skip identical copies", "Files with the same content are written once."],
      ]
        .map(([k, l, s]) => `<label class="check"><input type="checkbox" data-action="set-bool" data-key="${k}" ${st[k] ? "checked" : ""}><span>${l}<small>${s}</small></span></label>`)
        .join("")}
      <div class="field"><label>Default destination</label><div class="row"><input type="text" id="set-dest" style="flex:1" value="${esc(st.defaultDestination || "")}" placeholder="Asked each time" spellcheck="false"><button class="btn" data-action="set-dest-browse">${icon("folder-open", "s")} Choose…</button></div></div></div>
    <div class="panel"><h3>Updates</h3>
      <label class="check"><input type="checkbox" data-action="set-bool" data-key="checkUpdates" ${st.checkUpdates ? "checked" : ""}><span>Check for a new version once a day<small>MAX only checks and tells you; it never downloads or installs anything by itself.</small></span></label>
      <div class="field"><label for="set-feed">Release feed</label><input type="text" id="set-feed" value="${esc(st.updateFeed || "")}" placeholder="https://api.github.com/repos/<owner>/<repo>/releases/latest" spellcheck="false"><span class="hint">Where new versions are announced. Leave empty to turn update checks off.</span></div>
      <div class="row"><button class="btn" data-action="check-updates">${icon("refresh-cw", "s")} Check now</button><span class="muted" style="font-size:var(--fs-s)">${
        u ? (u.notConfigured ? "No release feed is set." : u.updateAvailable ? `Version ${esc(u.latest)} is available.` : `You have the latest version (${esc(u.current)}).`) : `You have version ${esc(sys.version || "")}.`
      }</span>${u?.updateAvailable && u.url ? `<button class="btn primary small" data-action="open-url" data-path="${esc(u.url)}">Get version ${esc(u.latest)}</button>` : ""}</div></div>
    <div class="panel"><h3>Where MAX keeps its data</h3>
      <p class="muted" style="margin:0">${sys.portable ? "Portable mode: everything stays next to the program, so MAX can run from a USB stick." : "Scans, settings and logs are stored in your user profile."}</p>
      ${[sys.portableWarning, st.loadWarning]
        .filter(Boolean)
        .map((n) => `<div class="callout warn">${icon("circle-alert")}<div>${esc(n)}</div></div>`)
        .join("")}
      ${sys.dataNote ? `<div class="callout">${icon("info")}<div>${esc(sys.dataNote)}</div></div>` : ""}
      <div class="row"><span class="mono ellipsis" style="flex:1">${esc(sys.dataDir || "")}</span><button class="btn small" data-action="reveal" data-path="${esc(sys.dataDir || "")}">Show</button></div>
      ${sys.portable ? "" : `<p class="faint" style="margin:0;font-size:var(--fs-s)">To use MAX portably, copy its program folder to a USB stick and create an empty file named <span class="mono">portable</span> next to max-recovery.exe.</p>`}</div>
    <p class="faint" style="font-size:var(--fs-s)">MAX File Recovery ${esc(sys.version || "")}. Sources are always opened read-only.</p>
  </div></div>`;
  return { head: "", body };
}

async function saveSettings(patchObj) {
  try {
    S.settings = await invoke("save_settings", { settings: { ...S.settings, ...patchObj } });
  } catch (e) {
    toastError(e);
  }
}

// ---------------------------------------------------------------------------------- actions
Object.assign(App.actions, {
  "img-browse": async () => {
    readImgForm();
    try {
      const p = await window.__TAURI__.dialog.save({ title: "Save the disk image as", defaultPath: "disk.img", filters: [{ name: "Raw disk image", extensions: ["img"] }] });
      if (p) {
        S.imgForm.dest = p;
        App.renderMain();
      }
    } catch (e) {
      toastError(e);
    }
  },
  "img-start": async () => {
    readImgForm();
    const f = S.imgForm;
    const [kind, ...rest] = f.source.split(":");
    const source = { kind, path: rest.join(":") };
    if (!f.dest.trim()) return toast("Choose where to save the image first.", { icon: "info" });
    try {
      const r = await invoke("start_imaging", { source, dest: f.dest.trim(), options: { retries: f.retries, hash: true } });
      S.imaging = { job: r.job, path: r.path, source, progress: { bytesDone: 0, bytesTotal: 0, state: "running" }, done: S.imaging?.job === r.job ? S.imaging.done : null };
      const early = S.pendingImagingDone?.job === r.job ? S.pendingImagingDone : null;
      S.pendingImagingDone = null;
      App.renderMain();
      App.renderRail();
      if (early) App.imagingDone(early);
    } catch (e) {
      if (needsAdmin(e)) adminToast(e);
      else toastError(e);
    }
  },
  "img-pause": async () => {
    const p = S.imaging?.progress;
    try {
      await invoke("pause_imaging", { job: S.imaging.job, paused: p?.state !== "paused" });
    } catch (e) {
      toastError(e);
    }
  },
  "img-cancel": async () => {
    const ok = await confirmDialog({ title: "Stop imaging?", body: "The part copied so far is kept as a partial image that can still be scanned.", ok: "Stop", cancel: "Keep copying" });
    if (!ok) return;
    try {
      await invoke("cancel_imaging", { job: S.imaging.job });
    } catch (e) {
      toastError(e);
    }
  },
  "img-scan": async () => {
    const path = S.imaging.done.path;
    try {
      const info = await invoke("open_image", { path });
      S.images = [{ path, info }, ...S.images.filter((i) => i.path.toLowerCase() !== path.toLowerCase())];
      save("images", S.images.map((i) => i.path));
      App.navigate({ name: "drive", source: { kind: "image", path } });
    } catch (e) {
      toastError(e);
    }
  },
  "img-show": () => invoke("reveal_path", { path: S.imaging.done.path }).catch(toastError),
  "img-new": () => {
    S.imaging = null;
    App.renderMain();
  },
  "rule-add": () => {
    readRules();
    S.rulesDraft.push({ id: "", name: "", ext: "", category: "other", header: "", headerOffset: 0, footer: "", maxSize: 50 * 1048576, enabled: true });
    App.renderMain();
  },
  "rule-del": (el) => {
    readRules();
    S.rulesDraft.splice(Number(el.dataset.key), 1);
    App.renderMain();
  },
  "rule-save": async () => {
    readRules();
    try {
      S.settings = await invoke("save_settings", { settings: { ...S.settings, customSignatures: S.rulesDraft.filter((r) => r.name || r.header) } });
      S.rulesDraft = structuredClone(S.settings.customSignatures);
      App.renderMain();
      toast("Rules saved. They apply to the next deep scan.");
    } catch (e) {
      toastError(e);
    }
  },
  reveal: (el) => invoke("reveal_path", { path: el.dataset.path }).catch(toastError),
  "open-url": (el) => {
    // open_url only opens https:// links, in the default browser. If that fails, show the link.
    const url = el.dataset.path;
    invoke("open_url", { url }).catch((e) => toast(`${errText(e)} ${url}`, { error: true }));
  },
  "import-session": async () => {
    try {
      const path = await window.__TAURI__.dialog.open({ multiple: false, title: "Open a saved scan", filters: [{ name: "MAX scan", extensions: ["maxscan"] }] });
      if (!path) return;
      const id = await invoke("import_session", { path });
      await App.refreshSessions();
      App.navigate({ name: "session", id });
    } catch (e) {
      toastError(e);
    }
  },
  "set-theme": (el) => App.setTheme(el.dataset.key),
  "set-ask-admin": async (el) => {
    try {
      await invoke("set_ask_admin", { enabled: el.checked });
      S.sys.askAdminAtStart = el.checked;
    } catch (e) {
      el.checked = !el.checked;
      toastError(e);
    }
  },
  "set-bool": (el) => saveSettings({ [el.dataset.key]: el.checked }),
  "set-dest-browse": async () => {
    try {
      const p = await window.__TAURI__.dialog.open({ directory: true, multiple: false, title: "Default destination for recovered files" });
      if (p) {
        await saveSettings({ defaultDestination: p });
        App.renderMain();
      }
    } catch (e) {
      toastError(e);
    }
  },
  "check-updates": async (el) => {
    const feed = document.getElementById("set-feed")?.value.trim() ?? "";
    if (feed !== (S.settings.updateFeed || "")) await saveSettings({ updateFeed: feed });
    el.disabled = true;
    try {
      S.update = await invoke("check_for_updates");
      save("updateCheckedAt", Date.now());
    } catch (e) {
      toastError(e);
    }
    App.renderMain();
  },
});

function readImgForm() {
  const s = document.getElementById("img-src");
  const d = document.getElementById("img-dest");
  const r = document.getElementById("img-retries");
  if (s) S.imgForm.source = s.value;
  if (d) S.imgForm.dest = d.value;
  if (r) S.imgForm.retries = Number(r.value);
}

// Inputs that save on change (not click actions).
export function onToolChange(e) {
  const t = e.target;
  if (t.id === "set-dest") saveSettings({ defaultDestination: t.value.trim() || null });
  if (t.id === "set-feed") saveSettings({ updateFeed: t.value.trim() });
  if (t.id === "img-src" || t.id === "img-dest" || t.id === "img-retries") readImgForm();
}
void openImage;
void relaunchAdmin;
void errText;
void ago;
