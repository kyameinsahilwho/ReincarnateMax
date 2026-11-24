// Rail (drives, images, scans, tools), the Start page ("What happened to your files?") and the
// drive page (identity, warnings, Recovery Map of the last scan, scan options).
import {
  S, App, esc, icon, bytes, int, date, ago, plural, duration, sourceLabel, sourceIcon, sameSource, invoke, toast, toastError,
  needsAdmin, errText, showDialog, load, save, $, patch, restoringFocus, confirmDialog, scanStarted, runningJobs, busyText,
} from "./core.js";
import { RecoveryMap } from "./map.js";

// ------------------------------------------------------------------------------ device lookup
export function volumeOf(letter) {
  return S.devices?.volumes.find((v) => v.letter.toUpperCase() === String(letter).toUpperCase());
}
export function diskOf(index) {
  return S.devices?.disks.find((d) => String(d.index) === String(index));
}
export function busLabel(d) {
  if (!d) return "";
  const media = d.media === "Unknown" ? "" : d.media;
  return [d.bus, media].filter(Boolean).join(" ");
}
export function describeSource(src) {
  // -> {title, sub, icon, disk, volume, image}
  if (!src) return { title: "", sub: "" };
  if (src.kind === "volume") {
    const v = volumeOf(src.path);
    const d = v && v.diskIndex != null ? diskOf(v.diskIndex) : null;
    return {
      title: `${src.path}:${v?.label ? ` ${v.label}` : ""}`,
      sub: [v?.fs || "Unknown file system", v ? bytes(v.size) : "", d ? `${d.model} (${busLabel(d)})` : ""].filter(Boolean).join(" · "),
      icon: sourceIcon(src, d),
      disk: d,
      volume: v,
    };
  }
  if (src.kind === "disk") {
    const d = diskOf(src.path);
    const window = src.offset ? ` · partition at ${bytes(src.offset)}` : "";
    return {
      title: d ? d.model || `Disk ${src.path}` : `Disk ${src.path}`,
      sub: d ? `Disk ${d.index} · ${bytes(d.size)} · ${busLabel(d)} · ${d.partitionStyle}${window}` : `Disk ${src.path}${window}`,
      icon: sourceIcon(src, d),
      disk: d,
    };
  }
  if (src.kind === "image") {
    const img = S.images.find((i) => i.path.toLowerCase() === src.path.toLowerCase());
    const name = src.path.split(/[\\/]/).pop();
    const window = src.offset ? ` · partition at ${bytes(src.offset)}` : "";
    return {
      title: name,
      sub: img ? `Disk image · ${bytes(img.info.size)} · ${img.info.fs || img.info.partitionStyle}${window}` : `Disk image${window}`,
      icon: "disc-3",
      image: img,
    };
  }
  if (src.kind === "snapshot") {
    const s = S.devices?.snapshots.find((x) => x.devicePath === src.path);
    return { title: `Restore point of ${s?.volume || "?"}:`, sub: s ? `Created ${date(s.created, true)}` : "Volume Shadow Copy", icon: "history" };
  }
  return { title: sourceLabel(src), sub: "" };
}

// ------------------------------------------------------------------------------------- rail
export function renderRail() {
  const v = S.view;
  const cur = (cond) => (cond ? ' aria-current="true"' : "");
  const isSrc = (src) => v.name === "drive" && sameSource(v.source, src);
  let h = `<div class="brand">
    <svg class="brand-mark" viewBox="0 0 26 26" aria-hidden="true"><rect width="26" height="26" rx="7" fill="#2c205c"/>${[0, 1, 2, 3]
      .map((r) =>
        [0, 1, 2, 3]
          .map((c) => {
            const lit = c === 0 || c === 3 || (r === c && r < 2) || (r + c === 3 && r < 2);
            return `<rect x="${4 + c * 4.75}" y="${4 + r * 4.75}" width="3.5" height="3.5" rx="0.8" fill="${lit ? "#beb0ff" : "#4e408c"}"/>`;
          })
          .join(""),
      )
      .join("")}</svg>
    <div class="brand-name">MAX<small>File Recovery</small></div>
  </div><div class="rail-scroll">`;
  h += `<button class="rail-item" data-action="go-home"${cur(v.name === "home")}>${icon("scan-search")}<span>Find lost files</span></button>`;

  // Drives: physical disks with their volumes.
  h += `<div class="rail-group"><div class="rail-group-head"><span>Drives</span><button data-action="refresh-devices" data-tip="Refresh the drive list" aria-label="Refresh drives">${icon("refresh-cw", "s")}</button></div>`;
  if (!S.devices) {
    h += `<div class="rail-item faint">${S.devicesError ? esc(S.devicesError) : "Looking for drives…"}</div>`;
  } else {
    for (const d of S.devices.disks) {
      const src = { kind: "disk", path: String(d.index) };
      h += `<button class="rail-item" data-action="open-source" data-kind="disk" data-path="${d.index}"${cur(isSrc(src))}>${icon(sourceIcon(src, d))}<span class="two ellipsis"><span class="ellipsis">${esc(d.model || `Disk ${d.index}`)}</span><small>Disk ${d.index} · ${bytes(d.size)}</small></span></button>`;
      for (const vol of S.devices.volumes.filter((x) => x.diskIndex === d.index)) {
        const vs = { kind: "volume", path: vol.letter };
        h += `<button class="rail-item sub" data-action="open-source" data-kind="volume" data-path="${esc(vol.letter)}"${cur(isSrc(vs))}><span class="ellipsis"><b>${esc(vol.letter)}:</b> ${esc(vol.label || vol.fs || "")}</span><span class="meta">${vol.state === "ready" ? bytes(vol.size) : esc(volState(vol))}</span></button>`;
      }
    }
    const orphans = S.devices.volumes.filter((x) => x.diskIndex == null && x.driveType !== "network");
    for (const vol of orphans) {
      h += `<button class="rail-item" data-action="open-source" data-kind="volume" data-path="${esc(vol.letter)}"${cur(isSrc({ kind: "volume", path: vol.letter }))}>${icon("hard-drive")}<span class="ellipsis"><b>${esc(vol.letter)}:</b> ${esc(vol.label || vol.fs)}</span><span class="meta">${bytes(vol.size)}</span></button>`;
    }
  }
  h += `</div>`;

  // Disk images.
  h += `<div class="rail-group"><div class="rail-group-head"><span>Disk images</span><button data-action="open-image" data-tip="Open a disk image (.img, .dd, .vhd, .vhdx)" aria-label="Open a disk image">${icon("plus", "s")}</button></div>`;
  if (!S.images.length) h += `<button class="rail-item faint" data-action="open-image">${icon("disc-3")}<span>Open a disk image…</span></button>`;
  for (const img of S.images) {
    const src = { kind: "image", path: img.path };
    h += `<button class="rail-item" data-action="open-source" data-kind="image" data-path="${esc(img.path)}"${cur(isSrc(src))} data-tip="${esc(img.path)}">${icon("disc-3")}<span class="ellipsis">${esc(img.path.split(/[\\/]/).pop())}</span><span class="meta">${bytes(img.info.size)}</span></button>`;
  }
  h += `</div>`;

  // Restore points (shadow copies) — only listed when elevated.
  if (S.devices?.snapshots?.length) {
    h += `<div class="rail-group"><div class="rail-group-head"><span>Restore points</span></div>`;
    for (const s of S.devices.snapshots) {
      const src = { kind: "snapshot", path: s.devicePath };
      h += `<button class="rail-item" data-action="open-source" data-kind="snapshot" data-path="${esc(s.devicePath)}"${cur(isSrc(src))}>${icon("history")}<span class="ellipsis">${esc(s.volume || "?")}: ${esc(date(s.created, true))}</span></button>`;
    }
    h += `</div>`;
  }

  // Scans.
  h += `<div class="rail-group"><div class="rail-group-head"><span>Scans</span><button data-action="go" data-view="scans" data-tip="All scans" aria-label="All scans">${icon("layers", "s")}</button></div>`;
  const sess = S.sessions.slice(0, 8);
  if (!sess.length) h += `<div class="rail-item faint" style="cursor:default">${icon("history")}<span>No scans yet</span></div>`;
  for (const s of sess) {
    const live = S.live[s.id];
    const running = live ? live.state === "running" || live.state === "paused" : s.state === "running";
    const pct = live && live.stageCount ? stagePct(live) : null;
    h += `<button class="rail-item" data-action="open-session" data-id="${esc(s.id)}"${cur(v.name === "session" && v.id === s.id)}>${icon(s.mode === "deep" ? "radar" : s.mode === "partitions" ? "split" : "scan-search")}<span class="two ellipsis" style="flex:1"><span class="ellipsis">${esc(s.label)}</span><small>${
      running ? (live?.stopping ? "Stopping…" : live?.state === "paused" ? "Paused" : `Scanning${pct != null ? ` · ${pct}%` : ""}`) : s.state === "interrupted" ? "Interrupted — can resume" : `${plural(s.files, "file")} · ${ago(s.updated)}`
    }</small>${running && pct != null ? `<span class="rail-mini"><i style="width:${pct}%"></i></span>` : ""}</span>${running && live?.state !== "paused" ? '<span class="live" aria-hidden="true"></span>' : ""}</button>`;
  }
  h += `</div></div>`;

  h += `<div class="rail-bottom">
    <button class="rail-item" data-action="go" data-view="imaging"${cur(v.name === "imaging")}>${icon("hard-drive-download")}<span>Disk imaging</span>${S.imaging && !S.imaging.done ? '<span class="live"></span>' : ""}</button>
    <button class="rail-item" data-action="go" data-view="rules"${cur(v.name === "rules")}>${icon("binary")}<span>Carving rules</span></button>
    <button class="rail-item" data-action="go" data-view="history"${cur(v.name === "history")}>${icon("history")}<span>Recovery history</span></button>
    <button class="rail-item" data-action="go" data-view="settings"${cur(v.name === "settings")}>${icon("settings")}<span>Settings</span></button>
  </div>`;
  restoringFocus(() => patch(document.getElementById("rail"), h));
}

export function volState(v) {
  return { noMedia: "No media", raw: "RAW", locked: "Locked", ready: "" }[v.state] ?? v.state;
}
// Overall percent of a scan from its stage index + stage progress.
export function stagePct(p) {
  if (!p.stageCount) return 0;
  const within = p.total ? Math.min(1, p.done / p.total) : 0;
  return Math.min(100, Math.floor(((p.stageIndex + within) / p.stageCount) * 100));
}

// ------------------------------------------------------------------------------------ home
const SCENARIOS = [
  { key: "deleted", title: "I deleted files by mistake", text: "Including Shift+Delete. Reads the file table for names, folders and dates.", mode: "quick" },
  { key: "bin", title: "I emptied the Recycle Bin", text: "MAX also restores the original names Windows kept in its Recycle Bin records.", mode: "quick" },
  { key: "format", title: "The drive or card was formatted", text: "Looks for the old file table and searches every sector for files by their content.", mode: "deep" },
  { key: "raw", title: "Windows says the drive needs formatting", text: "A RAW or damaged drive. Don't format it — MAX reads it as it is.", mode: "deep" },
  { key: "partition", title: "A partition or drive letter disappeared", text: "Searches a whole disk for partitions its table no longer lists.", mode: "partitions" },
  { key: "failing", title: "The drive is failing or very slow", text: "Copy it to a disk image first, then recover from the copy.", mode: "image" },
];

export function renderHome() {
  const st = S.home || (S.home = { scenario: load("scenario", "deleted"), pick: null });
  const scen = SCENARIOS.find((s) => s.key === st.scenario) || SCENARIOS[0];
  const wantDisk = scen.mode === "partitions";
  const choices = [];
  if (S.devices) {
    if (wantDisk) {
      for (const d of S.devices.disks) choices.push({ src: { kind: "disk", path: String(d.index) }, d });
    } else {
      for (const vol of S.devices.volumes.filter((x) => x.driveType !== "network" && x.driveType !== "cdrom")) {
        choices.push({ src: { kind: "volume", path: vol.letter }, vol, d: vol.diskIndex != null ? diskOf(vol.diskIndex) : null });
      }
      if (scen.key === "raw" || scen.key === "format") {
        for (const d of S.devices.disks.filter((d) => d.removable || d.bus === "USB" || d.bus === "SD")) choices.push({ src: { kind: "disk", path: String(d.index) }, d, whole: true });
      }
    }
  }
  for (const img of S.images) choices.push({ src: { kind: "image", path: img.path }, img });
  if (!st.pick || !choices.some((c) => sameSource(c.src, st.pick))) st.pick = null;

  let cards = "";
  for (const c of choices) {
    const pressed = st.pick && sameSource(st.pick, c.src);
    let title, desc, side = "", usage = "";
    if (c.vol) {
      title = `${esc(c.vol.letter)}: ${esc(c.vol.label || (c.vol.driveType === "removable" ? "Removable drive" : "Local disk"))}`;
      desc = [c.vol.fs || "Unknown", c.d ? `${c.d.model}` : ""].filter(Boolean).map(esc).join(" · ");
      if (c.vol.state === "ready" && c.vol.size) {
        const used = Math.max(0, c.vol.size - c.vol.free);
        side = `${bytes(c.vol.size)}<br><span class="faint">${bytes(c.vol.free)} free</span>`;
        usage = `<div class="usage" aria-hidden="true"><i style="width:${((used / c.vol.size) * 100).toFixed(1)}%"></i></div>`;
      } else side = `<span class="tag ${c.vol.state === "raw" ? "warn" : ""}">${esc(volState(c.vol) || c.vol.state)}</span>`;
      if (c.vol.isSystem) title += ` <span class="tag">Windows</span>`;
      if (c.vol.state === "raw") title += ` <span class="tag warn">RAW</span>`;
    } else if (c.d) {
      title = `${esc(c.d.model || `Disk ${c.d.index}`)}${c.whole ? ' <span class="tag">Whole device</span>' : ""}`;
      desc = `Disk ${c.d.index} · ${esc(busLabel(c.d))} · ${esc(c.d.partitionStyle)} · ${plural(c.d.partitions.length, "partition")}`;
      side = bytes(c.d.size);
    } else if (c.img) {
      title = esc(c.img.path.split(/[\\/]/).pop());
      desc = `Disk image · ${esc(c.img.info.fs || c.img.info.partitionStyle)}`;
      side = bytes(c.img.info.size);
    }
    const ic = c.img ? "disc-3" : sourceIcon(c.src, c.d);
    cards += `<button class="drive-card" data-action="home-pick" data-kind="${c.src.kind}" data-path="${esc(c.src.path)}" aria-pressed="${pressed ? "true" : "false"}">
      <span class="icon">${icon(ic, "l")}</span><span class="title ellipsis">${title}</span><span class="side">${side}</span><span class="desc ellipsis">${desc}</span>${usage}</button>`;
  }
  if (!cards) cards = `<div class="empty"><p>${S.devicesError ? esc(S.devicesError) : "Looking for drives…"}</p></div>`;

  const go = scen.mode === "image" ? "Image this drive" : scen.mode === "partitions" ? "Search for partitions" : scen.mode === "deep" ? "Start deep scan" : "Start quick scan";
  const note =
    scen.mode === "quick"
      ? "Usually takes under a minute. You can run a deep scan afterwards."
      : scen.mode === "deep"
        ? "Reads every sector, so it takes a while on large drives. You can pause it and resume later."
        : scen.mode === "partitions"
          ? "Reads the partition tables and searches the disk for partitions they no longer list."
          : "Nothing is written to this drive. The image goes to a folder on another drive.";

  const html = `<div class="page"><div class="home">
    <section>
      <h2>What happened to your files?</h2>
      <p class="lede">MAX reads your drive without changing it, shows what can still be recovered and how intact it is, and copies it to another drive.</p>
      <div class="scen" role="radiogroup" aria-label="What happened">${SCENARIOS.map(
        (s) => `<label class="scen-item"><input type="radio" name="scenario" value="${s.key}" data-action="home-scenario" ${s.key === scen.key ? "checked" : ""}><b>${esc(s.title)}</b><small>${esc(s.text)}</small></label>`,
      ).join("")}</div>
    </section>
    <section>
      <div class="pick-head"><h3>${wantDisk ? "Which disk?" : "Where were the files?"}</h3><span class="pick-extra">${scen.mode === "quick" ? `<button class="btn small ghost" data-action="pick-folder" data-tip="Only list deleted files from one folder and its subfolders">${icon("folder-search", "s")} Scan a folder</button>` : ""}<button class="btn small ghost" data-action="open-image">${icon("disc-3", "s")} Open a disk image</button></span></div>
      <div class="drive-list">${cards}</div>
      <div class="home-cta"><button class="btn primary big" data-action="home-go" ${st.pick ? "" : "disabled"}>${esc(go)}</button><span class="note">${st.pick ? esc(note) : "Pick a drive to continue."}</span></div>
    </section>
  </div></div>`;
  return { head: "", body: html };
}

// ------------------------------------------------------------------------------- drive view
let driveMap = null;

export function renderDrive() {
  const src = S.view.source;
  const info = describeSource(src);
  const st = S.drive && sameSource(S.drive.source, src) ? S.drive : (S.drive = { source: src, mode: defaultMode(src), cats: null, existing: null, partitions: null, smart: null });
  const vol = info.volume;
  const disk = info.disk;
  const isWhole = (src.kind === "disk" || src.kind === "image") && !src.offset;
  const elevated = !!S.sys?.elevated;
  const rawNeedsAdmin = src.kind !== "image" && !elevated;
  st.startBlocked = rawNeedsAdmin || vol?.bitlocker === "locked";

  // Warnings, most important first.
  const warns = [];
  if (rawNeedsAdmin)
    warns.push(`<div class="callout warn">${icon("shield-alert")}<div class="grow"><b>Scanning a drive needs administrator rights.</b> Windows only lets administrators read drive sectors directly. Disk images can be scanned without them.</div><button class="btn small" data-action="relaunch-admin">Restart as administrator</button></div>`);
  if (vol?.bitlocker === "locked")
    warns.push(`<div class="callout danger">${icon("lock")}<div><b>This drive is locked with BitLocker.</b> Unlock it in Windows (File Explorer → the drive → Unlock) first; MAX can only read the encrypted bytes otherwise.</div></div>`);
  else if (vol?.bitlocker === "unlocked")
    warns.push(`<div class="callout">${icon("lock-open")}<div><b>BitLocker is on and the drive is unlocked.</b> MAX reads it through Windows, so files can be recovered while it stays unlocked. Images of it stay encrypted.</div></div>`);
  const trim = vol?.trimEnabled ?? disk?.trimEnabled;
  const ssd = vol?.ssd ?? (disk ? disk.media === "SSD" : null);
  if (ssd && trim)
    warns.push(`<div class="callout warn">${icon("zap")}<div><b>This SSD erases deleted data (TRIM).</b> Files deleted more than a few minutes ago have usually been wiped. MAX can often still find their names and folders, and MAX marks erased files as Partial. Stop using this drive to keep what's left.</div></div>`);
  if (disk?.health === "Warning" || disk?.health === "Unhealthy")
    warns.push(`<div class="callout danger">${icon("activity")}<div class="grow"><b>Windows reports this drive as ${esc(disk.health.toLowerCase())}.</b> Every read wears it further. Make a disk image first, then recover from the image.</div><button class="btn small" data-action="go-imaging-for">Image this drive</button></div>`);
  if (vol?.state === "raw")
    warns.push(`<div class="callout">${icon("info")}<div><b>Windows can't read this drive's file system (RAW).</b> Don't format it. A deep scan reads it as it is.</div></div>`);

  // Facts.
  const facts = [];
  if (vol) {
    facts.push(["File system", vol.fs || "Unknown"], ["Capacity", bytes(vol.size)]);
    if (vol.state === "ready") facts.push(["In use", bytes(vol.size - vol.free)], ["Free", bytes(vol.free)]);
  }
  if (disk) facts.push(["Device", disk.model || `Disk ${disk.index}`], ["Connection", busLabel(disk) || "–"]);
  if (src.kind === "disk" && disk) facts.push(["Partition table", disk.partitionStyle], ["Size", bytes(disk.size)]);
  if (info.image) facts.push(["Format", info.image.info.format], ["Contents", info.image.info.fs || info.image.info.partitionStyle], ["Size", bytes(info.image.info.size)]);

  // Partition layout for whole disks / images.
  let parts = "";
  if (isWhole) {
    const list = src.kind === "disk" ? disk?.partitions : info.image?.info.partitions;
    const size = src.kind === "disk" ? disk?.size : info.image?.info.size;
    if (list && size) parts = partBar(list, size, src);
  }

  // Sessions of this source.
  const mine = S.sessions.filter((s) => sameSource(s.source, src));
  const last = mine.find((s) => s.state === "done" || s.state === "running" || s.state === "paused") || mine[0];
  const sessList = mine.length
    ? `<div><h3 class="side-h">Earlier scans</h3><div class="sessions-mini">${mine
        .slice(0, 6)
        .map(
          (s) =>
            `<button class="sess-row" data-action="open-session" data-id="${esc(s.id)}"><span class="ellipsis">${esc(s.label)}</span><span class="faint">${plural(s.files, "file")}</span><small>${esc(modeLabel(s.mode))} · ${esc(stateLabel(s.state))} · ${esc(date(s.created, true))}</small></button>`,
        )
        .join("")}</div></div>`
    : "";

  // Scan options.
  const modes = [
    { key: "quick", title: "Quick scan", text: "Reads the file system for deleted files with their names, folders and dates.", eta: "Usually under a minute", ok: !isWhole || src.kind === "image" || true },
    { key: "deep", title: "Deep scan", text: "Also reads every sector: finds files after formatting, on RAW drives and without names.", eta: etaDeep(src, disk, info) },
  ];
  if (isWhole) modes.push({ key: "partitions", title: "Find lost partitions", text: "Searches the whole disk for partitions its table no longer lists.", eta: "A few minutes" });
  // A folder scan (volume sources the file system can read): quick only, see folderHtml.
  const canFolder = src.kind === "volume" && vol?.state !== "raw";
  if (!canFolder) st.folder = null;
  if (st.folder) st.mode = "quick";
  const typeCats = ["photo", "video", "audio", "document", "archive", "other"];
  const cats = st.cats || typeCats;
  const side = `<div><h3 class="side-h">Scan</h3><div class="mode-list" role="radiogroup">${modes
    .map((m) => `<label class="mode"><input type="radio" name="scanmode" value="${m.key}" data-action="drive-mode" ${st.mode === m.key ? "checked" : ""} ${st.folder && m.key !== "quick" ? "disabled" : ""}><b>${esc(m.title)}</b><small>${esc(m.text)}</small><span class="eta">${esc(m.eta)}</span></label>`)
    .join("")}</div></div>
    ${canFolder ? folderHtml(st.folder) : ""}
    ${
      st.mode === "deep"
        ? `<div><h3 class="side-h">Look for</h3><div class="types">${typeCats
            .map((c) => `<button class="chip" data-action="drive-cat" data-key="${c}" aria-pressed="${cats.includes(c)}">${icon({ photo: "image", video: "film", audio: "music", document: "file-text", archive: "file-archive", other: "file" }[c], "s")}${esc({ photo: "Photos", video: "Videos", audio: "Audio", document: "Documents", archive: "Archives", other: "Other" }[c])}</button>`)
            .join("")}</div><p class="faint" style="font-size:var(--fs-xs);margin:8px 0 0">Applies to files found by content. Files found in the file system are always listed.</p></div>`
        : ""
    }
    ${
      st.mode !== "partitions"
        ? `<label class="check"><input type="checkbox" data-action="drive-existing" ${(st.existing ?? defaultExisting(src, vol)) ? "checked" : ""}><span>Also list files that still exist<small>Useful for damaged or RAW drives, partitions and images, where it's on unless you turn it off. Off: only deleted and lost files.</small></span></label>`
        : ""
    }
    <button class="btn primary big" data-action="start-scan" ${st.startBlocked || st.loc?.refuse ? "disabled" : ""}>${icon(st.mode === "deep" ? "radar" : st.mode === "partitions" ? "split" : "scan-search")} ${esc(st.folder ? "Scan this folder" : st.mode === "deep" ? "Start deep scan" : st.mode === "partitions" ? "Search for partitions" : "Start quick scan")}</button>
    <div class="scan-loc" id="scan-loc" aria-live="polite">${locHtml(st.loc)}</div>
    ${src.kind !== "image" ? `<button class="btn" data-action="go-imaging-for">${icon("hard-drive-download")} Make a disk image instead</button>` : ""}
    ${disk && src.kind !== "image" ? `<button class="btn ghost" data-action="drive-health">${icon("activity")} Drive health</button>` : ""}
    ${sessList}`;

  const mapHead = last
    ? `<div class="map-top"><div><b>Recovery Map</b> <span class="muted">from ${esc(last.label)}, ${esc(ago(last.updated))}</span></div><div class="legend">${legend()}</div></div>`
    : `<div class="map-top"><div><b>Recovery Map</b> <span class="muted">— fills in as MAX scans</span></div><div class="legend">${legend()}</div></div>`;
  const body = `<div class="drive-body">
    <div class="drive-main">
      ${warns.join("")}
      ${facts.length ? `<div class="facts">${facts.map(([k, v]) => `<div class="fact"><small>${esc(k)}</small><b>${esc(v)}</b></div>`).join("")}</div>` : ""}
      ${parts}
      <div class="map-wrap" style="flex:1;min-height:280px">${mapHead}<div class="map-canvas-box${last ? "" : " ghost"}" id="drive-map"></div>
      ${last ? `<div class="map-stats" id="drive-map-stats"></div>` : `<p class="map-hint">Each square is a slice of the drive. After a scan: <b>green</b> = files in use, <b>blue</b> = file system structures, <b>yellow</b> = recoverable data, <b>red</b> = unreadable, <b>grey</b> = not read yet.</p>`}</div>
    </div>
    <aside class="drive-side">${side}</aside>
  </div>`;
  const head = `<header class="page-head"><span class="head-icon">${icon(info.icon || "hard-drive", "l")}</span><div class="ellipsis"><h1 class="ellipsis">${esc(info.title)}</h1><div class="sub ellipsis">${esc(info.sub)}</div></div></header>`;
  return {
    head,
    body,
    after() {
      scanLocation(st);
      const box = document.getElementById("drive-map");
      if (!box) return;
      if (driveMap && driveMap.box === box && driveMap.sessionId === last?.id) return;
      driveMap?.destroy();
      driveMap = null;
      if (!last) {
        // A ghost grid: everything grey until the first scan.
        const len = vol?.size || disk?.size || info.image?.info.size || 1;
        driveMap = new RecoveryMap(box, { sourceLen: len, fetch: async (s, e, cells) => ({ start: s, end: e, cellBytes: Math.ceil((e - s) / cells), cells: btoa("\0".repeat(Math.min(cells, 65536))), sourceLen: len, totals: [0, 0, 0, 0, 0] }) });
        return;
      }
      driveMap = new RecoveryMap(box, {
        sourceLen: last.sourceLen,
        fetch: (start, end, cells) => invoke("map_cells", { sessionId: last.id, start, end, cells }),
        onData: (d) => {
          const el = document.getElementById("drive-map-stats");
          if (el) patch(el, mapStats(d));
        },
        onSelect: () => {},
        onZoom: () => App.navigate({ name: "session", id: last.id, tab: "map" }),
      });
      driveMap.sessionId = last.id;
    },
    leave() {
      clearTimeout(locTimer);
      // A preview cut off by leaving must be asked again on return.
      st.locKey = null;
      driveMap?.destroy();
      driveMap = null;
    },
  };
}

// Where the scan's own results would be kept (scan_location), shown under the Start button.
// Asked again (debounced) when the source, the scan mode or the number of running scans changes.
let locTimer = 0;
function scanLocation(st) {
  const key = JSON.stringify([st.source.kind, String(st.source.path).toLowerCase(), st.source.offset || 0, st.mode, runningJobs().scans]);
  if (st.locKey === key) return;
  st.locKey = key;
  clearTimeout(locTimer);
  locTimer = setTimeout(async () => {
    let loc = null;
    try {
      loc = await invoke("scan_location", { source: st.source });
    } catch (e) {
      // Unelevated volume sources can fail with the administrator sentence; Start already says so.
      if (!needsAdmin(e)) console.warn("scan_location failed:", errText(e));
    }
    if (S.drive !== st || st.locKey !== key) return;
    st.loc = loc;
    patch(document.getElementById("scan-loc"), locHtml(loc));
    const btn = document.querySelector('#main [data-action="start-scan"]');
    if (btn) btn.disabled = !!(st.startBlocked || loc?.refuse);
  }, 250);
}
// The "Only one folder" block of the drive page.
function folderHtml(f) {
  if (!f)
    return `<div class="folder-scope"><button class="btn" data-action="pick-folder">${icon("folder-search")} Scan one folder only…</button><small class="faint">Lists only deleted files from a folder you pick and its subfolders. If the folder itself was deleted, pick the folder that contained it.</small></div>`;
  return `<div class="folder-scope on"><div class="folder-chip">${icon("folder-open", "s")}<span class="ellipsis" data-tip="${esc(f.display)}">${esc(f.display)}</span><button class="btn ghost small icon" data-action="clear-folder" aria-label="Scan the whole drive instead" data-tip="Scan the whole drive instead">${icon("x", "s")}</button></div><small class="faint">Only files from this folder and its subfolders are listed. MAX still reads the drive's whole file table. Files whose folder record is gone, and files found only by their content, need a scan of the whole drive.</small><button class="btn small ghost" data-action="pick-folder">Pick another folder</button></div>`;
}

function locHtml(loc) {
  if (!loc) return "";
  if (loc.refuse) return `<div class="callout danger">${icon("circle-x")}<div>${esc(loc.refuse)}</div></div>`;
  if (!loc.message) return "";
  if (loc.sameDrive) return `<div class="callout warn">${icon("triangle-alert")}<div>${esc(loc.message)}</div></div>`;
  return `<p class="loc-note">${icon("hard-drive", "s")}<span>${esc(loc.message)}</span></p>`;
}

export function legend() {
  return `<span><i class="lg-live"></i>Files in use</span><span><i class="lg-meta"></i>File system</span><span><i class="lg-rec"></i>Recoverable</span><span><i class="lg-bad"></i>Unreadable</span><span><i class="lg-em"></i>Read, empty</span><span><i class="lg-un"></i>Not scanned</span>`;
}
export function mapStats(d) {
  const [scanned, meta, live, rec, bad] = d.totals || [0, 0, 0, 0, 0];
  const span = Math.max(1, d.end - d.start);
  const pct = (x) => `${((x / span) * 100).toFixed(x && x / span < 0.001 ? 2 : 1)}%`;
  return `<span>Read <b>${bytes(scanned)}</b> (${pct(scanned)})</span><span>Recoverable <b>${bytes(rec)}</b></span><span>In use <b>${bytes(live)}</b></span><span>File system <b>${bytes(meta)}</b></span><span>Unreadable <b>${bytes(bad)}</b></span>`;
}

function partBar(list, size, src) {
  const items = [...list].sort((a, b) => a.offset - b.offset);
  const segs = [];
  let pos = 0;
  for (const p of items) {
    if (p.offset - pos > 16 * 1024 * 1024) segs.push({ free: true, offset: pos, size: p.offset - pos });
    segs.push(p);
    pos = Math.max(pos, p.offset + p.size);
  }
  if (size - pos > 16 * 1024 * 1024) segs.push({ free: true, offset: pos, size: size - pos });
  return `<div><div class="partbar" role="list" aria-label="Partitions">${segs
    .map((p) => {
      const grow = Math.max(p.size / size, 0.035);
      const cls = p.free ? "free" : /EFI|reserved|Recovery/i.test(p.typeName) ? "sys" : "data";
      const name = p.free ? "Unallocated" : p.letter ? `${p.letter}: ${p.label || ""}` : p.label || p.typeName;
      const tip = `${name} · ${bytes(p.size)}${p.fs ? ` · ${p.fs}` : ""} · starts at ${bytes(p.offset)}`;
      return `<div class="p ${cls}" role="listitem" style="flex:${grow}" data-tip="${esc(tip)}"><b>${esc(name)}</b><span>${bytes(p.size)}${p.fs ? ` · ${esc(p.fs)}` : ""}</span></div>`;
    })
    .join("")}</div>${src.kind === "disk" ? `<p class="faint" style="font-size:var(--fs-xs);margin:6px 0 0">Pick “Find lost partitions” to search the unallocated space for deleted partitions.</p>` : ""}</div>`;
}

// Mirrors the backend's include_existing default (scan/jobs.rs): on for disk images, restore points,
// partitions (a window at an offset) and RAW volumes. The backend can also turn it on when it had to
// use the backup boot sector; the UI can't know that before the scan.
export function defaultExisting(src, vol) {
  if (!src) return false;
  if (src.kind === "image" || src.kind === "snapshot") return true;
  if (src.offset > 0) return true;
  if (src.kind === "volume") return (vol || volumeOf(src.path))?.state === "raw";
  return false;
}

function defaultMode(src) {
  if (src.kind === "volume") {
    const v = volumeOf(src.path);
    if (v?.state === "raw") return "deep";
  }
  return "quick";
}
function etaDeep(src, disk, info) {
  const size = info.volume?.size || disk?.size || info.image?.info.size || 0;
  if (!size) return "Depends on the drive's size";
  const speed = src.kind === "image" ? 600e6 : disk?.media === "SSD" ? (disk.bus === "NVMe" ? 900e6 : 400e6) : disk?.bus === "USB" || disk?.bus === "SD" ? 60e6 : 130e6;
  return `About ${duration(size / speed)} for ${bytes(size)}`;
}
export function modeLabel(m) {
  return { quick: "Quick scan", deep: "Deep scan", partitions: "Partition search" }[m] || m;
}
export function stateLabel(s) {
  return { running: "Scanning", paused: "Paused", done: "Finished", cancelled: "Stopped", failed: "Failed", interrupted: "Interrupted" }[s] || s;
}

// ---------------------------------------------------------------------------------- actions
Object.assign(App.actions, {
  "go-home": () => App.navigate({ name: "home" }),
  go: (el) => App.navigate({ name: el.dataset.view }),
  "open-source": (el) => App.navigate({ name: "drive", source: { kind: el.dataset.kind, path: el.dataset.path } }),
  "refresh-devices": () => App.refreshDevices(true),
  "home-scenario": (el) => {
    S.home.scenario = el.value;
    save("scenario", el.value);
    App.renderMain();
  },
  "home-pick": (el) => {
    S.home.pick = { kind: el.dataset.kind, path: el.dataset.path };
    App.renderMain();
  },
  "home-go": () => {
    const scen = SCENARIOS.find((s) => s.key === S.home.scenario);
    const src = S.home.pick;
    if (!src) return;
    if (scen.mode === "image") {
      S.imagingPrefill = src;
      return App.navigate({ name: "imaging" });
    }
    S.drive = { source: src, mode: scen.mode === "partitions" && src.kind === "volume" ? "deep" : scen.mode, cats: null, existing: null };
    App.navigate({ name: "drive", source: src });
  },
  "drive-mode": (el) => {
    S.drive.mode = el.value;
    App.renderMain();
  },
  "drive-cat": (el) => {
    const all = ["photo", "video", "audio", "document", "archive", "other"];
    const cur = new Set(S.drive.cats || all);
    cur.has(el.dataset.key) ? cur.delete(el.dataset.key) : cur.add(el.dataset.key);
    if (!cur.size) return toast("Pick at least one kind of file.", { icon: "info" });
    S.drive.cats = all.filter((c) => cur.has(c));
    App.renderMain();
  },
  "drive-existing": (el) => {
    S.drive.existing = el.checked;
  },
  "start-scan": async (el) => {
    const st = S.drive;
    const options = { mode: st.mode };
    // Left out until the user changes it, so the backend applies its own default (shown checked above).
    if (st.existing != null) options.includeExisting = !!st.existing;
    if (st.mode === "deep" && st.cats && st.cats.length < 6) options.carveTypes = st.cats;
    if (st.folder) {
      options.mode = "quick";
      options.folder = st.folder.folder;
    }
    el.disabled = true;
    try {
      const r = await invoke("start_scan", { source: st.source, options });
      scanStarted(r);
      await App.refreshSessions();
      App.navigate({ name: "session", id: r.sessionId, tab: st.mode === "partitions" ? "partitions" : "map" });
    } catch (e) {
      el.disabled = !!(st.startBlocked || st.loc?.refuse);
      if (needsAdmin(e)) adminToast(e);
      else toastError(e);
    }
  },
  "go-imaging-for": () => {
    S.imagingPrefill = S.view.source;
    App.navigate({ name: "imaging" });
  },
  "drive-health": () => showHealth(),
  "open-image": () => openImage(),
  "pick-folder": () => pickFolder(),
  "clear-folder": () => {
    if (S.drive) S.drive.folder = null;
    App.renderMain();
  },
  "relaunch-admin": () => relaunchAdmin(),
});

export function adminToast(e) {
  toast(errText(e), { error: true, action: "Restart as administrator", onAction: relaunchAdmin });
}

export async function relaunchAdmin() {
  const busy = busyText(runningJobs(), "Restarting stops");
  const ok = await confirmDialog({
    title: "Restart as administrator?",
    body: busy ? `${esc(busy)} Windows will ask for permission.` : "Windows will ask for permission. Running scans keep their results and can be resumed after the restart.",
    ok: "Restart",
    danger: !!busy,
  });
  if (!ok) return;
  try {
    const accepted = await invoke("relaunch_elevated");
    if (!accepted) toast("Windows didn't give MAX administrator rights, so it keeps running as before.", { icon: "info" });
  } catch (e) {
    toastError(e);
  }
}

// Scan one folder: the folder's drive with a folder scope (start_scan's `folder` option).
export async function pickFolder() {
  let path;
  try {
    path = await window.__TAURI__.dialog.open({ directory: true, multiple: false, title: "Which folder were the files in?" });
  } catch (e) {
    return toastError(e);
  }
  if (Array.isArray(path)) path = path[0];
  if (!path) return;
  let r;
  try {
    r = await invoke("folder_source", { path });
  } catch (e) {
    return toastError(e);
  }
  const vol = volumeOf(r.source.path);
  if (!vol) return toast(`MAX doesn't list drive ${r.source.path}: yet. Refresh the drive list and pick the folder again.`, { error: true });
  if (vol.driveType === "network" || vol.driveType === "cdrom") return toast("MAX can only scan folders on local drives.", { error: true });
  const keep = S.drive && sameSource(S.drive.source, r.source) ? S.drive : null;
  S.drive = { source: r.source, mode: "quick", cats: keep?.cats ?? null, existing: keep?.existing ?? null, folder: r.folder ? r : null };
  if (!r.folder) toast(`That's the whole of ${r.source.path}:, so MAX scans all of it.`, { icon: "info" });
  if (S.view.name === "drive" && sameSource(S.view.source, r.source)) App.renderMain();
  else App.navigate({ name: "drive", source: r.source });
}

export async function openImage() {
  let path;
  try {
    path = await window.__TAURI__.dialog.open({
      multiple: false,
      directory: false,
      title: "Open a disk image",
      filters: [{ name: "Disk images", extensions: ["img", "dd", "raw", "bin", "iso", "vhd", "vhdx", "001", "ima"] }, { name: "All files", extensions: ["*"] }],
    });
  } catch (e) {
    return toastError(e);
  }
  if (!path) return;
  try {
    const info = await invoke("open_image", { path });
    S.images = [{ path, info }, ...S.images.filter((i) => i.path.toLowerCase() !== path.toLowerCase())].slice(0, 12);
    save("images", S.images.map((i) => i.path));
    App.navigate({ name: "drive", source: { kind: "image", path } });
  } catch (e) {
    toastError(e);
  }
}

async function showHealth() {
  const disk = describeSource(S.view.source).disk;
  if (!disk) return;
  const p = showDialog(`<form method="dialog"><header><h2>Drive health</h2><p>${esc(disk.model)} · Disk ${disk.index}</p></header><div class="body" id="health-body"><p class="muted">Reading health data…</p></div><footer><button class="btn primary" value="ok">Close</button></footer></form>`, { wide: true });
  try {
    const s = await invoke("smart_info", { disk: disk.index });
    const el = document.getElementById("health-body");
    if (!el) return;
    const rows = [
      ["Status", s.health],
      ["Temperature", s.temperatureC != null ? `${s.temperatureC} °C` : null],
      ["Powered on", s.powerOnHours != null ? `${int(s.powerOnHours)} hours` : null],
      ["Power cycles", s.powerCycles != null ? int(s.powerCycles) : null],
      ["Wear", s.percentUsed != null ? `${s.percentUsed}% of rated life used` : null],
      ["Media errors", s.mediaErrors != null ? int(s.mediaErrors) : null],
      ["Reallocated sectors", s.reallocatedSectors != null ? int(s.reallocatedSectors) : null],
      ["Pending sectors", s.pendingSectors != null ? int(s.pendingSectors) : null],
      ["Unsafe shutdowns", s.unsafeShutdowns != null ? int(s.unsafeShutdowns) : null],
      ["Data read", s.dataRead != null ? bytes(s.dataRead) : null],
      ["Data written", s.dataWritten != null ? bytes(s.dataWritten) : null],
    ].filter(([, v]) => v != null);
    el.innerHTML = `${s.warnings.map((w) => `<div class="callout danger">${icon("triangle-alert")}<div>${esc(w)}</div></div>`).join("")}
      ${s.needsAdmin ? `<div class="callout">${icon("shield")}<div class="grow">Detailed health counters need administrator rights.</div><button type="button" class="btn small" data-action="relaunch-admin">Restart as administrator</button></div>` : ""}
      <dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>
      ${
        s.attributes.length
          ? `<table class="table"><thead><tr><th>ID</th><th>Attribute</th><th class="r">Value</th><th class="r">Worst</th><th class="r">Threshold</th><th class="r">Raw</th></tr></thead><tbody>${s.attributes
              .map((a) => `<tr><td>${a.id}</td><td>${esc(a.name)} ${a.status !== "ok" ? `<span class="tag ${a.status === "fail" ? "danger" : "warn"}">${a.status === "fail" ? "Failing" : "Watch"}</span>` : ""}</td><td class="r">${a.current}</td><td class="r">${a.worst}</td><td class="r">${a.threshold}</td><td class="r">${int(a.raw)}</td></tr>`)
              .join("")}</tbody></table>`
          : ""
      }
      <p class="faint" style="margin:0;font-size:var(--fs-xs)">Source: ${esc(s.source || "Windows")}</p>`;
  } catch (e) {
    const el = document.getElementById("health-body");
    if (el) el.innerHTML = `<div class="callout warn">${icon("circle-alert")}<div>${esc(errText(e))}</div></div>`;
  }
  await p;
}
