// The Recovery Map: the whole source as a grid of cells, each coloured by what MAX knows about
// that byte range. Zoomable (each zoom re-asks the backend for finer cells), hoverable (sector
// range + contents), selectable by click or drag (the region inspector shows what's there).
import { b64, bytes, esc, floatTip, int } from "./core.js";

// Bits from MapData.cells (MapKind index order in model.rs).
export const BIT = { scanned: 1, meta: 2, live: 4, rec: 8, bad: 16 };
// Priority when a cell holds several kinds: the rarest, most important wins.
const BUCKETS = ["bad", "rec", "meta", "live", "empty", "unscanned"];
export function cellKind(v) {
  if (v & BIT.bad) return "bad";
  if (v & BIT.rec) return "rec";
  if (v & BIT.meta) return "meta";
  if (v & BIT.live) return "live";
  if (v & BIT.scanned) return "empty";
  return "unscanned";
}
export const KIND_TEXT = {
  bad: "Unreadable sectors",
  rec: "Recoverable data",
  meta: "File system structures",
  live: "Files in use",
  empty: "Read, nothing found",
  unscanned: "Not scanned yet",
};

function colors() {
  const cs = getComputedStyle(document.documentElement);
  const v = (n) => cs.getPropertyValue(n).trim();
  return {
    bad: v("--map-bad"),
    rec: v("--map-rec"),
    meta: v("--map-meta"),
    live: v("--map-live"),
    empty: v("--map-empty"),
    unscanned: v("--map-unscanned"),
    sel: v("--text"),
    focus: v("--primary"),
  };
}

export class RecoveryMap {
  /**
   * @param {HTMLElement} box   element that receives the canvas (position: relative, sized by CSS)
   * @param {object} o
   *   fetch(start, end, cells) -> Promise<MapData>
   *   sourceLen, sectorSize
   *   onSelect({start, end}) / onView({start, end})
   */
  constructor(box, o) {
    this.box = box;
    this.o = o;
    this.view = { start: 0, end: o.sourceLen || 1 };
    this.data = null;
    this.cellsArr = null;
    this.sel = null; // {a, b} cell indexes (inclusive)
    this.hover = -1;
    this.gen = 0;
    this.canvas = document.createElement("canvas");
    this.canvas.setAttribute("role", "img");
    this.canvas.setAttribute("aria-label", "Recovery Map of the drive");
    box.appendChild(this.canvas);
    this.colors = colors();
    this.ro = new ResizeObserver(() => this.layout(true));
    this.ro.observe(box);
    this._rt = () => this.retheme();
    window.addEventListener("max-retheme", this._rt);
    this.bind();
    this.layout(true);
  }

  destroy() {
    this.ro.disconnect();
    window.removeEventListener("max-retheme", this._rt);
    floatTip(null);
    this.canvas.remove();
    this.dead = true;
  }

  retheme() {
    this.colors = colors();
    this.draw();
  }

  setView(start, end) {
    this.view = { start, end: Math.max(end, start + 1) };
    this.sel = null;
    this.o.onView?.(this.view);
    return this.refresh();
  }

  layout(refetch) {
    const w = this.box.clientWidth;
    const h = this.box.clientHeight;
    if (!w || !h) return;
    const dpr = window.devicePixelRatio || 1;
    // Cell size: 7 px with a 1.5 px gap on large boxes; grow cells if the grid would exceed the
    // backend's 65,536-cell limit.
    let cs = 7;
    const gap = 1.5;
    let cols, rows;
    for (;;) {
      cols = Math.max(8, Math.floor((w - 12 + gap) / (cs + gap)));
      rows = Math.max(4, Math.floor((h - 12 + gap) / (cs + gap)));
      if (cols * rows <= 65536) break;
      cs += 1;
    }
    const changed = cols !== this.cols || rows !== this.rows;
    Object.assign(this, { cs, gap, cols, rows, w, h, dpr });
    this.ox = Math.round((w - (cols * (cs + gap) - gap)) / 2);
    this.oy = Math.round((h - (rows * (cs + gap) - gap)) / 2);
    this.canvas.width = Math.round(w * dpr);
    this.canvas.height = Math.round(h * dpr);
    if (changed && refetch) this.refresh();
    else this.draw();
  }

  get count() {
    return this.cols * this.rows;
  }
  cellBytes() {
    return this.data ? this.data.cellBytes : Math.ceil((this.view.end - this.view.start) / this.count);
  }
  cellRange(i) {
    const cb = this.cellBytes();
    const s = this.view.start + i * cb;
    return { start: s, end: Math.min(this.view.end, s + cb) };
  }

  async refresh() {
    if (!this.cols || this.dead) return;
    const g = ++this.gen;
    try {
      const d = await this.o.fetch(this.view.start, this.view.end, this.count);
      if (g !== this.gen || this.dead) return;
      this.data = d;
      this.cellsArr = b64(d.cells);
      this.draw();
      this.o.onData?.(d);
    } catch (e) {
      if (g !== this.gen) return;
      this.data = null;
      this.cellsArr = null;
      this.draw();
      this.o.onError?.(e);
    }
  }

  draw() {
    const ctx = this.canvas.getContext("2d");
    if (!ctx || !this.cols) return;
    const { cs, gap, cols, dpr, ox, oy } = this;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, this.w, this.h);
    const paths = {};
    for (const k of BUCKETS) paths[k] = new Path2D();
    const n = this.count;
    const arr = this.cellsArr;
    const used = arr ? Math.min(arr.length, n) : n;
    for (let i = 0; i < used; i++) {
      const k = arr ? cellKind(arr[i]) : "unscanned";
      const x = ox + (i % cols) * (cs + gap);
      const y = oy + Math.floor(i / cols) * (cs + gap);
      paths[k].rect(x, y, cs, cs);
    }
    for (const k of BUCKETS) {
      ctx.fillStyle = this.colors[k];
      ctx.fill(paths[k]);
    }
    // Selection: outline each selected cell run per row.
    if (this.sel) {
      const a = Math.min(this.sel.a, this.sel.b);
      const b = Math.max(this.sel.a, this.sel.b);
      ctx.strokeStyle = this.colors.sel;
      ctx.lineWidth = 1.5;
      for (let r = Math.floor(a / cols); r <= Math.floor(b / cols); r++) {
        const c0 = r === Math.floor(a / cols) ? a % cols : 0;
        const c1 = r === Math.floor(b / cols) ? b % cols : cols - 1;
        const x = ox + c0 * (cs + gap) - 1.5;
        const y = oy + r * (cs + gap) - 1.5;
        ctx.strokeRect(x, y, (c1 - c0 + 1) * (cs + gap) - gap + 3, cs + 3);
      }
    }
    if (this.hover >= 0 && this.hover < used) {
      const x = ox + (this.hover % cols) * (cs + gap);
      const y = oy + Math.floor(this.hover / cols) * (cs + gap);
      ctx.strokeStyle = this.colors.focus;
      ctx.lineWidth = 2;
      ctx.strokeRect(x - 1, y - 1, cs + 2, cs + 2);
    }
  }

  cellAt(e) {
    const r = this.canvas.getBoundingClientRect();
    const x = e.clientX - r.left - this.ox;
    const y = e.clientY - r.top - this.oy;
    const step = this.cs + this.gap;
    const c = Math.floor(x / step);
    const row = Math.floor(y / step);
    if (c < 0 || row < 0 || c >= this.cols || row >= this.rows) return -1;
    const i = row * this.cols + c;
    return this.cellsArr && i >= this.cellsArr.length ? -1 : i;
  }

  tipFor(i) {
    const { start, end } = this.cellRange(i);
    const ss = this.o.sectorSize || 512;
    const v = this.cellsArr ? this.cellsArr[i] : 0;
    const kinds = [];
    if (v & BIT.bad) kinds.push(KIND_TEXT.bad);
    if (v & BIT.rec) kinds.push(KIND_TEXT.rec);
    if (v & BIT.meta) kinds.push(KIND_TEXT.meta);
    if (v & BIT.live) kinds.push(KIND_TEXT.live);
    if (!kinds.length) kinds.push(v & BIT.scanned ? KIND_TEXT.empty : KIND_TEXT.unscanned);
    return `<div class="tt-h">${esc(kinds.join(" · "))}</div>${bytes(start)} – ${bytes(end)}<br>Sectors ${int(Math.floor(start / ss))} – ${int(Math.ceil(end / ss) - 1)}`;
  }

  bind() {
    const c = this.canvas;
    let down = null;
    c.addEventListener("pointermove", (e) => {
      const i = this.cellAt(e);
      if (down != null && i >= 0) {
        this.sel = { a: down, b: i };
      }
      if (i !== this.hover) {
        this.hover = i;
        this.draw();
      }
      floatTip(i >= 0 ? this.tipFor(i) : null, e.clientX, e.clientY);
    });
    c.addEventListener("pointerleave", () => {
      this.hover = -1;
      floatTip(null);
      this.draw();
    });
    c.addEventListener("pointerdown", (e) => {
      const i = this.cellAt(e);
      if (i < 0) return;
      down = i;
      c.setPointerCapture(e.pointerId);
      this.sel = { a: i, b: i };
      this.draw();
    });
    c.addEventListener("pointerup", () => {
      if (down == null) return;
      down = null;
      this.emitSelection();
    });
    c.addEventListener("dblclick", (e) => {
      const i = this.cellAt(e);
      if (i < 0) return;
      this.zoomToSelection();
    });
    c.addEventListener(
      "wheel",
      (e) => {
        if (!e.ctrlKey) return;
        e.preventDefault();
        const i = this.cellAt(e);
        if (e.deltaY < 0 && i >= 0) {
          this.sel = { a: i, b: i };
          this.zoomToSelection(8);
        } else if (e.deltaY > 0) this.zoomOut();
      },
      { passive: false },
    );
    c.tabIndex = 0;
    c.addEventListener("keydown", (e) => {
      const n = this.cellsArr ? this.cellsArr.length : this.count;
      let i = this.sel ? this.sel.b : -1;
      const moves = { ArrowRight: 1, ArrowLeft: -1, ArrowDown: this.cols, ArrowUp: -this.cols };
      if (moves[e.key] != null) {
        e.preventDefault();
        i = Math.max(0, Math.min(n - 1, (i < 0 ? 0 : i) + moves[e.key]));
        this.sel = e.shiftKey && this.sel ? { a: this.sel.a, b: i } : { a: i, b: i };
        this.draw();
        this.emitSelection();
      } else if (e.key === "Enter" || e.key === "+") {
        this.zoomToSelection();
      } else if (e.key === "-" || e.key === "Backspace") {
        this.zoomOut();
      }
    });
  }

  selectionRange() {
    if (!this.sel) return null;
    const a = Math.min(this.sel.a, this.sel.b);
    const b = Math.max(this.sel.a, this.sel.b);
    return { start: this.cellRange(a).start, end: this.cellRange(b).end };
  }
  emitSelection() {
    const r = this.selectionRange();
    if (r) this.o.onSelect?.(r);
  }
  // Zoom into the selection; a single cell grows to `minCells` cells of context around it.
  zoomToSelection(minCells = 1) {
    const r = this.selectionRange();
    if (!r) return;
    let { start, end } = r;
    const ss = this.o.sectorSize || 512;
    if (end - start <= ss * 64) return; // already at sector resolution
    if (minCells > 1) {
      const span = (end - start) * minCells;
      const mid = (start + end) / 2;
      start = Math.max(this.view.start, Math.floor(mid - span / 2));
      end = Math.min(this.view.end, Math.ceil(mid + span / 2));
    }
    this.o.onZoom?.({ start, end });
  }
  zoomOut() {
    this.o.onZoomOut?.();
  }
}
