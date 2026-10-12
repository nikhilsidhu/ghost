// The capture on a canvas the size of the viewport, inside a native scroll container so
// rows scroll like any list; only rows in view are drawn. Scrolling moves through rows,
// ⌘/Ctrl-scroll or pinching zooms around the pointer, sideways or Shift-scrolling pans,
// dragging pans either way, dragging on the ruler selects a stretch of time, clicking
// selects a span or folds a module, and double-clicking zooms to a span or fits.

import { createEffect, createSignal, on, onCleanup, onMount, Show } from "solid-js";
import { floatingClass, floatingStyle } from "../components/ui/popover";
import { cn } from "../lib/cn";
import { formatOffset, formatUs } from "./format";
import { shade, themeValue } from "./palette";
import { heldThread, MODULE_ROW_HEIGHT, overBudget, SPAN_ROW_HEIGHT, type Layout, type Row, type Span, type Trace } from "./trace-model";

export const LABEL_WIDTH = 168;
export const RULER_HEIGHT = 22;
/** Pointer movement below which a press counts as a click, not a drag. */
const CLICK_SLOP_PX = 3;
const ZOOM_SPEED = 0.002;
/** Share of the view a key press zooms or pans by. */
const KEY_STEP = 0.2;
/** Bars narrower than this get no text. */
const MIN_LABEL_PX = 40;
/** The narrowest view, in microseconds. */
const MIN_VIEW_US = 10;
/** How near a tiny span the pointer may be and still pick it. */
const HIT_SLOP_PX = 2;

export interface View {
  start: number;
  end: number;
}

export type Range = [number, number];

/** First index in `spans` (sorted, not overlapping) whose span ends at or after `us`. */
function firstEndingAfter(spans: Span[], us: number): number {
  let [lo, hi] = [0, spans.length];
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (spans[mid].end < us) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** The row at content height `y`. */
function rowAt(rows: Row[], y: number): Row | null {
  let [lo, hi] = [0, rows.length - 1];
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const row = rows[mid];
    const height = row.type === "module" ? MODULE_ROW_HEIGHT : SPAN_ROW_HEIGHT;
    if (y < row.top) hi = mid - 1;
    else if (y >= row.top + height) lo = mid + 1;
    else return row;
  }
  return null;
}

/** Ruler tick spacing for a view of `us` across about eight ticks: 1, 2 or 5 × 10^n. */
function tickStep(us: number): number {
  const rough = us / 8;
  const power = 10 ** Math.floor(Math.log10(rough));
  return [1, 2, 5, 10].map((m) => m * power).find((step) => step >= rough)!;
}

export default function Timeline(props: {
  trace: Trace;
  layout: Layout;
  view: View;
  onView: (view: View) => void;
  selected: Span | null;
  onSelect: (span: Span | null) => void;
  range: Range | null;
  onRange: (range: Range | null) => void;
  /** Zoom into the selected range. */
  onCommitRange: () => void;
  onFit: () => void;
  onToggleModule: (id: string) => void;
  /** Spans the filter leaves out, drawn faint. */
  dimmed: (span: Span) => boolean;
  blockingUs: number;
}) {
  const [size, setSize] = createSignal({ width: 800, height: 400 });
  const [scrollTop, setScrollTop] = createSignal(0);
  const [hover, setHover] = createSignal<{ span: Span; x: number; y: number } | null>(null);
  let canvas!: HTMLCanvasElement;
  let container!: HTMLDivElement;

  const plotWidth = () => Math.max(1, size().width - LABEL_WIDTH);
  const xOf = (us: number) => LABEL_WIDTH + ((us - props.view.start) / (props.view.end - props.view.start)) * plotWidth();
  const usOf = (x: number) => props.view.start + ((x - LABEL_WIDTH) / plotWidth()) * (props.view.end - props.view.start);
  const contentHeight = () => RULER_HEIGHT + props.layout.height;

  /** The earliest and latest times there is anything to see. */
  const bounds = () => {
    let earliest = 0;
    for (const span of props.trace.spans) earliest = Math.min(earliest, span.start);
    return { lo: earliest, hi: Math.max(props.trace.durationUs, 1) };
  };
  const setView = (start: number, end: number) => {
    const { lo, hi } = bounds();
    const width = Math.min(Math.max(end - start, MIN_VIEW_US), hi - lo);
    const from = Math.min(Math.max(start, lo), hi - width);
    props.onView({ start: from, end: from + width });
  };

  const draw = () => {
    const { width, height } = size();
    const ratio = window.devicePixelRatio || 1;
    canvas.width = width * ratio;
    canvas.height = height * ratio;
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    const g = canvas.getContext("2d");
    if (!g) return;
    g.setTransform(ratio, 0, 0, ratio, 0, 0);
    g.font = `11px ${themeValue("--font-mono")}`;
    g.textBaseline = "middle";
    const charWidth = g.measureText("0").width || 6.6;
    const fit = (text: string, room: number) => {
      const chars = Math.floor(room / charWidth);
      return text.length <= chars ? text : chars > 1 ? `${text.slice(0, chars - 1)}…` : "";
    };
    g.fillStyle = shade("neutral", 950);
    g.fillRect(0, 0, width, height);
    const { start, end } = props.view;
    const offset = RULER_HEIGHT - scrollTop();
    const selected = props.selected;

    for (const row of props.layout.rows) {
      const rowHeight = row.type === "module" ? MODULE_ROW_HEIGHT : SPAN_ROW_HEIGHT;
      const y = row.top + offset;
      if (y + rowHeight < RULER_HEIGHT || y > height) continue;
      if (row.type === "module") {
        g.fillStyle = shade("neutral", 900);
        g.fillRect(0, y, width, rowHeight);
        g.fillStyle = shade(row.module.color, 400);
        g.fillRect(8, y + rowHeight / 2 - 3, 6, 6);
        g.fillStyle = shade("neutral", 300);
        g.fillText(`${row.collapsed ? "▸" : "▾"} ${row.module.label} · ${row.count}`, 20, y + rowHeight / 2);
        continue;
      }
      if (row.label) {
        g.fillStyle = shade("neutral", 400);
        g.fillText(fit(row.label, LABEL_WIDTH - 28), 20, y + rowHeight / 2);
      }
      g.save();
      g.beginPath();
      g.rect(LABEL_WIDTH, y, plotWidth(), rowHeight);
      g.clip();
      // Spans under a pixel wide merge into one block per run, so dense stretches stay
      // visible without drawing thousands of slivers.
      let merged: { from: number; to: number; color: string } | null = null;
      const flush = () => {
        if (!merged) return;
        g.fillStyle = merged.color;
        g.fillRect(merged.from, y + 1, Math.max(1, merged.to - merged.from), rowHeight - 2);
        merged = null;
      };
      for (let i = firstEndingAfter(row.spans, start); i < row.spans.length && row.spans[i].start <= end; i++) {
        const span = row.spans[i];
        const x0 = xOf(span.start);
        const x1 = xOf(span.end);
        if (x1 - x0 < 1) {
          const color = shade(span.module.color, 700);
          if (merged && merged.color === color && x0 - merged.to < 1) merged.to = Math.max(merged.to, x1);
          else {
            flush();
            merged = { from: x0, to: x1, color };
          }
          continue;
        }
        flush();
        const isSelected = span === selected;
        const isFrame = span.frontend === "frame" || span.frontend === "longtask";
        g.globalAlpha = props.dimmed(span) ? 0.25 : 1;
        g.fillStyle = isSelected ? shade(span.module.color, 300) : isFrame ? shade("amber", 600) : shade(span.module.color, 600);
        g.fillRect(x0, y + 1, x1 - x0, rowHeight - 2);
        if (!isFrame && (overBudget(span) || heldThread(span, props.blockingUs))) {
          g.strokeStyle = shade("amber", 400);
          g.strokeRect(x0 + 0.5, y + 1.5, x1 - x0 - 1, rowHeight - 3);
        }
        if (span.open) {
          // Still running at the capture: its end is not its end.
          g.fillStyle = shade("neutral", 50);
          g.fillRect(x1 - 2, y + 1, 2, rowHeight - 2);
        }
        const visibleFrom = Math.max(x0, LABEL_WIDTH);
        const room = x1 - visibleFrom - 8;
        if (room >= MIN_LABEL_PX - 8) {
          g.fillStyle = isSelected ? shade("neutral", 950) : shade("neutral", 100);
          g.fillText(fit(span.name, room), visibleFrom + 4, y + rowHeight / 2);
        }
        g.globalAlpha = 1;
      }
      flush();
      g.restore();
    }

    const range = props.range;
    if (range) {
      const [a, b] = [xOf(Math.min(...range)), xOf(Math.max(...range))];
      g.fillStyle = shade("purple", 400);
      g.globalAlpha = 0.15;
      g.fillRect(Math.max(a, LABEL_WIDTH), RULER_HEIGHT, b - Math.max(a, LABEL_WIDTH), height - RULER_HEIGHT);
      g.globalAlpha = 1;
    }

    g.fillStyle = shade("neutral", 900);
    g.fillRect(0, 0, width, RULER_HEIGHT);
    g.fillStyle = shade("neutral", 500);
    g.fillText("drag to select", 8, RULER_HEIGHT / 2);
    g.save();
    g.beginPath();
    g.rect(LABEL_WIDTH, 0, plotWidth(), height);
    g.clip();
    const step = tickStep(end - start);
    for (let t = Math.ceil(start / step) * step; t <= end; t += step) {
      const x = xOf(t);
      g.fillStyle = shade("neutral", 800);
      g.fillRect(x, RULER_HEIGHT, 1, height - RULER_HEIGHT);
      g.fillStyle = shade("neutral", 600);
      g.fillRect(x, RULER_HEIGHT - 6, 1, 6);
      g.fillStyle = shade("neutral", 400);
      g.fillText(step >= 100_000 ? formatOffset(t) : formatUs(t), x + 4, RULER_HEIGHT / 2 - 1);
    }
    if (range) {
      const [a, b] = [xOf(Math.min(...range)), xOf(Math.max(...range))];
      g.fillStyle = shade("purple", 400);
      g.fillRect(a, RULER_HEIGHT - 3, Math.max(1, b - a), 3);
    }
    g.restore();
    g.fillStyle = shade("neutral", 800);
    g.fillRect(LABEL_WIDTH - 1, 0, 1, height);
  };

  createEffect(() => {
    // Everything drawn depends on these.
    void [size(), scrollTop(), props.view, props.layout, props.selected, props.range, props.dimmed, props.blockingUs];
    draw();
  });

  // Bring a newly selected span's row into view.
  createEffect(
    on(
      () => props.selected,
      (span) => {
        if (!span || span.row < 0) return;
        const row = props.layout.rows[span.row];
        const visible = size().height - RULER_HEIGHT;
        if (row.top < container.scrollTop || row.top + SPAN_ROW_HEIGHT > container.scrollTop + visible) {
          container.scrollTop = Math.max(0, row.top - visible / 3);
        }
      },
    ),
  );

  onMount(() => {
    const observer = new ResizeObserver(() => setSize({ width: container.clientWidth, height: container.clientHeight }));
    observer.observe(container);
    onCleanup(() => observer.disconnect());
  });

  const pointer = (e: MouseEvent) => {
    const box = canvas.getBoundingClientRect();
    return { x: e.clientX - box.left, y: e.clientY - box.top };
  };

  const hit = (x: number, y: number): { row: Row; span: Span | null } | null => {
    if (y < RULER_HEIGHT) return null;
    const row = rowAt(props.layout.rows, y - RULER_HEIGHT + scrollTop());
    if (!row) return null;
    if (row.type === "module" || x < LABEL_WIDTH) return { row, span: null };
    const [from, to] = [usOf(x - HIT_SLOP_PX), usOf(x + HIT_SLOP_PX)];
    const at = usOf(x);
    let best: Span | null = null;
    for (let i = firstEndingAfter(row.spans, from); i < row.spans.length && row.spans[i].start <= to; i++) {
      const span = row.spans[i];
      if (span.start <= at && at <= span.end) return { row, span };
      best ??= span;
    }
    return { row, span: best };
  };

  const zoomAt = (x: number, factor: number) => {
    const { start, end } = props.view;
    const pivot = usOf(Math.max(x, LABEL_WIDTH));
    const width = (end - start) * factor;
    const left = (pivot - start) / (end - start);
    setView(pivot - width * left, pivot + width * (1 - left));
  };
  const panBy = (us: number) => setView(props.view.start + us, props.view.end + us);

  const onWheel = (e: WheelEvent) => {
    const { x } = pointer(e);
    if (e.ctrlKey || e.metaKey) {
      e.preventDefault();
      zoomAt(x, Math.exp(e.deltaY * ZOOM_SPEED));
      return;
    }
    const sideways = e.shiftKey ? e.deltaY || e.deltaX : Math.abs(e.deltaX) > Math.abs(e.deltaY) ? e.deltaX : 0;
    if (sideways !== 0) {
      e.preventDefault();
      panBy((sideways / plotWidth()) * (props.view.end - props.view.start));
    }
    // Otherwise the container scrolls through rows on its own.
  };

  const onMouseDown = (e: MouseEvent) => {
    if (e.button !== 0) return;
    canvas.focus();
    const start = pointer(e);
    const onRuler = start.y < RULER_HEIGHT && start.x >= LABEL_WIDTH;
    const pressed = { view: props.view, scrollTop: container.scrollTop };
    let moved = false;
    if (onRuler) props.onRange([usOf(start.x), usOf(start.x)]);
    const move = (event: MouseEvent) => {
      const at = pointer(event);
      if (Math.hypot(at.x - start.x, at.y - start.y) >= CLICK_SLOP_PX) moved = true;
      if (onRuler) {
        props.onRange([props.range?.[0] ?? usOf(start.x), usOf(at.x)]);
        return;
      }
      if (!moved) return;
      const shift = ((start.x - at.x) / plotWidth()) * (pressed.view.end - pressed.view.start);
      setView(pressed.view.start + shift, pressed.view.end + shift);
      container.scrollTop = pressed.scrollTop + (start.y - at.y);
    };
    const up = () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
      if (moved) return;
      if (onRuler) return props.onRange(null);
      const target = hit(start.x, start.y);
      if (target?.row.type === "module") props.onToggleModule(target.row.module.id);
      else props.onSelect(target?.span ?? null);
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  };

  const onMouseMove = (e: MouseEvent) => {
    const at = pointer(e);
    const target = hit(at.x, at.y);
    setHover(target?.span ? { span: target.span, ...at } : null);
  };

  const onDblClick = (e: MouseEvent) => {
    const at = pointer(e);
    if (at.y < RULER_HEIGHT && props.range) return props.onCommitRange();
    const span = hit(at.x, at.y)?.span;
    if (!span) return props.onFit();
    const pad = span.duration * 0.1;
    setView(span.start - pad, span.end + pad);
  };

  const onKeyDown = (e: KeyboardEvent) => {
    const width = props.view.end - props.view.start;
    const centre = LABEL_WIDTH + plotWidth() / 2;
    const actions: Record<string, () => void> = {
      w: () => zoomAt(centre, 1 - KEY_STEP),
      s: () => zoomAt(centre, 1 + KEY_STEP),
      a: () => panBy(-width * KEY_STEP),
      d: () => panBy(width * KEY_STEP),
      Enter: () => props.range && props.onCommitRange(),
      Escape: () => {
        props.onSelect(null);
        props.onRange(null);
      },
    };
    const action = actions[e.key.length === 1 ? e.key.toLowerCase() : e.key];
    if (!action) return;
    e.preventDefault();
    action();
  };

  return (
    <div
      ref={container}
      class="scrollarea relative flex-1 min-h-0 overflow-y-auto overflow-x-hidden rounded-lg border border-[var(--neutral-800)]"
      onScroll={() => setScrollTop(container.scrollTop)}
    >
      <canvas
        ref={canvas}
        tabindex="0"
        aria-label="Timeline of the capture"
        class="sticky top-0 block cursor-crosshair outline-none"
        onWheel={onWheel}
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMove}
        onMouseLeave={() => setHover(null)}
        onDblClick={onDblClick}
        onKeyDown={onKeyDown}
      />
      <div style={{ height: `${Math.max(0, contentHeight() - size().height)}px` }} />
      <Show when={hover()}>
        {(h) => (
          <div
            class={cn(floatingClass, "absolute pointer-events-none px-2 py-1 text-[11px]")}
            style={{ ...floatingStyle, left: `${Math.min(h().x + 12, size().width - 240)}px`, top: `${h().y + scrollTop() + 14}px` }}
          >
            <div>{h().span.name}</div>
            <div class="text-[var(--neutral-400)]">
              {formatUs(h().span.duration)}
              {h().span.open ? " so far" : ""} · own {formatUs(h().span.own)}
              <Show when={h().span.busy !== null}> · busy {formatUs(h().span.busy!)}</Show>
            </div>
          </div>
        )}
      </Show>
    </div>
  );
}
