// The whole capture at a glance, lined up with the timeline below: one bar per pixel for
// the longest top-level span there, on a log scale so a 1 ms span and a 1 s span both
// show, with amber marks where the main window went over budget. Clicking centres the
// timeline there; dragging zooms it to the stretch dragged over.

import { createEffect, createMemo, createSignal, onCleanup, onMount } from "solid-js";
import { COMMAND_BUDGET_MS } from "../lib/devtools/budgets";
import { shade, themeValue } from "./palette";
import { LABEL_WIDTH, type Range, type View } from "./Timeline";
import { overBudget, type Trace } from "./trace-model";

const HEIGHT = 44;
const MARK_HEIGHT = 3;
/** Durations past this reach the top of the strip. */
const SCALE_MAX_MS = 1000;
const CLICK_SLOP_PX = 3;

const heightOf = (ms: number) => Math.min(1, Math.log10(1 + ms) / Math.log10(1 + SCALE_MAX_MS));

export default function Overview(props: { trace: Trace; view: View; range: Range | null; onView: (view: View) => void }) {
  const [width, setWidth] = createSignal(800);
  const [drag, setDrag] = createSignal<Range | null>(null);
  let canvas!: HTMLCanvasElement;
  let container!: HTMLDivElement;

  const plotWidth = () => Math.max(1, width() - LABEL_WIDTH);
  const duration = () => Math.max(props.trace.durationUs, 1);
  const xOf = (us: number) => LABEL_WIDTH + (us / duration()) * plotWidth();
  const usOf = (x: number) => ((x - LABEL_WIDTH) / plotWidth()) * duration();

  /** Per pixel column: the longest top-level span there, and whether anything there went over budget in the main window. */
  const columns = createMemo(() => {
    const longest = new Array<{ ms: number; color: string } | null>(plotWidth()).fill(null);
    const marked = new Array<boolean>(plotWidth()).fill(false);
    for (const span of props.trace.spans) {
      if (span.parent) continue;
      const column = Math.floor((Math.max(span.start, 0) / duration()) * plotWidth());
      if (column < 0 || column >= longest.length) continue;
      if (span.frontend) {
        if (overBudget(span)) marked[column] = true;
        continue;
      }
      const ms = span.duration / 1000;
      if (!longest[column] || ms > longest[column]!.ms) longest[column] = { ms, color: span.module.color };
    }
    return { longest, marked };
  });

  const draw = () => {
    const ratio = window.devicePixelRatio || 1;
    canvas.width = width() * ratio;
    canvas.height = HEIGHT * ratio;
    canvas.style.width = `${width()}px`;
    canvas.style.height = `${HEIGHT}px`;
    const g = canvas.getContext("2d");
    if (!g) return;
    g.setTransform(ratio, 0, 0, ratio, 0, 0);
    g.fillStyle = shade("neutral", 900);
    g.fillRect(0, 0, width(), HEIGHT);
    const plotHeight = HEIGHT - MARK_HEIGHT - 2;
    const budgetY = HEIGHT - heightOf(COMMAND_BUDGET_MS) * plotHeight;
    g.fillStyle = shade("neutral", 700);
    for (let x = LABEL_WIDTH; x < width(); x += 6) g.fillRect(x, budgetY, 3, 1);
    g.fillStyle = shade("neutral", 500);
    g.font = `10px ${themeValue("--font-mono")}`;
    g.textBaseline = "middle";
    g.fillText(`${COMMAND_BUDGET_MS} ms`, LABEL_WIDTH - 44, budgetY);
    const { longest, marked } = columns();
    longest.forEach((column, i) => {
      if (!column) return;
      const h = Math.max(2, heightOf(column.ms) * plotHeight);
      g.fillStyle = shade(column.color, 500);
      g.fillRect(LABEL_WIDTH + i, HEIGHT - h, 1, h);
    });
    g.fillStyle = shade("amber", 400);
    marked.forEach((mark, i) => mark && g.fillRect(LABEL_WIDTH + i - 1, 0, 3, MARK_HEIGHT));

    const shown = drag() ?? [props.view.start, props.view.end];
    const [a, b] = [xOf(Math.min(...shown)), xOf(Math.max(...shown))];
    if (b - a < plotWidth() - 1) {
      g.fillStyle = shade("purple", 400);
      g.globalAlpha = 0.15;
      g.fillRect(a, 0, Math.max(1, b - a), HEIGHT);
      g.globalAlpha = 1;
      g.strokeStyle = shade("purple", 400);
      g.strokeRect(a + 0.5, 0.5, Math.max(1, b - a - 1), HEIGHT - 1);
    }
    if (props.range) {
      const [from, to] = [xOf(Math.min(...props.range)), xOf(Math.max(...props.range))];
      g.fillStyle = shade("purple", 300);
      g.fillRect(from, HEIGHT - 2, Math.max(1, to - from), 2);
    }
  };

  createEffect(() => {
    void [width(), columns(), props.view, props.range, drag()];
    draw();
  });

  onMount(() => {
    const observer = new ResizeObserver(() => setWidth(container.clientWidth));
    observer.observe(container);
    onCleanup(() => observer.disconnect());
  });

  const onMouseDown = (e: MouseEvent) => {
    if (e.button !== 0) return;
    const box = canvas.getBoundingClientRect();
    const xAt = (event: MouseEvent) => event.clientX - box.left;
    const startX = xAt(e);
    if (startX < LABEL_WIDTH) return;
    const clamp = (us: number) => Math.min(Math.max(us, 0), duration());
    const move = (event: MouseEvent) => {
      if (Math.abs(xAt(event) - startX) >= CLICK_SLOP_PX) setDrag([clamp(usOf(startX)), clamp(usOf(xAt(event)))]);
    };
    const up = () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseup", up);
      const dragged = drag();
      setDrag(null);
      if (dragged) return props.onView({ start: Math.min(...dragged), end: Math.max(...dragged) });
      const half = (props.view.end - props.view.start) / 2;
      const centre = Math.min(Math.max(usOf(startX), half), duration() - half);
      props.onView({ start: centre - half, end: centre + half });
    };
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseup", up);
  };

  return (
    <div ref={container} class="rounded-lg overflow-hidden flex-shrink-0">
      <canvas ref={canvas} class="block cursor-pointer" aria-label="Overview of the capture" onMouseDown={onMouseDown} />
    </div>
  );
}
