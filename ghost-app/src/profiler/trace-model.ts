// Turns a capture into the timeline's rows, and answers what the views ask of it: a
// span's own time and where the rest went, how it compares with others of its kind, and
// what a stretch of time held. Times are microseconds from the capture's start.

import { COMMAND_BUDGET_MS, INTERACTION_BUDGET_MS, LONG_FRAME_MS } from "../lib/devtools/budgets";
import type { FrontendEvent, FrontendEventKind } from "../lib/devtools/types";
import type { TraceCapture } from "../lib/generated/TraceCapture";
import { COMMANDS_MODULE, MAIN_TARGET, moduleOf, moduleRank, type Module } from "./modules";

export const MODULE_ROW_HEIGHT = 22;
export const SPAN_ROW_HEIGHT = 18;

export interface Span {
  id: string;
  parent: Span | null;
  /** In order of start. */
  children: Span[];
  target: string;
  name: string;
  /** What makes spans the same kind: `target::name`. */
  kind: string;
  module: Module;
  start: number;
  end: number;
  duration: number;
  /** Unknown for the main window's events and spans still running. */
  busy: number | null;
  ownBusy: number | null;
  longestPoll: number | null;
  open: boolean;
  /** Time not covered by its children. */
  own: number;
  /** The main window's kind of event; null for backend spans. */
  frontend: FrontendEventKind | null;
  /** Row it is drawn on, among its module's rows; -1 until laid out. */
  row: number;
}

export interface Trace {
  spans: Span[];
  byId: Map<string, Span>;
  durationUs: number;
  startUnixMs: number;
  truncated: boolean;
}

export type Row =
  | { type: "module"; module: Module; collapsed: boolean; count: number; top: number }
  | { type: "spans"; module: Module; label: string | null; spans: Span[]; top: number };

export interface Layout {
  rows: Row[];
  height: number;
  /** Modules present, in order, whether shown or not. */
  modules: Module[];
}

/** Interval lengths covered by `[start, end)` pairs, overlaps counted once. */
function unionLength(intervals: [number, number][]): number {
  const sorted = intervals.filter(([a, b]) => b > a).sort((x, y) => x[0] - y[0]);
  let total = 0;
  let [from, to] = [-Infinity, -Infinity];
  for (const [a, b] of sorted) {
    if (a > to) {
      if (to > from) total += to - from;
      [from, to] = [a, b];
    } else {
      to = Math.max(to, b);
    }
  }
  if (to > from) total += to - from;
  return total;
}

/** The parts of `span` its children leave uncovered. */
export function ownSegments(span: Span): [number, number][] {
  const segments: [number, number][] = [];
  let cursor = span.start;
  const covered = span.children
    .map((c): [number, number] => [Math.max(c.start, span.start), Math.min(c.end, span.end)])
    .filter(([a, b]) => b > a)
    .sort((x, y) => x[0] - y[0]);
  for (const [a, b] of covered) {
    if (a > cursor) segments.push([cursor, a]);
    cursor = Math.max(cursor, b);
  }
  if (span.end > cursor) segments.push([cursor, span.end]);
  return segments;
}

const overlap = (a: number, b: number, from: number, to: number) => Math.max(0, Math.min(b, to) - Math.max(a, from));

const FRONTEND_NAMES: Record<FrontendEventKind, (event: FrontendEvent) => string> = {
  command: (e) => e.name,
  interaction: (e) => e.name,
  frame: () => "long frame",
  longtask: () => "long task",
};

/** Id of a main-window event in a trace, which the monitor's slow events point at too. */
export const frontendId = (event: FrontendEvent) => `${MAIN_TARGET}:${event.kind}:${event.startUnixMs}:${event.name}`;

/** The capture's spans, with the main window's events of the same stretch alongside. */
export function buildTrace(capture: TraceCapture, frontend: readonly FrontendEvent[]): Trace {
  const spans: Span[] = capture.spans.map((s) => ({
    id: s.id,
    parent: null,
    children: [],
    target: s.target,
    name: s.name,
    kind: `${s.target}::${s.name}`,
    module: moduleOf(s.target),
    start: s.start_us,
    end: s.start_us + s.duration_us,
    duration: s.duration_us,
    busy: s.open ? null : s.busy_us,
    ownBusy: s.open ? null : s.own_busy_us,
    longestPoll: s.open ? null : s.longest_poll_us,
    open: s.open,
    own: 0,
    frontend: null,
    row: -1,
  }));
  const captureEndMs = capture.start_unix_ms + capture.duration_us / 1000;
  for (const event of frontend) {
    if (event.startUnixMs + event.durationMs < capture.start_unix_ms || event.startUnixMs > captureEndMs) continue;
    const target = `${MAIN_TARGET}::${event.kind}`;
    const name = FRONTEND_NAMES[event.kind](event);
    const start = (event.startUnixMs - capture.start_unix_ms) * 1000;
    spans.push({
      id: frontendId(event),
      parent: null,
      children: [],
      target,
      name,
      kind: `${target}::${name}`,
      module: moduleOf(target),
      start,
      end: start + event.durationMs * 1000,
      duration: event.durationMs * 1000,
      busy: null,
      ownBusy: null,
      longestPoll: null,
      open: false,
      own: 0,
      frontend: event.kind,
      row: -1,
    });
  }
  const byId = new Map(spans.map((s) => [s.id, s]));
  for (const span of capture.spans) {
    // A parent that closed before the capture's start is not in it: the span is a root here.
    const parent = span.parent ? byId.get(span.parent) : undefined;
    if (!parent) continue;
    const child = byId.get(span.id)!;
    child.parent = parent;
    parent.children.push(child);
  }
  for (const span of spans) {
    span.children.sort((a, b) => a.start - b.start);
    span.own = span.duration - unionLength(span.children.map((c) => [Math.max(c.start, span.start), Math.min(c.end, span.end)]));
  }
  return { spans, byId, durationUs: capture.duration_us, startUnixMs: capture.start_unix_ms, truncated: capture.truncated };
}

/**
 * Rows for the timeline. Each module gets a header row; under it, its top-level spans
 * gather by kind, longest in total first. A span's children go on the rows below it, and
 * spans that overlap in time (top-level ones of a kind, or siblings) take rows of their
 * own, so nothing is drawn over anything else.
 */
export function layoutTrace(trace: Trace, collapsed: ReadonlySet<string>, hidden: ReadonlySet<string>): Layout {
  for (const span of trace.spans) span.row = -1;
  // Each child's row below its parent; `pack` returns the rows a subtree needs and when it ends.
  const offset = new Map<Span, number>();
  const pack = (span: Span): { height: number; end: number } => {
    const rowEnds: number[] = [];
    let height = 1;
    let end = span.end;
    for (const child of span.children) {
      const sub = pack(child);
      let row = 1;
      const fits = (top: number) => {
        for (let r = top; r < top + sub.height; r++) if ((rowEnds[r] ?? -Infinity) > child.start) return false;
        return true;
      };
      while (!fits(row)) row++;
      for (let r = row; r < row + sub.height; r++) rowEnds[r] = sub.end;
      offset.set(child, row);
      height = Math.max(height, row + sub.height);
      end = Math.max(end, sub.end);
    }
    return { height, end };
  };
  const place = (span: Span, row: number) => {
    span.row = row;
    for (const child of span.children) place(child, row + offset.get(child)!);
  };

  const byModule = new Map<string, { module: Module; roots: Span[] }>();
  for (const span of trace.spans) {
    if (span.parent) continue;
    const entry = byModule.get(span.module.id) ?? { module: span.module, roots: [] };
    entry.roots.push(span);
    byModule.set(span.module.id, entry);
  }
  const modules = [...byModule.values()].map((m) => m.module).sort((a, b) => moduleRank(a) - moduleRank(b));

  const rows: Row[] = [];
  let top = 0;
  for (const module of modules) {
    if (hidden.has(module.id)) continue;
    const { roots } = byModule.get(module.id)!;
    const isCollapsed = collapsed.has(module.id);
    rows.push({ type: "module", module, collapsed: isCollapsed, count: roots.length, top });
    top += MODULE_ROW_HEIGHT;
    if (isCollapsed) continue;

    const byKind = new Map<string, Span[]>();
    for (const root of roots) {
      const group = byKind.get(root.kind);
      if (group) group.push(root);
      else byKind.set(root.kind, [root]);
    }
    const total = (list: Span[]) => list.reduce((sum, s) => sum + s.duration, 0);
    const groups = [...byKind.values()].sort((a, b) => total(b) - total(a));

    for (const group of groups) {
      group.sort((a, b) => a.start - b.start);
      const lanes: { end: number; height: number; members: Span[] }[] = [];
      for (const root of group) {
        const sub = pack(root);
        const lane = lanes.find((l) => l.end <= root.start);
        if (lane) {
          lane.end = sub.end;
          lane.height = Math.max(lane.height, sub.height);
          lane.members.push(root);
        } else {
          lanes.push({ end: sub.end, height: sub.height, members: [root] });
        }
      }
      const firstRow = rows.length;
      for (const lane of lanes) {
        const laneRow = rows.length;
        for (let r = 0; r < lane.height; r++) {
          rows.push({ type: "spans", module, label: null, spans: [], top });
          top += SPAN_ROW_HEIGHT;
        }
        for (const root of lane.members) place(root, laneRow);
      }
      (rows[firstRow] as Extract<Row, { type: "spans" }>).label = `${group[0].name} ×${group.length}`;
      for (const root of group) collect(root, rows);
    }
  }
  for (const row of rows) if (row.type === "spans") row.spans.sort((a, b) => a.start - b.start);
  return { rows, height: top, modules };
}

function collect(span: Span, rows: Row[]) {
  (rows[span.row] as Extract<Row, { type: "spans" }>).spans.push(span);
  for (const child of span.children) collect(child, rows);
}

/** The span and the ones enclosing it, outermost first. */
export function ancestry(span: Span): Span[] {
  const chain: Span[] = [];
  for (let s: Span | null = span; s; s = s.parent) chain.unshift(s);
  return chain;
}

export interface Share {
  kind: string;
  name: string;
  module: Module;
  us: number;
}

/** Where a span's time went: per kind of child, the time those children covered, and its
 * own time; largest first. */
export function breakdown(span: Span): { own: number; children: Share[] } {
  const byKind = new Map<string, { child: Span; intervals: [number, number][] }>();
  for (const child of span.children) {
    const entry = byKind.get(child.kind) ?? { child, intervals: [] };
    entry.intervals.push([Math.max(child.start, span.start), Math.min(child.end, span.end)]);
    byKind.set(child.kind, entry);
  }
  const children = [...byKind.entries()]
    .map(([kind, { child, intervals }]) => ({ kind, name: child.name, module: child.module, us: unionLength(intervals) }))
    .sort((a, b) => b.us - a.us);
  return { own: span.own, children };
}

export interface KindComparison {
  count: number;
  medianUs: number;
  p95Us: number;
  maxUs: number;
  /** Share of the others this one took longer than. */
  slowerThan: number;
}

/** How a span's duration compares with every span of its kind in the trace. */
export function compareWithKind(trace: Trace, span: Span): KindComparison {
  const durations = trace.spans.filter((s) => s.kind === span.kind).map((s) => s.duration).sort((a, b) => a - b);
  const at = (fraction: number) => durations[Math.min(durations.length - 1, Math.floor(fraction * durations.length))];
  const others = durations.length - 1;
  const faster = durations.filter((d) => d < span.duration).length;
  return {
    count: durations.length,
    medianUs: at(0.5),
    p95Us: at(0.95),
    maxUs: durations[durations.length - 1],
    slowerThan: others > 0 ? faster / others : 0,
  };
}

/** The backend's span for a command the main window waited on: the commands span of that
 * name that began during the round trip. */
export function backendOf(trace: Trace, span: Span): Span | null {
  if (span.frontend !== "command") return null;
  let best: Span | null = null;
  for (const s of trace.spans) {
    if (s.frontend || s.module.id !== COMMANDS_MODULE || s.name !== span.name || s.start < span.start || s.start > span.end) continue;
    if (!best || s.start < best.start) best = s;
  }
  return best;
}

export interface ModuleTime {
  module: Module;
  /** Own time of its spans inside the range; concurrent spans each count. */
  us: number;
  spans: number;
}

/** Per module, the own time its spans spent inside [from, to]. */
export function timeByModule(trace: Trace, from: number, to: number, include: (span: Span) => boolean): ModuleTime[] {
  const byModule = new Map<string, ModuleTime>();
  for (const span of trace.spans) {
    if (!include(span) || span.end < from || span.start > to) continue;
    const entry = byModule.get(span.module.id) ?? { module: span.module, us: 0, spans: 0 };
    entry.spans += 1;
    for (const [a, b] of ownSegments(span)) entry.us += overlap(a, b, from, to);
    byModule.set(span.module.id, entry);
  }
  return [...byModule.values()].sort((a, b) => b.us - a.us);
}

export interface KindTime {
  kind: string;
  target: string;
  name: string;
  module: Module;
  count: number;
  /** Own time inside the range. */
  ownUs: number;
  /** Time inside the range any span of the kind was open, overlaps counted once. */
  totalUs: number;
  /** Own code running, in proportion to the own time inside the range; null where unknown. */
  busyUs: number | null;
}

/** Per kind of span, the time it took inside [from, to]: own time first. */
export function bottomUp(trace: Trace, from: number, to: number, include: (span: Span) => boolean): KindTime[] {
  const byKind = new Map<string, KindTime & { intervals: [number, number][] }>();
  for (const span of trace.spans) {
    if (!include(span) || span.end < from || span.start > to) continue;
    const entry = byKind.get(span.kind) ?? {
      kind: span.kind,
      target: span.target,
      name: span.name,
      module: span.module,
      count: 0,
      ownUs: 0,
      totalUs: 0,
      busyUs: null,
      intervals: [],
    };
    const ownInside = ownSegments(span).reduce((sum, [a, b]) => sum + overlap(a, b, from, to), 0);
    entry.count += 1;
    entry.ownUs += ownInside;
    entry.intervals.push([Math.max(span.start, from), Math.min(span.end, to)]);
    if (span.ownBusy !== null) entry.busyUs = (entry.busyUs ?? 0) + (span.own > 0 ? (span.ownBusy * ownInside) / span.own : 0);
    byKind.set(span.kind, entry);
  }
  return [...byKind.values()]
    .map(({ intervals, ...entry }) => ({ ...entry, totalUs: unionLength(intervals) }))
    .sort((a, b) => b.ownUs - a.ownUs);
}

/** Spans overlapping [from, to], longest first. */
export function longestSpans(trace: Trace, from: number, to: number, include: (span: Span) => boolean, limit: number): Span[] {
  return trace.spans
    .filter((s) => include(s) && s.end >= from && s.start <= to)
    .sort((a, b) => b.duration - a.duration)
    .slice(0, limit);
}

/** The budget a span answers to: a command and the interface's wait on it, input, and
 * the main window's frames and tasks. Null for the rest, which nobody waits on directly. */
export function budgetUs(span: Span): number | null {
  if (span.frontend === "command" || (span.module.id === COMMANDS_MODULE && !span.parent)) return COMMAND_BUDGET_MS * 1000;
  if (span.frontend === "interaction") return INTERACTION_BUDGET_MS * 1000;
  if (span.frontend === "frame" || span.frontend === "longtask") return LONG_FRAME_MS * 1000;
  return null;
}

/** Whether the span ran past its budget. */
export const overBudget = (span: Span) => {
  const budget = budgetUs(span);
  return budget !== null && span.duration > budget;
};

/** Whether the span's own code held its thread for `blockingUs` or longer. */
export const heldThread = (span: Span, blockingUs: number) => (span.longestPoll ?? 0) >= blockingUs;
