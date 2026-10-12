// The profiler's live data: the backend polled once a second and the main window's
// reports, kept the way the views show them. Statistics start when the profiler opens,
// on both sides, so the commands table compares like with like.

import { createSignal, onCleanup } from "solid-js";
import { createStore, reconcile } from "solid-js/store";
import { invoke } from "@tauri-apps/api/core";
import { emitTo, listen } from "@tauri-apps/api/event";
import type { CallFigure } from "../lib/generated/CallFigure";
import type { DevtoolsLimits } from "../lib/generated/DevtoolsLimits";
import type { DevtoolsSnapshot } from "../lib/generated/DevtoolsSnapshot";
import type { SpanTiming } from "../lib/generated/SpanTiming";
import type { TraceCapture } from "../lib/generated/TraceCapture";
import { AUDIO_LOAD_BUDGET, COMMAND_BUDGET_MS, INTERACTION_BUDGET_MS, LONG_FRAME_MS } from "../lib/devtools/budgets";
import { percentile } from "../lib/devtools/measure";
import { FRONTEND_REPORT_EVENT, FRONTEND_SYNC_EVENT, MAIN_WINDOW, type FrontendEvent, type FrontendReport } from "../lib/devtools/types";
import { callSecond, type CallSecond } from "./call";
import { shortTarget } from "./modules";
import { buildTrace, frontendId, type Trace } from "./trace-model";

const POLL_MS = 1000;
/** Points each call chart keeps, one a second. */
export const SERIES_POINTS = 60;
const SLOW_EVENTS_KEPT = 50;
/** Round trips kept per command for its percentile. */
const COMMAND_SAMPLES = 10_000;
/** How long a capture waits for the main window's history when the profiler just opened. */
const BACKLOG_WAIT_MS = 1000;

export type SpanRow = SpanTiming & { kind: string };

export interface CommandRow {
  name: string;
  calls: number;
  avgMs: number;
  p95Ms: number;
  maxMs: number;
}

export type SlowEventKind = "command" | "input" | "frame" | "long task" | "blocked" | "audio";

/** Something that went over its budget. */
export interface SlowEvent {
  key: string;
  kind: SlowEventKind;
  label: string;
  atUnixMs: number;
  durationMs: number;
  /** How long it took, or for audio its load. */
  value: number;
  budget: number;
  unit: "ms" | "load";
  /** The span standing for it in a capture. */
  spanId: string | null;
}

const withKind = (span: SpanTiming): SpanRow => ({ ...span, kind: `${span.target}::${span.name}` });

function slowFromFrontend(events: readonly FrontendEvent[]): SlowEvent[] {
  const slow: SlowEvent[] = [];
  for (const e of events) {
    const base = { key: frontendId(e), atUnixMs: e.startUnixMs, durationMs: e.durationMs, value: e.durationMs, unit: "ms" as const, spanId: frontendId(e) };
    if (e.kind === "command" && e.durationMs > COMMAND_BUDGET_MS) slow.push({ ...base, kind: "command", label: e.name, budget: COMMAND_BUDGET_MS });
    if (e.kind === "interaction" && e.durationMs > INTERACTION_BUDGET_MS) slow.push({ ...base, kind: "input", label: e.name, budget: INTERACTION_BUDGET_MS });
    if (e.kind === "frame") slow.push({ ...base, kind: "frame", label: "main window", budget: LONG_FRAME_MS });
    if (e.kind === "longtask") slow.push({ ...base, kind: "long task", label: "main window", budget: LONG_FRAME_MS });
  }
  return slow;
}

export function createProfilerData() {
  const [limits, setLimits] = createSignal<DevtoolsLimits | null>(null);
  const [snapshot, setSnapshot] = createSignal<DevtoolsSnapshot | null>(null);
  const [tables, setTables] = createStore<{ spans: SpanRow[]; commands: CommandRow[] }>({ spans: [], commands: [] });
  const [slowEvents, setSlowEvents] = createSignal<SlowEvent[]>([]);
  /** The current call, a second at a time; empty outside a call. */
  const [callSeries, setCallSeries] = createSignal<CallSecond[]>([]);
  const [openedAt] = createSignal(Date.now());
  const [statsSince, setStatsSince] = createSignal(Date.now());
  const [now, setNow] = createSignal(Date.now());
  const [error, setError] = createSignal<string | null>(null);
  const [trace, setTrace] = createSignal<Trace | null>(null);

  /** The main window's recent history, for captures. */
  let history: FrontendEvent[] = [];
  let backlogArrived: () => void = () => {};
  const backlog = new Promise<void>((resolve) => { backlogArrived = resolve; });
  const samples = new Map<string, { calls: number; totalMs: number; maxMs: number; recent: number[] }>();
  const seenBlocking = new Set<string>();
  let lastCall: { figure: CallFigure; at: number } | null = null;

  const addSlow = (events: SlowEvent[]) => {
    if (events.length === 0) return;
    setSlowEvents((list) => [...events, ...list].sort((a, b) => b.atUnixMs - a.atUnixMs).slice(0, SLOW_EVENTS_KEPT));
  };

  const recordCommand = (name: string, ms: number) => {
    const s = samples.get(name) ?? { calls: 0, totalMs: 0, maxMs: 0, recent: [] };
    s.calls += 1;
    s.totalMs += ms;
    s.maxMs = Math.max(s.maxMs, ms);
    s.recent.push(ms);
    if (s.recent.length > COMMAND_SAMPLES) s.recent.shift();
    samples.set(name, s);
  };

  const commandRows = (): CommandRow[] =>
    [...samples.entries()].map(([name, s]) => ({ name, calls: s.calls, avgMs: s.totalMs / s.calls, p95Ms: percentile(s.recent, 0.95), maxMs: s.maxMs }));

  const onReport = (report: FrontendReport) => {
    const horizon = Date.now() - (limits()?.capture_window_ms ?? Infinity);
    // The backlog predates the statistics' start: it goes to captures and slow events only.
    history = report.backlog ? report.events : [...history.filter((e) => e.startUnixMs + e.durationMs >= horizon), ...report.events];
    addSlow(slowFromFrontend(report.events));
    if (report.backlog) {
      backlogArrived();
      return;
    }
    for (const e of report.events) if (e.kind === "command") recordCommand(e.name, e.durationMs);
  };

  const slowFromSnapshot = (next: DevtoolsSnapshot): SlowEvent[] => {
    const slow: SlowEvent[] = [];
    for (const b of next.blocking) {
      if (seenBlocking.has(b.id)) continue;
      seenBlocking.add(b.id);
      slow.push({
        key: `blocked:${b.id}`,
        kind: "blocked",
        label: `${shortTarget(b.target)}::${b.name}`,
        atUnixMs: b.ended_unix_ms - b.longest_poll_ms,
        durationMs: b.longest_poll_ms,
        value: b.longest_poll_ms,
        budget: limits()?.blocking_ms ?? b.longest_poll_ms,
        unit: "ms",
        spanId: b.id,
      });
    }
    const at = Date.now();
    for (const [label, peak] of [["capture", next.call?.capture.peak ?? 0], ["playback", next.call?.playback.peak ?? 0]] as const) {
      if (peak < AUDIO_LOAD_BUDGET) continue;
      slow.push({ key: `audio:${label}:${at}`, kind: "audio", label, atUnixMs: at - POLL_MS, durationMs: POLL_MS, value: peak, budget: AUDIO_LOAD_BUDGET, unit: "load", spanId: null });
    }
    return slow;
  };

  const recordCall = (figure: CallFigure | null) => {
    const at = Date.now();
    if (!figure) {
      lastCall = null;
      setCallSeries([]);
      return;
    }
    const second = callSecond(lastCall?.figure ?? null, figure, lastCall ? (at - lastCall.at) / 1000 : POLL_MS / 1000);
    lastCall = { figure, at };
    setCallSeries((series) => [...series, second].slice(-SERIES_POINTS));
  };

  const poll = async () => {
    try {
      const next = await invoke<DevtoolsSnapshot>("devtools_snapshot");
      setNow(Date.now());
      setSnapshot(next);
      setTables("spans", reconcile(next.spans.map(withKind), { key: "kind" }));
      setTables("commands", reconcile(commandRows(), { key: "name" }));
      recordCall(next.call);
      addSlow(slowFromSnapshot(next));
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  };

  const reset = async () => {
    await invoke("devtools_reset");
    samples.clear();
    setTables("commands", []);
    setStatsSince(Date.now());
  };

  /** Capture the flight recorder, with the main window's events of the same stretch. */
  const capture = async (): Promise<Trace> => {
    await Promise.race([backlog, new Promise((resolve) => setTimeout(resolve, BACKLOG_WAIT_MS))]);
    const next = buildTrace(await invoke<TraceCapture>("devtools_capture"), history);
    setTrace(next);
    return next;
  };

  const start = async () => {
    const unlisten = listen<FrontendReport>(FRONTEND_REPORT_EVENT, (event) => onReport(event.payload));
    let timer: ReturnType<typeof setInterval> | undefined;
    onCleanup(() => {
      clearInterval(timer);
      unlisten.then((stop) => stop());
    });
    setLimits(await invoke<DevtoolsLimits>("devtools_limits"));
    await unlisten;
    await emitTo(MAIN_WINDOW, FRONTEND_SYNC_EVENT);
    await reset();
    // The audio threads' first loads cover the time since whoever read them last.
    await invoke<DevtoolsSnapshot>("devtools_snapshot");
    timer = setInterval(poll, POLL_MS);
  };

  return { limits, snapshot, tables, slowEvents, callSeries, openedAt, statsSince, now, error, trace, start, reset, capture };
}

export type ProfilerData = ReturnType<typeof createProfilerData>;
