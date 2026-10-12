// Measures the main window for the profiler: command round trips, input, and frames
// long enough to see. Keeps as long a history as the backend's flight recorder, so a
// capture shows this side too; reports once a second, and the whole history when the
// profiler opens.

import { invoke } from "@tauri-apps/api/core";
import { emitTo, listen } from "@tauri-apps/api/event";
import type { DevtoolsLimits } from "../generated/DevtoolsLimits";
import { LONG_FRAME_MS } from "./budgets";
import { takeCommands } from "./commands";
import { toUnixMs } from "./measure";
import { FRONTEND_REPORT_EVENT, FRONTEND_SYNC_EVENT, PROFILER_WINDOW, type FrontendEvent, type FrontendReport } from "./types";

const REPORT_INTERVAL_MS = 1000;
/** Event Timing reports nothing quicker than this (the API's minimum). */
const EVENT_THRESHOLD_MS = 16;
/** Input that counts as an interaction where entries carry no interaction id. */
const DISCRETE_INPUT = new Set(["click", "keydown"]);
/** Interaction ids remembered while their entries arrive; one interaction's come together. */
const INTERACTIONS_REMEMBERED = 50;

let fresh: FrontendEvent[] = [];
let history: FrontendEvent[] = [];
/** How long the history keeps events: the flight recorder's window, once known. */
let historyMs = Infinity;

/** Frames long enough to see, measured between animation frames while the window shows. */
function watchFrames() {
  let last: number | null = null;
  // A hidden window stops rendering; the gap is not a frame.
  document.addEventListener("visibilitychange", () => { last = null; });
  const tick = (now: number) => {
    if (last !== null && now - last >= LONG_FRAME_MS) {
      fresh.push({ kind: "frame", name: "", startUnixMs: toUnixMs(last), durationMs: now - last });
    }
    last = now;
    requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

/** Observe an entry type if this webview supports it. */
function observe(type: string, onEntry: (entry: PerformanceEntry) => void, options: Record<string, unknown> = {}) {
  if (!PerformanceObserver.supportedEntryTypes?.includes(type)) return;
  new PerformanceObserver((list) => list.getEntries().forEach(onEntry)).observe({ type, buffered: false, ...options });
}

/** One click or key press yields several entries (down, up, click) under one interaction
 * id; the longest stands for the interaction. */
function watchInteractions() {
  const byInteraction = new Map<number, FrontendEvent>();
  observe(
    "event",
    (entry) => {
      const id = (entry as PerformanceEntry & { interactionId?: number }).interactionId;
      if (id === undefined ? !DISCRETE_INPUT.has(entry.name) : id === 0) return;
      const event: FrontendEvent = { kind: "interaction", name: entry.name, startUnixMs: toUnixMs(entry.startTime), durationMs: entry.duration };
      if (id === undefined) {
        fresh.push(event);
        return;
      }
      const seen = byInteraction.get(id);
      if (seen) {
        if (event.durationMs > seen.durationMs) Object.assign(seen, event);
        return;
      }
      byInteraction.set(id, event);
      fresh.push(event);
      if (byInteraction.size > INTERACTIONS_REMEMBERED) byInteraction.delete(byInteraction.keys().next().value!);
    },
    { durationThreshold: EVENT_THRESHOLD_MS },
  );
}

/** Move what happened since the last report into the history, dropping what aged out. */
function collect(): FrontendEvent[] {
  const events = [...takeCommands(), ...fresh];
  fresh = [];
  const horizon = Date.now() - historyMs;
  history = [...history.filter((e) => e.startUnixMs + e.durationMs >= horizon), ...events];
  return events;
}

export function startFrontendReports() {
  invoke<DevtoolsLimits>("devtools_limits").then((limits) => { historyMs = limits.capture_window_ms; });
  watchFrames();
  // Event Timing: WebView2, and WebKit from Safari 26.2 / WebKitGTK 2.52.
  watchInteractions();
  // Long Tasks: WebView2 only.
  observe("longtask", (e) => {
    fresh.push({ kind: "longtask", name: "", startUnixMs: toUnixMs(e.startTime), durationMs: e.duration });
  });
  const send = (report: FrontendReport) => emitTo(PROFILER_WINDOW, FRONTEND_REPORT_EVENT, report).catch(() => {});

  listen(FRONTEND_SYNC_EVENT, () => {
    collect();
    send({ events: history, backlog: true });
  });
  setInterval(() => send({ events: collect(), backlog: false }), REPORT_INTERVAL_MS);
}
