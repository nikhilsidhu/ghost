// What the main window reports to the profiler window: what it measures of itself,
// which the backend cannot see.

export type FrontendEventKind = "command" | "interaction" | "frame" | "longtask";

/** Something the main window did or went through, in wall-clock time so it lines up
 * with the backend's captures. */
export interface FrontendEvent {
  kind: FrontendEventKind;
  /** The command, or the input event's type; empty for frames and long tasks. */
  name: string;
  startUnixMs: number;
  durationMs: number;
}

export interface FrontendReport {
  events: FrontendEvent[];
  /** The events are the window's whole history, sent when the profiler opens. */
  backlog: boolean;
}

export const FRONTEND_REPORT_EVENT = "devtools-frontend";
/** The profiler asking the main window for its backlog. */
export const FRONTEND_SYNC_EVENT = "devtools-sync";
/** The backend telling an open profiler to capture; a new one gets the fragment in its
 * URL instead. Both match devtools.rs. */
export const CAPTURE_EVENT = "devtools-capture";
export const CAPTURE_FRAGMENT = "#capture";
export const MAIN_WINDOW = "main";
export const PROFILER_WINDOW = "profiler";
