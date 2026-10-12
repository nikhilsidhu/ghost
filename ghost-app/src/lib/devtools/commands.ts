// Command round trips as the interface waited for them, held until the main window's
// next report takes them.

import { toUnixMs } from "./measure";
import type { FrontendEvent } from "./types";

let completed: FrontendEvent[] = [];

/** `name` was invoked at `startedAt` (a `performance.now()` reading) and took `durationMs`. */
export function recordCommand(name: string, startedAt: number, durationMs: number) {
  completed.push({ kind: "command", name, startUnixMs: toUnixMs(startedAt), durationMs });
}

export function takeCommands(): FrontendEvent[] {
  const taken = completed;
  completed = [];
  return taken;
}
