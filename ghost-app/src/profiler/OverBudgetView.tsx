// Everything that went over its budget since the profiler opened: a slow command or
// input, a frame long enough to see, a backend operation that held its thread, an audio
// thread past half of real time. Each one still in the flight recorder opens its moment
// in a capture.

import { For, Show } from "solid-js";
import { SettingGroup } from "../components/settings/controls";
import { cn } from "../lib/cn";
import type { ProfilerData, SlowEvent } from "./data";
import { ago, formatMs, load } from "./format";
import { emptyClass, numClass, OverBudget, rowClass, warnClass } from "./table";

const COLUMNS = "72px 112px minmax(0, 1fr) 72px 96px 16px";

const KIND_LABELS: Record<SlowEvent["kind"], string> = {
  command: "command",
  input: "input",
  frame: "frame",
  "long task": "long task",
  blocked: "held thread",
  audio: "audio",
};

const figure = (event: SlowEvent) => (event.unit === "ms" ? formatMs(event.value) : load(event.value));
const budget = (event: SlowEvent) => (event.unit === "ms" ? `${event.budget} ms` : load(event.budget));

export default function OverBudgetView(props: { data: ProfilerData; onOpen: (event: SlowEvent) => void }) {
  const inCapture = (event: SlowEvent) => props.data.now() - event.atUnixMs < (props.data.limits()?.capture_window_ms ?? 0);

  return (
    <div class="px-2 pb-6">
      <SettingGroup label="newest first">
        <Show when={props.data.slowEvents().length > 0} fallback={<div class={emptyClass}>nothing has gone over budget since the profiler opened</div>}>
          <For each={props.data.slowEvents()}>
            {(event) => (
              <button
                class={cn(rowClass, "-mx-3 px-3 w-[calc(100%+1.5rem)] text-left", inCapture(event) ? "cursor-pointer hover:bg-[var(--hover)]" : "cursor-default")}
                style={{ "grid-template-columns": COLUMNS }}
                disabled={!inCapture(event)}
                title={inCapture(event) ? "Capture and show this moment" : "Older than the flight recorder keeps"}
                onClick={() => props.onOpen(event)}
              >
                <span class="text-[var(--neutral-500)] tabular-nums">{ago(event.atUnixMs, props.data.now())}</span>
                <OverBudget>{KIND_LABELS[event.kind]}</OverBudget>
                <span class="truncate text-[var(--neutral-200)]">{event.label}</span>
                <span class={cn(numClass, warnClass)}>{figure(event)}</span>
                <span class={cn(numClass, "text-[var(--neutral-500)]")}>budget {budget(event)}</span>
                <span class="text-[var(--neutral-500)]">{inCapture(event) ? "›" : ""}</span>
              </button>
            )}
          </For>
        </Show>
      </SettingGroup>
    </div>
  );
}
