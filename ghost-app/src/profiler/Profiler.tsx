// The profiler window of devtools builds. Over budget lists what went past its budget
// since it opened, statistics where time went, trace what happened over the last minute
// (captured from the flight recorder), and call how each stream of a call is doing.

import { createEffect, createSignal, onCleanup, onMount, Show } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import { PanelHeader } from "../components/ui/panel-header";
import { Button } from "../components/ui/button";
import { FadedScrollArea } from "../components/ui/scroll-area";
import { Tabs } from "../components/ui/tabs";
import { devProfile } from "../lib/dev-profile";
import { CAPTURE_EVENT, CAPTURE_FRAGMENT } from "../lib/devtools/types";
import { cn } from "../lib/cn";
import CallView from "./CallView";
import { createProfilerData, type SlowEvent } from "./data";
import { clockTime, duration, formatOffset } from "./format";
import OverBudgetView from "./OverBudgetView";
import StatisticsView from "./StatisticsView";
import TraceView, { type Focus } from "./TraceView";

type Tab = "over budget" | "statistics" | "trace" | "call";
const ALWAYS: readonly Tab[] = ["over budget", "statistics", "trace"];

export default function Profiler() {
  const data = createProfilerData();
  const [tab, setTab] = createSignal<Tab>("over budget");
  const [focus, setFocus] = createSignal<Focus | null>(null);
  const [capturing, setCapturing] = createSignal(false);
  const inCall = () => data.snapshot()?.call !== null && data.snapshot()?.call !== undefined;
  const tabs = () => (inCall() ? [...ALWAYS, "call" as const] : ALWAYS).map((value) => ({ value, label: value }));

  /** Capture the flight recorder and show it, at `event` if one was picked. */
  const capture = async (event?: SlowEvent) => {
    setCapturing(true);
    try {
      const trace = await data.capture();
      setTab("trace");
      setFocus(event ? { trace, event } : null);
    } finally {
      setCapturing(false);
    }
  };

  onMount(() => {
    data.start();
    // Opened by /capture in the main window, or asked again while open.
    if (location.hash === CAPTURE_FRAGMENT) capture();
    const unlisten = listen(CAPTURE_EVENT, () => capture());
    onCleanup(() => unlisten.then((stop) => stop()));
  });

  // The call tab goes when the call does.
  createEffect(() => {
    if (tab() === "call" && !inCall()) setTab("over budget");
  });

  const status = () => {
    const trace = data.trace();
    switch (tab()) {
      case "over budget":
        return `since the profiler opened at ${clockTime(data.openedAt())}`;
      case "statistics":
        return `since ${clockTime(data.statsSince())}, ${duration(data.statsSince(), data.now())}`;
      case "trace":
        return trace ? `captured ${clockTime(trace.startUnixMs + trace.durationUs / 1000)} · ${formatOffset(trace.durationUs)} · ${trace.spans.length} spans` : "";
      case "call": {
        const ping = data.snapshot()?.call?.ping_ms;
        return ping === null || ping === undefined ? "" : `voice server round trip ${ping} ms`;
      }
    }
  };

  const pane = (name: Tab) => cn("flex-1 min-h-0 flex flex-col", tab() !== name && "hidden");

  return (
    <div class="h-screen flex flex-col bg-[var(--neutral-950)] text-[var(--neutral-200)]">
      <PanelHeader title="profiler">
        <Show when={devProfile()}>
          <span class="text-xs text-[var(--neutral-500)]">{devProfile()}</span>
        </Show>
        <div class="ml-3">
          <Tabs value={tab()} onChange={setTab} tabs={tabs()} label="Profiler views" />
        </div>
        <div class="flex-1" />
        <span class="text-xs text-[var(--neutral-500)] truncate">{status()}</span>
        <Show when={tab() === "statistics"}>
          <Button variant="ghost" size="sm" onClick={() => data.reset()}>
            reset
          </Button>
        </Show>
      </PanelHeader>

      <Show when={data.error()}>
        <div class="px-4 pb-2 text-xs text-[var(--red-400)]">{data.error()}</div>
      </Show>

      <div class={pane("over budget")}>
        <FadedScrollArea>
          <OverBudgetView data={data} onOpen={capture} />
        </FadedScrollArea>
      </div>
      <div class={pane("statistics")}>
        <FadedScrollArea>
          <StatisticsView data={data} />
        </FadedScrollArea>
      </div>
      <div class={pane("trace")}>
        <TraceView data={data} focus={focus()} capturing={capturing()} onCapture={() => capture()} />
      </div>
      <div class={pane("call")}>
        <FadedScrollArea>
          <CallView data={data} />
        </FadedScrollArea>
      </div>
    </div>
  );
}
