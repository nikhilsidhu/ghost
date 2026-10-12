// What one process wrote, filterable. New lines follow live; scrolling up holds the view
// where it is until the reader scrolls back down.

import { createEffect, createMemo, createSignal, on, onCleanup, Show } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import { Card } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { ScrollArea } from "../components/ui/scroll-area";
import { cn } from "../lib/cn";
import { LOG_EVENT, processLog } from "./api";

/** Lines kept in view, as many as the launcher keeps per process. */
const MAX_LINES = 5000;
/** How near the bottom counts as reading the newest lines. */
const FOLLOW_SLACK_PX = 24;

export function LogPanel(props: { process: string; label?: string; class?: string }) {
  const [lines, setLines] = createSignal<string[]>([]);
  const [filter, setFilter] = createSignal("");
  let body!: HTMLDivElement;
  let following = true;

  const shown = createMemo(() => {
    const query = filter().trim().toLowerCase();
    return query ? lines().filter((line) => line.toLowerCase().includes(query)) : lines();
  });

  createEffect(
    on(
      () => props.process,
      (process) => {
        following = true;
        setLines([]);
        processLog(process).then(setLines).catch(() => setLines([]));
        const unlisten = listen<{ process: string; line: string }>(LOG_EVENT, (event) => {
          if (event.payload.process === process) setLines((all) => [...all, event.payload.line].slice(-MAX_LINES));
        });
        onCleanup(() => unlisten.then((stop) => stop()));
      },
    ),
  );

  // Stay on the newest line while the reader is there.
  createEffect(() => {
    shown();
    if (following) queueMicrotask(() => (body.scrollTop = body.scrollHeight));
  });

  return (
    <div class={cn("flex flex-col min-h-0 mx-2", props.class)}>
      <div class="flex items-center justify-between gap-3 px-3 mb-1.5">
        <span class="text-xs text-[var(--neutral-500)]">{props.label ?? "log"}</span>
        <Input class="h-6 text-[11px] w-48 px-2" placeholder="filter" aria-label={`Filter the ${props.process} log`} value={filter()} onInput={(e) => setFilter(e.currentTarget.value)} />
      </div>
      <Card class="flex-1 min-h-0 flex flex-col">
        <ScrollArea
          ref={body}
          class="flex-1 min-h-0 px-3 py-2"
          onScroll={() => (following = body.scrollHeight - body.scrollTop - body.clientHeight < FOLLOW_SLACK_PX)}
        >
          <Show when={shown().length > 0} fallback={<div class="text-xs text-[var(--neutral-500)]">{lines().length ? "nothing matches" : "nothing written yet"}</div>}>
            <pre class="text-[11px] leading-[1.5] text-[var(--neutral-300)] whitespace-pre-wrap break-words font-mono">{shown().join("\n")}</pre>
          </Show>
        </ScrollArea>
      </Card>
    </div>
  );
}
