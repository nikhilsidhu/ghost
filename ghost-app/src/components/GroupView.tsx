import { Show, For } from "solid-js";
import type { Group, Channel } from "../lib/types";
import { ScrollArea } from "./ui/scroll-area";

interface Props {
  group: Group;
  channels: Channel[];
}

export function GroupView(props: Props) {
  return (
    <div class="flex-1 flex flex-col min-h-0">
      <div class="h-14 flex-shrink-0 flex items-center px-4">
        <span class="text-base font-medium text-[var(--neutral-200)]">
          {props.group.name}
        </span>
      </div>

      <ScrollArea class="flex-1 p-4">
        <div class="text-xs uppercase tracking-wider text-[var(--neutral-500)] mb-2">
          channels
        </div>
        <For each={props.channels}>
          {(ch) => (
            <div class="flex items-center gap-2 px-2 py-1.5 rounded text-sm text-[var(--neutral-400)]">
              <span class="text-[var(--neutral-500)]">
                {ch.kind === "text" ? "#" : "♪"}
              </span>
              {ch.name}
            </div>
          )}
        </For>
        <Show when={props.channels.length === 0}>
          <div class="text-sm text-[var(--neutral-600)] px-2">no channels</div>
        </Show>
      </ScrollArea>
    </div>
  );
}
