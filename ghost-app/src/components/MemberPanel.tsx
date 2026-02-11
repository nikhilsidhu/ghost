import { For, Show } from "solid-js";
import type { Member } from "../lib/types";
import { ScrollArea } from "./ui/scroll-area";

interface Props {
  members: Member[];
}

export function MemberPanel(props: Props) {
  return (
    <div
      class="w-56 flex-shrink-0 border-l border-[var(--neutral-800)] flex flex-col"
      style={{ background: "var(--neutral-900)" }}
    >
      <div class="h-7 flex-shrink-0" />
      <div class="h-14 flex-shrink-0 flex items-center px-3">
        <span class="text-xs uppercase tracking-wider text-[var(--neutral-500)]">
          members — {props.members.length}
        </span>
      </div>
      <ScrollArea class="flex-1">
        <div class="px-2 py-1">
          <For each={props.members}>
            {(m) => (
              <div class="flex items-center gap-2.5 px-1.5 py-1.5">
                <div
                  class="w-6 h-6 rounded-full flex items-center justify-center text-xs flex-shrink-0"
                  style={{ background: "var(--purple-800)", color: "var(--purple-300)" }}
                >
                  {m.display_name[0]}
                </div>
                <div class="flex-1 min-w-0">
                  <div class="text-sm text-[var(--neutral-300)] truncate">
                    {m.display_name}
                  </div>
                  <Show when={m.role === "creator"}>
                    <div class="text-xs text-[var(--purple-400)]">creator</div>
                  </Show>
                </div>
              </div>
            )}
          </For>
        </div>
      </ScrollArea>
    </div>
  );
}
