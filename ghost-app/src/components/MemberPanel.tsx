import { For, Show } from "solid-js";
import { ScrollArea } from "./ui/scroll-area";
import { Avatar } from "./ui/avatar";
import { members } from "../lib/store";

export function MemberPanel() {
  return (
    <div
      class="w-56 flex-shrink-0 flex flex-col"
      style={{ background: "var(--neutral-950)" }}
    >
      <div class="h-7 flex-shrink-0" />
      <div class="h-10 flex-shrink-0 flex items-center px-3">
        <span class="text-sm font-medium text-[var(--neutral-500)]">
          members — {members().length}
        </span>
      </div>
      <ScrollArea class="flex-1">
        <div class="px-2 py-1">
          <For each={members()}>
            {(m) => (
              <div class="flex items-center gap-2.5 px-2 py-1.5 rounded-md hover:bg-[var(--hover)]">
                <Avatar
                  hashKey={m.fingerprint}
                  label={m.display_name}
                  class="w-[var(--size-md)] h-[var(--size-md)] text-xs transition-all duration-200 opacity-85 hover:opacity-100 hover:scale-105"
                />
                <div class="flex-1 min-w-0">
                  <div class="text-sm text-[var(--neutral-200)] truncate">
                    {m.display_name}
                  </div>
                  <Show when={m.role === "creator"}>
                    <div class="text-[11px] text-[var(--purple-400)] leading-tight">creator</div>
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
