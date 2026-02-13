import { For, Show } from "solid-js";
import type { Member } from "../lib/types";
import { hashGradient, onFlareMove, onFlareLeave } from "../lib/gradients";
import { ScrollArea } from "./ui/scroll-area";

interface Props {
  members: Member[];
}

export function MemberPanel(props: Props) {
  return (
    <div
      class="w-56 flex-shrink-0 flex flex-col"
      style={{ background: "var(--neutral-950)" }}
    >
      <div class="h-7 flex-shrink-0" />
      <div class="h-10 flex-shrink-0 flex items-center px-3">
        <span class="text-xs uppercase tracking-wider text-[var(--neutral-500)]">
          members — {props.members.length}
        </span>
      </div>
      <ScrollArea class="flex-1">
        <div class="px-2 py-1">
          <For each={props.members}>
            {(m) => {
              const grad = hashGradient(m.fingerprint);
              return (
                <div class="flex items-center gap-2.5 px-2 py-1.5 rounded-md hover:bg-[var(--hover)]">
                  <button
                    class="avatar-flare w-[var(--size-md)] h-[var(--size-md)] rounded-full flex items-center justify-center text-xs font-semibold flex-shrink-0 cursor-pointer transition-all duration-200 opacity-85 hover:opacity-100 hover:scale-105"
                    style={{
                      background: `linear-gradient(${grad.angle}deg, ${grad.from}, ${grad.to})`,
                      color: "var(--neutral-100)",
                    }}
                    onMouseMove={onFlareMove}
                    onMouseLeave={onFlareLeave}
                  >
                    {m.display_name[0]?.toUpperCase()}
                  </button>
                  <div class="flex-1 min-w-0">
                    <div class="text-sm text-[var(--neutral-200)] truncate">
                      {m.display_name}
                    </div>
                    <Show when={m.role === "creator"}>
                      <div class="text-[11px] text-[var(--purple-400)] leading-tight">creator</div>
                    </Show>
                  </div>
                </div>
              );
            }}
          </For>
        </div>
      </ScrollArea>
    </div>
  );
}
