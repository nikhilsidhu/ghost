import { Show, For } from "solid-js";
import { cn } from "../../lib/cn";
import { hashGradient } from "../../lib/gradients";
import { Avatar } from "../ui/avatar";
import { showTimestamps } from "./AppearanceSettings";

const MOCK_MESSAGES = [
  { sender: "alice", fp: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", content: "has anyone tried the new relay?", ts: "2:41 PM" },
  { sender: "bob", fp: "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3", content: "yeah it's way faster now", ts: "2:42 PM" },
  { sender: "bob", fp: "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3", content: "latency dropped by half", ts: "2:42 PM" },
  { sender: "clara", fp: "1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d", content: "nice, i'll switch over tonight", ts: "2:43 PM" },
];

export default function AppearancePreview() {
  return (
    <div class="flex-1 flex flex-col min-h-0">
      <div class="h-14 flex-shrink-0 flex items-center px-4">
        <span class="text-sm text-[var(--neutral-500)] mr-1">#</span>
        <span class="text-base font-medium text-[var(--neutral-200)]">preview</span>
      </div>
      <div class="divider-h" />
      <div class="flex-1 px-4 py-2">
        <For each={MOCK_MESSAGES}>
          {(msg, idx) => {
            const grouped = () => idx() > 0 && MOCK_MESSAGES[idx() - 1].fp === msg.fp;
            const grad = () => hashGradient(msg.fp);
            return (
              <div
                class={cn(
                  "group/msg -mx-2 px-2 rounded-md",
                  grouped() ? "py-1 pl-[var(--msg-indent)]" : "mt-2 py-1.5",
                )}
              >
                <Show when={!grouped()}>
                  <div class="flex items-start gap-3">
                    <Avatar
                      hashKey={msg.fp}
                      label={msg.sender}
                      class="w-[var(--size-md)] h-[var(--size-md)] text-xs mt-1 opacity-85"
                    />
                    <div class="flex-1 min-w-0">
                      <div class="flex items-baseline gap-2">
                        <span class="text-sm font-medium" style={{ color: grad().from }}>
                          {msg.sender}
                        </span>
                        <Show when={showTimestamps()}>
                          <span class="text-xs text-[var(--neutral-600)]">{msg.ts}</span>
                        </Show>
                      </div>
                      <div class="text-sm text-[var(--neutral-300)] break-words leading-relaxed">
                        {msg.content}
                      </div>
                    </div>
                  </div>
                </Show>
                <Show when={grouped()}>
                  <div class="text-sm text-[var(--neutral-300)] break-words leading-relaxed">
                    {msg.content}
                  </div>
                </Show>
              </div>
            );
          }}
        </For>
      </div>
    </div>
  );
}
