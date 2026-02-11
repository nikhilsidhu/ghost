import { Show, For } from "solid-js";
import type { Group, Channel, Member, Identity } from "../lib/types";
import { ScrollArea } from "./ui/scroll-area";
import { MessageView } from "./MessageView";
import { cn } from "../lib/cn";

interface Props {
  group: Group;
  channels: Channel[];
  members: Member[];
  identity: Identity | null;
  selectedChannelId: string | null;
  onSelectChannel: (id: string) => void;
}

export function GroupView(props: Props) {
  return (
    <div class="flex-1 flex flex-col min-h-0">
      <div class="h-14 flex-shrink-0 flex items-center px-4">
        <span class="text-base font-medium text-[var(--neutral-200)]">
          {props.group.name}
        </span>
      </div>

      <div class="flex-1 flex min-h-0">
        <div class="w-48 flex-shrink-0 border-r border-[var(--neutral-800)]">
          <ScrollArea class="h-full p-2">
            <div class="text-xs uppercase tracking-wider text-[var(--neutral-500)] px-2 mb-2">
              channels
            </div>
            <For each={props.channels}>
              {(ch) => (
                <button
                  class={cn(
                    "w-full flex items-center gap-2 px-2 py-1.5 rounded text-sm cursor-pointer",
                    ch.channel_id === props.selectedChannelId
                      ? "bg-[var(--purple-800)] text-[var(--neutral-100)]"
                      : "text-[var(--neutral-400)] hover:bg-[var(--neutral-800)]",
                  )}
                  onClick={() => { if (ch.kind === "text") props.onSelectChannel(ch.channel_id); }}
                >
                  <span class="text-[var(--neutral-500)]">
                    {ch.kind === "text" ? "#" : "\u266a"}
                  </span>
                  {ch.name}
                </button>
              )}
            </For>
            <Show when={props.channels.length === 0}>
              <div class="text-sm text-[var(--neutral-600)] px-2">no channels</div>
            </Show>
          </ScrollArea>
        </div>

        <Show
          when={props.selectedChannelId}
          fallback={
            <div class="flex-1 flex items-center justify-center">
              <span class="text-xs text-[var(--neutral-500)]">select a channel</span>
            </div>
          }
        >
          {(channelId) => (
            <MessageView
              groupId={props.group.group_id}
              channelId={channelId()}
              members={props.members}
              identity={props.identity}
            />
          )}
        </Show>
      </div>
    </div>
  );
}
