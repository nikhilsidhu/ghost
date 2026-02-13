import { createSignal, createEffect, on, For, Show } from "solid-js";
import type { Identity, Group, Channel } from "../lib/types";
import { ScrollArea } from "./ui/scroll-area";
import { cn } from "../lib/cn";
import { Pin, PinOff, AudioLines } from "lucide-solid";

const GROUP_COLORS: { bg: string; fg: string }[] = [
  { bg: "var(--purple-700)", fg: "var(--purple-200)" },
  { bg: "var(--violet-700)", fg: "var(--violet-200)" },
  { bg: "var(--cyan-700)", fg: "var(--cyan-200)" },
  { bg: "var(--emerald-700)", fg: "var(--emerald-200)" },
  { bg: "var(--amber-700)", fg: "var(--amber-200)" },
  { bg: "var(--rose-700)", fg: "var(--rose-200)" },
  { bg: "var(--red-700)", fg: "var(--red-200)" },
];

const groupColor = (groupId: string) => {
  let hash = 0;
  for (let i = 0; i < groupId.length; i++) {
    hash = (hash * 31 + groupId.charCodeAt(i)) | 0;
  }
  return GROUP_COLORS[Math.abs(hash) % GROUP_COLORS.length];
};

// Wraps a DOM update in a view transition when supported (Safari 18+, Chrome 111+)
const withTransition = (fn: () => void) => {
  if ("startViewTransition" in document) {
    (document as any).startViewTransition(fn);
  } else {
    fn();
  }
};

interface SidebarProps {
  identity: Identity | null;
  groups: Group[];
  pinnedGroupIds: Set<string>;
  selectedGroupId: string | null;
  channels: Channel[];
  selectedChannelId: string | null;
  onSelectGroup: (id: string) => void;
  onDeselectGroup: () => void;
  onSelectChannel: (id: string) => void;
  onTogglePin: (id: string) => void;
  onCreateChannel: (kind: "text" | "voice") => void;
}

export function Sidebar(props: SidebarProps) {
  const [textCollapsed, setTextCollapsed] = createSignal(false);
  const [voiceCollapsed, setVoiceCollapsed] = createSignal(false);

  createEffect(on(() => props.selectedGroupId, () => {
    setTextCollapsed(false);
    setVoiceCollapsed(false);
  }));

  const selectedGroup = () =>
    props.groups.find((g) => g.group_id === props.selectedGroupId);

  const sortedGroups = () => {
    const all = props.groups;
    const pinIds = props.pinnedGroupIds;
    const pinned = all.filter((g) => pinIds.has(g.group_id));
    const unpinned = all.filter((g) => !pinIds.has(g.group_id));
    return [...pinned, ...unpinned];
  };

  const textChannels = () => props.channels.filter((c) => c.kind === "text");
  const voiceChannels = () => props.channels.filter((c) => c.kind === "voice");

  return (
    <div
      class="w-64 flex-shrink-0 flex flex-col border-r border-[var(--neutral-800)]"
      style={{ background: "var(--neutral-900)" }}
    >
      <div data-tauri-drag-region class="h-7 flex-shrink-0" />

      <Show when={props.identity}>
        {(id) => {
          const [copied, setCopied] = createSignal(false);
          const copyFp = () => {
            navigator.clipboard.writeText(id().fingerprint);
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          };
          return (
            <div class="h-14 flex-shrink-0 flex items-center gap-3 px-3 cursor-pointer" onClick={copyFp}>
              <div
                class="w-8 h-8 rounded-full flex items-center justify-center text-sm flex-shrink-0"
                style={{ background: "var(--purple-700)", color: "var(--purple-200)" }}
              >
                {id().display_name[0]}
              </div>
              <div class="min-w-0">
                <div class="text-sm text-[var(--neutral-200)] truncate leading-tight">
                  {id().display_name}
                </div>
                <div class="text-xs text-[var(--neutral-500)] truncate leading-tight">
                  {copied() ? "copied" : id().fingerprint_short}
                </div>
              </div>
            </div>
          );
        }}
      </Show>

      <Show
        when={selectedGroup()}
        fallback={
          <ScrollArea class="flex-1">
            <div class="px-1.5 pt-1">
              <For each={sortedGroups()}>
                {(group) => {
                  const isPinned = () => props.pinnedGroupIds.has(group.group_id);
                  const color = groupColor(group.group_id);
                  return (
                    <div
                      class="group relative flex items-center gap-2.5 mx-1.5 px-2 py-1.5 rounded text-sm cursor-pointer text-[var(--neutral-400)] hover:bg-[var(--neutral-800)]"
                      onClick={() => withTransition(() => props.onSelectGroup(group.group_id))}
                    >
                      <div
                        class="w-8 h-8 rounded-lg flex items-center justify-center text-xs font-medium flex-shrink-0"
                        style={{
                          background: color.bg,
                          color: color.fg,
                          "view-transition-name": `g-${group.group_id}`,
                        }}
                      >
                        {group.name[0].toUpperCase()}
                      </div>
                      <span class="truncate flex-1">{group.name}</span>
                      <button
                        onClick={(e) => { e.stopPropagation(); props.onTogglePin(group.group_id); }}
                        class="flex-shrink-0 ml-1 p-0.5 rounded cursor-pointer"
                        title={isPinned() ? "unpin" : "pin"}
                      >
                        <Show when={isPinned()} fallback={
                          <Pin size={13} class="transition-opacity text-[var(--neutral-500)] opacity-0 group-hover:opacity-100" />
                        }>
                          <span class="relative flex items-center justify-center w-[13px] h-[13px]">
                            <Pin size={13} class="absolute inset-0 transition-opacity text-[var(--purple-400)] opacity-40 group-hover:opacity-0" />
                            <PinOff size={13} class="absolute inset-0 transition-opacity text-[var(--neutral-400)] opacity-0 group-hover:opacity-100" />
                          </span>
                        </Show>
                      </button>
                    </div>
                  );
                }}
              </For>
            </div>
          </ScrollArea>
        }
      >
        {(group) => (
          <div class="flex-1 flex min-h-0">
            {/* Icon column: back button + group icons */}
            <div
              class="w-12 flex-shrink-0 flex flex-col items-center pt-1.5"
              style={{ "box-shadow": "2px 0 8px rgba(0,0,0,0.35)" }}
            >
              <button
                class="w-8 h-8 flex-shrink-0 rounded-lg flex items-center justify-center text-lg text-[var(--neutral-500)] hover:text-[var(--neutral-200)] hover:bg-[var(--neutral-800)] cursor-pointer"
                onClick={() => withTransition(() => props.onDeselectGroup())}
                title="back to groups"
              >
                {"\u2039"}
              </button>
              <ScrollArea class="flex-1 w-full">
                <div class="flex flex-col items-center gap-1.5 py-1.5">
                  <For each={sortedGroups()}>
                    {(g) => {
                      const color = groupColor(g.group_id);
                      const isActive = () => g.group_id === props.selectedGroupId;
                      return (
                        <button
                          class={cn(
                            "w-8 h-8 flex-shrink-0 rounded-lg flex items-center justify-center text-xs font-medium cursor-pointer",
                            isActive()
                              ? "ring-2 ring-[var(--purple-400)]"
                              : "opacity-60 hover:opacity-100",
                          )}
                          style={{
                            background: color.bg,
                            color: color.fg,
                            "view-transition-name": `g-${g.group_id}`,
                          }}
                          onClick={() => withTransition(() => props.onSelectGroup(g.group_id))}
                          title={g.name}
                        >
                          {g.name[0].toUpperCase()}
                        </button>
                      );
                    }}
                  </For>
                </div>
              </ScrollArea>
            </div>

            {/* Channel panel */}
            <div class="flex-1 flex flex-col min-h-0 min-w-0">
              <button
                class="h-8 flex items-center px-3 mt-1.5 flex-shrink-0 text-sm text-[var(--neutral-300)] hover:text-[var(--neutral-200)] cursor-pointer truncate"
                onClick={() => withTransition(() => props.onDeselectGroup())}
              >
                {group().name}
              </button>

              <ScrollArea class="flex-1">
                <div>
                  <div class="flex items-center justify-between px-3 py-1">
                    <button
                      class="flex items-center gap-1 text-xs uppercase tracking-wider text-[var(--neutral-500)] cursor-pointer hover:text-[var(--neutral-400)]"
                      onClick={() => setTextCollapsed((v) => !v)}
                    >
                      <span class="text-[10px]">{textCollapsed() ? "\u25b8" : "\u25be"}</span>
                      text channels
                    </button>
                    <button
                      class="w-5 h-5 flex items-center justify-center rounded text-sm leading-none text-[var(--neutral-500)] hover:text-[var(--neutral-200)] hover:bg-[var(--neutral-700)] cursor-pointer"
                      onClick={() => props.onCreateChannel("text")}
                    >
                      +
                    </button>
                  </div>
                  <Show when={!textCollapsed()}>
                    <div class="px-1.5">
                      <For each={textChannels()}>
                        {(ch) => (
                          <button
                            class={cn(
                              "w-full flex items-center gap-2 mx-1.5 px-2.5 py-1.5 rounded text-sm cursor-pointer",
                              ch.channel_id === props.selectedChannelId
                                ? "bg-[var(--purple-800)] text-[var(--neutral-100)]"
                                : "text-[var(--neutral-400)] hover:bg-[var(--neutral-800)]",
                            )}
                            onClick={() => props.onSelectChannel(ch.channel_id)}
                          >
                            <span class="text-[var(--neutral-500)]">#</span>
                            {ch.name}
                          </button>
                        )}
                      </For>
                    </div>
                  </Show>
                </div>

                <div class="mt-2">
                  <div class="flex items-center justify-between px-3 py-1">
                    <button
                      class="flex items-center gap-1 text-xs uppercase tracking-wider text-[var(--neutral-500)] cursor-pointer hover:text-[var(--neutral-400)]"
                      onClick={() => setVoiceCollapsed((v) => !v)}
                    >
                      <span class="text-[10px]">{voiceCollapsed() ? "\u25b8" : "\u25be"}</span>
                      voice channels
                    </button>
                    <button
                      class="w-5 h-5 flex items-center justify-center rounded text-sm leading-none text-[var(--neutral-500)] hover:text-[var(--neutral-200)] hover:bg-[var(--neutral-700)] cursor-pointer"
                      onClick={() => props.onCreateChannel("voice")}
                    >
                      +
                    </button>
                  </div>
                  <Show when={!voiceCollapsed()}>
                    <div class="px-1.5">
                      <For each={voiceChannels()}>
                        {(ch) => (
                          <button
                            class={cn(
                              "w-full flex items-center gap-2 mx-1.5 px-2.5 py-1.5 rounded text-sm cursor-pointer",
                              ch.channel_id === props.selectedChannelId
                                ? "bg-[var(--purple-800)] text-[var(--neutral-100)]"
                                : "text-[var(--neutral-400)] hover:bg-[var(--neutral-800)]",
                            )}
                            onClick={() => props.onSelectChannel(ch.channel_id)}
                          >
                            <AudioLines size={14} class="text-[var(--neutral-500)] flex-shrink-0" />
                            {ch.name}
                          </button>
                        )}
                      </For>
                    </div>
                  </Show>
                </div>
              </ScrollArea>
            </div>
          </div>
        )}
      </Show>
    </div>
  );
}
