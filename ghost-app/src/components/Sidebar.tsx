import { createSignal, createEffect, on, For, Show } from "solid-js";
import type { JSX } from "solid-js";
import type { Group, Channel } from "../lib/types";
import { hashGradient } from "../lib/gradients";
import { Avatar } from "./ui/avatar";
import { Tooltip } from "./ui/tooltip";
import { ScrollArea } from "./ui/scroll-area";
import { cn } from "../lib/cn";
import { AudioLines, Settings } from "lucide-solid";
import { channelPrefix } from "../lib/constants";
import {
  identity, groups, selectedGroupId, channels, selectedChannelId,
  selectedGroup, selectGroup, selectChannel,
} from "../lib/store";
import { handleCreateChannel } from "../lib/commands";
import {
  DragDropProvider,
  DragDropSensors,
  DragOverlay,
  SortableProvider,
  createSortable,
  closestCenter,
  transformStyle,
} from "@thisbeyond/solid-dnd";
import type { DragEvent } from "@thisbeyond/solid-dnd";

export function Sidebar() {
  const [textCollapsed, setTextCollapsed] = createSignal(false);
  const [voiceCollapsed, setVoiceCollapsed] = createSignal(false);
  const [groupOrder, setGroupOrder] = createSignal<string[]>([]);
  const [channelOrder, setChannelOrder] = createSignal<string[]>([]);
  const [activeGroupId, setActiveGroupId] = createSignal<string | null>(null);
  const [activeChannelId, setActiveChannelId] = createSignal<string | null>(null);

  createEffect(on(selectedGroupId, () => {
    setTextCollapsed(false);
    setVoiceCollapsed(false);
  }));

  createEffect(on(groups, (gs) => {
    const current = groupOrder();
    const ids = gs.map((g) => g.group_id);
    const ordered = current.filter((id) => ids.includes(id));
    const newIds = ids.filter((id) => !ordered.includes(id));
    if (newIds.length > 0 || ordered.length !== current.length) {
      setGroupOrder([...ordered, ...newIds]);
    }
  }));

  createEffect(on(channels, (chs) => {
    const current = channelOrder();
    const ids = chs.map((c) => c.channel_id);
    const ordered = current.filter((id) => ids.includes(id));
    const newIds = ids.filter((id) => !ordered.includes(id));
    if (newIds.length > 0 || ordered.length !== current.length) {
      setChannelOrder([...ordered, ...newIds]);
    }
  }));

  const orderedGroups = () => {
    const order = groupOrder();
    const map = new Map(groups().map((g) => [g.group_id, g]));
    return order.map((id) => map.get(id)!).filter(Boolean);
  };

  const textChannels = () => {
    const order = channelOrder();
    const text = channels().filter((c) => c.kind === "text");
    const map = new Map(text.map((c) => [c.channel_id, c]));
    return order.map((id) => map.get(id)).filter((c): c is Channel => c !== undefined && c.kind === "text");
  };

  const voiceChannels = () => {
    const order = channelOrder();
    const voice = channels().filter((c) => c.kind === "voice");
    const map = new Map(voice.map((c) => [c.channel_id, c]));
    return order.map((id) => map.get(id)).filter((c): c is Channel => c !== undefined && c.kind === "voice");
  };

  const handleGroupClick = (groupId: string) => {
    selectGroup(groupId === selectedGroupId() ? null : groupId);
  };

  const onGroupDragStart = (e: DragEvent) => setActiveGroupId(String(e.draggable.id));
  const onGroupDragEnd = (e: DragEvent) => {
    setActiveGroupId(null);
    if (e.draggable && e.droppable) {
      const from = String(e.draggable.id);
      const to = String(e.droppable.id);
      if (from !== to) {
        const order = [...groupOrder()];
        const fromIdx = order.indexOf(from);
        const toIdx = order.indexOf(to);
        if (fromIdx >= 0 && toIdx >= 0) {
          order.splice(fromIdx, 1);
          order.splice(toIdx, 0, from);
          setGroupOrder(order);
        }
      }
    }
  };

  const onChannelDragStart = (e: DragEvent) => setActiveChannelId(String(e.draggable.id));
  const onChannelDragEnd = (e: DragEvent) => {
    setActiveChannelId(null);
    if (e.draggable && e.droppable) {
      const from = String(e.draggable.id);
      const to = String(e.droppable.id);
      if (from !== to) {
        const order = [...channelOrder()];
        const fromIdx = order.indexOf(from);
        const toIdx = order.indexOf(to);
        if (fromIdx >= 0 && toIdx >= 0) {
          order.splice(fromIdx, 1);
          order.splice(toIdx, 0, from);
          setChannelOrder(order);
        }
      }
    }
  };

  return (
    <div class="flex-shrink-0 flex h-full">
      {/* Activity bar */}
      <div
        class="w-[var(--size-lg)] flex-shrink-0 flex flex-col"
        style={{ background: "var(--neutral-950)" }}
      >
        <div class="h-7 flex-shrink-0" />

        {/* Scrollable group icons */}
        <DragDropProvider
          collisionDetector={closestCenter}
          onDragStart={onGroupDragStart}
          onDragEnd={onGroupDragEnd}
        >
          <DragDropSensors />
          <ScrollArea class="flex-1 w-full">
            <SortableProvider ids={groupOrder()}>
              <div class="flex flex-col items-center">
                <For each={orderedGroups()}>
                  {(g) => <GroupIcon group={g} isActive={g.group_id === selectedGroupId()} onClick={handleGroupClick} />}
                </For>
              </div>
            </SortableProvider>
          </ScrollArea>
          <DragOverlay>
            {(() => {
              const id = activeGroupId();
              if (!id) return null;
              const g = groups().find((x) => x.group_id === id);
              if (!g) return null;
              const grad = hashGradient(g.group_id);
              return (
                <div class="w-[var(--size-lg)] h-[var(--size-lg)] flex items-center justify-center">
                  <div
                    class="w-[var(--size-md)] h-[var(--size-md)] rounded-[14%] flex items-center justify-center text-sm font-semibold opacity-80"
                    style={{
                      background: `linear-gradient(${grad.angle}deg, ${grad.from}, ${grad.to})`,
                      color: "var(--neutral-100)",
                    }}
                  >
                    {g.name[0]?.toUpperCase()}
                  </div>
                </div>
              );
            })()}
          </DragOverlay>
        </DragDropProvider>

        {/* Bottom dock */}
        <div class="flex-shrink-0 flex flex-col items-center pb-2">
          <div class="divider-h w-8 mb-2" />

          <Tooltip label="settings">
            <button
              class="w-[var(--size-md)] h-[var(--size-md)] rounded-lg flex items-center justify-center cursor-pointer opacity-50 hover:opacity-100 mb-1.5"
            >
              <Settings size={16} class="text-[var(--neutral-300)]" />
            </button>
          </Tooltip>

          <Show when={identity()}>
            {(id) => {
              const [copied, setCopied] = createSignal(false);
              const copyFp = () => {
                navigator.clipboard.writeText(id().fingerprint);
                setCopied(true);
                setTimeout(() => setCopied(false), 1200);
              };
              return (
                <Tooltip label={copied() ? "copied!" : id().fingerprint_short}>
                  <button
                    class="flex flex-col items-center gap-0.5 cursor-pointer hover:opacity-80"
                    onClick={copyFp}
                  >
                    <Avatar
                      hashKey={id().fingerprint}
                      label={id().display_name}
                      class="w-[var(--size-md)] h-[var(--size-md)] text-sm"
                    />
                    <span class="text-[9px] text-[var(--neutral-500)] truncate max-w-[40px] leading-tight">
                      {copied() ? "copied" : id().display_name}
                    </span>
                  </button>
                </Tooltip>
              );
            }}
          </Show>
        </div>
      </div>

      <div class="divider-v" />

      {/* Channel panel */}
      <Show when={selectedGroup()}>
        {(group) => (
          <div
            class="w-52 flex-shrink-0 flex flex-col min-h-0"
            style={{ background: "var(--neutral-950)" }}
          >
            <div class="h-7 flex-shrink-0" />

            <div class="h-[var(--size-lg)] flex items-center px-3 flex-shrink-0">
              <span class="text-base font-semibold text-[var(--neutral-100)] truncate">
                {group().name}
              </span>
            </div>

            <DragDropProvider
              collisionDetector={closestCenter}
              onDragStart={onChannelDragStart}
              onDragEnd={onChannelDragEnd}
            >
              <DragDropSensors />
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
                      class="w-[var(--size-sm)] h-[var(--size-sm)] flex items-center justify-center rounded-md text-sm leading-none text-[var(--neutral-500)] hover:text-[var(--neutral-200)] cursor-pointer hover:bg-[var(--hover)]"
                      onClick={() => handleCreateChannel("text")}
                    >
                      +
                    </button>
                  </div>
                  <Show when={!textCollapsed()}>
                    <div class="px-2">
                      <SortableProvider ids={textChannels().map((c) => c.channel_id)}>
                        <For each={textChannels()}>
                          {(ch) => (
                            <ChannelItem
                              channel={ch}
                              isSelected={ch.channel_id === selectedChannelId()}
                              onSelect={selectChannel}
                              icon={<span class="text-[var(--neutral-500)]">#</span>}
                            />
                          )}
                        </For>
                      </SortableProvider>
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
                      class="w-[var(--size-sm)] h-[var(--size-sm)] flex items-center justify-center rounded-md text-sm leading-none text-[var(--neutral-500)] hover:text-[var(--neutral-200)] cursor-pointer hover:bg-[var(--hover)]"
                      onClick={() => handleCreateChannel("voice")}
                    >
                      +
                    </button>
                  </div>
                  <Show when={!voiceCollapsed()}>
                    <div class="px-2">
                      <SortableProvider ids={voiceChannels().map((c) => c.channel_id)}>
                        <For each={voiceChannels()}>
                          {(ch) => (
                            <ChannelItem
                              channel={ch}
                              isSelected={ch.channel_id === selectedChannelId()}
                              onSelect={selectChannel}
                              icon={<AudioLines size={14} class="text-[var(--neutral-500)] flex-shrink-0" />}
                            />
                          )}
                        </For>
                      </SortableProvider>
                    </div>
                  </Show>
                </div>
              </ScrollArea>
              <DragOverlay>
                {(() => {
                  const id = activeChannelId();
                  if (!id) return null;
                  const ch = channels().find((c) => c.channel_id === id);
                  if (!ch) return null;
                  return (
                    <div class="flex items-center gap-2 px-2 py-1.5 rounded-md text-sm text-[var(--neutral-200)] bg-[var(--neutral-800)] opacity-80">
                      {channelPrefix(ch.kind)} {ch.name}
                    </div>
                  );
                })()}
              </DragOverlay>
            </DragDropProvider>
          </div>
        )}
      </Show>
    </div>
  );
}

// Rounded group icon with active indicator bar
function GroupIcon(props: { group: Group; isActive: boolean; onClick: (id: string) => void }) {
  const sortable = createSortable(props.group.group_id);
  const grad = hashGradient(props.group.group_id);

  return (
    <div
      ref={sortable.ref}
      class="relative flex items-center justify-center w-full group/gi"
      style={transformStyle(sortable.transform)}
      {...sortable.dragActivators}
    >
      {/* Left indicator — tall bar when active, short pill on hover */}
      <div
        class={cn(
          "absolute left-0 w-[3px] rounded-r-full transition-all duration-200",
          props.isActive
            ? "top-1 bottom-1 opacity-100"
            : "top-[38%] bottom-[38%] opacity-0 group-hover/gi:opacity-100",
        )}
        style={{ background: "var(--neutral-400)" }}
      />
      <Tooltip label={props.group.name}>
        <button
          class="w-[var(--size-lg)] h-[var(--size-lg)] flex items-center justify-center cursor-pointer"
          onClick={() => props.onClick(props.group.group_id)}
        >
          <Avatar
            hashKey={props.group.group_id}
            label={props.group.name}
            square
            active={props.isActive}
            class={cn(
              "relative w-[var(--size-md)] h-[var(--size-md)] text-sm transition-all duration-200",
              props.isActive || props.group.has_unread
                ? "opacity-100 scale-100"
                : "opacity-60 scale-95 group-hover/gi:opacity-90 group-hover/gi:scale-100",
            )}
          >
            {props.group.name[0]?.toUpperCase()}
            {/* Unread dot */}
            <Show when={!props.isActive && props.group.has_unread}>
              <div
                class="absolute -top-0.5 -right-0.5 w-[10px] h-[10px] rounded-full border-2"
                style={{ background: "var(--neutral-100)", "border-color": "var(--neutral-950)" }}
              />
            </Show>
            {/* Breathing glow on active group */}
            <Show when={props.isActive}>
              <div
                class="absolute inset-0 rounded-[14%] pointer-events-none"
                style={{
                  "box-shadow": `0 0 6px 1.5px ${grad.glow}35, 0 0 12px 2px ${grad.glow}12`,
                  animation: "breathe 3.5s ease-in-out infinite",
                }}
              />
            </Show>
          </Avatar>
        </button>
      </Tooltip>
    </div>
  );
}

// Sortable channel item for drag-reorder
function ChannelItem(props: {
  channel: Channel;
  isSelected: boolean;
  onSelect: (id: string) => void;
  icon: JSX.Element;
}) {
  const sortable = createSortable(props.channel.channel_id);

  return (
    <button
      ref={sortable.ref}
      class={cn(
        "w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-sm cursor-pointer",
        props.isSelected
          ? "bg-[var(--active)] text-[var(--neutral-100)]"
          : props.channel.unread_count > 0
            ? "text-[var(--neutral-100)] font-medium hover:bg-[var(--hover)]"
            : "text-[var(--neutral-400)] hover:bg-[var(--hover)]",
      )}
      style={transformStyle(sortable.transform)}
      {...sortable.dragActivators}
      onClick={() => props.onSelect(props.channel.channel_id)}
    >
      {props.icon}
      <span class="flex-1 truncate">{props.channel.name}</span>
      {/* Fixed-width slot so badge doesn't shift channel name */}
      <span class="flex-shrink-0 w-5 flex items-center justify-end">
        <Show when={props.channel.unread_count > 0 && !props.isSelected}>
          <span class="min-w-[18px] h-[18px] px-1 rounded-full text-[10px] font-semibold flex items-center justify-center bg-[var(--purple-500)] text-[var(--neutral-100)]">
            {props.channel.unread_count > 99 ? "99+" : props.channel.unread_count}
          </span>
        </Show>
      </span>
    </button>
  );
}
