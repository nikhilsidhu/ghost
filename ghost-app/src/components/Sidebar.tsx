import { createSignal, createEffect, on, onCleanup, For, Show } from "solid-js";
import type { JSX } from "solid-js";
import type { Group, Channel } from "../lib/types";
import { hashGradient } from "../lib/gradients";
import { Avatar } from "./ui/avatar";
import { Tooltip } from "./ui/tooltip";
import { ScrollArea } from "./ui/scroll-area";
import { cn } from "../lib/cn";
import { AudioLines, Settings, X, Mic, MicOff, Headphones, HeadphoneOff, PhoneOff } from "lucide-solid";
import { channelPrefix } from "../lib/constants";
import {
  identity, groups, selectedGroupId, channels, selectedChannelId,
  selectedGroup, selectGroup, selectChannel,
  settingsOpen, settingsCategory, setSettingsCategory, toggleSettings,
  isInCall, isMuted, isDeafened, toggleMute, toggleDeafen, endCall,
} from "../lib/store";
import { sections } from "../lib/settings-registry";
import "../lib/settings";
import { handleCreateChannel } from "../lib/commands";
import { SettingsPanel } from "./SettingsPanel";
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
  const onEscape = (e: KeyboardEvent) => { if (e.key === "Escape" && settingsOpen()) toggleSettings(); };
  window.addEventListener("keydown", onEscape);
  onCleanup(() => window.removeEventListener("keydown", onEscape));

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
        {/* Swap zone: group icons ↔ settings icons */}
        <div class="flex-1 w-full relative overflow-hidden">
          {/* Group icons */}
          <div
            class={cn(
              "absolute inset-0",
              settingsOpen() && "pointer-events-none",
            )}
            style={{
              transform: settingsOpen() ? "translateY(-100%)" : "translateY(0)",
              transition: `transform ${150 + orderedGroups().length * 25}ms var(--ease-out)`,
            }}
          >
            <DragDropProvider
              collisionDetector={closestCenter}
              onDragStart={onGroupDragStart}
              onDragEnd={onGroupDragEnd}
            >
              <DragDropSensors />
              <ScrollArea class="h-full w-full scrollbar-none">
                <SortableProvider ids={groupOrder()}>
                  <div class="flex flex-col items-center pt-6 pb-3">
                    <For each={orderedGroups()}>
                      {(g) => (
                        <GroupIcon group={g} isActive={g.group_id === selectedGroupId()} onClick={handleGroupClick} />
                      )}
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
                        {g.name[0]?.toLowerCase()}
                      </div>
                    </div>
                  );
                })()}
              </DragOverlay>
            </DragDropProvider>
          </div>

          {/* Settings icons */}
          <div
            class={cn(
              "absolute inset-0",
              !settingsOpen() && "pointer-events-none",
            )}
            style={{
              transform: settingsOpen() ? "translateY(0)" : "translateY(-100%)",
              transition: `transform ${150 + sections().length * 25}ms var(--ease-out)`,
            }}
          >
            <div class="flex flex-col items-center pt-6 pb-3">
              <For each={sections()}>
                {(section) => {
                  const active = () => settingsCategory() === section.id;
                  return (
                    <Tooltip label={section.label}>
                      <button
                        class="w-[var(--size-lg)] h-[var(--size-lg)] flex items-center justify-center cursor-pointer"
                        onClick={() => setSettingsCategory(section.id)}
                      >
                        <div
                          class={cn(
                            "w-[var(--size-md)] h-[var(--size-md)] rounded-lg flex items-center justify-center transition-all duration-200",
                            active()
                              ? "bg-[var(--neutral-800)] text-[var(--neutral-100)]"
                              : "text-[var(--neutral-500)] hover:text-[var(--neutral-300)] hover:bg-[var(--neutral-800)]/50",
                          )}
                        >
                          <section.icon size={20} />
                        </div>
                      </button>
                    </Tooltip>
                  );
                }}
              </For>
            </div>
          </div>

          {/* Top fade overlay — masks icons sliding under traffic lights */}
          <div
            class="absolute top-0 left-0 right-0 h-8 pointer-events-none z-10"
            style={{ background: "linear-gradient(to top, transparent, var(--neutral-950))" }}
          />

          {/* Bottom fade overlay */}
          <div
            class="absolute bottom-0 left-0 right-0 h-8 pointer-events-none"
            style={{ background: "linear-gradient(to bottom, transparent, var(--neutral-950))" }}
          />
        </div>

        {/* Bottom dock — each item uses the same --size-lg cell as group icons */}
        <div class="flex-shrink-0 flex flex-col items-center pb-3 pt-2 group/dock">

          {/* Mute — pinned when active, hover-revealed otherwise */}
          <div class={cn(
            "overflow-hidden w-[var(--size-lg)] flex items-center justify-center",
            isMuted()
              ? "max-h-[var(--size-lg)]"
              : "max-h-0 group-hover/dock:max-h-[var(--size-lg)]",
          )}
          style={{ transition: "max-height 200ms var(--ease-out)" }}
          >
            <Tooltip label={isMuted() ? "unmute" : "mute"}>
              <button
                class={cn(
                  "w-[var(--size-lg)] h-[var(--size-md)] rounded-lg flex items-center justify-center cursor-pointer transition-all duration-150",
                  isMuted() ? "opacity-100 hover:brightness-125" : "opacity-50 hover:opacity-100",
                )}
                onClick={toggleMute}
              >
                {isMuted()
                  ? <MicOff size={18} class="text-[var(--amber-400)]" />
                  : <Mic size={18} class="text-[var(--neutral-300)]" />}
              </button>
            </Tooltip>
          </div>

          {/* Deafen — pinned when active, hover-revealed otherwise */}
          <div class={cn(
            "overflow-hidden w-[var(--size-lg)] flex items-center justify-center",
            isDeafened()
              ? "max-h-[var(--size-lg)]"
              : "max-h-0 group-hover/dock:max-h-[var(--size-lg)]",
          )}
          style={{ transition: "max-height 200ms var(--ease-out)" }}
          >
            <Tooltip label={isDeafened() ? "undeafen" : "deafen"}>
              <button
                class={cn(
                  "w-[var(--size-lg)] h-[var(--size-md)] rounded-lg flex items-center justify-center cursor-pointer transition-all duration-150",
                  isDeafened() ? "opacity-100 hover:brightness-125" : "opacity-50 hover:opacity-100",
                )}
                onClick={toggleDeafen}
              >
                {isDeafened()
                  ? <HeadphoneOff size={18} class="text-[var(--cyan-400)]" />
                  : <Headphones size={18} class="text-[var(--neutral-300)]" />}
              </button>
            </Tooltip>
          </div>

          {/* End call — persistent when in call */}
          <Show when={isInCall()}>
            <Tooltip label="end call">
              <button
                class="w-[var(--size-lg)] h-[var(--size-lg)] flex items-center justify-center cursor-pointer opacity-80 hover:opacity-100 transition-all duration-150"
                onClick={endCall}
              >
                <PhoneOff size={18} class="text-[var(--red-400)]" />
              </button>
            </Tooltip>
          </Show>

          {/* User avatar */}
          <Show when={identity()}>
            {(id) => {
              const [copied, setCopied] = createSignal(false);
              const copyFp = () => {
                navigator.clipboard.writeText(id().fingerprint);
                setCopied(true);
                setTimeout(() => setCopied(false), 1200);
              };
              return (
                <Tooltip label={copied() ? "copied!" : id().display_name}>
                  <button
                    class="w-[var(--size-lg)] h-[var(--size-lg)] flex items-center justify-center cursor-pointer hover:opacity-80"
                    onClick={copyFp}
                  >
                    <Avatar
                      hashKey={id().fingerprint}
                      label={id().display_name}
                      class="w-[var(--size-md)] h-[var(--size-md)] text-sm"
                    />
                  </button>
                </Tooltip>
              );
            }}
          </Show>

          {/* Settings */}
          <Tooltip label="settings">
            <button
              class={cn(
                "w-[var(--size-lg)] h-[var(--size-md)] flex items-center justify-center cursor-pointer transition-all duration-150 group/settings",
                settingsOpen() ? "opacity-100" : "opacity-50 hover:opacity-100",
              )}
              onClick={toggleSettings}
            >
              <div
                class="relative w-5 h-5"
                style={{
                  transform: settingsOpen() ? "rotate(180deg)" : "rotate(0deg)",
                  transition: "transform 300ms var(--ease-out)",
                }}
              >
                <Settings size={20} class={cn(
                  "absolute inset-0 text-[var(--neutral-300)] transition-opacity duration-200",
                  settingsOpen() ? "opacity-0" : "opacity-100",
                )} />
                <X size={20} class={cn(
                  "absolute inset-0 text-[var(--neutral-300)] transition-opacity duration-200",
                  settingsOpen() ? "opacity-100" : "opacity-0",
                )} />
              </div>
            </button>
          </Tooltip>
        </div>
      </div>

      <div class="divider-v" style={{ "will-change": "transform" }} />

      {/* Panel swap zone */}
      <div
        class="relative flex-shrink-0"
        style={{
          width: settingsOpen() ? "320px" : selectedGroup() ? "208px" : "0px",
          transition: "width 300ms var(--ease-out)",
        }}
      >
        {/* Settings panel — slides down after channel exits up */}
        <div
          class={cn(
            "absolute inset-0",
            settingsOpen() ? "opacity-100" : "opacity-0 pointer-events-none",
          )}
          style={{
            transform: settingsOpen() ? "translateY(0)" : "translateY(-2rem)",
            transition: "opacity 300ms var(--ease-out), transform 300ms var(--ease-out)",
          }}
        >
          <SettingsPanel onClose={toggleSettings} />
        </div>

        {/* Channel panel — slides up when settings opens */}
        <div
          class={cn(
            "absolute inset-0",
            !settingsOpen() && selectedGroup() ? "opacity-100" : "opacity-0 pointer-events-none",
          )}
          style={{
            transform: settingsOpen() ? "translateY(-2rem)" : "translateY(0)",
            transition: "opacity 300ms var(--ease-out), transform 300ms var(--ease-out)",
          }}
        >
          <Show when={selectedGroup()}>
            {(group) => (
              <div
                class="w-full h-full flex flex-col min-h-0"
                style={{ background: "var(--neutral-950)" }}
              >
                <div class="h-7 flex-shrink-0" />

                <div class="h-[var(--size-lg)] flex items-center px-4 flex-shrink-0 -mt-1">
                  <span class="text-base font-semibold text-[var(--neutral-100)] truncate lowercase">
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
                    <div class="pt-2">
                      <div class="flex items-center justify-between px-3 py-1">
                        <button
                          class="flex items-center gap-1 text-sm font-medium text-[var(--neutral-500)] cursor-pointer hover:text-[var(--neutral-400)]"
                          onClick={() => setTextCollapsed((v) => !v)}
                        >
                          <span class="text-[10px]">{textCollapsed() ? "\u25b8" : "\u25be"}</span>
                          text channels
                        </button>
                        <button
                          class="w-6 h-6 flex items-center justify-center rounded-md text-sm leading-none text-[var(--neutral-500)] hover:text-[var(--neutral-200)] cursor-pointer hover:bg-[var(--hover)]"
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
                          class="flex items-center gap-1 text-sm font-medium text-[var(--neutral-500)] cursor-pointer hover:text-[var(--neutral-400)]"
                          onClick={() => setVoiceCollapsed((v) => !v)}
                        >
                          <span class="text-[10px]">{voiceCollapsed() ? "\u25b8" : "\u25be"}</span>
                          voice channels
                        </button>
                        <button
                          class="w-6 h-6 flex items-center justify-center rounded-md text-sm leading-none text-[var(--neutral-500)] hover:text-[var(--neutral-200)] cursor-pointer hover:bg-[var(--hover)]"
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
      </div>
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
                : "opacity-60 scale-95 hover:opacity-90 hover:scale-100",
            )}
          >
            {props.group.name[0]?.toLowerCase()}
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
        "w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-sm text-left cursor-pointer",
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
