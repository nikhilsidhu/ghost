import { createSignal, createEffect, on, onCleanup, For, Show } from "solid-js";
import type { JSX } from "solid-js";
import type { Server, Channel } from "../lib/types";
import { hashGradient } from "../lib/gradients";
import { Avatar } from "./ui/avatar";
import { Tooltip } from "./ui/tooltip";
import { ScrollArea } from "./ui/scroll-area";
import { cn } from "../lib/cn";
import { Settings, X, Mailbox } from "lucide-solid";
import { channelPrefix, slideDuration } from "../lib/constants";
import {
  identity, servers, selectedServerId, channels, selectedChannelId,
  selectedServer, selectServer, selectChannel,
  settingsOpen, settingsCategory, setSettingsCategory, toggleSettings,
  joinVoiceChannel, isInVoiceChannel, endCall,
  voiceChannelMembers,
  dmViewActive, dms, serverList, activateDmView, selectDm,
} from "../lib/store";
import { sections } from "../lib/settings-registry";
import "../lib/settings";
import { handleCreateChannel, handleCreateDm } from "../lib/commands";
import { SettingsPanel } from "./SettingsPanel";
import { VoiceDock, VoiceChannelItem, VoiceParticipantList } from "./VoiceControls";
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
  const [serverOrder, setServerOrder] = createSignal<string[]>([]);
  const [channelOrder, setChannelOrder] = createSignal<string[]>([]);
  const [activeServerId, setActiveServerId] = createSignal<string | null>(null);
  const [activeChannelId, setActiveChannelId] = createSignal<string | null>(null);

  createEffect(on(selectedServerId, () => {
    setTextCollapsed(false);
    setVoiceCollapsed(false);
  }));

  createEffect(on(servers, (gs) => {
    const current = serverOrder();
    const ids = gs.map((g) => g.server_id);
    const ordered = current.filter((id) => ids.includes(id));
    const newIds = ids.filter((id) => !ordered.includes(id));
    if (newIds.length > 0 || ordered.length !== current.length) {
      setServerOrder([...ordered, ...newIds]);
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

  const orderedServers = () => {
    const order = serverOrder();
    const list = serverList();
    const map = new Map(list.map((g) => [g.server_id, g]));
    return order.map((id) => map.get(id)).filter((g): g is Server => g !== undefined);
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

  const handleServerClick = (serverId: string) => {
    if (serverId === selectedServerId() && !dmViewActive()) {
      selectServer(null);
    } else {
      selectServer(serverId);
    }
  };

  const onServerDragStart = (e: DragEvent) => setActiveServerId(String(e.draggable.id));
  const onServerDragEnd = (e: DragEvent) => {
    setActiveServerId(null);
    if (e.draggable && e.droppable) {
      const from = String(e.draggable.id);
      const to = String(e.droppable.id);
      if (from !== to) {
        const order = [...serverOrder()];
        const fromIdx = order.indexOf(from);
        const toIdx = order.indexOf(to);
        if (fromIdx >= 0 && toIdx >= 0) {
          order.splice(fromIdx, 1);
          order.splice(toIdx, 0, from);
          setServerOrder(order);
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
        {/* Swap zone: server icons ↔ settings icons */}
        <div class="flex-1 w-full relative overflow-hidden">
          {/* Server icons */}
          <div
            class={cn(
              "absolute inset-0 overflow-hidden",
              settingsOpen() && "pointer-events-none",
            )}
            style={{
              transform: settingsOpen() ? "translateY(-100%)" : "translateY(0)",
              transition: `transform ${slideDuration(orderedServers().length)} var(--ease-out)`,
            }}
          >
            <DragDropProvider
              collisionDetector={closestCenter}
              onDragStart={onServerDragStart}
              onDragEnd={onServerDragEnd}
            >
              <DragDropSensors />
              <ScrollArea class="h-full w-full scrollbar-none">
                <div class="flex flex-col items-center pt-6 pb-3">
                  <DmIcon />
                  <SortableProvider ids={serverOrder()}>
                    <For each={orderedServers()}>
                      {(g) => (
                        <ServerIcon server={g} isActive={g.server_id === selectedServerId() && !dmViewActive()} onClick={handleServerClick} />
                      )}
                    </For>
                  </SortableProvider>
                </div>
              </ScrollArea>
              <DragOverlay>
                {(() => {
                  const id = activeServerId();
                  if (!id) return null;
                  const g = servers().find((x) => x.server_id === id);
                  if (!g) return null;
                  const grad = hashGradient(g.server_id);
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
              "absolute inset-0 overflow-hidden",
              !settingsOpen() && "pointer-events-none",
            )}
            style={{
              transform: settingsOpen() ? "translateY(0)" : "translateY(-100%)",
              transition: `transform ${slideDuration(sections().length)} var(--ease-out)`,
            }}
          >
            <div class="flex flex-col items-center pt-6 pb-3">
              <For each={sections()}>
                {(section) => {
                  const active = () => settingsCategory() === section.id;
                  return (
                    <div class="relative flex items-center justify-center w-full group/si">
                      {/* Left indicator — tall bar when active, short pill on hover */}
                      <div
                        class={cn(
                          "absolute left-0 w-[3px] rounded-r-full transition-all duration-200",
                          active()
                            ? "top-1 bottom-1 opacity-100"
                            : "top-[38%] bottom-[38%] opacity-0 group-hover/si:opacity-100",
                        )}
                        style={{ background: "var(--neutral-400)" }}
                      />
                      <Tooltip label={section.label}>
                        <button
                          class={cn(
                            "w-[var(--size-lg)] h-[var(--size-lg)] flex items-center justify-center cursor-pointer transition-all duration-200",
                            active()
                              ? "opacity-100 text-[var(--neutral-100)]"
                              : "opacity-50 hover:opacity-90 text-[var(--neutral-400)]",
                          )}
                          onClick={() => setSettingsCategory(section.id)}
                        >
                          <section.icon size={20} />
                        </button>
                      </Tooltip>
                    </div>
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

        {/* Bottom dock — each item uses the same --size-lg cell as server icons */}
        <div class="flex-shrink-0 flex flex-col items-center pb-3 pt-2 group/dock">

          <VoiceDock />

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
                  transition: "transform var(--duration-slow) var(--ease-out)",
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
        class="relative flex-shrink-0 overflow-hidden"
        style={{
          width: settingsOpen() ? "380px" : (selectedServer() || dmViewActive()) ? "208px" : "0px",
          transition: `width ${slideDuration(settingsOpen() ? sections().length : orderedServers().length)} var(--ease-out)`,
        }}
      >
        {/* Settings panel — slides down from top, synced with settings icons */}
        <div
          class={cn(
            "absolute inset-0",
            !settingsOpen() && "pointer-events-none",
          )}
          style={{
            transform: settingsOpen() ? "translateY(0)" : "translateY(-100%)",
            transition: `transform ${slideDuration(sections().length)} var(--ease-out)`,
          }}
        >
          <SettingsPanel onClose={toggleSettings} />
        </div>

        {/* Channel panel — slides up when settings opens, synced with server icons */}
        <div
          class={cn(
            "absolute inset-0",
            (settingsOpen() || (!selectedServer() && !dmViewActive())) && "pointer-events-none",
          )}
          style={{
            transform: settingsOpen() ? "translateY(-100%)" : "translateY(0)",
            transition: `transform ${slideDuration(orderedServers().length)} var(--ease-out)`,
          }}
        >
          <Show when={dmViewActive()}>
            <DmPanel />
          </Show>
          <Show when={!dmViewActive() && selectedServer()}>
            {(server) => (
              <div
                class="w-full h-full flex flex-col min-h-0"
                style={{ background: "var(--neutral-950)" }}
              >
                <div class="h-7 flex-shrink-0" />

                <div class="h-[var(--size-lg)] flex items-center px-4 flex-shrink-0 -mt-1">
                  <span class="text-base font-semibold text-[var(--neutral-100)] truncate lowercase">
                    {server().name}
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
                              {(ch) => {
                                const active = () => isInVoiceChannel(ch.channel_id);
                                return (
                                  <>
                                    <VoiceChannelItem
                                      channel={ch}
                                      active={active()}
                                      onToggle={() => {
                                        if (active()) endCall();
                                        else {
                                          const sid = selectedServerId();
                                          if (sid) joinVoiceChannel(sid, ch.channel_id);
                                        }
                                      }}
                                    />
                                    <Show when={active() || voiceChannelMembers().has(ch.channel_id)}>
                                      <VoiceParticipantList channelId={ch.channel_id} />
                                    </Show>
                                  </>
                                );
                              }}
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

// Rounded server icon with active indicator bar
function ServerIcon(props: { server: Server; isActive: boolean; onClick: (id: string) => void }) {
  const sortable = createSortable(props.server.server_id);
  const grad = hashGradient(props.server.server_id);

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
      <Tooltip label={props.server.name}>
        <button
          class="w-[var(--size-lg)] h-[var(--size-lg)] flex items-center justify-center cursor-pointer"
          onClick={() => props.onClick(props.server.server_id)}
        >
          <Avatar
            hashKey={props.server.server_id}
            label={props.server.name}
            square
            active={props.isActive}
            class={cn(
              "relative w-[var(--size-md)] h-[var(--size-md)] text-sm transition-all duration-200",
              props.isActive || props.server.has_unread
                ? "opacity-100 scale-100"
                : "opacity-60 scale-95 hover:opacity-90 hover:scale-100",
            )}
          >
            {props.server.name[0]?.toLowerCase()}
            {/* Unread dot */}
            <Show when={!props.isActive && props.server.has_unread}>
              <div
                class="absolute -top-0.5 -right-0.5 w-[10px] h-[10px] rounded-full border-2"
                style={{ background: "var(--neutral-100)", "border-color": "var(--neutral-950)" }}
              />
            </Show>
            {/* Breathing glow on active server */}
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

function DmIcon() {
  const active = () => dmViewActive();
  const hasUnread = () => dms().some((g) => g.has_unread);

  return (
    <div class="relative flex items-center justify-center w-full group/dm">
      <div
        class={cn(
          "absolute left-0 w-[3px] rounded-r-full transition-all duration-200",
          active()
            ? "top-1 bottom-1 opacity-100"
            : "top-[38%] bottom-[38%] opacity-0 group-hover/dm:opacity-100",
        )}
        style={{ background: "var(--neutral-400)" }}
      />
      <Tooltip label="direct messages">
        <button
          class={cn(
            "w-[var(--size-lg)] h-[var(--size-lg)] flex items-center justify-center cursor-pointer transition-all duration-200",
            active()
              ? "opacity-100 text-[var(--neutral-100)]"
              : "opacity-50 hover:opacity-90 text-[var(--neutral-400)]",
          )}
          onClick={() => dmViewActive() ? selectServer(null) : activateDmView()}
        >
          <div class="relative">
            <Mailbox size={26} />
            <Show when={!active() && hasUnread()}>
              <div
                class="absolute -top-0.5 -right-0.5 w-[10px] h-[10px] rounded-full border-2"
                style={{ background: "var(--neutral-100)", "border-color": "var(--neutral-950)" }}
              />
            </Show>
          </div>
        </button>
      </Tooltip>
    </div>
  );
}

function DmPanel() {
  const dmList = dms;

  return (
    <div
      class="w-full h-full flex flex-col min-h-0"
      style={{ background: "var(--neutral-950)" }}
    >
      <div class="h-7 flex-shrink-0" />

      <div class="h-[var(--size-lg)] flex items-center justify-between px-4 flex-shrink-0 -mt-1">
        <span class="text-base font-semibold text-[var(--neutral-100)] lowercase">
          direct messages
        </span>
        <button
          class="w-6 h-6 flex items-center justify-center rounded-md text-sm leading-none text-[var(--neutral-500)] hover:text-[var(--neutral-200)] cursor-pointer hover:bg-[var(--hover)]"
          onClick={handleCreateDm}
        >
          +
        </button>
      </div>

      <ScrollArea class="flex-1">
        <div class="px-2 pt-1">
          <Show
            when={dmList().length > 0}
            fallback={
              <div class="px-2 py-8 text-center text-sm text-[var(--neutral-500)]">
                no conversations yet
              </div>
            }
          >
            <For each={dmList()}>
              {(dm) => (
                <DmItem
                  dm={dm}
                  isSelected={dm.server_id === selectedServerId()}
                  onSelect={selectDm}
                />
              )}
            </For>
          </Show>
        </div>
      </ScrollArea>
    </div>
  );
}

function DmItem(props: { dm: Server; isSelected: boolean; onSelect: (id: string) => void }) {
  return (
    <button
      class={cn(
        "w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-sm text-left cursor-pointer",
        props.isSelected
          ? "bg-[var(--active)] text-[var(--neutral-100)]"
          : props.dm.has_unread
            ? "text-[var(--neutral-100)] font-medium hover:bg-[var(--hover)]"
            : "text-[var(--neutral-400)] hover:bg-[var(--hover)]",
      )}
      onClick={() => props.onSelect(props.dm.server_id)}
    >
      <Avatar
        hashKey={props.dm.server_id}
        label={props.dm.name}
        class="w-6 h-6 text-[10px] flex-shrink-0"
      />
      <span class="flex-1 truncate">{props.dm.name}</span>
      <Show when={props.dm.has_unread && !props.isSelected}>
        <div
          class="w-2 h-2 rounded-full flex-shrink-0"
          style={{ background: "var(--neutral-100)" }}
        />
      </Show>
    </button>
  );
}

