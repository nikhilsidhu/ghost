import { createSignal, createEffect, on, onMount, onCleanup, Show, For } from "solid-js";
import { listen } from "@tauri-apps/api/event";
import type { Identity, Group, Channel, Member, Message } from "../lib/types";
import {
  getIdentity, listGroups, listChannels, listMembers,
  listPinnedGroups, markChannelRead,
  createGroup, createChannel as apiCreateChannel,
  renameChannel as apiRenameChannel, deleteChannel as apiDeleteChannel,
  createInvite, joinByInvite, setDisplayName, seedTestData,
} from "../lib/api";
import { Sidebar } from "./Sidebar";
import { GroupView } from "./GroupView";
import { MemberPanel } from "./MemberPanel";
import { CommandPalette } from "./CommandPalette";
import { registerCommand, registerProvider, triggerCommand, type CommandDef, type SearchProvider } from "../lib/registry";
import { channelPrefix } from "../lib/constants";
import { InviteDialog } from "./InviteDialog";
import { ShortcutOverlay } from "./ShortcutOverlay";
import { KeyBadge } from "./KeyBadge";
import { shortcuts as shortcutDefs } from "../lib/shortcuts";

export function Layout() {
  const [identity, setIdentity] = createSignal<Identity | null>(null);
  const [groups, setGroups] = createSignal<Group[]>([]);
  const [selectedGroupId, setSelectedGroupId] = createSignal<string | null>(null);
  const [channels, setChannels] = createSignal<Channel[]>([]);
  const [members, setMembers] = createSignal<Member[]>([]);
  const [pinnedGroupIds, setPinnedGroupIds] = createSignal<Set<string>>(new Set());
  const [selectedChannelId, setSelectedChannelId] = createSignal<string | null>(null);
  const [inviteLink, setInviteLink] = createSignal<string | null>(null);
  const [showInfo, setShowInfo] = createSignal(false);
  const [desiredChannelKind, setDesiredChannelKind] = createSignal<string>("text");
  const [allChannels, setAllChannels] = createSignal<Channel[]>([]);

  // --- Refresh helpers ---

  const refreshGroups = async () => {
    const gs = await listGroups();
    setGroups(gs);
  };

  const refreshAllChannels = async () => {
    const gs = groups();
    if (gs.length === 0) { setAllChannels([]); return; }
    const results = await Promise.all(gs.map((g) => listChannels(g.group_id)));
    setAllChannels(results.flat());
  };

  const refreshChannels = async () => {
    const gid = selectedGroupId();
    if (!gid) { setChannels([]); return; }
    const ch = await listChannels(gid);
    setChannels(ch);
    // Keep allChannels in sync for search
    setAllChannels((prev) => [...prev.filter((c) => c.group_id !== gid), ...ch]);
  };

  const refreshPins = async () => {
    const ids = await listPinnedGroups();
    setPinnedGroupIds(new Set(ids));
  };

  const handleCreateChannel = (kind: "text" | "voice") => {
    setDesiredChannelKind(kind);
    triggerCommand("create-channel");
  };

  const handleSelectChannel = (id: string) => {
    setSelectedChannelId(id);
    // Zero out unread locally and persist to backend
    setChannels((prev) => {
      const updated = prev.map((c) =>
        c.channel_id === id ? { ...c, unread_count: 0 } : c
      );
      // If no channels have unreads left, clear the group's has_unread flag
      if (!updated.some((c) => c.unread_count > 0)) {
        const gid = selectedGroupId();
        if (gid) {
          setGroups((gs) => gs.map((g) =>
            g.group_id === gid ? { ...g, has_unread: false } : g
          ));
        }
      }
      return updated;
    });
    markChannelRead(id).catch(() => {});
  };

  onMount(async () => {
    const id = await getIdentity();
    setIdentity(id);
    await refreshGroups();
    await refreshPins();
    await refreshAllChannels();

    // Track unread for messages arriving in non-active channels
    const unlisten = await listen<Message>("message", (event) => {
      const msg = event.payload;
      if (msg.channel_id === selectedChannelId()) return;
      const inCurrentGroup = channels().some((c) => c.channel_id === msg.channel_id);
      if (inCurrentGroup) {
        setChannels((prev) => prev.map((c) =>
          c.channel_id === msg.channel_id ? { ...c, unread_count: c.unread_count + 1 } : c
        ));
      } else {
        // Message for another group — refresh to update has_unread flags
        refreshGroups();
      }
    });
    onCleanup(unlisten);
  });

  createEffect(on(selectedGroupId, async (id) => {
    setSelectedChannelId(null);
    if (!id) { setChannels([]); setMembers([]); return; }
    const [ch, mem] = await Promise.all([listChannels(id), listMembers(id)]);
    setChannels(ch);
    setMembers(mem);
  }));

  const selectedGroup = () => groups().find((g) => g.group_id === selectedGroupId());

  // --- Completion providers ---

  const groupCompleter = (q: string, _collected: Record<string, string>) => {
    const lq = q.toLowerCase();
    return groups()
      .filter((g) => !lq || g.name.toLowerCase().includes(lq))
      .map((g) => ({ label: g.name, value: g.group_id, iconKey: g.group_id, iconLabel: g.name[0]?.toUpperCase() }));
  };

  const channelCompleter = (q: string, collected: Record<string, string>) => {
    const gid = collected.group;
    const pool = gid ? allChannels().filter((ch) => ch.group_id === gid) : channels();
    const lq = q.toLowerCase();
    return pool
      .filter((ch) => !lq || ch.name.toLowerCase().includes(lq))
      .map((ch) => ({ label: `${channelPrefix(ch.kind)} ${ch.name}`, value: ch.channel_id }));
  };

  const typeCompleter = (_q: string, _collected: Record<string, string>) => [
    { label: "text", value: "text" },
    { label: "voice", value: "voice" },
  ];

  // --- Search providers ---

  const groupProvider: SearchProvider = (q) => {
    let gList = groups();
    if (q) {
      gList = gList
        .filter((g) => g.name.toLowerCase().includes(q))
        .sort((a, b) => {
          const aExact = a.name.toLowerCase() === q ? 0 : 1;
          const bExact = b.name.toLowerCase() === q ? 0 : 1;
          if (aExact !== bExact) return aExact - bExact;
          const aStarts = a.name.toLowerCase().startsWith(q) ? 0 : 1;
          const bStarts = b.name.toLowerCase().startsWith(q) ? 0 : 1;
          return aStarts - bStarts;
        });
    }
    const pinned = gList.filter((g) => pinnedGroupIds().has(g.group_id));
    const rest = gList.filter((g) => !pinnedGroupIds().has(g.group_id));
    return [...pinned, ...rest].map((g) => ({
      id: g.group_id,
      label: g.name,
      iconKey: g.group_id,
      iconLabel: g.name[0]?.toUpperCase(),
      onSelect: () => setSelectedGroupId(g.group_id),
    }));
  };

  const channelProvider: SearchProvider = (q) => {
    if (!q) return [];
    const groupMap = new Map(groups().map((g) => [g.group_id, g.name]));
    return allChannels()
      .filter((ch) => ch.name.toLowerCase().includes(q))
      .map((ch) => ({
        id: ch.channel_id,
        label: ch.name,
        prefix: channelPrefix(ch.kind),
        badge: groupMap.get(ch.group_id) ?? "",
        onSelect: () => { setSelectedGroupId(ch.group_id); handleSelectChannel(ch.channel_id); },
      }));
  };

  // --- Shortcuts & commands ---

  const overlayShortcuts = shortcutDefs.filter((s) => s.id !== "shortcuts");

  const commands: CommandDef[] = [
    {
      id: "create-group",
      command: "create group",
      args: [{ name: "name", placeholder: "group name" }],
      execute: async (args) => {
        await createGroup(args.name);
        await refreshGroups();
      },
    },
    {
      id: "create-channel",
      command: "create channel",
      args: [
        {
          name: "group",
          placeholder: "group",
          complete: groupCompleter,
          defaultValue: () => selectedGroupId(),
        },
        { name: "name", placeholder: "channel name" },
        {
          name: "type",
          placeholder: "text or voice",
          complete: typeCompleter,
          defaultValue: () => desiredChannelKind(),
        },
      ],
      execute: async (args) => {
        await apiCreateChannel(args.group, args.name, args.type);
        await refreshChannels();
      },
    },
    {
      id: "rename-channel",
      command: "rename channel",
      args: [
        { name: "group", placeholder: "group", complete: groupCompleter, defaultValue: () => selectedGroupId() },
        { name: "channel", placeholder: "channel", complete: channelCompleter },
        { name: "name", placeholder: "new name" },
      ],
      execute: async (args) => {
        await apiRenameChannel(args.channel, args.name);
        await refreshChannels();
      },
    },
    {
      id: "rename-self",
      command: "rename self",
      args: [{ name: "name", placeholder: "new display name" }],
      execute: async (args) => {
        await setDisplayName(args.name);
        const id = await getIdentity();
        setIdentity(id);
      },
    },
    {
      id: "delete-channel",
      command: "delete channel",
      dangerous: true,
      args: [
        { name: "group", placeholder: "group", complete: groupCompleter, defaultValue: () => selectedGroupId() },
        { name: "channel", placeholder: "channel", complete: channelCompleter },
      ],
      execute: async (args) => {
        await apiDeleteChannel(args.channel);
        await refreshChannels();
      },
    },
    {
      id: "invite",
      command: "invite",
      args: [
        {
          name: "group",
          placeholder: "group",
          complete: groupCompleter,
          defaultValue: () => selectedGroupId(),
        },
      ],
      execute: async (args) => {
        const invite = await createInvite(args.group);
        setInviteLink(invite.link);
      },
    },
    {
      id: "join",
      command: "join",
      args: [{ name: "link", placeholder: "paste invite link" }],
      execute: async (args) => {
        const url = new URL(args.link);
        const relay = url.searchParams.get("relay");
        const token = url.searchParams.get("token");
        if (!relay || !token) throw new Error("invalid invite link");
        await joinByInvite(relay, token);
        await refreshGroups();
      },
    },
    {
      id: "info",
      command: "info",
      args: [],
      execute: async () => {
        setShowInfo(true);
      },
    },
  ];

  const unsubs = [
    ...commands.map(registerCommand),
    registerProvider(groupProvider),
    registerProvider(channelProvider),
  ];
  onCleanup(() => unsubs.forEach((u) => u()));

  return (
    <div class="h-screen flex relative" style={{ background: "var(--neutral-950)" }}>
      <div data-tauri-drag-region class="absolute inset-x-0 top-0 h-7 z-10" />
      <Sidebar
        identity={identity()}
        groups={groups()}
        selectedGroupId={selectedGroupId()}
        channels={channels()}
        selectedChannelId={selectedChannelId()}
        onSelectGroup={setSelectedGroupId}
        onDeselectGroup={() => setSelectedGroupId(null)}
        onSelectChannel={handleSelectChannel}
        onCreateChannel={handleCreateChannel}
      />
      <div class="divider-v" />
      <main class="flex-1 flex flex-col min-w-0 pt-7">
        <Show
          when={selectedGroup()}
          fallback={
            <div class="flex-1 flex items-center justify-center">
              <div class="flex flex-col items-center gap-5">
                <span class="text-sm text-[var(--neutral-400)]">select a group</span>
                <div class="flex flex-col gap-2.5">
                  <For each={shortcutDefs}>
                    {(s) => (
                      <div class="flex items-center gap-3">
                        <div class="flex items-center gap-1 w-[76px] justify-end">
                          <For each={s.keys}>
                            {(k) => <KeyBadge value={k} />}
                          </For>
                        </div>
                        <span class="text-xs text-[var(--neutral-500)]">{s.label.toLowerCase()}</span>
                      </div>
                    )}
                  </For>
                </div>
                <button
                  class="mt-1 px-3 py-1.5 rounded-md text-xs text-[var(--neutral-400)] hover:bg-[var(--hover)] cursor-pointer"
                  style={{ border: "1px solid var(--neutral-700)" }}
                  onClick={async () => {
                    try {
                      await seedTestData();
                      await refreshGroups();
                      await refreshPins();
                    } catch {}
                  }}
                >
                  seed test data
                </button>
              </div>
            </div>
          }
        >
          {(group) => (
            <Show
              when={selectedChannelId()}
              fallback={
                <div class="flex-1 flex items-center justify-center">
                  <div class="text-center">
                    <span class="text-sm text-[var(--neutral-400)]">select a channel</span>
                    <span class="text-xs block mt-1 text-[var(--neutral-600)]">from the sidebar</span>
                  </div>
                </div>
              }
            >
              {(channelId) => {
                const channelName = () =>
                  channels().find((c) => c.channel_id === channelId())?.name ?? "";
                return (
                  <GroupView
                    group={group()}
                    channelId={channelId()}
                    channelName={channelName()}
                    members={members()}
                    identity={identity()}
                  />
                );
              }}
            </Show>
          )}
        </Show>
      </main>
      <Show when={selectedGroup()}>
        <div class="divider-v" />
        <MemberPanel members={members()} />
      </Show>
      <CommandPalette />
      <InviteDialog link={inviteLink()} onClose={() => setInviteLink(null)} />
      <ShortcutOverlay shortcuts={overlayShortcuts} forceOpen={showInfo()} onClose={() => setShowInfo(false)} />
    </div>
  );
}
