import { createSignal, createEffect, on, onMount, Show, For } from "solid-js";
import type { Identity, Group, Channel, Member } from "../lib/types";
import {
  getIdentity, listGroups, listChannels, listMembers,
  listPinnedGroups,
  createGroup, createChannel as apiCreateChannel,
  renameChannel as apiRenameChannel, deleteChannel as apiDeleteChannel,
  createInvite, joinByInvite, seedTestData,
} from "../lib/api";
import { Sidebar } from "./Sidebar";
import { GroupView } from "./GroupView";
import { MemberPanel } from "./MemberPanel";
import { CommandPalette, type CommandDef } from "./CommandPalette";
import { InviteDialog } from "./InviteDialog";
import { ShortcutOverlay } from "./ShortcutOverlay";
import { shortcuts as shortcutDefs } from "../lib/shortcuts";

export function Layout() {
  const [identity, setIdentity] = createSignal<Identity | null>(null);
  const [groups, setGroups] = createSignal<Group[]>([]);
  const [selectedGroupId, setSelectedGroupId] = createSignal<string | null>(null);
  const [channels, setChannels] = createSignal<Channel[]>([]);
  const [members, setMembers] = createSignal<Member[]>([]);
  const [pinnedGroupIds, setPinnedGroupIds] = createSignal<Set<string>>(new Set());
  const [selectedChannelId, setSelectedChannelId] = createSignal<string | null>(null);
  const [openCommandId, setOpenCommandId] = createSignal<string | null>(null);
  const [inviteLink, setInviteLink] = createSignal<string | null>(null);
  const [showInfo, setShowInfo] = createSignal(false);
  const [desiredChannelKind, setDesiredChannelKind] = createSignal<string>("text");

  // --- Refresh helpers ---

  const refreshGroups = async () => {
    const gs = await listGroups();
    setGroups(gs);
  };

  const refreshChannels = async () => {
    const gid = selectedGroupId();
    if (!gid) { setChannels([]); return; }
    const ch = await listChannels(gid);
    setChannels(ch);
  };

  const refreshPins = async () => {
    const ids = await listPinnedGroups();
    setPinnedGroupIds(new Set(ids));
  };

  const handleCreateChannel = (kind: "text" | "voice") => {
    setDesiredChannelKind(kind);
    setOpenCommandId("create-channel");
  };

  onMount(async () => {
    const id = await getIdentity();
    setIdentity(id);
    await refreshGroups();
    await refreshPins();
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

  const groupCompleter = (q: string) => {
    const lq = q.toLowerCase();
    return groups()
      .filter((g) => !lq || g.name.toLowerCase().includes(lq))
      .map((g) => ({ label: g.name, value: g.group_id }));
  };

  const channelCompleter = (q: string) => {
    const lq = q.toLowerCase();
    return channels()
      .filter((ch) => !lq || ch.name.toLowerCase().includes(lq))
      .map((ch) => ({ label: `${ch.kind === "text" ? "#" : "\u266a"} ${ch.name}`, value: ch.channel_id }));
  };

  const typeCompleter = () => [
    { label: "text", value: "text" },
    { label: "voice", value: "voice" },
  ];

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
        { name: "channel", placeholder: "channel", complete: channelCompleter },
        { name: "name", placeholder: "new name" },
      ],
      execute: async (args) => {
        await apiRenameChannel(args.channel, args.name);
        await refreshChannels();
      },
    },
    {
      id: "delete-channel",
      command: "delete channel",
      args: [
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
        onSelectChannel={setSelectedChannelId}
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
                            {(k) => (
                              <kbd class="inline-flex items-center justify-center min-w-[22px] h-[22px] px-1.5 rounded text-[11px] font-medium bg-[var(--neutral-800)] text-[var(--neutral-400)] border border-[var(--neutral-700)]">
                                {k === "Cmd" ? "\u2318" : k}
                              </kbd>
                            )}
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
      <CommandPalette
        groups={groups()}
        pinnedGroupIds={pinnedGroupIds()}
        commands={commands}
        onSelectGroup={setSelectedGroupId}
        openCommandId={openCommandId()}
        onOpenCommandHandled={() => setOpenCommandId(null)}
      />
      <InviteDialog link={inviteLink()} onClose={() => setInviteLink(null)} />
      <ShortcutOverlay shortcuts={overlayShortcuts} forceOpen={showInfo()} onClose={() => setShowInfo(false)} />
    </div>
  );
}
