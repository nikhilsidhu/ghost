import { createSignal, createEffect, on, onMount, Show } from "solid-js";
import type { Identity, Group, Channel, Member } from "../lib/types";
import {
  getIdentity, listGroups, listChannels, listMembers,
  listPinnedGroups, pinGroup, unpinGroup,
  createGroup, createChannel as apiCreateChannel,
  renameChannel as apiRenameChannel, deleteChannel as apiDeleteChannel,
} from "../lib/api";
import { Sidebar } from "./Sidebar";
import { GroupView } from "./GroupView";
import { MemberPanel } from "./MemberPanel";
import { CommandPalette, type CommandDef } from "./CommandPalette";

export function Layout() {
  const [identity, setIdentity] = createSignal<Identity | null>(null);
  const [groups, setGroups] = createSignal<Group[]>([]);
  const [selectedGroupId, setSelectedGroupId] = createSignal<string | null>(null);
  const [channels, setChannels] = createSignal<Channel[]>([]);
  const [members, setMembers] = createSignal<Member[]>([]);
  const [pinnedGroupIds, setPinnedGroupIds] = createSignal<Set<string>>(new Set());
  const [selectedChannelId, setSelectedChannelId] = createSignal<string | null>(null);
  const [openCommandId, setOpenCommandId] = createSignal<string | null>(null);

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

  const handleTogglePin = async (groupId: string) => {
    if (pinnedGroupIds().has(groupId)) {
      await unpinGroup(groupId);
    } else {
      await pinGroup(groupId);
    }
    await refreshPins();
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

  // --- Command definitions ---

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
          defaultValue: () => "text",
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
  ];

  return (
    <div class="h-screen flex relative" style={{ background: "var(--neutral-950)" }}>
      <div class="absolute left-0 right-0 top-[84px] h-px bg-[var(--neutral-800)] z-10" />
      <Sidebar
        identity={identity()}
        groups={groups()}
        pinnedGroupIds={pinnedGroupIds()}
        selectedGroupId={selectedGroupId()}
        onSelectGroup={setSelectedGroupId}
        onCreateGroup={() => setOpenCommandId("create-group")}
        onTogglePin={handleTogglePin}
      />
      <main class="flex-1 flex flex-col min-w-0">
        <div data-tauri-drag-region class="h-7 flex-shrink-0" />
        <Show
          when={selectedGroup()}
          fallback={
            <div class="flex-1 flex items-center justify-center">
              <span class="text-xs" style={{ color: "var(--neutral-500)" }}>
                select a group
              </span>
            </div>
          }
        >
          {(group) => (
            <GroupView
              group={group()}
              channels={channels()}
              members={members()}
              identity={identity()}
              selectedChannelId={selectedChannelId()}
              onSelectChannel={setSelectedChannelId}
            />
          )}
        </Show>
      </main>
      <Show when={selectedGroup()}>
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
    </div>
  );
}
