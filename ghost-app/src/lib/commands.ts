import {
  groups, selectedGroupId, channels, allChannels,
  pinnedGroupIds, desiredChannelKind,
  selectGroup, selectChannel, refreshGroups, refreshChannels,
  updateIdentity, setInviteLink, setShowInfo, setDesiredChannelKind,
} from "./store";
import {
  createGroup, createChannel, renameChannel, deleteChannel,
  createInvite, joinByInvite, setDisplayName,
} from "./api";
import { registerCommand, registerProvider, triggerCommand } from "./registry";
import type { CommandDef, SearchProvider } from "./registry";
import { channelPrefix } from "./constants";

// --- Completers ---

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
    onSelect: () => selectGroup(g.group_id),
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
      onSelect: () => { selectGroup(ch.group_id); selectChannel(ch.channel_id); },
    }));
};

// --- Commands ---

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
      { name: "group", placeholder: "group", complete: groupCompleter, defaultValue: () => selectedGroupId() },
      { name: "name", placeholder: "channel name" },
      { name: "type", placeholder: "text or voice", complete: typeCompleter, defaultValue: () => desiredChannelKind() },
    ],
    execute: async (args) => {
      await createChannel(args.group, args.name, args.type);
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
      await renameChannel(args.channel, args.name);
      await refreshChannels();
    },
  },
  {
    id: "rename-self",
    command: "rename self",
    args: [{ name: "name", placeholder: "new display name" }],
    execute: async (args) => {
      await setDisplayName(args.name);
      await updateIdentity();
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
      await deleteChannel(args.channel);
      await refreshChannels();
    },
  },
  {
    id: "invite",
    command: "invite",
    args: [{ name: "group", placeholder: "group", complete: groupCompleter, defaultValue: () => selectedGroupId() }],
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
    execute: async () => { setShowInfo(true); },
  },
];

// --- Auto-register on import ---

commands.forEach(registerCommand);
registerProvider(groupProvider);
registerProvider(channelProvider);

// Sidebar uses this to open the create-channel command with the right kind
export const handleCreateChannel = (kind: "text" | "voice") => {
  setDesiredChannelKind(kind);
  triggerCommand("create-channel");
};
