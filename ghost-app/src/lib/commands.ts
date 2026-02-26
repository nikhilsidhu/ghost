import {
  servers, selectedServerId, channels, allChannels,
  desiredChannelKind, contacts,
  selectServer, selectChannel, selectDm, refreshServers, refreshChannels, refreshAllMembers,
  updateIdentity, setInviteLink, setShowInfo, setDesiredChannelKind,
} from "./store";
import {
  createServer, createDm, createChannel, renameChannel, deleteChannel,
  createInvite, joinByInvite, setDisplayName,
} from "./api";
import { registerCommand, registerProvider, triggerCommand } from "./registry";
import type { CommandDef, SearchProvider } from "./registry";
import { channelPrefix } from "./constants";

// --- Completers ---

const serverCompleter = (q: string, _collected: Record<string, string>) => {
  const lq = q.toLowerCase();
  return servers()
    .filter((s) => !lq || s.name.toLowerCase().includes(lq))
    .map((s) => ({ label: s.name, value: s.server_id, iconKey: s.server_id, iconLabel: s.name[0]?.toUpperCase() }));
};

const channelCompleter = (q: string, collected: Record<string, string>) => {
  const sid = collected.server;
  const pool = sid ? allChannels().filter((ch) => ch.server_id === sid) : channels();
  const lq = q.toLowerCase();
  return pool
    .filter((ch) => !lq || ch.name.toLowerCase().includes(lq))
    .map((ch) => ({ label: `${channelPrefix(ch.kind)} ${ch.name}`, value: ch.channel_id }));
};

const typeCompleter = (_q: string, _collected: Record<string, string>) => [
  { label: "text", value: "text" },
  { label: "voice", value: "voice" },
];

const contactCompleter = (q: string, _collected: Record<string, string>) => {
  const lq = q.toLowerCase();
  return contacts()
    .filter((c) => !lq || c.display_name.toLowerCase().includes(lq))
    .map((c) => ({ label: c.display_name, value: c.display_name }));
};

// --- Search providers ---

const serverProvider: SearchProvider = (q) => {
  let sList = servers();
  if (q) {
    sList = sList
      .filter((s) => s.name.toLowerCase().includes(q))
      .sort((a, b) => {
        const aExact = a.name.toLowerCase() === q ? 0 : 1;
        const bExact = b.name.toLowerCase() === q ? 0 : 1;
        if (aExact !== bExact) return aExact - bExact;
        const aStarts = a.name.toLowerCase().startsWith(q) ? 0 : 1;
        const bStarts = b.name.toLowerCase().startsWith(q) ? 0 : 1;
        return aStarts - bStarts;
      });
  }
  return sList.map((s) => ({
    id: s.server_id,
    label: s.name,
    iconKey: s.server_id,
    iconLabel: s.name[0]?.toUpperCase(),
    onSelect: () => selectServer(s.server_id),
  }));
};

const channelProvider: SearchProvider = (q) => {
  const serverMap = new Map(servers().map((s) => [s.server_id, s.name]));
  const pool = q ? allChannels().filter((ch) => ch.name.toLowerCase().includes(q)) : allChannels();
  return pool.map((ch) => ({
    id: ch.channel_id,
    label: ch.name,
    prefix: channelPrefix(ch.kind),
    badge: serverMap.get(ch.server_id) ?? "",
    badgeIconKey: ch.server_id,
    onSelect: () => { selectServer(ch.server_id); selectChannel(ch.channel_id); },
  }));
};

// --- Commands ---

const commands: CommandDef[] = [
  {
    id: "create-server",
    command: "create server",
    args: [{ name: "name", placeholder: "server name" }],
    execute: async (args) => {
      await createServer(args.name);
      await refreshServers();
    },
  },
  {
    id: "create-channel",
    command: "create channel",
    args: [
      { name: "server", placeholder: "server", complete: serverCompleter, defaultValue: () => selectedServerId() },
      { name: "name", placeholder: "channel name" },
      { name: "type", placeholder: "text or voice", complete: typeCompleter, defaultValue: () => desiredChannelKind() },
    ],
    execute: async (args) => {
      await createChannel(args.server, args.name, args.type);
      await refreshChannels();
    },
  },
  {
    id: "rename-channel",
    command: "rename channel",
    args: [
      { name: "server", placeholder: "server", complete: serverCompleter, defaultValue: () => selectedServerId() },
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
      { name: "server", placeholder: "server", complete: serverCompleter, defaultValue: () => selectedServerId() },
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
    args: [{ name: "server", placeholder: "server", complete: serverCompleter, defaultValue: () => selectedServerId() }],
    execute: async (args) => {
      const invite = await createInvite(args.server);
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
      await refreshServers();
    },
  },
  {
    id: "new-dm",
    command: "new dm",
    args: [{ name: "name", placeholder: "contact", complete: contactCompleter }],
    execute: async (args) => {
      const dm = await createDm(args.name);
      await refreshServers();
      await refreshAllMembers();
      await selectDm(dm.server_id);
      const invite = await createInvite(dm.server_id);
      setInviteLink(invite.link);
    },
  },
  {
    id: "info",
    command: "info",
    args: [],
    execute: async () => { setShowInfo(true); },
  },
];

// --- Auto-register on import (with HMR cleanup) ---

const cleanups: (() => void)[] = [];

if (import.meta.hot) {
  import.meta.hot.dispose(() => { cleanups.forEach((fn) => fn()); cleanups.length = 0; });
}

cleanups.push(...commands.map(registerCommand));
cleanups.push(registerProvider(serverProvider));
cleanups.push(registerProvider(channelProvider));

// Sidebar uses this to open the create-channel command with the right kind
export const handleCreateChannel = (kind: "text" | "voice") => {
  setDesiredChannelKind(kind);
  triggerCommand("create-channel");
};

export const handleCreateDm = () => {
  triggerCommand("new-dm");
};
