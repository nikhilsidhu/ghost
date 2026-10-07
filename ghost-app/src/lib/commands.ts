import {
  servers, selectedServerId, channels, allChannels, members, serverRoles,
  desiredChannelKind, contacts,
  selectServer, selectChannel, selectDm, refreshServers, refreshChannels, refreshAllMembers, refreshRoles,
  updateIdentity, setInviteLink, setMoveLink, setShowInfo, setDesiredChannelKind,
} from "./store";
import {
  createServer, createDm, createChannel, renameChannel, deleteChannel,
  createInvite, joinByInvite, setDisplayName, moveServer, followServerMove,
  createPrivateChannel, getChannelAccess, setChannelAccess, getServerRoles, setServerRoles,
} from "./api";
import { ALL_PERMISSIONS, PERMISSIONS } from "./types";
import type { ServerPolicy } from "./types";
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

const memberCompleter = (q: string, _collected: Record<string, string>) => {
  const lq = q.toLowerCase();
  return members()
    .filter((m) => !lq || m.display_name.toLowerCase().includes(lq))
    .map((m) => ({ label: m.display_name, value: m.fingerprint, iconKey: m.fingerprint, iconLabel: m.display_name[0]?.toUpperCase() }));
};

const roleLabel = (id: number, name: string) => name || `role ${id}`;

const roleCompleter = (q: string, _collected: Record<string, string>) => {
  const lq = q.toLowerCase();
  return (serverRoles()?.policy.roles ?? [])
    .map((r) => ({ label: roleLabel(r.id, r.name), value: String(r.id) }))
    .filter((o) => !lq || o.label.toLowerCase().includes(lq));
};

/** A role or a single member, for private channel access lists. */
const accessCompleter = (q: string, collected: Record<string, string>) => [
  ...roleCompleter(q, collected).map((o) => ({ ...o, label: `role: ${o.label}`, value: `role:${o.value}` })),
  ...memberCompleter(q, collected).map((o) => ({ ...o, value: `member:${o.value}` })),
];

const PERMISSION_PRESETS: Record<string, number> = {
  "nothing": 0,
  "invite": PERMISSIONS.invite,
  "moderate (invite, kick)": PERMISSIONS.invite | PERMISSIONS.kick,
  "manage channels": PERMISSIONS.invite | PERMISSIONS.manageChannels,
  "admin (everything)": ALL_PERMISSIONS,
};

const permissionCompleter = (q: string, _collected: Record<string, string>) => {
  const lq = q.toLowerCase();
  return Object.keys(PERMISSION_PRESETS)
    .filter((name) => !lq || name.includes(lq))
    .map((name) => ({ label: name, value: String(PERMISSION_PRESETS[name]) }));
};

const privateChannelCompleter = (q: string, collected: Record<string, string>) =>
  channelCompleter(q, collected).filter((o) => channels().find((ch) => ch.channel_id === o.value)?.private);

/** Read the server's current policy, change it, and commit the result. */
const updatePolicy = async (serverId: string, change: (policy: ServerPolicy) => void) => {
  const { policy } = await getServerRoles(serverId);
  change(policy);
  await setServerRoles(serverId, policy);
  await Promise.all([refreshRoles(), refreshServers(), refreshAllMembers()]);
};

const parseAccess = (value: string) => {
  const [kind, id] = value.split(":");
  return kind === "role" ? { roles: [Number(id)], accounts: [] as string[] } : { roles: [] as number[], accounts: [id] };
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
    id: "create-private-channel",
    command: "create private channel",
    args: [
      { name: "server", placeholder: "server", complete: serverCompleter, defaultValue: () => selectedServerId() },
      { name: "name", placeholder: "channel name" },
      { name: "type", placeholder: "text or voice", complete: typeCompleter, defaultValue: () => desiredChannelKind() },
      { name: "access", placeholder: "role or member who may see it", complete: accessCompleter },
    ],
    execute: async (args) => {
      const access = parseAccess(args.access);
      await createPrivateChannel(args.server, args.name, args.type, access.roles, access.accounts);
      await refreshChannels();
    },
  },
  {
    id: "allow-in-channel",
    command: "allow in channel",
    args: [
      { name: "server", placeholder: "server", complete: serverCompleter, defaultValue: () => selectedServerId() },
      { name: "channel", placeholder: "private channel", complete: privateChannelCompleter },
      { name: "access", placeholder: "role or member", complete: accessCompleter },
    ],
    execute: async (args) => {
      const current = await getChannelAccess(args.channel);
      if (!current) throw new Error("not a private channel");
      const added = parseAccess(args.access);
      await setChannelAccess(args.channel, {
        roles: [...new Set([...current.roles, ...added.roles])],
        accounts: [...new Set([...current.accounts, ...added.accounts])],
      });
    },
  },
  {
    id: "disallow-in-channel",
    command: "disallow in channel",
    dangerous: true,
    args: [
      { name: "server", placeholder: "server", complete: serverCompleter, defaultValue: () => selectedServerId() },
      { name: "channel", placeholder: "private channel", complete: privateChannelCompleter },
      { name: "access", placeholder: "role or member", complete: accessCompleter },
    ],
    execute: async (args) => {
      const current = await getChannelAccess(args.channel);
      if (!current) throw new Error("not a private channel");
      const removed = parseAccess(args.access);
      await setChannelAccess(args.channel, {
        roles: current.roles.filter((r) => !removed.roles.includes(r)),
        accounts: current.accounts.filter((a) => !removed.accounts.includes(a)),
      });
    },
  },
  {
    id: "create-role",
    command: "create role",
    args: [
      { name: "server", placeholder: "server", complete: serverCompleter, defaultValue: () => selectedServerId() },
      { name: "name", placeholder: "role name" },
      { name: "permissions", placeholder: "what it may do", complete: permissionCompleter },
    ],
    execute: async (args) => {
      await updatePolicy(args.server, (policy) => {
        const id = Math.max(0, ...policy.roles.map((r) => r.id)) + 1;
        if (id > 255) throw new Error("a server has at most 255 roles");
        // New roles rank lowest, which anyone who may manage roles can create.
        policy.roles.push({ id, name: args.name, permissions: Number(args.permissions) });
      });
    },
  },
  {
    id: "delete-role",
    command: "delete role",
    dangerous: true,
    args: [
      { name: "server", placeholder: "server", complete: serverCompleter, defaultValue: () => selectedServerId() },
      { name: "role", placeholder: "role", complete: roleCompleter },
    ],
    execute: async (args) => {
      const id = Number(args.role);
      await updatePolicy(args.server, (policy) => {
        policy.roles = policy.roles.filter((r) => r.id !== id);
        for (const a of policy.assignments) a.roles = a.roles.filter((r) => r !== id);
      });
    },
  },
  {
    id: "assign-role",
    command: "assign role",
    args: [
      { name: "server", placeholder: "server", complete: serverCompleter, defaultValue: () => selectedServerId() },
      { name: "member", placeholder: "member", complete: memberCompleter },
      { name: "role", placeholder: "role", complete: roleCompleter },
    ],
    execute: async (args) => {
      const id = Number(args.role);
      await updatePolicy(args.server, (policy) => {
        const existing = policy.assignments.find((a) => a.fingerprint === args.member);
        if (existing) existing.roles = [...new Set([...existing.roles, id])];
        else policy.assignments.push({ fingerprint: args.member, roles: [id] });
      });
    },
  },
  {
    id: "unassign-role",
    command: "unassign role",
    args: [
      { name: "server", placeholder: "server", complete: serverCompleter, defaultValue: () => selectedServerId() },
      { name: "member", placeholder: "member", complete: memberCompleter },
      { name: "role", placeholder: "role", complete: roleCompleter },
    ],
    execute: async (args) => {
      const id = Number(args.role);
      await updatePolicy(args.server, (policy) => {
        for (const a of policy.assignments) {
          if (a.fingerprint === args.member) a.roles = a.roles.filter((r) => r !== id);
        }
      });
    },
  },
  {
    id: "everyone-permissions",
    command: "set everyone permissions",
    args: [
      { name: "server", placeholder: "server", complete: serverCompleter, defaultValue: () => selectedServerId() },
      { name: "permissions", placeholder: "what every member may do", complete: permissionCompleter },
    ],
    execute: async (args) => {
      await updatePolicy(args.server, (policy) => { policy.everyone = Number(args.permissions); });
    },
  },
  {
    id: "transfer-ownership",
    command: "transfer ownership",
    dangerous: true,
    args: [
      { name: "server", placeholder: "server", complete: serverCompleter, defaultValue: () => selectedServerId() },
      { name: "member", placeholder: "new owner", complete: memberCompleter },
    ],
    execute: async (args) => {
      await updatePolicy(args.server, (policy) => { policy.owner_fp = args.member; });
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
      const key = url.searchParams.get("k");
      if (!relay || !token || !key) throw new Error("invalid invite link");
      await joinByInvite(relay, token, key, url.searchParams.get("r"));
      await refreshServers();
    },
  },
  {
    id: "move-server",
    command: "move server",
    args: [
      { name: "server", placeholder: "server", complete: serverCompleter, defaultValue: () => selectedServerId() },
      { name: "relay", placeholder: "new relay url" },
    ],
    execute: async (args) => {
      setMoveLink(await moveServer(args.server, args.relay));
      await refreshServers();
    },
  },
  {
    id: "follow-move",
    command: "follow server move",
    args: [{ name: "link", placeholder: "paste move link" }],
    execute: async (args) => {
      await followServerMove(args.link);
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
