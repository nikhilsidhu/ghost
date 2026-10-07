// The role and channel-access palette commands against a mocked backend: each test
// runs a command as the palette would and checks exactly what reached the backend.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import type { ChannelAccess, ServerPolicy, ServerRoles } from "./types";

const SERVER = "aa".repeat(32);
const CHANNEL = "bb".repeat(32);
const OWNER = "11".repeat(32);
const BOB = "22".repeat(32);
const CAROL = "33".repeat(32);

let policy: ServerPolicy;
let access: ChannelAccess;
/** Arguments of each command the backend received, by command name. */
let received: Record<string, unknown[]>;

function mockBackend() {
  policy = {
    owner_fp: OWNER,
    everyone: 1,
    roles: [{ id: 3, name: "mods", permissions: 2 }, { id: 7, name: "helpers", permissions: 1 }],
    assignments: [{ fingerprint: BOB, roles: [3] }],
  };
  access = { roles: [7], accounts: [] };
  received = {};
  mockIPC((cmd, args) => {
    (received[cmd] ??= []).push(args);
    switch (cmd) {
      case "get_server_roles":
        return { policy: structuredClone(policy), my_permissions: 15, explicit: true, members_missing_support: [] } satisfies ServerRoles;
      case "get_channel_access": return structuredClone(access);
      case "list_servers": case "list_channels": case "list_members": return [];
      default: return null;
    }
  });
}

/** Run a registered palette command with the given arguments. */
async function run(id: string, args: Record<string, string>) {
  const { commands } = await import("./registry");
  const command = commands().find((c) => c.id === id);
  if (!command) throw new Error(`no command ${id}`);
  await command.execute(args);
}

/** Arguments of the latest call to a command. */
const lastArgs = <T,>(cmd: string): T => {
  const calls = received[cmd] ?? [];
  return calls[calls.length - 1] as T;
};
const sentPolicy = () => lastArgs<{ policy: ServerPolicy }>("set_server_roles").policy;
const sentAccess = () => lastArgs<{ access: ChannelAccess }>("set_channel_access").access;

describe("palette commands", () => {
  beforeEach(async () => {
    vi.resetModules();
    mockBackend();
    await import("./commands");
  });
  afterEach(clearMocks);

  it("creates a role below every existing one with the next free id", async () => {
    await run("create-role", { server: SERVER, name: "artists", permissions: "1" });
    const roles = sentPolicy().roles;
    expect(roles[roles.length - 1]).toEqual({ id: 8, name: "artists", permissions: 1 });
    expect(sentPolicy().roles.slice(0, 2)).toEqual(policy.roles);
  });

  it("deletes a role and takes it from everyone who had it", async () => {
    await run("delete-role", { server: SERVER, role: "3" });
    expect(sentPolicy().roles.map((r) => r.id)).toEqual([7]);
    expect(sentPolicy().assignments).toEqual([{ fingerprint: BOB, roles: [] }]);
  });

  it("assigns and unassigns roles without duplicating them", async () => {
    await run("assign-role", { server: SERVER, member: BOB, role: "3" });
    expect(sentPolicy().assignments).toEqual([{ fingerprint: BOB, roles: [3] }]);
    await run("assign-role", { server: SERVER, member: CAROL, role: "7" });
    expect(sentPolicy().assignments).toContainEqual({ fingerprint: CAROL, roles: [7] });
    await run("unassign-role", { server: SERVER, member: BOB, role: "3" });
    expect(sentPolicy().assignments).toContainEqual({ fingerprint: BOB, roles: [] });
  });

  it("changes what everyone may do and who owns the server", async () => {
    await run("everyone-permissions", { server: SERVER, permissions: "0" });
    expect(sentPolicy().everyone).toBe(0);
    await run("transfer-ownership", { server: SERVER, member: BOB });
    expect(sentPolicy().owner_fp).toBe(BOB);
  });

  it("adds to and removes from a private channel's access", async () => {
    await run("allow-in-channel", { server: SERVER, channel: CHANNEL, access: `member:${CAROL}` });
    expect(sentAccess()).toEqual({ roles: [7], accounts: [CAROL] });
    await run("disallow-in-channel", { server: SERVER, channel: CHANNEL, access: "role:7" });
    expect(sentAccess()).toEqual({ roles: [], accounts: [] });
  });
});
