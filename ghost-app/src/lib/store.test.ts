// The store against a mocked backend: commands answer from fixtures and the tests
// emit the events the Rust side sends, checking the UI state the store derives.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { emit } from "@tauri-apps/api/event";
import type { Channel, Member, Message, OnlinePresenceEvent, Server, VoiceChannelMembers } from "./types";

const SERVER = "aa".repeat(32);
const GENERAL = "bb".repeat(32);
const RANDOM = "cc".repeat(32);
const ME = "11".repeat(32);
const BOB = "22".repeat(32);

const server: Server = {
  server_id: SERVER, name: "club", kind: "server", creator_fp: ME, owner_fp: ME,
  permissions: 15, created_at: 1, has_unread: false,
};
const channel = (channel_id: string, name: string): Channel => ({
  channel_id, server_id: SERVER, name, kind: "text", position: 0, unread_count: 0, private: false,
});
const member = (fingerprint: string, display_name: string): Member => ({
  server_id: SERVER, fingerprint, display_name, role: "member", joined_at: 1, roles: [],
});

/** Commands the backend answered, in order. */
let calls: string[] = [];
/** What `list_channels` returns; tests change it to simulate the backend's state. */
let serverChannels: Channel[] = [];

function mockBackend() {
  calls = [];
  serverChannels = [channel(GENERAL, "general"), channel(RANDOM, "random")];
  mockIPC((cmd) => {
    calls.push(cmd);
    switch (cmd) {
      case "get_identity": return { fingerprint: ME, fingerprint_short: ME.slice(0, 16), display_name: "me" };
      case "list_servers": return [server];
      case "list_channels": return serverChannels;
      case "list_members": return [member(ME, "me"), member(BOB, "bob")];
      case "get_server_roles": return null;
      case "get_cached_avatar": return null;
      default: return null;
    }
  }, { shouldMockEvents: true });
}

/** Let listeners and the refreshes they start run. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

// The store keeps module-level state, so each test gets a fresh copy.
async function freshStore() {
  const { vi } = await import("vitest");
  vi.resetModules();
  const store = await import("./store");
  await store.initialize();
  await store.selectServer(SERVER);
  await settle();
  return store;
}

describe("store", () => {
  beforeEach(mockBackend);
  afterEach(clearMocks);

  it("counts unread messages in channels other than the open one", async () => {
    const store = await freshStore();
    store.selectChannel(GENERAL);
    const message: Message = {
      message_id: "dd".repeat(32), channel_id: RANDOM, sender_fp: BOB, message_type: 0,
      timestamp: 2, received_at: 2, content: "hi",
    };
    await emit("message", message);
    await settle();
    expect(store.channels().find((c) => c.channel_id === RANDOM)?.unread_count).toBe(1);
    expect(store.channels().find((c) => c.channel_id === GENERAL)?.unread_count).toBe(0);
  });

  it("reloads the open server's channels when the backend reports it changed", async () => {
    const store = await freshStore();
    serverChannels = [...serverChannels, channel("ee".repeat(32), "new")];
    await emit("sync", SERVER);
    await settle();
    expect(store.channels().map((c) => c.name)).toContain("new");
  });

  it("leaves the server's view when this account is kicked", async () => {
    const store = await freshStore();
    expect(store.selectedServerId()).toBe(SERVER);
    await emit("kicked", SERVER);
    await settle();
    expect(store.selectedServerId()).toBeNull();
    expect(store.channels()).toEqual([]);
    expect(store.members()).toEqual([]);
  });

  it("tracks who is in each voice channel and forgets empty ones", async () => {
    const store = await freshStore();
    const joined: VoiceChannelMembers = { channel_id: GENERAL, members: [{ fingerprint: BOB, muted: false, deafened: true }] };
    await emit("voice-channel-members", joined);
    await settle();
    expect(store.voiceChannelMembers().get(GENERAL)).toEqual(joined.members);
    await emit("voice-channel-members", { channel_id: GENERAL, members: [] } satisfies VoiceChannelMembers);
    await settle();
    expect(store.voiceChannelMembers().has(GENERAL)).toBe(false);
  });

  it("records members' online status per server", async () => {
    const store = await freshStore();
    const presence: OnlinePresenceEvent = {
      server_id: SERVER,
      members: [{ fingerprint: BOB, status: "away", status_message: "lunch", avatar_hash: null }],
    };
    await emit("online-presence", presence);
    await settle();
    expect(store.onlinePresence().get(BOB)?.status).toBe("away");
    expect(store.onlinePresence().get(BOB)?.status_message).toBe("lunch");
  });
});
