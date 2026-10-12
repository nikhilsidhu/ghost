// The store against a mocked backend: commands answer from fixtures and the tests
// emit the events the Rust side sends, checking the UI state the store derives.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { emit } from "@tauri-apps/api/event";
import type { Channel, ChannelWaiting, Config, LiveState, Member, Message, OnlinePresenceEvent, Server, VoiceChannelMembers, VoiceState } from "./types";

const SERVER = "aa".repeat(32);
const GENERAL = "bb".repeat(32);
const RANDOM = "cc".repeat(32);
const ME = "11".repeat(32);
const BOB = "22".repeat(32);

const server: Server = {
  server_id: SERVER, name: "club", kind: "server", owner_fp: ME,
  permissions: 15, created_at: 1, has_unread: false, removed: null,
  halted: null,
};
const channel = (channel_id: string, name: string): Channel => ({
  channel_id, server_id: SERVER, name, kind: "text", position: 0, unread_count: 0, private: false,
});
const member = (fingerprint: string, display_name: string): Member => ({
  server_id: SERVER, fingerprint, display_name, joined_at: 1, roles: [],
});

/** Commands the backend answered, in order. */
let calls: string[] = [];
/** What `list_channels` and `list_servers` return; tests change them to simulate the backend's state. */
let serverChannels: Channel[] = [];
let servers: Server[] = [];
/** What `live_state` returns. */
let live: LiveState;
/** What `get_config` returns. */
let config: Config;
const defaultConfig = (): Config => ({
  display_name: "me", relay_url: "http://relay", input_device: null, output_device: null,
  noise_suppression: "nnnoiseless", agc: "auto", input_mode: "voice_activity", vad_threshold: 0.85,
  input_gain: 1, auto_mute_on_idle: true, status: "online", status_message: null, status_expiry: null,
});
const quietLive = (): LiveState => ({
  connectivity: { home: true, any: true, relays_down: [], relays_refusing: [], catching_up: false },
  online: [], voice: [], alerts: [], device_removed: null, voice_state: null, waiting_channels: [], status: "online",
});

function mockBackend() {
  calls = [];
  serverChannels = [channel(GENERAL, "general"), channel(RANDOM, "random")];
  servers = [server];
  live = quietLive();
  config = defaultConfig();
  mockIPC((cmd) => {
    calls.push(cmd);
    switch (cmd) {
      case "get_identity": return { fingerprint: ME, fingerprint_short: ME.slice(0, 16), display_name: "me" };
      case "list_servers": return servers;
      case "list_channels": return serverChannels;
      case "list_members": return [member(ME, "me"), member(BOB, "bob")];
      case "get_server_roles": return null;
      case "get_cached_avatar": return new ArrayBuffer(0);
      case "live_state": return live;
      case "get_config": return config;
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
  store.listenForLiveState();
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
      timestamp: 2, received_at: 2, content: "hi", delivery: "delivered",
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

  it("keeps a server it was kicked from open, read-only, saying who removed it", async () => {
    const store = await freshStore();
    servers = [{ ...server, removed: { at: 5, by: "bob" } }];
    await emit("kicked", SERVER);
    await settle();
    expect(store.selectedServerId()).toBe(SERVER);
    expect(store.selectedServer()?.removed?.by).toBe("bob");
    expect(store.channels().map((c) => c.name)).toContain("general");
  });

  it("forgets a server it was removed from, closing it", async () => {
    const store = await freshStore();
    servers = [];
    await store.forgetServer(SERVER);
    await settle();
    expect(calls).toContain("forget_server");
    expect(store.selectedServerId()).toBeNull();
    expect(store.servers()).toEqual([]);
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

  it("shows a call in progress and an idle status after a reload, from the snapshot", async () => {
    live = {
      ...quietLive(),
      voice_state: { connected: true, server_id: SERVER, channel_id: GENERAL, muted: true, deafened: false, udp_port: 9000, phase: "live", media_path: "open" },
      status: "idle",
    };
    const store = await freshStore();
    expect(store.isInCall()).toBe(true);
    expect(store.voiceChannelId()).toBe(GENERAL);
    expect(store.isMuted()).toBe(true);
    expect(store.ownStatus()).toBe("idle");
  });

  it("drops the old session's rosters when the session restarts", async () => {
    const store = await freshStore();
    await emit("online-presence", { server_id: SERVER, members: [{ fingerprint: BOB, status: "online", status_message: null, avatar_hash: null }] } satisfies OnlinePresenceEvent);
    await emit("voice-channel-members", { channel_id: GENERAL, members: [{ fingerprint: BOB, muted: false, deafened: false }] } satisfies VoiceChannelMembers);
    await settle();
    expect(store.onlinePresence().has(BOB)).toBe(true);

    await emit("live-reset", null);
    await settle();
    expect(store.onlinePresence().has(BOB)).toBe(false);
    expect(store.voiceChannelMembers().size).toBe(0);
  });

  it("knows which channels wait for their server's changes, from events and the snapshot", async () => {
    live = { ...quietLive(), waiting_channels: [RANDOM] };
    const store = await freshStore();
    expect(store.waitingChannels().has(RANDOM)).toBe(true);

    await emit("channel-waiting", { channel_id: GENERAL, waiting: true } satisfies ChannelWaiting);
    await emit("channel-waiting", { channel_id: RANDOM, waiting: false } satisfies ChannelWaiting);
    await settle();
    expect([...store.waitingChannels()]).toEqual([GENERAL]);
  });

  it("follows a call through reconnecting to its end, with the reason it ended", async () => {
    const store = await freshStore();
    const call: VoiceState = {
      connected: true, server_id: SERVER, channel_id: GENERAL, muted: false, deafened: false,
      udp_port: 9000, phase: "reconnecting", media_path: "open",
    };
    await emit("voice-state", call);
    await settle();
    expect(store.voicePhase()).toBe("reconnecting");
    expect(store.isInCall()).toBe(true);

    await emit("voice-error", "Lost the connection to the voice server");
    await emit("voice-state", { ...call, connected: false, server_id: null, channel_id: null, udp_port: null, phase: null, media_path: null } satisfies VoiceState);
    await settle();
    expect(store.voicePhase()).toBeNull();
    expect(store.isInCall()).toBe(false);
    expect(store.voiceError()).toEqual({ channelId: GENERAL, message: "Lost the connection to the voice server", notice: false });
  });

  it("tells a notice apart from an error, and blocked media from a working call", async () => {
    const store = await freshStore();
    await emit("voice-state", {
      connected: true, server_id: SERVER, channel_id: GENERAL, muted: false, deafened: false,
      udp_port: 9000, phase: "live", media_path: "blocked",
    } satisfies VoiceState);
    await emit("voice-notice", "the chosen audio device is not available; using the system default instead");
    await settle();
    expect(store.voiceMediaPath()).toBe("blocked");
    expect(store.voiceError()?.notice).toBe(true);
  });

  it("shows a status and status message another device chose", async () => {
    const store = await freshStore();
    config = { ...config, status: "away", status_message: "lunch", status_expiry: 1_900_000_000_000 };
    await emit("sync-status", "");
    await settle();
    await settle();
    expect(store.ownStatus()).toBe("away");
    expect(store.ownStatusMessage()).toBe("lunch");
    expect(store.expiresAt()).toBe(1_900_000_000_000);
  });

  it("follows push to talk chosen on another device", async () => {
    const store = await freshStore();
    config = { ...config, input_mode: "push_to_talk" };
    await emit("sync-pref", "input_mode");
    await settle();
    await settle();
    expect(store.isPttMode()).toBe(true);
  });

  it("knows when the call's mute is the one going idle applied", async () => {
    const store = await freshStore();
    await emit("auto-muted", true);
    await settle();
    expect(store.autoMuted()).toBe(true);
    await emit("auto-muted", false);
    await settle();
    expect(store.autoMuted()).toBe(false);
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
