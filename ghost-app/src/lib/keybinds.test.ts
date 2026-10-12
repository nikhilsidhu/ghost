// The push-to-talk shortcut against a mocked backend: it is bound only during a call in
// push-to-talk mode, and unbinding it lets go of the gate, since a key held then would
// never be heard released.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { clearMocks, mockIPC } from "@tauri-apps/api/mocks";
import { emit } from "@tauri-apps/api/event";
import type { VoiceState } from "./types";

/** Commands the backend answered, with their arguments, in order. */
let calls: { cmd: string; args: unknown }[] = [];

function mockBackend() {
  calls = [];
  mockIPC((cmd, args) => {
    calls.push({ cmd, args });
    switch (cmd) {
      case "get_keybinds": return { push_to_talk: "F13" };
      case "get_config": return { input_mode: "push_to_talk" };
      default: return null;
    }
  }, { shouldMockEvents: true });
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

const call = (connected: boolean): VoiceState => ({
  connected, server_id: null, channel_id: null, muted: false, deafened: false,
  udp_port: null, phase: connected ? "live" : null, media_path: null,
});

describe("push to talk", () => {
  beforeEach(mockBackend);
  afterEach(clearMocks);

  it("lets go of the gate when the shortcut is unbound at the end of a call", async () => {
    const { vi } = await import("vitest");
    vi.resetModules();
    const keybinds = await import("./keybinds");
    await keybinds.initKeybinds();
    await emit("voice-state", call(true));
    await settle();
    expect(calls.some((c) => c.cmd === "plugin:global-shortcut|register")).toBe(true);

    await emit("voice-state", call(false));
    await settle();
    await settle();
    expect(calls.some((c) => c.cmd === "plugin:global-shortcut|unregister")).toBe(true);
    expect(calls).toContainEqual({ cmd: "set_ptt_active", args: { active: false } });
  });
});
