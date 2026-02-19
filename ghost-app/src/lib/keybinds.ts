import { register, unregister } from "@tauri-apps/plugin-global-shortcut";
import { listen } from "@tauri-apps/api/event";
import { getKeybinds, getConfig, setPttActive } from "./api";
import type { VoiceState } from "./types";

let currentPttShortcut: string | null = null;
let voiceActive = false;
let inputMode = "voice_activity";
let pttActiveCallback: ((active: boolean) => void) | null = null;

export function onPttActiveChange(cb: (active: boolean) => void) {
  pttActiveCallback = cb;
}

function pttEnabled() {
  return inputMode === "push_to_talk";
}

async function registerPtt(shortcut: string) {
  if (currentPttShortcut === shortcut) return;
  await unregisterPtt();
  try {
    await register(shortcut, (event) => {
      if (event.state === "Pressed") {
        pttActiveCallback?.(true);
        setPttActive(true).catch(() => {});
      } else if (event.state === "Released") {
        pttActiveCallback?.(false);
        setPttActive(false).catch(() => {});
      }
    });
    currentPttShortcut = shortcut;
    console.log("keybinds: registered PTT shortcut:", shortcut);
  } catch (e) {
    const inst = import.meta.env.VITE_GHOST_INSTANCE;
    console.error(`keybinds${inst ? ` [#${inst}]` : ""}: failed to register PTT shortcut:`, shortcut, "(likely owned by another instance)", e);
  }
}

async function unregisterPtt() {
  if (!currentPttShortcut) return;
  try {
    await unregister(currentPttShortcut);
  } catch {
    // already unregistered or invalid
  }
  currentPttShortcut = null;
}

function syncPtt() {
  if (voiceActive && pttEnabled() && pttShortcut) {
    registerPtt(pttShortcut);
  } else {
    unregisterPtt();
  }
}

let pttShortcut: string | null = null;

export function setPttShortcut(shortcut: string | null) {
  pttShortcut = shortcut;
  syncPtt();
}

export function setInputMode(mode: string) {
  inputMode = mode;
  syncPtt();
}

export async function initKeybinds() {
  // Listener first — avoids race with early voice joins (dev auto-join)
  listen<VoiceState>("voice-state", (event) => {
    const wasActive = voiceActive;
    voiceActive = event.payload.connected;
    if (voiceActive !== wasActive) syncPtt();
  });

  const [kb, config] = await Promise.all([getKeybinds(), getConfig()]);
  pttShortcut = kb.push_to_talk;
  inputMode = config.input_mode;
  syncPtt();
}
