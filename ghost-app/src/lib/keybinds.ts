import { register, unregister } from "@tauri-apps/plugin-global-shortcut";
import { listen } from "@tauri-apps/api/event";
import { getKeybinds, getConfig, setVoiceMuted } from "./api";
import type { VoiceState } from "./types";

let currentPttShortcut: string | null = null;
let voiceActive = false;
let inputMode = "voice_activity";

function pttEnabled() {
  return inputMode === "push_to_talk";
}

async function registerPtt(shortcut: string) {
  if (currentPttShortcut === shortcut) return;
  await unregisterPtt();
  try {
    await register(shortcut, (event) => {
      if (event.state === "Pressed") {
        setVoiceMuted(false).catch(() => {});
      } else if (event.state === "Released") {
        setVoiceMuted(true).catch(() => {});
      }
    });
    currentPttShortcut = shortcut;
  } catch (e) {
    console.error("keybinds: failed to register PTT shortcut:", e);
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
  const [kb, config] = await Promise.all([getKeybinds(), getConfig()]);
  pttShortcut = kb.push_to_talk;
  inputMode = config.input_mode;

  listen<VoiceState>("voice-state", (event) => {
    const wasActive = voiceActive;
    voiceActive = event.payload.connected;
    if (voiceActive !== wasActive) syncPtt();
  });
}
