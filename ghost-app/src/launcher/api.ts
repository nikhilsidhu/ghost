// The Ghost Dev launcher's commands, as its page calls them.

import { invoke } from "@tauri-apps/api/core";
import type { CallView } from "./generated/CallView";
import type { LauncherView } from "./generated/LauncherView";
import type { NetworkView } from "./generated/NetworkView";
import type { Preview } from "./generated/Preview";
import type { Sizes } from "./generated/Sizes";
import type { Voice } from "./generated/Voice";

export const launcherView = () => invoke<LauncherView>("launcher_view");
export const processLog = (process: string) => invoke<string[]>("process_log", { process });
export const rebuild = () => invoke<void>("rebuild");

export const relayStart = (name: string) => invoke<void>("relay_start", { name });
export const relayStop = (name: string) => invoke<void>("relay_stop", { name });
export const relayReset = (name: string) => invoke<void>("relay_reset", { name });

export const profileAdd = (name: string, relay: string) => invoke<void>("profile_add", { name, relay });
export const profileRemove = (name: string) => invoke<void>("profile_remove", { name });
export const profileStart = (name: string) => invoke<void>("profile_start", { name });
export const profileStop = (name: string) => invoke<void>("profile_stop", { name });
export const profileReset = (name: string) => invoke<void>("profile_reset", { name });
export const profileWindow = (name: string, cmd: "focus" | "open_profiler") => invoke<void>("profile_window", { name, cmd });
export const windowsTile = () => invoke<void>("windows_tile");

export const callView = (profile: string) => invoke<CallView>("call_view", { profile });
export const setNetwork = (relay: string, slot: number, network: NetworkView) => invoke<void>("set_network", { relay, slot, network });
export const callerAdd = (profile: string, relay: string, voice: Voice) => invoke<number>("caller_add", { profile, relay, voice });
export const callerVoice = (id: number, voice: Voice) => invoke<void>("caller_voice", { id, voice });
export const callerRemove = (id: number) => invoke<void>("caller_remove", { id });

export const blueprintUse = (id: string, sizes: Sizes | null) => invoke<void>("blueprint_use", { id, sizes });
export const blueprintPreview = (id: string, sizes: Sizes) => invoke<Preview>("blueprint_preview", { id, sizes });
export const blueprintSave = (name: string) => invoke<void>("blueprint_save", { name });
export const blueprintDelete = (id: string) => invoke<void>("blueprint_delete", { id });

/** Sent with each line a process writes. */
export const LOG_EVENT = "launcher-log";
/** Sent when a process starts or stops, or anything else shown changes. */
export const CHANGED_EVENT = "launcher-changed";
