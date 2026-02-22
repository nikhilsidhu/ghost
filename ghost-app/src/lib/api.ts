import { invoke } from "@tauri-apps/api/core";
import type { Identity, Server, Channel, Member, Message, Invite, Config, AudioDevices, DevSession, KeybindConfig } from "./types";

export const getIdentity = () => invoke<Identity>("get_identity");

export const listServers = () => invoke<Server[]>("list_servers");

export const createServer = (name: string) =>
  invoke<Server>("create_server", { name });

export const createDm = (name: string) =>
  invoke<Server>("create_dm", { name });

export const listChannels = (serverId: string) =>
  invoke<Channel[]>("list_channels", { serverId });

export const listMembers = (serverId: string) =>
  invoke<Member[]>("list_members", { serverId });

export const pinServer = (serverId: string) =>
  invoke<void>("pin_server", { serverId });

export const unpinServer = (serverId: string) =>
  invoke<void>("unpin_server", { serverId });

export const listPinnedServers = () =>
  invoke<string[]>("list_pinned_servers");

export const listMessages = (channelId: string, before?: number, limit?: number) =>
  invoke<Message[]>("list_messages", { channelId, before, limit });

export const sendMessage = (serverId: string, channelId: string, content: string) =>
  invoke<Message>("send_message", { serverId, channelId, content });

export const createChannel = (serverId: string, name: string, kind: string) =>
  invoke<Channel>("create_channel", { serverId, name, kind });

export const renameChannel = (channelId: string, name: string) =>
  invoke<void>("rename_channel", { channelId, name });

export const deleteChannel = (channelId: string) =>
  invoke<void>("delete_channel", { channelId });

export const kickMember = (serverId: string, fingerprint: string) =>
  invoke<void>("kick_member", { serverId, fingerprint });

export const markChannelRead = (channelId: string) =>
  invoke<void>("mark_channel_read", { channelId });

export const createInvite = (serverId: string) =>
  invoke<Invite>("create_invite", { serverId });

export const joinByInvite = (relayUrl: string, token: string) =>
  invoke<Server>("join_by_invite", { relayUrl, token });

export const getConfig = () => invoke<Config>("get_config");

export const setDisplayName = (name: string) =>
  invoke<void>("set_display_name", { name });

export const setRelayUrl = (url: string) =>
  invoke<void>("set_relay_url", { url });

// Voice
export const joinVoice = (serverId: string, channelId: string, muted: boolean, deafened: boolean) =>
  invoke<void>("join_voice", { serverId, channelId, muted, deafened });

export const leaveVoice = () => invoke<void>("leave_voice");

export const setVoiceMuted = (muted: boolean) =>
  invoke<void>("set_muted", { muted });

export const setVoiceDeafened = (deafened: boolean) =>
  invoke<void>("set_deafened", { deafened });

// Audio devices
export const listAudioDevices = () => invoke<AudioDevices>("list_audio_devices");
export const setInputDevice = (name: string | null) =>
  invoke<void>("set_input_device", { name });
export const setOutputDevice = (name: string | null) =>
  invoke<void>("set_output_device", { name });

// Voice processing
export const setNoiseSuppression = (mode: string) =>
  invoke<void>("set_noise_suppression", { mode });
export const setAgc = (mode: string) =>
  invoke<void>("set_agc", { mode });

// Input mode
export const setInputMode = (mode: string) =>
  invoke<void>("set_input_mode", { mode });
export const setPttActive = (active: boolean) =>
  invoke<void>("set_ptt_active", { active });

// Voice tuning
export const setVadThreshold = (value: number) =>
  invoke<void>("set_vad_threshold", { value });
export const setInputGain = (value: number) =>
  invoke<void>("set_input_gain", { value });

// Audio testing
export const startMicTest = () => invoke<void>("start_mic_test");
export const stopMicTest = () => invoke<void>("stop_mic_test");
export const playTestTone = () => invoke<void>("play_test_tone");

// Keybinds
export const getKeybinds = () => invoke<KeybindConfig>("get_keybinds");
export const setKeybind = (action: string, shortcut: string | null) =>
  invoke<void>("set_keybind", { action, shortcut });

// Online presence
export const setStatus = (status: string) =>
  invoke<void>("set_status", { status });
export const setStatusMessage = (message: string | null, expiry: number | null) =>
  invoke<void>("set_status_message", { message, expiry });

// Dev testing
export const createDevSession = () => invoke<Server>("create_dev_session");
export const readDevSession = () => invoke<DevSession | null>("read_dev_session");
