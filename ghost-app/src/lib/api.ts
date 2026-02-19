import { invoke } from "@tauri-apps/api/core";
import type { Identity, Group, Channel, Member, Message, Invite, Config, AudioDevices, DevSession, KeybindConfig } from "./types";

export const getIdentity = () => invoke<Identity>("get_identity");

export const listGroups = () => invoke<Group[]>("list_groups");

export const createGroup = (name: string) =>
  invoke<Group>("create_group", { name });

export const listChannels = (groupId: string) =>
  invoke<Channel[]>("list_channels", { groupId });

export const listMembers = (groupId: string) =>
  invoke<Member[]>("list_members", { groupId });

export const pinGroup = (groupId: string) =>
  invoke<void>("pin_group", { groupId });

export const unpinGroup = (groupId: string) =>
  invoke<void>("unpin_group", { groupId });

export const listPinnedGroups = () =>
  invoke<string[]>("list_pinned_groups");

export const listMessages = (channelId: string, before?: number, limit?: number) =>
  invoke<Message[]>("list_messages", { channelId, before, limit });

export const sendMessage = (groupId: string, channelId: string, content: string) =>
  invoke<Message>("send_message", { groupId, channelId, content });

export const createChannel = (groupId: string, name: string, kind: string) =>
  invoke<Channel>("create_channel", { groupId, name, kind });

export const renameChannel = (channelId: string, name: string) =>
  invoke<void>("rename_channel", { channelId, name });

export const deleteChannel = (channelId: string) =>
  invoke<void>("delete_channel", { channelId });

export const markChannelRead = (channelId: string) =>
  invoke<void>("mark_channel_read", { channelId });

export const createInvite = (groupId: string) =>
  invoke<Invite>("create_invite", { groupId });

export const joinByInvite = (relayUrl: string, token: string) =>
  invoke<Group>("join_by_invite", { relayUrl, token });

export const getConfig = () => invoke<Config>("get_config");

export const setDisplayName = (name: string) =>
  invoke<void>("set_display_name", { name });

export const setRelayUrl = (url: string) =>
  invoke<void>("set_relay_url", { url });

export const seedTestData = () => invoke<void>("seed_test_data");

// Voice
export const joinVoice = (groupId: string, channelId: string) =>
  invoke<void>("join_voice", { groupId, channelId });

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

// Audio testing
export const startMicTest = () => invoke<void>("start_mic_test");
export const stopMicTest = () => invoke<void>("stop_mic_test");
export const playTestTone = () => invoke<void>("play_test_tone");

// Keybinds
export const getKeybinds = () => invoke<KeybindConfig>("get_keybinds");
export const setKeybind = (action: string, shortcut: string | null) =>
  invoke<void>("set_keybind", { action, shortcut });

// Dev testing
export const createDevSession = () => invoke<Group>("create_dev_session");
export const readDevSession = () => invoke<DevSession | null>("read_dev_session");
