import { invoke } from "./invoke";
import type {
  Identity, Server, Channel, Member, Message, Invite, Config, AudioDevice, AudioDevices, KeybindConfig, Device, ServerRoles, ServerPolicy,
  ChannelAccess, KeptOut, ChannelKind, NoiseSuppression, Agc, InputMode, OnlineStatus, LiveState, ProfileReach,
} from "./types";

export const getIdentity = () => invoke<Identity>("get_identity");

/** What the session reported before the listeners were up. */
export const liveState = () => invoke<LiveState>("live_state");

/** The user acted in this window; an idle device comes back online at once. */
export const noteActivity = () => invoke<void>("note_activity");

/** The user dismissed an account alert. */
export const dismissAccountAlert = (id: number) => invoke<void>("dismiss_alert", { id });

/** Whether going idle mutes a call. */
export const setAutoMuteOnIdle = (enabled: boolean) => invoke<void>("set_auto_mute_on_idle", { enabled });
export const setEchoCancellation = (enabled: boolean) => invoke<void>("set_echo_cancellation", { enabled });

export const listServers = () => invoke<Server[]>("list_servers");

export const createServer = (name: string) =>
  invoke<Server>("create_server", { name });

export const createDm = (name: string) =>
  invoke<Server>("create_dm", { name });

export const listChannels = (serverId: string) =>
  invoke<Channel[]>("list_channels", { serverId });

export const listMembers = (serverId: string) =>
  invoke<Member[]>("list_members", { serverId });

export const saveServerOrder = (order: string[]) =>
  invoke<void>("save_server_order", { order });

export const getServerOrder = () =>
  invoke<string[]>("get_server_order");

export const listMessages = (channelId: string, before?: number, limit?: number) =>
  invoke<Message[]>("list_messages", { channelId, before, limit });

export const retryMessage = (messageId: string) =>
  invoke<Message>("retry_message", { messageId });

export const sendMessage = (serverId: string, channelId: string, content: string) =>
  invoke<Message>("send_message", { serverId, channelId, content });

export const createChannel = (serverId: string, name: string, kind: ChannelKind) =>
  invoke<Channel>("create_channel", { serverId, name, kind });

export const renameChannel = (channelId: string, name: string) =>
  invoke<void>("rename_channel", { channelId, name });

export const deleteChannel = (channelId: string) =>
  invoke<void>("delete_channel", { channelId });
/** The server's channels in the order given, for everyone; needs the manage channels permission. */
export const reorderChannels = (serverId: string, channelIds: string[]) =>
  invoke<void>("reorder_channels", { serverId, channelIds });

/** Resolves to whether the member is also kept from rejoining. */
export const kickMember = (serverId: string, fingerprint: string) =>
  invoke<void>("kick_member", { serverId, fingerprint });

export const keptOut = (serverId: string) =>
  invoke<KeptOut[]>("kept_out", { serverId });

export const letBackIn = (serverId: string, fingerprint: string) =>
  invoke<void>("let_back_in", { serverId, fingerprint });

/** Drop a server this account was removed from, or stopped following, with its history. */
export const forgetServer = (serverId: string) =>
  invoke<void>("forget_server", { serverId });

/** Take the relay's version of a halted server after all. */
export const acceptRelayState = (serverId: string) =>
  invoke<void>("accept_relay_state", { serverId });

/** A channel only the given roles and accounts (and channel managers) can see. */
export const createPrivateChannel = (serverId: string, name: string, kind: ChannelKind, roles: number[], accounts: string[]) =>
  invoke<Channel>("create_private_channel", { serverId, name, kind, roles, accounts });

/** Resolves to null for a public channel. */
export const getChannelAccess = (channelId: string) =>
  invoke<ChannelAccess | null>("get_channel_access", { channelId });

export const setChannelAccess = (channelId: string, access: ChannelAccess) =>
  invoke<void>("set_channel_access", { channelId, access });

export const getServerRoles = (serverId: string) =>
  invoke<ServerRoles>("get_server_roles", { serverId });

/** Replace roles, assignments, everyone permissions or owner; the relay and members check it. */
export const setServerRoles = (serverId: string, policy: ServerPolicy) =>
  invoke<void>("set_server_roles", { serverId, policy });

export const markChannelRead = (channelId: string) =>
  invoke<void>("mark_channel_read", { channelId });

export const createInvite = (serverId: string) =>
  invoke<Invite>("create_invite", { serverId });

/** Move a server you created to another relay; resolves to a move link for members. */
export const moveServer = (serverId: string, relayUrl: string) =>
  invoke<string>("move_server", { serverId, relayUrl });
/** Follow a move link from a server's creator; resolves true if this device moved. */
export const followServerMove = (link: string) =>
  invoke<boolean>("follow_server_move", { link });
/** `key` (the link's `k` parameter) opens the sealed invite; `relayRef` (its `r`
 *  parameter) pins the relay's key when present. */
export const joinByInvite = (relayUrl: string, token: string, key: string, relayRef?: string | null) =>
  invoke<Server>("join_by_invite", { relayUrl, token, key, relayRef: relayRef ?? null });

export const getConfig = () => invoke<Config>("get_config");

/** How many of the account's servers heard the new name now; the rest hear it later. */
export const setDisplayName = (name: string) =>
  invoke<ProfileReach>("set_display_name", { name });

/** Connect to the account's home relay at another address; refused for a relay that is not the home. */
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
export const setInputDevice = (device: AudioDevice | null) =>
  invoke<void>("set_input_device", { device });
export const setOutputDevice = (device: AudioDevice | null) =>
  invoke<void>("set_output_device", { device });

// Voice processing
export const setNoiseSuppression = (mode: NoiseSuppression) =>
  invoke<void>("set_noise_suppression", { mode });
export const setAgc = (mode: Agc) =>
  invoke<void>("set_agc", { mode });

// Input mode
export const setInputMode = (mode: InputMode) =>
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
export const setStatus = (status: OnlineStatus) =>
  invoke<void>("set_status", { status });
export const setStatusMessage = (message: string | null, expiry: number | null) =>
  invoke<void>("set_status_message", { message, expiry });

// Avatars
/** The image bytes as the user cropped them, in any format a browser shows. */
export const uploadAvatar = (image: Uint8Array) =>
  invoke<ProfileReach>("upload_avatar", image);
export const clearAvatar = () =>
  invoke<ProfileReach>("clear_avatar");
/** Raw image bytes; empty when no avatar is cached. */
export const getCachedAvatar = (fingerprintHex: string) =>
  invoke<ArrayBuffer>("get_cached_avatar", { fingerprintHex });

// Devices
import type { AccountAlert, AccountStatus, DeviceList, KeyCheck, PairingStatus, RecoveryOutcome, RevokeOutcome, UnfinishedOutcome } from "./types";
export type { AccountAlert };

export const getDevices = () => invoke<DeviceList>("get_devices");
export const revokeDevice = (deviceKeyHex: string) =>
  invoke<RevokeOutcome>("revoke_device", { deviceKeyHex });
/** Give a device of this account the label its list shows, recorded in the identity log. */
export const renameDevice = (deviceKeyHex: string, label: string) =>
  invoke<void>("rename_device", { deviceKeyHex, label });

// Account: where this device stands, and making an account (the recovery key is shown,
// then typed back, before anything is sent). `deviceLabel` names this device in the
// account's device list; empty means the machine's name.
export const getAccountStatus = () => invoke<AccountStatus>("get_account_status");
export const beginCreateAccount = (displayName: string, relayUrl: string, deviceLabel: string) =>
  invoke<string>("begin_create_account", { displayName, relayUrl, deviceLabel });
export const confirmNewAccount = (typed: string) => invoke<void>("confirm_new_account", { typed });
export const cancelCreateAccount = () => invoke<void>("cancel_create_account");

// Pairing, existing device: start, poll, confirm the codes match
export const startPairing = () => invoke<string>("start_pairing");
export const checkPairing = () => invoke<PairingStatus>("check_pairing");
export const confirmPairing = () => invoke<void>("confirm_pairing");
export const cancelPairing = () => invoke<void>("cancel_pairing");
// Pairing, new device
export const joinAsNewDevice = (pairingCode: string, deviceLabel: string) =>
  invoke<string>("join_as_new_device", { pairingCode, deviceLabel });

// Recovery: find the account, show the new key, type it back, recover
export const beginRecovery = (recoveryKey: string, relayUrl: string, deviceLabel: string) =>
  invoke<string>("begin_recovery", { recoveryKey, relayUrl, deviceLabel });
export const confirmRecovery = (typed: string) => invoke<RecoveryOutcome>("confirm_recovery", { typed });
export const recoverThroughRelay = () => invoke<RecoveryOutcome>("recover_through_relay");
/** Finish an account this device was making when the app last closed, if its relay holds it. */
export const resumeUnfinishedAccount = () => invoke<UnfinishedOutcome>("resume_unfinished_account");
export const cancelRecovery = () => invoke<void>("cancel_recovery");

// Recovery key: check or replace
export const checkRecoveryKey = (recoveryKey: string) => invoke<KeyCheck>("check_recovery_key", { recoveryKey });
export const beginReplaceRecoveryKey = (current: string) =>
  invoke<string>("begin_replace_recovery_key", { current });
export const confirmNewRecoveryKey = (typed: string) => invoke<void>("confirm_new_recovery_key", { typed });
export const cancelNewRecoveryKey = () => invoke<void>("cancel_new_recovery_key");

// Home relay, and forgetting a removed device's account
export const moveHome = (recoveryKey: string, relayUrl: string) =>
  invoke<void>("move_home", { recoveryKey, relayUrl });
export const resetDevice = () => invoke<void>("reset_device");

// Debug builds only: the command exists nowhere else.
export const getDevProfile = () => invoke<string | null>("dev_profile");

// Devtools builds only: the command exists nowhere else.
export const openProfiler = (capture = false) => invoke<void>("devtools_open_profiler", { capture });
