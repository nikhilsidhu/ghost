// Command results and event payloads, generated from the Rust types the backend sends
// (`ghost-app/src-tauri/src/bindings.rs`). Regenerate with `cargo test -p ghost-app bindings`.
export type { Identity } from "./generated/Identity";
export type { Server } from "./generated/Server";
export type { Channel } from "./generated/Channel";
export type { Member } from "./generated/Member";
export type { Role } from "./generated/Role";
export type { RoleAssignment } from "./generated/RoleAssignment";
export type { ServerPolicy } from "./generated/ServerPolicy";
export type { ServerRoles } from "./generated/ServerRoles";
export type { ChannelAccess } from "./generated/ChannelAccess";
export type { Message } from "./generated/Message";
export type { Invite } from "./generated/Invite";
export type { Config } from "./generated/Config";
export type { KeybindConfig } from "./generated/KeybindConfig";
export type { Device } from "./generated/Device";
export type { AudioDevices } from "./generated/AudioDevices";
export type { VoiceState } from "./generated/VoiceState";
export type { VoiceParticipants } from "./generated/VoiceParticipants";
export type { VoiceSpeaking } from "./generated/VoiceSpeaking";
export type { VoiceMuteState } from "./generated/VoiceMuteState";
export type { VoiceQuality } from "./generated/VoiceQuality";
export type { VoiceChannelMembers } from "./generated/VoiceChannelMembers";
export type { VoiceChannelMember } from "./generated/VoiceChannelMember";
export type { OnlinePresenceEvent } from "./generated/OnlinePresenceEvent";
export type { OnlinePresenceMember } from "./generated/OnlinePresenceMember";

/** Permission bits of a server policy; must match ghost-wire's policy module
 *  (constants are not generated, only types). */
export const PERMISSIONS = {
  invite: 1,
  kick: 2,
  manageChannels: 4,
  manageRoles: 8,
} as const;
export const ALL_PERMISSIONS = 15;
