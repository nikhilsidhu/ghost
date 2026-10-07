export interface Identity {
  fingerprint: string;
  fingerprint_short: string;
  display_name: string;
}

export interface Server {
  server_id: string;
  name: string;
  kind: "server" | "group" | "dm";
  creator_fp: string;
  /** Owner under the server's policy, who may do everything. */
  owner_fp: string;
  /** This account's permission bits in the server (see PERMISSIONS). */
  permissions: number;
  created_at: number;
  has_unread: boolean;
}

/** Permission bits of a server policy; must match ghost-wire's policy module. */
export const PERMISSIONS = {
  invite: 1,
  kick: 2,
  manageChannels: 4,
  manageRoles: 8,
} as const;
export const ALL_PERMISSIONS = 15;

export interface Role {
  id: number;
  name: string;
  permissions: number;
}

export interface RoleAssignment {
  fingerprint: string;
  roles: number[];
}

/** A server's policy with role names; roles are listed by rank, highest first. */
export interface ServerPolicy {
  owner_fp: string;
  everyone: number;
  roles: Role[];
  assignments: RoleAssignment[];
}

export interface ServerRoles {
  policy: ServerPolicy;
  my_permissions: number;
  /** False while the server still runs under the implicit policy of an old group. */
  explicit: boolean;
  /** Members whose app must update before the server can have roles. */
  members_missing_support: string[];
}

/** Who a private channel admits besides the server's channel managers. */
export interface ChannelAccess {
  roles: number[];
  accounts: string[];
}

export interface Channel {
  channel_id: string;
  server_id: string;
  name: string;
  kind: "text" | "voice";
  position: number;
  unread_count: number;
  /** Only members its access list admits can see it. */
  private: boolean;
}

export interface Member {
  server_id: string;
  fingerprint: string;
  display_name: string;
  role: "creator" | "member";
  joined_at: number;
  /** Ids of the server roles assigned to this member, highest first. */
  roles: number[];
}

export interface Invite {
  token: string;
  link: string;
}

export interface Config {
  display_name: string | null;
  relay_url: string | null;
  input_device: string | null;
  output_device: string | null;
  noise_suppression: string;
  agc: string;
  input_mode: string;
  vad_threshold: number;
  input_gain: number;
  status: string;
  status_message: string | null;
}

export interface AudioDevices {
  inputs: string[];
  outputs: string[];
  default_input: string | null;
  default_output: string | null;
}

export interface Message {
  message_id: string;
  channel_id: string;
  sender_fp: string;
  message_type: number;
  timestamp: number;
  received_at: number;
  content: string;
}

export interface VoiceState {
  connected: boolean;
  server_id: string | null;
  channel_id: string | null;
  muted: boolean;
  deafened: boolean;
  udp_port: number | null;
}

export interface VoiceParticipants {
  participants: string[];
}

export interface VoiceSpeaking {
  fingerprint: string;
  speaking: boolean;
}

export interface VoiceMuteState {
  fingerprint: string;
  muted: boolean;
  deafened: boolean;
}

export interface VoiceQuality {
  packet_loss: number;
  jitter_depth: number;
  jitter_target: number;
  ping_ms: number | null;
}

export interface KeybindConfig {
  push_to_talk: string | null;
}

export interface Device {
  device_key: string;
  label: string;
  added_at_seq: number;
  is_active: boolean;
  is_current: boolean;
}

export interface OnlinePresenceEvent {
  server_id: string;
  members: OnlinePresenceMember[];
}

export interface OnlinePresenceMember {
  fingerprint: string;
  status: "online" | "idle" | "away" | "offline";
  status_message: string | null;
  avatar_hash: string | null;
}
