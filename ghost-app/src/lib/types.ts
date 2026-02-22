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
  created_at: number;
  has_unread: boolean;
}

export interface Channel {
  channel_id: string;
  server_id: string;
  name: string;
  kind: "text" | "voice";
  position: number;
  unread_count: number;
}

export interface Member {
  server_id: string;
  fingerprint: string;
  display_name: string;
  role: "creator" | "member";
  joined_at: number;
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

export interface DevSession {
  relay_url: string;
  token: string;
}

export interface KeybindConfig {
  push_to_talk: string | null;
}

export interface OnlinePresenceEvent {
  server_id: string;
  members: OnlinePresenceMember[];
}

export interface OnlinePresenceMember {
  fingerprint: string;
  status: "online" | "idle" | "away";
  status_message: string | null;
  avatar_hash: string | null;
}
