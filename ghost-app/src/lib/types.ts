export interface Identity {
  fingerprint: string;
  fingerprint_short: string;
  display_name: string;
}

export interface Group {
  group_id: string;
  name: string;
  creator_fp: string;
  created_at: number;
  has_unread: boolean;
}

export interface Channel {
  channel_id: string;
  group_id: string;
  name: string;
  kind: "text" | "voice";
  position: number;
  unread_count: number;
}

export interface Member {
  group_id: string;
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
