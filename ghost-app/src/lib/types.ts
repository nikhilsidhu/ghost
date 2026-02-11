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
}

export interface Channel {
  channel_id: string;
  group_id: string;
  name: string;
  kind: "text" | "voice";
  position: number;
}

export interface Member {
  group_id: string;
  fingerprint: string;
  display_name: string;
  role: "creator" | "member";
  joined_at: number;
}
