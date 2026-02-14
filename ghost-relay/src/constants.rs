pub const DEFAULT_PORT: u16 = 7700;
pub const DEFAULT_MAX_BLOB_SIZE: usize = 10 * 1024 * 1024; // 10 MB
pub const DEFAULT_TTL_SECS: u64 = 72 * 3600; // 72 hours
pub const DEFAULT_LONG_POLL_MS: u64 = 30_000;
pub const MAX_LONG_POLL_MS: u64 = 120_000; // 2 minutes
pub const WORKER_INTERVAL_SECS: u64 = 60;
pub const NOTIFY_CAPACITY: usize = 4;
pub const DEFAULT_READ_LIMIT: u32 = 1000;
pub const WS_PING_INTERVAL_SECS: u64 = 30;
pub const WS_FRAME_HEADER_SIZE: usize = 16; // seq(8) + received_at(8)
pub const WS_MAX_FANOUT_BATCH: u32 = 100;

// Voice / SFU
pub const DEFAULT_VOICE_PORT: u16 = 10000;
pub const DEFAULT_MAX_VOICE_PARTICIPANTS: usize = 25;
pub const VOICE_HEADER_SIZE: usize = 79; // version(1) + channel_id(32) + sender_fp(32) + seq(4) + epoch(8) + payload_len(2)
pub const VOICE_VERSION: u8 = 1;
pub const VOICE_MAX_PACKET: usize = 1500;
pub const VOICE_UDP_TIMEOUT_SECS: u64 = 30;
pub const VOICE_EVENT_CAPACITY: usize = 16;
