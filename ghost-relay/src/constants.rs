pub const DEFAULT_PORT: u16 = 7700;
pub const DEFAULT_MAX_BLOB_SIZE: usize = 10 * 1024 * 1024; // 10 MB
pub const DEFAULT_LONG_POLL_MS: u64 = 30_000;
pub const MAX_LONG_POLL_MS: u64 = 120_000; // 2 minutes
pub const WORKER_INTERVAL_SECS: u64 = 60;
/// Seconds between the pings a connection must answer.
pub const DEFAULT_WS_PING_SECS: u64 = 15;
/// Pings in a row a connection may leave unanswered before it is dead.
pub const WS_MISSED_PONGS: u32 = 2;
/// How long a connection the relay closes waits for the device to answer the close frame
/// before the socket goes anyway.
pub const WS_CLOSE_WAIT_SECS: u64 = 2;
/// Seconds a device's presence outlives a connection that ended without a close frame,
/// so a blip shows nothing and a device that comes back replaces itself silently.
pub const DEFAULT_PRESENCE_GRACE_SECS: u64 = 30;
/// Log entries read per page when a WebSocket catches up from the log.
pub const WS_CATCHUP_PAGE: u32 = 100;
/// Committed entries a slow WebSocket may fall behind before it re-reads the log.
pub const FRAME_FANOUT_CAPACITY: usize = 256;
/// Voice state announcements a slow WebSocket may fall behind before it is sent the
/// mailbox's voice snapshot again.
pub const VOICE_FANOUT_CAPACITY: usize = 16;
/// Online presence announcements a slow WebSocket may fall behind before it is sent the
/// mailbox's online snapshot again.
pub const PRESENCE_FANOUT_CAPACITY: usize = 32;
/// Private channel admissions a slow WebSocket may fall behind on.
pub const CHANNELS_FANOUT_CAPACITY: usize = 32;

// Voice relay
pub const DEFAULT_VOICE_PORT: u16 = 10000;
pub const DEFAULT_MAX_VOICE_PARTICIPANTS: usize = 25;
pub const VOICE_UDP_TIMEOUT_SECS: u64 = 30;
pub const VOICE_EVENT_CAPACITY: usize = 16;
pub const MAX_PRESENCE_BLOB_SIZE: usize = 2048;
pub const PRESENCE_RATE_LIMIT: u32 = 2;
pub const SPEAKING_RATE_LIMIT: u32 = 20;
/// Reception reports a voice connection may send per second; clients send one every 2 s.
pub const RECEPTION_RATE_LIMIT: u32 = 1;

// Log retention
pub const DEFAULT_LOG_RETENTION_HOURS: u64 = 72; // 3 days
pub const DEFAULT_LOG_MIN_ENTRIES: u64 = 100; // keep at least this many per mailbox

// Avatar blob storage
pub const MAX_AVATAR_SIZE: usize = 512 * 1024; // 512 KB

// Multi-relay: how often a mirror pulls new identity log entries from each account's home
pub const DEFAULT_MIRROR_REFRESH_SECS: u64 = 30;
/// How long a mirror grant lasts unless a device of the account names the relay again;
/// each device's account check does every few minutes while it runs, so a relay no
/// device knows any more stops being pushed to and pulling within a week.
pub const MIRROR_GRANT_TTL_MS: u64 = 7 * 24 * 3600 * 1000;
pub const MIRROR_FETCH_TIMEOUT_SECS: u64 = 10;

// Invites
/// Longest an invite may stay open, whatever expiry the creator asks for.
pub const MAX_INVITE_LIFETIME_MS: u64 = 72 * 3600 * 1000;

// Per-address limits, for what happens before anyone has authenticated
/// Signatures that fail to verify before the address is refused for the minute.
pub const AUTH_FAILURES_PER_MINUTE: usize = 30;
/// Requests without credentials that validate or store something, per address.
pub const UNAUTHENTICATED_PER_MINUTE: usize = 60;

// Bodies
/// Largest key set push or response: every generation an account has had, each
/// at most `ACCOUNT_KEY_SET_MAX_BYTES`.
pub const MAX_KEY_SETS_BODY: usize = 1024 * 1024;

// Federation
/// Relays spoken to at once when pushing to or pulling from other relays.
pub const FEDERATION_CONCURRENCY: usize = 8;
