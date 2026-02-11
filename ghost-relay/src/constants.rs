pub const DEFAULT_PORT: u16 = 7700;
pub const DEFAULT_MAX_BLOB_SIZE: usize = 10 * 1024 * 1024; // 10 MB
pub const DEFAULT_MAX_MEMORY: usize = 512 * 1024 * 1024; // 512 MB
pub const DEFAULT_TTL_SECS: u64 = 72 * 3600; // 72 hours
pub const DEFAULT_LONG_POLL_MS: u64 = 30_000;
pub const MAX_LONG_POLL_MS: u64 = 120_000; // 2 minutes
pub const WORKER_INTERVAL_SECS: u64 = 60;
pub const NOTIFY_CAPACITY: usize = 4;
