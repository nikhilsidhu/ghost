use crate::constants::*;

pub struct Config {
    pub port: u16,
    pub max_blob_size: usize,
    pub voice_port: u16,
    pub max_voice_participants: usize,
    pub db_path: Option<String>,
    pub log_retention_hours: u64,
    pub log_min_entries: u64,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            port: parse_env("GHOST_PORT", DEFAULT_PORT),
            max_blob_size: parse_env("GHOST_MAX_BLOB_SIZE", DEFAULT_MAX_BLOB_SIZE),
            voice_port: parse_env("GHOST_VOICE_PORT", DEFAULT_VOICE_PORT),
            max_voice_participants: parse_env(
                "GHOST_MAX_VOICE_PARTICIPANTS",
                DEFAULT_MAX_VOICE_PARTICIPANTS,
            ),
            db_path: std::env::var("GHOST_DB_PATH").ok(),
            log_retention_hours: parse_env("GHOST_LOG_RETENTION_HOURS", DEFAULT_LOG_RETENTION_HOURS),
            log_min_entries: parse_env("GHOST_LOG_MIN_ENTRIES", DEFAULT_LOG_MIN_ENTRIES),
        }
    }
}

fn parse_env<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
