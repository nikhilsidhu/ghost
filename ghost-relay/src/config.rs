use crate::constants::*;

pub struct Config {
    pub port: u16,
    pub max_blob_size: usize,
    pub voice_port: u16,
    pub max_voice_participants: usize,
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
        }
    }
}

fn parse_env<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
