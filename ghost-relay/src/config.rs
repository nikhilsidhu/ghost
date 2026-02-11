use crate::constants::*;

pub struct Config {
    pub port: u16,
    pub max_blob_size: usize,
    pub max_memory: usize,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            port: parse_env("GHOST_PORT", DEFAULT_PORT),
            max_blob_size: parse_env("GHOST_MAX_BLOB_SIZE", DEFAULT_MAX_BLOB_SIZE),
            max_memory: parse_env("GHOST_MAX_MEMORY", DEFAULT_MAX_MEMORY),
        }
    }

    #[cfg(test)]
    pub fn test_defaults() -> Self {
        Self {
            port: 0,
            max_blob_size: DEFAULT_MAX_BLOB_SIZE,
            max_memory: DEFAULT_MAX_MEMORY,
        }
    }
}

fn parse_env<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
