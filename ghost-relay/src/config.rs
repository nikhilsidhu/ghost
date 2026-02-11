use std::time::Duration;

pub struct Config {
    pub port: u16,
    pub ttl: Duration,
    pub max_blob_size: usize,
    pub max_memory: usize,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            port: parse_env("GHOST_PORT", 7700),
            ttl: Duration::from_secs(parse_env("GHOST_TTL_SECS", 72 * 3600)),
            max_blob_size: parse_env("GHOST_MAX_BLOB_SIZE", 10 * 1024 * 1024),
            max_memory: parse_env("GHOST_MAX_MEMORY", 512 * 1024 * 1024),
        }
    }

    #[cfg(test)]
    pub fn test_defaults() -> Self {
        Self {
            port: 0,
            ttl: Duration::from_secs(72 * 3600),
            max_blob_size: 10 * 1024 * 1024,
            max_memory: 512 * 1024 * 1024,
        }
    }
}

fn parse_env<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
