use std::net::IpAddr;

use crate::constants::*;

pub struct Config {
    pub port: u16,
    pub max_blob_size: usize,
    pub voice_port: u16,
    /// UDP port clients are told to send voice to, when it differs from `voice_port`
    /// (the relay sits behind a port mapping or a forwarder).
    pub voice_public_port: Option<u16>,
    pub max_voice_participants: usize,
    pub db_path: Option<String>,
    pub log_retention_hours: u64,
    pub log_min_entries: u64,
    /// Base URL clients reach this relay at, advertised in its RelayRef.
    pub public_url: Option<String>,
    /// Seconds between pulls of mirrored accounts' logs from their home relays.
    pub mirror_refresh_secs: u64,
    /// Proxies in front of this relay whose `X-Forwarded-For` names the real client.
    /// Empty when clients connect directly.
    pub trusted_proxies: Vec<IpAddr>,
    /// Seconds between the pings a mailbox connection must answer; two unanswered end it.
    pub ws_ping_secs: u64,
    /// Seconds a device stays present after its connection ended without a close frame.
    pub presence_grace_secs: u64,
    /// Tests only: accept commits without judging them under the group's policy, as a
    /// dishonest relay would. Never read from the environment.
    pub skip_policy_checks_for_tests: bool,
    /// Tests only: devices this relay refuses as revoked whatever the log says, as a
    /// stale or dishonest relay would. Shared so a test can add one while the relay runs.
    pub revoked_devices_for_tests: std::sync::Arc<std::sync::RwLock<std::collections::HashSet<[u8; 32]>>>,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            port: parse_env("GHOST_PORT", DEFAULT_PORT),
            max_blob_size: parse_env("GHOST_MAX_BLOB_SIZE", DEFAULT_MAX_BLOB_SIZE),
            voice_port: parse_env("GHOST_VOICE_PORT", DEFAULT_VOICE_PORT),
            voice_public_port: std::env::var("GHOST_VOICE_PUBLIC_PORT").ok().and_then(|v| v.parse().ok()),
            max_voice_participants: parse_env(
                "GHOST_MAX_VOICE_PARTICIPANTS",
                DEFAULT_MAX_VOICE_PARTICIPANTS,
            ),
            db_path: std::env::var("GHOST_DB_PATH").ok(),
            log_retention_hours: parse_env("GHOST_LOG_RETENTION_HOURS", DEFAULT_LOG_RETENTION_HOURS),
            log_min_entries: parse_env("GHOST_LOG_MIN_ENTRIES", DEFAULT_LOG_MIN_ENTRIES),
            public_url: std::env::var("GHOST_PUBLIC_URL").ok(),
            mirror_refresh_secs: parse_env("GHOST_MIRROR_REFRESH_SECS", DEFAULT_MIRROR_REFRESH_SECS),
            trusted_proxies: std::env::var("GHOST_TRUSTED_PROXIES")
                .ok()
                .map(|list| list.split(',').filter_map(|ip| ip.trim().parse().ok()).collect())
                .unwrap_or_default(),
            ws_ping_secs: parse_env("GHOST_WS_PING_SECS", DEFAULT_WS_PING_SECS),
            presence_grace_secs: parse_env("GHOST_PRESENCE_GRACE_SECS", DEFAULT_PRESENCE_GRACE_SECS),
            skip_policy_checks_for_tests: false,
            revoked_devices_for_tests: Default::default(),
        }
    }
}

fn parse_env<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
