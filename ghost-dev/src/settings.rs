//! The launcher's saved settings: which relays it runs, on which ports, and which
//! profiles exist with their home relays.

use serde::{Deserialize, Serialize};

use crate::paths;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelaySettings {
    pub name: String,
    pub port: u16,
    pub voice_port: u16,
}

impl RelaySettings {
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSettings {
    pub name: String,
    /// The relay a new account registers on; it stays its home until a reset.
    pub relay: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub relays: Vec<RelaySettings>,
    pub profiles: Vec<ProfileSettings>,
}

impl Default for Settings {
    /// Relay A on the relay's own default ports, so an app started by hand finds it too,
    /// and relay B beside it for testing across relays.
    fn default() -> Self {
        let relay = |name: &str, port, voice_port| RelaySettings { name: name.into(), port, voice_port };
        let profile = |name: &str| ProfileSettings { name: name.into(), relay: "A".into() };
        Self { relays: vec![relay("A", 7700, 10000), relay("B", 7701, 10001)], profiles: vec![profile("alice"), profile("bob")] }
    }
}

impl Settings {
    pub fn load() -> Self {
        std::fs::read(paths::settings()).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        std::fs::create_dir_all(paths::home()).map_err(|e| e.to_string())?;
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(paths::settings(), json).map_err(|e| e.to_string())
    }

    pub fn relay(&self, name: &str) -> Result<&RelaySettings, String> {
        self.relays.iter().find(|relay| relay.name == name).ok_or_else(|| format!("no relay {name}"))
    }

    /// The relay whose URL is `url`, by port.
    pub fn relay_at(&self, url: &str) -> Option<&RelaySettings> {
        self.relays.iter().find(|relay| url.trim_end_matches('/').ends_with(&format!(":{}", relay.port)))
    }

    pub fn profile(&self, name: &str) -> Result<&ProfileSettings, String> {
        self.profiles.iter().find(|profile| profile.name == name).ok_or_else(|| format!("no profile {name}"))
    }
}
