use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeybindConfig {
    pub push_to_talk: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GhostConfig {
    pub display_name: Option<String>,
    pub relay_url: Option<String>,
    pub input_device: Option<String>,
    pub output_device: Option<String>,
    pub noise_suppression: Option<String>,
    pub agc: Option<String>,
    pub input_mode: Option<String>,
    pub vad_threshold: Option<f32>,
    pub input_gain: Option<f32>,
    pub keybinds: Option<KeybindConfig>,
    pub status: Option<String>,
    pub status_message: Option<String>,
    pub status_expiry: Option<u64>,
}

impl GhostConfig {
    pub fn noise_suppression_mode(&self) -> crate::audio::NoiseSuppressionMode {
        match self.noise_suppression.as_deref() {
            Some("off") => crate::audio::NoiseSuppressionMode::Off,
            _ => crate::audio::NoiseSuppressionMode::Nnnoiseless,
        }
    }

    pub fn agc_mode(&self) -> crate::audio::AgcMode {
        match self.agc.as_deref() {
            Some("off") => crate::audio::AgcMode::Off,
            _ => crate::audio::AgcMode::Auto,
        }
    }

    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let content = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(path, content).map_err(|e| e.to_string())
    }
}

pub fn config_path(ghost_dir: &Path) -> PathBuf {
    ghost_dir.join("config.toml")
}
