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
    pub fn noise_suppression_mode(&self) -> ghost_audio::NoiseSuppressionMode {
        ghost_audio::NoiseSuppressionMode::from_config(self.noise_suppression.as_deref().unwrap_or_default())
    }

    pub fn agc_mode(&self) -> ghost_audio::AgcMode {
        ghost_audio::AgcMode::from_config(self.agc.as_deref().unwrap_or_default())
    }

    pub fn input_mode(&self) -> ghost_audio::InputMode {
        ghost_audio::InputMode::from_config(self.input_mode.as_deref().unwrap_or_default())
    }

    pub fn vad_threshold(&self) -> f32 {
        self.vad_threshold.unwrap_or(ghost_audio::constants::VAD_THRESHOLD)
    }

    pub fn device_choice(&self) -> crate::audio::DeviceChoice {
        crate::audio::DeviceChoice { input: self.input_device.clone(), output: self.output_device.clone() }
    }

    /// Put the configured processing settings into effect.
    pub fn apply_audio(&self, audio: &ghost_audio::VoiceAudio) {
        audio.set_noise_suppression(self.noise_suppression_mode());
        audio.set_agc(self.agc_mode());
        audio.set_vad_threshold(self.vad_threshold());
        audio.set_input_gain(self.input_gain.unwrap_or(1.0));
        audio.set_input_mode(self.input_mode());
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
