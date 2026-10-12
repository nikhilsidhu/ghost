use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::dto::{AgcDto, InputModeDto, NoiseSuppressionDto, OnlineStatusDto};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeybindConfig {
    pub push_to_talk: Option<String>,
}

/// This device's settings, kept in `config.toml` in the data directory. The settings
/// shared between an account's devices are also carried by sync; the relay URL and the
/// audio devices are this device's alone.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GhostConfig {
    pub display_name: Option<String>,
    pub relay_url: Option<String>,
    pub input_device: Option<String>,
    pub output_device: Option<String>,
    pub noise_suppression: Option<NoiseSuppressionDto>,
    pub agc: Option<AgcDto>,
    pub input_mode: Option<InputModeDto>,
    pub vad_threshold: Option<f32>,
    pub input_gain: Option<f32>,
    pub keybinds: Option<KeybindConfig>,
    /// Whether going idle mutes a call; on unless turned off.
    pub auto_mute_on_idle: Option<bool>,
    /// The status the user chose; never idle, which follows inactivity.
    pub status: Option<OnlineStatusDto>,
    pub status_message: Option<String>,
    pub status_expiry: Option<u64>,
}

impl GhostConfig {
    pub fn noise_suppression(&self) -> NoiseSuppressionDto {
        self.noise_suppression.unwrap_or_default()
    }

    pub fn agc(&self) -> AgcDto {
        self.agc.unwrap_or_default()
    }

    pub fn input_mode(&self) -> InputModeDto {
        self.input_mode.unwrap_or_default()
    }

    pub fn status(&self) -> OnlineStatusDto {
        self.status.unwrap_or_default()
    }

    pub fn auto_mute_on_idle(&self) -> bool {
        self.auto_mute_on_idle.unwrap_or(true)
    }

    pub fn vad_threshold(&self) -> f32 {
        self.vad_threshold.unwrap_or(ghost_audio::constants::VAD_THRESHOLD)
    }

    pub fn input_gain(&self) -> f32 {
        self.input_gain.unwrap_or(1.0)
    }

    /// Forget what belonged to the account this device was in, keeping what belongs to
    /// the machine: the audio devices chosen.
    pub fn forget_account(&mut self) {
        *self = Self { input_device: self.input_device.take(), output_device: self.output_device.take(), ..Self::default() };
    }

    pub fn device_choice(&self) -> crate::audio::DeviceChoice {
        crate::audio::DeviceChoice { input: self.input_device.clone(), output: self.output_device.clone() }
    }

    /// Put the configured processing settings into effect.
    pub fn apply_audio(&self, audio: &ghost_audio::VoiceAudio) {
        audio.set_noise_suppression(self.noise_suppression().into());
        audio.set_agc(self.agc().into());
        audio.set_vad_threshold(self.vad_threshold());
        audio.set_input_gain(self.input_gain());
        audio.set_input_mode(self.input_mode().into());
    }

    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let content = toml::to_string_pretty(self).map_err(std::io::Error::other)?;
        fs::write(path, content)
    }
}

pub fn config_path(ghost_dir: &Path) -> PathBuf {
    ghost_dir.join("config.toml")
}
