use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::audio::{device_id, find_by_name, ChosenDevice, Direction};
use crate::dto::{AgcDto, InputModeDto, NoiseSuppressionDto, OnlineStatusDto};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeybindConfig {
    pub push_to_talk: Option<String>,
}

/// This device's settings, kept in `config.toml` in the data directory. The settings
/// shared between an account's devices are also carried by sync; the relay URL, the
/// audio devices, echo cancellation and the microphones' learned gains are this
/// device's alone.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GhostConfig {
    pub display_name: Option<String>,
    pub relay_url: Option<String>,
    /// The microphone calls use; none follows the system default.
    pub input_device: Option<ChosenDevice>,
    /// The speakers calls use; none follows the system default.
    pub output_device: Option<ChosenDevice>,
    pub noise_suppression: Option<NoiseSuppressionDto>,
    pub agc: Option<AgcDto>,
    pub input_mode: Option<InputModeDto>,
    pub vad_threshold: Option<f32>,
    pub input_gain: Option<f32>,
    /// Whether echo cancellation runs; on unless turned off. Whether it is needed
    /// depends on this device's speakers, so it is not synced.
    pub echo_cancellation: Option<bool>,
    /// The gain the volume normalizer settled on, by microphone id, so a call starts at
    /// the right loudness instead of finding it again.
    pub learned_gains: Option<BTreeMap<String, f32>>,
    /// Gains learned before microphones had ids, by name; each moves to `learned_gains`
    /// once its microphone is seen.
    pub input_gains: Option<BTreeMap<String, f32>>,
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

    pub fn echo_cancellation(&self) -> bool {
        self.echo_cancellation.unwrap_or(true)
    }

    /// Forget what belonged to the account this device was in, keeping what belongs to
    /// the machine: the audio devices chosen, echo cancellation and what was learned of
    /// the microphones.
    pub fn forget_account(&mut self) {
        *self = Self {
            input_device: self.input_device.take(),
            output_device: self.output_device.take(),
            echo_cancellation: self.echo_cancellation.take(),
            learned_gains: self.learned_gains.take(),
            input_gains: self.input_gains.take(),
            ..Self::default()
        };
    }

    /// Whether anything is still saved by device name, from before devices had ids.
    pub fn has_device_names(&self) -> bool {
        let named = |chosen: &Option<ChosenDevice>| chosen.as_ref().is_some_and(|chosen| chosen.id.is_none());
        named(&self.input_device) || named(&self.output_device) || self.input_gains.is_some()
    }

    /// Give what was saved by device name, before devices had ids, the ids of the devices
    /// of those names connected now; the rest keeps its name until its device is seen.
    /// Whether anything changed.
    pub fn identify_devices(&mut self, host: &cpal::Host) -> bool {
        let mut changed = false;
        for (chosen, direction) in [(&mut self.input_device, Direction::Input), (&mut self.output_device, Direction::Output)] {
            let Some(chosen) = chosen.as_mut().filter(|chosen| chosen.id.is_none()) else { continue };
            if let Some(id) = find_by_name(host, &chosen.name, direction).as_ref().and_then(device_id) {
                chosen.id = Some(id);
                changed = true;
            }
        }
        if let Some(named) = self.input_gains.take() {
            let mut unseen = BTreeMap::new();
            for (name, gain) in named {
                match find_by_name(host, &name, Direction::Input).as_ref().and_then(device_id) {
                    Some(id) => {
                        // A gain learned under the id already is the newer.
                        self.learned_gains.get_or_insert_with(Default::default).entry(id).or_insert(gain);
                        changed = true;
                    }
                    None => {
                        unseen.insert(name, gain);
                    }
                }
            }
            changed |= unseen.is_empty();
            self.input_gains = (!unseen.is_empty()).then_some(unseen);
        }
        changed
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
        audio.set_echo_cancellation(self.echo_cancellation());
        audio.set_learned_gains(self.learned_gains.iter().flatten().map(|(input, gain)| (input.clone(), *gain)).collect());
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
