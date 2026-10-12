//! Applies settings restored or received through cross-device sync to this
//! application's configuration, voice pipeline, presence and UI. The sync
//! protocol itself lives in `ghost_core::flows::sync`.

use std::path::Path;

use ghost_core::flows::presence::PresenceInfo;
use ghost_core::flows::sync::SyncSettings;
use ghost_audio::{InputMode, VoiceAudio};
use ghost_core::voice::Voice;
use tauri::{AppHandle, Emitter};

use crate::config::GhostConfig;
use crate::constants::INPUT_GAIN_MAX;
use crate::dto::{setting_from_name, AgcDto, InputModeDto, NoiseSuppressionDto, OnlineStatusDto};
use crate::state::SessionHandles;

/// Switch the input mode. Choosing push to talk drops a standing mute, since the key
/// now decides when to send.
pub async fn apply_input_mode(audio: &VoiceAudio, voice: &Voice, mode: InputMode) {
    audio.set_input_mode(mode);
    if mode == InputMode::PushToTalk {
        let _ = voice.unmute_for_push_to_talk().await;
    }
}

/// The settings a sync carried, as this build knows them. A value another version
/// wrote under a name this one does not know is left alone.
pub struct SyncedSettings {
    pub noise_suppression: Option<NoiseSuppressionDto>,
    pub agc: Option<AgcDto>,
    pub input_mode: Option<InputModeDto>,
    pub status: Option<OnlineStatusDto>,
}

impl SyncedSettings {
    pub fn parse(settings: &SyncSettings) -> Self {
        Self {
            noise_suppression: settings.noise_suppression.as_deref().and_then(setting_from_name),
            agc: settings.agc.as_deref().and_then(setting_from_name),
            input_mode: settings.input_mode.as_deref().and_then(setting_from_name),
            status: settings.status.as_deref().and_then(setting_from_name),
        }
    }
}

/// Apply synced settings to the config, saving if anything changed.
pub fn apply_sync_to_config(settings: &SyncSettings, cfg: &mut GhostConfig, path: &Path) {
    let parsed = SyncedSettings::parse(settings);
    let mut dirty = false;
    if let Some(name) = &settings.display_name {
        cfg.display_name = Some(name.clone());
        dirty = true;
    }
    if let Some(mode) = parsed.noise_suppression {
        cfg.noise_suppression = Some(mode);
        dirty = true;
    }
    if let Some(mode) = parsed.agc {
        cfg.agc = Some(mode);
        dirty = true;
    }
    if let Some(mode) = parsed.input_mode {
        cfg.input_mode = Some(mode);
        dirty = true;
    }
    if let Some(threshold) = settings.vad_threshold {
        cfg.vad_threshold = Some(threshold.clamp(0.0, 1.0));
        dirty = true;
    }
    if let Some(gain) = settings.input_gain {
        cfg.input_gain = Some(gain.clamp(0.0, INPUT_GAIN_MAX));
        dirty = true;
    }
    if let Some(status) = parsed.status {
        cfg.status = Some(status);
        dirty = true;
    }
    if let Some(message) = &settings.status_message {
        cfg.status_message = message.as_ref().map(|m| m.text.clone());
        cfg.status_expiry = message.as_ref().and_then(|m| m.expires_at);
        dirty = true;
    }
    if dirty {
        if let Err(e) = cfg.save(path) {
            tracing::warn!("synced settings not saved: {e}");
        }
    }
}

/// Apply status fields from config to the in-memory presence.
pub fn apply_config_to_presence(cfg: &GhostConfig, presence: &mut PresenceInfo) {
    presence.status = cfg.status().into();
    presence.status_message = cfg.status_message.clone();
    presence.status_expiry = cfg.status_expiry;
}

/// Apply settings synced from another device to this app: persist them in the config,
/// steer the audio pipeline, and tell the front end. Read marks, the display name and
/// the presence status were already applied by the session.
pub async fn apply_synced_settings(settings: &SyncSettings, app: &AppHandle, handles: &SessionHandles) {
    {
        let mut cfg = handles.config.lock().await;
        apply_sync_to_config(settings, &mut cfg, &handles.config_path);
    }

    let parsed = SyncedSettings::parse(settings);
    if let Some(mode) = parsed.noise_suppression {
        handles.audio.set_noise_suppression(mode.into());
    }
    if let Some(mode) = parsed.agc {
        handles.audio.set_agc(mode.into());
    }
    if let Some(mode) = parsed.input_mode {
        apply_input_mode(&handles.audio, &handles.voice, mode.into()).await;
    }
    {
        let cfg = handles.config.lock().await;
        if settings.vad_threshold.is_some() {
            handles.audio.set_vad_threshold(cfg.vad_threshold());
        }
        if settings.input_gain.is_some() {
            handles.audio.set_input_gain(cfg.input_gain());
        }
    }

    if settings.server_order_changed {
        let _ = app.emit("sync-server-order", "");
    }
    if !settings.read_marks.is_empty() {
        let _ = app.emit("sync-read-state", "");
    }
    if settings.display_name.is_some() {
        let _ = app.emit("display-name-sync", "");
    }
    if settings.noise_suppression.is_some() {
        let _ = app.emit("sync-pref", "noise_suppression");
    }
    if settings.agc.is_some() {
        let _ = app.emit("sync-pref", "agc");
    }
    if settings.input_mode.is_some() {
        let _ = app.emit("sync-pref", "input_mode");
    }
    if settings.vad_threshold.is_some() {
        let _ = app.emit("sync-pref", "vad_threshold");
    }
    if settings.input_gain.is_some() {
        let _ = app.emit("sync-pref", "input_gain");
    }
    if settings.status.is_some() || settings.status_message.is_some() {
        let _ = app.emit("sync-status", "");
    }
}
