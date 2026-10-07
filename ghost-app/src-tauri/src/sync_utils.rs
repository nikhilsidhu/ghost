//! Applies settings restored or received through cross-device sync to this
//! application's configuration, voice pipeline, presence and UI. The sync
//! protocol itself lives in `ghost_core::flows::sync`.

use std::path::Path;
use std::sync::Arc;

use ghost_core::flows::presence::PresenceInfo;
use ghost_core::flows::sync::SyncSettings;
use ghost_audio::{AgcMode, InputMode, NoiseSuppressionMode, VoiceAudio};
use ghost_core::mls::presence::OnlineStatus;
use ghost_core::voice::Voice;
use tauri::{AppHandle, Emitter};
use tokio::sync::Mutex;

/// Switch the input mode. Choosing push to talk drops a standing mute, since the key
/// now decides when to send.
pub async fn apply_input_mode(audio: &VoiceAudio, voice: &Voice, mode: InputMode) {
    audio.set_input_mode(mode);
    if mode == InputMode::PushToTalk {
        let _ = voice.unmute_for_push_to_talk().await;
    }
}

/// Apply parsed settings to config, saving if anything changed.
pub fn apply_sync_to_config(settings: &SyncSettings, cfg: &mut crate::config::GhostConfig, path: &Path) {
    let mut dirty = false;
    if let Some(ref name) = settings.display_name {
        cfg.display_name = Some(name.clone());
        dirty = true;
    }
    if let Some(ref mode) = settings.noise_suppression {
        cfg.noise_suppression = Some(mode.clone());
        dirty = true;
    }
    if let Some(ref mode) = settings.agc {
        cfg.agc = Some(mode.clone());
        dirty = true;
    }
    if let Some(ref mode) = settings.input_mode {
        cfg.input_mode = Some(mode.clone());
        dirty = true;
    }
    if let Some(ref status) = settings.status {
        cfg.status = Some(status.clone());
        dirty = true;
    }
    if let Some(ref msg_opt) = settings.status_message {
        cfg.status_message = msg_opt.clone();
        dirty = true;
    }
    if dirty {
        let _ = cfg.save(path);
    }
}

/// Apply status fields from config to the in-memory presence.
pub fn apply_config_to_presence(cfg: &crate::config::GhostConfig, presence: &mut PresenceInfo) {
    if let Some(ref status) = cfg.status {
        presence.status = OnlineStatus::from_config(status);
    }
    presence.status_message = cfg.status_message.clone();
}

/// Apply settings synced from another device to this app: persist them in the config,
/// steer the audio pipeline, and tell the front end. Read marks, the display name and
/// the presence status were already applied by the session.
pub async fn apply_synced_settings(
    settings: &SyncSettings,
    app: &AppHandle,
    config: &Arc<Mutex<crate::config::GhostConfig>>,
    config_path: &Path,
    audio: &VoiceAudio,
    voice: &Voice,
) {
    {
        let mut cfg = config.lock().await;
        apply_sync_to_config(settings, &mut cfg, config_path);
    }

    if let Some(ref mode) = settings.noise_suppression {
        audio.set_noise_suppression(NoiseSuppressionMode::from_config(mode));
    }
    if let Some(ref mode) = settings.agc {
        audio.set_agc(AgcMode::from_config(mode));
    }
    if let Some(ref mode) = settings.input_mode {
        apply_input_mode(audio, voice, InputMode::from_config(mode)).await;
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
    if settings.status.is_some() || settings.status_message.is_some() {
        let _ = app.emit("sync-status", "");
    }
}
