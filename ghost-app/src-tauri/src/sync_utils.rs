//! Applies settings restored or received through cross-device sync to this
//! application's configuration, voice pipeline, presence and UI. The sync
//! protocol itself lives in `ghost_core::flows::sync`.

use std::path::Path;
use std::sync::Arc;

use ghost_core::client::GhostClient;
use ghost_core::flows::sync::SyncSettings;
use ghost_core::mls::presence::OnlineStatus;
use ghost_core::relay::RelayClient;
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, Mutex};

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
pub fn apply_config_to_presence(cfg: &crate::config::GhostConfig, presence: &mut crate::presence::PresenceInfo) {
    if let Some(ref status) = cfg.status {
        presence.status = match status.as_str() {
            "away" => OnlineStatus::Away,
            "invisible" => OnlineStatus::Invisible,
            _ => OnlineStatus::Online,
        };
    }
    presence.status_message = cfg.status_message.clone();
}

/// Apply all side effects from parsed sync settings: read marks, display name,
/// config persistence, voice commands, presence broadcast, and frontend events.
pub async fn apply_sync_side_effects(
    settings: &SyncSettings,
    app: &AppHandle,
    client: &Arc<Mutex<GhostClient>>,
    relay: &Arc<Mutex<RelayClient>>,
    config: &Arc<Mutex<crate::config::GhostConfig>>,
    config_path: &Path,
    presence: &Arc<Mutex<crate::presence::PresenceInfo>>,
    voice_cmd_tx: &mpsc::Sender<crate::voice_task::VoiceCommand>,
) {
    if !settings.read_marks.is_empty() {
        let c = client.lock().await;
        for (cid, read_ts) in &settings.read_marks {
            let _ = c.store().mark_channel_read(cid, *read_ts);
        }
    }

    if let Some(ref name) = settings.display_name {
        let mut c = client.lock().await;
        c.set_display_name(name.clone());
    }

    {
        let mut cfg = config.lock().await;
        apply_sync_to_config(settings, &mut cfg, config_path);
    }

    if let Some(ref mode) = settings.noise_suppression {
        let ns = crate::audio::NoiseSuppressionMode::from_config(mode) as u8;
        let _ = voice_cmd_tx.send(crate::voice_task::VoiceCommand::SetNoiseSuppression(ns)).await;
    }
    if let Some(ref mode) = settings.agc {
        let agc = crate::audio::AgcMode::from_config(mode) as u8;
        let _ = voice_cmd_tx.send(crate::voice_task::VoiceCommand::SetAgc(agc)).await;
    }
    if let Some(ref mode) = settings.input_mode {
        let mode_u8 = if mode == "push_to_talk" { crate::audio::INPUT_MODE_PTT } else { crate::audio::INPUT_MODE_VA };
        let _ = voice_cmd_tx.send(crate::voice_task::VoiceCommand::SetInputMode(mode_u8)).await;
    }

    if settings.status.is_some() || settings.status_message.is_some() {
        let info = {
            let mut p = presence.lock().await;
            if let Some(ref status) = settings.status {
                p.status = match status.as_str() {
                    "away" => OnlineStatus::Away,
                    "invisible" => OnlineStatus::Invisible,
                    _ => OnlineStatus::Online,
                };
            }
            if let Some(ref msg_opt) = settings.status_message {
                p.status_message = msg_opt.clone();
            }
            p.clone()
        };
        crate::presence::broadcast_presence(client, relay, &info).await;
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
