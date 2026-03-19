use std::path::Path;
use std::sync::Arc;

use ghost_core::client::GhostClient;
use ghost_core::mls::presence::OnlineStatus;
use ghost_core::relay::RelayClient;
use ghost_core::wire::{
    SyncServerMeta, SYNC_KEY_AGC, SYNC_KEY_DISPLAY_NAME, SYNC_KEY_INPUT_MODE,
    SYNC_KEY_NOISE_SUPPRESSION, SYNC_KEY_READ_PREFIX, SYNC_KEY_SERVER_ORDER,
    SYNC_KEY_SERVER_PREFIX, SYNC_KEY_STATUS, SYNC_KEY_STATUS_MESSAGE,
};
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, Mutex};

/// Send a sync message to all linked devices via the sync MLS group.
pub async fn post_sync_message(
    client: &Arc<Mutex<GhostClient>>,
    relay: &Arc<Mutex<RelayClient>>,
    msg_type: u8,
    payload: &[u8],
) {
    let outbound = {
        let c = client.lock().await;
        if !c.has_sync_group() { return; }
        let mut inner = Vec::with_capacity(1 + payload.len());
        inner.push(msg_type);
        inner.extend_from_slice(payload);
        match c.send_sync(&inner) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("sync send: {e}");
                return;
            }
        }
    };
    let r = relay.lock().await;
    let _ = r.send(&outbound.mailbox_id, outbound.blob).await;
}

/// Dump local sync state, encrypt with sync_key, and PUT to relay as a durable snapshot.
pub async fn push_sync_snapshot(
    client: &Arc<Mutex<GhostClient>>,
    relay: &Arc<Mutex<RelayClient>>,
) {
    use ghost_core::wire::{encode_sync_state_dump, sync_seal};

    let (sync_key, account_fp, dump_blob) = {
        let c = client.lock().await;
        let sk = match c.sync_key() {
            Some(k) => k,
            None => return,
        };
        let entries = c.sync_dump().unwrap_or_default();
        let blob = match encode_sync_state_dump(&entries) {
            Ok(b) => b,
            Err(_) => return,
        };
        (sk, *c.fingerprint(), blob)
    };

    let sealed = match sync_seal(&sync_key, &dump_blob) {
        Ok(s) => s,
        Err(_) => return,
    };

    let r = relay.lock().await;
    let _ = r.put_sync_state(&account_fp, sealed).await;
}

/// Parsed sync settings extracted from sync state entries.
pub struct SyncSettings {
    pub display_name: Option<String>,
    pub noise_suppression: Option<String>,
    pub agc: Option<String>,
    pub input_mode: Option<String>,
    pub status: Option<String>,
    pub status_message: Option<Option<String>>,
    pub read_marks: Vec<([u8; 32], u64)>,
    pub server_entries: Vec<([u8; 32], SyncServerMeta)>,
    pub server_order_changed: bool,
}

/// Parse sync state entries into typed settings.
pub fn parse_sync_entries(entries: &[(String, Option<Vec<u8>>, u64)]) -> SyncSettings {
    let mut s = SyncSettings {
        display_name: None,
        noise_suppression: None,
        agc: None,
        input_mode: None,
        status: None,
        status_message: None,
        read_marks: Vec::new(),
        server_entries: Vec::new(),
        server_order_changed: false,
    };

    for (key, value, _ts) in entries {
        if key == SYNC_KEY_SERVER_ORDER {
            s.server_order_changed = true;
        } else if let Some(id_hex) = key.strip_prefix(SYNC_KEY_READ_PREFIX) {
            if let Some(val) = value {
                if val.len() == 8 {
                    let read_ts = u64::from_be_bytes(val[..8].try_into().unwrap());
                    if let Ok(bytes) = hex::decode(id_hex) {
                        if let Ok(cid) = <[u8; 32]>::try_from(bytes.as_slice()) {
                            s.read_marks.push((cid, read_ts));
                        }
                    }
                }
            }
        } else if key == SYNC_KEY_DISPLAY_NAME {
            if let Some(val) = value {
                if let Ok(name) = std::str::from_utf8(val) {
                    s.display_name = Some(name.to_string());
                }
            }
        } else if key == SYNC_KEY_NOISE_SUPPRESSION {
            if let Some(val) = value {
                if let Ok(mode) = std::str::from_utf8(val) {
                    s.noise_suppression = Some(mode.to_string());
                }
            }
        } else if key == SYNC_KEY_AGC {
            if let Some(val) = value {
                if let Ok(mode) = std::str::from_utf8(val) {
                    s.agc = Some(mode.to_string());
                }
            }
        } else if key == SYNC_KEY_INPUT_MODE {
            if let Some(val) = value {
                if let Ok(mode) = std::str::from_utf8(val) {
                    s.input_mode = Some(mode.to_string());
                }
            }
        } else if key == SYNC_KEY_STATUS {
            if let Some(val) = value {
                if let Ok(status) = std::str::from_utf8(val) {
                    s.status = Some(status.to_string());
                }
            }
        } else if key == SYNC_KEY_STATUS_MESSAGE {
            match value {
                Some(val) => {
                    if let Ok(msg) = std::str::from_utf8(val) {
                        s.status_message = Some(Some(msg.to_string()));
                    }
                }
                None => s.status_message = Some(None),
            }
        } else if let Some(id_hex) = key.strip_prefix(SYNC_KEY_SERVER_PREFIX) {
            if let Some(val) = value {
                if let Ok(bytes) = hex::decode(id_hex) {
                    if let Ok(server_id) = <[u8; 32]>::try_from(bytes.as_slice()) {
                        if let Ok(meta) = SyncServerMeta::from_bytes(val) {
                            s.server_entries.push((server_id, meta));
                        }
                    }
                }
            }
        }
    }

    s
}

/// Apply parsed settings to config, saving if anything changed.
pub fn apply_sync_to_config(
    settings: &SyncSettings,
    cfg: &mut crate::config::GhostConfig,
    path: &Path,
) {
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
    // Read marks
    if !settings.read_marks.is_empty() {
        let c = client.lock().await;
        for (cid, read_ts) in &settings.read_marks {
            let _ = c.store().mark_channel_read(cid, *read_ts);
        }
    }

    // Display name
    if let Some(ref name) = settings.display_name {
        let mut c = client.lock().await;
        c.set_display_name(name.clone());
    }

    // Config persistence
    {
        let mut cfg = config.lock().await;
        apply_sync_to_config(settings, &mut cfg, config_path);
    }

    // Voice commands
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

    // Presence broadcast
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

    // Frontend events
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
