//! Runs the core session loop for this app and turns its events into the UI events the
//! front end listens for. Everything protocol-related happens in `ghost_core::session`.

use std::path::PathBuf;
use std::sync::Arc;

use ghost_core::client::GhostClient;
use ghost_core::flows::presence::PresenceInfo;
use ghost_core::mls::presence::OnlineStatus;
use ghost_core::relay::{RelayClient, RelayEvent};
use ghost_core::session::{ClientEvent, EventSink, ServerScope, Session};
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, Mutex};

use crate::dto::MessageDto;

#[derive(Serialize, Clone)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "VoiceChannelMembers"))]
pub(crate) struct VoiceChannelMembersEvent {
    channel_id: String,
    members: Vec<VoiceChannelMember>,
}

#[derive(Serialize, Clone)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "VoiceChannelMember"))]
pub(crate) struct VoiceChannelMember {
    fingerprint: String,
    muted: bool,
    deafened: bool,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "OnlinePresenceEvent"))]
pub(crate) struct OnlinePresenceEvent {
    server_id: String,
    members: Vec<OnlinePresenceMemberDto>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "OnlinePresenceMember"))]
pub(crate) struct OnlinePresenceMemberDto {
    fingerprint: String,
    #[cfg_attr(test, ts(type = "\"online\" | \"idle\" | \"away\" | \"offline\""))]
    status: String,
    status_message: Option<String>,
    avatar_hash: Option<String>,
}

/// How the front end names a member's online status.
fn status_str(s: OnlineStatus) -> &'static str {
    match s {
        OnlineStatus::Online => "online",
        OnlineStatus::Idle => "idle",
        OnlineStatus::Away => "away",
        OnlineStatus::Invisible => "offline",
    }
}

/// Emits session events to the webview and applies synced settings to this app's
/// configuration and audio pipeline.
struct TauriSink {
    app: AppHandle,
    config: Arc<Mutex<crate::config::GhostConfig>>,
    config_path: PathBuf,
    voice_cmd_tx: mpsc::Sender<crate::voice_task::VoiceCommand>,
}

impl EventSink for TauriSink {
    fn emit(&self, event: ClientEvent) {
        let app = &self.app;
        let _ = match event {
            ClientEvent::ServerChanged(ServerScope::One(server_id)) => app.emit("sync", hex::encode(server_id)),
            ClientEvent::ServerChanged(ServerScope::All) => app.emit("sync", "all"),
            ClientEvent::Message { message, received_at } => app.emit("message", &MessageDto::from_incoming(&message, received_at)),
            ClientEvent::Kicked(server_id) => app.emit("kicked", hex::encode(server_id)),
            ClientEvent::AvatarUpdated(fp) => app.emit("avatar-updated", hex::encode(fp)),
            ClientEvent::AvatarCleared(fp) => app.emit("avatar-cleared", hex::encode(fp)),
            ClientEvent::DisplayNameSynced => app.emit("display-name-sync", ()),
            ClientEvent::RelayConnectivity(connected) => app.emit("relay-connectivity", connected),
            ClientEvent::VoiceTakeover(channel_id) => app.emit("voice-takeover", hex::encode(channel_id)),
            ClientEvent::VoiceChannelMembers { channel_id, members } => app.emit(
                "voice-channel-members",
                &VoiceChannelMembersEvent {
                    channel_id: hex::encode(channel_id),
                    members: members
                        .iter()
                        .map(|m| VoiceChannelMember { fingerprint: hex::encode(m.fingerprint), muted: m.muted, deafened: m.deafened })
                        .collect(),
                },
            ),
            ClientEvent::OnlinePresence { server_id, members } => app.emit(
                "online-presence",
                &OnlinePresenceEvent {
                    server_id: hex::encode(server_id),
                    members: members
                        .iter()
                        .map(|m| OnlinePresenceMemberDto {
                            fingerprint: hex::encode(m.fingerprint),
                            status: status_str(m.status).to_string(),
                            status_message: m.status_message.clone(),
                            avatar_hash: m.avatar_hash.map(hex::encode),
                        })
                        .collect(),
                },
            ),
            ClientEvent::SettingsSynced(settings) => {
                let (app, config, config_path, voice_cmd_tx) =
                    (app.clone(), self.config.clone(), self.config_path.clone(), self.voice_cmd_tx.clone());
                tauri::async_runtime::spawn(async move {
                    crate::sync_utils::apply_synced_settings(&settings, &app, &config, &config_path, &voice_cmd_tx).await;
                });
                Ok(())
            }
        };
    }
}

/// Run the session loop for this app until the relay client's event channel closes.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    app: AppHandle,
    client: Arc<Mutex<GhostClient>>,
    relay: Arc<Mutex<RelayClient>>,
    events: mpsc::Receiver<RelayEvent>,
    presence: Arc<Mutex<PresenceInfo>>,
    data_dir: PathBuf,
    config: Arc<Mutex<crate::config::GhostConfig>>,
    config_path: PathBuf,
    voice_cmd_tx: mpsc::Sender<crate::voice_task::VoiceCommand>,
) {
    let sink = Arc::new(TauriSink { app, config, config_path, voice_cmd_tx });
    Session { client, relay, presence, sink, data_dir, discovery: Arc::default() }.run(events).await;
}
