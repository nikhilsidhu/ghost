//! Runs the core session and voice loops for this app and turns their events into the
//! UI events the front end listens for. Everything protocol-related happens in
//! `ghost_core::session` and `ghost_core::voice`.

use std::path::PathBuf;
use std::sync::Arc;

use ghost_core::client::GhostClient;
use ghost_core::flows::presence::PresenceInfo;
use ghost_core::mls::presence::OnlineStatus;
use ghost_core::relay::{RelayClient, RelayEvent};
use ghost_audio::VoiceAudio;
use ghost_core::session::{ClientEvent, EventSink, ServerScope, Session};
use ghost_core::voice::{Voice, VoiceEvent};
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, Mutex};

use crate::dto::MessageDto;

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "VoiceState"))]
pub(crate) struct VoiceStateEvent {
    connected: bool,
    server_id: Option<String>,
    channel_id: Option<String>,
    muted: bool,
    deafened: bool,
    udp_port: Option<u16>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "VoiceParticipants"))]
pub(crate) struct VoiceParticipantsEvent {
    participants: Vec<String>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "VoiceSpeaking"))]
pub(crate) struct VoiceSpeakingEvent {
    fingerprint: String,
    speaking: bool,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "VoiceMuteState"))]
pub(crate) struct VoiceMuteStateEvent {
    fingerprint: String,
    muted: bool,
    deafened: bool,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "VoiceQuality"))]
pub(crate) struct VoiceQualityEvent {
    packet_loss: f32,
    jitter_depth: u32,
    jitter_target: u32,
    ping_ms: Option<u32>,
}

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

/// Emit this device's own voice events to the webview.
fn emit_voice(app: &AppHandle, event: VoiceEvent) -> tauri::Result<()> {
    match event {
        VoiceEvent::State(state) => app.emit(
            "voice-state",
            &VoiceStateEvent {
                connected: state.connected,
                server_id: state.server_id.map(hex::encode),
                channel_id: state.channel_id.map(hex::encode),
                muted: state.muted,
                deafened: state.deafened,
                udp_port: state.udp_port,
            },
        ),
        VoiceEvent::Participants(everyone) => {
            app.emit("voice-participants", &VoiceParticipantsEvent { participants: everyone.iter().map(hex::encode).collect() })
        }
        VoiceEvent::Speaking { fingerprint, speaking } => {
            app.emit("voice-speaking", &VoiceSpeakingEvent { fingerprint: hex::encode(fingerprint), speaking })
        }
        VoiceEvent::MuteState { fingerprint, muted, deafened } => {
            app.emit("voice-mute-state", &VoiceMuteStateEvent { fingerprint: hex::encode(fingerprint), muted, deafened })
        }
        VoiceEvent::Quality { quality, ping_ms } => app.emit(
            "voice-quality",
            &VoiceQualityEvent {
                packet_loss: quality.packet_loss_pct,
                jitter_depth: quality.jitter_depth,
                jitter_target: quality.jitter_target,
                ping_ms,
            },
        ),
        VoiceEvent::Error(message) => app.emit("voice-error", message),
    }
}

/// Emits session and voice events to the webview and applies synced settings to this
/// app's configuration and audio.
pub struct TauriSink {
    app: AppHandle,
    config: Arc<Mutex<crate::config::GhostConfig>>,
    config_path: PathBuf,
    audio: Arc<VoiceAudio>,
    voice: Voice,
}

impl TauriSink {
    pub fn new(
        app: AppHandle,
        config: Arc<Mutex<crate::config::GhostConfig>>,
        config_path: PathBuf,
        audio: Arc<VoiceAudio>,
        voice: Voice,
    ) -> Self {
        Self { app, config, config_path, audio, voice }
    }
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
                let (app, config, config_path, audio, voice) =
                    (app.clone(), self.config.clone(), self.config_path.clone(), self.audio.clone(), self.voice.clone());
                tauri::async_runtime::spawn(async move {
                    crate::sync_utils::apply_synced_settings(&settings, &app, &config, &config_path, &audio, &voice).await;
                });
                Ok(())
            }
            ClientEvent::Voice(event) => emit_voice(app, event),
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
    audio: Arc<VoiceAudio>,
    voice: Voice,
) {
    let sink = Arc::new(TauriSink::new(app, config, config_path, audio, voice));
    Session { client, relay, presence, sink, data_dir, discovery: Arc::default() }.run(events).await;
}
