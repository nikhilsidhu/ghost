//! Runs the core session and voice loops for this app and turns their events into the
//! UI events the front end listens for. Everything protocol-related happens in
//! `ghost_core::session` and `ghost_core::voice`.

use std::collections::HashMap;
use std::sync::Arc;

use ghost_core::relay::RelayEvent;
use ghost_core::session::{AccountAlert, ClientEvent, Connectivity, EventSink, ServerScope, Session};
use ghost_core::voice::{CallPhase, MediaPath, VoiceEvent, VoiceState};
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::sync::mpsc;

use crate::dto::{AccountAlertDto, AccountAlertKindDto, DeliveryDto, MessageDeliveryDto, MessageDto, OnlineStatusDto, PresenceStatusDto};
use crate::state::SessionHandles;

#[derive(Serialize, Clone)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "VoiceState"))]
pub(crate) struct VoiceStateEvent {
    connected: bool,
    server_id: Option<String>,
    channel_id: Option<String>,
    muted: bool,
    deafened: bool,
    udp_port: Option<u16>,
    /// Where the call stands; `null` out of a call.
    phase: Option<CallPhaseDto>,
    /// Whether the call's media reaches the relay; `null` until media starts.
    media_path: Option<MediaPathDto>,
}

#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "CallPhase"))]
pub(crate) enum CallPhaseDto {
    Joining,
    Live,
    Reconnecting,
}

impl From<CallPhase> for CallPhaseDto {
    fn from(phase: CallPhase) -> Self {
        match phase {
            CallPhase::Joining => Self::Joining,
            CallPhase::Live => Self::Live,
            CallPhase::Reconnecting => Self::Reconnecting,
        }
    }
}

#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "MediaPath"))]
pub(crate) enum MediaPathDto {
    Unconfirmed,
    Open,
    Blocked,
}

impl From<MediaPath> for MediaPathDto {
    fn from(path: MediaPath) -> Self {
        match path {
            MediaPath::Unconfirmed => Self::Unconfirmed,
            MediaPath::Open => Self::Open,
            MediaPath::Blocked => Self::Blocked,
        }
    }
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

/// A private channel whose messages wait for a change to its server's group, or no longer do.
#[derive(Serialize, Clone)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "ChannelWaiting"))]
pub(crate) struct ChannelWaitingEvent {
    channel_id: String,
    waiting: bool,
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

#[derive(Serialize, Clone)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "OnlinePresenceEvent"))]
pub(crate) struct OnlinePresenceEvent {
    server_id: String,
    members: Vec<OnlinePresenceMemberDto>,
}

#[derive(Serialize, Clone)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "OnlinePresenceMember"))]
pub(crate) struct OnlinePresenceMemberDto {
    fingerprint: String,
    status: PresenceStatusDto,
    status_message: Option<String>,
    avatar_hash: Option<String>,
}

/// Where this device's relay connections stand.
#[derive(Serialize, Clone, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "Connectivity"))]
pub(crate) struct ConnectivityDto {
    /// The home relay answers.
    home: bool,
    /// Any relay connection is up.
    any: bool,
    /// Relays, by URL, with a connection down.
    relays_down: Vec<String>,
    /// Relays, by URL, that answer but refuse this device a server's mailbox.
    relays_refusing: Vec<String>,
    /// A connection that came up is still delivering what was missed while it was down.
    catching_up: bool,
}

impl From<&Connectivity> for ConnectivityDto {
    fn from(c: &Connectivity) -> Self {
        Self {
            home: c.home,
            any: c.any,
            relays_down: c.relays_down.clone(),
            relays_refusing: c.relays_refusing.clone(),
            catching_up: c.catching_up,
        }
    }
}

/// The latest of each state the webview only ever hears as an event, for a front end
/// that starts, or reloads, after the session reported it.
#[derive(Default)]
pub struct LiveState {
    connectivity: ConnectivityDto,
    /// By server id.
    online: HashMap<String, OnlinePresenceEvent>,
    /// By channel id.
    voice: HashMap<String, VoiceChannelMembersEvent>,
    /// Raised and not dismissed yet, oldest first.
    alerts: Vec<AccountAlertDto>,
    next_alert_id: u64,
    /// Another device removed this one from the account.
    /// "This device was removed", with what removed it, once reported.
    device_removed: Option<AccountAlertDto>,
    /// This device's own call, as the voice loop last reported it.
    voice_state: Option<VoiceStateEvent>,
    /// Private channels whose messages wait for a change to their server's group.
    waiting_channels: std::collections::HashSet<String>,
}

impl LiveState {
    /// What the webview needs to show the session as it is; `status` is what this device
    /// announces now (idle, or the status chosen), which presence holds.
    pub fn snapshot(&self, status: OnlineStatusDto) -> LiveStateDto {
        LiveStateDto {
            connectivity: self.connectivity.clone(),
            online: self.online.values().cloned().collect(),
            voice: self.voice.values().cloned().collect(),
            alerts: self.alerts.clone(),
            device_removed: self.device_removed.clone(),
            voice_state: self.voice_state.clone(),
            waiting_channels: self.waiting_channels.iter().cloned().collect(),
            status,
        }
    }

    /// Keep an alert until it is dismissed, giving it its id; "this device was removed"
    /// is a state, not an alert.
    fn raise(&mut self, mut alert: AccountAlertDto) -> AccountAlertDto {
        if alert.kind == AccountAlertKindDto::ThisDeviceRemoved {
            self.device_removed = Some(alert.clone());
            return alert;
        }
        self.next_alert_id += 1;
        alert.id = self.next_alert_id;
        self.alerts.push(alert.clone());
        alert
    }

    pub fn dismiss_alert(&mut self, id: u64) {
        self.alerts.retain(|alert| alert.id != id);
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "LiveState"))]
pub(crate) struct LiveStateDto {
    connectivity: ConnectivityDto,
    online: Vec<OnlinePresenceEvent>,
    voice: Vec<VoiceChannelMembersEvent>,
    alerts: Vec<AccountAlertDto>,
    /// Set once this device was removed from its account, which takes over the window.
    device_removed: Option<AccountAlertDto>,
    /// This device's own call; `None` before the voice loop said anything.
    voice_state: Option<VoiceStateEvent>,
    /// Private channels whose messages wait for a change to their server's group.
    waiting_channels: Vec<String>,
    /// What this device announces now.
    status: OnlineStatusDto,
}

impl From<&VoiceState> for VoiceStateEvent {
    fn from(state: &VoiceState) -> Self {
        Self {
            connected: state.connected,
            server_id: state.server_id.map(hex::encode),
            channel_id: state.channel_id.map(hex::encode),
            muted: state.muted,
            deafened: state.deafened,
            udp_port: state.udp_port,
            phase: state.phase.map(CallPhaseDto::from),
            media_path: state.media_path.map(MediaPathDto::from),
        }
    }
}

/// Emit this device's own voice events to the webview.
fn emit_voice(app: &AppHandle, event: VoiceEvent) -> tauri::Result<()> {
    match event {
        VoiceEvent::State(state) => app.emit("voice-state", &VoiceStateEvent::from(&state)),
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
        VoiceEvent::Notice(message) => app.emit("voice-notice", message),
    }
}

/// Emits session and voice events to the webview and applies synced settings to this
/// app's configuration and audio.
pub struct TauriSink {
    app: AppHandle,
    handles: SessionHandles,
}

impl TauriSink {
    pub fn new(app: AppHandle, handles: SessionHandles) -> Self {
        Self { app, handles }
    }
}

impl EventSink for TauriSink {
    fn emit(&self, event: ClientEvent) {
        let app = &self.app;
        let _ = match event {
            ClientEvent::ServerChanged(ServerScope::One(server_id)) => app.emit("sync", hex::encode(server_id)),
            ClientEvent::ServerChanged(ServerScope::All) => app.emit("sync", "all"),
            ClientEvent::Message { message, received_at } => app.emit("message", &MessageDto::from_incoming(&message, received_at)),
            ClientEvent::MessageDelivered { message_id } => app.emit(
                "message-delivery",
                &MessageDeliveryDto { message_id: hex::encode(message_id), delivery: DeliveryDto::Delivered, reason: None },
            ),
            ClientEvent::MessageFailed { message_id, reason } => app.emit(
                "message-delivery",
                &MessageDeliveryDto { message_id: hex::encode(message_id), delivery: DeliveryDto::Failed, reason: Some(reason) },
            ),
            ClientEvent::Kicked(server_id) => app.emit("kicked", hex::encode(server_id)),
            ClientEvent::HomeFollowed { url } => {
                // The next start connects to the account's home where it is now.
                let handles = self.handles.clone();
                tauri::async_runtime::spawn(async move {
                    let mut cfg = handles.config.lock().await;
                    cfg.relay_url = Some(url);
                    if let Err(e) = cfg.save(&handles.config_path) {
                        tracing::error!("the moved home's address not saved: {e}");
                    }
                });
                Ok(())
            }
            // The server list shows it read-only; the message view explains and offers the way out.
            ClientEvent::ServerHalted { server_id, .. } => app.emit("sync", hex::encode(server_id)),
            ClientEvent::ChannelWaiting { channel_id, waiting, .. } => {
                let event = ChannelWaitingEvent { channel_id: hex::encode(channel_id), waiting };
                {
                    let mut live = self.handles.live.lock().unwrap();
                    if waiting {
                        live.waiting_channels.insert(event.channel_id.clone());
                    } else {
                        live.waiting_channels.remove(&event.channel_id);
                    }
                }
                app.emit("channel-waiting", &event)
            }
            ClientEvent::AvatarUpdated(fp) => app.emit("avatar-updated", hex::encode(fp)),
            ClientEvent::AvatarCleared(fp) => app.emit("avatar-cleared", hex::encode(fp)),
            ClientEvent::DisplayNameSynced => app.emit("display-name-sync", ()),
            ClientEvent::RelayConnectivity(connectivity) => {
                let dto = ConnectivityDto::from(&connectivity);
                self.handles.live.lock().unwrap().connectivity = dto.clone();
                app.emit("relay-connectivity", &dto)
            }
            ClientEvent::VoiceChannelMembers { channel_id, members } => {
                let event = VoiceChannelMembersEvent {
                    channel_id: hex::encode(channel_id),
                    members: members
                        .iter()
                        .map(|m| VoiceChannelMember { fingerprint: hex::encode(m.fingerprint), muted: m.muted, deafened: m.deafened })
                        .collect(),
                };
                {
                    let mut live = self.handles.live.lock().unwrap();
                    if event.members.is_empty() {
                        live.voice.remove(&event.channel_id);
                    } else {
                        live.voice.insert(event.channel_id.clone(), event.clone());
                    }
                }
                app.emit("voice-channel-members", &event)
            }
            ClientEvent::OnlinePresence { server_id, members } => {
                let event = OnlinePresenceEvent {
                    server_id: hex::encode(server_id),
                    members: members
                        .iter()
                        .map(|m| OnlinePresenceMemberDto {
                            fingerprint: hex::encode(m.fingerprint),
                            status: m.status.into(),
                            status_message: m.status_message.clone(),
                            avatar_hash: m.avatar_hash.map(hex::encode),
                        })
                        .collect(),
                };
                self.handles.live.lock().unwrap().online.insert(event.server_id.clone(), event.clone());
                app.emit("online-presence", &event)
            }
            ClientEvent::SettingsSynced(settings) => {
                let (app, handles) = (app.clone(), self.handles.clone());
                tauri::async_runtime::spawn(async move {
                    crate::sync_utils::apply_synced_settings(&settings, &app, &handles).await;
                });
                Ok(())
            }
            ClientEvent::Voice(event) => {
                if let VoiceEvent::State(state) = &event {
                    self.handles.live.lock().unwrap().voice_state = Some(VoiceStateEvent::from(state));
                }
                emit_voice(app, event)
            }
            ClientEvent::Account(alert) => {
                if matches!(alert, AccountAlert::ThisDeviceRemoved { .. }) {
                    // Nothing this device sends is the account's any more.
                    let voice = self.handles.voice.clone();
                    tauri::async_runtime::spawn(async move {
                        if let Err(e) = voice.leave().await {
                            tracing::warn!("the call not left after this device's removal: {e}");
                        }
                    });
                }
                let dto = self.handles.live.lock().unwrap().raise(account_alert_dto(&alert));
                app.emit("account-alert", &dto)
            }
            ClientEvent::SplitView { server_id, account_fp } => {
                // Named as this device knows the member, which takes the client.
                let (app, client, live) = (app.clone(), self.handles.client.clone(), self.handles.live.clone());
                tauri::async_runtime::spawn(async move {
                    let account_name = client.lock().await.member_name(&server_id, &account_fp);
                    let dto = live.lock().unwrap().raise(AccountAlertDto { account_name, ..AccountAlertDto::of(AccountAlertKindDto::SplitView) });
                    let _ = app.emit("account-alert", &dto);
                });
                Ok(())
            }
        };
    }
}

fn account_alert_dto(alert: &AccountAlert) -> AccountAlertDto {
    match alert {
        AccountAlert::DeviceLinked { label } => {
            AccountAlertDto { device_label: Some(label.clone()), ..AccountAlertDto::of(AccountAlertKindDto::DeviceLinked) }
        }
        AccountAlert::DeviceRemoved { label, by } => {
            AccountAlertDto { device_label: Some(label.clone()), ..AccountAlertDto::removal(AccountAlertKindDto::DeviceRemoved, Some(by)) }
        }
        AccountAlert::RecoveryKeyReplaced { by } => {
            AccountAlertDto { device_label: Some(by.clone()), ..AccountAlertDto::of(AccountAlertKindDto::RecoveryKeyReplaced) }
        }
        AccountAlert::HomeMoved { relay_vk } => {
            AccountAlertDto { relay_vk: Some(hex::encode(relay_vk)), ..AccountAlertDto::of(AccountAlertKindDto::HomeMoved) }
        }
        AccountAlert::BadAccountKey { generation, writer, writer_label } => AccountAlertDto {
            generation: Some(*generation),
            device_key: Some(hex::encode(writer)),
            device_label: Some(writer_label.clone()),
            ..AccountAlertDto::of(AccountAlertKindDto::BadAccountKey)
        },
        AccountAlert::ThisDeviceRemoved { cause } => AccountAlertDto::removal(AccountAlertKindDto::ThisDeviceRemoved, cause.as_ref()),
        AccountAlert::HistoryReplaced { discarded, lost_devices } => AccountAlertDto {
            discarded: Some(*discarded),
            lost_devices: lost_devices.clone(),
            ..AccountAlertDto::of(AccountAlertKindDto::HistoryReplaced)
        },
        AccountAlert::RemovalRefused { label, reason } => AccountAlertDto {
            device_label: Some(label.clone()),
            reason: Some(reason.clone()),
            ..AccountAlertDto::of(AccountAlertKindDto::RemovalRefused)
        },
        AccountAlert::RelayRefusesDevice { relay_url } => {
            AccountAlertDto { relay_url: Some(relay_url.clone()), ..AccountAlertDto::of(AccountAlertKindDto::RelayRefusesDevice) }
        }
    }
}

/// Run the session loop for this app until the relay client's event channel closes.
pub async fn run(app: AppHandle, handles: SessionHandles, events: mpsc::Receiver<RelayEvent>) {
    // A new session reports everything afresh; the call is the voice loop's, which goes on.
    {
        let mut live = handles.live.lock().unwrap();
        let voice_state = live.voice_state.take();
        *live = LiveState { voice_state, ..LiveState::default() };
    }
    // A webview that showed the old session's rosters drops them and reads the snapshot.
    let _ = app.emit("live-reset", ());
    let SessionHandles { client, relay, presence, data_dir, .. } = handles.clone();
    let sink = Arc::new(TauriSink::new(app, handles));
    Session { client, relay, presence, sink, data_dir, discovery: Arc::default(), split_views: Arc::default() }.run(events).await;
}
