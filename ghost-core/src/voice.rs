//! A device's voice calls: signaling with the relay hosting the channel, sealed
//! presence, per-sender keys, and the media session that carries the call's audio.
//! The desktop app and headless devices run this same loop and differ only in the
//! audio track they plug in.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use ghost_media::{AudioTrack, MediaSession, SessionConfig, TrackIo, TrackQuality};
use ghost_wire::voice::{ClientMsg, PeerEntry, ServerMsg};
use rand::RngCore;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::error::{GhostError, Result};
use crate::flows::{self, SharedClient, SharedRelay};
use crate::mls::voice::PresenceState;
use crate::session::{ClientEvent, EventSink};
use crate::wire::SyncMessageType;

const WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const WS_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// How often our own speaking state is checked, to tell the room and the UI.
const SPEAKING_POLL: Duration = Duration::from_millis(100);
/// How often call quality is reported and the relay pinged for latency.
const QUALITY_POLL: Duration = Duration::from_secs(2);
const COMMAND_QUEUE: usize = 16;

type WsStream = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type WsSink = SplitSink<WsStream, Message>;
type WsReader = SplitStream<WsStream>;

/// Where this device stands in voice.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VoiceState {
    pub connected: bool,
    pub server_id: Option<[u8; 32]>,
    pub channel_id: Option<[u8; 32]>,
    pub muted: bool,
    pub deafened: bool,
    /// The relay's voice UDP port, once it welcomed us.
    pub udp_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VoiceEvent {
    State(VoiceState),
    /// Everyone in the call, this account included.
    Participants(Vec<[u8; 32]>),
    Speaking { fingerprint: [u8; 32], speaking: bool },
    MuteState { fingerprint: [u8; 32], muted: bool, deafened: bool },
    Quality { quality: TrackQuality, ping_ms: Option<u32> },
    Error(String),
}

enum Command {
    Join { server_id: [u8; 32], channel_id: [u8; 32], muted: bool, deafened: bool },
    Leave,
    SetMuted(bool),
    SetDeafened(bool),
    UnmuteForPushToTalk,
}

/// Controls the voice loop. Cheap to clone.
#[derive(Clone)]
pub struct Voice {
    commands: mpsc::Sender<Command>,
}

impl Voice {
    /// A voice controller and the loop that serves it, which the caller runs.
    pub fn new(client: Arc<SharedClient>, relay: Arc<SharedRelay>, audio: Arc<dyn AudioTrack>) -> (Self, VoiceLoop) {
        let (commands, receiver) = mpsc::channel(COMMAND_QUEUE);
        (Self { commands }, VoiceLoop { client, relay, audio, commands: receiver })
    }

    async fn send(&self, command: Command) -> Result<()> {
        self.commands.send(command).await.map_err(|_| GhostError::Network("voice loop not running".into()))
    }

    /// Join a channel's call, leaving any other; this account's other devices leave it.
    pub async fn join(&self, server_id: [u8; 32], channel_id: [u8; 32], muted: bool, deafened: bool) -> Result<()> {
        self.send(Command::Join { server_id, channel_id, muted, deafened }).await
    }

    pub async fn leave(&self) -> Result<()> {
        self.send(Command::Leave).await
    }

    /// Unmuting while deafened also undeafens.
    pub async fn set_muted(&self, muted: bool) -> Result<()> {
        self.send(Command::SetMuted(muted)).await
    }

    /// Deafening also mutes; undeafening unmutes.
    pub async fn set_deafened(&self, deafened: bool) -> Result<()> {
        self.send(Command::SetDeafened(deafened)).await
    }

    /// Push to talk was chosen: the key decides when to send, so a standing mute goes.
    pub async fn unmute_for_push_to_talk(&self) -> Result<()> {
        self.send(Command::UnmuteForPushToTalk).await
    }
}

/// The call this device is in.
struct Call {
    server_id: [u8; 32],
    channel_id: [u8; 32],
    relay_url: String,
    own_fp: [u8; 32],
    own_device_vk: [u8; 32],
    /// Fresh per call and mixed into our key, so rejoining in the same MLS epoch never
    /// reuses a key and counter pair.
    voice_salt: [u8; 32],
    ws: WsSink,
    udp_port: Option<u16>,
    /// Up once the relay welcomed us.
    media: Option<MediaSession>,
    peers: HashMap<u32, PresenceState>,
    last_speaking: bool,
    ping_sent_at: Option<Instant>,
    last_ping_ms: Option<u32>,
}

/// Serves a `Voice` until every `Voice` is dropped.
pub struct VoiceLoop {
    client: Arc<SharedClient>,
    relay: Arc<SharedRelay>,
    audio: Arc<dyn AudioTrack>,
    commands: mpsc::Receiver<Command>,
}

impl VoiceLoop {
    /// Serve commands, reporting to `sink`.
    pub async fn run(self, sink: Arc<dyn EventSink>) {
        let VoiceLoop { client, relay, audio, commands } = self;
        Runner { client, relay, audio, sink, muted: false, deafened: false }.run(commands).await;
    }
}

/// The running loop's state. Mute and deafen outlive calls.
struct Runner {
    client: Arc<SharedClient>,
    relay: Arc<SharedRelay>,
    audio: Arc<dyn AudioTrack>,
    sink: Arc<dyn EventSink>,
    muted: bool,
    deafened: bool,
}

impl Runner {
    fn emit(&self, event: VoiceEvent) {
        self.sink.emit(ClientEvent::Voice(event));
    }

    fn error(&self, message: String) {
        eprintln!("voice: {message}");
        self.emit(VoiceEvent::Error(message));
    }

    fn state(&self, call: &Option<Call>) -> VoiceState {
        match call {
            Some(call) => VoiceState {
                connected: true,
                server_id: Some(call.server_id),
                channel_id: Some(call.channel_id),
                muted: self.muted,
                deafened: self.deafened,
                udp_port: call.udp_port,
            },
            None => VoiceState { muted: self.muted, deafened: self.deafened, ..VoiceState::default() },
        }
    }

    fn emit_state(&self, call: &Option<Call>) {
        self.emit(VoiceEvent::State(self.state(call)));
    }

    fn emit_participants(&self, call: &Call) {
        let mut everyone: Vec<[u8; 32]> = call.peers.values().map(|p| p.fingerprint).collect();
        everyone.push(call.own_fp);
        self.emit(VoiceEvent::Participants(everyone));
    }

    fn emit_mute_state(&self, peer: &PresenceState) {
        self.emit(VoiceEvent::MuteState { fingerprint: peer.fingerprint, muted: peer.muted, deafened: peer.deafened });
    }

    async fn run(mut self, mut commands: mpsc::Receiver<Command>) {
        let mut call: Option<Call> = None;
        let mut ws_read: Option<WsReader> = None;
        let mut speaking_tick = tokio::time::interval(SPEAKING_POLL);
        let mut quality_tick = tokio::time::interval(QUALITY_POLL);
        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(command) => self.handle_command(command, &mut call, &mut ws_read).await,
                    None => break,
                },
                message = async {
                    match ws_read.as_mut() {
                        Some(read) => read.next().await,
                        None => std::future::pending().await,
                    }
                } => match message {
                    Some(Ok(message)) => self.handle_message(message, &mut call).await,
                    Some(Err(e)) => {
                        self.error(format!("ws read: {e}"));
                        self.reset(&mut call, &mut ws_read);
                    }
                    None => self.reset(&mut call, &mut ws_read),
                },
                _ = speaking_tick.tick() => self.poll_speaking(&mut call).await,
                _ = quality_tick.tick() => self.poll_quality(&mut call).await,
            }
        }
        self.leave(&mut call, &mut ws_read).await;
    }

    async fn handle_command(&mut self, command: Command, call: &mut Option<Call>, ws_read: &mut Option<WsReader>) {
        match command {
            Command::Join { server_id, channel_id, muted, deafened } => {
                self.leave(call, ws_read).await;
                self.muted = muted;
                self.deafened = deafened;
                self.audio.set_muted(muted);
                self.audio.set_deafened(deafened);
                match self.connect(server_id, channel_id).await {
                    Ok((joined, read)) => {
                        *call = Some(joined);
                        *ws_read = Some(read);
                    }
                    Err(e) => self.error(e.to_string()),
                }
                self.emit_state(call);
            }
            Command::Leave => {
                self.leave(call, ws_read).await;
                self.emit_state(call);
            }
            Command::SetMuted(muted) => {
                if !muted && self.deafened {
                    self.deafened = false;
                    self.audio.set_deafened(false);
                }
                self.muted = muted;
                self.audio.set_muted(muted);
                self.mute_changed(call).await;
            }
            Command::SetDeafened(deafened) => {
                self.deafened = deafened;
                self.muted = deafened;
                self.audio.set_muted(deafened);
                self.audio.set_deafened(deafened);
                self.mute_changed(call).await;
            }
            Command::UnmuteForPushToTalk => {
                if self.muted {
                    self.muted = false;
                    self.audio.set_muted(false);
                    self.mute_changed(call).await;
                }
            }
        }
    }

    /// Open the call's signaling socket and announce ourselves. Media starts when the
    /// relay's welcome arrives.
    async fn connect(&self, server_id: [u8; 32], channel_id: [u8; 32]) -> Result<(Call, WsReader)> {
        let mut voice_salt = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut voice_salt);
        // The room belongs to the group carrying the channel (the server's, or a private
        // channel's own), on the relay hosting the server.
        let (own_fp, own_device_vk, mailbox_id, hosting_relay_url, presence) = {
            let client = self.client.lock().await;
            let mailbox_id = client
                .mailbox_id_for_channel(&channel_id)
                .ok_or_else(|| GhostError::Format("voice: channel has no group".into()))?;
            let presence = client.seal_presence_blob(&channel_id, self.muted, self.deafened, voice_salt)?;
            (
                client.identity().fingerprint,
                *client.identity().verifying_key.as_bytes(),
                mailbox_id,
                flows::server_relay_url(&client, &server_id),
                B64.encode(presence),
            )
        };
        flows::sync::post_message(&self.client, &self.relay, SyncMessageType::VoiceTakeover, &channel_id).await;

        let (relay_url, request) = {
            let relay = self.relay.lock().await;
            let relay_url = hosting_relay_url.unwrap_or_else(|| relay.base_url().to_string());
            let request = relay.at(&relay_url).voice_ws_request(&mailbox_id, &channel_id)?;
            (relay_url, request)
        };
        let stream = match tokio::time::timeout(WS_CONNECT_TIMEOUT, tokio_tungstenite::connect_async(request)).await {
            Ok(Ok((stream, _))) => stream,
            Ok(Err(e)) => return Err(GhostError::Network(format!("voice ws connect: {e}"))),
            Err(_) => return Err(GhostError::Network("voice ws connect timed out".into())),
        };
        let (mut ws, read) = stream.split();
        send_msg(&mut ws, &ClientMsg::Join { presence: presence.clone() })
            .await
            .map_err(|e| GhostError::Network(format!("voice ws send: {e}")))?;
        self.announce(&server_id, serde_json::json!({ "vs": { "ch": B64.encode(channel_id), "p": presence } })).await;

        let call = Call {
            server_id,
            channel_id,
            relay_url,
            own_fp,
            own_device_vk,
            voice_salt,
            ws,
            udp_port: None,
            media: None,
            peers: HashMap::new(),
            last_speaking: false,
            ping_sent_at: None,
            last_ping_ms: None,
        };
        Ok((call, read))
    }

    /// Tell the whole server, over its mailbox connection, who is in which call.
    async fn announce(&self, server_id: &[u8; 32], announcement: serde_json::Value) {
        let mailbox_id = self.client.lock().await.mailbox_id_for_server(server_id);
        if let Some(mailbox_id) = mailbox_id {
            let _ = self.relay.lock().await.send_text(&mailbox_id, announcement.to_string()).await;
        }
    }

    /// Leave the call, telling the room and the server.
    async fn leave(&self, call: &mut Option<Call>, ws_read: &mut Option<WsReader>) {
        let Some(current) = call.as_mut() else { return };
        let (server_id, channel_id) = (current.server_id, current.channel_id);
        let _ = tokio::time::timeout(WS_SEND_TIMEOUT, async {
            let _ = send_msg(&mut current.ws, &ClientMsg::Leave).await;
            let _ = current.ws.close().await;
        })
        .await;
        self.announce(&server_id, serde_json::json!({ "vs": { "ch": B64.encode(channel_id), "leave": true } })).await;
        self.reset(call, ws_read);
    }

    /// Drop the call without telling the relay (it already ended the connection).
    fn reset(&self, call: &mut Option<Call>, ws_read: &mut Option<WsReader>) {
        if call.take().is_some() {
            self.audio.stop();
        }
        *ws_read = None;
        self.emit_state(call);
    }

    /// Our mute or deafen changed: report it, and reseal our presence for the room and
    /// the server.
    async fn mute_changed(&self, call: &mut Option<Call>) {
        self.emit_state(call);
        let Some(current) = call.as_mut() else { return };
        let sealed = self.client.lock().await.seal_presence_blob(&current.channel_id, self.muted, self.deafened, current.voice_salt);
        match sealed {
            Ok(blob) => {
                let blob = B64.encode(blob);
                let _ = send_msg(&mut current.ws, &ClientMsg::Presence { blob: blob.clone() }).await;
                let (server_id, channel_id) = (current.server_id, current.channel_id);
                self.announce(&server_id, serde_json::json!({ "vs": { "ch": B64.encode(channel_id), "p": blob } })).await;
            }
            Err(e) => eprintln!("voice: failed to seal presence update: {e}"),
        }
    }

    /// Open a peer's presence blob and derive the key its frames are sealed with.
    async fn open_presence(&self, channel_id: &[u8; 32], blob: &str) -> Result<(PresenceState, [u8; 32])> {
        let blob = B64.decode(blob).map_err(|e| GhostError::Format(format!("presence base64: {e}")))?;
        let client = self.client.lock().await;
        let presence = client.open_presence_blob(channel_id, &blob)?;
        let key = client.derive_voice_key(channel_id, &presence.fingerprint, &presence.device_vk, &presence.voice_salt)?;
        Ok((presence, key))
    }

    /// Open every listed peer's presence; peers whose presence does not open are left out.
    async fn open_peers(&self, channel_id: &[u8; 32], peers: &[PeerEntry]) -> Vec<(u32, PresenceState, [u8; 32])> {
        let mut opened = Vec::new();
        for peer in peers {
            match self.open_presence(channel_id, &peer.presence).await {
                Ok((presence, key)) => opened.push((peer.slot_id, presence, key)),
                Err(e) => eprintln!("voice: presence of slot {} did not open: {e}", peer.slot_id),
            }
        }
        opened
    }

    async fn handle_message(&mut self, message: Message, call: &mut Option<Call>) {
        let Some(current) = call.as_mut() else { return };
        let text = match message {
            Message::Pong(_) => {
                if let Some(sent) = current.ping_sent_at.take() {
                    current.last_ping_ms = Some(sent.elapsed().as_millis() as u32);
                }
                return;
            }
            Message::Text(text) => text,
            _ => return,
        };
        let message = match serde_json::from_str::<ServerMsg>(text.as_str()) {
            Ok(message) => message,
            Err(e) => return self.error(format!("voice ws parse: {e}")),
        };
        match message {
            ServerMsg::Welcome { slot_id, port, room, token, peers } => {
                self.welcome(call, slot_id, port, &room, &token, &peers).await;
            }
            ServerMsg::Joined { slot_id, presence } => match self.open_presence(&current.channel_id, &presence).await {
                Ok((presence, key)) => {
                    self.emit_mute_state(&presence);
                    if let Some(media) = &current.media {
                        let epoch = self.client.lock().await.voice_epoch(&current.channel_id).unwrap_or(0);
                        if let Err(e) = media.set_peer(slot_id, epoch, &key) {
                            eprintln!("voice: key for slot {slot_id}: {e}");
                        }
                    }
                    current.peers.insert(slot_id, presence);
                    self.emit_participants(current);
                }
                Err(e) => eprintln!("voice: presence of joining slot {slot_id} did not open: {e}"),
            },
            ServerMsg::Left { slot_id } => {
                current.peers.remove(&slot_id);
                if let Some(media) = &current.media {
                    media.remove_peer(slot_id);
                }
                self.emit_participants(current);
            }
            ServerMsg::Presence { slot_id, blob } => match self.open_presence(&current.channel_id, &blob).await {
                Ok((presence, _)) => {
                    self.emit_mute_state(&presence);
                    if let Some(known) = current.peers.get_mut(&slot_id) {
                        *known = presence;
                    }
                }
                Err(e) => eprintln!("voice: presence update of slot {slot_id} did not open: {e}"),
            },
            ServerMsg::Speaking { slot_id, speaking } => {
                if let Some(peer) = current.peers.get(&slot_id) {
                    self.emit(VoiceEvent::Speaking { fingerprint: peer.fingerprint, speaking });
                }
            }
            ServerMsg::Error { message } => self.error(format!("relay: {message}")),
        }
    }

    /// The relay admitted us (or, after a resync, resent the room): start media, or
    /// bring the peers up to date if it is already running.
    async fn welcome(&self, call: &mut Option<Call>, slot_id: u32, port: u16, room: &str, token: &str, peers: &[PeerEntry]) {
        let Some(current) = call.as_mut() else { return };
        let epoch = self.client.lock().await.voice_epoch(&current.channel_id).unwrap_or(0);
        let opened = self.open_peers(&current.channel_id, peers).await;
        current.peers = opened.iter().map(|(slot, presence, _)| (*slot, presence.clone())).collect();
        current.udp_port = Some(port);
        self.emit_state(call);
        let Some(current) = call.as_mut() else { return };
        self.emit_participants(current);
        for presence in current.peers.values() {
            self.emit_mute_state(presence);
        }

        if let Some(media) = &current.media {
            media.retain_peers(&opened.iter().map(|(slot, ..)| *slot).collect::<HashSet<u32>>());
            for (slot, _, key) in &opened {
                if let Err(e) = media.set_peer(*slot, epoch, key) {
                    eprintln!("voice: key for slot {slot}: {e}");
                }
            }
            return;
        }
        match self.start_media(current, slot_id, port, room, token, epoch, &opened).await {
            Ok(media) => current.media = Some(media),
            Err(e) => self.error(format!("voice media: {e}")),
        }
    }

    async fn start_media(
        &self,
        call: &Call,
        slot_id: u32,
        port: u16,
        room: &str,
        token: &str,
        epoch: u64,
        peers: &[(u32, PresenceState, [u8; 32])],
    ) -> Result<MediaSession> {
        let (Some(room_id), Some(bind_token)) = (decode_b64_32(room), decode_b64_32(token)) else {
            return Err(GhostError::Format("relay sent a malformed welcome".into()));
        };
        let send_key = self.client.lock().await.derive_voice_key(&call.channel_id, &call.own_fp, &call.own_device_vk, &call.voice_salt)?;
        let endpoint = resolve_endpoint(&call.relay_url, port).await?;
        let config = SessionConfig { endpoint, room_id, slot_id, bind_token, epoch, send_key };
        let (media, received) = MediaSession::start(config).await.map_err(|e| GhostError::Network(e.to_string()))?;
        for (slot, _, key) in peers {
            media.set_peer(*slot, epoch, key).map_err(|e| GhostError::Crypto(e.to_string()))?;
        }
        self.audio.start(TrackIo { sender: media.sender(), received }).map_err(GhostError::Network)?;
        Ok(media)
    }

    async fn poll_speaking(&self, call: &mut Option<Call>) {
        let Some(current) = call.as_mut().filter(|c| c.media.is_some()) else { return };
        let speaking = self.audio.speaking();
        if speaking != current.last_speaking {
            current.last_speaking = speaking;
            self.emit(VoiceEvent::Speaking { fingerprint: current.own_fp, speaking });
            let _ = send_msg(&mut current.ws, &ClientMsg::Speaking { speaking }).await;
        }
    }

    async fn poll_quality(&self, call: &mut Option<Call>) {
        let Some(current) = call.as_mut().filter(|c| c.media.is_some()) else { return };
        self.emit(VoiceEvent::Quality { quality: self.audio.quality(), ping_ms: current.last_ping_ms });
        current.ping_sent_at = Some(Instant::now());
        let _ = current.ws.send(Message::Ping(Vec::new().into())).await;
    }
}

async fn send_msg(ws: &mut WsSink, message: &ClientMsg) -> std::result::Result<(), tokio_tungstenite::tungstenite::Error> {
    let text = serde_json::to_string(message).expect("voice messages serialize");
    ws.send(Message::Text(text.into())).await
}

/// A 32-byte value the relay sent in base64.
fn decode_b64_32(value: &str) -> Option<[u8; 32]> {
    B64.decode(value).ok()?.try_into().ok()
}

/// The relay's voice UDP address: the host of its URL, at the port its welcome named.
async fn resolve_endpoint(relay_url: &str, port: u16) -> Result<SocketAddr> {
    let url = reqwest::Url::parse(relay_url).map_err(|e| GhostError::Format(format!("relay url: {e}")))?;
    let host = url.host_str().ok_or_else(|| GhostError::Format("relay url has no host".into()))?;
    // IPv6 literals keep their URL brackets in `host_str`.
    let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
    let mut addresses =
        tokio::net::lookup_host((host, port)).await.map_err(|e| GhostError::Network(format!("resolve relay: {e}")))?;
    addresses.next().ok_or_else(|| GhostError::Network("relay address resolved to nothing".into()))
}
