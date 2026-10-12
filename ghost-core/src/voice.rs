//! A device's voice calls: signaling with the relay hosting the channel, sealed
//! presence, per-sender keys, and the media session that carries the call's audio.
//! The desktop app and headless devices run this same loop and differ only in the
//! audio track they plug in.
//!
//! A call outlives a dropped signaling connection: the loop reopens it for a while and
//! claims the call's slot back with its token, and media flows on meanwhile. Past that
//! window, or when the relay ends the call on purpose, the call ends and the user is
//! told why.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use ghost_media::{AudioTrack, MediaSession, SessionConfig, TrackEvent, TrackIo, TrackQuality};
pub use ghost_media::MediaPath;
use ghost_wire::presence::PresenceSender;
use ghost_wire::voice::{ClientMsg, PeerEntry, ServerMsg};
use rand::RngCore;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

use crate::error::{GhostError, Result};
use crate::flows::{self, SharedClient};
use crate::relay::RelayClient;
use crate::mls::voice::PresenceState;
use crate::session::{ClientEvent, EventSink};

const WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest a send on the signaling connection may take; one stuck longer is left for the
/// silence check to end.
const WS_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the relay has to welcome a join or a resume.
const WELCOME_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a call rides out a dropped signaling connection, reopening it, before it ends.
const RECONNECT_WINDOW: Duration = Duration::from_secs(30);
/// Between attempts to reopen it.
const RECONNECT_RETRY: Duration = Duration::from_secs(1);
/// Silence on the signaling connection past which it is taken for dead: the relay answers
/// the ping sent every `QUALITY_POLL`, so this is several answers missed.
const SIGNALING_SILENCE_LIMIT: Duration = Duration::from_secs(10);
/// How often the call's deadlines (welcome, silence, reconnecting) are checked.
const CALL_CHECK: Duration = Duration::from_millis(500);
/// How often our own speaking state is checked, to tell the room and the UI.
const SPEAKING_POLL: Duration = Duration::from_millis(100);
/// How often call quality is reported and the relay pinged for latency.
const QUALITY_POLL: Duration = Duration::from_secs(2);

/// How often the call follows this device's epoch in the call's group. When it moves, the
/// presence is sealed again and the send key rotated, so callers at the new epoch can open
/// and hear us, and presences that did not open are tried again.
const EPOCH_POLL: Duration = Duration::from_millis(250);
const COMMAND_QUEUE: usize = 16;

/// What the user is told when the relay stops answering binds.
const NO_MEDIA_PATH: &str = "No voice traffic reaches the voice server; UDP may be blocked on this network";

type WsStream = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type WsSink = SplitSink<WsStream, Message>;
type WsReader = SplitStream<WsStream>;

/// Where a call stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallPhase {
    /// Asked to join; the relay has not welcomed this device yet.
    Joining,
    /// In the call.
    Live,
    /// The signaling connection dropped and is being reopened; the call, and its media,
    /// carry on meanwhile.
    Reconnecting,
}

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
    /// Where the call stands; `None` out of a call.
    pub phase: Option<CallPhase>,
    /// Whether the call's media reaches the relay; `None` until media starts.
    pub media_path: Option<MediaPath>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VoiceEvent {
    State(VoiceState),
    /// Everyone in the call, this account included.
    Participants(Vec<[u8; 32]>),
    Speaking { fingerprint: [u8; 32], speaking: bool },
    MuteState { fingerprint: [u8; 32], muted: bool, deafened: bool },
    Quality { quality: TrackQuality, ping_ms: Option<u32> },
    /// Something went wrong, or the call ended for a reason the user should hear.
    Error(String),
    /// Worth telling the user while the call goes on (a device was replaced by another).
    Notice(String),
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
    /// Whether the loop is in a call right now, for whoever else wants the microphone.
    in_call: Arc<AtomicBool>,
    /// Whether this device is muted, as the loop last reported.
    muted: Arc<AtomicBool>,
}

impl Voice {
    /// A voice controller and the loop that serves it, which the caller runs.
    pub fn new(client: Arc<SharedClient>, relay: Arc<RelayClient>, audio: Arc<dyn AudioTrack>) -> (Self, VoiceLoop) {
        let (commands, receiver) = mpsc::channel(COMMAND_QUEUE);
        let in_call = Arc::new(AtomicBool::new(false));
        let muted = Arc::new(AtomicBool::new(false));
        let voice = Self {
            commands,
            in_call: in_call.clone(),
            muted: muted.clone(),
        };
        let voice_loop = VoiceLoop {
            client,
            relay,
            audio,
            commands: receiver,
            in_call,
            muted,
        };
        (voice, voice_loop)
    }

    /// Whether this device is in a call, so the microphone is spoken for.
    pub fn in_call(&self) -> bool {
        self.in_call.load(Ordering::Relaxed)
    }

    /// Whether this device is muted (deafened included); it outlives calls.
    pub fn muted(&self) -> bool {
        self.muted.load(Ordering::Relaxed)
    }

    async fn send(&self, command: Command) -> Result<()> {
        self.commands.send(command).await.map_err(|_| GhostError::Network("voice loop not running".into()))
    }

    /// Join a channel's call, leaving any other. The relay holds one device per account
    /// in a call, so another device of this account in it is let go.
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
    /// The group carrying the channel, whose room the call is in.
    room_mailbox: [u8; 32],
    relay_url: String,
    own_fp: [u8; 32],
    own_device_vk: [u8; 32],
    /// Fresh per call and mixed into our key, so rejoining in the same MLS epoch never
    /// reuses a key and counter pair.
    voice_salt: [u8; 32],
    phase: CallPhase,
    /// The signaling connection's sending half, while it is up.
    ws: Option<WsSink>,
    /// When the join or resume now waiting for a welcome went out.
    asked_at: Option<Instant>,
    /// When the signaling connection dropped, while reconnecting.
    lost_at: Option<Instant>,
    /// When the next attempt to reopen it is due.
    retry_at: Option<Instant>,
    /// When anything last came from the relay on the signaling connection.
    heard_at: Instant,
    udp_port: Option<u16>,
    /// Our media slot, from the relay's welcome.
    slot_id: Option<u32>,
    /// The slot's token, which keys our binds and claims the slot back after a drop.
    token: Option<[u8; 32]>,
    /// Up once the relay welcomed us.
    media: Option<MediaSession>,
    /// Whether media reaches the relay, as last reported.
    media_path: MediaPath,
    peers: HashMap<u32, PresenceState>,
    /// Callers whose presence did not open, by slot, with the epoch it was last tried at.
    /// Their frames wait in the media session until a key comes.
    unopened: HashMap<u32, Unopened>,
    /// The epoch our presence was last sealed in, which our send key follows.
    epoch: u64,
    last_speaking: bool,
    ping_sent_at: Option<Instant>,
    last_ping_ms: Option<u32>,
}

/// A caller's presence as the relay passed it on, not opened yet.
struct Unopened {
    from: PresenceSender,
    blob: String,
    tried_at_epoch: u64,
}

/// What the loop waits on for the current call besides commands and timers: the
/// signaling connection, an attempt to open one, and the track's reports.
#[derive(Default)]
struct Link {
    read: Option<WsReader>,
    opening: Option<oneshot::Receiver<Result<WsStream>>>,
    track: Option<mpsc::UnboundedReceiver<TrackEvent>>,
}

/// Serves a `Voice` until every `Voice` is dropped.
pub struct VoiceLoop {
    client: Arc<SharedClient>,
    relay: Arc<RelayClient>,
    audio: Arc<dyn AudioTrack>,
    commands: mpsc::Receiver<Command>,
    in_call: Arc<AtomicBool>,
    muted: Arc<AtomicBool>,
}

impl VoiceLoop {
    /// Serve commands, reporting to `sink`.
    pub async fn run(self, sink: Arc<dyn EventSink>) {
        let runner = Runner {
            client: self.client,
            relay: self.relay,
            audio: self.audio,
            sink,
            muted: false,
            deafened: false,
            in_call: self.in_call,
            muted_now: self.muted,
        };
        runner.run(self.commands).await;
    }
}

/// The running loop's state. Mute and deafen outlive calls.
struct Runner {
    client: Arc<SharedClient>,
    relay: Arc<RelayClient>,
    audio: Arc<dyn AudioTrack>,
    sink: Arc<dyn EventSink>,
    muted: bool,
    deafened: bool,
    in_call: Arc<AtomicBool>,
    /// `muted`, for the `Voice` handles to read.
    muted_now: Arc<AtomicBool>,
}

impl Runner {
    fn emit(&self, event: VoiceEvent) {
        self.sink.emit(ClientEvent::Voice(event));
    }

    fn error(&self, message: String) {
        tracing::error!("voice: {message}");
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
                phase: Some(call.phase),
                media_path: call.media.as_ref().map(|_| call.media_path),
            },
            None => VoiceState { muted: self.muted, deafened: self.deafened, ..VoiceState::default() },
        }
    }

    fn emit_state(&self, call: &Option<Call>) {
        self.in_call.store(call.is_some(), Ordering::Relaxed);
        self.muted_now.store(self.muted, Ordering::Relaxed);
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
        let mut link = Link::default();
        let mut connections = self.relay.connections();
        let mut speaking_tick = tokio::time::interval(SPEAKING_POLL);
        let mut quality_tick = tokio::time::interval(QUALITY_POLL);
        let mut epoch_tick = tokio::time::interval(EPOCH_POLL);
        let mut call_tick = tokio::time::interval(CALL_CHECK);
        loop {
            let Link { read, opening, track } = &mut link;
            tokio::select! {
                command = commands.recv() => match command {
                    Some(command) => self.handle_command(command, &mut call, &mut link).await,
                    None => break,
                },
                message = next_message(read) => self.heard(message, &mut call, &mut link).await,
                opened = attempt_outcome(opening) => self.opened(opened, &mut call, &mut link).await,
                event = next_track_event(track) => self.track_event(event, &mut call, &mut link).await,
                mailbox = next_connected(&mut connections) => self.mailbox_connected(mailbox, &call).await,
                _ = speaking_tick.tick() => self.poll_speaking(&mut call).await,
                _ = quality_tick.tick() => self.poll_quality(&mut call).await,
                _ = epoch_tick.tick() => {
                    self.follow_epoch(&mut call).await;
                    self.retry_unopened(&mut call).await;
                }
                _ = call_tick.tick() => self.check_call(&mut call, &mut link).await,
            }
        }
        self.leave(&mut call, &mut link).await;
    }

    async fn handle_command(&mut self, command: Command, call: &mut Option<Call>, link: &mut Link) {
        match command {
            Command::Join { server_id, channel_id, muted, deafened } => {
                self.leave(call, link).await;
                self.muted = muted;
                self.deafened = deafened;
                self.audio.set_muted(muted);
                self.audio.set_deafened(deafened);
                match self.prepare(server_id, channel_id).await {
                    Ok(joining) => {
                        self.start_attempt(&joining, link);
                        *call = Some(joining);
                    }
                    Err(e) => self.error(e.to_string()),
                }
                self.emit_state(call);
            }
            Command::Leave => self.leave(call, link).await,
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

    /// A call to `channel_id`, joining: what the join needs, checked here so a refusal
    /// comes at once. The room belongs to the group carrying the channel (the server's,
    /// or a private channel's own), on the relay hosting the server.
    async fn prepare(&self, server_id: [u8; 32], channel_id: [u8; 32]) -> Result<Call> {
        let mut voice_salt = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut voice_salt);
        let client = self.client.lock().await;
        client.ensure_member(&server_id)?;
        let room_mailbox = client
            .mailbox_id_for_channel(&channel_id)
            .ok_or_else(|| GhostError::Format("voice: channel has no group".into()))?;
        // Sealing now proves the channel's group can carry our presence; each join or
        // resume seals it afresh.
        client.seal_presence_blob(&channel_id, self.muted, self.deafened, voice_salt)?;
        Ok(Call {
            server_id,
            channel_id,
            room_mailbox,
            relay_url: flows::server_relay_url(&client, &server_id).unwrap_or_else(|| self.relay.base_url()),
            own_fp: client.identity().fingerprint,
            own_device_vk: *client.identity().verifying_key.as_bytes(),
            voice_salt,
            phase: CallPhase::Joining,
            ws: None,
            asked_at: None,
            lost_at: None,
            retry_at: None,
            heard_at: Instant::now(),
            udp_port: None,
            slot_id: None,
            token: None,
            media: None,
            media_path: MediaPath::Unconfirmed,
            peers: HashMap::new(),
            unopened: HashMap::new(),
            epoch: client.channel_epoch(&channel_id).unwrap_or(0),
            last_speaking: false,
            ping_sent_at: None,
            last_ping_ms: None,
        })
    }

    /// Open the call's signaling connection in the background; `opened` takes the outcome.
    fn start_attempt(&self, current: &Call, link: &mut Link) {
        let request = self.relay.at(&current.relay_url).voice_ws_request(&current.room_mailbox, &current.channel_id);
        let (reply, outcome) = oneshot::channel();
        tokio::spawn(async move {
            let opened = match request {
                Ok(request) => open_signaling(request).await,
                Err(e) => Err(e),
            };
            let _ = reply.send(opened);
        });
        link.opening = Some(outcome);
    }

    /// The signaling connection opened, or did not. Opened, it asks the relay to resume
    /// the call's slot if it has one, else to join; either way with the presence as it is
    /// now.
    async fn opened(&mut self, opened: Result<WsStream>, call: &mut Option<Call>, link: &mut Link) {
        let stream = match opened {
            Ok(stream) => stream,
            Err(e) => return self.attempt_failed(e, call, link).await,
        };
        let Some(current) = call.as_mut() else { return };
        let (mut ws, read) = stream.split();
        let (presence, epoch) = match self.seal_presence(current).await {
            Ok(sealed) => sealed,
            Err(e) => return self.end_call(format!("Could not join: {e}"), call, link).await,
        };
        let ask = match (current.slot_id, current.token) {
            (Some(slot_id), Some(token)) => ClientMsg::Resume { slot_id, token: B64.encode(token), presence },
            _ => ClientMsg::Join { presence },
        };
        if !send_within(&mut ws, &ask).await {
            return self.attempt_failed(GhostError::Network("voice ws send failed".into()), call, link).await;
        }
        let now = Instant::now();
        current.epoch = epoch;
        current.ws = Some(ws);
        current.asked_at = Some(now);
        current.heard_at = now;
        link.read = Some(read);
    }

    /// An attempt to open the signaling connection failed. A join that never got going
    /// ends, as does a call the relay now refuses; otherwise the next attempt follows.
    async fn attempt_failed(&mut self, e: GhostError, call: &mut Option<Call>, link: &mut Link) {
        let Some(current) = call.as_mut() else { return };
        match current.phase {
            CallPhase::Joining => self.end_call(e.to_string(), call, link).await,
            _ if matches!(e, GhostError::RelayStatus { .. }) => self.end_call(format!("Could not rejoin the call: {e}"), call, link).await,
            _ => {
                tracing::debug!("voice: reopening the signaling connection failed: {e}");
                current.retry_at = Some(Instant::now() + RECONNECT_RETRY);
            }
        }
    }

    /// Something came on the signaling connection, or it ended.
    async fn heard(&mut self, message: Option<std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>, call: &mut Option<Call>, link: &mut Link) {
        let Some(current) = call.as_mut() else { return };
        current.heard_at = Instant::now();
        match message {
            Some(Ok(Message::Close(frame))) => match frame.and_then(|f| ended_by_relay(u16::from(f.code))) {
                Some(why) => self.end_call(why.to_string(), call, link).await,
                None => self.signaling_lost("the voice server closed the connection", call, link).await,
            },
            Some(Ok(message)) => self.handle_message(message, call, link).await,
            Some(Err(e)) => self.signaling_lost(&format!("ws read: {e}"), call, link).await,
            None => self.signaling_lost("the connection ended", call, link).await,
        }
    }

    /// The signaling connection dropped. A join the relay never welcomed ends; a call
    /// under way carries on, media and all, while the connection is reopened.
    async fn signaling_lost(&mut self, why: &str, call: &mut Option<Call>, link: &mut Link) {
        let Some(current) = call.as_mut() else { return };
        link.read = None;
        current.ws = None;
        current.asked_at = None;
        if current.phase == CallPhase::Joining {
            return self.end_call(format!("Could not join: {why}"), call, link).await;
        }
        tracing::info!("voice: signaling connection lost ({why}); reconnecting");
        current.retry_at = Some(Instant::now());
        if current.phase != CallPhase::Reconnecting {
            current.phase = CallPhase::Reconnecting;
            current.lost_at = Some(Instant::now());
            self.emit_state(call);
        }
    }

    /// The call's deadlines: a welcome that does not come, a connection gone quiet, a
    /// reconnection due or out of time.
    async fn check_call(&mut self, call: &mut Option<Call>, link: &mut Link) {
        let Some(current) = call.as_mut() else { return };
        let now = Instant::now();
        if current.asked_at.is_some_and(|at| now.duration_since(at) > WELCOME_TIMEOUT) {
            return match current.phase {
                CallPhase::Joining => self.end_call("The voice server did not answer".into(), call, link).await,
                _ => self.signaling_lost("no welcome", call, link).await,
            };
        }
        if current.phase == CallPhase::Live && now.duration_since(current.heard_at) > SIGNALING_SILENCE_LIMIT {
            return self.signaling_lost("the voice server went quiet", call, link).await;
        }
        if current.phase != CallPhase::Reconnecting {
            return;
        }
        if current.lost_at.is_some_and(|at| now.duration_since(at) > RECONNECT_WINDOW) {
            return self.end_call("Lost the connection to the voice server".into(), call, link).await;
        }
        let idle = current.ws.is_none() && link.opening.is_none();
        if idle && current.retry_at.is_some_and(|at| now >= at) {
            current.retry_at = None;
            self.start_attempt(current, link);
        }
    }

    /// Tell the whole server, over its mailbox connection, who is in which call.
    async fn announce(&self, server_id: &[u8; 32], announcement: serde_json::Value) {
        let mailbox_id = self.client.lock().await.mailbox_id_for_server(server_id);
        if let Some(mailbox_id) = mailbox_id {
            if let Err(e) = self.relay.send_text(&mailbox_id, announcement.to_string()) {
                tracing::debug!("voice: presence on mailbox {} waits for its connection: {e}", ghost_wire::short_id(&mailbox_id));
            }
        }
    }

    /// Our presence in the call as it is now, sealed, and the epoch it was sealed in.
    async fn seal_presence(&self, current: &Call) -> Result<(String, u64)> {
        let client = self.client.lock().await;
        let blob = client.seal_presence_blob(&current.channel_id, self.muted, self.deafened, current.voice_salt)?;
        Ok((B64.encode(blob), client.channel_epoch(&current.channel_id).unwrap_or(0)))
    }

    /// Tell the server that this device is in the call, and how it is muted.
    async fn announce_presence(&self, current: &Call) {
        match self.seal_presence(current).await {
            Ok((blob, _)) => self.announce(&current.server_id, serde_json::json!({ "vs": { "ch": B64.encode(current.channel_id), "p": blob } })).await,
            Err(e) => tracing::warn!("voice: presence not sealed: {e}"),
        }
    }

    /// A mailbox connection came up (`None`: some did, unknown which). The relay may have
    /// withdrawn this device's voice presence while the server's mailbox was away, so a
    /// call under way says again where it is.
    async fn mailbox_connected(&self, mailbox: Option<[u8; 32]>, call: &Option<Call>) {
        let Some(current) = call.as_ref().filter(|c| c.phase != CallPhase::Joining) else { return };
        let server_mailbox = self.client.lock().await.mailbox_id_for_server(&current.server_id);
        if mailbox.is_none() || mailbox == server_mailbox {
            self.announce_presence(current).await;
        }
    }

    /// End the call for a reason the user should hear.
    async fn end_call(&mut self, why: String, call: &mut Option<Call>, link: &mut Link) {
        self.error(why);
        self.leave(call, link).await;
    }

    /// Leave the call: tell the room while the connection is up and the server in any
    /// case, then stop media and audio. Every end of a call comes through here, so no
    /// voice presence outlives the call.
    async fn leave(&mut self, call: &mut Option<Call>, link: &mut Link) {
        *link = Link::default();
        let Some(mut current) = call.take() else { return };
        if let Some(ws) = current.ws.as_mut() {
            let _ = tokio::time::timeout(WS_SEND_TIMEOUT, async {
                let _ = send_msg(ws, &ClientMsg::Leave).await;
                let _ = ws.close().await;
            })
            .await;
        }
        self.announce(&current.server_id, serde_json::json!({ "vs": { "ch": B64.encode(current.channel_id), "leave": true } })).await;
        drop(current);
        self.audio.stop();
        self.emit_state(call);
    }

    /// Our mute or deafen changed: report it, and reseal our presence for the room and
    /// the server.
    async fn mute_changed(&self, call: &mut Option<Call>) {
        self.emit_state(call);
        let Some(current) = call.as_mut().filter(|c| c.phase != CallPhase::Joining) else { return };
        let blob = match self.seal_presence(current).await {
            Ok((blob, _)) => blob,
            Err(e) => return tracing::warn!("voice: failed to seal presence update: {e}"),
        };
        if let Some(ws) = current.ws.as_mut() {
            send_within(ws, &ClientMsg::Presence { blob: blob.clone() }).await;
        }
        self.announce(&current.server_id, serde_json::json!({ "vs": { "ch": B64.encode(current.channel_id), "p": blob } })).await;
    }

    /// What the track reported: a notice for the user, or the end of its audio, which
    /// ends the call.
    async fn track_event(&mut self, event: TrackEvent, call: &mut Option<Call>, link: &mut Link) {
        match event {
            TrackEvent::Notice(notice) => {
                tracing::warn!("voice: {notice}");
                self.emit(VoiceEvent::Notice(notice));
            }
            TrackEvent::Failed(e) => self.end_call(format!("Voice audio stopped: {e}"), call, link).await,
        }
    }

    /// Open a peer's presence blob, as the relay attributed it, and derive the key its
    /// frames are sealed with.
    async fn open_presence(&self, channel_id: &[u8; 32], from: &PresenceSender, blob: &str) -> Result<(PresenceState, [u8; 32])> {
        let blob = B64.decode(blob).map_err(|e| GhostError::Format(format!("presence base64: {e}")))?;
        let client = self.client.lock().await;
        let presence = client.open_presence_blob(channel_id, from, &blob)?;
        let key = client.derive_voice_key(channel_id, &presence.fingerprint, &presence.device_vk, &presence.voice_salt)?;
        Ok((presence, key))
    }

    /// Open every listed peer's presence; those that do not open are returned to be tried
    /// again once this device's epoch moves.
    async fn open_peers(&self, channel_id: &[u8; 32], peers: &[PeerEntry]) -> (Vec<(u32, PresenceState, [u8; 32])>, HashMap<u32, Unopened>) {
        let epoch = self.client.lock().await.channel_epoch(channel_id).unwrap_or(0);
        let mut opened = Vec::new();
        let mut unopened = HashMap::new();
        for peer in peers {
            match self.open_presence(channel_id, &peer.from, &peer.presence).await {
                Ok((presence, key)) => opened.push((peer.slot_id, presence, key)),
                Err(e) => {
                    tracing::debug!("voice: presence of slot {} did not open at epoch {epoch}; tried again when it moves: {e}", peer.slot_id);
                    unopened.insert(peer.slot_id, Unopened { from: peer.from, blob: peer.presence.clone(), tried_at_epoch: epoch });
                }
            }
        }
        (opened, unopened)
    }

    /// Keep a caller's presence that did not open, to try again once the epoch moves.
    async fn keep_unopened(&self, current: &mut Call, slot_id: u32, from: PresenceSender, blob: String, e: &GhostError) {
        let epoch = self.client.lock().await.channel_epoch(&current.channel_id).unwrap_or(0);
        tracing::debug!("voice: presence of slot {slot_id} did not open at epoch {epoch}; tried again when it moves: {e}");
        current.unopened.insert(slot_id, Unopened { from, blob, tried_at_epoch: epoch });
    }

    /// When this device's epoch in the call's group moved, seal our presence again for the
    /// room and the server, and seal what we send with the new epoch's key: callers who
    /// are at the new epoch can open neither what was sealed before. A call the relay has
    /// not welcomed yet waits: its welcome is followed by this check.
    async fn follow_epoch(&self, call: &mut Option<Call>) {
        let Some(current) = call.as_mut().filter(|c| c.phase != CallPhase::Joining) else { return };
        let (epoch, sealed, send_key) = {
            let client = self.client.lock().await;
            let epoch = client.channel_epoch(&current.channel_id).unwrap_or(0);
            if epoch == current.epoch {
                return;
            }
            let sealed = client.seal_presence_blob(&current.channel_id, self.muted, self.deafened, current.voice_salt);
            let send_key = client.derive_voice_key(&current.channel_id, &current.own_fp, &current.own_device_vk, &current.voice_salt);
            (epoch, sealed, send_key)
        };
        let (blob, send_key) = match (sealed, send_key) {
            (Ok(blob), Ok(key)) => (B64.encode(blob), key),
            (Err(e), _) | (_, Err(e)) => {
                tracing::warn!("voice: presence not sealed for epoch {epoch}: {e}");
                return;
            }
        };
        if let Some(media) = &current.media {
            if let Err(e) = media.set_send_key(epoch, &send_key) {
                tracing::warn!("voice: send key for epoch {epoch}: {e}");
                return;
            }
        }
        current.epoch = epoch;
        // While reconnecting, the resume carries the presence sealed afresh.
        if let Some(ws) = current.ws.as_mut() {
            send_within(ws, &ClientMsg::Presence { blob: blob.clone() }).await;
        }
        self.announce(&current.server_id, serde_json::json!({ "vs": { "ch": B64.encode(current.channel_id), "p": blob } })).await;
    }

    /// Try again the presences that did not open, once this device's epoch in the call's
    /// group differs from the one each was tried at; each that opens joins the call.
    async fn retry_unopened(&self, call: &mut Option<Call>) {
        let Some(current) = call.as_mut().filter(|c| !c.unopened.is_empty()) else { return };
        let epoch = self.client.lock().await.channel_epoch(&current.channel_id).unwrap_or(0);
        let due: Vec<u32> = current.unopened.iter().filter(|(_, u)| u.tried_at_epoch != epoch).map(|(slot, _)| *slot).collect();
        if due.is_empty() {
            return;
        }
        for slot_id in due {
            let Some(entry) = current.unopened.remove(&slot_id) else { continue };
            match self.open_presence(&current.channel_id, &entry.from, &entry.blob).await {
                Ok((presence, key)) => {
                    self.emit_mute_state(&presence);
                    if let Some(media) = &current.media {
                        if let Err(e) = media.set_peer(slot_id, epoch, &key) {
                            tracing::warn!("voice: key for slot {slot_id}: {e}");
                        }
                    }
                    current.peers.insert(slot_id, presence);
                }
                Err(_) => {
                    current.unopened.insert(slot_id, Unopened { tried_at_epoch: epoch, ..entry });
                }
            }
        }
        self.emit_participants(current);
    }

    async fn handle_message(&mut self, message: Message, call: &mut Option<Call>, link: &mut Link) {
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
                self.welcome(call, link, slot_id, port, &room, &token, &peers).await;
            }
            ServerMsg::NotResumed => self.rejoin(call, link).await,
            ServerMsg::Joined { slot_id, presence, from } => match self.open_presence(&current.channel_id, &from, &presence).await {
                Ok((presence, key)) => {
                    self.emit_mute_state(&presence);
                    if let Some(media) = &current.media {
                        let epoch = self.client.lock().await.channel_epoch(&current.channel_id).unwrap_or(0);
                        if let Err(e) = media.set_peer(slot_id, epoch, &key) {
                            tracing::warn!("voice: key for slot {slot_id}: {e}");
                        }
                    }
                    current.unopened.remove(&slot_id);
                    current.peers.insert(slot_id, presence);
                    self.emit_participants(current);
                }
                Err(e) => self.keep_unopened(current, slot_id, from, presence, &e).await,
            },
            ServerMsg::Left { slot_id } => {
                current.peers.remove(&slot_id);
                current.unopened.remove(&slot_id);
                if let Some(media) = &current.media {
                    media.remove_peer(slot_id);
                }
                self.emit_participants(current);
            }
            ServerMsg::Presence { slot_id, blob, from } => match self.open_presence(&current.channel_id, &from, &blob).await {
                Ok((presence, key)) => {
                    self.emit_mute_state(&presence);
                    match current.peers.get_mut(&slot_id) {
                        Some(known) => {
                            *known = presence;
                            // Sealed again for a new epoch: its frames follow with the new key.
                            if let Some(media) = &current.media {
                                let epoch = self.client.lock().await.channel_epoch(&current.channel_id).unwrap_or(0);
                                if let Err(e) = media.set_peer(slot_id, epoch, &key) {
                                    tracing::warn!("voice: key for slot {slot_id}: {e}");
                                }
                            }
                        }
                        // A caller whose earlier presence did not open: this one did.
                        None if current.unopened.remove(&slot_id).is_some() => {
                            if let Some(media) = &current.media {
                                let epoch = self.client.lock().await.channel_epoch(&current.channel_id).unwrap_or(0);
                                if let Err(e) = media.set_peer(slot_id, epoch, &key) {
                                    tracing::warn!("voice: key for slot {slot_id}: {e}");
                                }
                            }
                            current.peers.insert(slot_id, presence);
                            self.emit_participants(current);
                        }
                        None => {}
                    }
                }
                // Sealed in an epoch this device is not at: tried again when ours moves, and
                // a caller already heard keeps its current key meanwhile.
                Err(e) => self.keep_unopened(current, slot_id, from, blob, &e).await,
            },
            ServerMsg::Speaking { slot_id, speaking } => {
                if let Some(peer) = current.peers.get(&slot_id) {
                    self.emit(VoiceEvent::Speaking { fingerprint: peer.fingerprint, speaking });
                }
            }
            // Refusing the join or resume waiting for a welcome ends the call: the room is
            // full, or will not have this device.
            ServerMsg::Error { message } if current.asked_at.is_some() => {
                self.end_call(format!("Could not join: {message}"), call, link).await;
            }
            ServerMsg::Error { message } => self.error(format!("relay: {message}")),
        }
    }

    /// The relay no longer has the call's slot (it ended it or restarted): join afresh on
    /// the reopened connection.
    async fn rejoin(&mut self, call: &mut Option<Call>, link: &mut Link) {
        let Some(current) = call.as_mut() else { return };
        let (presence, epoch) = match self.seal_presence(current).await {
            Ok(sealed) => sealed,
            Err(e) => return self.end_call(format!("Could not rejoin the call: {e}"), call, link).await,
        };
        let Some(ws) = current.ws.as_mut() else { return };
        if !send_within(ws, &ClientMsg::Join { presence }).await {
            return self.signaling_lost("send failed", call, link).await;
        }
        current.epoch = epoch;
        current.asked_at = Some(Instant::now());
    }

    /// The relay admitted us, resumed our slot, or resent the room after a resync: start
    /// media on the slot, or bring the running media up to date. A new slot (the old one
    /// was lost) starts media over.
    #[allow(clippy::too_many_arguments)]
    async fn welcome(&mut self, call: &mut Option<Call>, link: &mut Link, slot_id: u32, port: u16, room: &str, token: &str, peers: &[PeerEntry]) {
        let Some(current) = call.as_mut() else { return };
        let (Some(room_id), Some(token)) = (decode_b64_32(room), decode_b64_32(token)) else {
            return self.end_call("The voice server sent a malformed welcome".into(), call, link).await;
        };
        let reconnected = current.phase == CallPhase::Reconnecting;
        if current.media.is_some() && (current.slot_id != Some(slot_id) || current.token != Some(token)) {
            current.media = None;
            link.track = None;
            self.audio.stop();
        }
        current.phase = CallPhase::Live;
        current.asked_at = None;
        current.lost_at = None;
        current.retry_at = None;
        current.slot_id = Some(slot_id);
        current.token = Some(token);
        current.udp_port = Some(port);
        let epoch = self.client.lock().await.channel_epoch(&current.channel_id).unwrap_or(0);
        let (opened, unopened) = self.open_peers(&current.channel_id, peers).await;
        current.peers = opened.iter().map(|(slot, presence, _)| (*slot, presence.clone())).collect();
        current.unopened = unopened;
        self.emit_state(call);
        let Some(current) = call.as_mut() else { return };
        self.emit_participants(current);
        for presence in current.peers.values() {
            self.emit_mute_state(presence);
        }
        // The whole server hears where this device is now that it is in the call.
        self.announce_presence(current).await;

        if let Some(media) = &current.media {
            // Callers not opened yet stay: their frames wait for a key.
            let present: HashSet<u32> = opened.iter().map(|(slot, ..)| *slot).chain(current.unopened.keys().copied()).collect();
            media.retain_peers(&present);
            for (slot, _, key) in &opened {
                if let Err(e) = media.set_peer(*slot, epoch, key) {
                    tracing::warn!("voice: key for slot {slot}: {e}");
                }
            }
            // Our address may have changed with whatever dropped the connection.
            if reconnected {
                media.rebind();
            }
            return;
        }
        match self.start_media(current, slot_id, port, room_id, token, epoch, &opened).await {
            Ok((media, track)) => {
                current.media = Some(media);
                current.media_path = MediaPath::Unconfirmed;
                link.track = Some(track);
                self.emit_state(call);
            }
            Err(e) => self.end_call(format!("Voice media could not start: {e}"), call, link).await,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_media(
        &self,
        call: &Call,
        slot_id: u32,
        port: u16,
        room_id: [u8; 32],
        bind_token: [u8; 32],
        epoch: u64,
        peers: &[(u32, PresenceState, [u8; 32])],
    ) -> Result<(MediaSession, mpsc::UnboundedReceiver<TrackEvent>)> {
        let send_key = self.client.lock().await.derive_voice_key(&call.channel_id, &call.own_fp, &call.own_device_vk, &call.voice_salt)?;
        let endpoint = resolve_endpoint(&call.relay_url, port).await?;
        let config = SessionConfig { endpoint, room_id, slot_id, bind_token, epoch, send_key };
        let (media, received) = MediaSession::start(config).await.map_err(|e| GhostError::Network(e.to_string()))?;
        for (slot, _, key) in peers {
            media.set_peer(*slot, epoch, key).map_err(|e| GhostError::Crypto(e.to_string()))?;
        }
        let (events, track) = mpsc::unbounded_channel();
        self.audio.start(TrackIo { sender: media.sender(), received, events }).map_err(GhostError::Network)?;
        Ok((media, track))
    }

    async fn poll_speaking(&self, call: &mut Option<Call>) {
        let Some(current) = call.as_mut().filter(|c| c.media.is_some()) else { return };
        let speaking = self.audio.speaking();
        if speaking != current.last_speaking {
            current.last_speaking = speaking;
            self.emit(VoiceEvent::Speaking { fingerprint: current.own_fp, speaking });
            if let Some(ws) = current.ws.as_mut() {
                send_within(ws, &ClientMsg::Speaking { speaking }).await;
            }
        }
    }

    /// Report call quality and whether media reaches the relay, and ping the relay, whose
    /// answers time the round trip and keep the connection from counting as quiet.
    async fn poll_quality(&self, call: &mut Option<Call>) {
        let Some(current) = call.as_mut() else { return };
        let mut path_changed = false;
        if let Some(media) = &current.media {
            self.emit(VoiceEvent::Quality { quality: self.audio.quality(), ping_ms: current.last_ping_ms });
            let path = media.media_path();
            if path != current.media_path {
                current.media_path = path;
                path_changed = true;
                if path == MediaPath::Blocked {
                    self.error(NO_MEDIA_PATH.into());
                }
            }
        }
        if current.phase == CallPhase::Live {
            if let Some(ws) = current.ws.as_mut() {
                current.ping_sent_at = Some(Instant::now());
                let _ = tokio::time::timeout(WS_SEND_TIMEOUT, ws.send(Message::Ping(Vec::new().into()))).await;
            }
        }
        if path_changed {
            self.emit_state(call);
        }
    }
}

async fn send_msg(ws: &mut WsSink, message: &ClientMsg) -> std::result::Result<(), tokio_tungstenite::tungstenite::Error> {
    let text = serde_json::to_string(message).expect("voice messages serialize");
    ws.send(Message::Text(text.into())).await
}

/// Send on the signaling connection within `WS_SEND_TIMEOUT`; whether it went.
async fn send_within(ws: &mut WsSink, message: &ClientMsg) -> bool {
    matches!(tokio::time::timeout(WS_SEND_TIMEOUT, send_msg(ws, message)).await, Ok(Ok(())))
}

/// Why the relay ended a call on purpose, by its close code; such a call is not reopened.
fn ended_by_relay(code: u16) -> Option<&'static str> {
    match code {
        ghost_wire::WS_CLOSE_REMOVED => Some("You were removed from this server"),
        ghost_wire::WS_CLOSE_DEVICE_REVOKED => Some("This device was removed from your account"),
        ghost_wire::WS_CLOSE_VOICE_REPLACED => Some("You joined this call from another device"),
        _ => None,
    }
}

/// Open a signaling connection to the relay hosting the call.
async fn open_signaling(request: tokio_tungstenite::tungstenite::http::Request<()>) -> Result<WsStream> {
    match tokio::time::timeout(WS_CONNECT_TIMEOUT, tokio_tungstenite::connect_async(request)).await {
        Ok(Ok((stream, _))) => Ok(stream),
        // The relay refused the call, e.g. to someone no longer in the channel's group.
        Ok(Err(tokio_tungstenite::tungstenite::Error::Http(response))) => {
            let message = response.body().as_deref().map(String::from_utf8_lossy).unwrap_or_default().into_owned();
            Err(GhostError::RelayStatus { status: response.status().as_u16(), context: "join voice".into(), message })
        }
        Ok(Err(e)) => Err(GhostError::Network(format!("voice ws connect: {e}"))),
        Err(_) => Err(GhostError::Network("voice ws connect timed out".into())),
    }
}

/// The next frame on the signaling connection, or its end (`None`); never, without one.
async fn next_message(read: &mut Option<WsReader>) -> Option<std::result::Result<Message, tokio_tungstenite::tungstenite::Error>> {
    match read.as_mut() {
        Some(read) => read.next().await,
        None => std::future::pending().await,
    }
}

/// The outcome of the attempt under way to open a signaling connection; never, without one.
async fn attempt_outcome(opening: &mut Option<oneshot::Receiver<Result<WsStream>>>) -> Result<WsStream> {
    let Some(outcome) = opening.as_mut() else { return std::future::pending().await };
    let opened = outcome.await.unwrap_or_else(|_| Err(GhostError::Network("voice connect attempt vanished".into())));
    *opening = None;
    opened
}

/// The track's next report; never, without a running track.
async fn next_track_event(track: &mut Option<mpsc::UnboundedReceiver<TrackEvent>>) -> TrackEvent {
    loop {
        let Some(events) = track.as_mut() else { return std::future::pending().await };
        match events.recv().await {
            Some(event) => return event,
            // The track stopped on purpose; nothing more comes from it.
            None => *track = None,
        }
    }
}

/// The next mailbox whose connection came up, or `None` when some were missed.
async fn next_connected(connections: &mut broadcast::Receiver<[u8; 32]>) -> Option<[u8; 32]> {
    match connections.recv().await {
        Ok(mailbox) => Some(mailbox),
        Err(RecvError::Lagged(_)) => None,
        Err(RecvError::Closed) => std::future::pending().await,
    }
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
