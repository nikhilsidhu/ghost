use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use ghost_core::client::GhostClient;
use ghost_core::mls::voice::PresenceState;
use ghost_core::relay::RelayClient;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

use crate::audio::AudioPipeline;
use crate::udp_transport::UdpTransport;

const WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const WS_SEND_TIMEOUT: Duration = Duration::from_secs(5);
const SPEAKING_POLL_MS: u64 = 100;
const QUALITY_POLL_MS: u64 = 2000;

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type WsSink = futures_util::stream::SplitSink<WsStream, Message>;
type WsReader = futures_util::stream::SplitStream<WsStream>;

pub enum VoiceCommand {
    Join {
        server_id: String,
        channel_id: String,
        relay_url: String,
        fingerprint: String,
        input_device: Option<String>,
        output_device: Option<String>,
        ns_mode: u8,
        agc_mode: u8,
        vad_threshold: u32,
        input_gain: u32,
        input_mode: u8,
        muted: bool,
        deafened: bool,
    },
    Leave,
    SetMuted(bool),
    SetDeafened(bool),
    SetNoiseSuppression(u8),
    SetAgc(u8),
    SetVadThreshold(u32),
    SetInputGain(u32),
    SetInputMode(u8),
    SetPttActive(bool),
}

#[derive(Clone, Serialize, Default)]
pub struct VoiceStateEvent {
    pub connected: bool,
    pub server_id: Option<String>,
    pub channel_id: Option<String>,
    pub muted: bool,
    pub deafened: bool,
    pub udp_port: Option<u16>,
}

#[derive(Clone, Serialize)]
pub struct VoiceParticipantsEvent {
    pub participants: Vec<String>,
}

#[derive(Clone, Serialize)]
pub struct VoiceSpeakingEvent {
    pub fingerprint: String,
    pub speaking: bool,
}

#[derive(Clone, Serialize)]
pub struct VoiceMuteStateEvent {
    pub fingerprint: String,
    pub muted: bool,
    pub deafened: bool,
}

#[derive(Clone, Serialize)]
pub struct VoiceQualityEvent {
    pub packet_loss: f32,
    pub jitter_depth: u32,
    pub jitter_target: u32,
    pub ping_ms: Option<u32>,
}

// Client → relay
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(dead_code)]
enum ClientMsg {
    Join { presence: String },
    Leave,
    Presence { blob: String },
    Speaking { speaking: bool },
    Resync,
}

// Relay → client
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMsg {
    Welcome { slot_id: u32, port: u16, peers: Vec<PeerEntry> },
    Joined { slot_id: u32, presence: String },
    Left { slot_id: u32 },
    Presence { slot_id: u32, blob: String },
    Speaking { slot_id: u32, speaking: bool },
    Error { message: String },
}

#[derive(Deserialize)]
struct PeerEntry {
    slot_id: u32,
    presence: String,
}

pub struct VoiceHandle {
    pub cmd_tx: mpsc::Sender<VoiceCommand>,
}

/// Active audio session dropped on disconnect to stop everything.
struct AudioSession {
    pipeline: AudioPipeline,
    #[allow(dead_code)]
    own_slot_id: u32,
    own_fp: [u8; 32],
    udp_send_task: JoinHandle<()>,
    udp_recv_task: JoinHandle<()>,
}

impl Drop for AudioSession {
    fn drop(&mut self) {
        self.udp_send_task.abort();
        self.udp_recv_task.abort();
    }
}

fn ws_url(relay_url: &str, channel_id: &str) -> Result<String, String> {
    let channel_bytes = hex::decode(channel_id).map_err(|e| format!("bad channel_id: {e}"))?;
    let channel_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&channel_bytes);
    let base = relay_url
        .replacen("http://", "ws://", 1)
        .replacen("https://", "wss://", 1);
    Ok(format!("{}/voice/{}", base, channel_b64))
}

fn relay_host(relay_url: &str) -> Result<String, String> {
    let parsed = url::Url::parse(relay_url).map_err(|e| format!("bad relay url: {e}"))?;
    parsed
        .host_str()
        .map(|h| h.to_string())
        .ok_or("no host in relay url".into())
}

/// Sends a leave message over WebSocket, closes it, and resets local state.
async fn disconnect(
    app: &AppHandle,
    ws: &mut Option<WsSink>,
    ws_read: &mut Option<WsReader>,
    state: &mut VoiceStateEvent,
    state_tx: &watch::Sender<VoiceStateEvent>,
    peer_state: &mut HashMap<u32, PresenceState>,
    audio: &mut Option<AudioSession>,
) {
    if let Some(ref mut sink) = ws {
        let msg = serde_json::to_string(&ClientMsg::Leave).unwrap();
        let _ = tokio::time::timeout(WS_SEND_TIMEOUT, async {
            let _ = sink.send(Message::Text(msg.into())).await;
            let _ = sink.close().await;
        })
        .await;
    }
    reset(app, ws, ws_read, state, state_tx, peer_state, audio);
}

/// Resets local state (preserves mute/deafen) without notifying the relay.
fn reset(
    app: &AppHandle,
    ws: &mut Option<WsSink>,
    ws_read: &mut Option<WsReader>,
    state: &mut VoiceStateEvent,
    state_tx: &watch::Sender<VoiceStateEvent>,
    peer_state: &mut HashMap<u32, PresenceState>,
    audio: &mut Option<AudioSession>,
) {
    *ws = None;
    *ws_read = None;
    *audio = None;
    *state = VoiceStateEvent {
        muted: state.muted,
        deafened: state.deafened,
        ..VoiceStateEvent::default()
    };
    peer_state.clear();
    let _ = state_tx.send(state.clone());
    let _ = app.emit("voice-state", &state);
}

fn emit_error(app: &AppHandle, msg: &str) {
    eprintln!("voice: {msg}");
    let _ = app.emit("voice-error", msg);
}

fn parse_hex_id(hex: &str) -> Option<[u8; 32]> {
    hex::decode(hex)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
}

/// Emit participant list (fingerprint hex strings) derived from peer_state.
fn emit_participants(app: &AppHandle, peer_state: &HashMap<u32, PresenceState>, own_fp: Option<&[u8; 32]>) {
    let mut fps: Vec<String> = peer_state
        .values()
        .map(|p| hex::encode(p.fingerprint))
        .collect();
    if let Some(fp) = own_fp {
        fps.push(hex::encode(fp));
    }
    let _ = app.emit("voice-participants", &VoiceParticipantsEvent { participants: fps });
}

/// Try to decrypt a presence blob and, on success, derive the voice key for that peer.
async fn process_presence_blob(
    client: &Arc<Mutex<GhostClient>>,
    server_id: &[u8; 32],
    channel_id: &[u8; 32],
    blob_b64: &str,
) -> Result<(ghost_core::mls::voice::PresenceState, [u8; 32]), String> {
    let blob = B64.decode(blob_b64).map_err(|e| format!("bad base64: {e}"))?;
    let c = client.lock().await;
    let ps = c
        .open_presence_blob(server_id, channel_id, &blob)
        .map_err(|e| format!("presence decrypt: {e}"))?;
    let voice_key = c
        .derive_voice_key(server_id, channel_id, &ps.fingerprint, &ps.device_vk, &ps.voice_salt)
        .map_err(|e| format!("derive key: {e}"))?;
    Ok((ps, voice_key))
}

/// Seal a presence blob for the local user.
async fn seal_presence(
    client: &Arc<Mutex<GhostClient>>,
    server_id: &[u8; 32],
    channel_id: &[u8; 32],
    muted: bool,
    deafened: bool,
    voice_salt: [u8; 32],
) -> Result<String, String> {
    let c = client.lock().await;
    let blob = c
        .seal_presence_blob(server_id, channel_id, muted, deafened, voice_salt)
        .map_err(|e| format!("seal presence: {e}"))?;
    Ok(B64.encode(&blob))
}

/// Start the audio pipeline and UDP transport after receiving Welcome.
async fn start_audio(
    client: &Arc<Mutex<GhostClient>>,
    server_id: &[u8; 32],
    channel_id: &[u8; 32],
    own_fp: &[u8; 32],
    own_device_vk: &[u8; 32],
    own_voice_salt: &[u8; 32],
    own_slot_id: u32,
    relay_url: &str,
    port: u16,
    peer_keys: HashMap<u32, ([u8; 32], [u8; 32])>,
    voice_state: &VoiceStateEvent,
    input_device: Option<String>,
    output_device: Option<String>,
) -> Result<AudioSession, String> {
    let (own_key, own_epoch) = {
        let c = client.lock().await;
        let key = c.derive_voice_key(server_id, channel_id, own_fp, own_device_vk, own_voice_salt)
            .map_err(|e| format!("derive own key: {e}"))?;
        let epoch = c.voice_epoch(server_id)
            .map_err(|e| format!("voice epoch: {e}"))?;
        (key, epoch)
    };

    let mut pipeline = AudioPipeline::start(
        own_slot_id, own_key, own_epoch, *channel_id, peer_keys,
        input_device, output_device,
    )?;
    pipeline.controls.muted.store(voice_state.muted, Ordering::Relaxed);
    pipeline.controls.deafened.store(voice_state.deafened, Ordering::Relaxed);

    let host = relay_host(relay_url)?;
    let transport = Arc::new(UdpTransport::connect(&host, port).await?);

    // Registration packet so relay learns our UDP address before we transmit audio
    let reg_pkt = crate::audio::build_packet(channel_id, own_slot_id, own_epoch, 0, &[]);
    if let Err(e) = transport.socket.send(&reg_pkt).await {
        eprintln!("voice udp registration send: {e}");
    }

    let mut outbound_rx = pipeline
        .outbound_rx
        .take()
        .ok_or("outbound_rx already taken")?;
    let inbound_tx = pipeline.inbound_tx.clone();

    let transport_send = transport.clone();
    let udp_send_task = tokio::spawn(async move {
        while let Some(pkt) = outbound_rx.recv().await {
            if let Err(e) = transport_send.socket.send(&pkt).await {
                eprintln!("voice udp send: {e}");
            }
        }
    });
    let udp_recv_task = tokio::spawn(async move {
        transport.recv_loop(inbound_tx, own_slot_id).await;
    });

    Ok(AudioSession {
        pipeline,
        own_slot_id,
        own_fp: *own_fp,
        udp_send_task,
        udp_recv_task,
    })
}

/// Context saved between receiving Join command and the relay's Welcome response.
struct PendingJoin {
    server_id: [u8; 32],
    channel_id: [u8; 32],
    relay_url: String,
    own_fp: [u8; 32],
    own_device_vk: [u8; 32],
    voice_salt: [u8; 32],
    input_device: Option<String>,
    output_device: Option<String>,
    ns_mode: u8,
    agc_mode: u8,
    vad_threshold: u32,
    input_gain: u32,
    input_mode: u8,
}

fn apply_pending_settings(p: &PendingJoin, session: &AudioSession) {
    let c = &session.pipeline.controls;
    c.noise_suppression.store(p.ns_mode, Ordering::Relaxed);
    c.agc.store(p.agc_mode, Ordering::Relaxed);
    c.vad_threshold.store(p.vad_threshold, Ordering::Relaxed);
    c.input_gain.store(p.input_gain, Ordering::Relaxed);
    c.input_mode.store(p.input_mode, Ordering::Relaxed);
}

/// Send a presence blob update to the relay (used on mute/deafen change).
async fn send_presence_update(
    ws: &mut Option<WsSink>,
    client: &Arc<Mutex<GhostClient>>,
    server_id: &[u8; 32],
    channel_id: &[u8; 32],
    muted: bool,
    deafened: bool,
    voice_salt: [u8; 32],
) {
    let Some(ref mut sink) = ws else { return };
    match seal_presence(client, server_id, channel_id, muted, deafened, voice_salt).await {
        Ok(blob_b64) => {
            let msg = serde_json::to_string(&ClientMsg::Presence { blob: blob_b64 }).unwrap();
            let _ = sink.send(Message::Text(msg.into())).await;
        }
        Err(e) => eprintln!("voice: failed to seal presence update: {e}"),
    }
}

/// Send a voice state JSON frame over the mailbox WS for server-wide visibility.
async fn send_mailbox_vs(
    relay: &Arc<Mutex<RelayClient>>,
    client: &Arc<Mutex<GhostClient>>,
    server_id: &[u8; 32],
    json: String,
) {
    let mailbox_id = {
        let c = client.lock().await;
        c.mailbox_id_for_server(server_id)
    };
    if let Some(mid) = mailbox_id {
        let r = relay.lock().await;
        let _ = r.send_text(&mid, json).await;
    }
}

pub async fn run(
    app: AppHandle,
    client: Arc<Mutex<GhostClient>>,
    relay: Arc<Mutex<RelayClient>>,
    mut cmd_rx: mpsc::Receiver<VoiceCommand>,
    state_tx: watch::Sender<VoiceStateEvent>,
) {
    let mut state = VoiceStateEvent::default();
    let mut ws: Option<WsSink> = None;
    let mut ws_read: Option<WsReader> = None;
    let mut peer_state: HashMap<u32, PresenceState> = HashMap::new();
    let mut audio: Option<AudioSession> = None;
    let mut last_speaking = false;
    let mut speaking_timer = tokio::time::interval(Duration::from_millis(SPEAKING_POLL_MS));

    let mut pending: Option<PendingJoin> = None;
    let mut quality_timer = tokio::time::interval(Duration::from_millis(QUALITY_POLL_MS));
    let mut ping_sent_at: Option<Instant> = None;
    let mut last_ping_ms: Option<u32> = None;

    // Parsed IDs cached while connected (avoids re-parsing on every presence update)
    let mut active_server_id: Option<[u8; 32]> = None;
    let mut active_channel_id: Option<[u8; 32]> = None;
    // Random salt generated per voice session, reused for all presence updates
    let mut active_voice_salt: [u8; 32] = [0u8; 32];

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break };
                match cmd {
                    VoiceCommand::Join { server_id, channel_id, relay_url, fingerprint, input_device, output_device, ns_mode, agc_mode, vad_threshold, input_gain, input_mode, muted, deafened } => {
                        disconnect(&app, &mut ws, &mut ws_read, &mut state, &state_tx, &mut peer_state, &mut audio).await;
                        pending = None;
                        active_server_id = None;
                        active_channel_id = None;

                        let server_id_bytes = match parse_hex_id(&server_id) {
                            Some(b) => b,
                            None => { emit_error(&app, "bad server_id"); continue; }
                        };
                        let channel_id_bytes = match parse_hex_id(&channel_id) {
                            Some(b) => b,
                            None => { emit_error(&app, "bad channel_id"); continue; }
                        };
                        let own_fp = match parse_hex_id(&fingerprint) {
                            Some(b) => b,
                            None => { emit_error(&app, "bad fingerprint"); continue; }
                        };
                        let own_device_vk = {
                            let c = client.lock().await;
                            *c.identity().verifying_key.as_bytes()
                        };

                        // Generate a random salt for this voice session
                        use rand::RngCore;
                        let mut voice_salt = [0u8; 32];
                        rand::rngs::OsRng.fill_bytes(&mut voice_salt);
                        active_voice_salt = voice_salt;

                        let url = match ws_url(&relay_url, &channel_id) {
                            Ok(u) => u,
                            Err(e) => {
                                emit_error(&app, &e);
                                continue;
                            }
                        };

                        // Seal initial presence blob
                        let presence_b64 = match seal_presence(&client, &server_id_bytes, &channel_id_bytes, muted, deafened, voice_salt).await {
                            Ok(b) => b,
                            Err(e) => {
                                emit_error(&app, &format!("seal presence: {e}"));
                                continue;
                            }
                        };

                        let stream = match tokio::time::timeout(
                            WS_CONNECT_TIMEOUT,
                            tokio_tungstenite::connect_async(&url),
                        ).await {
                            Ok(Ok((stream, _))) => stream,
                            Ok(Err(e)) => {
                                emit_error(&app, &format!("ws connect: {e}"));
                                continue;
                            }
                            Err(_) => {
                                emit_error(&app, "ws connect timed out");
                                continue;
                            }
                        };
                        let (mut sink, read) = stream.split();
                        let join_msg = serde_json::to_string(&ClientMsg::Join { presence: presence_b64.clone() }).unwrap();
                        if let Err(e) = sink.send(Message::Text(join_msg.into())).await {
                            emit_error(&app, &format!("ws send: {e}"));
                            continue;
                        }

                        // Broadcast voice state over mailbox WS after successful voice WS join
                        let ch_b64 = B64.encode(channel_id_bytes);
                        let vs_json = serde_json::json!({"vs":{"ch":&ch_b64,"p":&presence_b64}}).to_string();
                        send_mailbox_vs(&relay, &client, &server_id_bytes, vs_json).await;
                        ws = Some(sink);
                        ws_read = Some(read);
                        state = VoiceStateEvent {
                            connected: true,
                            server_id: Some(server_id),
                            channel_id: Some(channel_id),
                            muted,
                            deafened,
                            udp_port: None,
                        };
                        active_server_id = Some(server_id_bytes);
                        active_channel_id = Some(channel_id_bytes);
                        pending = Some(PendingJoin {
                            server_id: server_id_bytes,
                            channel_id: channel_id_bytes,
                            relay_url,
                            own_fp,
                            own_device_vk,
                            voice_salt,
                            input_device,
                            output_device,
                            ns_mode,
                            agc_mode,
                            vad_threshold,
                            input_gain,
                            input_mode,
                        });
                        let _ = state_tx.send(state.clone());
                        let _ = app.emit("voice-state", &state);
                    }
                    VoiceCommand::Leave => {
                        // Broadcast leave over mailbox WS
                        if let (Some(sid), Some(cid)) = (active_server_id, active_channel_id) {
                            let ch_b64 = B64.encode(cid);
                            let vs_json = serde_json::json!({"vs":{"ch":ch_b64,"leave":true}}).to_string();
                            send_mailbox_vs(&relay, &client, &sid, vs_json).await;
                        }
                        disconnect(&app, &mut ws, &mut ws_read, &mut state, &state_tx, &mut peer_state, &mut audio).await;
                        pending = None;
                        active_server_id = None;
                        active_channel_id = None;
                    }
                    VoiceCommand::SetMuted(muted) => {
                        // unmuting while deafened also undeafens
                        if !muted && state.deafened {
                            state.deafened = false;
                            if let Some(ref session) = audio {
                                session.pipeline.controls.deafened.store(false, Ordering::Relaxed);
                            }
                        }
                        state.muted = muted;
                        if let Some(ref session) = audio {
                            session.pipeline.controls.muted.store(muted, Ordering::Relaxed);
                        }
                        let _ = state_tx.send(state.clone());
                        let _ = app.emit("voice-state", &state);
                        if let (Some(sid), Some(cid)) = (active_server_id, active_channel_id) {
                            send_presence_update(&mut ws, &client, &sid, &cid, state.muted, state.deafened, active_voice_salt).await;
                            // Also broadcast over mailbox WS
                            if let Ok(blob_b64) = seal_presence(&client, &sid, &cid, state.muted, state.deafened, active_voice_salt).await {
                                let ch_b64 = B64.encode(cid);
                                let vs_json = serde_json::json!({"vs":{"ch":ch_b64,"p":blob_b64}}).to_string();
                                send_mailbox_vs(&relay, &client, &sid, vs_json).await;
                            }
                        }
                    }
                    VoiceCommand::SetDeafened(deafened) => {
                        state.deafened = deafened;
                        state.muted = deafened;
                        if let Some(ref session) = audio {
                            session.pipeline.controls.muted.store(deafened, Ordering::Relaxed);
                            session.pipeline.controls.deafened.store(deafened, Ordering::Relaxed);
                        }
                        let _ = state_tx.send(state.clone());
                        let _ = app.emit("voice-state", &state);
                        if let (Some(sid), Some(cid)) = (active_server_id, active_channel_id) {
                            send_presence_update(&mut ws, &client, &sid, &cid, state.muted, state.deafened, active_voice_salt).await;
                            // Also broadcast over mailbox WS
                            if let Ok(blob_b64) = seal_presence(&client, &sid, &cid, state.muted, state.deafened, active_voice_salt).await {
                                let ch_b64 = B64.encode(cid);
                                let vs_json = serde_json::json!({"vs":{"ch":ch_b64,"p":blob_b64}}).to_string();
                                send_mailbox_vs(&relay, &client, &sid, vs_json).await;
                            }
                        }
                    }
                    VoiceCommand::SetNoiseSuppression(mode) => {
                        if let Some(ref session) = audio {
                            session.pipeline.controls.noise_suppression.store(mode, Ordering::Relaxed);
                        }
                    }
                    VoiceCommand::SetVadThreshold(bits) => {
                        if let Some(ref session) = audio {
                            session.pipeline.controls.vad_threshold.store(bits, Ordering::Relaxed);
                        }
                    }
                    VoiceCommand::SetInputGain(bits) => {
                        if let Some(ref session) = audio {
                            session.pipeline.controls.input_gain.store(bits, Ordering::Relaxed);
                        }
                    }
                    VoiceCommand::SetAgc(mode) => {
                        if let Some(ref session) = audio {
                            session.pipeline.controls.agc.store(mode, Ordering::Relaxed);
                        }
                    }
                    VoiceCommand::SetInputMode(mode) => {
                        if let Some(ref session) = audio {
                            session.pipeline.controls.input_mode.store(mode, Ordering::Relaxed);
                        }
                        if mode == crate::audio::INPUT_MODE_PTT && state.muted {
                            state.muted = false;
                            if let Some(ref session) = audio {
                                session.pipeline.controls.muted.store(false, Ordering::Relaxed);
                            }
                            let _ = state_tx.send(state.clone());
                            let _ = app.emit("voice-state", &state);
                            if let (Some(sid), Some(cid)) = (active_server_id, active_channel_id) {
                                send_presence_update(&mut ws, &client, &sid, &cid, state.muted, state.deafened, active_voice_salt).await;
                                if let Ok(blob_b64) = seal_presence(&client, &sid, &cid, state.muted, state.deafened, active_voice_salt).await {
                                    let ch_b64 = B64.encode(cid);
                                    let vs_json = serde_json::json!({"vs":{"ch":ch_b64,"p":blob_b64}}).to_string();
                                    send_mailbox_vs(&relay, &client, &sid, vs_json).await;
                                }
                            }
                        }
                    }
                    VoiceCommand::SetPttActive(active) => {
                        if let Some(ref session) = audio {
                            session.pipeline.controls.ptt_active.store(active, Ordering::Relaxed);
                        }
                    }
                }
            }
            msg = async {
                match ws_read.as_mut() {
                    Some(read) => read.next().await,
                    None => std::future::pending().await,
                }
            } => {
                let Some(msg) = msg else {
                    reset(&app, &mut ws, &mut ws_read, &mut state, &state_tx, &mut peer_state, &mut audio);
                    pending = None;
                    active_server_id = None;
                    active_channel_id = None;
                    continue;
                };
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => {
                        emit_error(&app, &format!("ws read: {e}"));
                        reset(&app, &mut ws, &mut ws_read, &mut state, &state_tx, &mut peer_state, &mut audio);
                        pending = None;
                        active_server_id = None;
                        active_channel_id = None;
                        continue;
                    }
                };
                if let Message::Pong(_) = &msg {
                    if let Some(sent) = ping_sent_at.take() {
                        last_ping_ms = Some(sent.elapsed().as_millis() as u32);
                    }
                }
                if let Message::Text(text) = msg {
                    match serde_json::from_str::<ServerMsg>(text.as_str()) {
                        Ok(server_msg) => match server_msg {
                            ServerMsg::Welcome { slot_id, port, peers } => {
                                let Some(p) = pending.take() else {
                                    // Resync: relay pushed fresh state after broadcast lag
                                    let Some(ref session) = audio else { continue };
                                    let (Some(sid), Some(cid)) = (active_server_id, active_channel_id) else { continue };
                                    let mut new_peer_state: HashMap<u32, PresenceState> = HashMap::new();
                                    let mut new_keys: HashMap<u32, ([u8; 32], [u8; 32])> = HashMap::new();
                                    for peer in &peers {
                                        match process_presence_blob(&client, &sid, &cid, &peer.presence).await {
                                            Ok((ps, voice_key)) => {
                                                new_keys.insert(peer.slot_id, (ps.fingerprint, voice_key));
                                                new_peer_state.insert(peer.slot_id, ps);
                                            }
                                            Err(e) => eprintln!("voice: resync decrypt (slot {}): {e}", peer.slot_id),
                                        }
                                    }
                                    if let Ok(mut pk) = session.pipeline.peer_keys.lock() {
                                        pk.clear();
                                        pk.extend(new_keys);
                                    }
                                    peer_state = new_peer_state;
                                    emit_participants(&app, &peer_state, Some(&session.own_fp));
                                    for ps in peer_state.values() {
                                        let _ = app.emit("voice-mute-state", &VoiceMuteStateEvent {
                                            fingerprint: hex::encode(ps.fingerprint),
                                            muted: ps.muted,
                                            deafened: ps.deafened,
                                        });
                                    }
                                    eprintln!("voice: resync complete, {} peers", peer_state.len());
                                    continue;
                                };

                                // Decrypt peer presence blobs and collect voice keys
                                let mut initial_keys: HashMap<u32, ([u8; 32], [u8; 32])> = HashMap::new();
                                for peer in &peers {
                                    match process_presence_blob(&client, &p.server_id, &p.channel_id, &peer.presence).await {
                                        Ok((ps, voice_key)) => {
                                            initial_keys.insert(peer.slot_id, (ps.fingerprint, voice_key));
                                            peer_state.insert(peer.slot_id, ps);
                                        }
                                        Err(e) => eprintln!("voice: failed to decrypt peer presence (slot {}): {e}", peer.slot_id),
                                    }
                                }

                                state.udp_port = Some(port);
                                let _ = state_tx.send(state.clone());
                                let _ = app.emit("voice-state", &state);
                                emit_participants(&app, &peer_state, Some(&p.own_fp));

                                for ps in peer_state.values() {
                                    let _ = app.emit("voice-mute-state", &VoiceMuteStateEvent {
                                        fingerprint: hex::encode(ps.fingerprint),
                                        muted: ps.muted,
                                        deafened: ps.deafened,
                                    });
                                }

                                match start_audio(
                                    &client, &p.server_id, &p.channel_id, &p.own_fp, &p.own_device_vk,
                                    &p.voice_salt, slot_id, &p.relay_url, port, initial_keys, &state,
                                    p.input_device.clone(), p.output_device.clone(),
                                ).await {
                                    Ok(session) => {
                                        apply_pending_settings(&p, &session);
                                        audio = Some(session);
                                    }
                                    Err(e) => emit_error(&app, &format!("audio start: {e}")),
                                }
                            }
                            ServerMsg::Joined { slot_id, presence } => {
                                let (Some(sid), Some(cid)) = (active_server_id, active_channel_id) else { continue };
                                match process_presence_blob(&client, &sid, &cid, &presence).await {
                                    Ok((ps, voice_key)) => {
                                        let _ = app.emit("voice-mute-state", &VoiceMuteStateEvent {
                                            fingerprint: hex::encode(ps.fingerprint),
                                            muted: ps.muted,
                                            deafened: ps.deafened,
                                        });
                                        if let Some(ref session) = audio {
                                            if let Ok(mut pk) = session.pipeline.peer_keys.lock() {
                                                pk.insert(slot_id, (ps.fingerprint, voice_key));
                                            }
                                        }
                                        peer_state.insert(slot_id, ps);
                                        emit_participants(&app, &peer_state, audio.as_ref().map(|s| &s.own_fp));
                                    }
                                    Err(e) => eprintln!("voice: failed to decrypt joined presence (slot {slot_id}): {e}"),
                                }
                            }
                            ServerMsg::Left { slot_id } => {
                                peer_state.remove(&slot_id);
                                if let Some(ref session) = audio {
                                    if let Ok(mut pk) = session.pipeline.peer_keys.lock() {
                                        pk.remove(&slot_id);
                                    }
                                }
                                emit_participants(&app, &peer_state, audio.as_ref().map(|s| &s.own_fp));
                            }
                            ServerMsg::Presence { slot_id, blob } => {
                                let (Some(sid), Some(cid)) = (active_server_id, active_channel_id) else { continue };
                                match process_presence_blob(&client, &sid, &cid, &blob).await {
                                    Ok((ps, _)) => {
                                        let _ = app.emit("voice-mute-state", &VoiceMuteStateEvent {
                                            fingerprint: hex::encode(ps.fingerprint),
                                            muted: ps.muted,
                                            deafened: ps.deafened,
                                        });
                                        if peer_state.contains_key(&slot_id) {
                                            peer_state.insert(slot_id, ps);
                                        }
                                    }
                                    Err(e) => eprintln!("voice: failed to decrypt presence update (slot {slot_id}): {e}"),
                                }
                            }
                            ServerMsg::Speaking { slot_id, speaking } => {
                                if let Some(info) = peer_state.get(&slot_id) {
                                    let _ = app.emit("voice-speaking", &VoiceSpeakingEvent {
                                        fingerprint: hex::encode(info.fingerprint),
                                        speaking,
                                    });
                                }
                            }
                            ServerMsg::Error { message } => {
                                emit_error(&app, &format!("server: {message}"));
                            }
                        },
                        Err(e) => emit_error(&app, &format!("ws parse: {e}")),
                    }
                }
            }
            // Poll local speaking state and send Speaking messages to relay + frontend
            _ = speaking_timer.tick() => {
                if let Some(ref session) = audio {
                    let speaking = session.pipeline.controls.speaking.load(Ordering::Relaxed);
                    if speaking != last_speaking {
                        last_speaking = speaking;
                        let fp_hex = hex::encode(session.own_fp);
                        let _ = app.emit("voice-speaking", &VoiceSpeakingEvent { fingerprint: fp_hex, speaking });
                        if let Some(ref mut sink) = ws {
                            let msg = serde_json::to_string(&ClientMsg::Speaking { speaking }).unwrap();
                            let _ = sink.send(Message::Text(msg.into())).await;
                        }
                    }
                }
            }
            // Poll quality metrics from audio pipeline and measure relay ping
            _ = quality_timer.tick() => {
                if let Some(ref session) = audio {
                    let c = &session.pipeline.controls;
                    let loss = f32::from_bits(c.packet_loss_pct.load(Ordering::Relaxed));
                    let depth = c.jitter_depth.load(Ordering::Relaxed);
                    let target = c.jitter_target.load(Ordering::Relaxed);
                    let _ = app.emit("voice-quality", &VoiceQualityEvent {
                        packet_loss: loss,
                        jitter_depth: depth,
                        jitter_target: target,
                        ping_ms: last_ping_ms,
                    });
                    if let Some(ref mut sink) = ws {
                        ping_sent_at = Some(Instant::now());
                        let _ = sink.send(Message::Ping(vec![].into())).await;
                    }
                }
            }
        }
    }
}
