use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use ghost_core::client::GhostClient;
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
        group_id: String,
        channel_id: String,
        relay_url: String,
        fingerprint: String,
        input_device: Option<String>,
        output_device: Option<String>,
        ns_mode: u8,
        agc_mode: u8,
    },
    Leave,
    SetMuted(bool),
    SetDeafened(bool),
    SetNoiseSuppression(u8),
    SetAgc(u8),
}

#[derive(Clone, Serialize, Default)]
pub struct VoiceStateEvent {
    pub connected: bool,
    pub group_id: Option<String>,
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

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMsg {
    Join { fingerprint: String },
    Leave,
    Speaking { speaking: bool },
    MuteState { muted: bool, deafened: bool },
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMsg {
    Participants { list: Vec<String> },
    Assigned { port: u16 },
    Joined { fingerprint: String },
    Left { fingerprint: String },
    Speaking { fingerprint: String, speaking: bool },
    MuteState { fingerprint: String, muted: bool, deafened: bool },
    Error { message: String },
}

pub struct VoiceHandle {
    pub cmd_tx: mpsc::Sender<VoiceCommand>,
}

/// Active audio session dropped on disconnect to stop everything.
struct AudioSession {
    pipeline: AudioPipeline,
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
    participants: &mut Vec<String>,
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
    reset(app, ws, ws_read, state, state_tx, participants, audio);
}

/// Resets local state (preserves mute/deafen) without notifying the relay.
fn reset(
    app: &AppHandle,
    ws: &mut Option<WsSink>,
    ws_read: &mut Option<WsReader>,
    state: &mut VoiceStateEvent,
    state_tx: &watch::Sender<VoiceStateEvent>,
    participants: &mut Vec<String>,
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
    participants.clear();
    let _ = state_tx.send(state.clone());
    let _ = app.emit("voice-state", &state);
}

fn emit_error(app: &AppHandle, msg: &str) {
    eprintln!("voice: {msg}");
    let _ = app.emit("voice-error", msg);
}

/// Context saved between receiving Join and the relay's Assigned+Participants responses.
struct PendingAudioStart {
    group_id: String,
    channel_id: String,
    relay_url: String,
    fingerprint: String,
    participant_fps: Vec<String>,
    input_device: Option<String>,
    output_device: Option<String>,
    ns_mode: u8,
    agc_mode: u8,
}

/// Derive voice encryption keys for a set of participant fingerprints.
async fn derive_peer_keys(
    client: &Arc<Mutex<GhostClient>>,
    group_id: &[u8; 32],
    channel_id: &[u8; 32],
    fp_hexes: &[String],
) -> Result<HashMap<[u8; 32], [u8; 32]>, String> {
    let client = client.lock().await;
    let mut keys = HashMap::new();
    for fp_hex in fp_hexes {
        let fp: [u8; 32] = hex::decode(fp_hex)
            .map_err(|e| format!("bad fp: {e}"))?
            .try_into()
            .map_err(|_| "fp not 32 bytes")?;
        let key = client
            .derive_voice_key(group_id, channel_id, &fp)
            .map_err(|e| format!("derive key: {e}"))?;
        keys.insert(fp, key);
    }
    Ok(keys)
}

/// Start the audio pipeline and UDP transport after receiving Assigned + Participants.
async fn start_audio(
    client: &Arc<Mutex<GhostClient>>,
    group_id_hex: &str,
    channel_id_hex: &str,
    own_fp_hex: &str,
    relay_url: &str,
    port: u16,
    participant_fps: &[String],
    voice_state: &VoiceStateEvent,
    input_device: Option<String>,
    output_device: Option<String>,
) -> Result<AudioSession, String> {
    let group_id: [u8; 32] = hex::decode(group_id_hex)
        .map_err(|e| format!("bad group_id: {e}"))?
        .try_into()
        .map_err(|_| "group_id not 32 bytes".to_string())?;
    let channel_id: [u8; 32] = hex::decode(channel_id_hex)
        .map_err(|e| format!("bad channel_id: {e}"))?
        .try_into()
        .map_err(|_| "channel_id not 32 bytes".to_string())?;
    let own_fp: [u8; 32] = hex::decode(own_fp_hex)
        .map_err(|e| format!("bad own_fp: {e}"))?
        .try_into()
        .map_err(|_| "own_fp not 32 bytes".to_string())?;

    // Derive own key
    let own_key = {
        let c = client.lock().await;
        c.derive_voice_key(&group_id, &channel_id, &own_fp)
            .map_err(|e| format!("derive own key: {e}"))?
    };

    // Derive peer keys (excluding self)
    let peer_fps: Vec<String> = participant_fps
        .iter()
        .filter(|fp| fp.as_str() != own_fp_hex)
        .cloned()
        .collect();
    let peer_keys = derive_peer_keys(client, &group_id, &channel_id, &peer_fps).await?;

    let mut pipeline = AudioPipeline::start(own_fp, own_key, channel_id, peer_keys, input_device, output_device)?;
    pipeline.controls.muted.store(voice_state.muted, Ordering::Relaxed);
    pipeline.controls.deafened.store(voice_state.deafened, Ordering::Relaxed);

    let host = relay_host(relay_url)?;
    let transport = Arc::new(UdpTransport::connect(&host, port).await?);

    let outbound_rx = pipeline
        .outbound_rx
        .take()
        .ok_or("outbound_rx already taken")?;
    let inbound_tx = pipeline.inbound_tx.clone();

    let transport_send = transport.clone();
    let udp_send_task = tokio::spawn(async move {
        transport_send.send_loop(outbound_rx).await;
    });
    let udp_recv_task = tokio::spawn(async move {
        transport.recv_loop(inbound_tx, own_fp).await;
    });

    Ok(AudioSession {
        pipeline,
        udp_send_task,
        udp_recv_task,
    })
}

pub async fn run(
    app: AppHandle,
    client: Arc<Mutex<GhostClient>>,
    mut cmd_rx: mpsc::Receiver<VoiceCommand>,
    state_tx: watch::Sender<VoiceStateEvent>,
) {
    let mut state = VoiceStateEvent::default();
    let mut ws: Option<WsSink> = None;
    let mut ws_read: Option<WsReader> = None;
    let mut participants: Vec<String> = Vec::new();
    let mut audio: Option<AudioSession> = None;
    let mut last_speaking = false;
    let mut speaking_timer = tokio::time::interval(Duration::from_millis(SPEAKING_POLL_MS));

    let mut pending: Option<PendingAudioStart> = None;
    let mut assigned_port: Option<u16> = None;
    let mut quality_timer = tokio::time::interval(Duration::from_millis(QUALITY_POLL_MS));
    let mut ping_sent_at: Option<Instant> = None;
    let mut last_ping_ms: Option<u32> = None;

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break };
                match cmd {
                    VoiceCommand::Join { group_id, channel_id, relay_url, fingerprint, input_device, output_device, ns_mode, agc_mode } => {
                        disconnect(&app, &mut ws, &mut ws_read, &mut state, &state_tx, &mut participants, &mut audio).await;
                        pending = None;
                        assigned_port = None;

                        let url = match ws_url(&relay_url, &channel_id) {
                            Ok(u) => u,
                            Err(e) => {
                                emit_error(&app, &e);
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
                        let join_msg = serde_json::to_string(&ClientMsg::Join { fingerprint: fingerprint.clone() }).unwrap();
                        if let Err(e) = sink.send(Message::Text(join_msg.into())).await {
                            emit_error(&app, &format!("ws send: {e}"));
                            continue;
                        }
                        ws = Some(sink);
                        ws_read = Some(read);
                        state = VoiceStateEvent {
                            connected: true,
                            group_id: Some(group_id.clone()),
                            channel_id: Some(channel_id.clone()),
                            muted: state.muted,
                            deafened: state.deafened,
                            udp_port: None,
                        };
                        pending = Some(PendingAudioStart {
                            group_id,
                            channel_id,
                            relay_url,
                            fingerprint,
                            participant_fps: Vec::new(),
                            input_device,
                            output_device,
                            ns_mode,
                            agc_mode,
                        });
                        let _ = state_tx.send(state.clone());
                        let _ = app.emit("voice-state", &state);
                    }
                    VoiceCommand::Leave => {
                        disconnect(&app, &mut ws, &mut ws_read, &mut state, &state_tx, &mut participants, &mut audio).await;
                        pending = None;
                        assigned_port = None;
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
                        if let Some(ref mut sink) = ws {
                            let msg = serde_json::to_string(&ClientMsg::MuteState { muted: state.muted, deafened: state.deafened }).unwrap();
                            let _ = sink.send(Message::Text(msg.into())).await;
                        }
                    }
                    VoiceCommand::SetDeafened(deafened) => {
                        state.deafened = deafened;
                        // deafen controls both: on → mute+deafen, off → unmute+undeafen
                        state.muted = deafened;
                        if let Some(ref session) = audio {
                            session.pipeline.controls.muted.store(deafened, Ordering::Relaxed);
                            session.pipeline.controls.deafened.store(deafened, Ordering::Relaxed);
                        }
                        let _ = state_tx.send(state.clone());
                        let _ = app.emit("voice-state", &state);
                        if let Some(ref mut sink) = ws {
                            let msg = serde_json::to_string(&ClientMsg::MuteState { muted: state.muted, deafened: state.deafened }).unwrap();
                            let _ = sink.send(Message::Text(msg.into())).await;
                        }
                    }
                    VoiceCommand::SetNoiseSuppression(mode) => {
                        if let Some(ref session) = audio {
                            session.pipeline.controls.noise_suppression.store(mode, Ordering::Relaxed);
                        }
                    }
                    VoiceCommand::SetAgc(mode) => {
                        if let Some(ref session) = audio {
                            session.pipeline.controls.agc.store(mode, Ordering::Relaxed);
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
                    reset(&app, &mut ws, &mut ws_read, &mut state, &state_tx, &mut participants, &mut audio);
                    pending = None;
                    assigned_port = None;
                    continue;
                };
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => {
                        emit_error(&app, &format!("ws read: {e}"));
                        reset(&app, &mut ws, &mut ws_read, &mut state, &state_tx, &mut participants, &mut audio);
                        pending = None;
                        assigned_port = None;
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
                            ServerMsg::Participants { list } => {
                                participants = list;
                                let _ = app.emit("voice-participants", &VoiceParticipantsEvent { participants: participants.clone() });

                                if let Some(ref mut p) = pending {
                                    p.participant_fps = participants.clone();
                                }
                                if let Some(port) = assigned_port {
                                    if let Some(p) = pending.take() {
                                        match start_audio(&client, &p.group_id, &p.channel_id, &p.fingerprint, &p.relay_url, port, &p.participant_fps, &state, p.input_device, p.output_device).await {
                                            Ok(session) => {
                                                session.pipeline.controls.noise_suppression.store(p.ns_mode, Ordering::Relaxed);
                                                session.pipeline.controls.agc.store(p.agc_mode, Ordering::Relaxed);
                                                audio = Some(session);
                                            }
                                            Err(e) => emit_error(&app, &format!("audio start: {e}")),
                                        }
                                    }
                                }
                            }
                            ServerMsg::Assigned { port } => {
                                state.udp_port = Some(port);
                                assigned_port = Some(port);
                                let _ = state_tx.send(state.clone());
                                let _ = app.emit("voice-state", &state);

                                if let Some(p) = pending.take() {
                                    if !p.participant_fps.is_empty() {
                                        match start_audio(&client, &p.group_id, &p.channel_id, &p.fingerprint, &p.relay_url, port, &p.participant_fps, &state, p.input_device, p.output_device).await {
                                            Ok(session) => {
                                                session.pipeline.controls.noise_suppression.store(p.ns_mode, Ordering::Relaxed);
                                                session.pipeline.controls.agc.store(p.agc_mode, Ordering::Relaxed);
                                                audio = Some(session);
                                            }
                                            Err(e) => emit_error(&app, &format!("audio start: {e}")),
                                        }
                                    } else {
                                        pending = Some(p);
                                    }
                                }
                            }
                            ServerMsg::Joined { fingerprint } => {
                                participants.push(fingerprint.clone());
                                let _ = app.emit("voice-participants", &VoiceParticipantsEvent { participants: participants.clone() });

                                // Derive key for new peer and add to audio pipeline
                                if let Some(ref session) = audio {
                                    if let (Some(gid_hex), Some(cid_hex)) = (&state.group_id, &state.channel_id) {
                                        let parsed = hex::decode(gid_hex)
                                            .ok()
                                            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                                            .zip(hex::decode(cid_hex).ok().and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()));
                                        if let Some((gid, cid)) = parsed {
                                            if let Ok(keys) = derive_peer_keys(&client, &gid, &cid, &[fingerprint]).await {
                                                if let Ok(mut pk) = session.pipeline.peer_keys.lock() {
                                                    pk.extend(keys);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            ServerMsg::Left { fingerprint } => {
                                participants.retain(|fp| fp != &fingerprint);
                                let _ = app.emit("voice-participants", &VoiceParticipantsEvent { participants: participants.clone() });

                                // Remove peer's key from audio pipeline
                                if let Some(ref session) = audio {
                                    if let Ok(fp_bytes) = hex::decode(&fingerprint) {
                                        if let Ok(fp_arr) = <[u8; 32]>::try_from(fp_bytes.as_slice()) {
                                            if let Ok(mut pk) = session.pipeline.peer_keys.lock() {
                                                pk.remove(&fp_arr);
                                            }
                                        }
                                    }
                                }
                            }
                            ServerMsg::Speaking { fingerprint, speaking } => {
                                let _ = app.emit("voice-speaking", &VoiceSpeakingEvent { fingerprint, speaking });
                            }
                            ServerMsg::MuteState { fingerprint, muted, deafened } => {
                                let _ = app.emit("voice-mute-state", &VoiceMuteStateEvent { fingerprint, muted, deafened });
                            }
                            ServerMsg::Error { message } => {
                                emit_error(&app, &format!("server: {message}"));
                            }
                        },
                        Err(e) => emit_error(&app, &format!("ws parse: {e}")),
                    }
                }
            }
            // Poll local speaking state and send Speaking messages to relay
            _ = speaking_timer.tick() => {
                if let Some(ref session) = audio {
                    let speaking = session.pipeline.controls.speaking.load(Ordering::Relaxed);
                    if speaking != last_speaking {
                        last_speaking = speaking;
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
                    // Send WS ping for next RTT measurement
                    if let Some(ref mut sink) = ws {
                        ping_sent_at = Some(Instant::now());
                        let _ = sink.send(Message::Ping(vec![].into())).await;
                    }
                }
            }
        }
    }
}
