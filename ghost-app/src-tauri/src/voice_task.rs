use std::time::Duration;

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::Message;

const WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const WS_SEND_TIMEOUT: Duration = Duration::from_secs(5);

type WsStream = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;
type WsSink = futures_util::stream::SplitSink<WsStream, Message>;
type WsReader = futures_util::stream::SplitStream<WsStream>;

pub enum VoiceCommand {
    Join {
        group_id: String,
        channel_id: String,
        relay_url: String,
        fingerprint: String,
    },
    Leave,
    SetMuted(bool),
    SetDeafened(bool),
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

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMsg {
    Join { fingerprint: String },
    Leave,
    Speaking { speaking: bool },
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMsg {
    Participants { list: Vec<String> },
    Assigned { port: u16 },
    Joined { fingerprint: String },
    Left { fingerprint: String },
    Speaking { fingerprint: String, speaking: bool },
    Error { message: String },
}

pub struct VoiceHandle {
    pub cmd_tx: mpsc::Sender<VoiceCommand>,
    pub state_rx: watch::Receiver<VoiceStateEvent>,
}

fn ws_url(relay_url: &str, channel_id: &str) -> Result<String, String> {
    let channel_bytes = hex::decode(channel_id).map_err(|e| format!("bad channel_id: {e}"))?;
    let channel_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&channel_bytes);
    let base = relay_url
        .replacen("http://", "ws://", 1)
        .replacen("https://", "wss://", 1);
    Ok(format!("{}/voice/{}", base, channel_b64))
}

/// Sends a leave message over WebSocket, closes it, and resets local state.
async fn disconnect(
    app: &AppHandle,
    ws: &mut Option<WsSink>,
    ws_read: &mut Option<WsReader>,
    state: &mut VoiceStateEvent,
    state_tx: &watch::Sender<VoiceStateEvent>,
    participants: &mut Vec<String>,
) {
    if let Some(ref mut sink) = ws {
        let msg = serde_json::to_string(&ClientMsg::Leave).unwrap();
        let _ = tokio::time::timeout(WS_SEND_TIMEOUT, async {
            let _ = sink.send(Message::Text(msg.into())).await;
            let _ = sink.close().await;
        })
        .await;
    }
    *ws = None;
    *ws_read = None;
    *state = VoiceStateEvent::default();
    participants.clear();
    let _ = state_tx.send(state.clone());
    let _ = app.emit("voice-state", &state);
}

/// Resets local state without notifying the relay (connection already gone).
fn reset(
    app: &AppHandle,
    ws: &mut Option<WsSink>,
    ws_read: &mut Option<WsReader>,
    state: &mut VoiceStateEvent,
    state_tx: &watch::Sender<VoiceStateEvent>,
    participants: &mut Vec<String>,
) {
    *ws = None;
    *ws_read = None;
    *state = VoiceStateEvent::default();
    participants.clear();
    let _ = state_tx.send(state.clone());
    let _ = app.emit("voice-state", &state);
}

fn emit_error(app: &AppHandle, msg: &str) {
    eprintln!("voice: {msg}");
    let _ = app.emit("voice-error", msg);
}

pub async fn run(
    app: AppHandle,
    mut cmd_rx: mpsc::Receiver<VoiceCommand>,
    state_tx: watch::Sender<VoiceStateEvent>,
) {
    let mut state = VoiceStateEvent::default();
    let mut ws: Option<WsSink> = None;
    let mut ws_read: Option<WsReader> = None;
    let mut participants: Vec<String> = Vec::new();

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break };
                match cmd {
                    VoiceCommand::Join { group_id, channel_id, relay_url, fingerprint } => {
                        disconnect(&app, &mut ws, &mut ws_read, &mut state, &state_tx, &mut participants).await;

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
                        let join_msg = serde_json::to_string(&ClientMsg::Join { fingerprint }).unwrap();
                        if let Err(e) = sink.send(Message::Text(join_msg.into())).await {
                            emit_error(&app, &format!("ws send: {e}"));
                            continue;
                        }
                        ws = Some(sink);
                        ws_read = Some(read);
                        state = VoiceStateEvent {
                            connected: true,
                            group_id: Some(group_id),
                            channel_id: Some(channel_id),
                            muted: false,
                            deafened: false,
                            udp_port: None,
                        };
                        let _ = state_tx.send(state.clone());
                        let _ = app.emit("voice-state", &state);
                    }
                    VoiceCommand::Leave => {
                        disconnect(&app, &mut ws, &mut ws_read, &mut state, &state_tx, &mut participants).await;
                    }
                    VoiceCommand::SetMuted(muted) => {
                        state.muted = muted;
                        let _ = state_tx.send(state.clone());
                        let _ = app.emit("voice-state", &state);
                    }
                    VoiceCommand::SetDeafened(deafened) => {
                        state.deafened = deafened;
                        let _ = state_tx.send(state.clone());
                        let _ = app.emit("voice-state", &state);
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
                    reset(&app, &mut ws, &mut ws_read, &mut state, &state_tx, &mut participants);
                    continue;
                };
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => {
                        emit_error(&app, &format!("ws read: {e}"));
                        reset(&app, &mut ws, &mut ws_read, &mut state, &state_tx, &mut participants);
                        continue;
                    }
                };
                if let Message::Text(text) = msg {
                    match serde_json::from_str::<ServerMsg>(text.as_str()) {
                        Ok(server_msg) => match server_msg {
                            ServerMsg::Participants { list } => {
                                participants = list;
                                let _ = app.emit("voice-participants", &VoiceParticipantsEvent { participants: participants.clone() });
                            }
                            ServerMsg::Assigned { port } => {
                                state.udp_port = Some(port);
                                let _ = state_tx.send(state.clone());
                                let _ = app.emit("voice-state", &state);
                            }
                            ServerMsg::Joined { fingerprint } => {
                                participants.push(fingerprint);
                                let _ = app.emit("voice-participants", &VoiceParticipantsEvent { participants: participants.clone() });
                            }
                            ServerMsg::Left { fingerprint } => {
                                participants.retain(|fp| fp != &fingerprint);
                                let _ = app.emit("voice-participants", &VoiceParticipantsEvent { participants: participants.clone() });
                            }
                            ServerMsg::Speaking { fingerprint, speaking } => {
                                let _ = app.emit("voice-speaking", &VoiceSpeakingEvent { fingerprint, speaking });
                            }
                            ServerMsg::Error { message } => {
                                emit_error(&app, &format!("server: {message}"));
                            }
                        },
                        Err(e) => emit_error(&app, &format!("ws parse: {e}")),
                    }
                }
            }
        }
    }
}
