use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::state::AppState;
use crate::util::decode_mailbox_id;
use crate::voice::{Participant, VoiceChannel, VoiceEvent};

const PING_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMsg {
    Join { fingerprint: String },
    Leave,
    Speaking { speaking: bool },
    MuteState { muted: bool, deafened: bool },
}

#[derive(Serialize)]
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

pub async fn ws_upgrade(
    State(state): State<AppState>,
    Path(channel_id): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    let id = match decode_mailbox_id(&channel_id) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    ws.on_upgrade(move |socket| voice_connection(socket, id, state))
}

async fn voice_connection(socket: WebSocket, channel_id: [u8; 32], state: AppState) {
    let (mut sink, mut stream) = socket.split();
    let mut ping_interval = tokio::time::interval(PING_INTERVAL);
    let mut fingerprint: Option<[u8; 32]> = None;
    let mut event_rx: Option<tokio::sync::broadcast::Receiver<VoiceEvent>> = None;

    loop {
        tokio::select! {
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<ClientMsg>(&text) {
                            Ok(ClientMsg::Join { fingerprint: fp_hex }) => {
                                let fp = match parse_fingerprint(&fp_hex) {
                                    Some(fp) => fp,
                                    None => {
                                        let _ = send_json(&mut sink, &ServerMsg::Error {
                                            message: "invalid fingerprint".into(),
                                        }).await;
                                        continue;
                                    }
                                };

                                let (participants_list, initial_mute, rx) = {
                                    let mut channels = state.voice_channels.write().await;
                                    let channel = channels
                                        .entry(channel_id)
                                        .or_insert_with(VoiceChannel::new);

                                    if channel.participants.len()
                                        >= state.config.max_voice_participants
                                    {
                                        let _ = send_json(&mut sink, &ServerMsg::Error {
                                            message: "channel full".into(),
                                        }).await;
                                        continue;
                                    }

                                    // Collect mute states before adding self
                                    let mute_states: Vec<_> = channel.participants.iter()
                                        .filter(|p| p.muted || p.deafened)
                                        .map(|p| (hex::encode(p.fingerprint), p.muted, p.deafened))
                                        .collect();

                                    // Remove stale entry if re-joining
                                    channel.participants.retain(|p| p.fingerprint != fp);
                                    channel.participants.push(Participant {
                                        fingerprint: fp,
                                        udp_addr: None,
                                        last_udp: std::time::Instant::now(),
                                        speaking: false,
                                        muted: false,
                                        deafened: false,
                                    });

                                    let list: Vec<String> = channel
                                        .participants
                                        .iter()
                                        .map(|p| hex::encode(p.fingerprint))
                                        .collect();

                                    let _ = channel.notify.send(VoiceEvent::Joined {
                                        fingerprint: fp,
                                    });

                                    let rx = channel.notify.subscribe();
                                    (list, mute_states, rx)
                                };

                                fingerprint = Some(fp);
                                event_rx = Some(rx);

                                let _ = send_json(&mut sink, &ServerMsg::Participants {
                                    list: participants_list,
                                }).await;
                                let udp_port = *state.voice_udp_port_rx.borrow();
                                let _ = send_json(&mut sink, &ServerMsg::Assigned {
                                    port: udp_port,
                                }).await;
                                // Send current mute states of existing participants
                                for (fp_hex, muted, deafened) in &initial_mute {
                                    let _ = send_json(&mut sink, &ServerMsg::MuteState {
                                        fingerprint: fp_hex.clone(),
                                        muted: *muted,
                                        deafened: *deafened,
                                    }).await;
                                }
                            }
                            Ok(ClientMsg::Leave) => {
                                break;
                            }
                            Ok(ClientMsg::Speaking { speaking }) => {
                                if let Some(fp) = fingerprint {
                                    let mut channels = state.voice_channels.write().await;
                                    if let Some(channel) = channels.get_mut(&channel_id) {
                                        if let Some(p) = channel.participants.iter_mut().find(|p| p.fingerprint == fp) {
                                            p.speaking = speaking;
                                        }
                                        let _ = channel.notify.send(VoiceEvent::Speaking {
                                            fingerprint: fp,
                                            speaking,
                                        });
                                    }
                                }
                            }
                            Ok(ClientMsg::MuteState { muted, deafened }) => {
                                if let Some(fp) = fingerprint {
                                    let mut channels = state.voice_channels.write().await;
                                    if let Some(channel) = channels.get_mut(&channel_id) {
                                        if let Some(p) = channel.participants.iter_mut().find(|p| p.fingerprint == fp) {
                                            p.muted = muted;
                                            p.deafened = deafened;
                                        }
                                        let _ = channel.notify.send(VoiceEvent::MuteState {
                                            fingerprint: fp,
                                            muted,
                                            deafened,
                                        });
                                    }
                                }
                            }
                            Err(_) => {
                                let _ = send_json(&mut sink, &ServerMsg::Error {
                                    message: "invalid message".into(),
                                }).await;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
            event = async {
                match &mut event_rx {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match event {
                    Ok(VoiceEvent::Joined { fingerprint: fp }) => {
                        if fingerprint.map_or(true, |own| own != fp) {
                            let _ = send_json(&mut sink, &ServerMsg::Joined {
                                fingerprint: hex::encode(fp),
                            }).await;
                        }
                    }
                    Ok(VoiceEvent::Left { fingerprint: fp }) => {
                        if fingerprint.map_or(true, |own| own != fp) {
                            let _ = send_json(&mut sink, &ServerMsg::Left {
                                fingerprint: hex::encode(fp),
                            }).await;
                        }
                    }
                    Ok(VoiceEvent::Speaking { fingerprint: fp, speaking }) => {
                        if fingerprint.map_or(true, |own| own != fp) {
                            let _ = send_json(&mut sink, &ServerMsg::Speaking {
                                fingerprint: hex::encode(fp),
                                speaking,
                            }).await;
                        }
                    }
                    Ok(VoiceEvent::MuteState { fingerprint: fp, muted, deafened }) => {
                        if fingerprint.map_or(true, |own| own != fp) {
                            let _ = send_json(&mut sink, &ServerMsg::MuteState {
                                fingerprint: hex::encode(fp),
                                muted,
                                deafened,
                            }).await;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = ping_interval.tick() => {
                if sink.send(Message::Ping(bytes::Bytes::new())).await.is_err() {
                    break;
                }
            }
        }
    }

    // Cleanup on disconnect
    if let Some(fp) = fingerprint {
        {
            let mut channels = state.voice_channels.write().await;
            if let Some(channel) = channels.get_mut(&channel_id) {
                channel.participants.retain(|p| p.fingerprint != fp);
                let _ = channel.notify.send(VoiceEvent::Left { fingerprint: fp });
                if channel.participants.is_empty() {
                    channels.remove(&channel_id);
                }
            }
        }
        state.routing.remove(&channel_id, &fp);
    }
}

fn parse_fingerprint(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    bytes.try_into().ok()
}

async fn send_json(
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    msg: &ServerMsg,
) -> Result<(), axum::Error> {
    let text = serde_json::to_string(msg).unwrap();
    sink.send(Message::text(text)).await
}
