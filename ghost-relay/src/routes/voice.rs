use std::collections::HashSet;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use ghost_wire::voice::{ClientMsg, PeerEntry, ServerMsg};
use std::time::{Duration, Instant};

use crate::auth::DeviceAuth;
use crate::constants::{MAX_PRESENCE_BLOB_SIZE, PRESENCE_RATE_LIMIT, SPEAKING_RATE_LIMIT};
use crate::error::RelayError;
use crate::state::AppState;
use crate::util::decode_mailbox_id;
use crate::voice::{Participant, VoiceChannel, VoiceEvent};

const PING_INTERVAL: Duration = Duration::from_secs(30);
const PONG_TIMEOUT: Duration = Duration::from_secs(60);

/// The welcome for an admitted slot: the room's current peers, and what the participant
/// needs to bind its UDP address.
fn welcome(state: &AppState, slot_id: u32, room_id: &[u8; 32], token: &[u8; 32], peers: Vec<PeerEntry>) -> ServerMsg {
    ServerMsg::Welcome {
        slot_id,
        port: state.config.voice_public_port.unwrap_or(*state.voice_udp_port_rx.borrow()),
        room: B64.encode(room_id),
        token: B64.encode(token),
        peers,
    }
}

/// GET /voice/{mailbox_id}/{channel_id} — join the voice room of a channel within the
/// group whose mailbox is named: the server's for a public channel, the channel's own
/// for a private one. Only members of that group may join.
pub async fn ws_upgrade(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path((mailbox_id, channel_id)): Path<(String, String)>,
    ws: WebSocketUpgrade,
) -> Response {
    let (mailbox_id, channel_id) = match (decode_mailbox_id(&mailbox_id), decode_mailbox_id(&channel_id)) {
        (Ok(m), Ok(c)) => (m, c),
        (Err(e), _) | (_, Err(e)) => return e.into_response(),
    };
    match state.is_group_member(&mailbox_id, &auth.account_fp) {
        Ok(true) => {}
        Ok(false) => return RelayError::Forbidden("not a member of this channel's group".into()).into_response(),
        Err(e) => return e.into_response(),
    }
    let room_id = ghost_wire::voice::voice_room_id(&mailbox_id, &channel_id);
    ws.on_upgrade(move |socket| voice_connection(socket, mailbox_id, room_id, state, auth))
}

async fn voice_connection(socket: WebSocket, mailbox_id: [u8; 32], room_id: [u8; 32], state: AppState, auth: DeviceAuth) {
    let (mut sink, mut stream) = socket.split();
    let mut ping_interval = tokio::time::interval(PING_INTERVAL);
    let mut last_pong = Instant::now();
    let mut slot_id: Option<u32> = None;
    let mut token = [0u8; 32];
    let mut event_rx: Option<tokio::sync::broadcast::Receiver<VoiceEvent>> = None;

    // Track which peer slots this connection knows about
    let mut known_slots: HashSet<u32> = HashSet::new();

    let mut revoke_rx = state.revocation_tx.subscribe();
    let mut departure_rx = state.departure_tx.subscribe();

    // Rate limiting state
    let mut last_presence_time = Instant::now();
    let mut presence_count: u32 = 0;
    let mut last_speaking_time = Instant::now();
    let mut speaking_count: u32 = 0;

    loop {
        tokio::select! {
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<ClientMsg>(&text) {
                            Ok(ClientMsg::Join { presence }) => {
                                if slot_id.is_some() {
                                    let _ = send_json(&mut sink, &ServerMsg::Error {
                                        message: "already joined".into(),
                                    }).await;
                                    continue;
                                }
                                let blob = match B64.decode(&presence) {
                                    Ok(b) if !b.is_empty() && b.len() <= MAX_PRESENCE_BLOB_SIZE => b,
                                    _ => {
                                        let _ = send_json(&mut sink, &ServerMsg::Error {
                                            message: "invalid presence blob".into(),
                                        }).await;
                                        continue;
                                    }
                                };

                                let (welcome, rx) = {
                                    let mut channels = state.voice_channels.write().await;
                                    let channel = channels
                                        .entry(room_id)
                                        .or_insert_with(VoiceChannel::new);

                                    if channel.participants.len()
                                        >= state.config.max_voice_participants
                                    {
                                        let _ = send_json(&mut sink, &ServerMsg::Error {
                                            message: "channel full".into(),
                                        }).await;
                                        continue;
                                    }

                                    let new_slot = channel.alloc_slot();

                                    // Collect existing peers before adding self
                                    let peers: Vec<PeerEntry> = channel
                                        .participants
                                        .iter()
                                        .filter_map(|p| {
                                            p.latest_presence.as_ref().map(|blob| PeerEntry {
                                                slot_id: p.slot_id,
                                                presence: B64.encode(blob),
                                            })
                                        })
                                        .collect();

                                    channel.participants.push(Participant {
                                        slot_id: new_slot,
                                        latest_presence: Some(blob.clone()),
                                    });
                                    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token);
                                    state.routing.admit(room_id, new_slot, token);

                                    let _ = channel.notify.send(VoiceEvent::Joined {
                                        slot_id: new_slot,
                                    });
                                    let _ = channel.notify.send(VoiceEvent::Presence {
                                        slot_id: new_slot,
                                        blob,
                                    });

                                    let rx = channel.notify.subscribe();
                                    (welcome(&state, new_slot, &room_id, &token, peers), rx)
                                };

                                // Set connection state after releasing the lock
                                let (own_sid, peer_sids) = match &welcome {
                                    ServerMsg::Welcome { slot_id, peers, .. } => {
                                        (*slot_id, peers.iter().map(|p| p.slot_id).collect::<Vec<_>>())
                                    }
                                    _ => unreachable!(),
                                };
                                slot_id = Some(own_sid);
                                event_rx = Some(rx);
                                for sid in peer_sids {
                                    known_slots.insert(sid);
                                }

                                let _ = send_json(&mut sink, &welcome).await;
                            }
                            Ok(ClientMsg::Leave) => {
                                break;
                            }
                            Ok(ClientMsg::Presence { blob: blob_b64 }) => {
                                let sid = match slot_id {
                                    Some(s) => s,
                                    None => continue,
                                };

                                // Rate limit
                                let now = Instant::now();
                                if now.duration_since(last_presence_time) >= Duration::from_secs(1) {
                                    last_presence_time = now;
                                    presence_count = 0;
                                }
                                presence_count += 1;
                                if presence_count > PRESENCE_RATE_LIMIT {
                                    continue;
                                }

                                let blob = match B64.decode(&blob_b64) {
                                    Ok(b) if !b.is_empty() && b.len() <= MAX_PRESENCE_BLOB_SIZE => b,
                                    _ => continue,
                                };

                                {
                                    let mut channels = state.voice_channels.write().await;
                                    if let Some(channel) = channels.get_mut(&room_id) {
                                        if let Some(p) = channel.participants.iter_mut().find(|p| p.slot_id == sid) {
                                            p.latest_presence = Some(blob.clone());
                                        }
                                        let _ = channel.notify.send(VoiceEvent::Presence {
                                            slot_id: sid,
                                            blob,
                                        });
                                    }
                                }
                            }
                            Ok(ClientMsg::Speaking { speaking }) => {
                                let sid = match slot_id {
                                    Some(s) => s,
                                    None => continue,
                                };

                                // Rate limit
                                let now = Instant::now();
                                if now.duration_since(last_speaking_time) >= Duration::from_secs(1) {
                                    last_speaking_time = now;
                                    speaking_count = 0;
                                }
                                speaking_count += 1;
                                if speaking_count > SPEAKING_RATE_LIMIT {
                                    continue;
                                }

                                {
                                    let channels = state.voice_channels.read().await;
                                    if let Some(channel) = channels.get(&room_id) {
                                        let _ = channel.notify.send(VoiceEvent::Speaking {
                                            slot_id: sid,
                                            speaking,
                                        });
                                    }
                                }
                            }
                            Ok(ClientMsg::Resync) => {
                                let sid = match slot_id {
                                    Some(s) => s,
                                    None => continue,
                                };

                                let channels = state.voice_channels.read().await;
                                if let Some(channel) = channels.get(&room_id) {
                                    let peers: Vec<PeerEntry> = channel
                                        .participants
                                        .iter()
                                        .filter(|p| p.slot_id != sid)
                                        .filter_map(|p| {
                                            p.latest_presence.as_ref().map(|blob| PeerEntry {
                                                slot_id: p.slot_id,
                                                presence: B64.encode(blob),
                                            })
                                        })
                                        .collect();

                                    let _ = send_json(&mut sink, &welcome(&state, sid, &room_id, &token, peers)).await;
                                }
                            }
                            Err(_) => {
                                let _ = send_json(&mut sink, &ServerMsg::Error {
                                    message: "invalid message".into(),
                                }).await;
                            }
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {
                        last_pong = Instant::now();
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
                    Ok(VoiceEvent::Joined { slot_id: sid }) => {
                        // No-op: the Presence event that follows carries the blob.
                        let _ = sid;
                    }
                    Ok(VoiceEvent::Left { slot_id: sid }) => {
                        if slot_id.map_or(true, |own| own != sid) {
                            known_slots.remove(&sid);
                            let _ = send_json(&mut sink, &ServerMsg::Left {
                                slot_id: sid,
                            }).await;
                        }
                    }
                    Ok(VoiceEvent::Presence { slot_id: sid, blob }) => {
                        if slot_id.map_or(true, |own| own != sid) {
                            if known_slots.insert(sid) {
                                // First time seeing this slot — it's a join
                                let _ = send_json(&mut sink, &ServerMsg::Joined {
                                    slot_id: sid,
                                    presence: B64.encode(&blob),
                                }).await;
                            } else {
                                let _ = send_json(&mut sink, &ServerMsg::Presence {
                                    slot_id: sid,
                                    blob: B64.encode(&blob),
                                }).await;
                            }
                        }
                    }
                    Ok(VoiceEvent::Speaking { slot_id: sid, speaking }) => {
                        if slot_id.map_or(true, |own| own != sid) {
                            let _ = send_json(&mut sink, &ServerMsg::Speaking {
                                slot_id: sid,
                                speaking,
                            }).await;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        // Receiver fell behind — send full state snapshot to recover
                        if let Some(sid) = slot_id {
                            eprintln!("voice ws: slot {sid} lagged {n} events, sending resync");
                            let channels = state.voice_channels.read().await;
                            if let Some(channel) = channels.get(&room_id) {
                                let peers: Vec<PeerEntry> = channel
                                    .participants
                                    .iter()
                                    .filter(|p| p.slot_id != sid)
                                    .filter_map(|p| {
                                        p.latest_presence.as_ref().map(|blob| PeerEntry {
                                            slot_id: p.slot_id,
                                            presence: B64.encode(blob),
                                        })
                                    })
                                    .collect();
                                known_slots.clear();
                                for peer in &peers {
                                    known_slots.insert(peer.slot_id);
                                }
                                let _ = send_json(&mut sink, &welcome(&state, sid, &room_id, &token, peers)).await;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            revoke_event = revoke_rx.recv() => {
                let revoked = match revoke_event {
                    Ok((afp, dvk)) => afp == auth.account_fp && dvk == auth.device_vk,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        !state.storage.is_active_device(&auth.account_fp, &auth.device_vk)
                            .unwrap_or(false)
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };
                if revoked {
                    let _ = sink.send(Message::Close(Some(
                        axum::extract::ws::CloseFrame {
                            code: ghost_wire::WS_CLOSE_DEVICE_REVOKED,
                            reason: "device revoked".into(),
                        },
                    ))).await;
                    break;
                }
            }
            departure = departure_rx.recv() => {
                let removed = match departure {
                    Ok(d) => d.mailbox_id == mailbox_id && d.account_fp == auth.account_fp,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        !state.is_group_member(&mailbox_id, &auth.account_fp).unwrap_or(false)
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };
                if removed {
                    let _ = sink.send(Message::Close(Some(axum::extract::ws::CloseFrame {
                        code: ghost_wire::WS_CLOSE_REMOVED,
                        reason: "removed from the group".into(),
                    }))).await;
                    break;
                }
            }
            _ = ping_interval.tick() => {
                if last_pong.elapsed() > PONG_TIMEOUT {
                    break;
                }
                if sink.send(Message::Ping(bytes::Bytes::new())).await.is_err() {
                    break;
                }
            }
        }
    }

    // Cleanup on disconnect
    if let Some(sid) = slot_id {
        {
            let mut channels = state.voice_channels.write().await;
            if let Some(channel) = channels.get_mut(&room_id) {
                channel.participants.retain(|p| p.slot_id != sid);
                let _ = channel.notify.send(VoiceEvent::Left { slot_id: sid });
                if channel.participants.is_empty() {
                    channels.remove(&room_id);
                }
            }
        }
        state.routing.remove(&room_id, &sid);
    }
}

async fn send_json(
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    msg: &ServerMsg,
) -> Result<(), axum::Error> {
    let text = serde_json::to_string(msg).unwrap();
    sink.send(Message::text(text)).await
}
