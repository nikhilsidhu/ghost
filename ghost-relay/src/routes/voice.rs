use std::collections::HashSet;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use ghost_wire::presence::PresenceSender;
use ghost_wire::voice::{ClientMsg, PeerEntry, Reception, ServerMsg};
use std::time::{Duration, Instant};

use crate::auth::DeviceAuth;
use crate::constants::{MAX_PRESENCE_BLOB_SIZE, PRESENCE_RATE_LIMIT, RECEPTION_RATE_LIMIT, SPEAKING_RATE_LIMIT};
use crate::error::RelayError;
use crate::state::AppState;
use crate::util::decode_mailbox_id;
use crate::voice::{Participant, VoiceChannel, VoiceEvent};

type Events = tokio::sync::broadcast::Receiver<VoiceEvent>;

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

/// The room's peers other than `except`, each with its latest presence and the device
/// that announced it.
fn peers_except(channel: &VoiceChannel, except: Option<u32>) -> Vec<PeerEntry> {
    channel
        .participants
        .iter()
        .filter(|p| Some(p.slot_id) != except)
        .filter_map(|p| {
            p.latest_presence.as_ref().map(|blob| PeerEntry { slot_id: p.slot_id, presence: B64.encode(blob), from: p.from })
        })
        .collect()
}

/// A presence blob as a client sent it: base64, non-empty, within the size cap.
fn decode_presence(encoded: &str) -> Option<Vec<u8>> {
    match B64.decode(encoded) {
        Ok(blob) if !blob.is_empty() && blob.len() <= MAX_PRESENCE_BLOB_SIZE => Some(blob),
        _ => None,
    }
}

/// A slot handed to a connection: the slot, its token, the room's other participants and
/// the room's events from then on.
struct Admitted {
    slot_id: u32,
    token: [u8; 32],
    peers: Vec<PeerEntry>,
    events: Events,
}

/// Admit a device to the room. The room holds one device per account, so another of the
/// account's devices gives up its slot first (and a stale one of this device, on a
/// connection it lost): the room hears it left, and its connection is told why.
async fn admit(state: &AppState, room_id: [u8; 32], conn_id: u64, from: PresenceSender, blob: Vec<u8>) -> Result<Admitted, &'static str> {
    let mut channels = state.voice_channels.write().await;
    let channel = channels.entry(room_id).or_insert_with(VoiceChannel::new);
    let (replaced, kept): (Vec<_>, Vec<_>) = channel.participants.drain(..).partition(|p| p.from.account_fp == from.account_fp);
    channel.participants = kept;
    for participant in &replaced {
        state.routing.remove(&room_id, &participant.slot_id);
        let _ = channel.notify.send(VoiceEvent::Left { slot_id: participant.slot_id });
        let _ = channel.notify.send(VoiceEvent::Replaced { slot_id: participant.slot_id });
    }
    if channel.participants.len() >= state.config.max_voice_participants {
        return Err("channel full");
    }
    let slot_id = channel.alloc_slot();
    let mut token = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token);
    let peers = peers_except(channel, None);
    channel.participants.push(Participant { slot_id, from, conn_id, token, latest_presence: Some(blob.clone()) });
    state.routing.admit(room_id, slot_id, token);
    let _ = channel.notify.send(VoiceEvent::Joined { slot_id });
    let _ = channel.notify.send(VoiceEvent::Presence { slot_id, from, blob });
    Ok(Admitted { slot_id, token, peers, events: channel.notify.subscribe() })
}

/// Hand a slot to the connection its device claimed it back on: the same device, with
/// the slot's token. The connection that held it learns it is superseded; the room hears
/// the presence as it is now and nothing else, and the slot's media never stopped.
async fn resume(state: &AppState, room_id: [u8; 32], conn_id: u64, from: PresenceSender, slot_id: u32, token: [u8; 32], blob: Vec<u8>) -> Option<Admitted> {
    let mut channels = state.voice_channels.write().await;
    let channel = channels.get_mut(&room_id)?;
    // Compared as hashes, which compare in constant time.
    let proven = |p: &&mut Participant| p.slot_id == slot_id && p.from == from && blake3::Hash::from(p.token) == blake3::Hash::from(token);
    let participant = channel.participants.iter_mut().find(proven)?;
    participant.conn_id = conn_id;
    participant.latest_presence = Some(blob.clone());
    let _ = channel.notify.send(VoiceEvent::Resumed { slot_id, conn_id });
    let _ = channel.notify.send(VoiceEvent::Presence { slot_id, from, blob });
    let peers = peers_except(channel, Some(slot_id));
    Some(Admitted { slot_id, token, peers, events: channel.notify.subscribe() })
}

/// Give up a slot the connection still holds: the room hears it left. A slot taken over
/// or claimed back since is no longer this connection's to give up.
async fn release(state: &AppState, room_id: [u8; 32], slot_id: u32, conn_id: u64) {
    let mut channels = state.voice_channels.write().await;
    let Some(channel) = channels.get_mut(&room_id) else { return };
    if !channel.holds(slot_id, conn_id) {
        return;
    }
    channel.participants.retain(|p| p.slot_id != slot_id);
    let _ = channel.notify.send(VoiceEvent::Left { slot_id });
    state.routing.remove(&room_id, &slot_id);
    if channel.participants.is_empty() {
        channels.remove(&room_id);
    }
}

/// Counts one kind of message per second, to drop a flood.
struct RateWindow {
    started: Instant,
    count: u32,
    limit: u32,
}

impl RateWindow {
    fn new(limit: u32) -> Self {
        Self { started: Instant::now(), count: 0, limit }
    }

    /// Whether one more message fits in this second's allowance.
    fn allow(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.started) >= Duration::from_secs(1) {
            self.started = now;
            self.count = 0;
        }
        self.count += 1;
        self.count <= self.limit
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
    match state.is_group_member(mailbox_id, auth.account_fp).await {
        Ok(true) => {}
        Ok(false) => return RelayError::Forbidden("not a member of this channel's group".into()).into_response(),
        Err(e) => return e.into_response(),
    }
    let room_id = ghost_wire::voice::voice_room_id(&mailbox_id, &channel_id);
    ws.on_upgrade(move |socket| voice_connection(socket, mailbox_id, room_id, state, auth))
}

async fn voice_connection(socket: WebSocket, mailbox_id: [u8; 32], room_id: [u8; 32], state: AppState, auth: DeviceAuth) {
    let (mut sink, mut stream) = socket.split();
    let from = PresenceSender { account_fp: auth.account_fp, device_vk: auth.device_vk };
    let conn_id = state.next_conn_id.fetch_add(1, Relaxed);
    let mut ping_interval = tokio::time::interval(PING_INTERVAL);
    let mut last_pong = Instant::now();
    // The slot this connection holds and its token, once joined or resumed; cleared when
    // the slot was taken over or claimed back elsewhere.
    let mut held: Option<(u32, [u8; 32])> = None;
    let mut event_rx: Option<Events> = None;

    // Track which peer slots this connection knows about
    let mut known_slots: HashSet<u32> = HashSet::new();

    let mut revoke_rx = state.revocation_tx.subscribe();
    let mut departure_rx = state.departure_tx.subscribe();

    let mut presence_rate = RateWindow::new(PRESENCE_RATE_LIMIT);
    let mut speaking_rate = RateWindow::new(SPEAKING_RATE_LIMIT);
    let mut reception_rate = RateWindow::new(RECEPTION_RATE_LIMIT);

    loop {
        tokio::select! {
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<ClientMsg>(&text) {
                            Ok(ClientMsg::Join { presence }) => {
                                if held.is_some() {
                                    let _ = send_json(&mut sink, &ServerMsg::Error {
                                        message: "already joined".into(),
                                    }).await;
                                    continue;
                                }
                                let Some(blob) = decode_presence(&presence) else {
                                    let _ = send_json(&mut sink, &ServerMsg::Error {
                                        message: "invalid presence blob".into(),
                                    }).await;
                                    continue;
                                };
                                match admit(&state, room_id, conn_id, from, blob).await {
                                    Ok(admitted) => {
                                        let _ = send_json(&mut sink, &welcome(&state, admitted.slot_id, &room_id, &admitted.token, admitted.peers.clone())).await;
                                        known_slots = admitted.peers.iter().map(|p| p.slot_id).collect();
                                        held = Some((admitted.slot_id, admitted.token));
                                        event_rx = Some(admitted.events);
                                    }
                                    Err(message) => {
                                        let _ = send_json(&mut sink, &ServerMsg::Error { message: message.into() }).await;
                                    }
                                }
                            }
                            Ok(ClientMsg::Resume { slot_id: claimed, token: claimed_token, presence }) => {
                                if held.is_some() {
                                    let _ = send_json(&mut sink, &ServerMsg::Error {
                                        message: "already joined".into(),
                                    }).await;
                                    continue;
                                }
                                let decoded = B64.decode(&claimed_token).ok().and_then(|t| <[u8; 32]>::try_from(t).ok());
                                let (Some(claimed_token), Some(blob)) = (decoded, decode_presence(&presence)) else {
                                    let _ = send_json(&mut sink, &ServerMsg::Error {
                                        message: "invalid resume".into(),
                                    }).await;
                                    continue;
                                };
                                match resume(&state, room_id, conn_id, from, claimed, claimed_token, blob).await {
                                    Some(admitted) => {
                                        let _ = send_json(&mut sink, &welcome(&state, admitted.slot_id, &room_id, &admitted.token, admitted.peers.clone())).await;
                                        known_slots = admitted.peers.iter().map(|p| p.slot_id).collect();
                                        held = Some((admitted.slot_id, admitted.token));
                                        event_rx = Some(admitted.events);
                                    }
                                    None => {
                                        let _ = send_json(&mut sink, &ServerMsg::NotResumed).await;
                                    }
                                }
                            }
                            Ok(ClientMsg::Leave) => {
                                break;
                            }
                            Ok(ClientMsg::Presence { blob: blob_b64 }) => {
                                let Some((sid, _)) = held else { continue };
                                if !presence_rate.allow() {
                                    continue;
                                }
                                let Some(blob) = decode_presence(&blob_b64) else { continue };
                                let mut channels = state.voice_channels.write().await;
                                if let Some(channel) = channels.get_mut(&room_id) {
                                    if let Some(p) = channel.participants.iter_mut().find(|p| p.slot_id == sid) {
                                        p.latest_presence = Some(blob.clone());
                                    }
                                    let _ = channel.notify.send(VoiceEvent::Presence {
                                        slot_id: sid,
                                        from,
                                        blob,
                                    });
                                }
                            }
                            Ok(ClientMsg::Speaking { speaking }) => {
                                let Some((sid, _)) = held else { continue };
                                if !speaking_rate.allow() {
                                    continue;
                                }
                                let channels = state.voice_channels.read().await;
                                if let Some(channel) = channels.get(&room_id) {
                                    let _ = channel.notify.send(VoiceEvent::Speaking {
                                        slot_id: sid,
                                        speaking,
                                    });
                                }
                            }
                            Ok(ClientMsg::Reception { reports }) => {
                                let Some((sid, _)) = held else { continue };
                                if !reception_rate.allow() {
                                    continue;
                                }
                                let channels = state.voice_channels.read().await;
                                if let Some(channel) = channels.get(&room_id) {
                                    // Only about the room's other participants, one report each.
                                    let mut told = HashSet::new();
                                    let reports: Vec<Reception> = reports
                                        .into_iter()
                                        .filter(|r| r.slot_id != sid && channel.participants.iter().any(|p| p.slot_id == r.slot_id) && told.insert(r.slot_id))
                                        .map(|r| Reception { loss_pct: r.loss_pct.min(100), ..r })
                                        .collect();
                                    if !reports.is_empty() {
                                        let _ = channel.notify.send(VoiceEvent::Reception { from: sid, reports: Arc::new(reports) });
                                    }
                                }
                            }
                            Ok(ClientMsg::Resync) => {
                                let Some((sid, token)) = held else { continue };
                                let channels = state.voice_channels.read().await;
                                if let Some(channel) = channels.get(&room_id) {
                                    let peers = peers_except(channel, Some(sid));
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
                let slot_id = held.map(|(sid, _)| sid);
                match event {
                    Ok(VoiceEvent::Joined { slot_id: sid }) => {
                        // No-op: the Presence event that follows carries the blob.
                        let _ = sid;
                    }
                    Ok(VoiceEvent::Replaced { slot_id: sid }) if slot_id == Some(sid) => {
                        // The joining device's admission already gave the slot up.
                        held = None;
                        let _ = sink.send(Message::Close(Some(axum::extract::ws::CloseFrame {
                            code: ghost_wire::WS_CLOSE_VOICE_REPLACED,
                            reason: "joined from another device".into(),
                        }))).await;
                        break;
                    }
                    Ok(VoiceEvent::Resumed { slot_id: sid, conn_id: holder }) if slot_id == Some(sid) && holder != conn_id => {
                        // The slot carries on under the connection that claimed it.
                        held = None;
                        break;
                    }
                    Ok(VoiceEvent::Replaced { .. } | VoiceEvent::Resumed { .. }) => {}
                    Ok(VoiceEvent::Left { slot_id: sid }) => {
                        if slot_id != Some(sid) {
                            known_slots.remove(&sid);
                            let _ = send_json(&mut sink, &ServerMsg::Left {
                                slot_id: sid,
                            }).await;
                        }
                    }
                    Ok(VoiceEvent::Presence { slot_id: sid, from: peer, blob }) => {
                        if slot_id != Some(sid) {
                            if known_slots.insert(sid) {
                                // First time seeing this slot — it's a join
                                let _ = send_json(&mut sink, &ServerMsg::Joined {
                                    slot_id: sid,
                                    presence: B64.encode(&blob),
                                    from: peer,
                                }).await;
                            } else {
                                let _ = send_json(&mut sink, &ServerMsg::Presence {
                                    slot_id: sid,
                                    blob: B64.encode(&blob),
                                    from: peer,
                                }).await;
                            }
                        }
                    }
                    Ok(VoiceEvent::Speaking { slot_id: sid, speaking }) => {
                        if slot_id != Some(sid) {
                            let _ = send_json(&mut sink, &ServerMsg::Speaking {
                                slot_id: sid,
                                speaking,
                            }).await;
                        }
                    }
                    Ok(VoiceEvent::Reception { from: reporter, reports }) => {
                        if let Some(report) = reports.iter().find(|r| Some(r.slot_id) == slot_id) {
                            let _ = send_json(&mut sink, &ServerMsg::Reception {
                                slot_id: reporter,
                                loss_pct: report.loss_pct,
                            }).await;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        // Behind the room's events, which may have taken the slot away;
                        // otherwise the room as it is now catches the connection up.
                        if let Some((sid, token)) = held {
                            tracing::debug!("voice ws: slot {sid} lagged {n} events, sending resync");
                            let channels = state.voice_channels.read().await;
                            let Some(channel) = channels.get(&room_id).filter(|c| c.holds(sid, conn_id)) else {
                                held = None;
                                break;
                            };
                            let peers = peers_except(channel, Some(sid));
                            known_slots = peers.iter().map(|p| p.slot_id).collect();
                            let _ = send_json(&mut sink, &welcome(&state, sid, &room_id, &token, peers)).await;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            revoke_event = revoke_rx.recv() => {
                let revoked = match revoke_event {
                    Ok((afp, dvk)) => afp == auth.account_fp && dvk == auth.device_vk,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        !state.storage.is_active_device(auth.account_fp, auth.device_vk).await.unwrap_or(false)
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };
                if revoked {
                    let _ = sink.send(Message::Close(Some(super::ws::revoked_close(&state, &auth).await))).await;
                    break;
                }
            }
            departure = departure_rx.recv() => {
                let removed = match departure {
                    Ok(d) => d.mailbox_id == mailbox_id && d.account_fp == auth.account_fp,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        !state.is_group_member(mailbox_id, auth.account_fp).await.unwrap_or(false)
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

    if let Some((sid, _)) = held {
        release(&state, room_id, sid, conn_id).await;
    }
}

async fn send_json(
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    msg: &ServerMsg,
) -> Result<(), axum::Error> {
    let text = serde_json::to_string(msg).unwrap();
    sink.send(Message::text(text)).await
}
