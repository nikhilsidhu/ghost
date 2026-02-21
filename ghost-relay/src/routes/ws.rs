use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use ghost_wire::{WS_FRAME_HEADER_SIZE, WS_SIGNAL_EPOCH_MISMATCH, WS_SIGNAL_GAP};

use crate::constants::{MAX_PRESENCE_BLOB_SIZE, WS_MAX_FANOUT_BATCH, WS_PING_INTERVAL_SECS};
use crate::mailbox::Mailbox;
use crate::state::{AppState, VpEntry};
use crate::util::decode_mailbox_id;

const HANDSHAKE_TIMEOUT_SECS: u64 = 5;

#[derive(Deserialize)]
struct VsMsg {
    vs: VsInner,
}

#[derive(Deserialize)]
struct VsInner {
    ch: String,
    p: Option<String>,
    leave: Option<bool>,
}

pub async fn ws_upgrade(
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    let id = match decode_mailbox_id(&mailbox_id) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    ws.on_upgrade(move |socket| ws_connection(socket, id, state))
}

async fn ws_connection(socket: WebSocket, mailbox_id: [u8; 32], state: AppState) {
    let (mut sink, mut stream) = socket.split();
    let conn_id = state.next_conn_id.fetch_add(1, Relaxed);

    // Subscribe before handshake so we don't miss blobs during replay
    let (mut seq_rx, mut voice_rx) = {
        let mut map = state.mailboxes.write().await;
        let mailbox = map.entry(mailbox_id).or_insert_with(Mailbox::new);
        (mailbox.seq_tx.subscribe(), mailbox.voice_tx.subscribe())
    };

    // Handshake: first binary frame is 8-byte BE last_seen_seq
    let timeout = Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
    let mut last_seen: u64 = match tokio::time::timeout(timeout, stream.next()).await {
        Ok(Some(Ok(Message::Binary(data)))) if data.len() == 8 => {
            u64::from_be_bytes(data[..8].try_into().unwrap())
        }
        _ => return,
    };

    // Detect gap: client asked for entries that have already been swept
    if last_seen > 0 {
        let has_gap = match state.storage.min_seq(&mailbox_id) {
            Ok(Some(min)) => last_seen + 1 < min,
            Ok(None) => true,
            Err(_) => false,
        };
        if has_gap {
            if sink.send(Message::text(WS_SIGNAL_GAP)).await.is_err() {
                return;
            }
        }
    }

    // Replay missed entries
    loop {
        let entries = match state.storage.read_from(&mailbox_id, last_seen, WS_MAX_FANOUT_BATCH) {
            Ok(e) => e,
            Err(_) => break,
        };
        if entries.is_empty() {
            break;
        }
        for entry in &entries {
            last_seen = entry.seq;
            let frame = encode_frame(entry.seq, entry.received_at, &entry.payload);
            if sink.send(Message::binary(frame)).await.is_err() {
                return;
            }
        }
    }

    // Voice state snapshot: send current voice presence for this mailbox
    {
        let vp = state.voice_presence.read().await;
        let entries: Vec<serde_json::Value> = vp
            .iter()
            .filter(|e| e.mailbox_id == mailbox_id)
            .map(|e| {
                serde_json::json!({
                    "ch": B64.encode(e.channel_id),
                    "p": B64.encode(&e.blob),
                })
            })
            .collect();
        // Always send snapshot (even empty) so client clears stale voice state
        let snap = serde_json::json!({ "vs_snap": entries });
        if sink.send(Message::text(snap.to_string())).await.is_err() {
            return;
        }
    }

    let ping_interval_dur = Duration::from_secs(WS_PING_INTERVAL_SECS);
    let mut ping_interval = tokio::time::interval(ping_interval_dur);
    let mut own_seqs: Vec<u64> = Vec::new();

    loop {
        tokio::select! {
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        match state.store_blob(&mailbox_id, &data).await {
                            Ok((seq, epoch_mismatch)) => {
                                own_seqs.push(seq);
                                let ack = if epoch_mismatch {
                                    Message::text(format!("{seq} {WS_SIGNAL_EPOCH_MISMATCH}"))
                                } else {
                                    Message::text(seq.to_string())
                                };
                                if sink.send(ack).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                let _ = sink.send(Message::text(format!("error: {e}"))).await;
                            }
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(vs) = serde_json::from_str::<VsMsg>(&text) {
                            handle_voice_state(&state, &mailbox_id, conn_id, vs.vs).await;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
            _ = seq_rx.changed() => {
                let entries = match state.storage.read_from(&mailbox_id, last_seen, WS_MAX_FANOUT_BATCH) {
                    Ok(entries) => entries,
                    Err(_) => continue,
                };
                for entry in &entries {
                    last_seen = entry.seq;
                    if let Some(pos) = own_seqs.iter().position(|&s| s == entry.seq) {
                        own_seqs.swap_remove(pos);
                        continue;
                    }
                    let frame = encode_frame(entry.seq, entry.received_at, &entry.payload);
                    if sink.send(Message::binary(frame)).await.is_err() {
                        return;
                    }
                }
            }
            voice_event = voice_rx.recv() => {
                match voice_event {
                    Ok((sender_conn_id, json)) if sender_conn_id != conn_id => {
                        if sink.send(Message::text(json)).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    _ => {} // own message or lagged
                }
            }
            _ = ping_interval.tick() => {
                if sink.send(Message::Ping(bytes::Bytes::new())).await.is_err() {
                    break;
                }
            }
        }
    }

    // Cleanup: remove voice presence entries for this connection and broadcast leaves
    let removed = {
        let mut vp = state.voice_presence.write().await;
        let mut removed = Vec::new();
        vp.retain(|e| {
            if e.conn_id == conn_id && e.mailbox_id == mailbox_id {
                removed.push((e.channel_id, e.blob.clone()));
                false
            } else {
                true
            }
        });
        removed
    };
    if !removed.is_empty() {
        let map = state.mailboxes.read().await;
        if let Some(mailbox) = map.get(&mailbox_id) {
            for (channel_id, blob) in removed {
                let leave_json = serde_json::json!({
                    "vs": {
                        "ch": B64.encode(channel_id),
                        "leave": true,
                        "p": B64.encode(&blob),
                    }
                });
                let _ = mailbox.voice_tx.send((conn_id, leave_json.to_string()));
            }
        }
    }
}

async fn handle_voice_state(
    state: &AppState,
    mailbox_id: &[u8; 32],
    conn_id: u64,
    vs: VsInner,
) {
    let channel_id: [u8; 32] = match B64.decode(&vs.ch) {
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        _ => return,
    };

    if vs.leave == Some(true) {
        // Remove this connection's entry for this channel
        let removed_blob = {
            let mut vp = state.voice_presence.write().await;
            let pos = vp.iter().position(|e| {
                e.conn_id == conn_id && e.mailbox_id == *mailbox_id && e.channel_id == channel_id
            });
            pos.map(|i| vp.remove(i).blob)
        };
        if let Some(blob) = removed_blob {
            let leave_json = serde_json::json!({
                "vs": {
                    "ch": vs.ch,
                    "leave": true,
                    "p": B64.encode(&blob),
                }
            });
            let map = state.mailboxes.read().await;
            if let Some(mailbox) = map.get(mailbox_id) {
                let _ = mailbox.voice_tx.send((conn_id, leave_json.to_string()));
            }
        }
    } else if let Some(p_b64) = vs.p {
        let blob = match B64.decode(&p_b64) {
            Ok(b) if !b.is_empty() && b.len() <= MAX_PRESENCE_BLOB_SIZE => b,
            _ => return,
        };
        // Upsert in voice_presence
        {
            let mut vp = state.voice_presence.write().await;
            if let Some(entry) = vp.iter_mut().find(|e| {
                e.conn_id == conn_id && e.mailbox_id == *mailbox_id && e.channel_id == channel_id
            }) {
                entry.blob = blob.clone();
            } else {
                vp.push(VpEntry {
                    mailbox_id: *mailbox_id,
                    channel_id,
                    conn_id,
                    blob: blob.clone(),
                });
            }
        }
        // Broadcast to all mailbox subscribers
        let broadcast_json = serde_json::json!({
            "vs": { "ch": vs.ch, "p": p_b64 }
        });
        let map = state.mailboxes.read().await;
        if let Some(mailbox) = map.get(mailbox_id) {
            let _ = mailbox.voice_tx.send((conn_id, broadcast_json.to_string()));
        }
    }
}

fn encode_frame(seq: u64, received_at: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(WS_FRAME_HEADER_SIZE + payload.len());
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(&received_at.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}
