use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;

use crate::constants::{WS_FRAME_HEADER_SIZE, WS_MAX_FANOUT_BATCH, WS_PING_INTERVAL_SECS};
use crate::mailbox::Mailbox;
use crate::state::AppState;
use crate::util::decode_mailbox_id;

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

    let mut seq_rx = {
        let mut map = state.mailboxes.write().await;
        let mailbox = map.entry(mailbox_id).or_insert_with(Mailbox::new);
        mailbox.seq_tx.subscribe()
    };

    let ping_interval_dur = Duration::from_secs(WS_PING_INTERVAL_SECS);
    let mut ping_interval = tokio::time::interval(ping_interval_dur);
    let mut last_seen: u64 = 0;
    let mut own_seqs: Vec<u64> = Vec::new();

    loop {
        tokio::select! {
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        match state.store_blob(&mailbox_id, &data).await {
                            Ok(seq) => {
                                own_seqs.push(seq);
                                let ack = Message::text(seq.to_string());
                                if sink.send(ack).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                let _ = sink.send(Message::text(format!("error: {e}"))).await;
                            }
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
            _ = ping_interval.tick() => {
                if sink.send(Message::Ping(bytes::Bytes::new())).await.is_err() {
                    break;
                }
            }
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
