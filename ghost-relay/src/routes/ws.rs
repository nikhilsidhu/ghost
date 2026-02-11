use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use uuid::Uuid;

use crate::error::RelayError;
use crate::mailbox::{Blob, Mailbox};
use crate::state::AppState;
use crate::util::{decode_mailbox_id, now_millis};

const PING_INTERVAL: Duration = Duration::from_secs(30);
const UUID_SIZE: usize = 16;
const TIMESTAMP_SIZE: usize = 8;
const BLOB_HEADER_SIZE: usize = UUID_SIZE + TIMESTAMP_SIZE;

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

    let mut rx = {
        let mut map = state.mailboxes.write().await;
        let mailbox = map.entry(mailbox_id).or_insert_with(Mailbox::new);
        mailbox.tx.subscribe()
    };

    let mut ping_interval = tokio::time::interval(PING_INTERVAL);
    // Track blob_ids this client submitted so we don't echo them back
    let mut own_blobs: Vec<Uuid> = Vec::new();

    loop {
        tokio::select! {
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        match store_blob(&state, &mailbox_id, data.to_vec()).await {
                            Ok(blob_id) => {
                                own_blobs.push(blob_id);
                                let ack = Message::text(blob_id.to_string());
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
                        if let Ok(blob_uuid) = text.as_str().parse::<Uuid>() {
                            remove_blob(&state, &mailbox_id, blob_uuid).await;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
            result = rx.recv() => {
                let blob_id = match result {
                    Ok(id) => id,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        own_blobs.clear();
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                };
                // Skip blobs this client submitted
                if let Some(pos) = own_blobs.iter().position(|id| *id == blob_id) {
                    own_blobs.swap_remove(pos);
                    continue;
                }
                // Send only the new blob
                let frame = {
                    let map = state.mailboxes.read().await;
                    map.get(&mailbox_id)
                        .and_then(|m| m.blobs.iter().find(|b| b.id == blob_id))
                        .map(encode_blob)
                };
                if let Some(frame) = frame {
                    if sink.send(Message::binary(frame)).await.is_err() {
                        break;
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

async fn store_blob(
    state: &AppState,
    mailbox_id: &[u8; 32],
    payload: Vec<u8>,
) -> Result<Uuid, RelayError> {
    if payload.len() > state.config.max_blob_size {
        return Err(RelayError::PayloadTooLarge);
    }
    if !state.try_reserve(payload.len()) {
        return Err(RelayError::StorageFull);
    }

    let blob_id = Uuid::new_v4();
    let received_at = now_millis();

    let mut map = state.mailboxes.write().await;
    let mailbox = map.entry(*mailbox_id).or_insert_with(Mailbox::new);
    mailbox.blobs.push(Blob {
        id: blob_id,
        received_at,
        payload,
    });
    let _ = mailbox.tx.send(blob_id);

    Ok(blob_id)
}

async fn remove_blob(state: &AppState, mailbox_id: &[u8; 32], blob_uuid: Uuid) {
    let mut map = state.mailboxes.write().await;
    if let Some(mailbox) = map.get_mut(mailbox_id) {
        if let Some(pos) = mailbox.blobs.iter().position(|b| b.id == blob_uuid) {
            let removed = mailbox.blobs.remove(pos);
            state.release(removed.payload.len());
        }
    }
}

/// blob_id (16 bytes) + received_at (8 bytes BE) + payload
fn encode_blob(blob: &Blob) -> Vec<u8> {
    let mut frame = Vec::with_capacity(BLOB_HEADER_SIZE + blob.payload.len());
    frame.extend_from_slice(blob.id.as_bytes());
    frame.extend_from_slice(&blob.received_at.to_be_bytes());
    frame.extend_from_slice(&blob.payload);
    frame
}
