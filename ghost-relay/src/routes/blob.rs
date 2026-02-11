use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Serialize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use uuid::Uuid;

use crate::error::{RelayError, Result};
use crate::mailbox::{Blob, Mailbox};
use crate::state::AppState;
use crate::util::{decode_mailbox_id, now_millis};

#[derive(Serialize)]
pub(crate) struct PostBlobResponse {
    blob_id: String,
}

#[derive(Serialize)]
pub(crate) struct BlobEntry {
    blob_id: String,
    received_at: u64,
    #[serde(with = "base64_payload")]
    payload: Vec<u8>,
}

mod base64_payload {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::Serializer;

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }
}

pub async fn post_blob(
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
    body: Bytes,
) -> Result<(StatusCode, Json<PostBlobResponse>)> {
    let id = decode_mailbox_id(&mailbox_id)?;

    if body.len() > state.config.max_blob_size {
        return Err(RelayError::PayloadTooLarge);
    }

    let current_mem = state.memory_used.load(Ordering::Relaxed);
    if current_mem + body.len() > state.config.max_memory {
        return Err(RelayError::StorageFull);
    }

    let blob_id = Uuid::new_v4();
    let received_at = now_millis();
    let payload = body.to_vec();

    state
        .memory_used
        .fetch_add(payload.len(), Ordering::Relaxed);

    let mut map = state.mailboxes.write().await;
    let mailbox = map.entry(id).or_insert_with(Mailbox::new);

    // Wake any long-poll or WS subscribers; ignore if none connected
    let _ = mailbox.tx.send(blob_id);

    mailbox.blobs.push(Blob {
        id: blob_id,
        received_at,
        payload,
    });

    Ok((
        StatusCode::CREATED,
        Json(PostBlobResponse {
            blob_id: blob_id.to_string(),
        }),
    ))
}

pub async fn get_blobs(
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<BlobEntry>>> {
    let id = decode_mailbox_id(&mailbox_id)?;

    let timeout_ms: u64 = headers
        .get("X-Ghost-Long-Poll")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    // No long-poll: read lock, no mailbox creation
    if timeout_ms == 0 {
        let map = state.mailboxes.read().await;
        return match map.get(&id) {
            Some(mailbox) => Ok(Json(to_entries(&mailbox.blobs))),
            None => Ok(Json(Vec::new())),
        };
    }

    // Long-poll: write lock to ensure mailbox exists, check + subscribe atomically
    let mut rx = {
        let mut map = state.mailboxes.write().await;
        let mailbox = map.entry(id).or_insert_with(Mailbox::new);
        if !mailbox.blobs.is_empty() {
            return Ok(Json(to_entries(&mailbox.blobs)));
        }
        mailbox.tx.subscribe()
    };

    let timeout = Duration::from_millis(timeout_ms);
    let _ = tokio::time::timeout(timeout, rx.recv()).await;

    // Return whatever's in the mailbox now
    let map = state.mailboxes.read().await;
    match map.get(&id) {
        Some(mailbox) => Ok(Json(to_entries(&mailbox.blobs))),
        None => Ok(Json(Vec::new())),
    }
}

pub async fn delete_blob(
    State(state): State<AppState>,
    Path((mailbox_id, blob_id)): Path<(String, String)>,
) -> Result<StatusCode> {
    let id = decode_mailbox_id(&mailbox_id)?;
    let blob_uuid: Uuid = blob_id
        .parse()
        .map_err(|_| RelayError::BadRequest("invalid blob id".into()))?;

    let mut map = state.mailboxes.write().await;
    let mailbox = map.get_mut(&id).ok_or(RelayError::NotFound)?;

    let pos = mailbox
        .blobs
        .iter()
        .position(|b| b.id == blob_uuid)
        .ok_or(RelayError::NotFound)?;

    let removed = mailbox.blobs.remove(pos);
    state
        .memory_used
        .fetch_sub(removed.payload.len(), Ordering::Relaxed);

    Ok(StatusCode::NO_CONTENT)
}

fn to_entries(blobs: &[Blob]) -> Vec<BlobEntry> {
    blobs
        .iter()
        .map(|b| BlobEntry {
            blob_id: b.id.to_string(),
            received_at: b.received_at,
            payload: b.payload.clone(),
        })
        .collect()
}
