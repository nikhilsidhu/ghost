use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::auth::DeviceAuth;
use crate::constants::{DEFAULT_READ_LIMIT, MAX_LONG_POLL_MS};
use crate::error::Result;
use crate::mailbox::Mailbox;
use crate::state::AppState;
use crate::util::decode_mailbox_id;

fn is_false(b: &bool) -> bool {
    !b
}

#[derive(Serialize)]
pub(crate) struct PostBlobResponse {
    seq: u64,
    #[serde(skip_serializing_if = "is_false")]
    epoch_mismatch: bool,
}

#[derive(Serialize)]
pub(crate) struct BlobEntry {
    seq: u64,
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

#[derive(Deserialize)]
pub(crate) struct BlobQuery {
    after: Option<u64>,
}

pub async fn post_blob(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
    body: Bytes,
) -> Result<(StatusCode, Json<PostBlobResponse>)> {
    let id = decode_mailbox_id(&mailbox_id)?;

    // Skip membership check for commits/proposals — MLS validation handles their
    // authorization, and external commits (joins) come from non-members by definition.
    let (envelope_type, _) = ghost_wire::decode_envelope(&body)
        .map_err(|e| crate::error::RelayError::BadRequest(format!("envelope: {e}")))?;
    if envelope_type == ghost_wire::EnvelopeType::Application {
        state.check_membership(&id, &auth.account_fp)?;
    }

    let (seq, epoch_mismatch) = state.store_blob(&id, &body).await?;
    Ok((StatusCode::CREATED, Json(PostBlobResponse { seq, epoch_mismatch })))
}

pub async fn get_blobs(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
    Query(query): Query<BlobQuery>,
    headers: HeaderMap,
) -> Result<Json<Vec<BlobEntry>>> {
    let id = decode_mailbox_id(&mailbox_id)?;
    state.check_membership(&id, &auth.account_fp)?;
    let after_seq = query.after.unwrap_or(0);

    let timeout_ms: u64 = headers
        .get("X-Ghost-Long-Poll")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
        .min(MAX_LONG_POLL_MS);

    if timeout_ms == 0 {
        let entries = state.storage.read_from(&id, after_seq, DEFAULT_READ_LIMIT)?;
        return Ok(Json(to_entries(entries)));
    }

    // Subscribe before checking so we don't miss notifications
    let mut rx = {
        let mut map = state.mailboxes.write().await;
        let mailbox = map.entry(id).or_insert_with(Mailbox::new);
        mailbox.seq_tx.subscribe()
    };

    let entries = state.storage.read_from(&id, after_seq, DEFAULT_READ_LIMIT)?;
    if !entries.is_empty() {
        return Ok(Json(to_entries(entries)));
    }

    let timeout = Duration::from_millis(timeout_ms);
    let _ = tokio::time::timeout(timeout, rx.changed()).await;

    let entries = state.storage.read_from(&id, after_seq, DEFAULT_READ_LIMIT)?;
    Ok(Json(to_entries(entries)))
}

fn to_entries(entries: Vec<crate::storage::LogEntry>) -> Vec<BlobEntry> {
    entries
        .into_iter()
        .map(|e| BlobEntry {
            seq: e.seq,
            received_at: e.received_at,
            payload: e.payload,
        })
        .collect()
}

pub async fn delete_mailbox(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
) -> Result<StatusCode> {
    let id = decode_mailbox_id(&mailbox_id)?;
    if !state.is_creator(&id, &auth.account_fp).await {
        return Err(crate::error::RelayError::Forbidden(
            "only group creator can delete a mailbox".into(),
        ));
    }
    state.delete_mailbox(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}
