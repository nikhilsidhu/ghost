use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::{RelayError, Result};
use crate::state::AppState;

use super::decode_account_fp;

const MAX_IDLOG_ENTRY_SIZE: usize = 4096;

/// PUT /idlog/{account_fp_hex} — append a new identity log entry.
pub async fn put(
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
    body: Bytes,
) -> Result<StatusCode> {
    let account_fp = decode_account_fp(&account_fp_hex)?;

    if body.is_empty() {
        return Err(RelayError::BadRequest("empty payload".into()));
    }
    if body.len() > MAX_IDLOG_ENTRY_SIZE {
        return Err(RelayError::PayloadTooLarge);
    }

    let revoked = state.storage.append_idlog_entry(&account_fp, &body)?;
    for device_vk in revoked {
        let _ = state.revocation_tx.send((account_fp, device_vk));
    }
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
pub struct IdLogQuery {
    after_seq: Option<u64>,
}

#[derive(Serialize)]
pub struct IdLogEntry {
    pub seq: u64,
    #[serde(with = "base64_payload")]
    pub payload: Vec<u8>,
}

mod base64_payload {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::Serializer;

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }
}

/// GET /idlog/{account_fp_hex}?after_seq=N — fetch identity log entries.
pub async fn get(
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
    Query(query): Query<IdLogQuery>,
) -> Result<Json<Vec<IdLogEntry>>> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    let after_seq = query.after_seq.unwrap_or(0);
    let rows = state.storage.get_idlog(&account_fp, after_seq)?;
    let entries: Vec<IdLogEntry> = rows
        .into_iter()
        .map(|r| IdLogEntry {
            seq: r.seq,
            payload: r.payload,
        })
        .collect();
    Ok(Json(entries))
}
