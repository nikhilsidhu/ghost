use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use ghost_wire::merkle::InclusionProof;
use serde::{Deserialize, Serialize};


use crate::error::{RelayError, Result};
use crate::state::AppState;

use super::decode_account_fp;

const MAX_IDLOG_ENTRY_SIZE: usize = 4096;

/// Byte offset of entry_type in the binary-encoded LogEntry.
/// Layout: seq(8) + prev_hash(32) + account_fp(32) = 72
const ENTRY_TYPE_OFFSET: usize = 72;
const ENTRY_TYPE_GENESIS: u8 = 0x01;
const ENTRY_TYPE_RECOVERY: u8 = 0x04;

/// PUT /idlog/{account_fp_hex} — append a new identity log entry.
/// Genesis entries (entry_type 0x01) are self-authenticating; all others require DeviceAuth.
pub async fn put(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    method: axum::http::Method,
    uri: axum::http::Uri,
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

    let is_genesis = body.len() > ENTRY_TYPE_OFFSET && body[ENTRY_TYPE_OFFSET] == ENTRY_TYPE_GENESIS;
    if !is_genesis {
        let auth = crate::auth::validate_auth_headers(&headers, method.as_str(), uri.path(), &state)?;
        if auth.account_fp != account_fp {
            return Err(RelayError::Forbidden("account mismatch".into()));
        }
    }

    if body.len() > ENTRY_TYPE_OFFSET && body[ENTRY_TYPE_OFFSET] == ENTRY_TYPE_RECOVERY {
        if !state.idlog_recovery_limiter.check(&account_fp) {
            return Err(RelayError::RateLimited);
        }
    }

    let (revoked, entry_seq) = state.storage.append_idlog_entry(&account_fp, &body)?;

    // Record in the key transparency tree
    state.kt_append_and_sign(&body, &account_fp, entry_seq).await;

    for device_vk in &revoked {
        let _ = state.revocation_tx.send((account_fp, *device_vk));
    }
    for device_vk in &revoked {
        state.generate_removal_proposals(&account_fp, device_vk).await;
    }
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
pub struct IdLogQuery {
    after_seq: Option<u64>,
}

#[derive(Serialize)]
pub struct IdLogResponse {
    pub entries: Vec<IdLogEntryWithProof>,
    #[serde(with = "base64_bytes")]
    pub checkpoint: Vec<u8>,
}

#[derive(Serialize)]
pub struct IdLogEntryWithProof {
    pub seq: u64,
    #[serde(with = "base64_bytes")]
    pub payload: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub inclusion_proof: Vec<u8>,
}

mod base64_bytes {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::Serializer;

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }
}

/// GET /idlog/{account_fp_hex}?after_seq=N — fetch identity log entries with KT proofs.
pub async fn get(
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
    Query(query): Query<IdLogQuery>,
) -> Result<Json<IdLogResponse>> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    let after_seq = query.after_seq.unwrap_or(0);
    let rows = state.storage.get_idlog(&account_fp, after_seq)?;

    // Load checkpoint + tree_size atomically from DB (both written in the
    // same transaction by kt_persist_state).
    let (checkpoint, tree_size) = state.storage.kt_load_checkpoint_with_size()?;

    let storage = &state.storage;
    let load = |start: u64, count: u64| -> Option<[u8; 32]> {
        storage.kt_load_hash(start, count).ok().flatten()
    };

    let mut entries = Vec::with_capacity(rows.len());
    for r in rows {
        let proof_bytes =
            match state.storage.kt_get_leaf_index(&account_fp, r.seq)? {
                Some(leaf_index) if leaf_index < tree_size => {
                    let proof =
                        InclusionProof::generate_from_store(leaf_index, tree_size, &load);
                    proof.to_bytes()
                }
                _ => Vec::new(),
            };

        entries.push(IdLogEntryWithProof {
            seq: r.seq,
            payload: r.payload,
            inclusion_proof: proof_bytes,
        });
    }

    Ok(Json(IdLogResponse {
        entries,
        checkpoint,
    }))
}
