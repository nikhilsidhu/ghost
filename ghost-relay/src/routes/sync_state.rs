use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use ghost_wire::SNAPSHOT_GENERATION_LEN;

use crate::auth::DeviceAuth;
use crate::error::{RelayError, Result};
use crate::state::AppState;

use super::decode_account_fp;

const MAX_SYNC_STATE_BLOB_SIZE: usize = 256 * 1024; // 256 KB

/// PUT /sync_state/{account_fp_hex} — store `[generation:8][sealed snapshot]`.
/// 409 when the stored snapshot's generation is equal or newer.
pub async fn put(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
    body: Bytes,
) -> Result<StatusCode> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    if auth.account_fp != account_fp {
        return Err(RelayError::Unauthorized("account mismatch".into()));
    }
    if body.len() <= SNAPSHOT_GENERATION_LEN {
        return Err(RelayError::BadRequest("missing generation or snapshot".into()));
    }
    if body.len() > MAX_SYNC_STATE_BLOB_SIZE + SNAPSHOT_GENERATION_LEN {
        return Err(RelayError::PayloadTooLarge);
    }
    let generation = u64::from_be_bytes(body[..SNAPSHOT_GENERATION_LEN].try_into().unwrap());
    state.storage.put_sync_state(account_fp, generation, body[SNAPSHOT_GENERATION_LEN..].to_vec()).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /sync_state/{account_fp_hex} — fetch `[generation:8][sealed snapshot]`.
pub async fn get(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
) -> Result<impl IntoResponse> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    if auth.account_fp != account_fp {
        return Err(RelayError::Unauthorized("account mismatch".into()));
    }
    match state.storage.get_sync_state(account_fp).await? {
        Some((generation, data)) => {
            let mut body = Vec::with_capacity(SNAPSHOT_GENERATION_LEN + data.len());
            body.extend_from_slice(&generation.to_be_bytes());
            body.extend_from_slice(&data);
            Ok((StatusCode::OK, body))
        }
        None => Err(RelayError::NotFound),
    }
}
