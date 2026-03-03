use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::auth::DeviceAuth;
use crate::error::{RelayError, Result};
use crate::state::AppState;

use super::decode_account_fp;

const MAX_SYNC_STATE_BLOB_SIZE: usize = 256 * 1024; // 256 KB

/// PUT /sync_state/{account_fp_hex} — store encrypted sync state snapshot.
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
    if body.is_empty() {
        return Err(RelayError::BadRequest("empty payload".into()));
    }
    if body.len() > MAX_SYNC_STATE_BLOB_SIZE {
        return Err(RelayError::PayloadTooLarge);
    }
    state.storage.put_sync_state(&account_fp, &body)?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /sync_state/{account_fp_hex} — fetch encrypted sync state snapshot.
pub async fn get(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
) -> Result<impl IntoResponse> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    if auth.account_fp != account_fp {
        return Err(RelayError::Unauthorized("account mismatch".into()));
    }
    match state.storage.get_sync_state(&account_fp)? {
        Some(data) => Ok((StatusCode::OK, data)),
        None => Err(RelayError::NotFound),
    }
}
