use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::auth::DeviceAuth;
use crate::constants::MAX_AVATAR_SIZE;
use crate::error::{RelayError, Result};
use crate::state::AppState;
use crate::util::decode_mailbox_id;

fn decode_fingerprint(hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex)
        .map_err(|_| RelayError::BadRequest("invalid hex fingerprint".into()))?;
    bytes
        .try_into()
        .map_err(|_| RelayError::BadRequest("fingerprint must be 32 bytes".into()))
}

pub async fn put(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path((mailbox_id, fingerprint)): Path<(String, String)>,
    body: Bytes,
) -> Result<StatusCode> {
    if body.len() > MAX_AVATAR_SIZE {
        return Err(RelayError::PayloadTooLarge);
    }
    let id = decode_mailbox_id(&mailbox_id)?;
    state.check_membership(&id, &auth.account_fp)?;
    let fp = decode_fingerprint(&fingerprint)?;
    if fp != auth.account_fp {
        return Err(RelayError::Forbidden("can only update your own avatar".into()));
    }
    state.storage.put_avatar(&id, &fp, &body)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path((mailbox_id, fingerprint)): Path<(String, String)>,
) -> Result<impl IntoResponse> {
    let id = decode_mailbox_id(&mailbox_id)?;
    state.check_membership(&id, &auth.account_fp)?;
    let fp = decode_fingerprint(&fingerprint)?;
    match state.storage.get_avatar(&id, &fp)? {
        Some(data) => Ok((StatusCode::OK, data)),
        None => Err(RelayError::NotFound),
    }
}

pub async fn delete(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path((mailbox_id, fingerprint)): Path<(String, String)>,
) -> Result<StatusCode> {
    let id = decode_mailbox_id(&mailbox_id)?;
    state.check_membership(&id, &auth.account_fp)?;
    let fp = decode_fingerprint(&fingerprint)?;
    if fp != auth.account_fp {
        return Err(RelayError::Forbidden("can only delete your own avatar".into()));
    }
    state.storage.delete_avatar(&id, &fp)?;
    Ok(StatusCode::NO_CONTENT)
}
