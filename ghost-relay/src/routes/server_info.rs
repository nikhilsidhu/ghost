use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::auth::DeviceAuth;
use crate::error::Result;
use crate::state::AppState;
use crate::util::decode_mailbox_id;

pub async fn put(
    _auth: DeviceAuth,
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
    body: Bytes,
) -> Result<StatusCode> {
    let id = decode_mailbox_id(&mailbox_id)?;
    state.storage.put_server_info(&id, &body)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get(
    _auth: DeviceAuth,
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
) -> Result<impl IntoResponse> {
    let id = decode_mailbox_id(&mailbox_id)?;
    match state.storage.get_server_info(&id)? {
        Some(data) => Ok((StatusCode::OK, data)),
        None => Err(crate::error::RelayError::NotFound),
    }
}
