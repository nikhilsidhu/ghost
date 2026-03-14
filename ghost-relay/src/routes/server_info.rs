use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::auth::DeviceAuth;
use crate::error::Result;
use crate::state::AppState;
use crate::util::decode_mailbox_id;

pub async fn put(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
    body: Bytes,
) -> Result<StatusCode> {
    let id = decode_mailbox_id(&mailbox_id)?;
    state.check_membership(&id, &auth.account_fp)?;
    if !state.is_creator(&id, &auth.account_fp).await {
        return Err(crate::error::RelayError::Forbidden(
            "only group creator can update server info".into(),
        ));
    }
    state.storage.put_server_info(&id, &body)?;

    // Try to initialize/update PublicGroup from the uploaded GroupInfo.
    // Failure is non-fatal: pre-upgrade groups may have non-standard GroupInfo.
    if let Err(e) = state.init_public_group(&id, &body).await {
        tracing::warn!("PublicGroup init skipped for {mailbox_id}: {e}");
    }

    Ok(StatusCode::NO_CONTENT)
}

pub async fn get(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
) -> Result<impl IntoResponse> {
    let id = decode_mailbox_id(&mailbox_id)?;
    state.check_membership(&id, &auth.account_fp)?;
    match state.storage.get_server_info(&id)? {
        Some(data) => Ok((StatusCode::OK, data)),
        None => Err(crate::error::RelayError::NotFound),
    }
}
