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
    if !state.may_initialize(&id, &auth.account_fp).await {
        // Members keep the published GroupInfo current after their commits, so other
        // devices can join by external commit; they cannot change the group state.
        if !state.group_info_matches_state(&id, &body).await? {
            return Err(crate::error::RelayError::Forbidden(
                "members may only publish GroupInfo for the relay's current group state".into(),
            ));
        }
        state.storage.put_server_info(&id, &body)?;
        return Ok(StatusCode::NO_CONTENT);
    }
    // Initialize/update the PublicGroup from the uploaded GroupInfo. A policy refusal
    // rejects the upload; other failures are non-fatal, since pre-upgrade groups may
    // have non-standard GroupInfo.
    match state.init_public_group(&id, &body, &auth.account_fp).await {
        Err(e @ crate::error::RelayError::Forbidden(_)) => return Err(e),
        Err(e) => tracing::warn!("PublicGroup init skipped for {mailbox_id}: {e}"),
        Ok(()) => {}
    }
    state.storage.put_server_info(&id, &body)?;

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
