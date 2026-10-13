use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;

use crate::auth::DeviceAuth;
use crate::error::Result;
use crate::state::AppState;
use crate::util::{decode_mailbox_id, now_millis};

pub async fn put(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
    body: Bytes,
) -> Result<StatusCode> {
    let id = decode_mailbox_id(&mailbox_id)?;
    state.check_membership(id, auth.account_fp).await?;
    if state.storage.sync_mailbox_owner(id).await?.is_some() {
        return Err(crate::error::RelayError::Forbidden("a sync mailbox has no group state".into()));
    }
    if !state.may_initialize(&id, &auth.account_fp) {
        // Members keep the published GroupInfo current after their commits, so other
        // devices can join by external commit; they cannot change the group state.
        state.publish_group_info(id, body.to_vec()).await?;
        return Ok(StatusCode::NO_CONTENT);
    }
    // Initialize/update the PublicGroup from the uploaded GroupInfo, which is stored
    // with it. A policy refusal rejects the upload; other failures are non-fatal, since
    // pre-upgrade groups may have non-standard GroupInfo, which is then stored alone. An
    // upload from a device behind on the group's epochs is dropped, keeping the newer
    // GroupInfo joiners need.
    match state.init_public_group(id, body.to_vec(), auth.account_fp).await {
        Err(e @ crate::error::RelayError::Forbidden(_)) => return Err(e),
        Err(e) => {
            tracing::warn!("PublicGroup init skipped for {mailbox_id}: {e}");
            state.storage.put_server_info(id, body.to_vec()).await?;
        }
        Ok(_) => {}
    }
    Ok(StatusCode::NO_CONTENT)
}

/// What a reader of the group state may add to its request.
#[derive(Deserialize)]
pub struct ServerInfoQuery {
    /// An invite into the mailbox, which admits a joiner that is not a member yet.
    invite: Option<String>,
}

pub async fn get(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
    Query(query): Query<ServerInfoQuery>,
) -> Result<impl IntoResponse> {
    let id = decode_mailbox_id(&mailbox_id)?;
    if let Err(refusal) = state.check_membership(id, auth.account_fp).await {
        // A joiner builds its external commit on the group state as the relay holds it.
        let invited = match &query.invite {
            Some(token) => state
                .storage
                .invite_get(token.clone())
                .await?
                .is_some_and(|invite| invite.mailbox == id && invite.expires_at > now_millis()),
            None => false,
        };
        if !invited {
            return Err(refusal);
        }
    }
    match state.storage.get_server_info(id).await? {
        Some(data) => Ok((StatusCode::OK, data)),
        None => Err(crate::error::RelayError::NotFound),
    }
}
