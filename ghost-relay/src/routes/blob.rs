use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

use crate::auth::DeviceAuth;
use crate::error::Result;
use crate::state::AppState;
use crate::util::decode_mailbox_id;

#[derive(Serialize)]
pub(crate) struct PostBlobResponse {
    seq: u64,
}

pub async fn post_blob(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
    body: Bytes,
) -> Result<(StatusCode, Json<PostBlobResponse>)> {
    let id = decode_mailbox_id(&mailbox_id)?;
    let stored = state.accept_post(id, auth.account_fp, body.to_vec()).await?;
    Ok((StatusCode::CREATED, Json(PostBlobResponse { seq: stored.seq })))
}

pub async fn delete_mailbox(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
) -> Result<StatusCode> {
    let id = decode_mailbox_id(&mailbox_id)?;
    state.may_delete(&id, &auth.account_fp)?;
    state.delete_mailbox(id).await?;
    Ok(StatusCode::NO_CONTENT)
}
