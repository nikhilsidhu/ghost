//! Private channel discovery: a member learns only the private channels it may enter.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use ghost_wire::policy::AdmittedChannels;

use crate::auth::DeviceAuth;
use crate::error::Result;
use crate::state::AppState;
use crate::util::decode_mailbox_id;

/// GET /servers/{server_mailbox}/channels — the server's private channel groups whose
/// policy admits the requesting account, with their published GroupInfo. Channels
/// that do not admit it are left out, so it never learns they exist.
pub async fn list(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(server_mailbox): Path<String>,
) -> Result<(StatusCode, Vec<u8>)> {
    let server_mailbox = decode_mailbox_id(&server_mailbox)?;
    let mut listing = AdmittedChannels::default();
    for mailbox in state.admitted_channels(&server_mailbox, &auth.account_fp).await? {
        if let Some(group_info) = state.storage.get_server_info(&mailbox)? {
            listing.0.push((mailbox, group_info));
        }
    }
    Ok((StatusCode::OK, listing.to_bytes()))
}
