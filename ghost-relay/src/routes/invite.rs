//! Invite rendezvous: the inviter opens a token for a server and uploads, once, the
//! sealed payload joiners fetch. Only the invite link carries the token, so only its
//! holders can fetch the payload. The token lives until the expiry this relay applies,
//! which it reports so the invite's grant and its creator's screen say the same.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::auth::{ClientIp, DeviceAuth};
use ghost_wire::INVITE_TOKEN_LEN;

use crate::constants::{DEFAULT_LONG_POLL_MS, MAX_INVITE_LIFETIME_MS, MAX_LONG_POLL_MS};
use crate::error::{RelayError, Result};
use crate::state::AppState;
use crate::util::{decode_mailbox_id, now_millis};

const LONG_POLL_HEADER: &str = "X-Ghost-Long-Poll";

#[derive(Deserialize)]
pub struct RegisterInvite {
    pub token: String,
    /// When the creator wants the invite to end; unset for as long as this relay allows.
    pub expires_at: Option<u64>,
    /// The server the invite is into: its mailbox, base64url.
    pub mailbox: String,
}

#[derive(Serialize)]
pub struct RegisteredInvite {
    /// When the invite ends: the creator's choice, or sooner when this relay allows less.
    pub expires_at: u64,
}

/// Whether the token is one the core makes: `INVITE_TOKEN_LEN` random bytes, hex-encoded.
fn well_formed_token(token: &str) -> bool {
    hex::decode(token).is_ok_and(|bytes| bytes.len() == INVITE_TOKEN_LEN)
}

/// POST /invite — open an invite. Its expiry is clamped, so no invite stays open forever,
/// and the expiry applied is the answer.
pub async fn register(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Json(body): Json<RegisterInvite>,
) -> Result<(StatusCode, Json<RegisteredInvite>)> {
    if !well_formed_token(&body.token) {
        return Err(RelayError::BadRequest(format!("an invite token is {INVITE_TOKEN_LEN} bytes, hex-encoded")));
    }
    let mailbox = decode_mailbox_id(&body.mailbox)?;
    state.check_membership(mailbox, auth.account_fp).await?;
    let longest = now_millis() + MAX_INVITE_LIFETIME_MS;
    let expires_at = body.expires_at.map_or(longest, |asked| asked.min(longest));
    state.storage.invite_register(body.token, mailbox, auth.account_fp, expires_at).await?;
    Ok((StatusCode::CREATED, Json(RegisteredInvite { expires_at })))
}

/// POST /invite/{token}/join — the inviter, or a member of the server, uploads the
/// payload, once.
pub async fn join(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(token): Path<String>,
    body: Bytes,
) -> Result<StatusCode> {
    if !well_formed_token(&token) {
        return Err(RelayError::NotFound);
    }
    state.storage.invite_set_payload(token.clone(), body.to_vec(), now_millis(), auth.account_fp).await?;
    state.notify_invite(&token);
    Ok(StatusCode::ACCEPTED)
}

/// GET /invite/{token}/join — a joiner fetches the payload, waiting for it to appear
/// when asked to. Unauthenticated: the joiner has no standing here yet.
pub async fn get_join(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Result<(StatusCode, Vec<u8>)> {
    state.ip_limits.check_unauthenticated(ip)?;
    if !well_formed_token(&token) {
        return Err(RelayError::NotFound);
    }
    let timeout_ms: u64 = headers
        .get(LONG_POLL_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_LONG_POLL_MS)
        .min(MAX_LONG_POLL_MS);

    // Subscribed before the first look, so an upload in between is not missed.
    let mut waiter = state.invite_waiter(&token);
    if let Some(found) = payload_of(&state, &token).await? {
        return Ok(found);
    }
    let _ = tokio::time::timeout(Duration::from_millis(timeout_ms), waiter.recv()).await;
    match payload_of(&state, &token).await? {
        Some(found) => Ok(found),
        None => Ok((StatusCode::NO_CONTENT, Vec::new())),
    }
}

/// The invite's payload with its sequence, if it has one; 404 for an unknown token.
async fn payload_of(state: &AppState, token: &str) -> Result<Option<(StatusCode, Vec<u8>)>> {
    let invite = state.storage.invite_get(token.to_string()).await?.ok_or(RelayError::NotFound)?;
    Ok(invite.payload.map(|payload| (StatusCode::OK, payload)))
}
