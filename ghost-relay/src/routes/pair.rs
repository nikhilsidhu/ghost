//! Device-linking rendezvous, kept at the account's home. Sessions are addressed by
//! account and a random token that only the pairing code carries, so only the holder
//! of the code can answer an offer or fetch the provision. Payloads are sealed by the
//! devices; the relay stores them opaquely for at most `PAIRING_TTL_MS`, or until the
//! existing device ends the session. The new device has no credentials yet, so its
//! requests are limited by address instead. A slot not filled yet answers 204, and a
//! session that is gone 404, so a device polling can tell the two apart.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::auth::{ClientIp, DeviceAuth};
use crate::error::{RelayError, Result};
use crate::state::AppState;
use crate::util::now_millis;

use super::decode_account_fp;
use ghost_wire::PAIRING_TTL_MS;

const PAIRING_TOKEN_LEN: usize = 16;
const MAX_PAIRING_PAYLOAD: usize = 4096;
const MAX_PROVISION_PAYLOAD: usize = 256 * 1024; // carries all server metadata

fn decode_token(hex_token: &str) -> Result<[u8; PAIRING_TOKEN_LEN]> {
    let bytes = hex::decode(hex_token).map_err(|_| RelayError::BadRequest("invalid hex pairing token".into()))?;
    bytes
        .try_into()
        .map_err(|_| RelayError::BadRequest(format!("pairing token must be {PAIRING_TOKEN_LEN} bytes")))
}

fn check_payload(body: &Bytes, max: usize) -> Result<()> {
    if body.is_empty() {
        return Err(RelayError::BadRequest("empty payload".into()));
    }
    if body.len() > max {
        return Err(RelayError::PayloadTooLarge);
    }
    Ok(())
}

/// A session's slot: its payload, or 204 while it is not filled yet.
fn slot(value: Option<Vec<u8>>) -> Response {
    match value {
        Some(payload) => (StatusCode::OK, payload).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

/// The existing device must be the account's, and the account homed here.
fn require_own_home(auth: &DeviceAuth, account_fp: &[u8; 32]) -> Result<()> {
    if auth.account_fp != *account_fp {
        return Err(RelayError::Unauthorized("account mismatch".into()));
    }
    auth.require_home()
}

/// POST /pair/{account_fp} — existing device opens a session. Body: `[token:16][sealed offer]`.
pub async fn post_offer(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
    body: Bytes,
) -> Result<StatusCode> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    require_own_home(&auth, &account_fp)?;
    if body.len() <= PAIRING_TOKEN_LEN {
        return Err(RelayError::BadRequest("missing token or offer".into()));
    }
    check_payload(&body.slice(PAIRING_TOKEN_LEN..), MAX_PAIRING_PAYLOAD)?;
    let (token, offer) = body.split_at(PAIRING_TOKEN_LEN);
    state.storage.pairing_open(account_fp, token.to_vec(), offer.to_vec(), now_millis() + PAIRING_TTL_MS).await?;
    Ok(StatusCode::CREATED)
}

/// GET /pair/{account_fp}/{token} — new device fetches the offer.
pub async fn get_offer(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path((account_fp_hex, token_hex)): Path<(String, String)>,
) -> Result<impl IntoResponse> {
    state.ip_limits.check_unauthenticated(ip)?;
    let account_fp = decode_account_fp(&account_fp_hex)?;
    let token = decode_token(&token_hex)?;
    let session = state.storage.pairing_get(account_fp, token.to_vec(), now_millis()).await?.ok_or(RelayError::NotFound)?;
    Ok((StatusCode::OK, session.offer))
}

/// POST /pair/{account_fp}/{token}/respond — new device answers, once.
pub async fn post_respond(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path((account_fp_hex, token_hex)): Path<(String, String)>,
    body: Bytes,
) -> Result<StatusCode> {
    state.ip_limits.check_unauthenticated(ip)?;
    let account_fp = decode_account_fp(&account_fp_hex)?;
    let token = decode_token(&token_hex)?;
    check_payload(&body, MAX_PAIRING_PAYLOAD)?;
    state.storage.pairing_set_response(account_fp, token.to_vec(), body.to_vec(), now_millis()).await?;
    Ok(StatusCode::CREATED)
}

/// GET /pair/{account_fp}/{token}/response — existing device polls for the answer.
pub async fn get_response(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path((account_fp_hex, token_hex)): Path<(String, String)>,
) -> Result<impl IntoResponse> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    require_own_home(&auth, &account_fp)?;
    let token = decode_token(&token_hex)?;
    let session = state.storage.pairing_get(account_fp, token.to_vec(), now_millis()).await?.ok_or(RelayError::NotFound)?;
    Ok(slot(session.response))
}

/// PUT /pair/{account_fp}/{token}/draft — existing device posts the AddDevice for the
/// new device to counter-sign. A later draft replaces it, since the log's head may
/// have moved, and clears the signature made for the old one.
pub async fn put_draft(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path((account_fp_hex, token_hex)): Path<(String, String)>,
    body: Bytes,
) -> Result<StatusCode> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    require_own_home(&auth, &account_fp)?;
    let token = decode_token(&token_hex)?;
    check_payload(&body, MAX_PAIRING_PAYLOAD)?;
    state.storage.pairing_set_draft(account_fp, token.to_vec(), body.to_vec(), now_millis()).await?;
    Ok(StatusCode::CREATED)
}

/// GET /pair/{account_fp}/{token}/draft — new device fetches the draft to counter-sign.
pub async fn get_draft(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path((account_fp_hex, token_hex)): Path<(String, String)>,
) -> Result<impl IntoResponse> {
    state.ip_limits.check_unauthenticated(ip)?;
    let account_fp = decode_account_fp(&account_fp_hex)?;
    let token = decode_token(&token_hex)?;
    let session = state.storage.pairing_get(account_fp, token.to_vec(), now_millis()).await?.ok_or(RelayError::NotFound)?;
    Ok(slot(session.draft))
}

/// POST /pair/{account_fp}/{token}/signatures — new device answers the current draft, once.
pub async fn post_signatures(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path((account_fp_hex, token_hex)): Path<(String, String)>,
    body: Bytes,
) -> Result<StatusCode> {
    state.ip_limits.check_unauthenticated(ip)?;
    let account_fp = decode_account_fp(&account_fp_hex)?;
    let token = decode_token(&token_hex)?;
    check_payload(&body, MAX_PAIRING_PAYLOAD)?;
    state.storage.pairing_set_signatures(account_fp, token.to_vec(), body.to_vec(), now_millis()).await?;
    Ok(StatusCode::CREATED)
}

/// GET /pair/{account_fp}/{token}/signatures — existing device polls for the counter-signature.
pub async fn get_signatures(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path((account_fp_hex, token_hex)): Path<(String, String)>,
) -> Result<impl IntoResponse> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    require_own_home(&auth, &account_fp)?;
    let token = decode_token(&token_hex)?;
    let session = state.storage.pairing_get(account_fp, token.to_vec(), now_millis()).await?.ok_or(RelayError::NotFound)?;
    Ok(slot(session.signatures))
}

/// PUT /pair/{account_fp}/{token}/provision — existing device uploads the sealed
/// provision. A later upload replaces it: a redraft after the log moved goes through
/// the upload again, and the new device fetches it only once it sees itself added.
pub async fn put_provision(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path((account_fp_hex, token_hex)): Path<(String, String)>,
    body: Bytes,
) -> Result<StatusCode> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    require_own_home(&auth, &account_fp)?;
    let token = decode_token(&token_hex)?;
    check_payload(&body, MAX_PROVISION_PAYLOAD)?;
    state.storage.pairing_set_provision(account_fp, token.to_vec(), body.to_vec(), now_millis()).await?;
    Ok(StatusCode::CREATED)
}

/// GET /pair/{account_fp}/{token}/provision — new device fetches the provision.
pub async fn get_provision(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path((account_fp_hex, token_hex)): Path<(String, String)>,
) -> Result<impl IntoResponse> {
    state.ip_limits.check_unauthenticated(ip)?;
    let account_fp = decode_account_fp(&account_fp_hex)?;
    let token = decode_token(&token_hex)?;
    let session = state.storage.pairing_get(account_fp, token.to_vec(), now_millis()).await?.ok_or(RelayError::NotFound)?;
    Ok(slot(session.provision))
}

/// DELETE /pair/{account_fp}/{token} — existing device ends the session: the new device
/// polling it hears it is gone, and the code answers nobody any more.
pub async fn delete_session(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path((account_fp_hex, token_hex)): Path<(String, String)>,
) -> Result<StatusCode> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    require_own_home(&auth, &account_fp)?;
    let token = decode_token(&token_hex)?;
    state.storage.pairing_close(account_fp, token.to_vec()).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Delete expired sessions.
pub async fn reap_expired(state: &AppState) {
    match state.storage.pairing_sweep(now_millis()).await {
        Ok(n) if n > 0 => tracing::debug!("swept {n} expired pairing sessions"),
        Err(e) => tracing::warn!("pairing sweep failed: {e}"),
        _ => {}
    }
}
