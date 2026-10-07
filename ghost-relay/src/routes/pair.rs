//! Device-linking rendezvous. Sessions are addressed by account and a random token
//! that only the pairing code carries, so only the holder of the code can answer an
//! offer or fetch the provision. Payloads are sealed by the devices; the relay
//! stores them opaquely for at most `PAIRING_TTL_MS`.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::auth::DeviceAuth;
use crate::error::{RelayError, Result};
use crate::state::AppState;
use crate::util::now_millis;

use super::decode_account_fp;

const PAIRING_TTL_MS: u64 = 10 * 60 * 1000;
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

fn require_account(auth: &DeviceAuth, account_fp: &[u8; 32]) -> Result<()> {
    if auth.account_fp != *account_fp {
        return Err(RelayError::Unauthorized("account mismatch".into()));
    }
    Ok(())
}

/// POST /pair/{account_fp} — existing device opens a session. Body: `[token:16][sealed offer]`.
pub async fn post_offer(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
    body: Bytes,
) -> Result<StatusCode> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    require_account(&auth, &account_fp)?;
    if body.len() <= PAIRING_TOKEN_LEN {
        return Err(RelayError::BadRequest("missing token or offer".into()));
    }
    check_payload(&body.slice(PAIRING_TOKEN_LEN..), MAX_PAIRING_PAYLOAD)?;
    let (token, offer) = body.split_at(PAIRING_TOKEN_LEN);
    state.storage.pairing_open(&account_fp, token, offer, now_millis() + PAIRING_TTL_MS)?;
    Ok(StatusCode::CREATED)
}

/// GET /pair/{account_fp}/{token} — new device fetches the offer.
pub async fn get_offer(
    State(state): State<AppState>,
    Path((account_fp_hex, token_hex)): Path<(String, String)>,
) -> Result<impl IntoResponse> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    let token = decode_token(&token_hex)?;
    let session = state.storage.pairing_get(&account_fp, &token, now_millis())?.ok_or(RelayError::NotFound)?;
    Ok((StatusCode::OK, session.offer))
}

/// POST /pair/{account_fp}/{token}/respond — new device answers, once.
pub async fn post_respond(
    State(state): State<AppState>,
    Path((account_fp_hex, token_hex)): Path<(String, String)>,
    body: Bytes,
) -> Result<StatusCode> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    let token = decode_token(&token_hex)?;
    check_payload(&body, MAX_PAIRING_PAYLOAD)?;
    state.storage.pairing_set_response(&account_fp, &token, &body, now_millis())?;
    Ok(StatusCode::CREATED)
}

/// GET /pair/{account_fp}/{token}/response — existing device polls for the answer.
pub async fn get_response(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path((account_fp_hex, token_hex)): Path<(String, String)>,
) -> Result<impl IntoResponse> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    require_account(&auth, &account_fp)?;
    let token = decode_token(&token_hex)?;
    let session = state.storage.pairing_get(&account_fp, &token, now_millis())?.ok_or(RelayError::NotFound)?;
    session.response.map(|r| (StatusCode::OK, r)).ok_or(RelayError::NotFound)
}

/// PUT /pair/{account_fp}/{token}/provision — existing device uploads the sealed provision.
pub async fn put_provision(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path((account_fp_hex, token_hex)): Path<(String, String)>,
    body: Bytes,
) -> Result<StatusCode> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    require_account(&auth, &account_fp)?;
    let token = decode_token(&token_hex)?;
    check_payload(&body, MAX_PROVISION_PAYLOAD)?;
    state.storage.pairing_set_provision(&account_fp, &token, &body, now_millis())?;
    Ok(StatusCode::CREATED)
}

/// GET /pair/{account_fp}/{token}/provision — new device fetches the provision.
pub async fn get_provision(
    State(state): State<AppState>,
    Path((account_fp_hex, token_hex)): Path<(String, String)>,
) -> Result<impl IntoResponse> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    let token = decode_token(&token_hex)?;
    let session = state.storage.pairing_get(&account_fp, &token, now_millis())?.ok_or(RelayError::NotFound)?;
    session.provision.map(|p| (StatusCode::OK, p)).ok_or(RelayError::NotFound)
}

/// Delete expired sessions.
pub fn reap_expired(state: &AppState) {
    match state.storage.pairing_sweep(now_millis()) {
        Ok(n) if n > 0 => tracing::debug!("swept {n} expired pairing sessions"),
        Err(e) => tracing::warn!("pairing sweep failed: {e}"),
        _ => {}
    }
}
