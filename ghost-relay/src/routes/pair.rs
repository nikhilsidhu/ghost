use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::auth::DeviceAuth;
use crate::error::{RelayError, Result};
use crate::state::{AppState, PairingSession, ProvisionEntry};

use super::decode_account_fp;

const PAIRING_TTL: Duration = Duration::from_secs(300); // 5 minutes
const MAX_PAIRING_PAYLOAD: usize = 4096;
const MAX_PROVISION_PAYLOAD: usize = 256 * 1024; // 256 KB — carries all server metadata

/// POST /pair/{account_fp} — existing device posts pairing offer.
pub async fn post_offer(
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
    body: Bytes,
) -> Result<StatusCode> {
    let account_fp = decode_account_fp(&account_fp_hex)?;

    if body.is_empty() {
        return Err(RelayError::BadRequest("empty payload".into()));
    }
    if body.len() > MAX_PAIRING_PAYLOAD {
        return Err(RelayError::PayloadTooLarge);
    }

    let mut map = state.pairing.write().await;
    map.insert(
        account_fp,
        PairingSession {
            offer: body.to_vec(),
            response: None,
            expires_at: Instant::now() + PAIRING_TTL,
        },
    );
    Ok(StatusCode::CREATED)
}

/// POST /pair/{account_fp}/respond — new device posts response.
pub async fn post_respond(
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
    body: Bytes,
) -> Result<StatusCode> {
    let account_fp = decode_account_fp(&account_fp_hex)?;

    if body.is_empty() {
        return Err(RelayError::BadRequest("empty payload".into()));
    }
    if body.len() > MAX_PAIRING_PAYLOAD {
        return Err(RelayError::PayloadTooLarge);
    }

    let mut map = state.pairing.write().await;
    let session = map.get_mut(&account_fp).ok_or(RelayError::NotFound)?;
    if Instant::now() >= session.expires_at {
        map.remove(&account_fp);
        return Err(RelayError::NotFound);
    }
    session.response = Some(body.to_vec());
    Ok(StatusCode::NO_CONTENT)
}

/// GET /pair/{account_fp}/response — existing device polls for response.
pub async fn get_response(
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
) -> Result<impl IntoResponse> {
    let account_fp = decode_account_fp(&account_fp_hex)?;

    let map = state.pairing.read().await;
    let session = map.get(&account_fp).ok_or(RelayError::NotFound)?;
    if Instant::now() >= session.expires_at {
        return Err(RelayError::NotFound);
    }
    match &session.response {
        Some(data) => Ok((StatusCode::OK, data.clone())),
        None => Err(RelayError::NotFound),
    }
}

/// GET /pair/{account_fp} — new device fetches the offer.
pub async fn get_offer(
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
) -> Result<impl IntoResponse> {
    let account_fp = decode_account_fp(&account_fp_hex)?;

    let map = state.pairing.read().await;
    let session = map.get(&account_fp).ok_or(RelayError::NotFound)?;
    if Instant::now() >= session.expires_at {
        return Err(RelayError::NotFound);
    }
    Ok((StatusCode::OK, session.offer.clone()))
}

/// PUT /pair/{account_fp}/provision — device A posts encrypted provision blob after pairing.
pub async fn put_provision(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
    body: Bytes,
) -> Result<StatusCode> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    if auth.account_fp != account_fp {
        return Err(RelayError::Unauthorized("account mismatch".into()));
    }

    if body.is_empty() {
        return Err(RelayError::BadRequest("empty payload".into()));
    }
    if body.len() > MAX_PROVISION_PAYLOAD {
        return Err(RelayError::PayloadTooLarge);
    }

    let mut map = state.provision.write().await;
    map.insert(
        account_fp,
        ProvisionEntry {
            data: body.to_vec(),
            expires_at: Instant::now() + PAIRING_TTL,
        },
    );
    Ok(StatusCode::CREATED)
}

/// GET /pair/{account_fp}/provision — device B fetches provision blob.
pub async fn get_provision(
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
) -> Result<impl IntoResponse> {
    let account_fp = decode_account_fp(&account_fp_hex)?;

    let map = state.provision.read().await;
    let entry = map.get(&account_fp).ok_or(RelayError::NotFound)?;
    if Instant::now() >= entry.expires_at {
        return Err(RelayError::NotFound);
    }
    Ok((StatusCode::OK, entry.data.clone()))
}

/// Reap expired pairing sessions and provision entries.
pub async fn reap_expired(state: &AppState) {
    let now = Instant::now();
    {
        let mut map = state.pairing.write().await;
        map.retain(|_, session| session.expires_at > now);
    }
    {
        let mut map = state.provision.write().await;
        map.retain(|_, entry| entry.expires_at > now);
    }
}
