use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use ghost_wire::anchor::{encode_sequence, ImportRequest};

use crate::auth::DeviceAuth;
use crate::error::{RelayError, Result};
use crate::state::AppState;

use super::decode_account_fp;
use super::idlog::AccountInfo;

/// GET /accounts/{account_fp_hex} — where this relay believes the account is homed.
pub async fn get(
    _auth: DeviceAuth,
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
) -> Result<Json<AccountInfo>> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    let row = state.storage.get_account(&account_fp)?.ok_or(RelayError::NotFound)?;
    Ok(Json(AccountInfo::from_row(&row)))
}

/// Longest chain an import may carry.
const MAX_IMPORT_ENTRIES: usize = 1024;

/// POST /accounts/{account_fp_hex}/import — become the account's home.
///
/// Authenticated by the request itself: the prefix carries its previous home's
/// anchors and the new `SetHomeRelay` must be signed by the master key or an
/// active device, so no credentials are needed and a device whose home is gone
/// can still move. Answers with the anchors for the newly sequenced entries.
pub async fn import(
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
    body: Bytes,
) -> Result<(StatusCode, Vec<u8>)> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    let request = ImportRequest::from_bytes(&body)
        .map_err(|e| RelayError::BadRequest(format!("invalid import: {e}")))?;
    if request.prefix.len() > MAX_IMPORT_ENTRIES {
        return Err(RelayError::PayloadTooLarge);
    }
    if !state.idlog_import_limiter.check(&account_fp) {
        return Err(RelayError::RateLimited);
    }

    let appended = state.storage.import_account(&account_fp, &request.prefix, &request.new_entries)?;
    let mut anchors = Vec::with_capacity(request.new_entries.len());
    for entry in &request.new_entries {
        anchors.push(state.kt_append_and_sign(entry).await?);
    }
    state.apply_revocations(&account_fp, &appended).await;
    Ok((StatusCode::CREATED, encode_sequence(&anchors)))
}

/// Most relays one account may grant; far beyond any realistic server count.
const MAX_MIRROR_GRANTS: usize = 256;

/// PUT /accounts/{account_fp_hex}/mirrors — the relays allowed to pull this
/// account's identity log from here, as concatenated 32-byte keys. Replaces the set.
pub async fn put_mirrors(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
    body: Bytes,
) -> Result<StatusCode> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    if auth.account_fp != account_fp {
        return Err(RelayError::Forbidden("account mismatch".into()));
    }
    if !body.len().is_multiple_of(32) {
        return Err(RelayError::BadRequest("body must be whole 32-byte relay keys".into()));
    }
    if body.len() / 32 > MAX_MIRROR_GRANTS {
        return Err(RelayError::PayloadTooLarge);
    }
    let relays: Vec<[u8; 32]> = body.chunks_exact(32).map(|c| c.try_into().unwrap()).collect();
    state.storage.set_mirror_grants(&account_fp, &relays)?;
    Ok(StatusCode::NO_CONTENT)
}
