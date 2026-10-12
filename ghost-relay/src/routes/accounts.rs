use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use ghost_wire::account_key::{decode_key_sets, encode_key_sets};
use ghost_wire::anchor::{encode_sequence, ImportRequest};
use ghost_wire::relay_ref::decode_refs;
use ghost_wire::server_location::ServerLocation;
use serde::{Deserialize, Serialize};

use crate::auth::{ClientIp, DeviceAuth, SignedBy};
use crate::error::{RelayError, Result};
use crate::state::AppState;
use crate::util::now_millis;

use super::{decode_account_fp, decode_id32};
use super::idlog::{authorize_read, AccountInfo, DeviceReaders};

/// GET /accounts/{account_fp_hex} — where this relay believes the account is homed.
pub async fn get(
    _auth: DeviceAuth,
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
) -> Result<Json<AccountInfo>> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    let row = state.storage.get_account(account_fp).await?.ok_or(RelayError::NotFound)?;
    Ok(Json(AccountInfo::from_row(&row)))
}

/// Longest chain an import may carry.
const MAX_IMPORT_ENTRIES: usize = 1024;

/// POST /accounts/{account_fp_hex}/import — become the account's home.
///
/// Authenticated by the request itself: the prefix carries its previous home's
/// anchors and the new `SetHomeRelay` must be signed by the root (or, before the
/// root rotates, an active device), so no credentials are needed and a device whose
/// home is gone can still move. Answers with the anchors for the newly sequenced
/// entries. The account rate limit counts only imports that validate; the address
/// limit counts every attempt.
pub async fn import(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(account_fp_hex): Path<String>,
    body: Bytes,
) -> Result<(StatusCode, Vec<u8>)> {
    state.ip_limits.check_unauthenticated(ip)?;
    let account_fp = decode_account_fp(&account_fp_hex)?;
    let request = ImportRequest::from_bytes(&body)
        .map_err(|e| RelayError::BadRequest(format!("invalid import: {e}")))?;
    if request.prefix.len() > MAX_IMPORT_ENTRIES {
        return Err(RelayError::PayloadTooLarge);
    }
    if !state.idlog_import_limiter.allows(&account_fp) {
        return Err(state.idlog_import_limiter.refusal(&account_fp));
    }

    let (change, anchors) = state.import_account(account_fp, request.prefix, request.new_entries, request.key_sets).await?;
    state.idlog_import_limiter.record(&account_fp);
    state.apply_log_change(&account_fp, &change).await;
    Ok((StatusCode::CREATED, encode_sequence(&anchors)))
}

#[derive(Serialize)]
pub struct RootLookup {
    pub account_fp: String,
    pub home_relay_vk: String,
}

/// GET /accounts/by_root — the account whose current root signed this request, for
/// a recovering device that knows only its recovery key.
pub async fn by_root(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
) -> Result<Json<RootLookup>> {
    state.ip_limits.check_unauthenticated(ip)?;
    let value = headers
        .get(ghost_wire::auth::ROOT_AUTH_HEADER)
        .ok_or_else(|| RelayError::Unauthorized("a root signature is required".into()))?
        .to_str()
        .map_err(|_| RelayError::Unauthorized("invalid root auth".into()))?;
    let root_vk = ghost_wire::auth::verify_root_auth(value, "GET", uri.path(), now_millis() / 1000)
        .map_err(|e| RelayError::Unauthorized(e.into()))?;
    let account = state.storage.account_by_root(root_vk).await?.ok_or(RelayError::NotFound)?;
    Ok(Json(RootLookup {
        account_fp: hex::encode(account.account_fp),
        home_relay_vk: hex::encode(account.home_relay_vk),
    }))
}

#[derive(Deserialize)]
pub struct KeySetQuery {
    from_generation: Option<u32>,
}

/// GET /accounts/{account_fp_hex}/key_sets?from_generation= — the account key sets
/// of the held chain, oldest first. Readers: the account's own devices, its root,
/// and relays it granted.
pub async fn get_key_sets(
    State(state): State<AppState>,
    signed: Option<SignedBy>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
    Path(account_fp_hex): Path<String>,
    Query(query): Query<KeySetQuery>,
) -> Result<(StatusCode, Vec<u8>)> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    authorize_read(&state, signed, &headers, uri.path(), &account_fp, DeviceReaders::OwnAccount).await?;
    let sets = state.storage.get_key_sets(account_fp, query.from_generation.unwrap_or(1)).await?;
    Ok((StatusCode::OK, encode_key_sets(&sets)))
}

/// PUT /accounts/{account_fp_hex}/key_sets — mirror path. Each set must match an
/// account key entry this relay holds, which commits to it, so no credentials are
/// needed and nothing else can be stored.
pub async fn put_key_sets(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(account_fp_hex): Path<String>,
    body: Bytes,
) -> Result<StatusCode> {
    state.ip_limits.check_unauthenticated(ip)?;
    let account_fp = decode_account_fp(&account_fp_hex)?;
    let sets = decode_key_sets(&body).map_err(|e| RelayError::BadRequest(e.to_string()))?;
    state.storage.put_key_sets(account_fp, sets).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Most relays one account may grant; far beyond any realistic server count.
const MAX_MIRROR_GRANTS: usize = 256;

/// PUT /accounts/{account_fp_hex}/mirrors — relays allowed to pull this account's
/// identity log from here, and pushed to when it grows, as `RelayRef`s (`encode_refs`).
/// Adds to the grants or renews them: each device names the relays it knows, so one
/// that has not synced a server yet takes nothing from another's. A grant no device
/// renews within `MIRROR_GRANT_TTL_MS` lapses. Only the home keeps grants.
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
    auth.require_home()?;
    let relays = decode_refs(&body).map_err(|e| RelayError::BadRequest(format!("relay refs: {e}")))?;
    if relays.len() > MAX_MIRROR_GRANTS {
        return Err(RelayError::PayloadTooLarge);
    }
    state.storage.grant_mirrors(account_fp, relays, now_millis()).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Largest server location record accepted; a RelayRef is at most 512 bytes.
const MAX_SERVER_LOCATION_BYTES: usize = 1024;

/// PUT /accounts/{account_fp_hex}/servers/{server_id_hex}/location — where a server
/// this account created now lives, kept at the account's home. The record must be
/// signed by an active device of the account and must increase the stored generation.
pub async fn put_server_location(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path((account_fp_hex, server_id_hex)): Path<(String, String)>,
    body: Bytes,
) -> Result<StatusCode> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    let server_id = decode_id32(&server_id_hex, "server id")?;
    if auth.account_fp != account_fp {
        return Err(RelayError::Forbidden("account mismatch".into()));
    }
    auth.require_home()?;
    if body.len() > MAX_SERVER_LOCATION_BYTES {
        return Err(RelayError::PayloadTooLarge);
    }
    let location = ServerLocation::from_bytes(&body).map_err(|e| RelayError::BadRequest(e.to_string()))?;
    if location.server_id != server_id {
        return Err(RelayError::BadRequest("record names a different server".into()));
    }
    location.verify_signature().map_err(|e| RelayError::Unprocessable(e.to_string()))?;
    if !state.storage.is_active_device(account_fp, location.signer_vk).await? {
        return Err(RelayError::Unprocessable("record is not signed by an active device of this account".into()));
    }
    state.storage.put_server_location(account_fp, server_id, location.generation, body.to_vec()).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /accounts/{account_fp_hex}/servers/{server_id_hex}/location — unauthenticated,
/// because a server's members need not be known to its creator's home relay.
pub async fn get_server_location(
    State(state): State<AppState>,
    Path((account_fp_hex, server_id_hex)): Path<(String, String)>,
) -> Result<(StatusCode, Vec<u8>)> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    let server_id = decode_id32(&server_id_hex, "server id")?;
    let data = state.storage.get_server_location(account_fp, server_id).await?.ok_or(RelayError::NotFound)?;
    Ok((StatusCode::OK, data))
}
