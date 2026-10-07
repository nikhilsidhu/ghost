use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ghost_wire::anchor::{decode_sequence, AnchoredEntry};
use ghost_wire::idlog::{EntryType, LogEntry};
use serde::{Deserialize, Serialize};

use crate::error::{RelayError, Result};
use crate::state::AppState;
use crate::util::now_millis;

use super::decode_account_fp;

const MAX_IDLOG_ENTRY_SIZE: usize = 4096;
/// A pushed chain is bounded by entry count, not bytes, so long-lived accounts fit.
const MAX_ANCHORED_BATCH: usize = 1024;

/// PUT /idlog/{account_fp_hex} — home path: sequence a raw entry from one of the
/// account's devices and answer with its anchor.
///
/// Genesis and Recovery entries are self-authenticating: the chain validator
/// checks their master-key signatures, and the submitting device has no active
/// key yet (none for genesis, all revoked by the entry itself for recovery).
/// Every other entry type requires DeviceAuth from an active device of the account.
pub async fn put(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    method: axum::http::Method,
    uri: axum::http::Uri,
    Path(account_fp_hex): Path<String>,
    body: Bytes,
) -> Result<(StatusCode, Vec<u8>)> {
    let account_fp = decode_account_fp(&account_fp_hex)?;

    if body.is_empty() {
        return Err(RelayError::BadRequest("empty payload".into()));
    }
    if body.len() > MAX_IDLOG_ENTRY_SIZE {
        return Err(RelayError::PayloadTooLarge);
    }
    let entry = LogEntry::from_bytes(&body)
        .map_err(|e| RelayError::BadRequest(format!("invalid entry: {e}")))?;

    let self_authenticating = matches!(entry.entry_type, EntryType::Genesis | EntryType::Recovery);
    if !self_authenticating {
        let auth = crate::auth::validate_auth_headers(&headers, method.as_str(), uri.path(), &state)?;
        if auth.account_fp != account_fp {
            return Err(RelayError::Forbidden("account mismatch".into()));
        }
    }

    if entry.entry_type == EntryType::Recovery && !state.idlog_recovery_limiter.check(&account_fp) {
        return Err(RelayError::RateLimited);
    }

    let appended = state.storage.append_idlog_entry(&account_fp, &body)?;
    let anchored = state.kt_append_and_sign(&entry).await?;
    state.apply_revocations(&account_fp, &[appended]).await;
    Ok((StatusCode::CREATED, anchored.to_bytes()))
}

#[derive(Deserialize)]
pub struct AnchoredQuery {
    /// Invite token that admits an account this relay has not seen before.
    invite: Option<String>,
}

/// PUT /idlog/{account_fp_hex}/anchored?invite= — mirror path: accept entries
/// another relay sequenced, each carrying that home's proof.
///
/// The batch authenticates itself: every entry is signed by an account key and
/// anchored by the home, so the sender needs no credentials. An unknown account
/// is admitted only with a valid invite for a server here (which also lets its
/// devices authenticate until the invite expires, so they can post their first
/// commits) or when a group here lists it as a member.
pub async fn put_anchored(
    State(state): State<AppState>,
    Path(account_fp_hex): Path<String>,
    Query(query): Query<AnchoredQuery>,
    body: Bytes,
) -> Result<(StatusCode, Json<AccountInfo>)> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    if body.is_empty() {
        return Err(RelayError::BadRequest("empty payload".into()));
    }
    let entries = decode_sequence(&body)
        .map_err(|e| RelayError::BadRequest(format!("invalid anchored entries: {e}")))?;
    if entries.len() > MAX_ANCHORED_BATCH {
        return Err(RelayError::PayloadTooLarge);
    }

    // Unknown accounts need an invite, unless a group here already lists them as
    // members (its creator moved the group here and uploaded its state).
    let known = state.storage.get_account(&account_fp)?.is_some();
    let listed = !known && state.storage.is_listed_member(&account_fp)?;
    let mut guest_until = None;
    if !known && !listed {
        let token = query.invite.ok_or_else(|| {
            RelayError::Forbidden("unknown account; an invite token is required".into())
        })?;
        let invites = state.invites.read().await;
        let invite = invites.get(&token).ok_or(RelayError::NotFound)?;
        if invite.expires_at <= now_millis() {
            return Err(RelayError::Gone("invite expired".into()));
        }
        guest_until = Some(invite.expires_at);
    }
    if !state.idlog_anchored_limiter.check(&account_fp) {
        return Err(RelayError::RateLimited);
    }

    let appended = state.storage.append_anchored_entries(&account_fp, &entries)?;
    if let Some(until) = guest_until {
        state.storage.set_account_guest_until(&account_fp, until)?;
    }
    state.apply_revocations(&account_fp, &appended).await;

    let account = state
        .storage
        .get_account(&account_fp)?
        .ok_or_else(|| RelayError::Storage("account missing after anchored append".into()))?;
    Ok((StatusCode::CREATED, Json(AccountInfo::from_row(&account))))
}

#[derive(Serialize)]
pub struct AccountInfo {
    pub home_relay_vk: String,
    pub head_seq: u64,
    pub is_home: bool,
}

impl AccountInfo {
    pub fn from_row(row: &crate::storage::AccountRow) -> Self {
        Self {
            home_relay_vk: hex::encode(row.home_relay_vk),
            head_seq: row.head_seq,
            is_home: row.is_home,
        }
    }
}

#[derive(Deserialize)]
pub struct IdLogQuery {
    after_seq: Option<u64>,
}

#[derive(Serialize)]
pub struct IdLogResponse {
    /// Relay that sequences this account's log; this relay's own key for
    /// accounts whose chain names no home.
    pub home_relay_vk: String,
    pub entries: Vec<IdLogAnchoredEntry>,
}

#[derive(Serialize)]
pub struct IdLogAnchoredEntry {
    pub seq: u64,
    /// base64 of an `AnchoredEntry`
    pub anchored: String,
}

/// Who may read an account's log, since it lists the account's devices: a device
/// this relay admits; the account's own master key, for a device recovering with no
/// active key yet; or a relay the account granted, pulling to keep its mirror fresh.
fn authorize_read(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    path: &str,
    account_fp: &[u8; 32],
) -> Result<()> {
    if let Some(value) = headers.get(ghost_wire::auth::RELAY_AUTH_HEADER) {
        let value = value.to_str().map_err(|_| RelayError::Unauthorized("invalid relay auth".into()))?;
        let relay_vk = ghost_wire::auth::verify_relay_auth(value, "GET", path, now_millis() / 1000)
            .map_err(|e| RelayError::Unauthorized(e.into()))?;
        if !state.storage.is_mirror_granted(account_fp, &relay_vk)? {
            return Err(RelayError::Forbidden("this account has not granted that relay".into()));
        }
        return Ok(());
    }
    let auth = crate::auth::verify_signed_headers(headers, "GET", path)?;
    if state.storage.may_authenticate(&auth.account_fp, &auth.device_vk, now_millis())? {
        return Ok(());
    }
    let is_own_master = auth.account_fp == *account_fp
        && state.storage.account_master_vk(account_fp)? == Some(auth.device_vk);
    if is_own_master {
        return Ok(());
    }
    Err(RelayError::Unauthorized("unknown, revoked, or unregistered device".into()))
}

/// GET /idlog/{account_fp_hex}?after_seq=N — anchored identity log entries.
pub async fn get(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
    Path(account_fp_hex): Path<String>,
    Query(query): Query<IdLogQuery>,
) -> Result<Json<IdLogResponse>> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    authorize_read(&state, &headers, uri.path(), &account_fp)?;
    let after_seq = query.after_seq.unwrap_or(0);
    let rows = state.storage.get_idlog(&account_fp, after_seq)?;
    let home_relay_vk = state
        .storage
        .get_account(&account_fp)?
        .map(|a| a.home_relay_vk)
        .unwrap_or(state.relay_vk);

    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let anchored = match (row.inclusion_proof, row.checkpoint) {
            (Some(proof), Some(checkpoint)) => {
                let mut bytes = Vec::with_capacity(6 + row.payload.len() + proof.len() + checkpoint.len());
                bytes.extend_from_slice(&(row.payload.len() as u32).to_be_bytes());
                bytes.extend_from_slice(&row.payload);
                bytes.extend_from_slice(&(proof.len() as u16).to_be_bytes());
                bytes.extend_from_slice(&proof);
                bytes.extend_from_slice(&checkpoint);
                bytes
            }
            _ => {
                let entry = LogEntry::from_bytes(&row.payload)
                    .map_err(|e| RelayError::Storage(format!("corrupt entry {}: {e}", row.seq)))?;
                let regenerated: Option<AnchoredEntry> = state.regenerate_anchor(&entry).await?;
                regenerated
                    .ok_or_else(|| RelayError::Storage(format!("entry {} has no anchor", row.seq)))?
                    .to_bytes()
            }
        };
        entries.push(IdLogAnchoredEntry { seq: row.seq, anchored: B64.encode(anchored) });
    }

    Ok(Json(IdLogResponse { home_relay_vk: hex::encode(home_relay_vk), entries }))
}
