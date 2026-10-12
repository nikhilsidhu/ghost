use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ghost_wire::account_key::AccountKeySet;
use ghost_wire::anchor::{decode_sequence, encode_sequence, AnchoredEntry};
use ghost_wire::batch::LogBatch;
use ghost_wire::idlog::{EntryType, LogEntry};
use serde::{Deserialize, Serialize};

use crate::auth::{admit, missing_signature, ClientIp, SignedBy};
use crate::error::{RelayError, Result};
use crate::state::AppState;
use crate::util::now_millis;

use super::decode_account_fp;

const MAX_IDLOG_ENTRY_SIZE: usize = 4096;
/// A pushed chain is bounded by entry count, not bytes, so long-lived accounts fit.
const MAX_ANCHORED_BATCH: usize = 1024;

/// PUT /idlog/{account_fp_hex} — home path for one raw entry, as clients from
/// before batches send it. Refused once the account's root has rotated: every
/// change after that travels with the account key it needs, as a batch.
pub async fn put(
    State(state): State<AppState>,
    signed: Option<SignedBy>,
    ClientIp(ip): ClientIp,
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
    if state.storage.account_state(account_fp).await?.is_some_and(|s| s.root_rotated()) {
        return Err(RelayError::Gone("this account appends in batches".into()));
    }

    let anchors = append(&state, signed, ip, account_fp, vec![entry], Vec::new()).await?;
    Ok((StatusCode::CREATED, anchors[0].to_bytes()))
}

/// POST /idlog/{account_fp_hex}/batch — home path: sequence entries that land
/// together or not at all, with the key sets their account key entries commit to.
pub async fn post_batch(
    State(state): State<AppState>,
    signed: Option<SignedBy>,
    ClientIp(ip): ClientIp,
    Path(account_fp_hex): Path<String>,
    body: Bytes,
) -> Result<(StatusCode, Vec<u8>)> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    let batch = LogBatch::from_bytes(&body).map_err(|e| RelayError::BadRequest(e.to_string()))?;
    let anchors = append(&state, signed, ip, account_fp, batch.entries, batch.key_sets).await?;
    Ok((StatusCode::CREATED, encode_sequence(&anchors)))
}

/// Authenticate, rate-limit, store and anchor entries on the home path.
///
/// Entries opening with a genesis or a recovery authenticate themselves: the
/// validator checks the genesis or root signature, and the submitting device has no
/// active key yet (none before genesis, all revoked by the recovery), so whatever
/// signature the request carries is not judged; those count against the address they
/// come from. Everything else needs a signature from an active device of the account.
/// Account rate limits count only entries that validate, so junk cannot spend the
/// owner's recovery attempts.
async fn append(
    state: &AppState,
    signed: Option<SignedBy>,
    ip: std::net::IpAddr,
    account_fp: [u8; 32],
    entries: Vec<LogEntry>,
    key_sets: Vec<AccountKeySet>,
) -> Result<Vec<AnchoredEntry>> {
    let first = entries.first().ok_or_else(|| RelayError::BadRequest("empty batch".into()))?;
    let self_authenticating = matches!(first.entry_type, EntryType::Genesis | EntryType::Recovery);
    if self_authenticating {
        state.ip_limits.check_unauthenticated(ip)?;
    } else {
        let auth = admit(state, signed.ok_or_else(missing_signature)?).await?;
        if auth.account_fp != account_fp {
            return Err(RelayError::Forbidden("account mismatch".into()));
        }
    }

    let recovers = entries.iter().any(|e| e.entry_type == EntryType::Recovery);
    let limiter = if recovers { &state.idlog_recovery_limiter } else { &state.idlog_batch_limiter };
    if !limiter.allows(&account_fp) {
        return Err(limiter.refusal(&account_fp));
    }
    let (change, anchors) = state.sequence_entries(account_fp, entries, key_sets).await?;
    limiter.record(&account_fp);
    state.apply_log_change(&account_fp, &change).await;
    Ok(anchors)
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
    ClientIp(ip): ClientIp,
    Path(account_fp_hex): Path<String>,
    Query(query): Query<AnchoredQuery>,
    body: Bytes,
) -> Result<(StatusCode, Json<AccountInfo>)> {
    state.ip_limits.check_unauthenticated(ip)?;
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
    let known = state.storage.get_account(account_fp).await?.is_some();
    let listed = !known && state.storage.is_listed_member(account_fp).await?;
    let mut guest_until = None;
    if !known && !listed {
        let token = query.invite.ok_or_else(|| {
            RelayError::Forbidden("unknown account; an invite token is required".into())
        })?;
        let invite = state.storage.invite_get(token).await?.ok_or(RelayError::NotFound)?;
        if invite.expires_at <= now_millis() {
            return Err(RelayError::Gone("invite expired".into()));
        }
        guest_until = Some(invite.expires_at);
    }
    if !state.idlog_anchored_limiter.allows(&account_fp) {
        return Err(state.idlog_anchored_limiter.refusal(&account_fp));
    }

    let change = state.storage.append_anchored_entries(account_fp, entries).await?;
    state.idlog_anchored_limiter.record(&account_fp);
    // Whoever pushes the log here means this relay to hold it, so its home grants it now.
    state.storage.clear_pull_refusals(account_fp).await?;
    if let Some(until) = guest_until {
        state.storage.set_account_guest_until(account_fp, until).await?;
    }
    state.apply_log_change(&account_fp, &change).await;

    let account = state
        .storage
        .get_account(account_fp)
        .await?
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
    /// The relay answering, so the reader knows whether it is reading from the home.
    pub relay_vk: String,
    /// This relay's latest signed KT checkpoint (base64), which proves the newest entry
    /// when this relay is the home; absent before the first entry.
    pub kt_head: Option<String>,
    pub entries: Vec<IdLogAnchoredEntry>,
}

#[derive(Serialize)]
pub struct IdLogAnchoredEntry {
    pub seq: u64,
    /// base64 of an `AnchoredEntry`
    pub anchored: String,
}

/// Which devices may read an account's data besides its root and granted relays.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum DeviceReaders {
    /// Any device this relay admits, as members check each other's logs, and the
    /// account's own devices.
    Admitted,
    /// Only the account's own active devices: its key sets are for nobody else.
    OwnAccount,
}

/// Who may read an account's log or key sets: the devices `readers` names; the
/// account's current root, for a device recovering with no active key yet; or a
/// relay the account granted, pulling to keep its mirror fresh. `signed` is the
/// verified device signature on the request, if it carried one.
pub(super) async fn authorize_read(
    state: &AppState,
    signed: Option<SignedBy>,
    headers: &axum::http::HeaderMap,
    path: &str,
    account_fp: &[u8; 32],
    readers: DeviceReaders,
) -> Result<()> {
    if signed.is_some_and(|s| state.config.revoked_devices_for_tests.read().unwrap().contains(&s.signer_vk)) {
        return Err(RelayError::DeviceRevoked(None));
    }
    if let Some(value) = headers.get(ghost_wire::auth::RELAY_AUTH_HEADER) {
        let value = value.to_str().map_err(|_| RelayError::Unauthorized("invalid relay auth".into()))?;
        let relay_vk = ghost_wire::auth::verify_relay_auth(value, "GET", path, now_millis() / 1000)
            .map_err(|e| RelayError::Unauthorized(e.into()))?;
        if !state.storage.is_mirror_granted(*account_fp, relay_vk, now_millis()).await? {
            return Err(RelayError::Forbidden("this account has not granted that relay".into()));
        }
        return Ok(());
    }
    let signed = signed.ok_or_else(missing_signature)?;
    let own_active = signed.account_fp == *account_fp && state.storage.is_active_device(*account_fp, signed.signer_vk).await?;
    let device_may_read = match readers {
        // An account's own devices read it on any relay that holds it: a former home is
        // where a device that missed the move learns of it.
        DeviceReaders::Admitted => own_active || state.storage.may_authenticate(signed.account_fp, signed.signer_vk, now_millis()).await?.is_some(),
        DeviceReaders::OwnAccount => own_active,
    };
    if device_may_read {
        return Ok(());
    }
    let is_current_root = signed.account_fp == *account_fp
        && state
            .storage
            .account_state(*account_fp)
            .await?
            .and_then(|s| s.root_verifying_key)
            == Some(signed.signer_vk);
    if is_current_root {
        return Ok(());
    }
    if state.storage.is_revoked_device(signed.account_fp, signed.signer_vk).await? {
        return Err(crate::auth::revoked(state, signed.account_fp, signed.signer_vk).await);
    }
    Err(RelayError::Unauthorized("unknown or unregistered device".into()))
}

/// GET /idlog/{account_fp_hex}?after_seq=N — anchored identity log entries.
pub async fn get(
    State(state): State<AppState>,
    signed: Option<SignedBy>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
    Path(account_fp_hex): Path<String>,
    Query(query): Query<IdLogQuery>,
) -> Result<Json<IdLogResponse>> {
    let account_fp = decode_account_fp(&account_fp_hex)?;
    authorize_read(&state, signed, &headers, uri.path(), &account_fp, DeviceReaders::Admitted).await?;
    let after_seq = query.after_seq.unwrap_or(0);
    let rows = state.storage.get_idlog(account_fp, after_seq).await?;
    let home_relay_vk = state
        .storage
        .get_account(account_fp)
        .await?
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
                let regenerated: Option<AnchoredEntry> = state.regenerate_anchor(entry).await?;
                regenerated
                    .ok_or_else(|| RelayError::Storage(format!("entry {} has no anchor", row.seq)))?
                    .to_bytes()
            }
        };
        entries.push(IdLogAnchoredEntry { seq: row.seq, anchored: B64.encode(anchored) });
    }

    let kt_head = state.storage.kt_load_checkpoint().await?.map(|cp| B64.encode(cp));
    Ok(Json(IdLogResponse { home_relay_vk: hex::encode(home_relay_vk), relay_vk: hex::encode(state.relay_vk), kt_head, entries }))
}
