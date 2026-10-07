//! Mirror refresh: pull new identity log entries for every account this relay
//! mirrors from that account's home relay. Devices also push new entries to
//! mirrors directly; the pull covers devices that were offline or failed to.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ghost_wire::anchor::AnchoredEntry;
use ghost_wire::relay_ref::RelayRef;
use serde::Deserialize;

use crate::constants::MIRROR_FETCH_TIMEOUT_SECS;
use crate::error::RelayError;
use crate::state::AppState;
use crate::storage::AccountRow;

#[derive(Deserialize)]
struct IdLogPage {
    entries: Vec<IdLogPageEntry>,
}

#[derive(Deserialize)]
struct IdLogPageEntry {
    anchored: String,
}

pub async fn run(state: AppState) {
    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(MIRROR_FETCH_TIMEOUT_SECS))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("mirror refresh disabled: http client: {e}");
            return;
        }
    };
    let mut interval = tokio::time::interval(Duration::from_secs(state.config.mirror_refresh_secs.max(1)));
    loop {
        interval.tick().await;
        let accounts = match state.storage.mirrored_accounts() {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("mirror refresh: listing accounts failed: {e}");
                continue;
            }
        };
        for account in accounts {
            if let Err(e) = refresh_account(&state, &http, &account).await {
                tracing::debug!("mirror refresh {}: {e}", hex::encode(&account.account_fp[..8]));
            }
        }
    }
}

/// Fetch entries after the mirrored head from the account's home and apply them.
/// Everything fetched is validated exactly like a device push, so a home that
/// serves bad data changes nothing here.
pub async fn refresh_account(state: &AppState, http: &reqwest::Client, account: &AccountRow) -> Result<usize, RelayError> {
    let home_ref = RelayRef::from_bytes(&account.home_relay_ref)
        .map_err(|e| RelayError::Storage(format!("stored home ref: {e}")))?;
    let Some(base) = home_ref.primary_https_url() else {
        return Ok(0);
    };
    let path = format!("/idlog/{}", hex::encode(account.account_fp));
    let url = format!("{base}{path}?after_seq={}", account.head_seq);
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(&state.relay_sk_bytes)
        .map_err(|e| RelayError::Storage(format!("relay key: {e}")))?;
    let resp = http
        .get(&url)
        .header(ghost_wire::auth::RELAY_AUTH_HEADER, ghost_wire::auth::sign_relay_auth("GET", &path, &signing_key))
        .send()
        .await
        .map_err(|e| RelayError::BadRequest(format!("fetch from home: {e}")))?;
    if !resp.status().is_success() {
        return Err(RelayError::BadRequest(format!("home answered {}", resp.status())));
    }
    let page: IdLogPage = resp
        .json()
        .await
        .map_err(|e| RelayError::BadRequest(format!("home response: {e}")))?;
    if page.entries.is_empty() {
        return Ok(0);
    }

    let mut entries = Vec::with_capacity(page.entries.len());
    for e in page.entries {
        let bytes = B64
            .decode(&e.anchored)
            .map_err(|e| RelayError::BadRequest(format!("home response base64: {e}")))?;
        entries.push(
            AnchoredEntry::from_bytes(&bytes)
                .map_err(|e| RelayError::BadRequest(format!("home response entry: {e}")))?,
        );
    }
    let appended = state.storage.append_anchored_entries(&account.account_fp, &entries)?;
    state.apply_revocations(&account.account_fp, &appended).await;
    Ok(appended.len())
}
