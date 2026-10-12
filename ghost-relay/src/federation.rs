//! Keeping mirrors current. A home pushes each entry it sequences to the relays the
//! account granted; every mirror also pulls each mirrored account's log from its home
//! on a timer, for pushes that were missed (the home was down, or a device registered
//! the account at a mirror the home did not know of yet). Both talk to a bounded number
//! of relays at once, so one unreachable relay delays nothing else.

use ghost_wire::short_id;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::StreamExt;
use ghost_wire::account_key::{decode_key_sets, encode_key_sets, AccountKeySet};
use ghost_wire::anchor::{encode_sequence, AnchoredEntry};
use ghost_wire::idlog::entry_hash;
use ghost_wire::relay_ref::RelayRef;
use serde::Deserialize;

use crate::constants::FEDERATION_CONCURRENCY;
use crate::error::RelayError;
use crate::state::AppState;
use crate::storage::AccountRow;
use crate::util::now_millis;

#[derive(Deserialize)]
struct IdLogPage {
    entries: Vec<IdLogPageEntry>,
}

#[derive(Deserialize)]
struct IdLogPageEntry {
    anchored: String,
}

/// Pull every mirrored account's log from its home, forever.
pub async fn run(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(state.config.mirror_refresh_secs.max(1)));
    loop {
        interval.tick().await;
        let accounts = match state.storage.mirrored_accounts().await {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("mirror refresh: listing accounts failed: {e}");
                continue;
            }
        };
        let interval_ms = state.config.mirror_refresh_secs.max(1) * 1000;
        let now = now_millis();
        futures_util::stream::iter(accounts.into_iter().filter(|account| account.pull_due(now, interval_ms)))
            .for_each_concurrent(FEDERATION_CONCURRENCY, |account| {
                let state = state.clone();
                async move {
                    let fp = account.account_fp;
                    match refresh_account(&state, &account).await {
                        Ok(()) if account.pull_refusals > 0 => {
                            if let Err(e) = state.storage.clear_pull_refusals(fp).await {
                                tracing::warn!("mirror refresh {}: refusals not cleared: {e}", short_id(&fp));
                            }
                        }
                        Ok(()) => {}
                        Err(RelayError::Forbidden(e)) => {
                            tracing::debug!("mirror refresh {}: {e}; the next pull waits longer", short_id(&fp));
                            if let Err(e) = state.storage.record_pull_refusal(fp).await {
                                tracing::warn!("mirror refresh {}: refusal not recorded: {e}", short_id(&fp));
                            }
                        }
                        Err(e) => tracing::debug!("mirror refresh {}: {e}", short_id(&fp)),
                    }
                }
            })
            .await;
    }
}

/// Hand entries this relay just sequenced to the relays the account granted, which
/// hold the account already, followed by the key sets those entries commit to: a
/// mirror is then complete without the device's own copy, which a recovery through it
/// relies on. A mirror that is down catches up on its next pull.
pub fn push_to_mirrors(state: AppState, account_fp: [u8; 32], anchors: Vec<AnchoredEntry>, key_sets: &[AccountKeySet]) {
    let anchors_body = encode_sequence(&anchors);
    // A mirror stores a set only once it holds the entry committing to it.
    let sets_body = (!key_sets.is_empty()).then(|| encode_key_sets(key_sets));
    tokio::spawn(async move {
        let grants = match state.storage.mirror_grants(account_fp, now_millis()).await {
            Ok(grants) => grants,
            Err(e) => {
                tracing::warn!("mirror push: grants of {} not read: {e}", short_id(&account_fp));
                return;
            }
        };
        let anchors_path = format!("/idlog/{}/anchored", hex::encode(account_fp));
        let sets_path = format!("/accounts/{}/key_sets", hex::encode(account_fp));
        futures_util::stream::iter(grants.into_iter().filter(|grant| grant.relay_vk != state.relay_vk))
            .for_each_concurrent(FEDERATION_CONCURRENCY, |grant| {
                let (state, anchors_body, sets_body) = (state.clone(), anchors_body.clone(), sets_body.clone());
                let (anchors_path, sets_path) = (anchors_path.clone(), sets_path.clone());
                async move {
                    if let Err(e) = push_to(&state, &grant, &anchors_path, anchors_body).await {
                        tracing::debug!("mirror push to {}: {e}", short_id(&grant.relay_vk));
                        return;
                    }
                    if let Some(sets_body) = sets_body {
                        if let Err(e) = push_to(&state, &grant, &sets_path, sets_body).await {
                            tracing::debug!("mirror key set push to {}: {e}", short_id(&grant.relay_vk));
                        }
                    }
                }
            })
            .await;
    });
}

async fn push_to(state: &AppState, mirror: &RelayRef, path: &str, body: Vec<u8>) -> Result<(), RelayError> {
    let Some(base) = mirror.primary_https_url() else {
        return Err(RelayError::BadRequest("grant names no address".into()));
    };
    let resp = state
        .http
        .put(format!("{base}{path}"))
        .body(body)
        .send()
        .await
        .map_err(|e| RelayError::BadRequest(format!("push: {e}")))?;
    if !resp.status().is_success() {
        return Err(RelayError::BadRequest(format!("mirror answered {}", resp.status())));
    }
    Ok(())
}

/// Fetch the account's log from its home and apply it, then any key sets this relay
/// lacks. Everything fetched is validated exactly like a device push, so a home that
/// serves bad data changes nothing here.
pub async fn refresh_account(state: &AppState, account: &AccountRow) -> Result<(), RelayError> {
    let home_ref = RelayRef::from_bytes(&account.home_relay_ref)
        .map_err(|e| RelayError::Storage(format!("stored home ref: {e}")))?;
    let Some(base) = home_ref.primary_https_url() else {
        // A later push whose `SetHomeRelay` carries an address gives one to pull from.
        if state.unaddressed_homes.lock().unwrap().insert(account.account_fp) {
            tracing::info!("mirror refresh {}: its home names no address; this relay keeps up through pushes alone", short_id(&account.account_fp));
        }
        return Ok(());
    };
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(&state.relay_sk_bytes)
        .map_err(|e| RelayError::Storage(format!("relay key: {e}")))?;
    let fp = &account.account_fp;

    // Ask from the entry before our head. Getting our head back unchanged means the
    // home only extended the chain; anything else means the chains diverged, so
    // fetch the whole chain and let the fork rule decide.
    let mut entries = fetch_entries(state, base, fp, account.head_seq.saturating_sub(1), &signing_key).await?;
    let held_head = state.storage.entry_hash_at(*fp, account.head_seq).await?;
    let extends = entries
        .first()
        .is_some_and(|a| a.entry.seq == account.head_seq && Some(entry_hash(&a.entry)) == held_head);
    if !extends {
        entries = fetch_entries(state, base, fp, 0, &signing_key).await?;
    }
    if !entries.is_empty() {
        let change = state.storage.append_anchored_entries(*fp, entries).await?;
        state.apply_log_change(fp, &change).await;
    }

    if let Some(generation) = state.storage.first_missing_key_set(*fp).await? {
        let path = format!("/accounts/{}/key_sets", hex::encode(fp));
        let resp = get_signed(state, base, &path, &format!("from_generation={generation}"), &signing_key).await?;
        let body = resp.bytes().await.map_err(|e| RelayError::BadRequest(format!("home key sets: {e}")))?;
        let sets = decode_key_sets(&body).map_err(|e| RelayError::BadRequest(format!("home key sets: {e}")))?;
        state.storage.put_key_sets(*fp, sets).await?;
    }
    Ok(())
}

/// Anchored entries after `after_seq`, as the home serves them.
async fn fetch_entries(
    state: &AppState,
    base: &str,
    account_fp: &[u8; 32],
    after_seq: u64,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<Vec<AnchoredEntry>, RelayError> {
    let path = format!("/idlog/{}", hex::encode(account_fp));
    let resp = get_signed(state, base, &path, &format!("after_seq={after_seq}"), signing_key).await?;
    let page: IdLogPage = resp
        .json()
        .await
        .map_err(|e| RelayError::BadRequest(format!("home response: {e}")))?;
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
    Ok(entries)
}

/// A GET to the home signed as this relay, which the home serves to relays the
/// account granted.
async fn get_signed(
    state: &AppState,
    base: &str,
    path: &str,
    query: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<reqwest::Response, RelayError> {
    let resp = state
        .http
        .get(format!("{base}{path}?{query}"))
        .header(ghost_wire::auth::RELAY_AUTH_HEADER, ghost_wire::auth::sign_relay_auth("GET", path, signing_key))
        .send()
        .await
        .map_err(|e| RelayError::BadRequest(format!("fetch from home: {e}")))?;
    if resp.status() == reqwest::StatusCode::FORBIDDEN {
        return Err(RelayError::Forbidden(format!("home {base} refused this relay: the account has not granted it")));
    }
    if !resp.status().is_success() {
        return Err(RelayError::BadRequest(format!("home {base} answered {}", resp.status())));
    }
    Ok(resp)
}
