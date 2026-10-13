//! Fetching and validating identity logs from a relay. An established client fetches
//! from the head it already holds, so a log that has not changed costs one small
//! request; a log that no longer continues from that head is fetched whole and the
//! fork rule decides.

use ghost_wire::idlog::{entry_hash, EntryBody, LogState};
use ghost_wire::merkle::{verify_extension, Checkpoint, ConsistencyProof};
use ghost_wire::short_id;

use crate::error::{GhostError, Result};
use crate::idlog_cache::validate_anchored_chain;
use crate::relay::{AnchoredLog, RelayClient};

use super::{SharedClient};

/// Fetch an account's full anchored log and validate the chain and every anchor,
/// without touching local state. For devices that have no identity yet (pairing,
/// recovery); established clients use [`fetch_and_verify`].
pub async fn fetch_chain(relay: &RelayClient, account_fp: &[u8; 32]) -> Result<(AnchoredLog, LogState)> {
    let log = relay.get_idlog(account_fp, 0).await?;
    let state = validate_anchored_chain(*account_fp, &log.entries, Some(&log.home_relay_vk))?;
    Ok((log, state))
}

/// Fetch what the relay holds past the cached head, or the whole log when the relay's
/// chain no longer continues from that head. Asking from the entry before the head and
/// getting the head back unchanged shows the relay only extended the chain.
async fn fetch_from_head(relay: &RelayClient, account_fp: &[u8; 32], cached_head: Option<(u64, [u8; 32])>) -> Result<AnchoredLog> {
    let Some((head_seq, head_hash)) = cached_head else {
        return relay.get_idlog(account_fp, 0).await;
    };
    let log = relay.get_idlog(account_fp, head_seq.saturating_sub(1)).await?;
    let continues = log.entries.first().is_some_and(|a| a.entry.seq == head_seq && entry_hash(&a.entry) == head_hash);
    if continues {
        Ok(log)
    } else {
        relay.get_idlog(account_fp, 0).await
    }
}

/// Fetch an account's anchored log past what is cached, validate it, and cache it.
/// When the serving relay is the account's home, also check that the home's current
/// KT head contains the newest entry and extends the last head this client accepted
/// from it, which is what exposes a home showing clients different logs.
pub async fn fetch_and_verify(
    client: &SharedClient,
    relay: &RelayClient,
    account_fp: &[u8; 32],
) -> Result<LogState> {
    let cached_head = client.lock().await.cached_head(account_fp);
    let log = fetch_from_head(relay, account_fp, cached_head).await?;

    // Only the home can prove its current tree; a mirror serves anchors verbatim. The
    // home is the newest entry naming one, else the one this client already holds, else
    // the serving relay's word.
    let named_home = log.entries.iter().rev().find_map(|a| match &a.entry.body {
        EntryBody::SetHomeRelay { relay_vk, .. } => Some(*relay_vk),
        _ => None,
    });
    let home = match named_home {
        Some(relay_vk) => relay_vk,
        None => client.lock().await.cached_home_relay(account_fp).unwrap_or(log.home_relay_vk),
    };
    if log.relay_vk == home {
        verify_home_head(client, relay, account_fp, &log).await?;
    }

    let mut c = client.lock().await;
    c.cache_anchored_log(account_fp, &log)
}

/// Bind the log to the home's current KT head. Checking the newest entry is enough:
/// each entry's `prev_hash` commits to every entry before it. The newest entry is the
/// last fetched, or the last cached when the fetch brought nothing new.
async fn verify_home_head(client: &SharedClient, relay: &RelayClient, account_fp: &[u8; 32], log: &AnchoredLog) -> Result<()> {
    let newest: Checkpoint = match log.entries.last() {
        Some(anchored) => anchored.checkpoint.clone(),
        None => {
            let c = client.lock().await;
            match c.store().get_cached_anchored_entries(account_fp)?.last() {
                Some(anchored) => anchored.checkpoint.clone(),
                None => return Ok(()),
            }
        }
    };
    let home = log.home_relay_vk;
    let head = log
        .kt_head
        .clone()
        .ok_or_else(|| GhostError::IdentityLog("home relay has entries but no KT head".into()))?;

    let prior = {
        let c = client.lock().await;
        c.kt_head(&home)?
    };
    let entry_proof = fetch_proof_if_grown(relay, newest.tree_size, head.tree_size).await?;
    let prior_proof = match &prior {
        Some(p) => fetch_proof_if_grown(relay, p.tree_size, head.tree_size).await?,
        None => None,
    };

    verify_extension(&newest, &head, entry_proof.as_ref()).map_err(|e| {
        GhostError::IdentityLog(format!("newest entry is not in the home's current tree: {e}"))
    })?;
    let c = client.lock().await;
    c.accept_kt_head(&home, &head, prior_proof.as_ref())
}

async fn fetch_proof_if_grown(relay: &RelayClient, from: u64, to: u64) -> Result<Option<ConsistencyProof>> {
    if from == 0 || to <= from {
        return Ok(None);
    }
    let bytes = relay.get_consistency_proof(from, to).await?;
    ConsistencyProof::from_bytes(&bytes)
        .map(Some)
        .map_err(|e| GhostError::IdentityLog(format!("bad consistency proof: {e}")))
}

/// Refresh a member's identity log from the relay hosting `server_id`, where every
/// member of it is registered. Returns whether the log was fetched and cached; a
/// failure is logged, and the caller then refuses a device the log still does not list.
pub async fn refresh_member(client: &SharedClient, home: &RelayClient, server_id: &[u8; 32], account_fp: &[u8; 32]) -> bool {
    let (hosting, cached_head) = {
        let c = client.lock().await;
        (super::server_relay_url(&c, server_id), c.cached_head(account_fp))
    };
    let fetched = match hosting {
        Some(url) => {
            tracing::debug!("refresh idlog for {}: fetching from the server's relay {url}", short_id(account_fp));
            fetch_from_head(&home.at(&url), account_fp, cached_head).await
        }
        None => {
            tracing::debug!("refresh idlog for {}: fetching from the home {}", short_id(account_fp), home.base_url());
            fetch_from_head(home, account_fp, cached_head).await
        }
    };
    let cached = match fetched {
        Ok(log) => client.lock().await.cache_anchored_log(account_fp, &log).map(|_| ()),
        Err(e) => Err(e),
    };
    match cached {
        Ok(()) => {
            tracing::debug!("refresh idlog for {}: fetched and cached", short_id(account_fp));
            true
        }
        Err(e) => {
            tracing::warn!("refresh idlog for {}: {e}", short_id(account_fp));
            false
        }
    }
}
