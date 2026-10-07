//! Fetching and validating identity logs from a relay.

use ghost_wire::idlog::LogState;
use ghost_wire::merkle::{verify_extension, ConsistencyProof};

use crate::error::{GhostError, Result};
use crate::idlog_cache::validate_anchored_chain;
use crate::relay::{AnchoredLog, RelayClient};

use super::{SharedClient, SharedRelay};

/// Fetch an account's full anchored log and validate the chain and every anchor,
/// without touching local state. For devices that have no identity yet (pairing,
/// recovery); established clients use [`fetch_and_verify`].
pub async fn fetch_chain(relay: &RelayClient, account_fp: &[u8; 32]) -> Result<(AnchoredLog, LogState)> {
    let log = relay.get_idlog(account_fp, 0).await?;
    let state = validate_anchored_chain(*account_fp, &log.entries, Some(&log.home_relay_vk))?;
    Ok((log, state))
}

/// Fetch an account's anchored log, validate it, and cache it. When the
/// connected relay is the account's home, also check that the home's current
/// KT head contains the newest entry and extends the last head this client
/// accepted from it, which is what exposes a home showing clients different logs.
pub async fn fetch_and_verify(
    client: &SharedClient,
    relay: &SharedRelay,
    account_fp: &[u8; 32],
) -> Result<LogState> {
    let (log, info) = {
        let r = relay.lock().await;
        (r.get_idlog(account_fp, 0).await?, r.get_relay_info().await?)
    };
    let state = validate_anchored_chain(*account_fp, &log.entries, Some(&log.home_relay_vk))?;

    // Only the home can prove its current tree; a mirror serves anchors verbatim.
    let home = state.home_relay_vk.unwrap_or(log.home_relay_vk);
    if info.relay_vk == home {
        verify_home_head(client, relay, &log, info.kt_head).await?;
    }

    let mut c = client.lock().await;
    c.cache_anchored_log(account_fp, &log)
}

/// Bind the log to the home's current KT head. Checking the newest entry is
/// enough: each entry's `prev_hash` commits to every entry before it.
async fn verify_home_head(
    client: &SharedClient,
    relay: &SharedRelay,
    log: &AnchoredLog,
    kt_head: Option<ghost_wire::merkle::Checkpoint>,
) -> Result<()> {
    let Some(newest) = log.entries.last() else { return Ok(()) };
    let home = log.home_relay_vk;
    let head = kt_head
        .ok_or_else(|| GhostError::IdentityLog("home relay has entries but no KT head".into()))?;

    let prior = {
        let c = client.lock().await;
        c.kt_head(&home)?
    };
    let entry_proof = fetch_proof_if_grown(relay, newest.checkpoint.tree_size, head.tree_size).await?;
    let prior_proof = match &prior {
        Some(p) => fetch_proof_if_grown(relay, p.tree_size, head.tree_size).await?,
        None => None,
    };

    verify_extension(&newest.checkpoint, &head, entry_proof.as_ref()).map_err(|e| {
        GhostError::IdentityLog(format!("newest entry is not in the home's current tree: {e}"))
    })?;
    let mut c = client.lock().await;
    c.accept_kt_head(&home, &head, prior_proof.as_ref())
}

async fn fetch_proof_if_grown(relay: &SharedRelay, from: u64, to: u64) -> Result<Option<ConsistencyProof>> {
    if from == 0 || to <= from {
        return Ok(None);
    }
    let bytes = {
        let r = relay.lock().await;
        r.get_consistency_proof(from, to).await?
    };
    ConsistencyProof::from_bytes(&bytes)
        .map(Some)
        .map_err(|e| GhostError::IdentityLog(format!("bad consistency proof: {e}")))
}

/// Warm the identity-log cache for a member. Failures are logged, not returned,
/// because credential validation is self-contained and the cache only serves gossip.
pub async fn cache_member(client: &SharedClient, relay: &SharedRelay, account_fp: &[u8; 32]) {
    if let Err(e) = fetch_and_verify(client, relay, account_fp).await {
        eprintln!("cache idlog for {}: {e}", hex::encode(&account_fp[..8]));
    }
}

/// Fetch and verify the caller's own identity log, re-pushing the stored genesis
/// entry first if the relay has lost it (relay database reset).
pub async fn fetch_own_log_or_republish(
    client: &SharedClient,
    relay: &SharedRelay,
    account_fp: &[u8; 32],
    genesis_entry: Option<&[u8]>,
) -> Result<LogState> {
    match fetch_and_verify(client, relay, account_fp).await {
        Ok(state) => Ok(state),
        Err(first_err) => {
            let Some(genesis) = genesis_entry else { return Err(first_err) };
            {
                let r = relay.lock().await;
                r.put_idlog_entry(account_fp, genesis.to_vec()).await?;
            }
            fetch_and_verify(client, relay, account_fp).await
        }
    }
}
