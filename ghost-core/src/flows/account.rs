//! Keeping the account's identity log in the shape other relays require.

use ghost_wire::anchor::ImportRequest;

use crate::error::{GhostError, Result};
use crate::identity::log::create_set_home_relay;
use crate::idlog_cache::validate_anchored_chain;
use crate::relay::{RelayClient, RelayInfo};

use super::{idlog, now_millis, SharedClient, SharedRelay};

/// Make sure the account's log names its home relay and return that relay's key.
///
/// Other relays mirror only accounts whose chain names a home, so a new account
/// appends `SetHomeRelay` right after genesis, and an account created before
/// multi-relay support appends it the next time it starts. The entry is appended
/// at the connected relay, which must be the home; a mirror refuses it.
pub async fn ensure_home_relay(client: &SharedClient, relay: &SharedRelay) -> Result<[u8; 32]> {
    let account_fp = {
        let c = client.lock().await;
        *c.fingerprint()
    };
    let state = idlog::fetch_and_verify(client, relay, &account_fp).await?;
    if let Some(home) = state.home_relay_vk {
        return Ok(home);
    }

    let info = {
        let r = relay.lock().await;
        r.get_relay_info().await?
    };
    let entry = {
        let c = client.lock().await;
        create_set_home_relay(&state, &c.signing_key_clone(), info.relay_ref)
    };
    let appended = {
        let r = relay.lock().await;
        r.put_idlog_entry(&account_fp, entry.to_bytes()).await
    };

    // Another device may have appended it first; the refreshed chain decides.
    let refreshed = idlog::fetch_and_verify(client, relay, &account_fp).await?;
    match (refreshed.home_relay_vk, appended) {
        (Some(home), _) => Ok(home),
        (None, Err(e)) => Err(e),
        (None, Ok(_)) => Err(GhostError::IdentityLog("home relay entry was accepted but is not in the log".into())),
    }
}

/// Make this account known to `relay` so its devices can authenticate there, and
/// remember how to reach the relay. A foreign relay receives the account's full
/// anchored chain; `invite` must name a live invite on it the first time. The
/// home relay already holds the chain, so nothing is pushed there.
pub async fn register_at(client: &SharedClient, relay: &SharedRelay, invite: Option<&str>) -> Result<RelayInfo> {
    let info = {
        let r = relay.lock().await;
        r.get_relay_info().await?
    };
    let (account_fp, home, chain) = {
        let c = client.lock().await;
        let account_fp = *c.fingerprint();
        c.store().upsert_relay(&info.relay_ref, now_millis())?;
        let home = c.store().get_cached_idlog_state(&account_fp)?.and_then(|s| s.home_relay_vk);
        (account_fp, home, c.store().get_cached_anchored_entries(&account_fp)?)
    };
    let home = home.ok_or_else(|| {
        GhostError::IdentityLog("identity log names no home relay yet; connect to the home relay first".into())
    })?;
    if home == info.relay_vk {
        return Ok(info);
    }

    let r = relay.lock().await;
    let account = r.put_anchored_entries(&account_fp, &chain, invite).await?;
    if account.home_relay_vk != home {
        return Err(GhostError::IdentityLog("relay recorded a different home for this account".into()));
    }
    Ok(info)
}

/// Clients, signing as this device, for every relay other than `home_vk` that
/// hosts one of the account's servers. Relays without a reachable endpoint are skipped.
pub(crate) async fn member_relay_clients(client: &SharedClient, home: &SharedRelay, home_vk: &[u8; 32]) -> Result<Vec<([u8; 32], RelayClient)>> {
    let targets = {
        let c = client.lock().await;
        c.store().server_relays()?
    };
    let home = home.lock().await;
    Ok(targets
        .iter()
        .filter(|r| r.relay_vk != *home_vk)
        .filter_map(|r| r.primary_https_url().map(|url| (r.relay_vk, home.at(url))))
        .collect())
}

/// The account's home relay key as cached locally, fetching the log if needed.
pub(crate) async fn home_relay_vk(client: &SharedClient, home: &SharedRelay) -> Result<[u8; 32]> {
    let (account_fp, cached) = {
        let c = client.lock().await;
        let fp = *c.fingerprint();
        (fp, c.store().get_cached_idlog_state(&fp)?.and_then(|s| s.home_relay_vk))
    };
    match cached {
        Some(vk) => Ok(vk),
        None => idlog::fetch_and_verify(client, home, &account_fp)
            .await?
            .home_relay_vk
            .ok_or_else(|| GhostError::IdentityLog("identity log names no home relay".into())),
    }
}

/// Let every relay hosting one of the account's servers pull its log from the home,
/// and no other relay: the log lists the account's devices.
pub async fn update_mirror_grants(client: &SharedClient, home: &SharedRelay) -> Result<()> {
    let home_vk = home_relay_vk(client, home).await?;
    let (account_fp, relays) = {
        let c = client.lock().await;
        let relays: Vec<[u8; 32]> = c
            .store()
            .server_relays()?
            .into_iter()
            .map(|r| r.relay_vk)
            .filter(|vk| *vk != home_vk)
            .collect();
        (*c.fingerprint(), relays)
    };
    let r = home.lock().await;
    r.put_mirror_grants(&account_fp, &relays).await
}

/// Refresh the account's own log from the home, then push the anchored chain to
/// every other relay that hosts one of the account's servers. Those relays then
/// apply new devices and revocations at once instead of on their next pull from
/// the home. Mirrors skip entries they hold, so a mirror that missed an earlier
/// push catches up here too. Returns the relays that could not be updated.
pub async fn replicate_own_log(client: &SharedClient, home: &SharedRelay) -> Result<Vec<([u8; 32], GhostError)>> {
    let account_fp = {
        let c = client.lock().await;
        *c.fingerprint()
    };
    let state = idlog::fetch_and_verify(client, home, &account_fp).await?;
    let home_vk = state
        .home_relay_vk
        .ok_or_else(|| GhostError::IdentityLog("identity log names no home relay".into()))?;
    let chain = {
        let c = client.lock().await;
        c.store().get_cached_anchored_entries(&account_fp)?
    };
    // Mirrors that miss this push catch up by pulling, which the home only allows for granted relays.
    if let Err(e) = update_mirror_grants(client, home).await {
        eprintln!("replicate: mirror grants not updated: {e}");
    }

    let mut failures = Vec::new();
    for (relay_vk, mirror) in member_relay_clients(client, home, &home_vk).await? {
        if let Err(e) = mirror.put_anchored_entries(&account_fp, &chain, None).await {
            failures.push((relay_vk, e));
        }
    }
    Ok(failures)
}

/// Move the account's home to `new_home` from a device that is still active.
///
/// Works from the device's cached chain, so the old home need not be reachable:
/// the new home receives the chain with the anchors the old home issued plus a
/// `SetHomeRelay` naming it, and becomes the only relay that sequences the log.
/// Every relay hosting one of the account's servers then learns the move, and so
/// does `old_home` when given and reachable, which stops sequencing for the
/// account. Returns the new home's key; the caller switches its home connection.
pub async fn rehome(client: &SharedClient, new_home: &SharedRelay, old_home: Option<&SharedRelay>) -> Result<[u8; 32]> {
    let info = {
        let r = new_home.lock().await;
        r.get_relay_info().await?
    };
    let (account_fp, chain, entry) = {
        let c = client.lock().await;
        let account_fp = *c.fingerprint();
        let chain = c.store().get_cached_anchored_entries(&account_fp)?;
        let state = validate_anchored_chain(account_fp, &chain, None)?;
        if state.home_relay_vk == Some(info.relay_vk) {
            return Ok(info.relay_vk);
        }
        let entry = create_set_home_relay(&state, &c.signing_key_clone(), info.relay_ref.clone());
        c.store().upsert_relay(&info.relay_ref, now_millis())?;
        (account_fp, chain, entry)
    };

    {
        let r = new_home.lock().await;
        r.import_account(&account_fp, &ImportRequest { prefix: chain, new_entries: vec![entry] }).await?;
    }

    for (relay_vk, e) in replicate_own_log(client, new_home).await? {
        eprintln!("rehome: relay {} not updated yet: {e}", hex::encode(&relay_vk[..8]));
    }
    if let Some(old) = old_home {
        let chain = {
            let c = client.lock().await;
            c.store().get_cached_anchored_entries(&account_fp)?
        };
        let r = old.lock().await;
        if let Err(e) = r.put_anchored_entries(&account_fp, &chain, None).await {
            eprintln!("rehome: old home not told about the move: {e}");
        }
    }
    Ok(info.relay_vk)
}
