//! Keeping this device's account keys current: fetching the generations it lacks,
//! opening its copies (and older generations through back-links), and adding a
//! generation when the account's log no longer has one covering its devices.

use ghost_wire::account_key::AccountKeySet;
use ghost_wire::idlog::{LogState, Recipient};

use crate::account_keys::{open_back_link, open_copy, AccountSeed};
use crate::error::{GhostError, Result};
use crate::identity::batch::BatchBuilder;

use super::{account, idlog, SharedClient};
use crate::relay::RelayClient;

/// Fetch the account's log and every key set this device lacks, and open them. A copy
/// that opens to the wrong seed fails with `BadAccountKeyCopy`; the generation's
/// writer is in the log (`AccountKeyState::writer`) for the alert.
pub async fn refresh(client: &SharedClient, relay: &RelayClient) -> Result<()> {
    let account_fp = {
        let c = client.lock().await;
        *c.fingerprint()
    };
    let state = idlog::fetch_and_verify(client, relay, &account_fp).await?;
    open_missing(client, relay, &state).await
}

/// Bring the account's log and key sets up to date from the relays hosting its servers,
/// which mirror both, for when the home cannot be reached: the log verifies by its
/// anchors, each copy against the generation's commitment in it. Whether one served.
pub async fn refresh_through_members(client: &SharedClient, home: &RelayClient) -> bool {
    let Ok(home_vk) = account::home_relay_vk(client, home).await else { return false };
    let Ok(members) = account::member_relay_clients(client, home, &home_vk).await else { return false };
    for (relay_vk, member) in members {
        match refresh(client, &member).await {
            Ok(()) => return true,
            Err(e) => tracing::warn!("account: keys not refreshed through relay {}: {e}", ghost_wire::short_id(&relay_vk)),
        }
    }
    false
}

/// Open every generation of `state` this device does not hold yet: its own copy where
/// it has one, older generations through the back-links of newer ones.
pub async fn open_missing(client: &SharedClient, relay: &RelayClient, state: &LogState) -> Result<()> {
    let missing = {
        let c = client.lock().await;
        let mut missing = Vec::new();
        for key in &state.account_keys {
            if c.account_seed(key.generation)?.is_none() {
                missing.push(key.generation);
            }
        }
        missing
    };
    let Some(&from) = missing.iter().min() else { return Ok(()) };
    let sets = relay.get_key_sets(&state.account_fp, from).await?;

    let c = client.lock().await;
    let me = Recipient::device(c.verifying_key_bytes());
    let box_key = c.identity().encryption_key.key_pair()?;
    // Newest first, so each opened generation can open the one its back-link names.
    for key in state.account_keys.iter().rev() {
        let held = c.account_seed(key.generation)?;
        let set = sets.iter().find(|set| set.matches(&state.account_fp, key));
        let seed = match (held, set) {
            (Some(seed), _) => Some(seed),
            (None, Some(set)) if set.copy_for(&me).is_some() => {
                let seed = open_copy(set, &me, &box_key, key)?;
                c.store_account_seed(&seed)?;
                Some(seed)
            }
            _ => None,
        };
        if let (Some(seed), Some(set)) = (seed, set) {
            open_link(&c, state, set, &seed)?;
        }
    }
    Ok(())
}

/// Open the generation `set`'s back-link names, if this device lacks it.
fn open_link(c: &crate::client::GhostClient, state: &LogState, set: &AccountKeySet, seed: &AccountSeed) -> Result<()> {
    let Some(link) = &set.back_link else { return Ok(()) };
    if c.account_seed(link.generation)?.is_some() {
        return Ok(());
    }
    let previous = state
        .account_keys
        .iter()
        .find(|k| k.generation == link.generation)
        .ok_or_else(|| GhostError::IdentityLog(format!("back-link to unknown generation {}", link.generation)))?;
    let older = open_back_link(set, seed, previous)?;
    c.store_account_seed(&older)
}

/// The newest generation this device holds, to link a new generation back to.
pub(crate) fn newest_held(c: &crate::client::GhostClient, state: &LogState) -> Result<Option<AccountSeed>> {
    for key in state.account_keys.iter().rev() {
        if let Some(seed) = c.account_seed(key.generation)? {
            return Ok(Some(seed));
        }
    }
    Ok(None)
}

/// When the account's current generation no longer covers exactly its devices (a
/// device published its key after the last generation, or a change landed without
/// its rekey), append a generation that does. Any active device may, so whichever
/// notices first repairs it; one that loses the race finds the log covered when it
/// refreshes. Returns whether a generation was added.
pub async fn repair(client: &SharedClient, home: &RelayClient) -> Result<bool> {
    let seed = account::append_built(client, home, |state| Box::pin(async move {
        if !state.rekey_needed() {
            return Ok(None);
        }
        open_missing(client, home, &state).await?;
        let c = client.lock().await;
        let previous = newest_held(&c, &state)?;
        let mut batch = BatchBuilder::new(state);
        let seed = batch.push_rekey(&c.signing_key_clone(), previous.as_ref())?;
        Ok(Some((batch.finish(), seed)))
    }))
    .await?;
    let Some(seed) = seed else { return Ok(false) };
    client.lock().await.store_account_seed(&seed)?;
    account::announce_change(client, home).await;
    Ok(true)
}
