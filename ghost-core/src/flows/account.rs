//! The account's identity log as this device changes it: publishing batches, keeping
//! the log in the shape other relays require, migrating to account keys, and the
//! recovery key's own operations.

use ghost_wire::account_key::AccountKeySet;
use ghost_wire::anchor::{AnchoredEntry, ImportRequest};
use ghost_wire::batch::LogBatch;
use ghost_wire::idlog::{EntryBody, LogState};
use ghost_wire::relay_ref::RelayRef;
use ghost_wire::short_id;

use crate::account_keys::RecoveryKey;
use crate::client::GhostClient;
use crate::error::{GhostError, Result};
use crate::identity::batch::BatchBuilder;
use crate::identity::log::{create_rotate_root, create_set_home_relay};
use crate::idlog_cache::validate_anchored_chain;
use crate::relay::{RelayClient, RelayInfo};

use super::{account_keys, idlog, now_millis, subscribe_sync_mailbox, SharedClient};

/// Append a batch at the home, then bring this device and the account's other relays
/// up to date: the cached log, the anchored chain on every member relay, and the key
/// sets the batch carries. Returns the home's anchors for the batch's entries.
pub async fn publish_batch(client: &SharedClient, home: &RelayClient, batch: &LogBatch) -> Result<Vec<AnchoredEntry>> {
    let account_fp = {
        let c = client.lock().await;
        *c.fingerprint()
    };
    let anchors = home.post_idlog_batch(&account_fp, batch).await?;
    let home_vk = home_relay_vk(client, home).await?;
    for (relay_vk, outcome) in replicate_own_log(client, home).await? {
        if let Err(e) = outcome {
            tracing::warn!("relay {} not updated yet: {e}", short_id(&relay_vk));
        }
    }
    if !batch.key_sets.is_empty() {
        for (relay_vk, member) in member_relay_clients(client, home, &home_vk).await? {
            if let Err(e) = member.put_key_sets(&account_fp, &batch.key_sets).await {
                tracing::warn!("relay {} has no key sets yet: {e}", short_id(&relay_vk));
            }
        }
    }
    Ok(anchors)
}

/// Rounds of reading the log, building a change on it and appending it, when other
/// devices' appends keep moving the head meanwhile.
const APPEND_ROUNDS: usize = 3;

/// A change being built on the log as read: the batch to append and what to keep once
/// it lands, or `None` when the log needs no change.
pub type Building<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<(LogBatch, T)>>> + Send + 'a>>;

/// Read the account's log at the home, build a change on it, and append it. Another
/// device appending at the same moment makes the home refuse the batch as stale (409):
/// the log is read again and the change built once more. `build` returns `None` when
/// the log as read needs no change (another device made it already), and what it
/// returns beside the batch (a new generation's seed) comes back once the batch landed.
pub async fn append_built<'a, T>(
    client: &SharedClient,
    home: &RelayClient,
    mut build: impl FnMut(LogState) -> Building<'a, T>,
) -> Result<Option<T>> {
    let account_fp = *client.lock().await.fingerprint();
    for round in 1..=APPEND_ROUNDS {
        let state = idlog::fetch_and_verify(client, home, &account_fp).await?;
        let Some((batch, kept)) = build(state).await? else { return Ok(None) };
        match publish_batch(client, home, &batch).await {
            Ok(_) => return Ok(Some(kept)),
            Err(GhostError::RelayStatus { status: 409, .. }) if round < APPEND_ROUNDS => {
                tracing::info!("account: the log moved meanwhile; building the change again");
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!("the last round returns")
}

/// Tell the account's other devices its log changed, so they read it now rather than at
/// their next check. Sent after any new generation is held, so it seals under it.
pub async fn announce_change(client: &SharedClient, home: &RelayClient) {
    super::sync::post_message(client, home, crate::wire::SyncMessageType::AccountChanged, &[]).await;
}

/// Whether a recovery key is the account's current one, and whether that is the home's
/// word now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyCheck {
    pub matches: bool,
    /// `false` when the home could not be reached and the answer is by the log as this
    /// device last verified it: a key replaced from another device since may differ.
    pub current: bool,
}

/// Whether `recovery_key` is the account's current one, by the log as the home serves it
/// now, or as last verified while the home is out of reach. Nothing of the key is sent.
pub async fn check_recovery_key(client: &SharedClient, home: &RelayClient, recovery_key: &RecoveryKey) -> Result<KeyCheck> {
    let account_fp = *client.lock().await.fingerprint();
    let current = match idlog::fetch_and_verify(client, home, &account_fp).await {
        Ok(_) => true,
        Err(GhostError::Network(_) | GhostError::RelayStatus { status: 500..=599, .. }) => false,
        Err(e) => return Err(e),
    };
    let root = client.lock().await.own_log().and_then(|log| log.root_verifying_key);
    Ok(KeyCheck { matches: root == Some(recovery_key.root()?.verifying_key().to_bytes()), current })
}

/// Replace the account's recovery key with `new_key`, which the user has saved. Needs
/// the current key: a device alone can never replace it.
pub async fn replace_recovery_key(client: &SharedClient, home: &RelayClient, current: &RecoveryKey, new_key: &RecoveryKey) -> Result<()> {
    let root = &current.root()?;
    let seed = append_built(client, home, |state| Box::pin(async move {
        if state.root_verifying_key != Some(root.verifying_key().to_bytes()) {
            return Err(GhostError::AuthenticationFailed);
        }
        account_keys::open_missing(client, home, &state).await?;
        let c = client.lock().await;
        // The new generation links back to the current one, so a device that does not
        // hold it yet would leave a gap in the chain of generations.
        let current_generation = state.account_key().map(|k| k.generation);
        if current_generation.is_some_and(|g| c.account_seed(g).ok().flatten().is_none()) {
            return Err(GhostError::AccountKeyUnavailable("this device does not hold the account's current key yet; try again in a moment".into()));
        }
        let device = c.signing_key_clone();
        let previous = account_keys::newest_held(&c, &state)?;
        let mut batch = BatchBuilder::new(state);
        batch.push(create_rotate_root(batch.state(), root, &new_key.root()?, new_key.recovery_box()?.public(), &device))?;
        let seed = batch.push_rekey(&device, previous.as_ref())?;
        Ok(Some((batch.finish(), seed)))
    }))
    .await?;
    if let Some(seed) = seed {
        client.lock().await.store_account_seed(&seed)?;
    }
    announce_change(client, home).await;
    Ok(())
}

/// Make this account known to `relay` so its devices can authenticate there, and
/// remember how to reach the relay. A foreign relay receives the account's full
/// anchored chain and the key sets its account key entries commit to, read from
/// `home`; `invite` must name a live invite on it the first time. The home relay
/// already holds both, so nothing is pushed there.
pub async fn register_at(client: &SharedClient, home: &RelayClient, relay: &RelayClient, invite: Option<&str>) -> Result<RelayInfo> {
    let info = relay.get_relay_info().await?;
    let (account_fp, home_vk, chain) = {
        let c = client.lock().await;
        let account_fp = *c.fingerprint();
        c.store().upsert_relay(&info.relay_ref, now_millis())?;
        let home_vk = c.store().get_cached_idlog_state(&account_fp)?.and_then(|s| s.home_relay_vk);
        (account_fp, home_vk, c.store().get_cached_anchored_entries(&account_fp)?)
    };
    let home_vk = home_vk.ok_or_else(|| {
        GhostError::IdentityLog("identity log names no home relay yet; connect to the home relay first".into())
    })?;
    if home_vk == info.relay_vk {
        return Ok(info);
    }

    let account = relay.put_anchored_entries(&account_fp, &chain, invite).await?;
    if account.home_relay_vk != home_vk {
        return Err(GhostError::IdentityLog("relay recorded a different home for this account".into()));
    }
    // Without the sets, recovering through this relay could not open the account's
    // copies; it also pulls them from the home, but only on its next refresh.
    match home.get_key_sets(&account_fp, 1).await {
        Ok(sets) if !sets.is_empty() => {
            if let Err(e) = relay.put_key_sets(&account_fp, &sets).await {
                tracing::warn!("relay {} has no key sets yet: {e}", short_id(&info.relay_vk));
            }
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("key sets not read from the home: {e}"),
    }
    Ok(info)
}

/// Every generation's key sets for the account, from the old home if it answers, else
/// from a relay hosting one of its servers. Empty when no reachable relay holds them
/// all; the generations made after a move are complete at the new home regardless.
async fn held_key_sets(
    client: &SharedClient,
    old_home: Option<&RelayClient>,
    new_home: &RelayClient,
    state: &LogState,
    old_vk: Option<[u8; 32]>,
) -> Vec<AccountKeySet> {
    let Some(first) = state.account_keys.first().map(|key| key.generation) else { return Vec::new() };
    let complete = |sets: &[AccountKeySet]| state.account_keys.iter().all(|key| sets.iter().any(|set| set.matches(&state.account_fp, key)));
    // A retried move finds them at the new home already.
    if let Ok(sets) = new_home.get_key_sets(&state.account_fp, first).await {
        if complete(&sets) {
            return Vec::new();
        }
    }
    if let Some(old) = old_home {
        match old.get_key_sets(&state.account_fp, first).await {
            Ok(sets) if complete(&sets) => return sets,
            Ok(_) => tracing::warn!("rehome: the old home lacks some key sets"),
            Err(e) => tracing::warn!("rehome: key sets not read from the old home: {e}"),
        }
    }
    let excluded = old_vk.or(state.home_relay_vk).unwrap_or_default();
    for (relay_vk, member) in member_relay_clients(client, new_home, &excluded).await.unwrap_or_default() {
        match member.get_key_sets(&state.account_fp, first).await {
            Ok(sets) if complete(&sets) => return sets,
            Ok(_) => {}
            Err(e) => tracing::warn!("rehome: key sets not read from relay {}: {e}", short_id(&relay_vk)),
        }
    }
    tracing::warn!("rehome: no reachable relay holds every key set; the new home starts without the older ones");
    Vec::new()
}

/// Clients, signing as this device, for every relay other than `home_vk` that
/// hosts one of the account's servers. Relays without a reachable endpoint are skipped.
pub(crate) async fn member_relay_clients(client: &SharedClient, home: &RelayClient, home_vk: &[u8; 32]) -> Result<Vec<([u8; 32], RelayClient)>> {
    let targets = {
        let c = client.lock().await;
        c.store().server_relays()?
    };
    Ok(targets
        .iter()
        .filter(|r| r.relay_vk != *home_vk)
        .filter_map(|r| r.primary_https_url().map(|url| (r.relay_vk, home.at(url))))
        .collect())
}

/// How many relays hosting the account's servers refuse this device as revoked, asked
/// now: the corroboration a refusal needs while the home cannot be reached. Each one's
/// log is cached along the way, as `follow_home` does.
pub async fn relays_refusing_this_device(client: &SharedClient, home: &RelayClient) -> Refusals {
    let (account_fp, home_vk) = {
        let c = client.lock().await;
        (*c.fingerprint(), c.relay_vk().unwrap_or_default())
    };
    let members = match member_relay_clients(client, home, &home_vk).await {
        Ok(members) => members,
        Err(e) => {
            tracing::warn!("account: the servers' relays are not known: {e}");
            return Refusals::default();
        }
    };
    let mut causes = Vec::new();
    for (relay_vk, member) in members {
        if let Err(GhostError::DeviceRevoked(cause)) = idlog::fetch_and_verify(client, &member, &account_fp).await {
            tracing::warn!("account: relay {} refuses this device as revoked", short_id(&relay_vk));
            causes.push(cause);
        }
    }
    let cause = causes.first().cloned().flatten().filter(|first| causes.iter().all(|c| c.as_ref() == Some(first)));
    Refusals { refusing: causes.len(), cause }
}

/// How many of the servers' relays refuse this device as revoked, and what revoked it
/// when every one of them says the same.
#[derive(Debug, Default)]
pub struct Refusals {
    pub refusing: usize,
    pub cause: Option<ghost_wire::RevocationCause>,
}

/// The account's home relay key as cached locally, fetching the log if needed.
pub(crate) async fn home_relay_vk(client: &SharedClient, home: &RelayClient) -> Result<[u8; 32]> {
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
/// and have the home push new entries to it, and no other relay: the log lists the
/// account's devices.
pub async fn update_mirror_grants(client: &SharedClient, home: &RelayClient) -> Result<()> {
    let home_vk = home_relay_vk(client, home).await?;
    let (account_fp, relays) = {
        let c = client.lock().await;
        let account_fp = *c.fingerprint();
        let mut relays: Vec<RelayRef> = c.store().server_relays()?.into_iter().filter(|r| r.relay_vk != home_vk).collect();
        // A former home keeps the log, which is where a device that missed a move
        // learns of it; granted, it is kept current rather than refused its pulls.
        let (tenures, _) = home_tenures(&c.store().get_cached_anchored_entries(&account_fp)?);
        for (former, _) in tenures {
            if former.relay_vk != home_vk && !relays.iter().any(|r| r.relay_vk == former.relay_vk) {
                relays.push(former);
            }
        }
        (account_fp, relays)
    };
    home.put_mirror_grants(&account_fp, &relays).await
}

/// From the account check: renew the mirrors' grants at the home, which lapse unless
/// renewed, and push the chain to any relay hosting the account's servers whose copy
/// is behind this device's, as one that missed a push while its pulls went to a home
/// that was down or never told would be.
pub async fn keep_mirrors_current(client: &SharedClient, home: &RelayClient) {
    if let Err(e) = update_mirror_grants(client, home).await {
        tracing::warn!("account: mirror grants not renewed: {e}");
    }
    let (account_fp, head, chain) = {
        let c = client.lock().await;
        let account_fp = *c.fingerprint();
        let Some(head) = c.own_log().map(|log| log.head_seq) else { return };
        let Ok(chain) = c.store().get_cached_anchored_entries(&account_fp) else { return };
        (account_fp, head, chain)
    };
    let Ok(home_vk) = home_relay_vk(client, home).await else { return };
    let Ok(members) = member_relay_clients(client, home, &home_vk).await else { return };
    for (relay_vk, member) in members {
        match member.get_account(&account_fp).await {
            Ok(info) if info.head_seq < head => match member.put_anchored_entries(&account_fp, &chain, None).await {
                Ok(_) => tracing::info!("account: relay {} was behind on the log; brought up to date", short_id(&relay_vk)),
                Err(e) => tracing::warn!("account: relay {} is behind on the log and not updated: {e}", short_id(&relay_vk)),
            },
            Ok(_) => {}
            Err(e) => tracing::debug!("account: relay {} not asked for its copy of the log: {e}", short_id(&relay_vk)),
        }
    }
}

/// The account's homes by its log: each former home with the sequence number of the move
/// that ended its tenure, and the current one.
fn home_tenures(chain: &[AnchoredEntry]) -> (Vec<(RelayRef, u64)>, Option<RelayRef>) {
    let mut tenures = Vec::new();
    let mut current: Option<RelayRef> = None;
    for anchored in chain {
        if let EntryBody::SetHomeRelay { relay_ref, .. } = &anchored.entry.body {
            if let Some(previous) = current.replace(relay_ref.clone()) {
                if previous.relay_vk != relay_ref.relay_vk {
                    tenures.push((previous, anchored.entry.seq));
                }
            }
        }
    }
    (tenures, current)
}

/// Record that the servers routed to the home live at `relay`: the ones made there stay
/// when the account moves, and are routed, granted and pushed to accordingly.
fn keep_home_servers_at(c: &GhostClient, relay: &RelayRef) -> Result<()> {
    c.store().upsert_relay(relay, now_millis())?;
    for (server_id, _) in c.server_mailboxes() {
        if c.store().server_relay(&server_id)?.is_none() {
            c.store().set_server_relay(&server_id, &relay.relay_vk)?;
        }
    }
    Ok(())
}

/// Refresh the account's own log from the home, then push the anchored chain to
/// every other relay that hosts one of the account's servers. Those relays then
/// apply new devices and revocations at once instead of on their next pull from
/// the home. Mirrors skip entries they hold, so a mirror that missed an earlier
/// push catches up here too. Returns how each relay took the push.
pub async fn replicate_own_log(client: &SharedClient, home: &RelayClient) -> Result<Vec<([u8; 32], Result<()>)>> {
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
        tracing::warn!("replicate: mirror grants not updated: {e}");
    }

    let mut outcomes = Vec::new();
    for (relay_vk, mirror) in member_relay_clients(client, home, &home_vk).await? {
        outcomes.push((relay_vk, mirror.put_anchored_entries(&account_fp, &chain, None).await.map(drop)));
    }
    Ok(outcomes)
}

/// Move the account's home to `new_home`, signed by the account's root, which the
/// user's recovery key gives: a device alone cannot, or a stolen one could move the
/// home to a relay that refuses its owner's recovery.
///
/// Works from the device's cached chain, so the old home need not be reachable:
/// the new home receives the chain with the anchors the old home issued plus a
/// `SetHomeRelay` naming it, and becomes the only relay that sequences the log.
/// Every relay hosting one of the account's servers then learns the move, and so
/// does `old_home` when given and reachable, which stops sequencing for the
/// account. Returns the new home's key; the caller switches its home connection.
pub async fn rehome(client: &SharedClient, new_home: &RelayClient, old_home: Option<&RelayClient>, recovery_key: &RecoveryKey) -> Result<[u8; 32]> {
    let new_vk = begin_move(client, new_home, old_home, recovery_key).await?;
    // Nothing noted: the account was homed there already, with nothing left to do.
    if noted_move(&*client.lock().await).is_some() {
        finish_move(client, new_home, old_home).await?;
    }
    Ok(new_vk)
}

/// The part of a move that makes it: the new home imports the chain with the root-signed
/// `SetHomeRelay` naming it, and the move is noted for `finish_move`, which `rehome`
/// runs next and the account check runs when it did not finish. A move to a relay noted
/// already signs nothing new. Returns the new home's key.
pub async fn begin_move(client: &SharedClient, new_home: &RelayClient, old_home: Option<&RelayClient>, recovery_key: &RecoveryKey) -> Result<[u8; 32]> {
    let info = new_home.get_relay_info().await?;
    let (account_fp, chain, state, entry) = {
        let c = client.lock().await;
        let account_fp = *c.fingerprint();
        let chain = c.store().get_cached_anchored_entries(&account_fp)?;
        let state = validate_anchored_chain(account_fp, &chain, None)?;
        if state.home_relay_vk == Some(info.relay_vk) {
            return Ok(info.relay_vk);
        }
        // A move to this relay whose import landed resumes rather than signing another.
        if noted_move(&c).is_some_and(|(noted, _)| noted.relay_vk == info.relay_vk) {
            return Ok(info.relay_vk);
        }
        let root = recovery_key.root()?;
        if state.root_verifying_key != Some(root.verifying_key().to_bytes()) {
            return Err(GhostError::AuthenticationFailed);
        }
        let entry = create_set_home_relay(&state, &root, info.relay_ref.clone());
        c.store().upsert_relay(&info.relay_ref, now_millis())?;
        (account_fp, chain, state, entry)
    };
    new_home.import_account(&account_fp, &ImportRequest { prefix: chain, new_entries: vec![entry], key_sets: Vec::new() }).await?;
    // The account is homed at the new relay from here. What follows is noted until it is
    // done, so a failure part way is finished by the account check, and a second try
    // of the move resumes this one rather than signing another.
    let old_ref = state.home_relay_vk.and_then(|old_vk| old_home.map(|old| RelayRef::https(old_vk, &old.base_url())).or_else(|| state.home_relay_ref.clone()));
    note_move(&*client.lock().await, &info.relay_ref, old_ref.as_ref())?;
    Ok(info.relay_vk)
}

/// Where this device keeps a move whose import landed and whose follow-up has not
/// finished: the new home's `RelayRef`, and the old home's when known.
const CONFIG_MOVE_NEW_HOME: &str = "move_new_home";
const CONFIG_MOVE_OLD_HOME: &str = "move_old_home";

fn note_move(c: &GhostClient, new_home: &RelayRef, old_home: Option<&RelayRef>) -> Result<()> {
    c.store().set_config_blob(CONFIG_MOVE_NEW_HOME, &new_home.to_bytes())?;
    match old_home {
        Some(old) => c.store().set_config_blob(CONFIG_MOVE_OLD_HOME, &old.to_bytes()),
        None => c.store().delete_config_blob(CONFIG_MOVE_OLD_HOME),
    }
}

/// The move noted and not finished, if any: (new home, old home).
fn noted_move(c: &GhostClient) -> Option<(RelayRef, Option<RelayRef>)> {
    let read = |key| c.store().get_config_blob(key).ok().flatten().and_then(|bytes| RelayRef::from_bytes(&bytes).ok());
    Some((read(CONFIG_MOVE_NEW_HOME)?, read(CONFIG_MOVE_OLD_HOME)))
}

fn clear_move(c: &GhostClient) -> Result<()> {
    c.store().delete_config_blob(CONFIG_MOVE_NEW_HOME)?;
    c.store().delete_config_blob(CONFIG_MOVE_OLD_HOME)
}

/// From the account check: finish a move whose follow-up failed part way, reaching the
/// new home and the old one at the addresses the move noted.
pub async fn resume_move(client: &SharedClient, home: &RelayClient) -> Result<()> {
    let Some((new_ref, old_ref)) = noted_move(&*client.lock().await) else { return Ok(()) };
    let new_url = new_ref.primary_https_url().ok_or_else(|| GhostError::IdentityLog("the new home gives no address to reach it at".into()))?;
    let new_home = home.at(new_url);
    let old_home = old_ref.as_ref().and_then(|old| old.primary_https_url()).map(|url| home.at(url));
    tracing::info!("account: finishing the move to {new_url}");
    finish_move(client, &new_home, old_home.as_ref()).await
}

/// What follows a move's import, each step safe to repeat: this device's copy of the log
/// read at the new home (so it names it), the key sets copied there, the servers made
/// at the old home kept routed to it, the log pushed to the other relays and the old
/// home told, and the account's other devices told to follow.
async fn finish_move(client: &SharedClient, new_home: &RelayClient, old_home: Option<&RelayClient>) -> Result<()> {
    let account_fp = *client.lock().await.fingerprint();
    let state = idlog::fetch_and_verify(client, new_home, &account_fp).await?;
    let new_vk = state.home_relay_vk.ok_or_else(|| GhostError::IdentityLog("identity log names no home relay".into()))?;
    let old = {
        let c = client.lock().await;
        noted_move(&c).and_then(|(_, old)| old)
    };

    // Recovery and relays that join later read every generation's sets at the home. Read
    // before the old home learns the move and stops admitting this device.
    let sets = held_key_sets(client, old_home, new_home, &state, old.as_ref().map(|o| o.relay_vk)).await;
    if !sets.is_empty() {
        new_home.put_key_sets(&account_fp, &sets).await?;
    }

    // The servers made at the old home stay there. Routing them there now puts the old
    // home among the relays granted and pushed to below, so it keeps mirroring the log.
    if let Some(old_ref) = &old {
        keep_home_servers_at(&*client.lock().await, old_ref)?;
    }

    let outcomes = replicate_own_log(client, new_home).await?;
    for (relay_vk, outcome) in &outcomes {
        if let Err(e) = outcome {
            tracing::warn!("rehome: relay {} not updated yet: {e}", short_id(relay_vk));
        }
    }
    // The old home stops sequencing the account once it holds the move: pushed to above
    // when it hosts one of the account's servers, told here otherwise.
    let old_vk = old.as_ref().map(|o| o.relay_vk).filter(|vk| *vk != new_vk);
    let pushed_to_old = old_vk.and_then(|vk| outcomes.iter().find(|(relay_vk, _)| *relay_vk == vk)).map(|(_, outcome)| outcome.is_ok());
    let told = match (pushed_to_old, old_home) {
        (Some(told), _) => told,
        (None, Some(old)) => {
            let chain = client.lock().await.store().get_cached_anchored_entries(&account_fp)?;
            match old.put_anchored_entries(&account_fp, &chain, None).await {
                Ok(_) => true,
                Err(e) => {
                    // `tell_former_homes` tries again on every account check.
                    tracing::warn!("rehome: old home not told about the move yet: {e}");
                    false
                }
            }
        }
        (None, None) => false,
    };
    if let (true, Some(old_vk)) = (told, old_vk) {
        client.lock().await.store().record_former_home_told(&old_vk, state.home_set_at_seq)?;
    }
    clear_move(&*client.lock().await)?;
    // The other devices follow at once rather than at their next check. A device still
    // admitted at the old home (a member of a group there) is told nothing else; one that
    // is not hears it from the old home's refusal too. Waited for: the session's
    // connections restart once the move is made, and a queued message would go with them.
    super::sync::post_message_and_wait(client, old_home.unwrap_or(new_home), crate::wire::SyncMessageType::AccountChanged, &[]).await;
    Ok(())
}

/// Point this device's home connection at the home the account's log names, when the
/// account moved. A home that missed the move still serves the log from before it, and
/// one that is down serves nothing, so the relays hosting the account's servers are
/// asked too; the cached log keeps what the fork rule prefers. Servers created on the
/// old home stay routed there. Returns the new home's URL when this device switched.
pub async fn follow_home(client: &SharedClient, home: &RelayClient) -> Result<Option<String>> {
    let account_fp = *client.lock().await.fingerprint();
    let connected_vk = client.lock().await.relay_vk();
    let excluded = connected_vk.unwrap_or_default();
    for (relay_vk, member) in member_relay_clients(client, home, &excluded).await? {
        if let Err(e) = idlog::fetch_and_verify(client, &member, &account_fp).await {
            tracing::warn!("account: log not read at relay {}: {e}", short_id(&relay_vk));
        }
    }

    let (named, url) = {
        let c = client.lock().await;
        let Some(named) = c.own_log().and_then(|log| log.home_relay_ref.clone()) else { return Ok(None) };
        if Some(named.relay_vk) == connected_vk {
            return Ok(None);
        }
        let known = c.store().get_relay(&named.relay_vk)?;
        let url = named.primary_https_url().or_else(|| known.as_ref().and_then(|r| r.primary_https_url())).map(str::to_string);
        (named, url)
    };
    let url = url.ok_or_else(|| GhostError::IdentityLog("the account's new home gives no address to reach it at".into()))?;

    // The servers made on the old home live there still; record it, so they are routed
    // there after a restart too. Their connections already are.
    let old_url = home.base_url();
    {
        let c = client.lock().await;
        if let Some(old_vk) = connected_vk {
            keep_home_servers_at(&c, &RelayRef::https(old_vk, &old_url))?;
        }
        c.store().upsert_relay(&named, now_millis())?;
    }
    home.set_base_url(&url);
    client.lock().await.set_relay_vk(named.relay_vk);

    // The sync mailbox is open on the home and two other relays; reopen the set with
    // the new home in it, each relay resuming from where this device last saw it there.
    {
        let c = client.lock().await;
        home.unsubscribe(&c.account_sync_mailbox());
        subscribe_sync_mailbox(&c, home);
    }
    Ok(Some(url))
}

/// Former homes, by key and the move that ended their tenure, that name no address to be
/// told of the move at; each is said once a run.
static UNADDRESSED_FORMER_HOMES: std::sync::Mutex<std::collections::BTreeSet<([u8; 32], u64)>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

/// Tell each former home about the move that ended its time as home, once. One that was
/// down during the move still believes it sequences the account, and would take changes
/// from a device that missed the move that no other relay accepts.
pub async fn tell_former_homes(client: &SharedClient) {
    let (account_fp, chain, tenures) = {
        let c = client.lock().await;
        let account_fp = *c.fingerprint();
        let Ok(chain) = c.store().get_cached_anchored_entries(&account_fp) else { return };
        let (tenures, current) = home_tenures(&chain);
        let current_vk = current.map(|r| r.relay_vk);
        let untold: Vec<(RelayRef, u64, Option<String>)> = tenures
            .into_iter()
            .filter(|(relay, _)| Some(relay.relay_vk) != current_vk)
            .filter(|(relay, ended_at)| !c.store().former_home_told(&relay.relay_vk, *ended_at).unwrap_or(true))
            .map(|(relay, ended_at)| {
                let known = c.store().get_relay(&relay.relay_vk).ok().flatten();
                let url = relay.primary_https_url().or_else(|| known.as_ref().and_then(|r| r.primary_https_url())).map(str::to_string);
                (relay, ended_at, url)
            })
            .collect();
        (account_fp, chain, untold)
    };
    for (relay, ended_at, url) in tenures {
        let Some(url) = url else {
            if UNADDRESSED_FORMER_HOMES.lock().unwrap_or_else(|e| e.into_inner()).insert((relay.relay_vk, ended_at)) {
                tracing::warn!("account: former home {} names no address, so it cannot be told of the move", short_id(&relay.relay_vk));
            }
            continue;
        };
        // Entries carry the anchors that prove them, so the old home needs no credentials.
        let (guest, _events) = RelayClient::new(&url);
        match guest.put_anchored_entries(&account_fp, &chain, None).await {
            Ok(_) => {
                if let Err(e) = client.lock().await.store().record_former_home_told(&relay.relay_vk, ended_at) {
                    tracing::warn!("account: former home told but not recorded: {e}");
                }
            }
            Err(e) => tracing::warn!("account: former home {} not told yet: {e}", short_id(&relay.relay_vk)),
        }
    }
}
