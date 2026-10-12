//! Recovering an account when every device is lost, with the recovery key the user
//! saved. Every recovery replaces that key in the same batch, so whoever held the old
//! one is locked out at once.

use ed25519_dalek::SigningKey;
use ghost_wire::account_key::AccountKeySet;
use ghost_wire::anchor::ImportRequest;
use ghost_wire::batch::LogBatch;
use ghost_wire::idlog::{LogState, Recipient};
use ghost_wire::relay_ref::RelayRef;

use crate::account_keys::{open_back_link, open_copy, AccountSeed, BoxKeyPair, DeviceEncryptionKey, RecoveryKey};
use crate::error::{GhostError, Result};
use crate::identity::batch::BatchBuilder;
use crate::identity::log::{create_device_key, create_recovery, create_rotate_root, create_set_home_relay};
use crate::identity::{Addition, Identity};
use crate::relay::{RelayClient, RootLookup};

use super::{devices, idlog, provision, sync, SharedClient};

/// Everything recovery established before the application opens the recovered device.
pub struct RecoveryMaterial {
    pub account_fp: [u8; 32],
    pub device_key: SigningKey,
    pub encryption_key: DeviceEncryptionKey,
    pub added_at: Addition,
    /// Generations opened through the recovery copy and back-links, and the new one.
    pub seeds: Vec<AccountSeed>,
    /// Devices that were active before the Recovery entry revoked them.
    pub prior_devices: Vec<[u8; 32]>,
    /// The account's sealed sync snapshot, fetched once this device was active; the
    /// error when the relay could not be asked.
    sealed_snapshot: std::result::Result<Option<Vec<u8>>, String>,
}

/// What a recovery made of the account's sync snapshot, which lists its servers and
/// holds its settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotRestore {
    Restored,
    /// The relay recovered through holds none, so there was nothing to restore.
    Missing,
    /// It is sealed under an account key the recovery key does not reach, or damaged: no
    /// device of the account can open it any more, and this device's state replaces it.
    Unreadable,
    /// The relay did not answer; the running session takes it in when it does.
    NotReached,
}

/// A finished recovery: the settings restored, and what became of the snapshot.
#[derive(Debug)]
pub struct Finished {
    pub settings: sync::SyncSettings,
    pub snapshot: SnapshotRestore,
}

impl RecoveryMaterial {
    /// Identity of the recovered device, for opening a new client.
    pub fn identity(&self) -> Identity {
        Identity::from_device(self.account_fp, self.device_key.clone(), self.encryption_key.clone(), self.added_at)
    }
}

/// The recovering device and what its batch produced.
struct Recovered {
    device_key: SigningKey,
    encryption_key: DeviceEncryptionKey,
    added_at: Addition,
    seed: AccountSeed,
}

/// Find the account `recovery_key` is the root of, through `relay`. `None` if that
/// relay holds no account with it as the current root.
pub async fn find_account(relay: &RelayClient, recovery_key: &RecoveryKey) -> Result<Option<RootLookup>> {
    relay.find_account_by_root(&recovery_key.root()?).await
}

/// An account found by its recovery key, and where its home is.
pub struct Located {
    pub account_fp: [u8; 32],
    /// The home as the account's log names it; `None` for a log from before homes.
    pub home: Option<RelayRef>,
    /// Whether `relay` itself is the home.
    pub relay_is_home: bool,
}

/// Find the account through `relay` and read where it lives, so recovery can go to the
/// home when it answers and know what moving away from it means when it does not.
pub async fn locate(relay: &RelayClient, recovery_key: &RecoveryKey) -> Result<Option<Located>> {
    let Some(found) = find_account(relay, recovery_key).await? else { return Ok(None) };
    let root = recovery_key.root()?;
    let (_, state) = idlog::fetch_chain(&root_reader(relay, found.account_fp, &root), &found.account_fp).await?;
    let relay_vk = relay.get_relay_info().await?.relay_vk;
    Ok(Some(Located { account_fp: found.account_fp, home: state.home_relay_ref.clone(), relay_is_home: found.home_relay_vk == relay_vk }))
}

/// A client for `relay` that signs with the account's root in the device headers,
/// which relays accept for reading the account's log and key sets.
fn root_reader(relay: &RelayClient, account_fp: [u8; 32], root: &SigningKey) -> RelayClient {
    let reader = relay.at(&relay.base_url());
    reader.set_auth(account_fp, root.verifying_key().to_bytes(), root.clone());
    reader
}

/// Open the recovery copy of the newest generation that has one for `recovery_box`,
/// then every older generation the back-links reach.
fn open_with_recovery_box(state: &LogState, sets: &[AccountKeySet], recovery_box: &BoxKeyPair) -> Result<Vec<AccountSeed>> {
    let me = Recipient::recovery(recovery_box.public());
    let mut opened: Vec<AccountSeed> = Vec::new();
    for key in state.account_keys.iter().rev() {
        let Some(set) = sets.iter().find(|set| set.matches(&state.account_fp, key)) else { continue };
        let seed = match opened.iter().position(|s| s.generation() == key.generation) {
            Some(index) => opened.remove(index),
            None if set.copy_for(&me).is_some() => open_copy(set, &me, recovery_box, key)?,
            None => continue,
        };
        if let Some(link) = &set.back_link {
            if !opened.iter().any(|s| s.generation() == link.generation) {
                if let Some(previous) = state.account_keys.iter().find(|k| k.generation == link.generation) {
                    opened.push(open_back_link(set, &seed, previous)?);
                }
            }
        }
        opened.push(seed);
    }
    Ok(opened)
}

/// The recovery batch for a new device: (a root-signed home move first, when given)
/// Recovery, the device's encryption key, the root rotating to `new_key`'s, and an
/// account key generation for the device and the new recovery key, linking back to
/// `previous`.
fn recovery_batch(
    state: LogState,
    root: &SigningKey,
    new_key: &RecoveryKey,
    label: &str,
    previous: Option<&AccountSeed>,
    new_home: Option<RelayRef>,
) -> Result<(LogBatch, Recovered)> {
    let device_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let encryption_key = DeviceEncryptionKey::generate();
    let mut batch = BatchBuilder::new(state);
    if let Some(home) = new_home {
        batch.push(create_set_home_relay(batch.state(), root, home))?;
    }
    let recovery = create_recovery(batch.state(), root, &device_key, label);
    let added_at = Addition::of(&recovery);
    batch.push(recovery)?;
    batch.push(create_device_key(batch.state(), &device_key, &device_key, encryption_key.key_pair()?.public()))?;
    batch.push(create_rotate_root(batch.state(), root, &new_key.root()?, new_key.recovery_box()?.public(), &device_key))?;
    let seed = batch.push_rekey(&device_key, previous)?;
    Ok((batch.finish(), Recovered { device_key, encryption_key, added_at, seed }))
}

/// Read the sealed sync snapshot from `relay_url` as the newly recovered device. A
/// failure is not fatal: `finish` asks again.
async fn fetch_snapshot(relay_url: &str, account_fp: [u8; 32], device_key: &SigningKey) -> std::result::Result<Option<Vec<u8>>, String> {
    let (relay, _events) = RelayClient::new(relay_url);
    relay.set_auth(account_fp, device_key.verifying_key().to_bytes(), device_key.clone());
    relay.get_sync_state(&account_fp).await.map(|found| found.map(|(_generation, sealed)| sealed)).map_err(|e| e.to_string())
}

async fn material(
    relay: &RelayClient,
    state: &LogState,
    mut seeds: Vec<AccountSeed>,
    recovered: Recovered,
) -> RecoveryMaterial {
    let prior_devices = state.active_devices().map(|d| d.verifying_key).collect();
    let sealed_snapshot = fetch_snapshot(&relay.base_url(), state.account_fp, &recovered.device_key).await;
    seeds.push(recovered.seed);
    RecoveryMaterial {
        account_fp: state.account_fp,
        device_key: recovered.device_key,
        encryption_key: recovered.encryption_key,
        added_at: recovered.added_at,
        seeds,
        prior_devices,
        sealed_snapshot,
    }
}

/// What a recovering device reads with the root: the account's chain, its key sets and
/// the generations the recovery copy opens.
struct ReadWithRoot {
    log: crate::relay::AnchoredLog,
    state: LogState,
    sets: Vec<AccountKeySet>,
    seeds: Vec<AccountSeed>,
}

async fn read_with_root(relay: &RelayClient, account_fp: [u8; 32], recovery_key: &RecoveryKey) -> Result<ReadWithRoot> {
    let root = recovery_key.root()?;
    let reader = root_reader(relay, account_fp, &root);
    let (log, state) = idlog::fetch_chain(&reader, &account_fp).await?;
    if state.root_verifying_key != Some(root.verifying_key().to_bytes()) {
        return Err(GhostError::AuthenticationFailed);
    }
    let first = state.account_keys.first().map_or(1, |k| k.generation);
    let sets = reader.get_key_sets(&account_fp, first).await?;
    let seeds = open_with_recovery_box(&state, &sets, &recovery_key.recovery_box()?)?;
    Ok(ReadWithRoot { log, state, sets, seeds })
}

/// Recover through the account's home with `recovery_key`, replacing it with `new_key`,
/// which the user has saved. `relay` is the home, used unauthenticated: the batch opens
/// with the root-signed Recovery.
pub async fn begin(relay: &RelayClient, account_fp: [u8; 32], recovery_key: &RecoveryKey, new_key: &RecoveryKey, label: &str) -> Result<RecoveryMaterial> {
    let ReadWithRoot { state, seeds, .. } = read_with_root(relay, account_fp, recovery_key).await?;
    let previous = seeds.iter().max_by_key(|s| s.generation());
    let (batch, recovered) = recovery_batch(state.clone(), &recovery_key.root()?, new_key, label, previous, None)?;
    relay.post_idlog_batch(&account_fp, &batch).await?;
    Ok(material(relay, &state, seeds, recovered).await)
}

/// Recover when the home is gone. `source` is any relay that mirrors the account (it
/// holds the anchored log, key sets and snapshot); `new_home` becomes the account's home.
/// The new home imports the chain followed by the root-signed move naming it and the
/// rest of the recovery batch, so each is anchored by the relay that is home when it
/// applies. `source` then learns the new entries, which revokes the old devices there.
pub async fn begin_with_new_home(
    source: &RelayClient,
    new_home: &RelayClient,
    account_fp: [u8; 32],
    recovery_key: &RecoveryKey,
    new_key: &RecoveryKey,
    label: &str,
) -> Result<RecoveryMaterial> {
    let ReadWithRoot { log, state, sets, seeds } = read_with_root(source, account_fp, recovery_key).await?;
    let previous = seeds.iter().max_by_key(|s| s.generation());
    let new_home_ref = new_home.get_relay_info().await?.relay_ref;
    let (batch, recovered) = recovery_batch(state.clone(), &recovery_key.root()?, new_key, label, previous, Some(new_home_ref))?;

    let request = ImportRequest { prefix: log.entries, new_entries: batch.entries, key_sets: batch.key_sets.clone() };
    new_home.import_account(&account_fp, &request).await?;
    // From here the account is recovered, and this device is its only one: what follows
    // is replication the relays repeat among themselves, so a failure is noted, never
    // allowed to lose the recovered device.
    // The import carries only the new generation's set; the home serves every one.
    if !sets.is_empty() {
        if let Err(e) = new_home.put_key_sets(&account_fp, &sets).await {
            tracing::warn!("recovery: older key sets not copied to the new home: {e}");
        }
    }
    let new_root = new_key.root()?;
    match root_reader(new_home, account_fp, &new_root).get_idlog(&account_fp, 0).await {
        Ok(chain) => {
            if let Err(e) = source.put_anchored_entries(&account_fp, &chain.entries, None).await {
                tracing::warn!("recovery: the relay recovered through does not have the new chain yet: {e}");
            }
        }
        Err(e) => tracing::warn!("recovery: the new home's chain not read back: {e}"),
    }
    if let Err(e) = source.put_key_sets(&account_fp, &batch.key_sets).await {
        tracing::warn!("recovery: the relay recovered through has no new key set yet: {e}");
    }
    Ok(material(source, &state, seeds, recovered).await)
}

/// Complete recovery once the application runs the recovered identity: keep the opened
/// account keys, restore the sync snapshot, rejoin every server it lists, remove the
/// old devices' MLS leaves, and push the merged snapshot under the new generation.
/// Returns the restored settings and what became of the snapshot.
pub async fn finish(client: &SharedClient, relay: &RelayClient, material: &RecoveryMaterial) -> Result<Finished> {
    idlog::fetch_and_verify(client, relay, &material.account_fp).await?;
    let fetched = match &material.sealed_snapshot {
        Ok(found) => Ok(found.clone()),
        // Not fetched while recovering: asked again now that this device runs.
        Err(_) => relay.get_sync_state(&material.account_fp).await.map(|found| found.map(|(_generation, sealed)| sealed)),
    };
    let (entries, snapshot) = {
        let c = client.lock().await;
        for seed in &material.seeds {
            c.store_account_seed(seed)?;
        }
        match fetched {
            Ok(Some(sealed)) => match sync::open_snapshot(&c, &sealed) {
                Ok(dump) => {
                    let _ = c.cover_sync(&dump.covered);
                    (dump.entries, SnapshotRestore::Restored)
                }
                Err(e) => {
                    tracing::warn!("recovery: sync snapshot unreadable: {e}");
                    (Vec::new(), SnapshotRestore::Unreadable)
                }
            },
            Ok(None) => (Vec::new(), SnapshotRestore::Missing),
            Err(e) => {
                tracing::warn!("recovery: sync snapshot not fetched: {e}");
                (Vec::new(), SnapshotRestore::NotReached)
            }
        }
    };
    let mut settings =
        if entries.is_empty() { sync::SyncSettings::default() } else { sync::import_entries(client, &entries).await? };

    // Rejoining a server on a foreign relay first pushes the chain there, so that
    // relay applies the Recovery entry (old devices out, this one in) before the commit.
    let server_entries = std::mem::take(&mut settings.server_entries);
    provision::rejoin_from_sync(client, relay, &server_entries, super::now_millis()).await;

    devices::remove_devices_leaves(client, relay, &material.prior_devices).await;
    // Each relay's copy is read before this device writes over it, which may list
    // servers the snapshot above did not.
    if let Some(mut merged) = sync::push_snapshot(client, relay).await {
        provision::rejoin_from_sync(client, relay, &std::mem::take(&mut merged.server_entries), super::now_millis()).await;
        settings.absorb(merged);
    }
    Ok(Finished { settings, snapshot })
}
