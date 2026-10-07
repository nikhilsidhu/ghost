//! Account recovery from a passphrase-protected blob when every device is lost.

use ed25519_dalek::SigningKey;
use zeroize::{Zeroize, Zeroizing};

use ghost_wire::anchor::ImportRequest;
use ghost_wire::idlog::{validate_entry, LogState};
use ghost_wire::recovery_bundle::RecoveryBundle;

use crate::crypto::keys::derive_ed25519_seed;
use crate::error::{GhostError, Result};
use crate::identity::export::{export_recovery_blob, import_recovery_blob};
use crate::identity::log::{create_recovery, create_set_home_relay};
use crate::identity::{compute_delegation_sig, Identity};
use crate::relay::RelayClient;
use crate::wire::{decode_sync_state_dump, sync_open};

use super::{account, devices, idlog, next_generation, provision, sync, SharedClient, SharedRelay};

pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// `relay_url#account_fp_hex`: where the recovery blob lives.
pub struct RecoveryCode {
    pub relay_url: String,
    pub account_fp: [u8; 32],
}

impl RecoveryCode {
    pub fn encode(&self) -> String {
        format!("{}#{}", self.relay_url, hex::encode(self.account_fp))
    }

    pub fn parse(code: &str) -> Result<Self> {
        let parts: Vec<&str> = code.splitn(2, '#').collect();
        if parts.len() != 2 {
            return Err(GhostError::Format("invalid recovery code".into()));
        }
        let bytes = hex::decode(parts[1]).map_err(|e| GhostError::Format(format!("recovery code fingerprint: {e}")))?;
        let account_fp = bytes
            .try_into()
            .map_err(|_| GhostError::Format("recovery code fingerprint must be 32 bytes".into()))?;
        Ok(Self { relay_url: parts[0].to_string(), account_fp })
    }
}

fn check_passphrase(passphrase: &str) -> Result<()> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(GhostError::Format(format!("passphrase must be at least {MIN_PASSPHRASE_CHARS} characters")));
    }
    Ok(())
}

/// Store a recovery bundle on the home relay, then copy it to every relay that
/// hosts one of the account's servers so recovery survives losing the home.
/// The home write must succeed; member copies are best effort.
async fn store_bundle(client: &SharedClient, home: &SharedRelay, bundle: &RecoveryBundle) -> Result<()> {
    let account_fp = {
        let c = client.lock().await;
        *c.fingerprint()
    };
    {
        let r = home.lock().await;
        r.put_recovery_bundle(&account_fp, bundle).await?;
    }
    let home_vk = account::home_relay_vk(client, home).await?;
    for (relay_vk, member) in account::member_relay_clients(client, home, &home_vk).await? {
        if let Err(e) = member.put_recovery_bundle(&account_fp, bundle).await {
            eprintln!("recovery bundle: relay {} not updated: {e}", hex::encode(&relay_vk[..8]));
        }
    }
    Ok(())
}

/// Encrypt the seed and sync key under the passphrase and store the bundle on every relay the account uses.
pub async fn set_passphrase(
    client: &SharedClient,
    relay: &SharedRelay,
    seed: &[u8; 32],
    passphrase: &str,
) -> Result<RecoveryCode> {
    check_passphrase(passphrase)?;
    let (sync_key, account_fp) = {
        let c = client.lock().await;
        let key = c.sync_key().ok_or_else(|| GhostError::Crypto("sync key not set".into()))?;
        (key, *c.fingerprint())
    };
    let bundle = RecoveryBundle {
        generation: next_generation(None),
        recovery_blob: export_recovery_blob(seed, &sync_key, passphrase)?,
        master_blob: Vec::new(),
    };
    store_bundle(client, relay, &bundle).await?;
    let r = relay.lock().await;
    Ok(RecoveryCode { relay_url: r.base_url().to_string(), account_fp })
}

/// Re-encrypt the stored recovery bundle under a new passphrase.
pub async fn change_passphrase(
    client: &SharedClient,
    relay: &SharedRelay,
    current: &str,
    new: &str,
) -> Result<()> {
    check_passphrase(new)?;
    let account_fp = {
        let c = client.lock().await;
        *c.fingerprint()
    };
    let stored = {
        let r = relay.lock().await;
        r.get_recovery_bundle(&account_fp)
            .await?
            .ok_or_else(|| GhostError::Format("no recovery blob found".into()))?
    };
    let recovered = import_recovery_blob(&stored.recovery_blob, current)?;
    let sync_key = match recovered.sync_key {
        Some(k) => k,
        None => {
            let c = client.lock().await;
            c.sync_key().ok_or_else(|| GhostError::Crypto("sync key not set".into()))?
        }
    };
    let bundle = RecoveryBundle {
        generation: next_generation(Some(stored.generation)),
        recovery_blob: export_recovery_blob(&recovered.seed, &sync_key, new)?,
        master_blob: stored.master_blob,
    };
    drop(recovered);
    store_bundle(client, relay, &bundle).await
}

pub async fn has_blob(client: &SharedClient, relay: &SharedRelay) -> Result<bool> {
    let account_fp = {
        let c = client.lock().await;
        *c.fingerprint()
    };
    let r = relay.lock().await;
    Ok(r.get_recovery_bundle(&account_fp).await?.is_some())
}

/// Everything [`begin`] established before the application replaces its local identity.
pub struct RecoveryMaterial {
    pub account_fp: [u8; 32],
    pub seed: Zeroizing<[u8; 32]>,
    /// Absent for v1 blobs; the application generates a fresh sync key in that case.
    pub sync_key: Option<[u8; 32]>,
    master_key: SigningKey,
    new_device_key: SigningKey,
    pub recovery_seq: u64,
    delegation_sig: [u8; 64],
    /// Devices that were active before the Recovery entry revoked them.
    pub prior_devices: Vec<[u8; 32]>,
    /// Generation of the bundle recovered from, so the re-encrypted one supersedes it.
    pub bundle_generation: u64,
    /// The account's sealed sync snapshot, fetched once this device was active.
    sealed_snapshot: Option<Vec<u8>>,
}

impl RecoveryMaterial {
    /// Identity of the recovered device, for opening a new client.
    pub fn identity(&self) -> Identity {
        Identity::from_device(
            self.account_fp,
            SigningKey::from_bytes(&self.new_device_key.to_bytes()),
            self.recovery_seq,
            self.master_key.verifying_key().to_bytes(),
            SigningKey::from_bytes(&self.master_key.to_bytes()),
            self.delegation_sig,
        )
    }

    pub fn device_key(&self) -> &SigningKey {
        &self.new_device_key
    }

    pub fn master_key(&self) -> &SigningKey {
        &self.master_key
    }

    pub fn delegation_sig(&self) -> [u8; 64] {
        self.delegation_sig
    }
}

/// What the passphrase unlocks, before any identity log change.
struct OpenedBundle {
    generation: u64,
    seed: Zeroizing<[u8; 32]>,
    sync_key: Option<[u8; 32]>,
    master_key: SigningKey,
}

/// Fetch and decrypt the recovery bundle from `relay` and prove it belongs to the account.
async fn open_bundle(relay: &RelayClient, account_fp: [u8; 32], passphrase: &str) -> Result<OpenedBundle> {
    let bundle = relay
        .get_recovery_bundle(&account_fp)
        .await?
        .ok_or_else(|| GhostError::Format("no recovery blob for this account".into()))?;
    let recovered = import_recovery_blob(&bundle.recovery_blob, passphrase)?;
    let seed = Zeroizing::new(recovered.seed);

    let mut ed_bytes = derive_ed25519_seed(&seed)?;
    let master_key = SigningKey::from_bytes(&ed_bytes);
    ed_bytes.zeroize();
    let expected_fp: [u8; 32] = blake3::hash(master_key.verifying_key().as_bytes()).into();
    if expected_fp != account_fp {
        return Err(GhostError::AuthenticationFailed);
    }
    Ok(OpenedBundle { generation: bundle.generation, seed, sync_key: recovered.sync_key, master_key })
}

/// A client for `relay` that signs with the account's master key, which relays
/// accept for reading the account's own log before any of its devices is active.
fn master_reader(relay: &RelayClient, account_fp: [u8; 32], opened: &OpenedBundle) -> RelayClient {
    let mut reader = relay.at(relay.base_url());
    reader.set_auth(account_fp, opened.master_key.verifying_key().to_bytes(), opened.master_key.clone());
    reader
}

/// Read the sealed sync snapshot from `relay_url` as the newly recovered device.
/// Missing or unreachable snapshots are not fatal: recovery then restores no servers.
async fn fetch_snapshot(relay_url: &str, account_fp: [u8; 32], device_key: &SigningKey) -> Option<Vec<u8>> {
    let (mut relay, _events) = RelayClient::new(relay_url);
    relay.set_auth(account_fp, device_key.verifying_key().to_bytes(), device_key.clone());
    match relay.get_sync_state(&account_fp).await {
        Ok(found) => found.map(|(_generation, sealed)| sealed),
        Err(e) => {
            eprintln!("recovery: sync snapshot unavailable: {e}");
            None
        }
    }
}

fn material(
    account_fp: [u8; 32],
    opened: OpenedBundle,
    new_device_key: SigningKey,
    log_state: &LogState,
    sealed_snapshot: Option<Vec<u8>>,
) -> RecoveryMaterial {
    let recovery_seq = log_state.head_seq + 1;
    let delegation_sig = compute_delegation_sig(
        &opened.master_key,
        new_device_key.verifying_key().as_bytes(),
        &account_fp,
        recovery_seq,
    );
    let prior_devices = log_state.devices.values().filter(|d| d.is_active()).map(|d| d.verifying_key).collect();
    RecoveryMaterial {
        account_fp,
        seed: opened.seed,
        sync_key: opened.sync_key,
        master_key: opened.master_key,
        new_device_key,
        recovery_seq,
        delegation_sig,
        prior_devices,
        bundle_generation: opened.generation,
        sealed_snapshot,
    }
}

/// Recover through a reachable home relay: decrypt the bundle, prove the passphrase
/// matches the account, and append a master-signed Recovery entry at the home that
/// revokes every previous device. `relay` is the home, unauthenticated because the
/// recovering device has no identity yet.
pub async fn begin(
    relay: &RelayClient,
    account_fp: [u8; 32],
    passphrase: &str,
    device_label: &str,
) -> Result<RecoveryMaterial> {
    let opened = open_bundle(relay, account_fp, passphrase).await?;
    let (_log, log_state) = idlog::fetch_chain(&master_reader(relay, account_fp, &opened), &account_fp).await?;

    let new_device_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let recovery_entry = create_recovery(&log_state, &opened.master_key, &new_device_key, device_label);
    relay.put_idlog_entry(&account_fp, recovery_entry.to_bytes()).await?;

    let sealed_snapshot = fetch_snapshot(relay.base_url(), account_fp, &new_device_key).await;
    Ok(material(account_fp, opened, new_device_key, &log_state, sealed_snapshot))
}

/// Recover when the home relay is gone. `source` is any relay that mirrors the account
/// (it holds the replicated bundle, snapshot and anchored log); `new_home` becomes the
/// account's home. The new home imports the chain followed by a master-signed
/// `SetHomeRelay` naming it and then the Recovery entry, so both are anchored by the
/// relay that is home when they apply. `source` then learns both, which revokes the old
/// devices there and admits this one. Both relays are used unauthenticated.
pub async fn begin_with_new_home(
    source: &RelayClient,
    new_home: &RelayClient,
    account_fp: [u8; 32],
    passphrase: &str,
    device_label: &str,
) -> Result<RecoveryMaterial> {
    let opened = open_bundle(source, account_fp, passphrase).await?;
    let (log, log_state) = idlog::fetch_chain(&master_reader(source, account_fp, &opened), &account_fp).await?;

    let new_home_ref = new_home.get_relay_info().await?.relay_ref;
    let move_entry = create_set_home_relay(&log_state, &opened.master_key, new_home_ref);
    let mut moved_state = log_state.clone();
    validate_entry(&mut moved_state, &move_entry)?;
    let new_device_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let recovery_entry = create_recovery(&moved_state, &opened.master_key, &new_device_key, device_label);

    let request = ImportRequest { prefix: log.entries, new_entries: vec![move_entry, recovery_entry] };
    new_home.import_account(&account_fp, &request).await?;

    let chain = master_reader(new_home, account_fp, &opened).get_idlog(&account_fp, 0).await?.entries;
    source.put_anchored_entries(&account_fp, &chain, None).await?;

    let sealed_snapshot = fetch_snapshot(source.base_url(), account_fp, &new_device_key).await;
    Ok(material(account_fp, opened, new_device_key, &moved_state, sealed_snapshot))
}

/// Complete recovery once the application runs the recovered identity: restore the sync
/// snapshot, rejoin every server it lists, remove the old devices' MLS leaves, store a
/// recovery blob under the new passphrase, and push the merged snapshot. `sync_key` is
/// the key the new client was opened with. Returns the restored settings.
pub async fn finish(
    client: &SharedClient,
    relay: &SharedRelay,
    material: &RecoveryMaterial,
    sync_key: [u8; 32],
    new_passphrase: &str,
) -> Result<sync::SyncSettings> {
    check_passphrase(new_passphrase)?;

    let mut settings = sync::SyncSettings::default();
    if let (Some(_), Some(sealed)) = (material.sync_key, &material.sealed_snapshot) {
        match sync_open(&sync_key, sealed).and_then(|d| decode_sync_state_dump(&d)) {
            Ok(entries) => settings = sync::import_entries(client, &entries).await?,
            Err(e) => eprintln!("recovery: sync snapshot unreadable: {e}"),
        }
    }

    // The recovered device starts a new sync group under the account's fixed sync mailbox;
    // the relay must drop the revoked devices' group state before it accepts the new one.
    super::reset_sync_mailbox(client, relay).await?;

    // Rejoining a server on a foreign relay first pushes the chain there, so that
    // relay applies the Recovery entry (old devices out, this one in) before the commit.
    let server_entries = std::mem::take(&mut settings.server_entries);
    provision::rejoin_from_sync(client, relay, &server_entries, super::now_millis()).await;

    for device_vk in &material.prior_devices {
        devices::remove_device_leaves(client, relay, device_vk).await;
    }

    let bundle = RecoveryBundle {
        generation: next_generation(Some(material.bundle_generation)),
        recovery_blob: export_recovery_blob(&material.seed, &sync_key, new_passphrase)?,
        master_blob: Vec::new(),
    };
    store_bundle(client, relay, &bundle).await?;
    sync::push_snapshot(client, relay).await;

    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_code_roundtrip() {
        let code = RecoveryCode { relay_url: "http://relay:7700".into(), account_fp: [0x5A; 32] };
        let parsed = RecoveryCode::parse(&code.encode()).unwrap();
        assert_eq!(parsed.relay_url, "http://relay:7700");
        assert_eq!(parsed.account_fp, [0x5A; 32]);
    }

    #[test]
    fn recovery_code_rejects_malformed() {
        assert!(RecoveryCode::parse("http://relay").is_err());
        assert!(RecoveryCode::parse("http://relay#notHex").is_err());
    }

    #[test]
    fn short_passphrase_rejected() {
        assert!(check_passphrase("short").is_err());
        assert!(check_passphrase("twelve chars").is_ok());
    }
}
