pub mod batch;
pub mod keyring_store;
pub mod log;

use ed25519_dalek::{SigningKey, VerifyingKey};
use ghost_wire::batch::LogBatch;
use ghost_wire::idlog::{LogEntry, LogState};
use ghost_wire::relay_ref::RelayRef;
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::account_keys::{AccountSeed, DeviceEncryptionKey, RecoveryKey};
use crate::crypto::keys::derive_ed25519_seed;
use crate::crypto::FINGERPRINT_SHORT_BYTES;
use crate::error::Result;
use crate::identity::batch::BatchBuilder;
use crate::identity::log::{
    counter_sign, create_device_key, create_genesis, create_rotate_root, create_set_home_relay, entry_hash, sign_entry,
};

/// The identity log entry that added a device, which its credential names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Addition {
    pub seq: u64,
    pub entry_hash: [u8; 32],
}

impl Addition {
    pub fn of(entry: &LogEntry) -> Self {
        Self { seq: entry.seq, entry_hash: entry_hash(entry) }
    }
}

/// A new account and its first device, ready to publish.
pub struct NewAccount {
    pub identity: Identity,
    /// Genesis, the home relay, the device's encryption key, the rotation to the
    /// recovery key's root and the first account key, published together.
    pub batch: LogBatch,
    pub account_seed: AccountSeed,
    pub db_key: [u8; 32],
    pub mls_db_key: [u8; 32],
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint_short())
            .field("display_name", &self.display_name)
            .finish()
    }
}

pub struct Identity {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    /// Opens this device's copies of the account key.
    pub encryption_key: DeviceEncryptionKey,
    pub fingerprint: [u8; 32],
    pub display_name: String,
    pub added_at: Addition,
}

impl Identity {
    /// A random identity with no identity log behind it, for tests that exercise MLS
    /// without relays.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut seed);
        let id = Self::from_seed(seed)?;
        seed.zeroize();
        Ok(id)
    }

    /// A deterministic one-device identity whose own key is also its account's genesis
    /// key, for tests that exercise MLS without relays. [`Identity::own_genesis`] is
    /// the log entry that added it.
    pub fn from_seed(seed: [u8; 32]) -> Result<Self> {
        let ed25519_bytes = derive_ed25519_seed(&seed)?;
        let signing_key = SigningKey::from_bytes(&ed25519_bytes);
        let genesis = standalone_genesis(&signing_key);
        Ok(Self::from_device(genesis.account_fp, signing_key, DeviceEncryptionKey::from_seed(seed), Addition::of(&genesis)))
    }

    /// For identities from [`Identity::generate`] and [`Identity::from_seed`]: the
    /// genesis that added the device, which tests put in a client's identity log cache.
    pub fn own_genesis(&self) -> LogEntry {
        standalone_genesis(&self.signing_key)
    }

    /// A device identity from stored parts. `fingerprint` is the account's.
    pub fn from_device(
        fingerprint: [u8; 32],
        signing_key: SigningKey,
        encryption_key: DeviceEncryptionKey,
        added_at: Addition,
    ) -> Self {
        let verifying_key = signing_key.verifying_key();
        let fp_hex = hex::encode(&fingerprint[..FINGERPRINT_SHORT_BYTES]);
        let display_name = format!("ghost-{fp_hex}");
        Self { signing_key, verifying_key, encryption_key, fingerprint, display_name, added_at }
    }

    /// Create an account homed at `home`, whose root is `recovery_key`'s. The user
    /// must have saved the key first: the genesis key that fixes the fingerprint is
    /// discarded here, and nothing else can act as the account's root.
    pub fn create_account(home: &RelayRef, device_label: &str, recovery_key: &RecoveryKey) -> Result<NewAccount> {
        let genesis_key = SigningKey::generate(&mut OsRng);
        let device_key = SigningKey::generate(&mut OsRng);
        let encryption_key = DeviceEncryptionKey::generate();
        let root = recovery_key.root()?;
        let recovery_box = recovery_key.recovery_box()?;

        let genesis = create_genesis(&genesis_key, &device_key, device_label);
        let account_fp = genesis.account_fp;
        let added_at = Addition::of(&genesis);
        let mut batch = BatchBuilder::new(LogState::empty(account_fp));
        batch.push(genesis)?;
        batch.push(create_set_home_relay(batch.state(), &device_key, home.clone()))?;
        batch.push(create_device_key(batch.state(), &device_key, &device_key, encryption_key.key_pair()?.public()))?;
        batch.push(create_rotate_root(batch.state(), &genesis_key, &root, recovery_box.public(), &device_key))?;
        let account_seed = batch.push_rekey(&device_key, None)?;

        let mut db_key = [0u8; 32];
        let mut mls_db_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut db_key);
        rand::RngCore::fill_bytes(&mut OsRng, &mut mls_db_key);

        Ok(NewAccount {
            identity: Self::from_device(account_fp, device_key, encryption_key, added_at),
            batch: batch.finish(),
            account_seed,
            db_key,
            mls_db_key,
        })
    }

    /// First 16 hex chars of fingerprint.
    pub fn fingerprint_short(&self) -> String {
        hex::encode(&self.fingerprint[..FINGERPRINT_SHORT_BYTES])
    }
}

/// The genesis of a one-device account whose genesis key is the device's own key,
/// stamped at time zero so the same key always yields the same entry.
fn standalone_genesis(key: &SigningKey) -> LogEntry {
    let mut entry = create_genesis(key, key, "test");
    entry.timestamp = 0;
    sign_entry(key, &mut entry);
    counter_sign(key, &mut entry);
    entry
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_wire::batch::apply_batch;

    #[test]
    fn generate_produces_unique_identities() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        assert_ne!(a.fingerprint, b.fingerprint, "generate must use randomness");
        assert!(a.display_name.starts_with("ghost-"));
        // Signing key actually works
        use ed25519_dalek::Signer;
        let sig = a.signing_key.sign(b"test");
        a.verifying_key.verify_strict(b"test", &sig).unwrap();
    }

    #[test]
    fn from_seed_deterministic() {
        let seed = [0x42u8; 32];
        let a = Identity::from_seed(seed).unwrap();
        let b = Identity::from_seed(seed).unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.verifying_key, b.verifying_key);
        assert_eq!(a.display_name, b.display_name);
    }

    #[test]
    fn different_seeds_different_identities() {
        let a = Identity::from_seed([0x01u8; 32]).unwrap();
        let b = Identity::from_seed([0x02u8; 32]).unwrap();
        assert_ne!(a.fingerprint, b.fingerprint);
    }

    #[test]
    fn fingerprint_short_is_16_hex_chars() {
        let id = Identity::generate().unwrap();
        assert_eq!(id.fingerprint_short().len(), 16);
    }

    #[test]
    fn a_new_account_is_rotated_covered_and_rooted_in_its_recovery_key() {
        let recovery_key = RecoveryKey::generate();
        let home = RelayRef::key_only([0x77; 32]);
        let account = Identity::create_account(&home, "laptop", &recovery_key).unwrap();
        let state = apply_batch(&LogState::empty(account.identity.fingerprint), &account.batch.entries, &account.batch.key_sets).unwrap();

        assert!(state.root_rotated());
        assert!(!state.rekey_needed());
        assert_eq!(state.root_verifying_key, Some(recovery_key.root().unwrap().verifying_key().to_bytes()));
        assert_eq!(state.recovery_box_key, Some(recovery_key.recovery_box().unwrap().public()));
        assert_eq!(state.home_relay_vk, Some([0x77; 32]));
        assert!(state.is_active_device(&account.identity.verifying_key.to_bytes()));
        assert_eq!(account.identity.added_at, Addition::of(&account.batch.entries[0]));
        assert!(account.account_seed.matches(state.account_key().unwrap()).unwrap());
    }
}
