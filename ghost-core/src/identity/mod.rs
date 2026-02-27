pub mod export;
pub mod keyring_store;
pub mod log;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::crypto::keys::derive_ed25519_seed;
use crate::crypto::FINGERPRINT_SHORT_BYTES;
use crate::error::Result;
use crate::identity::log::{create_genesis, LogEntry};

/// Everything returned from account creation. Seed is zeroized on drop.
pub struct AccountCreation {
    pub identity: Identity,
    pub genesis_entry: LogEntry,
    pub seed: [u8; 32],
    pub db_key: [u8; 32],
    pub mls_db_key: [u8; 32],
}

impl Drop for AccountCreation {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
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
    pub fingerprint: [u8; 32],
    pub display_name: String,
    /// Sequence number in the identity log that authorized this device key.
    pub idlog_seq: u64,
}

impl Identity {
    /// Generate a random identity (single-device convenience for tests).
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut seed);
        Self::from_seed(seed)
    }

    /// Derive identity from seed. Signing key = seed-derived master key.
    /// In production multi-device, use `from_device` instead — this is mainly for tests
    /// and single-device flows where the seed-derived key IS the device key.
    pub fn from_seed(seed: [u8; 32]) -> Result<Self> {
        let ed25519_bytes = derive_ed25519_seed(&seed)?;
        let signing_key = SigningKey::from_bytes(&ed25519_bytes);
        let verifying_key = signing_key.verifying_key();
        let fingerprint: [u8; 32] = blake3::hash(verifying_key.as_bytes()).into();

        let fp_hex = hex::encode(&fingerprint[..FINGERPRINT_SHORT_BYTES]);
        let display_name = format!("ghost-{fp_hex}");

        // 0 = seed-derived identity, not registered in any identity log
        Ok(Self { signing_key, verifying_key, fingerprint, display_name, idlog_seq: 0 })
    }

    /// Restore a device identity from stored components.
    /// `fingerprint` is the account-level fingerprint (Blake3 of master verifying key).
    /// `signing_key` is this device's random Ed25519 key.
    pub fn from_device(fingerprint: [u8; 32], signing_key: SigningKey, idlog_seq: u64) -> Self {
        let verifying_key = signing_key.verifying_key();
        let fp_hex = hex::encode(&fingerprint[..FINGERPRINT_SHORT_BYTES]);
        let display_name = format!("ghost-{fp_hex}");
        Self { signing_key, verifying_key, fingerprint, display_name, idlog_seq }
    }

    /// Create a new account: derive master key from random seed, generate device key,
    /// create genesis identity log entry. Returns everything needed to persist and display.
    pub fn create_account(device_label: &str) -> Result<AccountCreation> {
        // Random seed → master key → fingerprint
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut seed);
        let ed25519_bytes = derive_ed25519_seed(&seed)?;
        let master_key = SigningKey::from_bytes(&ed25519_bytes);
        let fingerprint: [u8; 32] = blake3::hash(master_key.verifying_key().as_bytes()).into();

        // Random device key
        let device_key = SigningKey::generate(&mut OsRng);
        let device_vk = device_key.verifying_key();
        let genesis = create_genesis(&master_key, &device_key, device_label);

        // Random DB encryption keys
        let mut db_key = [0u8; 32];
        let mut mls_db_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut db_key);
        rand::RngCore::fill_bytes(&mut OsRng, &mut mls_db_key);

        let fp_hex = hex::encode(&fingerprint[..FINGERPRINT_SHORT_BYTES]);
        let identity = Identity {
            signing_key: device_key,
            verifying_key: device_vk,
            fingerprint,
            display_name: format!("ghost-{fp_hex}"),
            idlog_seq: 1,
        };

        Ok(AccountCreation { identity, genesis_entry: genesis, seed, db_key, mls_db_key })
    }

    /// First 16 hex chars of fingerprint.
    pub fn fingerprint_short(&self) -> String {
        hex::encode(&self.fingerprint[..FINGERPRINT_SHORT_BYTES])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_valid_identity() {
        let id = Identity::generate().unwrap();
        assert_eq!(id.fingerprint.len(), 32);
        assert!(id.display_name.starts_with("ghost-"));
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
    fn fingerprint_is_blake3_of_verifying_key() {
        let id = Identity::from_seed([0xAAu8; 32]).unwrap();
        let expected: [u8; 32] = blake3::hash(id.verifying_key.as_bytes()).into();
        assert_eq!(id.fingerprint, expected);
    }

    #[test]
    fn fingerprint_short_is_16_hex_chars() {
        let id = Identity::generate().unwrap();
        assert_eq!(id.fingerprint_short().len(), 16);
    }

    #[test]
    fn from_device_uses_provided_fingerprint() {
        let key = SigningKey::generate(&mut OsRng);
        let fp = [0xBBu8; 32];
        let id = Identity::from_device(fp, key, 0);
        assert_eq!(id.fingerprint, fp);
    }
}
