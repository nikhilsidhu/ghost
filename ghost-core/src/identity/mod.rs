pub mod export;
pub mod keyring_store;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::crypto::keys::{derive_ed25519_seed, derive_x25519_secret};
use crate::crypto::FINGERPRINT_SHORT_BYTES;
use crate::error::Result;

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint_short())
            .field("display_name", &self.display_name)
            .finish()
    }
}

pub struct Identity {
    seed: [u8; 32],
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub x25519_secret: StaticSecret,
    pub x25519_public: X25519Public,
    pub fingerprint: [u8; 32],
    pub display_name: String,
}

impl Identity {
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut seed);
        Self::from_seed(seed)
    }

    /// All keys derived deterministically from seed
    pub fn from_seed(seed: [u8; 32]) -> Result<Self> {
        let ed25519_bytes = derive_ed25519_seed(&seed)?;
        let signing_key = SigningKey::from_bytes(&ed25519_bytes);
        let verifying_key = signing_key.verifying_key();
        let x25519_secret = derive_x25519_secret(&seed)?;
        let x25519_public = X25519Public::from(&x25519_secret);
        let fingerprint: [u8; 32] = blake3::hash(verifying_key.as_bytes()).into();

        let fp_hex = hex::encode(&fingerprint[..FINGERPRINT_SHORT_BYTES]);
        let display_name = format!("ghost-{fp_hex}");

        Ok(Self {
            seed,
            signing_key,
            verifying_key,
            x25519_secret,
            x25519_public,
            fingerprint,
            display_name,
        })
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
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
        assert_eq!(a.x25519_public.as_bytes(), b.x25519_public.as_bytes());
        assert_eq!(a.display_name, b.display_name);
    }

    #[test]
    fn different_seeds_different_identities() {
        let a = Identity::from_seed([0x01u8; 32]).unwrap();
        let b = Identity::from_seed([0x02u8; 32]).unwrap();
        assert_ne!(a.fingerprint, b.fingerprint);
        assert_ne!(a.x25519_public.as_bytes(), b.x25519_public.as_bytes());
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
}
