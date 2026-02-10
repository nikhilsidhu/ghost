use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::StaticSecret;

use crate::error::{GhostError, Result};

/// HKDF-SHA256: extract-then-expand with domain separation
pub fn derive_key(ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .map_err(|e| GhostError::Crypto(format!("HKDF expand failed: {e}")))?;
    Ok(out)
}

/// Seed -> Ed25519 signing key bytes via HKDF
pub fn derive_ed25519_seed(seed: &[u8; 32]) -> Result<[u8; 32]> {
    derive_key(seed, super::ED25519_DERIVE_LABEL)
}

/// Seed -> X25519 static secret via HKDF
pub fn derive_x25519_secret(seed: &[u8; 32]) -> Result<StaticSecret> {
    let bytes = derive_key(seed, super::X25519_DERIVE_LABEL)?;
    Ok(StaticSecret::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_deterministic() {
        let seed = [0xABu8; 32];
        let a = derive_key(&seed, b"test-info").unwrap();
        let b = derive_key(&seed, b"test-info").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn derive_key_different_info_different_output() {
        let seed = [0xABu8; 32];
        let a = derive_key(&seed, b"info-one").unwrap();
        let b = derive_key(&seed, b"info-two").unwrap();
        assert_ne!(a, b);
    }

}
