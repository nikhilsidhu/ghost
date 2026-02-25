use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use rand::rngs::OsRng;

use crate::error::{GhostError, Result};

const VERSION: u8 = 1;
const EXPORT_LEN: usize = 1 + 32 + 12 + 48; // 93 bytes

const ARGON2_MEMORY_KIB: u32 = 19 * 1024; // 19 MiB
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;

/// Encrypt a 32-byte seed with a passphrase. Returns 93 bytes.
pub fn export_seed(seed: &[u8; 32], passphrase: &str) -> Result<Vec<u8>> {
    let mut salt = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut salt);

    let key = derive_export_key(passphrase.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new(&key.into());

    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, seed.as_ref())
        .map_err(|e| GhostError::Export(format!("encrypt failed: {e}")))?;

    let mut out = Vec::with_capacity(EXPORT_LEN);
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a 32-byte seed from exported bytes + passphrase.
pub fn import_seed(data: &[u8], passphrase: &str) -> Result<[u8; 32]> {
    if data.len() != EXPORT_LEN {
        return Err(GhostError::Format(format!(
            "expected {EXPORT_LEN} bytes, got {}",
            data.len()
        )));
    }
    if data[0] != VERSION {
        return Err(GhostError::Format(format!(
            "unsupported version: {}",
            data[0]
        )));
    }

    let salt = &data[1..33];
    let nonce_bytes = &data[33..45];
    let ciphertext = &data[45..93];

    let key = derive_export_key(passphrase.as_bytes(), salt)?;
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| GhostError::AuthenticationFailed)?;

    let seed: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| GhostError::InvalidKey("decrypted seed not 32 bytes".into()))?;

    Ok(seed)
}

// Derive an AES-256 key from a user passphrase using Argon2id, so brute-forcing exported seeds is expensive.
fn derive_export_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let params = argon2::Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM, Some(32))
        .map_err(|e| GhostError::Crypto(format!("argon2 params: {e}")))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| GhostError::Crypto(format!("argon2 hash failed: {e}")))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_import_roundtrip() {
        let seed = [0xBBu8; 32];
        let blob = export_seed(&seed, "hunter2").unwrap();
        assert_eq!(blob.len(), EXPORT_LEN);

        let restored = import_seed(&blob, "hunter2").unwrap();
        assert_eq!(seed, restored);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let seed = [0xCCu8; 32];
        let blob = export_seed(&seed, "correct").unwrap();
        let err = import_seed(&blob, "wrong").unwrap_err();
        assert!(matches!(err, GhostError::AuthenticationFailed));
    }

    #[test]
    fn bad_length_fails() {
        let err = import_seed(&[0u8; 50], "pass").unwrap_err();
        assert!(matches!(err, GhostError::Format(_)));
    }

    #[test]
    fn bad_version_fails() {
        let mut blob = vec![0xFF];
        blob.extend_from_slice(&[0u8; 92]);
        let err = import_seed(&blob, "pass").unwrap_err();
        assert!(matches!(err, GhostError::Format(_)));
    }
}
