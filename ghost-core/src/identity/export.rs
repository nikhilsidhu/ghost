use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use rand::rngs::OsRng;
use zeroize::Zeroize;

use crate::error::{GhostError, Result};

const V1_LEN: usize = 1 + 32 + 12 + 48;  // 93 bytes (seed only)
const V2_LEN: usize = 1 + 32 + 12 + 80;  // 125 bytes (seed + sync_key)

const ARGON2_MEMORY_KIB: u32 = 19 * 1024; // 19 MiB
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;

pub struct RecoveryBlob {
    pub seed: [u8; 32],
    pub sync_key: Option<[u8; 32]>,
}

impl std::fmt::Debug for RecoveryBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryBlob").finish_non_exhaustive()
    }
}

impl Drop for RecoveryBlob {
    fn drop(&mut self) {
        self.seed.zeroize();
        if let Some(ref mut k) = self.sync_key {
            k.zeroize();
        }
    }
}

/// Encrypt seed + sync_key with a passphrase. Returns 125 bytes (v2 format).
pub fn export_recovery_blob(seed: &[u8; 32], sync_key: &[u8; 32], passphrase: &str) -> Result<Vec<u8>> {
    let mut salt = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut salt);

    let key = derive_export_key(passphrase.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new(&key.into());

    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut plaintext = Vec::with_capacity(64);
    plaintext.extend_from_slice(seed);
    plaintext.extend_from_slice(sync_key);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| GhostError::Export(format!("encrypt failed: {e}")));
    plaintext.zeroize();
    let ciphertext = ciphertext?;

    let mut out = Vec::with_capacity(V2_LEN);
    out.push(2); // version
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a recovery blob. Supports v1 (seed only, 93 bytes) and v2 (seed + sync_key, 125 bytes).
pub fn import_recovery_blob(data: &[u8], passphrase: &str) -> Result<RecoveryBlob> {
    if data.is_empty() {
        return Err(GhostError::Format("empty blob".into()));
    }

    match data[0] {
        1 => import_v1(data, passphrase),
        2 => import_v2(data, passphrase),
        v => Err(GhostError::Format(format!("unsupported version: {v}"))),
    }
}

fn import_v1(data: &[u8], passphrase: &str) -> Result<RecoveryBlob> {
    if data.len() != V1_LEN {
        return Err(GhostError::Format(format!("v1: expected {V1_LEN} bytes, got {}", data.len())));
    }

    let salt = &data[1..33];
    let nonce_bytes = &data[33..45];
    let ciphertext = &data[45..93];

    let key = derive_export_key(passphrase.as_bytes(), salt)?;
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(nonce_bytes);

    let mut plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| GhostError::AuthenticationFailed)?;

    let result = if plaintext.len() == 32 {
        let seed: [u8; 32] = plaintext[..32].try_into().unwrap();
        Ok(RecoveryBlob { seed, sync_key: None })
    } else {
        Err(GhostError::InvalidKey("v1: decrypted seed not 32 bytes".into()))
    };
    plaintext.zeroize();
    result
}

fn import_v2(data: &[u8], passphrase: &str) -> Result<RecoveryBlob> {
    if data.len() != V2_LEN {
        return Err(GhostError::Format(format!("v2: expected {V2_LEN} bytes, got {}", data.len())));
    }

    let salt = &data[1..33];
    let nonce_bytes = &data[33..45];
    let ciphertext = &data[45..125];

    let key = derive_export_key(passphrase.as_bytes(), salt)?;
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| GhostError::AuthenticationFailed)?;

    if plaintext.len() != 64 {
        return Err(GhostError::InvalidKey("v2: decrypted blob not 64 bytes".into()));
    }

    let seed: [u8; 32] = plaintext[..32].try_into().unwrap();
    let sync_key: [u8; 32] = plaintext[32..64].try_into().unwrap();
    let mut plaintext = plaintext;
    plaintext.zeroize();

    Ok(RecoveryBlob { seed, sync_key: Some(sync_key) })
}

// Derive an AES-256 key from a user passphrase using Argon2id.
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
    fn v2_roundtrip() {
        let seed = [0xBBu8; 32];
        let sync_key = [0xCCu8; 32];
        let blob = export_recovery_blob(&seed, &sync_key, "hunter2").unwrap();
        assert_eq!(blob.len(), V2_LEN);
        assert_eq!(blob[0], 2);

        let restored = import_recovery_blob(&blob, "hunter2").unwrap();
        assert_eq!(restored.seed, seed);
        assert_eq!(restored.sync_key.unwrap(), sync_key);
    }

    #[test]
    fn v1_backward_compat() {
        // Manually create a v1 blob using the same crypto
        let seed = [0xAAu8; 32];
        let mut salt = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut salt);
        let key = derive_export_key(b"oldpass", &salt).unwrap();
        let cipher = Aes256Gcm::new(&key.into());
        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher.encrypt(nonce, seed.as_ref()).unwrap();

        let mut blob = Vec::with_capacity(V1_LEN);
        blob.push(1);
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);
        assert_eq!(blob.len(), V1_LEN);

        let restored = import_recovery_blob(&blob, "oldpass").unwrap();
        assert_eq!(restored.seed, seed);
        assert!(restored.sync_key.is_none());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let blob = export_recovery_blob(&[0xCCu8; 32], &[0xDDu8; 32], "correct").unwrap();
        let err = import_recovery_blob(&blob, "wrong").unwrap_err();
        assert!(matches!(err, GhostError::AuthenticationFailed));
    }

    #[test]
    fn bad_length_fails() {
        let err = import_recovery_blob(&[2u8; 50], "pass").unwrap_err();
        assert!(matches!(err, GhostError::Format(_)));
    }

    #[test]
    fn bad_version_fails() {
        let mut blob = vec![0xFF];
        blob.extend_from_slice(&[0u8; 124]);
        let err = import_recovery_blob(&blob, "pass").unwrap_err();
        assert!(matches!(err, GhostError::Format(_)));
    }

    #[test]
    fn empty_blob_fails() {
        let err = import_recovery_blob(&[], "pass").unwrap_err();
        assert!(matches!(err, GhostError::Format(_)));
    }
}
