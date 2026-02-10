use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use rand::rngs::OsRng;

use super::Identity;
use crate::error::{GhostError, Result};

const VERSION: u8 = 1;
const EXPORT_LEN: usize = 1 + 32 + 12 + 48; // 93 bytes

/// Encrypt identity seed with a passphrase. Returns 93 bytes.
pub fn export(identity: &Identity, passphrase: &str) -> Result<Vec<u8>> {
    let mut salt = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut salt);

    let key = derive_export_key(passphrase.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new(&key.into());

    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, identity.seed().as_ref())
        .map_err(|e| GhostError::Export(format!("encrypt failed: {e}")))?;

    let mut out = Vec::with_capacity(EXPORT_LEN);
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt identity seed from exported bytes + passphrase.
pub fn import(data: &[u8], passphrase: &str) -> Result<Identity> {
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

    Identity::from_seed(seed)
}

/// Argon2id: memory-hard password KDF (19 MiB, 2 iterations, 1 thread).
fn derive_export_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let params = argon2::Params::new(19 * 1024, 2, 1, Some(32))
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
        let id = Identity::from_seed([0xBBu8; 32]).unwrap();
        let blob = export(&id, "hunter2").unwrap();
        assert_eq!(blob.len(), EXPORT_LEN);

        let restored = import(&blob, "hunter2").unwrap();
        assert_eq!(id.fingerprint, restored.fingerprint);
        assert_eq!(id.verifying_key, restored.verifying_key);
        assert_eq!(
            id.x25519_public.as_bytes(),
            restored.x25519_public.as_bytes()
        );
    }

    #[test]
    fn wrong_passphrase_fails() {
        let id = Identity::from_seed([0xCCu8; 32]).unwrap();
        let blob = export(&id, "correct").unwrap();
        let err = import(&blob, "wrong").unwrap_err();
        assert!(matches!(err, GhostError::AuthenticationFailed));
    }

    #[test]
    fn bad_length_fails() {
        let err = import(&[0u8; 50], "pass").unwrap_err();
        assert!(matches!(err, GhostError::Format(_)));
    }

    #[test]
    fn bad_version_fails() {
        let mut blob = vec![0xFF];
        blob.extend_from_slice(&[0u8; 92]);
        let err = import(&blob, "pass").unwrap_err();
        assert!(matches!(err, GhostError::Format(_)));
    }

    #[test]
    fn export_is_93_bytes() {
        let id = Identity::generate().unwrap();
        let blob = export(&id, "test").unwrap();
        assert_eq!(blob.len(), 93);
    }
}
