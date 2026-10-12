//! AES-256-GCM with a random 96-bit nonce prefixed to the ciphertext.
//! Shared by sync messages, pairing blobs, and presence blobs so the wire
//! format is identical everywhere: `nonce(12) || ciphertext || tag(16)`.

use aes_gcm::aead::{Aead, AeadCore, OsRng, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

use crate::error::{GhostError, Result};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Encrypt `plaintext` under `key`. `context` names the caller in error messages.
pub fn seal(key: &[u8; 32], plaintext: &[u8], context: &str) -> Result<Vec<u8>> {
    seal_bound(key, plaintext, &[], context)
}

/// Encrypt `plaintext` under `key`, bound to `aad`: it opens only with the same `aad`.
pub fn seal_bound(key: &[u8; 32], plaintext: &[u8], aad: &[u8], context: &str) -> Result<Vec<u8>> {
    let (nonce, ciphertext) = seal_detached(key, plaintext, aad, context)?;
    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Encrypt `plaintext` bound to `aad`, returning the random nonce and the ciphertext
/// separately, for formats that frame them apart.
pub fn seal_detached(key: &[u8; 32], plaintext: &[u8], aad: &[u8], context: &str) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|e| GhostError::Crypto(format!("{context} seal: {e}")))?;
    Ok((nonce.into(), ciphertext))
}

/// Decrypt what [`seal_detached`] produced, with the same `aad`.
pub fn open_detached(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ciphertext: &[u8], aad: &[u8], context: &str) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| GhostError::Crypto(format!("{context} open: authentication failed")))
}

/// Decrypt a `nonce || ciphertext` blob produced by [`seal`].
pub fn open(key: &[u8; 32], blob: &[u8], context: &str) -> Result<Vec<u8>> {
    open_bound(key, blob, &[], context)
}

/// Decrypt a `nonce || ciphertext` blob produced by [`seal_bound`] with the same `aad`.
pub fn open_bound(key: &[u8; 32], blob: &[u8], aad: &[u8], context: &str) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(GhostError::Crypto(format!("{context} open: blob too short")));
    }
    let nonce: [u8; NONCE_LEN] = blob[..NONCE_LEN].try_into().expect("checked length");
    open_detached(key, &nonce, &blob[NONCE_LEN..], aad, context)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [0x11u8; 32];
        let blob = seal(&key, b"hello", "test").unwrap();
        assert_eq!(blob.len(), NONCE_LEN + 5 + TAG_LEN);
        assert_eq!(open(&key, &blob, "test").unwrap(), b"hello");
    }

    #[test]
    fn wrong_key_fails() {
        let blob = seal(&[0x11u8; 32], b"hello", "test").unwrap();
        assert!(open(&[0x22u8; 32], &blob, "test").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [0x11u8; 32];
        let mut blob = seal(&key, b"hello", "test").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(open(&key, &blob, "test").is_err());
    }

    #[test]
    fn a_bound_seal_opens_only_with_its_aad() {
        let key = [0x11u8; 32];
        let blob = seal_bound(&key, b"hello", b"context", "test").unwrap();
        assert_eq!(open_bound(&key, &blob, b"context", "test").unwrap(), b"hello");
        assert!(open_bound(&key, &blob, b"other", "test").is_err());
        assert!(open(&key, &blob, "test").is_err(), "no aad is a different aad");
        let (nonce, ct) = seal_detached(&key, b"hello", b"context", "test").unwrap();
        assert_eq!(open_detached(&key, &nonce, &ct, b"context", "test").unwrap(), b"hello");
    }

    #[test]
    fn short_blob_rejected() {
        assert!(open(&[0u8; 32], &[0u8; 10], "test").is_err());
    }
}
