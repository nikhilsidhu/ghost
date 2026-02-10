use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

use crate::crypto::{GhostProvider, VOICE_EXPORT_LABEL};
use crate::error::{GhostError, Result};

use super::group::GhostGroup;

/// Each sender in a voice channel gets their own encryption key so nonces never collide.
pub fn derive_voice_key(
    group: &GhostGroup,
    provider: &GhostProvider,
    channel_id: &[u8; 32],
    sender_fp: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut context = Vec::with_capacity(64);
    context.extend_from_slice(channel_id);
    context.extend_from_slice(sender_fp);

    let secret = group.export_secret(provider, VOICE_EXPORT_LABEL, &context, 32)?;
    let key: [u8; 32] = secret
        .try_into()
        .map_err(|_| GhostError::Crypto("voice key not 32 bytes".into()))?;
    Ok(key)
}

/// Encrypt one audio frame before sending it to the voice channel.
pub fn encrypt_voice_frame(
    key: &[u8; 32],
    sequence: u32,
    opus_frame: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = voice_nonce(sequence);
    cipher
        .encrypt(Nonce::from_slice(&nonce), opus_frame)
        .map_err(|e| GhostError::Crypto(format!("voice encrypt: {e}")))
}

/// Decrypt a received audio frame from another sender.
pub fn decrypt_voice_frame(
    key: &[u8; 32],
    sequence: u32,
    encrypted: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = voice_nonce(sequence);
    cipher
        .decrypt(Nonce::from_slice(&nonce), encrypted)
        .map_err(|e| GhostError::Crypto(format!("voice decrypt: {e}")))
}

// Build a 12-byte nonce: 8 zero bytes then the sequence number.
fn voice_nonce(sequence: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[8..12].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn voice_frame_roundtrip() {
        let key = [0x42u8; 32];
        let frame = b"fake opus data here";
        let encrypted = encrypt_voice_frame(&key, 1, frame).unwrap();
        let decrypted = decrypt_voice_frame(&key, 1, &encrypted).unwrap();
        assert_eq!(decrypted, frame);
    }

    #[test]
    fn wrong_sequence_fails() {
        let key = [0x42u8; 32];
        let frame = b"opus";
        let encrypted = encrypt_voice_frame(&key, 1, frame).unwrap();
        assert!(decrypt_voice_frame(&key, 2, &encrypted).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let frame = b"opus";
        let encrypted = encrypt_voice_frame(&key1, 1, frame).unwrap();
        assert!(decrypt_voice_frame(&key2, 1, &encrypted).is_err());
    }

    #[test]
    fn derive_voice_key_deterministic() {
        let provider = GhostProvider::new();
        let alice = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = super::super::group::GhostGroup::create(&provider, &alice).unwrap();

        let channel_id = [0xFFu8; 32];
        let key1 = derive_voice_key(&group, &provider, &channel_id, &alice.fingerprint).unwrap();
        let key2 = derive_voice_key(&group, &provider, &channel_id, &alice.fingerprint).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn different_sender_different_key() {
        let provider = GhostProvider::new();
        let alice = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = super::super::group::GhostGroup::create(&provider, &alice).unwrap();

        let channel_id = [0xFFu8; 32];
        let fp_a = [0xAAu8; 32];
        let fp_b = [0xBBu8; 32];
        let key_a = derive_voice_key(&group, &provider, &channel_id, &fp_a).unwrap();
        let key_b = derive_voice_key(&group, &provider, &channel_id, &fp_b).unwrap();
        assert_ne!(key_a, key_b);
    }
}
