use aes_gcm::aead::{Aead, AeadCore, OsRng};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

use crate::crypto::{GhostProvider, VOICE_EXPORT_LABEL, VOICE_PRESENCE_EXPORT_LABEL};
use crate::error::{GhostError, Result};

use super::group::GhostGroup;

fn derive_export_key(
    group: &GhostGroup,
    provider: &GhostProvider,
    label: &str,
    channel_id: &[u8; 32],
    sender_fp: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut context = Vec::with_capacity(64);
    context.extend_from_slice(channel_id);
    context.extend_from_slice(sender_fp);
    let secret = group.export_secret(provider, label, &context, 32)?;
    let key: [u8; 32] = secret
        .try_into()
        .map_err(|_| GhostError::Crypto("export key not 32 bytes".into()))?;
    Ok(key)
}

/// Each sender in a voice channel gets their own encryption key so nonces never collide.
/// `device_vk` ensures two devices sharing a fingerprint derive different keys.
pub fn derive_voice_key(
    group: &GhostGroup,
    provider: &GhostProvider,
    channel_id: &[u8; 32],
    sender_fp: &[u8; 32],
    device_vk: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut context = Vec::with_capacity(96);
    context.extend_from_slice(channel_id);
    context.extend_from_slice(sender_fp);
    context.extend_from_slice(device_vk);
    let secret = group.export_secret(provider, VOICE_EXPORT_LABEL, &context, 32)?;
    let key: [u8; 32] = secret
        .try_into()
        .map_err(|_| GhostError::Crypto("export key not 32 bytes".into()))?;
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

fn voice_nonce(sequence: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[8..12].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

// --- Presence blob crypto ---

/// Voice presence state, encrypted inside a presence blob.
/// Identity resolved via fingerprint lookup in member database — no display name here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceState {
    pub fingerprint: [u8; 32],
    pub muted: bool,
    pub deafened: bool,
    pub device_vk: [u8; 32],
}

impl PresenceState {
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut buf = [0u8; 66];
        buf[0..32].copy_from_slice(&self.fingerprint);
        buf[32] = self.muted as u8;
        buf[33] = self.deafened as u8;
        buf[34..66].copy_from_slice(&self.device_vk);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 66 {
            return Err(GhostError::Crypto("presence too short".into()));
        }
        let fingerprint: [u8; 32] = data[0..32].try_into().unwrap();
        let muted = data[32] != 0;
        let deafened = data[33] != 0;
        let device_vk: [u8; 32] = data[34..66].try_into().unwrap();
        Ok(Self { fingerprint, muted, deafened, device_vk })
    }
}

/// Derive a per-sender presence encryption key for a voice channel.
pub fn derive_presence_key(
    group: &GhostGroup,
    provider: &GhostProvider,
    channel_id: &[u8; 32],
    sender_fp: &[u8; 32],
) -> Result<[u8; 32]> {
    derive_export_key(group, provider, VOICE_PRESENCE_EXPORT_LABEL, channel_id, sender_fp)
}

/// Encrypt a presence state blob. Wire format: [nonce:12][ciphertext+tag].
pub fn seal_presence(key: &[u8; 32], state: &PresenceState) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let plaintext = state.to_bytes();
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|e| GhostError::Crypto(format!("presence seal: {e}")))?;
    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypt a presence blob. Returns the parsed state.
pub fn open_presence(key: &[u8; 32], blob: &[u8]) -> Result<PresenceState> {
    if blob.len() < 12 + 16 {
        return Err(GhostError::Crypto("presence blob too short".into()));
    }
    let nonce = Nonce::from_slice(&blob[..12]);
    let ciphertext = &blob[12..];
    let cipher = Aes256Gcm::new(key.into());
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| GhostError::Crypto("presence open: auth failed".into()))?;
    PresenceState::from_bytes(&plaintext)
}

/// Try to decrypt a presence blob by trying each member's per-sender key.
pub fn try_open_presence(
    member_fps: &[[u8; 32]],
    group: &GhostGroup,
    provider: &GhostProvider,
    channel_id: &[u8; 32],
    blob: &[u8],
) -> Result<PresenceState> {
    for fp in member_fps {
        if let Ok(key) = derive_presence_key(group, provider, channel_id, fp) {
            if let Ok(state) = open_presence(&key, blob) {
                if state.fingerprint == *fp {
                    return Ok(state);
                }
            }
        }
    }
    Err(GhostError::Crypto("no member key decrypts this presence blob".into()))
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
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = super::super::group::GhostGroup::create(&provider, &id, None).unwrap();

        let channel_id = [0xFFu8; 32];
        let vk = *id.verifying_key.as_bytes();
        let key1 = derive_voice_key(&group, &provider, &channel_id, &id.fingerprint, &vk).unwrap();
        let key2 = derive_voice_key(&group, &provider, &channel_id, &id.fingerprint, &vk).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn different_sender_different_key() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = super::super::group::GhostGroup::create(&provider, &id, None).unwrap();

        let channel_id = [0xFFu8; 32];
        let fp_a = [0xAAu8; 32];
        let fp_b = [0xBBu8; 32];
        let vk = [0x00u8; 32];
        let key_a = derive_voice_key(&group, &provider, &channel_id, &fp_a, &vk).unwrap();
        let key_b = derive_voice_key(&group, &provider, &channel_id, &fp_b, &vk).unwrap();
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn different_device_vk_different_key() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = super::super::group::GhostGroup::create(&provider, &id, None).unwrap();

        let channel_id = [0xFFu8; 32];
        let vk_a = [0xAAu8; 32];
        let vk_b = [0xBBu8; 32];
        let key_a = derive_voice_key(&group, &provider, &channel_id, &id.fingerprint, &vk_a).unwrap();
        let key_b = derive_voice_key(&group, &provider, &channel_id, &id.fingerprint, &vk_b).unwrap();
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn presence_state_roundtrip() {
        let state = PresenceState {
            fingerprint: [0xAA; 32],
            muted: true,
            deafened: false,
            device_vk: [0xDD; 32],
        };
        let bytes = state.to_bytes();
        let parsed = PresenceState::from_bytes(&bytes).unwrap();
        assert_eq!(state, parsed);
    }

    #[test]
    fn presence_seal_open_roundtrip() {
        let key = [0x42u8; 32];
        let state = PresenceState {
            fingerprint: [0xBB; 32],
            muted: false,
            deafened: true,
            device_vk: [0xDD; 32],
        };
        let blob = seal_presence(&key, &state).unwrap();
        let opened = open_presence(&key, &blob).unwrap();
        assert_eq!(state, opened);
    }

    #[test]
    fn presence_wrong_key_fails() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let state = PresenceState {
            fingerprint: [0xCC; 32],
            muted: false,
            deafened: false,
            device_vk: [0xDD; 32],
        };
        let blob = seal_presence(&key1, &state).unwrap();
        assert!(open_presence(&key2, &blob).is_err());
    }

    #[test]
    fn presence_trial_decryption() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = super::super::group::GhostGroup::create(&provider, &id, None).unwrap();

        let channel_id = [0xFFu8; 32];
        let sender_fp = id.fingerprint;

        let key = derive_presence_key(&group, &provider, &channel_id, &sender_fp).unwrap();
        let state = PresenceState {
            fingerprint: sender_fp,
            muted: true,
            deafened: false,
            device_vk: *id.verifying_key.as_bytes(),
        };
        let blob = seal_presence(&key, &state).unwrap();

        // Trial decryption with a list including the real sender
        let candidates = vec![[0xAA; 32], sender_fp, [0xBB; 32]];
        let opened = try_open_presence(&candidates, &group, &provider, &channel_id, &blob).unwrap();
        assert_eq!(opened.fingerprint, sender_fp);
        assert!(opened.muted);
    }

    #[test]
    fn presence_trial_decryption_fails_no_match() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = super::super::group::GhostGroup::create(&provider, &id, None).unwrap();

        let channel_id = [0xFFu8; 32];
        let key = derive_presence_key(&group, &provider, &channel_id, &id.fingerprint).unwrap();
        let state = PresenceState {
            fingerprint: id.fingerprint,
            muted: false,
            deafened: false,
            device_vk: *id.verifying_key.as_bytes(),
        };
        let blob = seal_presence(&key, &state).unwrap();

        // No matching fingerprint in candidates
        let candidates = vec![[0xAA; 32], [0xBB; 32]];
        assert!(try_open_presence(&candidates, &group, &provider, &channel_id, &blob).is_err());
    }

    #[test]
    fn different_channel_different_key() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = super::super::group::GhostGroup::create(&provider, &id, None).unwrap();

        let vk = *id.verifying_key.as_bytes();
        let key_a = derive_voice_key(&group, &provider, &[0xAA; 32], &id.fingerprint, &vk).unwrap();
        let key_b = derive_voice_key(&group, &provider, &[0xBB; 32], &id.fingerprint, &vk).unwrap();
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn presence_state_truncated_rejected() {
        assert!(PresenceState::from_bytes(&[0x00; 10]).is_err());
    }

    #[test]
    fn presence_key_differs_from_voice_key() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = super::super::group::GhostGroup::create(&provider, &id, None).unwrap();

        let channel_id = [0xFFu8; 32];
        let vk = *id.verifying_key.as_bytes();
        let voice = derive_voice_key(&group, &provider, &channel_id, &id.fingerprint, &vk).unwrap();
        let presence = derive_presence_key(&group, &provider, &channel_id, &id.fingerprint).unwrap();
        assert_ne!(voice, presence);
    }
}
