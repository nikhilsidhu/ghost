//! Voice keys from the MLS group: each sender's frame key (the frames themselves are
//! sealed in `ghost_media`) and the keys of sealed voice presence. Presence keys are per
//! device, derived from the group and the device the relay stamps as the sender, and
//! each seal is bound to that stamp and its channel: no member can pass presence off as
//! another's, and a blob cannot be re-attributed or moved to another channel.

use ghost_wire::presence::PresenceSender;

use crate::crypto::{aead, GhostProvider, VOICE_EXPORT_LABEL, VOICE_PRESENCE_EXPORT_LABEL};
use crate::error::{GhostError, Result};

use super::group::GhostGroup;

/// Each sender in a voice channel gets their own encryption key so nonces never collide.
/// `device_vk` ensures two devices sharing a fingerprint derive different keys.
/// `voice_salt` is a random 32-byte value generated per voice session to prevent
/// nonce reuse when reconnecting within the same MLS epoch.
pub fn derive_voice_key(
    group: &GhostGroup,
    provider: &GhostProvider,
    channel_id: &[u8; 32],
    sender_fp: &[u8; 32],
    device_vk: &[u8; 32],
    voice_salt: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut context = Vec::with_capacity(128);
    context.extend_from_slice(channel_id);
    context.extend_from_slice(sender_fp);
    context.extend_from_slice(device_vk);
    context.extend_from_slice(voice_salt);
    let secret = group.export_secret(provider, VOICE_EXPORT_LABEL, &context, 32)?;
    secret.try_into().map_err(|_| GhostError::Crypto("export key not 32 bytes".into()))
}

// --- Presence blob crypto ---

/// A device in a voice channel: who it is, as the relay stamped it, and what it sealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceState {
    pub fingerprint: [u8; 32],
    pub device_vk: [u8; 32],
    pub muted: bool,
    pub deafened: bool,
    /// Random value generated per voice session, mixed into key derivation to prevent
    /// AES-GCM nonce reuse when reconnecting within the same MLS epoch.
    pub voice_salt: [u8; 32],
}

/// Sealed body: `[muted:1][deafened:1][voice_salt:32]`.
const PRESENCE_BODY_LEN: usize = 34;
/// Binds a voice presence seal to its sender and channel.
const VOICE_PRESENCE_BINDING: &[u8] = b"ghost-voice-presence-v2";

impl PresenceState {
    /// The device's announcement for `sender`.
    pub fn new(sender: &PresenceSender, muted: bool, deafened: bool, voice_salt: [u8; 32]) -> Self {
        Self { fingerprint: sender.account_fp, device_vk: sender.device_vk, muted, deafened, voice_salt }
    }

    pub fn sender(&self) -> PresenceSender {
        PresenceSender { account_fp: self.fingerprint, device_vk: self.device_vk }
    }

    fn body(&self) -> [u8; PRESENCE_BODY_LEN] {
        let mut buf = [0u8; PRESENCE_BODY_LEN];
        buf[0] = self.muted as u8;
        buf[1] = self.deafened as u8;
        buf[2..].copy_from_slice(&self.voice_salt);
        buf
    }

    fn from_body(sender: &PresenceSender, data: &[u8]) -> Result<Self> {
        if data.len() != PRESENCE_BODY_LEN {
            return Err(GhostError::Crypto("voice presence body has the wrong length".into()));
        }
        Ok(Self::new(sender, data[0] != 0, data[1] != 0, data[2..].try_into().unwrap()))
    }
}

/// The key one device seals its presence in a voice channel with.
pub fn derive_presence_key(
    group: &GhostGroup,
    provider: &GhostProvider,
    channel_id: &[u8; 32],
    sender: &PresenceSender,
) -> Result<[u8; 32]> {
    let context = sender.binding(&[], channel_id);
    let secret = group.export_secret(provider, VOICE_PRESENCE_EXPORT_LABEL, &context, 32)?;
    secret.try_into().map_err(|_| GhostError::Crypto("export key not 32 bytes".into()))
}

/// Seal a device's presence in `channel_id`. Wire format: [nonce:12][ciphertext+tag].
pub fn seal_presence(key: &[u8; 32], channel_id: &[u8; 32], state: &PresenceState) -> Result<Vec<u8>> {
    let aad = state.sender().binding(VOICE_PRESENCE_BINDING, channel_id);
    aead::seal_bound(key, &state.body(), &aad, "voice presence")
}

/// Open a blob the relay attributed to `sender` in `channel_id`; it opens only if that
/// device sealed it for that channel.
pub fn open_presence(key: &[u8; 32], channel_id: &[u8; 32], sender: &PresenceSender, blob: &[u8]) -> Result<PresenceState> {
    let aad = sender.binding(VOICE_PRESENCE_BINDING, channel_id);
    let plaintext = aead::open_bound(key, blob, &aad, "voice presence")?;
    PresenceState::from_body(sender, &plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn group_of(id: &Identity) -> (GhostProvider, GhostGroup) {
        let provider = GhostProvider::new_in_memory().unwrap();
        let group = super::super::group::test_group(&provider, id, None);
        (provider, group)
    }

    #[test]
    fn voice_keys_differ_by_sender_device_salt_and_channel_and_are_deterministic() {
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let (provider, group) = group_of(&id);
        let (channel, fp, vk, salt) = ([0xFF; 32], id.fingerprint, *id.verifying_key.as_bytes(), [0x99; 32]);
        let key = derive_voice_key(&group, &provider, &channel, &fp, &vk, &salt).unwrap();
        assert_eq!(key, derive_voice_key(&group, &provider, &channel, &fp, &vk, &salt).unwrap());
        assert_ne!(key, derive_voice_key(&group, &provider, &channel, &[0xBB; 32], &vk, &salt).unwrap());
        assert_ne!(key, derive_voice_key(&group, &provider, &channel, &fp, &[0xBB; 32], &salt).unwrap());
        assert_ne!(key, derive_voice_key(&group, &provider, &channel, &fp, &vk, &[0xBB; 32]).unwrap());
        assert_ne!(key, derive_voice_key(&group, &provider, &[0xAA; 32], &fp, &vk, &salt).unwrap());
    }

    #[test]
    fn presence_opens_only_for_the_stamped_sender_and_channel() {
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let (provider, group) = group_of(&id);
        let channel = [0xFF; 32];
        let alice = PresenceSender { account_fp: id.fingerprint, device_vk: *id.verifying_key.as_bytes() };
        let key = derive_presence_key(&group, &provider, &channel, &alice).unwrap();
        let state = PresenceState::new(&alice, true, false, [0x11; 32]);
        let blob = seal_presence(&key, &channel, &state).unwrap();
        assert_eq!(open_presence(&key, &channel, &alice, &blob).unwrap(), state);

        assert!(open_presence(&[0x43; 32], &channel, &alice, &blob).is_err(), "wrong key");
        assert!(open_presence(&key, &[0xEE; 32], &alice, &blob).is_err(), "another channel");
        let other_device = PresenceSender { device_vk: [0x99; 32], ..alice };
        assert!(open_presence(&key, &channel, &other_device, &blob).is_err(), "stamped as another device");
        let bob = PresenceSender { account_fp: [0xBB; 32], device_vk: [0x99; 32] };
        let bobs_key = derive_presence_key(&group, &provider, &channel, &bob).unwrap();
        assert_ne!(key, bobs_key);
        assert!(open_presence(&bobs_key, &channel, &bob, &blob).is_err(), "stamped as another account");
        assert_ne!(key, derive_voice_key(&group, &provider, &channel, &alice.account_fp, &alice.device_vk, &[0x99; 32]).unwrap());
    }

    #[test]
    fn a_presence_body_must_be_whole() {
        let sender = PresenceSender { account_fp: [1; 32], device_vk: [2; 32] };
        assert!(PresenceState::from_body(&sender, &[0x00; 10]).is_err());
        assert!(PresenceState::from_body(&sender, &[0x00; PRESENCE_BODY_LEN + 1]).is_err());
    }
}
