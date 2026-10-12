//! Online presence (status, status message, avatar), sealed per server so only members
//! read it. Each sending device has its own key, derived from the group and the device
//! the relay stamps as the sender, and the seal is bound to that stamp: a member cannot
//! pass presence off as another's, and the relay cannot re-attribute a blob it holds.

use ghost_wire::bytes::{put_prefixed16, Reader};
use ghost_wire::presence::PresenceSender;

use crate::crypto::{aead, GhostProvider, ONLINE_PRESENCE_EXPORT_LABEL};
use crate::error::{GhostError, Result};

use super::group::GhostGroup;

/// Online availability status, broadcast via encrypted presence blobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OnlineStatus {
    Online = 0,
    Idle = 1,
    Away = 2,
    Invisible = 3,
}

impl OnlineStatus {
    /// The status a user chose, as stored in settings ("online", "away", "invisible").
    /// Idle is never chosen: it follows inactivity.
    pub fn from_config(value: &str) -> Self {
        match value {
            "away" => Self::Away,
            "invisible" => Self::Invisible,
            _ => Self::Online,
        }
    }
}

impl TryFrom<u8> for OnlineStatus {
    type Error = GhostError;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::Online),
            1 => Ok(Self::Idle),
            2 => Ok(Self::Away),
            3 => Ok(Self::Invisible),
            _ => Err(GhostError::Crypto("invalid online status".into())),
        }
    }
}

/// A user's avatar as announced: the hash naming the sealed version the relay holds,
/// and the key that opens it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvatarRef {
    pub hash: [u8; 32],
    pub key: [u8; 32],
}

/// What a device announces about its user, server-wide. Who announced it is the
/// relay's stamp, not part of the sealed body. The avatar's key rides along, so a member
/// who joined after it was announced can still open it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnlinePresence {
    pub status: OnlineStatus,
    pub status_message: Option<String>,
    pub status_expiry: Option<u64>,
    pub avatar: Option<AvatarRef>,
}

// Wire format: [status:1][flags:1][optional fields...]
// flags bit 0 = has_message, bit 1 = has_expiry, bit 2 = has_avatar
// message: [len_be16:2][utf8 bytes]
// expiry: [be64:8]
// avatar: [hash:32][key:32]

const FLAG_HAS_MESSAGE: u8 = 0x01;
const FLAG_HAS_EXPIRY: u8 = 0x02;
const FLAG_HAS_AVATAR: u8 = 0x04;

/// Binds an online presence seal to its sender.
const ONLINE_PRESENCE_BINDING: &[u8] = b"ghost-online-presence-v3";

impl OnlinePresence {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(48);
        buf.push(self.status as u8);
        let mut flags = 0u8;
        if self.status_message.is_some() {
            flags |= FLAG_HAS_MESSAGE;
        }
        if self.status_expiry.is_some() {
            flags |= FLAG_HAS_EXPIRY;
        }
        if self.avatar.is_some() {
            flags |= FLAG_HAS_AVATAR;
        }
        buf.push(flags);
        if let Some(ref msg) = self.status_message {
            let bytes = msg.as_bytes();
            put_prefixed16(&mut buf, &bytes[..bytes.len().min(u16::MAX as usize)]);
        }
        if let Some(expiry) = self.status_expiry {
            buf.extend_from_slice(&expiry.to_be_bytes());
        }
        if let Some(ref avatar) = self.avatar {
            buf.extend_from_slice(&avatar.hash);
            buf.extend_from_slice(&avatar.key);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let status = OnlineStatus::try_from(r.u8()?)?;
        let flags = r.u8()?;
        let status_message = if flags & FLAG_HAS_MESSAGE != 0 { Some(r.string()?) } else { None };
        let status_expiry = if flags & FLAG_HAS_EXPIRY != 0 { Some(r.u64()?) } else { None };
        let avatar = if flags & FLAG_HAS_AVATAR != 0 { Some(AvatarRef { hash: r.array()?, key: r.array()? }) } else { None };
        Ok(Self { status, status_message, status_expiry, avatar })
    }
}

/// The key one device seals its online presence with in this group.
pub fn derive_online_presence_key(group: &GhostGroup, provider: &GhostProvider, sender: &PresenceSender) -> Result<[u8; 32]> {
    let context = sender.binding(&[], &[]);
    let secret = group.export_secret(provider, ONLINE_PRESENCE_EXPORT_LABEL, &context, 32)?;
    secret.try_into().map_err(|_| GhostError::Crypto("export key not 32 bytes".into()))
}

/// Seal `state` as sent by `sender`. Wire format: [nonce:12][ciphertext+tag].
pub fn seal_online_presence(key: &[u8; 32], sender: &PresenceSender, state: &OnlinePresence) -> Result<Vec<u8>> {
    aead::seal_bound(key, &state.to_bytes(), &sender.binding(ONLINE_PRESENCE_BINDING, &[]), "online presence")
}

/// Open a blob the relay attributed to `sender`; it opens only if `sender` sealed it.
pub fn open_online_presence(key: &[u8; 32], sender: &PresenceSender, blob: &[u8]) -> Result<OnlinePresence> {
    let plaintext = aead::open_bound(key, blob, &sender.binding(ONLINE_PRESENCE_BINDING, &[]), "online presence")?;
    OnlinePresence::from_bytes(&plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn sender(account: u8, device: u8) -> PresenceSender {
        PresenceSender { account_fp: [account; 32], device_vk: [device; 32] }
    }

    fn state(status: OnlineStatus) -> OnlinePresence {
        OnlinePresence { status, status_message: None, status_expiry: None, avatar: None }
    }

    #[test]
    fn online_presence_roundtrips_with_any_combination_of_fields() {
        let full = OnlinePresence {
            status: OnlineStatus::Away,
            status_message: Some("brb lunch".into()),
            status_expiry: Some(1700000000000),
            avatar: Some(AvatarRef { hash: [0xCC; 32], key: [0xDD; 32] }),
        };
        let only_expiry_and_avatar = OnlinePresence { status_message: None, ..full.clone() };
        for state in [state(OnlineStatus::Online), full, only_expiry_and_avatar] {
            assert_eq!(OnlinePresence::from_bytes(&state.to_bytes()).unwrap(), state);
        }
        assert_eq!(state(OnlineStatus::Online).to_bytes().len(), 2);
        assert!(OnlinePresence::from_bytes(&[0x00]).is_err());
        assert!(OnlinePresence::from_bytes(&[0x00, FLAG_HAS_AVATAR, 0x01]).is_err(), "truncated avatar hash");
        let mut hash_alone = vec![0x00, FLAG_HAS_AVATAR];
        hash_alone.extend_from_slice(&[0xCC; 32]);
        assert!(OnlinePresence::from_bytes(&hash_alone).is_err(), "an avatar without its key");
    }

    #[test]
    fn a_blob_opens_only_for_the_sender_the_relay_stamped() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = super::super::group::test_group(&provider, &id, None);
        let alice = PresenceSender { account_fp: id.fingerprint, device_vk: *id.verifying_key.as_bytes() };
        let key = derive_online_presence_key(&group, &provider, &alice).unwrap();
        let blob = seal_online_presence(&key, &alice, &state(OnlineStatus::Idle)).unwrap();
        assert_eq!(open_online_presence(&key, &alice, &blob).unwrap().status, OnlineStatus::Idle);

        // Stamped as another device or account, even with the right key, it does not open.
        let other_device = PresenceSender { device_vk: [0x99; 32], ..alice };
        assert!(open_online_presence(&key, &other_device, &blob).is_err());
        let other_key = derive_online_presence_key(&group, &provider, &sender(0xBB, 0x99)).unwrap();
        assert_ne!(key, other_key, "each device has its own key");
        assert!(open_online_presence(&other_key, &sender(0xBB, 0x99), &blob).is_err());
        assert!(open_online_presence(&[0x43; 32], &alice, &blob).is_err());
    }

    #[test]
    fn key_differs_from_voice_presence_key() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = super::super::group::test_group(&provider, &id, None);
        let alice = PresenceSender { account_fp: id.fingerprint, device_vk: *id.verifying_key.as_bytes() };
        let voice = super::super::voice::derive_presence_key(&group, &provider, &[0xFF; 32], &alice).unwrap();
        let online = derive_online_presence_key(&group, &provider, &alice).unwrap();
        assert_ne!(voice, online);
    }
}
