use aes_gcm::aead::{Aead, AeadCore, OsRng};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

use crate::crypto::{GhostProvider, ONLINE_PRESENCE_EXPORT_LABEL};
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

/// Online presence state, encrypted and broadcast server-wide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnlinePresence {
    pub fingerprint: [u8; 32],
    pub status: OnlineStatus,
    pub status_message: Option<String>,
    pub status_expiry: Option<u64>,
    pub avatar_hash: Option<[u8; 32]>,
}

// Wire format: [fp:32][status:1][flags:1][optional fields...]
// flags bit 0 = has_message, bit 1 = has_expiry, bit 2 = has_avatar_hash
// message: [len_le16:2][utf8 bytes]
// expiry: [be64:8]
// avatar_hash: [32]

const FLAG_HAS_MESSAGE: u8 = 0x01;
const FLAG_HAS_EXPIRY: u8 = 0x02;
const FLAG_HAS_AVATAR_HASH: u8 = 0x04;

impl OnlinePresence {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&self.fingerprint);
        buf.push(self.status as u8);
        let mut flags = 0u8;
        if self.status_message.is_some() { flags |= FLAG_HAS_MESSAGE; }
        if self.status_expiry.is_some() { flags |= FLAG_HAS_EXPIRY; }
        if self.avatar_hash.is_some() { flags |= FLAG_HAS_AVATAR_HASH; }
        buf.push(flags);
        if let Some(ref msg) = self.status_message {
            let bytes = msg.as_bytes();
            let len = bytes.len().min(u16::MAX as usize);
            buf.extend_from_slice(&(len as u16).to_le_bytes());
            buf.extend_from_slice(&bytes[..len]);
        }
        if let Some(expiry) = self.status_expiry {
            buf.extend_from_slice(&expiry.to_be_bytes());
        }
        if let Some(ref hash) = self.avatar_hash {
            buf.extend_from_slice(hash);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 34 {
            return Err(GhostError::Crypto("online presence too short".into()));
        }
        let fingerprint: [u8; 32] = data[0..32].try_into().unwrap();
        let status = OnlineStatus::try_from(data[32])?;
        let flags = data[33];
        let mut offset = 34;

        let status_message = if flags & FLAG_HAS_MESSAGE != 0 {
            if data.len() < offset + 2 {
                return Err(GhostError::Crypto("truncated message length".into()));
            }
            let len = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;
            if data.len() < offset + len {
                return Err(GhostError::Crypto("truncated message body".into()));
            }
            let msg = std::str::from_utf8(&data[offset..offset + len])
                .map_err(|_| GhostError::Crypto("invalid utf8 in status message".into()))?
                .to_string();
            offset += len;
            Some(msg)
        } else {
            None
        };

        let status_expiry = if flags & FLAG_HAS_EXPIRY != 0 {
            if data.len() < offset + 8 {
                return Err(GhostError::Crypto("truncated expiry".into()));
            }
            let expiry = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
            offset += 8;
            Some(expiry)
        } else {
            None
        };

        let avatar_hash = if flags & FLAG_HAS_AVATAR_HASH != 0 {
            if data.len() < offset + 32 {
                return Err(GhostError::Crypto("truncated avatar hash".into()));
            }
            let hash: [u8; 32] = data[offset..offset + 32].try_into().unwrap();
            Some(hash)
        } else {
            None
        };

        Ok(Self { fingerprint, status, status_message, status_expiry, avatar_hash })
    }
}

/// Derive per-sender online presence key. Context = sender fingerprint only (server-wide).
pub fn derive_online_presence_key(
    group: &GhostGroup,
    provider: &GhostProvider,
    sender_fp: &[u8; 32],
) -> Result<[u8; 32]> {
    let secret = group.export_secret(provider, ONLINE_PRESENCE_EXPORT_LABEL, sender_fp, 32)?;
    let key: [u8; 32] = secret
        .try_into()
        .map_err(|_| GhostError::Crypto("export key not 32 bytes".into()))?;
    Ok(key)
}

/// Encrypt an online presence blob. Wire format: [nonce:12][ciphertext+tag].
pub fn seal_online_presence(key: &[u8; 32], state: &OnlinePresence) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let plaintext = state.to_bytes();
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|e| GhostError::Crypto(format!("online presence seal: {e}")))?;
    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypt an online presence blob.
pub fn open_online_presence(key: &[u8; 32], blob: &[u8]) -> Result<OnlinePresence> {
    if blob.len() < 12 + 16 {
        return Err(GhostError::Crypto("online presence blob too short".into()));
    }
    let nonce = Nonce::from_slice(&blob[..12]);
    let ciphertext = &blob[12..];
    let cipher = Aes256Gcm::new(key.into());
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| GhostError::Crypto("online presence open: auth failed".into()))?;
    OnlinePresence::from_bytes(&plaintext)
}

/// Trial-decrypt an online presence blob against all member keys.
pub fn try_open_online_presence(
    member_fps: &[[u8; 32]],
    group: &GhostGroup,
    provider: &GhostProvider,
    blob: &[u8],
) -> Result<OnlinePresence> {
    for fp in member_fps {
        if let Ok(key) = derive_online_presence_key(group, provider, fp) {
            if let Ok(state) = open_online_presence(&key, blob) {
                if state.fingerprint == *fp {
                    return Ok(state);
                }
            }
        }
    }
    Err(GhostError::Crypto("no member key decrypts this online presence blob".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    #[test]
    fn online_presence_roundtrip_minimal() {
        let state = OnlinePresence {
            fingerprint: [0xAA; 32],
            status: OnlineStatus::Online,
            status_message: None,
            status_expiry: None,
            avatar_hash: None,
        };
        let bytes = state.to_bytes();
        assert_eq!(bytes.len(), 34);
        let parsed = OnlinePresence::from_bytes(&bytes).unwrap();
        assert_eq!(state, parsed);
    }

    #[test]
    fn online_presence_roundtrip_full() {
        let state = OnlinePresence {
            fingerprint: [0xBB; 32],
            status: OnlineStatus::Away,
            status_message: Some("brb lunch".into()),
            status_expiry: Some(1700000000000),
            avatar_hash: Some([0xCC; 32]),
        };
        let bytes = state.to_bytes();
        let parsed = OnlinePresence::from_bytes(&bytes).unwrap();
        assert_eq!(state, parsed);
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = [0x42u8; 32];
        let state = OnlinePresence {
            fingerprint: [0xDD; 32],
            status: OnlineStatus::Idle,
            status_message: Some("afk".into()),
            status_expiry: None,
            avatar_hash: None,
        };
        let blob = seal_online_presence(&key, &state).unwrap();
        let opened = open_online_presence(&key, &blob).unwrap();
        assert_eq!(state, opened);
    }

    #[test]
    fn wrong_key_fails() {
        let state = OnlinePresence {
            fingerprint: [0xEE; 32],
            status: OnlineStatus::Online,
            status_message: None,
            status_expiry: None,
            avatar_hash: None,
        };
        let blob = seal_online_presence(&[0x42; 32], &state).unwrap();
        assert!(open_online_presence(&[0x43; 32], &blob).is_err());
    }

    #[test]
    fn trial_decryption() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = super::super::group::GhostGroup::create(&provider, &id).unwrap();

        let key = derive_online_presence_key(&group, &provider, &id.fingerprint).unwrap();
        let state = OnlinePresence {
            fingerprint: id.fingerprint,
            status: OnlineStatus::Online,
            status_message: Some("hello".into()),
            status_expiry: None,
            avatar_hash: None,
        };
        let blob = seal_online_presence(&key, &state).unwrap();

        let candidates = vec![[0xAA; 32], id.fingerprint, [0xBB; 32]];
        let opened = try_open_online_presence(&candidates, &group, &provider, &blob).unwrap();
        assert_eq!(opened.fingerprint, id.fingerprint);
        assert_eq!(opened.status, OnlineStatus::Online);
        assert_eq!(opened.status_message.as_deref(), Some("hello"));
    }

    #[test]
    fn key_differs_from_voice_presence_key() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01u8; 32]).unwrap();
        let group = super::super::group::GhostGroup::create(&provider, &id).unwrap();

        let channel_id = [0xFF; 32];
        let voice = super::super::voice::derive_presence_key(
            &group, &provider, &channel_id, &id.fingerprint,
        ).unwrap();
        let online = derive_online_presence_key(&group, &provider, &id.fingerprint).unwrap();
        assert_ne!(voice, online);
    }
}
