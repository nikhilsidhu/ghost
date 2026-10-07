//! The passphrase-encrypted recovery material, replicated to every relay the
//! account uses so recovery still works when the home relay is gone. Relays
//! never decrypt it; they only order writes by `generation`.

use thiserror::Error;

pub const RECOVERY_BUNDLE_VERSION: u8 = 0x01;
pub const RECOVERY_BUNDLE_MAX_BYTES: usize = 8192;

#[derive(Debug, Error)]
pub enum RecoveryBundleError {
    #[error("recovery bundle: {0}")]
    Format(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryBundle {
    /// Last writer wins; relays refuse a write that does not increase it.
    pub generation: u64,
    /// Seed and sync key under the user's passphrase (Argon2id + AES-256-GCM).
    pub recovery_blob: Vec<u8>,
    /// Reserved for the encrypted master key once it leaves devices; empty today.
    pub master_blob: Vec<u8>,
}

impl RecoveryBundle {
    /// `[version:1][generation:8][blob_len:2][blob][master_len:2][master]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(13 + self.recovery_blob.len() + self.master_blob.len());
        buf.push(RECOVERY_BUNDLE_VERSION);
        buf.extend_from_slice(&self.generation.to_be_bytes());
        buf.extend_from_slice(&(self.recovery_blob.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.recovery_blob);
        buf.extend_from_slice(&(self.master_blob.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.master_blob);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, RecoveryBundleError> {
        let err = |msg: &str| RecoveryBundleError::Format(msg.into());
        if data.len() > RECOVERY_BUNDLE_MAX_BYTES {
            return Err(err("too large"));
        }
        if data.len() < 13 {
            return Err(err("too short"));
        }
        if data[0] != RECOVERY_BUNDLE_VERSION {
            return Err(err("unknown version"));
        }
        let generation = u64::from_be_bytes(data[1..9].try_into().unwrap());
        let blob_len = u16::from_be_bytes(data[9..11].try_into().unwrap()) as usize;
        let blob_end = 11 + blob_len;
        if data.len() < blob_end + 2 {
            return Err(err("recovery blob truncated"));
        }
        let master_len = u16::from_be_bytes(data[blob_end..blob_end + 2].try_into().unwrap()) as usize;
        if data.len() != blob_end + 2 + master_len {
            return Err(err("master blob length mismatch"));
        }
        if blob_len == 0 {
            return Err(err("empty recovery blob"));
        }
        Ok(Self {
            generation,
            recovery_blob: data[11..blob_end].to_vec(),
            master_blob: data[blob_end + 2..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let b = RecoveryBundle { generation: 7, recovery_blob: vec![1, 2, 3], master_blob: vec![] };
        assert_eq!(RecoveryBundle::from_bytes(&b.to_bytes()).unwrap(), b);
        let b = RecoveryBundle { generation: u64::MAX, recovery_blob: vec![9; 125], master_blob: vec![4; 10] };
        assert_eq!(RecoveryBundle::from_bytes(&b.to_bytes()).unwrap(), b);
    }

    #[test]
    fn rejects_malformed() {
        let mut bytes = RecoveryBundle { generation: 1, recovery_blob: vec![1], master_blob: vec![] }.to_bytes();
        bytes.push(0);
        assert!(RecoveryBundle::from_bytes(&bytes).is_err(), "trailing byte");
        let bytes = RecoveryBundle { generation: 1, recovery_blob: vec![], master_blob: vec![] }.to_bytes();
        assert!(RecoveryBundle::from_bytes(&bytes).is_err(), "empty blob");
        let mut bytes = RecoveryBundle { generation: 1, recovery_blob: vec![1], master_blob: vec![] }.to_bytes();
        bytes[0] = 2;
        assert!(RecoveryBundle::from_bytes(&bytes).is_err(), "version");
        assert!(RecoveryBundle::from_bytes(&vec![0u8; RECOVERY_BUNDLE_MAX_BYTES + 1]).is_err(), "size cap");
    }
}
