use std::collections::HashMap;

use crate::error::{GhostError, Result};
use crate::identity::log::LogState;

/// Binds an account fingerprint to an authorized device key at a specific identity log sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberBinding {
    pub account_fp: [u8; 32],
    pub idlog_seq: u64,
    pub device_key: [u8; 32],
}

/// Maps account fingerprints to authorized device keys within an MLS group.
/// Wire format: [count: 2 BE] ([account_fp: 32][idlog_seq: 8 BE][device_key: 32]) * count
#[derive(Debug, Clone, Default)]
pub struct GroupMembership {
    pub bindings: Vec<MemberBinding>,
}

const BINDING_SIZE: usize = 32 + 8 + 32; // 72 bytes per binding

impl GroupMembership {
    pub fn new() -> Self {
        Self { bindings: Vec::new() }
    }

    /// Add or update a binding. If the same (account_fp, device_key) exists, updates idlog_seq.
    pub fn add(&mut self, binding: MemberBinding) {
        if let Some(existing) = self.bindings.iter_mut().find(|b| {
            b.account_fp == binding.account_fp && b.device_key == binding.device_key
        }) {
            existing.idlog_seq = binding.idlog_seq;
        } else {
            self.bindings.push(binding);
        }
    }

    /// Remove all bindings for an account.
    pub fn remove_account(&mut self, account_fp: &[u8; 32]) {
        self.bindings.retain(|b| &b.account_fp != account_fp);
    }

    /// Remove a specific device binding.
    pub fn remove_device(&mut self, device_key: &[u8; 32]) {
        self.bindings.retain(|b| &b.device_key != device_key);
    }

    pub fn encode(&self) -> Vec<u8> {
        let count = self.bindings.len() as u16;
        let mut out = Vec::with_capacity(2 + self.bindings.len() * BINDING_SIZE);
        out.extend_from_slice(&count.to_be_bytes());
        for b in &self.bindings {
            out.extend_from_slice(&b.account_fp);
            out.extend_from_slice(&b.idlog_seq.to_be_bytes());
            out.extend_from_slice(&b.device_key);
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(GhostError::Format("membership extension too short".into()));
        }
        let count = u16::from_be_bytes([data[0], data[1]]) as usize;
        let expected = 2 + count * BINDING_SIZE;
        if data.len() != expected {
            return Err(GhostError::Format(format!(
                "membership extension: expected {expected} bytes, got {}",
                data.len()
            )));
        }
        let mut bindings = Vec::with_capacity(count);
        let mut offset = 2;
        for _ in 0..count {
            let account_fp: [u8; 32] = data[offset..offset + 32].try_into().unwrap();
            offset += 32;
            let idlog_seq = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let device_key: [u8; 32] = data[offset..offset + 32].try_into().unwrap();
            offset += 32;
            bindings.push(MemberBinding { account_fp, idlog_seq, device_key });
        }
        Ok(Self { bindings })
    }

    /// Validate all bindings against a cache of identity log states.
    /// Returns an error if any binding's device key is not authorized in the corresponding log.
    pub fn validate(&self, log_cache: &HashMap<[u8; 32], LogState>) -> Result<()> {
        for b in &self.bindings {
            let state = log_cache.get(&b.account_fp).ok_or_else(|| {
                GhostError::IdentityLog(format!(
                    "no identity log for account {}",
                    hex::encode(&b.account_fp[..8])
                ))
            })?;

            let device = state.devices.get(&b.device_key).ok_or_else(|| {
                GhostError::IdentityLog(format!(
                    "device key {} not found in identity log for {}",
                    hex::encode(&b.device_key[..8]),
                    hex::encode(&b.account_fp[..8])
                ))
            })?;

            if !device.is_active() {
                return Err(GhostError::IdentityLog(format!(
                    "device key {} was revoked for {}",
                    hex::encode(&b.device_key[..8]),
                    hex::encode(&b.account_fp[..8])
                )));
            }

            if b.idlog_seq > state.head_seq {
                return Err(GhostError::IdentityLog(format!(
                    "binding idlog_seq {} exceeds log head {} for {}",
                    b.idlog_seq,
                    state.head_seq,
                    hex::encode(&b.account_fp[..8])
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::log::DeviceInfo;

    fn fp(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn encode_decode_empty() {
        let m = GroupMembership::new();
        let bytes = m.encode();
        assert_eq!(bytes.len(), 2);
        let decoded = GroupMembership::decode(&bytes).unwrap();
        assert!(decoded.bindings.is_empty());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut m = GroupMembership::new();
        m.add(MemberBinding { account_fp: fp(0x01), idlog_seq: 1, device_key: fp(0xAA) });
        m.add(MemberBinding { account_fp: fp(0x02), idlog_seq: 3, device_key: fp(0xBB) });
        m.add(MemberBinding { account_fp: fp(0x01), idlog_seq: 2, device_key: fp(0xCC) });

        let bytes = m.encode();
        assert_eq!(bytes.len(), 2 + 3 * BINDING_SIZE);

        let decoded = GroupMembership::decode(&bytes).unwrap();
        assert_eq!(decoded.bindings.len(), 3);
        assert_eq!(decoded.bindings[0].account_fp, fp(0x01));
        assert_eq!(decoded.bindings[0].idlog_seq, 1);
        assert_eq!(decoded.bindings[0].device_key, fp(0xAA));
        assert_eq!(decoded.bindings[1].idlog_seq, 3);
        assert_eq!(decoded.bindings[2].device_key, fp(0xCC));
    }

    #[test]
    fn add_updates_existing() {
        let mut m = GroupMembership::new();
        m.add(MemberBinding { account_fp: fp(0x01), idlog_seq: 1, device_key: fp(0xAA) });
        m.add(MemberBinding { account_fp: fp(0x01), idlog_seq: 5, device_key: fp(0xAA) });
        assert_eq!(m.bindings.len(), 1);
        assert_eq!(m.bindings[0].idlog_seq, 5);
    }

    #[test]
    fn remove_account() {
        let mut m = GroupMembership::new();
        m.add(MemberBinding { account_fp: fp(0x01), idlog_seq: 1, device_key: fp(0xAA) });
        m.add(MemberBinding { account_fp: fp(0x01), idlog_seq: 2, device_key: fp(0xBB) });
        m.add(MemberBinding { account_fp: fp(0x02), idlog_seq: 1, device_key: fp(0xCC) });
        m.remove_account(&fp(0x01));
        assert_eq!(m.bindings.len(), 1);
        assert_eq!(m.bindings[0].account_fp, fp(0x02));
    }

    #[test]
    fn remove_device() {
        let mut m = GroupMembership::new();
        m.add(MemberBinding { account_fp: fp(0x01), idlog_seq: 1, device_key: fp(0xAA) });
        m.add(MemberBinding { account_fp: fp(0x01), idlog_seq: 2, device_key: fp(0xBB) });
        m.remove_device(&fp(0xAA));
        assert_eq!(m.bindings.len(), 1);
        assert_eq!(m.bindings[0].device_key, fp(0xBB));
    }

    #[test]
    fn decode_rejects_truncated() {
        assert!(GroupMembership::decode(&[]).is_err());
        assert!(GroupMembership::decode(&[0x00, 0x01]).is_err()); // claims 1 entry, no data
    }

    #[test]
    fn decode_rejects_wrong_length() {
        let mut data = vec![0x00, 0x01]; // 1 entry
        data.extend_from_slice(&[0u8; 50]); // too short (needs 72)
        assert!(GroupMembership::decode(&data).is_err());
    }

    #[test]
    fn validate_accepts_authorized_device() {
        let mut m = GroupMembership::new();
        m.add(MemberBinding { account_fp: fp(0x01), idlog_seq: 1, device_key: fp(0xAA) });

        let mut cache = HashMap::new();
        let mut state = LogState {
            account_fp: fp(0x01),
            master_verifying_key: Some(fp(0xFF)),
            devices: HashMap::new(),
            head_seq: 2,
            head_hash: [0u8; 32],
        };
        state.devices.insert(fp(0xAA), DeviceInfo {
            verifying_key: fp(0xAA),
            added_at_seq: 1,
            label: "device-1".into(),
            revoked_at_seq: None,
        });
        cache.insert(fp(0x01), state);

        assert!(m.validate(&cache).is_ok());
    }

    #[test]
    fn validate_rejects_revoked_device() {
        let mut m = GroupMembership::new();
        m.add(MemberBinding { account_fp: fp(0x01), idlog_seq: 1, device_key: fp(0xAA) });

        let mut cache = HashMap::new();
        let mut state = LogState {
            account_fp: fp(0x01),
            master_verifying_key: Some(fp(0xFF)),
            devices: HashMap::new(),
            head_seq: 3,
            head_hash: [0u8; 32],
        };
        state.devices.insert(fp(0xAA), DeviceInfo {
            verifying_key: fp(0xAA),
            added_at_seq: 1,
            label: "device-1".into(),
            revoked_at_seq: Some(2),
        });
        cache.insert(fp(0x01), state);

        assert!(m.validate(&cache).is_err());
    }

    #[test]
    fn validate_rejects_unknown_device() {
        let mut m = GroupMembership::new();
        m.add(MemberBinding { account_fp: fp(0x01), idlog_seq: 1, device_key: fp(0xAA) });

        let mut cache = HashMap::new();
        cache.insert(fp(0x01), LogState {
            account_fp: fp(0x01),
            master_verifying_key: Some(fp(0xFF)),
            devices: HashMap::new(),
            head_seq: 2,
            head_hash: [0u8; 32],
        });

        assert!(m.validate(&cache).is_err());
    }

    #[test]
    fn validate_rejects_missing_log() {
        let mut m = GroupMembership::new();
        m.add(MemberBinding { account_fp: fp(0x01), idlog_seq: 1, device_key: fp(0xAA) });
        let cache = HashMap::new();
        assert!(m.validate(&cache).is_err());
    }
}
