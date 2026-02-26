use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use std::collections::HashMap;

use crate::crypto::IDLOG_SIGN_PREFIX;
use crate::error::{GhostError, Result};

// ── Entry types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryType {
    Genesis = 0x01,
    AddDevice = 0x02,
    RevokeDevice = 0x03,
    Recovery = 0x04,
}

impl TryFrom<u8> for EntryType {
    type Error = u8;
    fn try_from(v: u8) -> std::result::Result<Self, u8> {
        match v {
            0x01 => Ok(Self::Genesis),
            0x02 => Ok(Self::AddDevice),
            0x03 => Ok(Self::RevokeDevice),
            0x04 => Ok(Self::Recovery),
            other => Err(other),
        }
    }
}

// ── Entry body variants ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum EntryBody {
    Genesis {
        master_verifying_key: [u8; 32],
        device_verifying_key: [u8; 32],
        device_label: String,
    },
    AddDevice {
        device_verifying_key: [u8; 32],
        device_label: String,
        authorizer_key: [u8; 32],
    },
    RevokeDevice {
        device_verifying_key: [u8; 32],
        revoker_key: [u8; 32],
    },
    Recovery {
        device_verifying_key: [u8; 32],
        device_label: String,
    },
}

// ── Log entry ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub seq: u64,
    pub prev_hash: [u8; 32],
    pub account_fp: [u8; 32],
    pub entry_type: EntryType,
    pub timestamp: u64,
    pub body: EntryBody,
    pub signature: [u8; 64],
    pub counter_signature: Option<[u8; 64]>,
}

// ── Tracked device state ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub verifying_key: [u8; 32],
    pub label: String,
    pub added_at_seq: u64,
    pub revoked_at_seq: Option<u64>,
}

impl DeviceInfo {
    pub fn is_active(&self) -> bool {
        self.revoked_at_seq.is_none()
    }
}

// ── Cumulative log state ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LogState {
    pub account_fp: [u8; 32],
    pub master_verifying_key: Option<[u8; 32]>,
    pub devices: HashMap<[u8; 32], DeviceInfo>,
    pub head_seq: u64,
    pub head_hash: [u8; 32],
}

impl LogState {
    pub fn empty(account_fp: [u8; 32]) -> Self {
        Self {
            account_fp,
            master_verifying_key: None,
            devices: HashMap::new(),
            head_seq: 0,
            head_hash: [0u8; 32],
        }
    }

    pub fn active_devices(&self) -> impl Iterator<Item = &DeviceInfo> {
        self.devices.values().filter(|d| d.is_active())
    }

    pub fn is_active_device(&self, key: &[u8; 32]) -> bool {
        self.devices.get(key).map_or(false, |d| d.is_active())
    }
}

// ── Deterministic binary encoding ───────────────────────────────────

fn encode_body(buf: &mut Vec<u8>, body: &EntryBody) {
    match body {
        EntryBody::Genesis { master_verifying_key, device_verifying_key, device_label } => {
            buf.extend_from_slice(master_verifying_key);
            buf.extend_from_slice(device_verifying_key);
            let label = device_label.as_bytes();
            buf.extend_from_slice(&(label.len() as u16).to_be_bytes());
            buf.extend_from_slice(label);
        }
        EntryBody::AddDevice { device_verifying_key, device_label, authorizer_key } => {
            buf.extend_from_slice(device_verifying_key);
            let label = device_label.as_bytes();
            buf.extend_from_slice(&(label.len() as u16).to_be_bytes());
            buf.extend_from_slice(label);
            buf.extend_from_slice(authorizer_key);
        }
        EntryBody::RevokeDevice { device_verifying_key, revoker_key } => {
            buf.extend_from_slice(device_verifying_key);
            buf.extend_from_slice(revoker_key);
        }
        EntryBody::Recovery { device_verifying_key, device_label } => {
            buf.extend_from_slice(device_verifying_key);
            let label = device_label.as_bytes();
            buf.extend_from_slice(&(label.len() as u16).to_be_bytes());
            buf.extend_from_slice(label);
        }
    }
}

fn canonical_bytes(entry: &LogEntry) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&entry.seq.to_be_bytes());
    buf.extend_from_slice(&entry.prev_hash);
    buf.extend_from_slice(&entry.account_fp);
    buf.push(entry.entry_type as u8);
    buf.extend_from_slice(&entry.timestamp.to_be_bytes());
    encode_body(&mut buf, &entry.body);
    buf
}

fn sign_message(entry: &LogEntry) -> Vec<u8> {
    let mut msg = Vec::with_capacity(IDLOG_SIGN_PREFIX.len() + 128);
    msg.extend_from_slice(IDLOG_SIGN_PREFIX);
    msg.extend_from_slice(&canonical_bytes(entry));
    msg
}

/// Hash of the full wire-format entry. Used as prev_hash for the next entry in the chain.
/// Must match what the relay computes (blake3 of the stored payload bytes).
pub fn entry_hash(entry: &LogEntry) -> [u8; 32] {
    blake3::hash(&entry.to_bytes()).into()
}

// ── Signature helpers ───────────────────────────────────────────────

fn verify_sig(key_bytes: &[u8; 32], entry: &LogEntry) -> Result<()> {
    let key = VerifyingKey::from_bytes(key_bytes)
        .map_err(|e| GhostError::InvalidKey(format!("bad verifying key: {e}")))?;
    let sig = Signature::from_bytes(&entry.signature);
    key.verify_strict(&sign_message(entry), &sig)
        .map_err(|_| GhostError::AuthenticationFailed)
}

fn verify_counter_sig(key_bytes: &[u8; 32], entry: &LogEntry) -> Result<()> {
    let cs = entry.counter_signature
        .ok_or_else(|| GhostError::Format("missing counter-signature".into()))?;
    let key = VerifyingKey::from_bytes(key_bytes)
        .map_err(|e| GhostError::InvalidKey(format!("bad verifying key: {e}")))?;
    let sig = Signature::from_bytes(&cs);
    key.verify_strict(&sign_message(entry), &sig)
        .map_err(|_| GhostError::AuthenticationFailed)
}

fn sign_entry(key: &SigningKey, entry: &mut LogEntry) {
    use ed25519_dalek::Signer;
    entry.signature = key.sign(&sign_message(entry)).to_bytes();
}

fn counter_sign(key: &SigningKey, entry: &mut LogEntry) {
    use ed25519_dalek::Signer;
    entry.counter_signature = Some(key.sign(&sign_message(entry)).to_bytes());
}

// ── Chain validation ────────────────────────────────────────────────

pub fn validate_chain(entries: &[LogEntry]) -> Result<LogState> {
    if entries.is_empty() {
        return Err(GhostError::Format("empty identity log".into()));
    }
    let mut state = LogState::empty(entries[0].account_fp);
    for entry in entries {
        validate_entry(&mut state, entry)?;
    }
    Ok(state)
}

pub fn validate_entry(state: &mut LogState, entry: &LogEntry) -> Result<()> {
    // Seq must be exactly next
    if entry.seq != state.head_seq + 1 {
        return Err(GhostError::Format(format!(
            "idlog: expected seq {}, got {}", state.head_seq + 1, entry.seq
        )));
    }

    // prev_hash must match
    if entry.seq == 1 {
        if entry.prev_hash != [0u8; 32] {
            return Err(GhostError::Format("idlog: genesis prev_hash must be zeroed".into()));
        }
    } else if entry.prev_hash != state.head_hash {
        return Err(GhostError::Format("idlog: prev_hash mismatch".into()));
    }

    // Account fingerprint must be consistent
    if entry.account_fp != state.account_fp {
        return Err(GhostError::Format("idlog: account_fp mismatch".into()));
    }

    match &entry.body {
        EntryBody::Genesis { master_verifying_key, device_verifying_key, device_label } => {
            if entry.seq != 1 {
                return Err(GhostError::Format("idlog: genesis must be seq 1".into()));
            }
            // Fingerprint = Blake3(master_verifying_key)
            let expected_fp: [u8; 32] = blake3::hash(master_verifying_key).into();
            if expected_fp != state.account_fp {
                return Err(GhostError::Format("idlog: fingerprint doesn't match master key".into()));
            }
            verify_sig(master_verifying_key, entry)?;
            verify_counter_sig(device_verifying_key, entry)?;

            state.master_verifying_key = Some(*master_verifying_key);
            state.devices.insert(*device_verifying_key, DeviceInfo {
                verifying_key: *device_verifying_key,
                label: device_label.clone(),
                added_at_seq: 1,
                revoked_at_seq: None,
            });
        }

        EntryBody::AddDevice { device_verifying_key, device_label, authorizer_key } => {
            let master = state.master_verifying_key
                .ok_or_else(|| GhostError::Format("idlog: AddDevice before genesis".into()))?;

            // Authorizer must be master key or active device
            if *authorizer_key != master && !state.is_active_device(authorizer_key) {
                return Err(GhostError::Format("idlog: unauthorized signer".into()));
            }
            verify_sig(authorizer_key, entry)?;
            verify_counter_sig(device_verifying_key, entry)?;

            // Must not already exist
            if state.devices.contains_key(device_verifying_key) {
                return Err(GhostError::Format("idlog: duplicate device key".into()));
            }

            state.devices.insert(*device_verifying_key, DeviceInfo {
                verifying_key: *device_verifying_key,
                label: device_label.clone(),
                added_at_seq: entry.seq,
                revoked_at_seq: None,
            });
        }

        EntryBody::RevokeDevice { device_verifying_key, revoker_key } => {
            let master = state.master_verifying_key
                .ok_or_else(|| GhostError::Format("idlog: RevokeDevice before genesis".into()))?;

            // Revoker must be master or active device
            if *revoker_key != master && !state.is_active_device(revoker_key) {
                return Err(GhostError::Format("idlog: unauthorized revoker".into()));
            }
            // Can't revoke yourself
            if revoker_key == device_verifying_key {
                return Err(GhostError::Format("idlog: cannot self-revoke".into()));
            }
            // Target must be active
            if !state.is_active_device(device_verifying_key) {
                return Err(GhostError::Format("idlog: device not active".into()));
            }
            verify_sig(revoker_key, entry)?;

            state.devices.get_mut(device_verifying_key).unwrap().revoked_at_seq = Some(entry.seq);
        }

        EntryBody::Recovery { device_verifying_key, device_label } => {
            let master = state.master_verifying_key
                .ok_or_else(|| GhostError::Format("idlog: Recovery before genesis".into()))?;

            // Recovery must be signed by master key
            verify_sig(&master, entry)?;
            verify_counter_sig(device_verifying_key, entry)?;

            // Revoke all active devices
            for dev in state.devices.values_mut() {
                if dev.is_active() {
                    dev.revoked_at_seq = Some(entry.seq);
                }
            }

            state.devices.insert(*device_verifying_key, DeviceInfo {
                verifying_key: *device_verifying_key,
                label: device_label.clone(),
                added_at_seq: entry.seq,
                revoked_at_seq: None,
            });
        }
    }

    state.head_seq = entry.seq;
    state.head_hash = entry_hash(entry);
    Ok(())
}

// ── Entry creation helpers ──────────────────────────────────────────

pub fn create_genesis(
    master_key: &SigningKey,
    device_key: &SigningKey,
    device_label: &str,
) -> LogEntry {
    let master_vk = master_key.verifying_key();
    let device_vk = device_key.verifying_key();
    let account_fp: [u8; 32] = blake3::hash(master_vk.as_bytes()).into();

    let mut entry = LogEntry {
        seq: 1,
        prev_hash: [0u8; 32],
        account_fp,
        entry_type: EntryType::Genesis,
        timestamp: now_millis(),
        body: EntryBody::Genesis {
            master_verifying_key: master_vk.to_bytes(),
            device_verifying_key: device_vk.to_bytes(),
            device_label: device_label.to_string(),
        },
        signature: [0u8; 64],
        counter_signature: None,
    };
    sign_entry(master_key, &mut entry);
    counter_sign(device_key, &mut entry);
    entry
}

/// Build an AddDevice entry. Requires the authorizer's signing key and the new device's signing key.
pub fn create_add_device(
    state: &LogState,
    authorizer_key: &SigningKey,
    new_device_key: &SigningKey,
    device_label: &str,
) -> LogEntry {
    let mut entry = LogEntry {
        seq: state.head_seq + 1,
        prev_hash: state.head_hash,
        account_fp: state.account_fp,
        entry_type: EntryType::AddDevice,
        timestamp: now_millis(),
        body: EntryBody::AddDevice {
            device_verifying_key: new_device_key.verifying_key().to_bytes(),
            device_label: device_label.to_string(),
            authorizer_key: authorizer_key.verifying_key().to_bytes(),
        },
        signature: [0u8; 64],
        counter_signature: None,
    };
    sign_entry(authorizer_key, &mut entry);
    counter_sign(new_device_key, &mut entry);
    entry
}

pub fn create_revoke_device(
    state: &LogState,
    revoker_key: &SigningKey,
    target_device_key: &[u8; 32],
) -> LogEntry {
    let mut entry = LogEntry {
        seq: state.head_seq + 1,
        prev_hash: state.head_hash,
        account_fp: state.account_fp,
        entry_type: EntryType::RevokeDevice,
        timestamp: now_millis(),
        body: EntryBody::RevokeDevice {
            device_verifying_key: *target_device_key,
            revoker_key: revoker_key.verifying_key().to_bytes(),
        },
        signature: [0u8; 64],
        counter_signature: None,
    };
    sign_entry(revoker_key, &mut entry);
    entry
}

pub fn create_recovery(
    state: &LogState,
    master_key: &SigningKey,
    new_device_key: &SigningKey,
    device_label: &str,
) -> LogEntry {
    let mut entry = LogEntry {
        seq: state.head_seq + 1,
        prev_hash: state.head_hash,
        account_fp: state.account_fp,
        entry_type: EntryType::Recovery,
        timestamp: now_millis(),
        body: EntryBody::Recovery {
            device_verifying_key: new_device_key.verifying_key().to_bytes(),
            device_label: device_label.to_string(),
        },
        signature: [0u8; 64],
        counter_signature: None,
    };
    sign_entry(master_key, &mut entry);
    counter_sign(new_device_key, &mut entry);
    entry
}

// ── Wire serialization ──────────────────────────────────────────────

impl LogEntry {
    pub fn to_bytes(&self) -> Vec<u8> {
        let body_bytes = {
            let mut buf = Vec::new();
            encode_body(&mut buf, &self.body);
            buf
        };
        let has_counter: u8 = if self.counter_signature.is_some() { 1 } else { 0 };
        let total = 8 + 32 + 32 + 1 + 8 + 4 + body_bytes.len() + 64 + 1
            + if has_counter == 1 { 64 } else { 0 };

        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.prev_hash);
        buf.extend_from_slice(&self.account_fp);
        buf.push(self.entry_type as u8);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&(body_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&body_bytes);
        buf.extend_from_slice(&self.signature);
        buf.push(has_counter);
        if let Some(cs) = &self.counter_signature {
            buf.extend_from_slice(cs);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let err = |msg: &str| GhostError::Format(format!("idlog: {msg}"));

        // Fixed header: seq(8) + prev_hash(32) + account_fp(32) + type(1) + timestamp(8) + body_len(4) = 85
        if data.len() < 85 {
            return Err(err("too short for header"));
        }

        let seq = u64::from_be_bytes(data[0..8].try_into().unwrap());
        let prev_hash: [u8; 32] = data[8..40].try_into().unwrap();
        let account_fp: [u8; 32] = data[40..72].try_into().unwrap();
        let entry_type = EntryType::try_from(data[72])
            .map_err(|v| err(&format!("unknown entry type: {v:#x}")))?;
        let timestamp = u64::from_be_bytes(data[73..81].try_into().unwrap());
        let body_len = u32::from_be_bytes(data[81..85].try_into().unwrap()) as usize;

        let body_end = 85 + body_len;
        // After body: signature(64) + has_counter(1) + optional counter(64)
        if data.len() < body_end + 65 {
            return Err(err("too short for signature"));
        }

        let body_data = &data[85..body_end];
        let body = decode_body(entry_type, body_data)?;

        let signature: [u8; 64] = data[body_end..body_end + 64].try_into().unwrap();
        let has_counter = data[body_end + 64];
        let (counter_signature, expected_len) = if has_counter == 1 {
            if data.len() < body_end + 65 + 64 {
                return Err(err("too short for counter-signature"));
            }
            let cs: [u8; 64] = data[body_end + 65..body_end + 129].try_into().unwrap();
            (Some(cs), body_end + 129)
        } else {
            (None, body_end + 65)
        };

        if data.len() != expected_len {
            return Err(err(&format!("{} trailing bytes", data.len() - expected_len)));
        }

        Ok(LogEntry {
            seq,
            prev_hash,
            account_fp,
            entry_type,
            timestamp,
            body,
            signature,
            counter_signature,
        })
    }
}

fn decode_body(entry_type: EntryType, data: &[u8]) -> Result<EntryBody> {
    let err = |msg: &str| GhostError::Format(format!("idlog body: {msg}"));

    match entry_type {
        EntryType::Genesis => {
            // master_vk(32) + device_vk(32) + label_len(2) + label
            if data.len() < 66 { return Err(err("genesis too short")); }
            let master_verifying_key: [u8; 32] = data[0..32].try_into().unwrap();
            let device_verifying_key: [u8; 32] = data[32..64].try_into().unwrap();
            let label_len = u16::from_be_bytes(data[64..66].try_into().unwrap()) as usize;
            if data.len() < 66 + label_len { return Err(err("genesis label truncated")); }
            let device_label = String::from_utf8(data[66..66 + label_len].to_vec())
                .map_err(|_| err("invalid utf8 in label"))?;
            Ok(EntryBody::Genesis { master_verifying_key, device_verifying_key, device_label })
        }
        EntryType::AddDevice => {
            // device_vk(32) + label_len(2) + label + authorizer_key(32)
            if data.len() < 34 { return Err(err("add_device too short")); }
            let device_verifying_key: [u8; 32] = data[0..32].try_into().unwrap();
            let label_len = u16::from_be_bytes(data[32..34].try_into().unwrap()) as usize;
            if data.len() < 34 + label_len + 32 { return Err(err("add_device truncated")); }
            let device_label = String::from_utf8(data[34..34 + label_len].to_vec())
                .map_err(|_| err("invalid utf8 in label"))?;
            let authorizer_key: [u8; 32] = data[34 + label_len..66 + label_len].try_into().unwrap();
            Ok(EntryBody::AddDevice { device_verifying_key, device_label, authorizer_key })
        }
        EntryType::RevokeDevice => {
            // device_vk(32) + revoker_key(32)
            if data.len() < 64 { return Err(err("revoke too short")); }
            let device_verifying_key: [u8; 32] = data[0..32].try_into().unwrap();
            let revoker_key: [u8; 32] = data[32..64].try_into().unwrap();
            Ok(EntryBody::RevokeDevice { device_verifying_key, revoker_key })
        }
        EntryType::Recovery => {
            // device_vk(32) + label_len(2) + label
            if data.len() < 34 { return Err(err("recovery too short")); }
            let device_verifying_key: [u8; 32] = data[0..32].try_into().unwrap();
            let label_len = u16::from_be_bytes(data[32..34].try_into().unwrap()) as usize;
            if data.len() < 34 + label_len { return Err(err("recovery label truncated")); }
            let device_label = String::from_utf8(data[34..34 + label_len].to_vec())
                .map_err(|_| err("invalid utf8 in label"))?;
            Ok(EntryBody::Recovery { device_verifying_key, device_label })
        }
    }
}

// ── Utilities ───────────────────────────────────────────────────────

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn random_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn master_key_and_fp() -> (SigningKey, [u8; 32]) {
        let mk = random_key();
        let fp: [u8; 32] = blake3::hash(mk.verifying_key().as_bytes()).into();
        (mk, fp)
    }

    fn build_genesis() -> (LogState, SigningKey, SigningKey) {
        let (mk, _) = master_key_and_fp();
        let dk = random_key();
        let entry = create_genesis(&mk, &dk, "device-1");
        let state = validate_chain(&[entry]).unwrap();
        (state, mk, dk)
    }

    // ── Genesis ─────────────────────────────────────────────────

    #[test]
    fn genesis_creates_valid_chain() {
        let (state, mk, dk) = build_genesis();
        assert_eq!(state.head_seq, 1);
        assert!(state.is_active_device(&dk.verifying_key().to_bytes()));
        assert_eq!(state.master_verifying_key.unwrap(), mk.verifying_key().to_bytes());
        assert_eq!(state.active_devices().count(), 1);
    }

    #[test]
    fn genesis_must_be_seq_1() {
        let (mk, _) = master_key_and_fp();
        let dk = random_key();
        let mut entry = create_genesis(&mk, &dk, "d1");
        entry.seq = 2;
        sign_entry(&mk, &mut entry);
        counter_sign(&dk, &mut entry);
        assert!(validate_chain(&[entry]).is_err());
    }

    #[test]
    fn genesis_rejects_wrong_fingerprint() {
        let mk = random_key();
        let dk = random_key();
        let mut entry = create_genesis(&mk, &dk, "d1");
        // Corrupt account_fp
        entry.account_fp = [0xFFu8; 32];
        sign_entry(&mk, &mut entry);
        counter_sign(&dk, &mut entry);
        assert!(validate_chain(&[entry]).is_err());
    }

    // ── AddDevice ───────────────────────────────────────────────

    #[test]
    fn add_device_by_existing_device() {
        let (state, _mk, dk) = build_genesis();
        let dk2 = random_key();
        let entry = create_add_device(&state, &dk, &dk2, "device-2");
        let mut state = state;
        validate_entry(&mut state, &entry).unwrap();
        assert_eq!(state.head_seq, 2);
        assert_eq!(state.active_devices().count(), 2);
    }

    #[test]
    fn add_device_by_master_key() {
        let (state, mk, _dk) = build_genesis();
        let dk2 = random_key();
        let entry = create_add_device(&state, &mk, &dk2, "device-2");
        let mut state = state;
        validate_entry(&mut state, &entry).unwrap();
        assert_eq!(state.active_devices().count(), 2);
    }

    #[test]
    fn add_device_rejects_unauthorized_signer() {
        let (state, _mk, _dk) = build_genesis();
        let rogue = random_key();
        let dk2 = random_key();
        let entry = create_add_device(&state, &rogue, &dk2, "rogue");
        let mut state = state;
        assert!(validate_entry(&mut state, &entry).is_err());
    }

    #[test]
    fn add_device_rejects_duplicate() {
        let (state, _mk, dk) = build_genesis();
        let dk2 = random_key();
        let entry = create_add_device(&state, &dk, &dk2, "device-2");
        let mut state = state;
        validate_entry(&mut state, &entry).unwrap();
        // Try adding dk2 again
        let entry2 = create_add_device(&state, &dk, &dk2, "device-2-again");
        assert!(validate_entry(&mut state, &entry2).is_err());
    }

    // ── RevokeDevice ────────────────────────────────────────────

    #[test]
    fn revoke_device() {
        let (state, _mk, dk) = build_genesis();
        let dk2 = random_key();
        let add_entry = create_add_device(&state, &dk, &dk2, "device-2");
        let mut state = state;
        validate_entry(&mut state, &add_entry).unwrap();

        let revoke_entry = create_revoke_device(&state, &dk, &dk2.verifying_key().to_bytes());
        validate_entry(&mut state, &revoke_entry).unwrap();
        assert_eq!(state.active_devices().count(), 1);
        assert!(!state.is_active_device(&dk2.verifying_key().to_bytes()));
    }

    #[test]
    fn revoke_by_master_key() {
        let (state, mk, dk) = build_genesis();
        let dk2 = random_key();
        let add_entry = create_add_device(&state, &dk, &dk2, "device-2");
        let mut state = state;
        validate_entry(&mut state, &add_entry).unwrap();

        let revoke_entry = create_revoke_device(&state, &mk, &dk2.verifying_key().to_bytes());
        validate_entry(&mut state, &revoke_entry).unwrap();
        assert_eq!(state.active_devices().count(), 1);
    }

    #[test]
    fn self_revoke_rejected() {
        let (state, _mk, dk) = build_genesis();
        let dk2 = random_key();
        let add_entry = create_add_device(&state, &dk, &dk2, "device-2");
        let mut state = state;
        validate_entry(&mut state, &add_entry).unwrap();

        let self_revoke = create_revoke_device(&state, &dk2, &dk2.verifying_key().to_bytes());
        assert!(validate_entry(&mut state, &self_revoke).is_err());
    }

    #[test]
    fn revoked_device_cannot_authorize() {
        let (state, _mk, dk) = build_genesis();
        let dk2 = random_key();
        let add2 = create_add_device(&state, &dk, &dk2, "device-2");
        let mut state = state;
        validate_entry(&mut state, &add2).unwrap();

        let revoke2 = create_revoke_device(&state, &dk, &dk2.verifying_key().to_bytes());
        validate_entry(&mut state, &revoke2).unwrap();

        // dk2 is revoked — should not be able to add dk3
        let dk3 = random_key();
        let add3 = create_add_device(&state, &dk2, &dk3, "device-3");
        assert!(validate_entry(&mut state, &add3).is_err());
    }

    // ── Recovery ────────────────────────────────────────────────

    #[test]
    fn recovery_revokes_all_and_adds_new() {
        let (state, mk, dk) = build_genesis();
        let dk2 = random_key();
        let add2 = create_add_device(&state, &dk, &dk2, "device-2");
        let mut state = state;
        validate_entry(&mut state, &add2).unwrap();
        assert_eq!(state.active_devices().count(), 2);

        let recovery_dk = random_key();
        let recovery = create_recovery(&state, &mk, &recovery_dk, "recovery-device");
        validate_entry(&mut state, &recovery).unwrap();

        assert_eq!(state.active_devices().count(), 1);
        assert!(state.is_active_device(&recovery_dk.verifying_key().to_bytes()));
        assert!(!state.is_active_device(&dk.verifying_key().to_bytes()));
        assert!(!state.is_active_device(&dk2.verifying_key().to_bytes()));
    }

    #[test]
    fn recovery_requires_master_key() {
        let (state, _mk, dk) = build_genesis();
        let recovery_dk = random_key();
        // Try signing recovery with device key instead of master
        let mut entry = LogEntry {
            seq: state.head_seq + 1,
            prev_hash: state.head_hash,
            account_fp: state.account_fp,
            entry_type: EntryType::Recovery,
            timestamp: now_millis(),
            body: EntryBody::Recovery {
                device_verifying_key: recovery_dk.verifying_key().to_bytes(),
                device_label: "bad-recovery".to_string(),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        sign_entry(&dk, &mut entry);
        counter_sign(&recovery_dk, &mut entry);
        let mut state = state;
        assert!(validate_entry(&mut state, &entry).is_err());
    }

    // ── Chain integrity ─────────────────────────────────────────

    #[test]
    fn tampered_signature_rejected() {
        let (mk, _) = master_key_and_fp();
        let dk = random_key();
        let mut entry = create_genesis(&mk, &dk, "d1");
        entry.signature[0] ^= 0xFF;
        assert!(validate_chain(&[entry]).is_err());
    }

    #[test]
    fn tampered_body_rejected() {
        let (mk, _) = master_key_and_fp();
        let dk = random_key();
        let mut entry = create_genesis(&mk, &dk, "d1");
        // Mutate device label without re-signing
        entry.body = EntryBody::Genesis {
            master_verifying_key: mk.verifying_key().to_bytes(),
            device_verifying_key: dk.verifying_key().to_bytes(),
            device_label: "tampered".to_string(),
        };
        assert!(validate_chain(&[entry]).is_err());
    }

    #[test]
    fn broken_prev_hash_rejected() {
        let (state, _mk, dk) = build_genesis();
        let dk2 = random_key();
        let mut entry = create_add_device(&state, &dk, &dk2, "device-2");
        entry.prev_hash = [0xFFu8; 32];
        sign_entry(&dk, &mut entry);
        counter_sign(&dk2, &mut entry);
        let mut state = state;
        assert!(validate_entry(&mut state, &entry).is_err());
    }

    // ── Wire serialization roundtrip ────────────────────────────

    #[test]
    fn genesis_roundtrip() {
        let (mk, _) = master_key_and_fp();
        let dk = random_key();
        let entry = create_genesis(&mk, &dk, "my-laptop");
        let bytes = entry.to_bytes();
        let restored = LogEntry::from_bytes(&bytes).unwrap();
        // Validate the restored entry produces valid chain
        validate_chain(&[restored]).unwrap();
    }

    #[test]
    fn full_chain_roundtrip() {
        let (mk, _) = master_key_and_fp();
        let dk = random_key();
        let dk2 = random_key();

        let genesis = create_genesis(&mk, &dk, "laptop");
        let mut state = validate_chain(&[genesis.clone()]).unwrap();

        let add = create_add_device(&state, &dk, &dk2, "phone");
        validate_entry(&mut state, &add).unwrap();

        let revoke = create_revoke_device(&state, &dk, &dk2.verifying_key().to_bytes());
        validate_entry(&mut state, &revoke).unwrap();

        let recovery_dk = random_key();
        let recovery = create_recovery(&state, &mk, &recovery_dk, "new-laptop");
        validate_entry(&mut state, &recovery).unwrap();

        // Serialize all entries
        let entries = [genesis, add, revoke, recovery];
        let serialized: Vec<Vec<u8>> = entries.iter().map(|e| e.to_bytes()).collect();
        let restored: Vec<LogEntry> = serialized.iter().map(|b| LogEntry::from_bytes(b).unwrap()).collect();

        // Validate the restored chain
        let restored_state = validate_chain(&restored).unwrap();
        assert_eq!(restored_state.head_seq, 4);
        assert_eq!(restored_state.active_devices().count(), 1);
        assert!(restored_state.is_active_device(&recovery_dk.verifying_key().to_bytes()));
    }

    // ── Seq gap rejected ────────────────────────────────────────

    #[test]
    fn seq_gap_rejected() {
        let (state, _mk, dk) = build_genesis();
        let dk2 = random_key();
        let mut entry = create_add_device(&state, &dk, &dk2, "device-2");
        // Skip seq 2, jump to 3
        entry.seq = 3;
        sign_entry(&dk, &mut entry);
        counter_sign(&dk2, &mut entry);
        let mut state = state;
        assert!(validate_entry(&mut state, &entry).is_err());
    }

    #[test]
    fn empty_chain_rejected() {
        assert!(validate_chain(&[]).is_err());
    }

    // ── Counter-signature tampering ────────────────────────────

    #[test]
    fn counter_sig_tampered_on_genesis_rejected() {
        let (mk, _) = master_key_and_fp();
        let dk = random_key();
        let mut entry = create_genesis(&mk, &dk, "d1");
        entry.counter_signature.as_mut().unwrap()[0] ^= 0xFF;
        assert!(validate_chain(&[entry]).is_err());
    }

    #[test]
    fn counter_sig_tampered_on_add_device_rejected() {
        let (state, _mk, dk) = build_genesis();
        let dk2 = random_key();
        let mut entry = create_add_device(&state, &dk, &dk2, "device-2");
        entry.counter_signature.as_mut().unwrap()[0] ^= 0xFF;
        let mut state = state;
        assert!(validate_entry(&mut state, &entry).is_err());
    }

    #[test]
    fn counter_sig_tampered_on_recovery_rejected() {
        let (state, mk, _dk) = build_genesis();
        let recovery_dk = random_key();
        let mut entry = create_recovery(&state, &mk, &recovery_dk, "recovery");
        entry.counter_signature.as_mut().unwrap()[0] ^= 0xFF;
        let mut state = state;
        assert!(validate_entry(&mut state, &entry).is_err());
    }

    // ── Before-genesis guards ──────────────────────────────────

    #[test]
    fn add_device_before_genesis_rejected() {
        let dk = random_key();
        let new_dk = random_key();
        let account_fp = [0xAA; 32];
        let mut entry = LogEntry {
            seq: 1,
            prev_hash: [0u8; 32],
            account_fp,
            entry_type: EntryType::AddDevice,
            timestamp: now_millis(),
            body: EntryBody::AddDevice {
                device_verifying_key: new_dk.verifying_key().to_bytes(),
                device_label: "sneaky".to_string(),
                authorizer_key: dk.verifying_key().to_bytes(),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        sign_entry(&dk, &mut entry);
        counter_sign(&new_dk, &mut entry);
        let mut state = LogState::empty(account_fp);
        let err = validate_entry(&mut state, &entry).unwrap_err();
        assert!(err.to_string().contains("AddDevice before genesis"));
    }

    #[test]
    fn revoke_device_before_genesis_rejected() {
        let dk = random_key();
        let target = random_key();
        let account_fp = [0xAA; 32];
        let mut entry = LogEntry {
            seq: 1,
            prev_hash: [0u8; 32],
            account_fp,
            entry_type: EntryType::RevokeDevice,
            timestamp: now_millis(),
            body: EntryBody::RevokeDevice {
                device_verifying_key: target.verifying_key().to_bytes(),
                revoker_key: dk.verifying_key().to_bytes(),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        sign_entry(&dk, &mut entry);
        let mut state = LogState::empty(account_fp);
        let err = validate_entry(&mut state, &entry).unwrap_err();
        assert!(err.to_string().contains("RevokeDevice before genesis"));
    }

    #[test]
    fn recovery_before_genesis_rejected() {
        let mk = random_key();
        let new_dk = random_key();
        let account_fp = [0xAA; 32];
        let mut entry = LogEntry {
            seq: 1,
            prev_hash: [0u8; 32],
            account_fp,
            entry_type: EntryType::Recovery,
            timestamp: now_millis(),
            body: EntryBody::Recovery {
                device_verifying_key: new_dk.verifying_key().to_bytes(),
                device_label: "recovery".to_string(),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        sign_entry(&mk, &mut entry);
        counter_sign(&new_dk, &mut entry);
        let mut state = LogState::empty(account_fp);
        let err = validate_entry(&mut state, &entry).unwrap_err();
        assert!(err.to_string().contains("Recovery before genesis"));
    }

    // ── Second genesis in chain ────────────────────────────────

    #[test]
    fn second_genesis_rejected() {
        let (mk, _) = master_key_and_fp();
        let dk = random_key();
        let genesis = create_genesis(&mk, &dk, "d1");
        let state = validate_chain(&[genesis.clone()]).unwrap();

        // Construct a second genesis at seq=2
        let dk2 = random_key();
        let mut entry = LogEntry {
            seq: 2,
            prev_hash: state.head_hash,
            account_fp: state.account_fp,
            entry_type: EntryType::Genesis,
            timestamp: now_millis(),
            body: EntryBody::Genesis {
                master_verifying_key: mk.verifying_key().to_bytes(),
                device_verifying_key: dk2.verifying_key().to_bytes(),
                device_label: "second-genesis".to_string(),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        sign_entry(&mk, &mut entry);
        counter_sign(&dk2, &mut entry);

        let err = validate_chain(&[genesis, entry]).unwrap_err();
        assert!(err.to_string().contains("genesis must be seq 1"));
    }

    // ── Authorizer/signer mismatch ─────────────────────────────

    #[test]
    fn add_device_authorizer_signer_mismatch() {
        let (state, _mk, dk) = build_genesis();
        let attacker = random_key();
        let new_dk = random_key();

        // Body claims authorizer is the legitimate device, but attacker signs
        let mut entry = LogEntry {
            seq: state.head_seq + 1,
            prev_hash: state.head_hash,
            account_fp: state.account_fp,
            entry_type: EntryType::AddDevice,
            timestamp: now_millis(),
            body: EntryBody::AddDevice {
                device_verifying_key: new_dk.verifying_key().to_bytes(),
                device_label: "evil".to_string(),
                authorizer_key: dk.verifying_key().to_bytes(),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        sign_entry(&attacker, &mut entry);
        counter_sign(&new_dk, &mut entry);

        let mut state = state;
        assert!(validate_entry(&mut state, &entry).is_err());
    }

    // ── Re-add revoked device ──────────────────────────────────

    #[test]
    fn readd_revoked_device_rejected() {
        let (state, _mk, dk) = build_genesis();
        let dk2 = random_key();
        let add2 = create_add_device(&state, &dk, &dk2, "device-2");
        let mut state = state;
        validate_entry(&mut state, &add2).unwrap();

        let revoke2 = create_revoke_device(&state, &dk, &dk2.verifying_key().to_bytes());
        validate_entry(&mut state, &revoke2).unwrap();
        assert!(!state.is_active_device(&dk2.verifying_key().to_bytes()));

        // Try to re-add the same device key
        let readd = create_add_device(&state, &dk, &dk2, "device-2-again");
        let err = validate_entry(&mut state, &readd).unwrap_err();
        assert!(err.to_string().contains("duplicate device key"));
    }

    // ── account_fp mismatch on non-genesis entry ───────────────

    #[test]
    fn account_fp_mismatch_on_add_device_rejected() {
        let (state, _mk, dk) = build_genesis();
        let new_dk = random_key();

        let mut entry = LogEntry {
            seq: state.head_seq + 1,
            prev_hash: state.head_hash,
            account_fp: [0xFF; 32], // wrong fingerprint
            entry_type: EntryType::AddDevice,
            timestamp: now_millis(),
            body: EntryBody::AddDevice {
                device_verifying_key: new_dk.verifying_key().to_bytes(),
                device_label: "wrong-fp".to_string(),
                authorizer_key: dk.verifying_key().to_bytes(),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        sign_entry(&dk, &mut entry);
        counter_sign(&new_dk, &mut entry);

        let mut state = state;
        let err = validate_entry(&mut state, &entry).unwrap_err();
        assert!(err.to_string().contains("account_fp mismatch"));
    }
}
