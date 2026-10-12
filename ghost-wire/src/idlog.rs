use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::HashMap;
use thiserror::Error;

use crate::bytes::{put_prefixed16, put_prefixed32, put_string, ReadError, Reader};

use crate::relay_ref::RelayRef;

/// Domain separator for identity log signatures.
pub const IDLOG_SIGN_PREFIX: &[u8] = b"ghost-idlog-v1:";

/// Domain separator for a device's signature over a public key it publishes.
pub const DEVICE_KEY_SIGN_PREFIX: &[u8] = b"ghost-device-key-v1:";

/// Domain separator for the device co-signature on a root rotation.
pub const ROTATE_ROOT_SIGN_PREFIX: &[u8] = b"ghost-rotate-root-v1:";

/// Most devices an account may have active once its root has rotated. Bounds the
/// recipients of every account key, so an `AccountKey` entry stays within one entry.
pub const MAX_ACTIVE_DEVICES: usize = 64;

/// Longest device label an entry may carry, in bytes; relays store and devices show them.
pub const MAX_DEVICE_LABEL_BYTES: usize = 64;

// ── Error type ──────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum IdlogError {
    #[error("invalid format: {0}")]
    Format(String),
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    #[error("authentication failed")]
    AuthenticationFailed,
}

pub type IdlogResult<T> = std::result::Result<T, IdlogError>;

// ── Entry types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryType {
    Genesis = 0x01,
    AddDevice = 0x02,
    RevokeDevice = 0x03,
    Recovery = 0x04,
    /// Names the relay that sequences and anchors this account's log.
    SetHomeRelay = 0x05,
    /// Publishes a public key of one of the account's devices.
    DeviceKey = 0x06,
    /// Replaces the account's root with one derived from a new recovery key.
    RotateRoot = 0x07,
    /// Starts a generation of the account key, naming who holds a copy.
    AccountKey = 0x08,
    /// Gives one of the account's devices a new label.
    RenameDevice = 0x09,
}

impl TryFrom<u8> for EntryType {
    type Error = u8;
    fn try_from(v: u8) -> std::result::Result<Self, u8> {
        match v {
            0x01 => Ok(Self::Genesis),
            0x02 => Ok(Self::AddDevice),
            0x03 => Ok(Self::RevokeDevice),
            0x04 => Ok(Self::Recovery),
            0x05 => Ok(Self::SetHomeRelay),
            0x06 => Ok(Self::DeviceKey),
            0x07 => Ok(Self::RotateRoot),
            0x08 => Ok(Self::AccountKey),
            0x09 => Ok(Self::RenameDevice),
            other => Err(other),
        }
    }
}

/// What a `DeviceKey` entry publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DeviceKeyKind {
    /// X25519 key that opens the device's copy of each account key.
    Encryption = 0x01,
    /// Reserved for the QUIC binding's transport key; refused until that binding exists.
    Transport = 0x02,
}

impl TryFrom<u8> for DeviceKeyKind {
    type Error = u8;
    fn try_from(v: u8) -> std::result::Result<Self, u8> {
        match v {
            0x01 => Ok(Self::Encryption),
            0x02 => Ok(Self::Transport),
            other => Err(other),
        }
    }
}

/// Who an account key copy is for. Declaration order is the sort order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RecipientKind {
    Device = 0x01,
    Recovery = 0x02,
}

impl TryFrom<u8> for RecipientKind {
    type Error = u8;
    fn try_from(v: u8) -> std::result::Result<Self, u8> {
        match v {
            0x01 => Ok(Self::Device),
            0x02 => Ok(Self::Recovery),
            other => Err(other),
        }
    }
}

/// One holder of an account key copy: a device, named by its signing key, or the
/// recovery key, named by its box key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Recipient {
    pub kind: RecipientKind,
    pub id: [u8; 32],
}

impl Recipient {
    pub fn device(device_vk: [u8; 32]) -> Self {
        Self { kind: RecipientKind::Device, id: device_vk }
    }

    pub fn recovery(box_key: [u8; 32]) -> Self {
        Self { kind: RecipientKind::Recovery, id: box_key }
    }
}

// ── Entry body variants ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum EntryBody {
    Genesis {
        genesis_verifying_key: [u8; 32],
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
    SetHomeRelay {
        relay_vk: [u8; 32],
        authorizer_key: [u8; 32],
        relay_ref: RelayRef,
    },
    DeviceKey {
        device_verifying_key: [u8; 32],
        kind: DeviceKeyKind,
        public_key: [u8; 32],
        authorizer_key: [u8; 32],
        /// By `device_verifying_key` over [`device_key_message`], so the device consents
        /// to the key wherever the entry lands.
        device_signature: [u8; 64],
    },
    RotateRoot {
        new_root_key: [u8; 32],
        recovery_box_key: [u8; 32],
        device_verifying_key: [u8; 32],
        /// By `device_verifying_key` over [`rotate_root_message`].
        device_signature: [u8; 64],
    },
    AccountKey {
        generation: u32,
        verifying_key: [u8; 32],
        encryption_key: [u8; 32],
        /// BLAKE3 of the `AccountKeySet` carrying the copies.
        set_digest: [u8; 32],
        authorizer_key: [u8; 32],
        /// Sorted; exactly the account's coverage when the entry applies.
        recipients: Vec<Recipient>,
    },
    RenameDevice {
        device_verifying_key: [u8; 32],
        device_label: String,
        authorizer_key: [u8; 32],
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
    /// X25519 key published by a `DeviceKey` entry; None until then.
    pub encryption_key: Option<[u8; 32]>,
}

impl DeviceInfo {
    pub fn is_active(&self) -> bool {
        self.revoked_at_seq.is_none()
    }
}

/// One account key generation, as its `AccountKey` entry published it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountKeyState {
    pub generation: u32,
    pub verifying_key: [u8; 32],
    pub encryption_key: [u8; 32],
    pub set_digest: [u8; 32],
    pub recipients: Vec<Recipient>,
    /// The device that wrote the generation, named when a copy turns out bad.
    pub writer: [u8; 32],
    /// Hash of the `AccountKey` entry, which keys its stored copies.
    pub entry_hash: [u8; 32],
}

// ── Cumulative log state ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LogState {
    pub account_fp: [u8; 32],
    /// The key the fingerprint commits to; set by genesis and never replaced.
    pub genesis_verifying_key: Option<[u8; 32]>,
    /// The key that signs recoveries, root rotations and home moves: the genesis key
    /// until the first `RotateRoot`, then a root derived from the recovery key.
    pub root_verifying_key: Option<[u8; 32]>,
    /// Public box key derived from the recovery key; set by every `RotateRoot`.
    pub recovery_box_key: Option<[u8; 32]>,
    pub devices: HashMap<[u8; 32], DeviceInfo>,
    /// Every account key generation in order; the last is current.
    pub account_keys: Vec<AccountKeyState>,
    pub head_seq: u64,
    pub head_hash: [u8; 32],
    /// None for a v1 account, whose home is whichever relay holds its genesis.
    pub home_relay_vk: Option<[u8; 32]>,
    pub home_relay_ref: Option<RelayRef>,
    pub home_set_at_seq: u64,
}

impl LogState {
    pub fn empty(account_fp: [u8; 32]) -> Self {
        Self {
            account_fp,
            genesis_verifying_key: None,
            root_verifying_key: None,
            recovery_box_key: None,
            devices: HashMap::new(),
            account_keys: Vec::new(),
            head_seq: 0,
            head_hash: [0u8; 32],
            home_relay_vk: None,
            home_relay_ref: None,
            home_set_at_seq: 0,
        }
    }

    pub fn active_devices(&self) -> impl Iterator<Item = &DeviceInfo> {
        self.devices.values().filter(|d| d.is_active())
    }

    pub fn is_active_device(&self, key: &[u8; 32]) -> bool {
        self.devices.get(key).map_or(false, |d| d.is_active())
    }

    /// Whether the account has moved its authority from the genesis key to a
    /// recovery key. Every rule that differs "once rotated" keys off this.
    pub fn root_rotated(&self) -> bool {
        self.recovery_box_key.is_some()
    }

    /// The current account key generation, if any.
    pub fn account_key(&self) -> Option<&AccountKeyState> {
        self.account_keys.last()
    }

    /// The generation whose copies are stored under `set_digest`.
    pub fn account_key_by_digest(&self, set_digest: &[u8; 32]) -> Option<&AccountKeyState> {
        self.account_keys.iter().find(|k| k.set_digest == *set_digest)
    }

    /// Who must hold a copy of the current account key, sorted: every active device
    /// that has published an encryption key, and the recovery key.
    pub fn coverage(&self) -> Vec<Recipient> {
        let mut recipients: Vec<Recipient> = self
            .active_devices()
            .filter(|d| d.encryption_key.is_some())
            .map(|d| Recipient::device(d.verifying_key))
            .chain(self.recovery_box_key.map(Recipient::recovery))
            .collect();
        recipients.sort();
        recipients
    }

    /// The current account key's holders differ from who should hold it, so no new
    /// data may be sealed under it until a device appends a generation that covers
    /// the account again.
    pub fn rekey_needed(&self) -> bool {
        self.root_rotated() && self.account_key().is_none_or(|k| k.recipients != self.coverage())
    }

    /// Whether `key` may add or revoke devices: an active device, or before the root
    /// rotates also the genesis key.
    fn may_manage_devices(&self, key: &[u8; 32]) -> bool {
        self.is_active_device(key) || (!self.root_rotated() && self.root_verifying_key == Some(*key))
    }

    /// Whether `key` may move the home: the root, or before the root rotates also an
    /// active device. A device that could move the home could move it to a relay
    /// that refuses its owner's recovery.
    fn may_move_home(&self, key: &[u8; 32]) -> bool {
        self.root_verifying_key == Some(*key) || (!self.root_rotated() && self.is_active_device(key))
    }

    /// Whether `entry`, appended to this state, is signed by the root. Root-signed
    /// history wins forks against device-signed history (see [`choose_branch`]).
    pub fn is_root_signed(&self, entry: &LogEntry) -> bool {
        let root = self.root_verifying_key;
        match &entry.body {
            EntryBody::Genesis { .. } | EntryBody::Recovery { .. } | EntryBody::RotateRoot { .. } => true,
            EntryBody::SetHomeRelay { authorizer_key, .. } => root == Some(*authorizer_key),
            EntryBody::AddDevice { authorizer_key, .. } => root == Some(*authorizer_key),
            EntryBody::RevokeDevice { revoker_key, .. } => root == Some(*revoker_key),
            EntryBody::RenameDevice { authorizer_key, .. } => root == Some(*authorizer_key),
            EntryBody::DeviceKey { .. } | EntryBody::AccountKey { .. } => false,
        }
    }

    fn root(&self, entry_name: &str) -> IdlogResult<[u8; 32]> {
        self.root_verifying_key
            .ok_or_else(|| IdlogError::Format(format!("idlog: {entry_name} before genesis")))
    }
}

// ── Messages signed inside bodies ───────────────────────────────────

/// What a device signs to publish one of its public keys. Independent of the entry's
/// position, so a new device can sign it before it knows where its entry will land.
pub fn device_key_message(account_fp: &[u8; 32], device_vk: &[u8; 32], kind: DeviceKeyKind, public_key: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(DEVICE_KEY_SIGN_PREFIX.len() + 32 + 32 + 1 + 32);
    msg.extend_from_slice(DEVICE_KEY_SIGN_PREFIX);
    msg.extend_from_slice(account_fp);
    msg.extend_from_slice(device_vk);
    msg.push(kind as u8);
    msg.extend_from_slice(public_key);
    msg
}

/// What the co-signing device signs for a root rotation at `seq` after `prev_hash`.
pub fn rotate_root_message(
    account_fp: &[u8; 32],
    seq: u64,
    prev_hash: &[u8; 32],
    new_root_key: &[u8; 32],
    recovery_box_key: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(ROTATE_ROOT_SIGN_PREFIX.len() + 32 + 8 + 32 + 32 + 32);
    msg.extend_from_slice(ROTATE_ROOT_SIGN_PREFIX);
    msg.extend_from_slice(account_fp);
    msg.extend_from_slice(&seq.to_be_bytes());
    msg.extend_from_slice(prev_hash);
    msg.extend_from_slice(new_root_key);
    msg.extend_from_slice(recovery_box_key);
    msg
}

// ── Deterministic binary encoding ───────────────────────────────────

pub fn encode_body(buf: &mut Vec<u8>, body: &EntryBody) {
    match body {
        EntryBody::Genesis { genesis_verifying_key, device_verifying_key, device_label } => {
            buf.extend_from_slice(genesis_verifying_key);
            buf.extend_from_slice(device_verifying_key);
            put_string(buf, device_label);
        }
        EntryBody::AddDevice { device_verifying_key, device_label, authorizer_key } => {
            buf.extend_from_slice(device_verifying_key);
            put_string(buf, device_label);
            buf.extend_from_slice(authorizer_key);
        }
        EntryBody::RevokeDevice { device_verifying_key, revoker_key } => {
            buf.extend_from_slice(device_verifying_key);
            buf.extend_from_slice(revoker_key);
        }
        EntryBody::Recovery { device_verifying_key, device_label } => {
            buf.extend_from_slice(device_verifying_key);
            put_string(buf, device_label);
        }
        EntryBody::SetHomeRelay { relay_vk, authorizer_key, relay_ref } => {
            buf.extend_from_slice(relay_vk);
            buf.extend_from_slice(authorizer_key);
            put_prefixed16(buf, &relay_ref.to_bytes());
        }
        EntryBody::DeviceKey { device_verifying_key, kind, public_key, authorizer_key, device_signature } => {
            buf.extend_from_slice(device_verifying_key);
            buf.push(*kind as u8);
            put_prefixed16(buf, public_key);
            buf.extend_from_slice(authorizer_key);
            buf.extend_from_slice(device_signature);
        }
        EntryBody::RotateRoot { new_root_key, recovery_box_key, device_verifying_key, device_signature } => {
            buf.extend_from_slice(new_root_key);
            buf.extend_from_slice(recovery_box_key);
            buf.extend_from_slice(device_verifying_key);
            buf.extend_from_slice(device_signature);
        }
        EntryBody::AccountKey { generation, verifying_key, encryption_key, set_digest, authorizer_key, recipients } => {
            buf.extend_from_slice(&generation.to_be_bytes());
            buf.extend_from_slice(verifying_key);
            buf.extend_from_slice(encryption_key);
            buf.extend_from_slice(set_digest);
            buf.extend_from_slice(authorizer_key);
            buf.push(recipients.len() as u8);
            for r in recipients {
                buf.push(r.kind as u8);
                buf.extend_from_slice(&r.id);
            }
        }
        EntryBody::RenameDevice { device_verifying_key, device_label, authorizer_key } => {
            buf.extend_from_slice(device_verifying_key);
            put_string(buf, device_label);
            buf.extend_from_slice(authorizer_key);
        }
    }
}

pub fn canonical_bytes(entry: &LogEntry) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&entry.seq.to_be_bytes());
    buf.extend_from_slice(&entry.prev_hash);
    buf.extend_from_slice(&entry.account_fp);
    buf.push(entry.entry_type as u8);
    buf.extend_from_slice(&entry.timestamp.to_be_bytes());
    encode_body(&mut buf, &entry.body);
    buf
}

/// Build the message that gets signed: prefix + canonical bytes.
pub fn sign_message(entry: &LogEntry) -> Vec<u8> {
    let mut msg = Vec::with_capacity(IDLOG_SIGN_PREFIX.len() + 128);
    msg.extend_from_slice(IDLOG_SIGN_PREFIX);
    msg.extend_from_slice(&canonical_bytes(entry));
    msg
}

/// Hash of the full wire-format entry. Used as prev_hash for the next entry in the chain.
pub fn entry_hash(entry: &LogEntry) -> [u8; 32] {
    blake3::hash(&entry.to_bytes()).into()
}

// ── Signature helpers ───────────────────────────────────────────────

fn verify_key_sig(key_bytes: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> IdlogResult<()> {
    let key = VerifyingKey::from_bytes(key_bytes)
        .map_err(|e| IdlogError::InvalidKey(format!("bad verifying key: {e}")))?;
    key.verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| IdlogError::AuthenticationFailed)
}

fn verify_sig(key_bytes: &[u8; 32], entry: &LogEntry) -> IdlogResult<()> {
    verify_key_sig(key_bytes, &sign_message(entry), &entry.signature)
}

fn verify_counter_sig(key_bytes: &[u8; 32], entry: &LogEntry) -> IdlogResult<()> {
    let cs = entry.counter_signature
        .ok_or_else(|| IdlogError::Format("missing counter-signature".into()))?;
    verify_key_sig(key_bytes, &sign_message(entry), &cs)
}

fn refuse_counter_sig(entry: &LogEntry) -> IdlogResult<()> {
    if entry.counter_signature.is_some() {
        return Err(IdlogError::Format("idlog: unexpected counter-signature".into()));
    }
    Ok(())
}

// ── Chain validation ────────────────────────────────────────────────

pub fn validate_chain(entries: &[LogEntry]) -> IdlogResult<LogState> {
    if entries.is_empty() {
        return Err(IdlogError::Format("empty identity log".into()));
    }
    let mut state = LogState::empty(entries[0].account_fp);
    for entry in entries {
        validate_entry(&mut state, entry)?;
    }
    Ok(state)
}

pub fn validate_entry(state: &mut LogState, entry: &LogEntry) -> IdlogResult<()> {
    let format = |msg: &str| IdlogError::Format(format!("idlog: {msg}"));

    // Seq must be exactly next
    if entry.seq != state.head_seq + 1 {
        return Err(IdlogError::Format(format!(
            "idlog: expected seq {}, got {}", state.head_seq + 1, entry.seq
        )));
    }

    // prev_hash must match
    if entry.seq == 1 {
        if entry.prev_hash != [0u8; 32] {
            return Err(format("genesis prev_hash must be zeroed"));
        }
    } else if entry.prev_hash != state.head_hash {
        return Err(format("prev_hash mismatch"));
    }

    // Account fingerprint must be consistent
    if entry.account_fp != state.account_fp {
        return Err(format("account_fp mismatch"));
    }

    match &entry.body {
        EntryBody::Genesis { genesis_verifying_key, device_verifying_key, device_label } => {
            if entry.seq != 1 {
                return Err(format("genesis must be seq 1"));
            }
            let expected_fp: [u8; 32] = blake3::hash(genesis_verifying_key).into();
            if expected_fp != state.account_fp {
                return Err(format("fingerprint doesn't match genesis key"));
            }
            verify_sig(genesis_verifying_key, entry)?;
            verify_counter_sig(device_verifying_key, entry)?;

            state.genesis_verifying_key = Some(*genesis_verifying_key);
            state.root_verifying_key = Some(*genesis_verifying_key);
            state.devices.insert(*device_verifying_key, DeviceInfo {
                verifying_key: *device_verifying_key,
                label: device_label.clone(),
                added_at_seq: 1,
                revoked_at_seq: None,
                encryption_key: None,
            });
        }

        EntryBody::AddDevice { device_verifying_key, device_label, authorizer_key } => {
            state.root("AddDevice")?;
            if !state.may_manage_devices(authorizer_key) {
                return Err(format("unauthorized signer"));
            }
            verify_sig(authorizer_key, entry)?;
            verify_counter_sig(device_verifying_key, entry)?;

            if state.devices.contains_key(device_verifying_key) {
                return Err(format("duplicate device key"));
            }
            if state.root_rotated() && state.active_devices().count() >= MAX_ACTIVE_DEVICES {
                return Err(format("too many active devices"));
            }

            state.devices.insert(*device_verifying_key, DeviceInfo {
                verifying_key: *device_verifying_key,
                label: device_label.clone(),
                added_at_seq: entry.seq,
                revoked_at_seq: None,
                encryption_key: None,
            });
        }

        EntryBody::RevokeDevice { device_verifying_key, revoker_key } => {
            state.root("RevokeDevice")?;
            if !state.may_manage_devices(revoker_key) {
                return Err(format("unauthorized revoker"));
            }
            if revoker_key == device_verifying_key {
                return Err(format("cannot self-revoke"));
            }
            if !state.is_active_device(device_verifying_key) {
                return Err(format("device not active"));
            }
            verify_sig(revoker_key, entry)?;
            refuse_counter_sig(entry)?;

            state.devices.get_mut(device_verifying_key).unwrap().revoked_at_seq = Some(entry.seq);
        }

        EntryBody::Recovery { device_verifying_key, device_label } => {
            let root = state.root("Recovery")?;
            verify_sig(&root, entry)?;
            verify_counter_sig(device_verifying_key, entry)?;
            if state.devices.contains_key(device_verifying_key) {
                return Err(format("duplicate device key"));
            }

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
                encryption_key: None,
            });
        }

        EntryBody::SetHomeRelay { relay_vk, authorizer_key, relay_ref } => {
            state.root("SetHomeRelay")?;
            if !state.may_move_home(authorizer_key) {
                return Err(format("unauthorized home relay change"));
            }
            if relay_ref.relay_vk != *relay_vk {
                return Err(format("relay ref names a different relay"));
            }
            verify_sig(authorizer_key, entry)?;
            refuse_counter_sig(entry)?;

            state.home_relay_vk = Some(*relay_vk);
            state.home_relay_ref = Some(relay_ref.clone());
            state.home_set_at_seq = entry.seq;
        }

        EntryBody::RenameDevice { device_verifying_key, device_label, authorizer_key } => {
            state.root("RenameDevice")?;
            if !state.may_manage_devices(authorizer_key) {
                return Err(format("unauthorized signer"));
            }
            if !state.is_active_device(device_verifying_key) {
                return Err(format("device not active"));
            }
            verify_sig(authorizer_key, entry)?;
            refuse_counter_sig(entry)?;

            state.devices.get_mut(device_verifying_key).unwrap().label = device_label.clone();
        }

        EntryBody::DeviceKey { device_verifying_key, kind, public_key, authorizer_key, device_signature } => {
            state.root("DeviceKey")?;
            if *kind != DeviceKeyKind::Encryption {
                return Err(format("device key kind not accepted yet"));
            }
            if !state.is_active_device(authorizer_key) {
                return Err(format("unauthorized device key publisher"));
            }
            let device = state
                .devices
                .get(device_verifying_key)
                .filter(|d| d.is_active())
                .ok_or_else(|| format("device key for a device that is not active"))?;
            if device.encryption_key.is_some() {
                return Err(format("device already published its encryption key"));
            }
            verify_sig(authorizer_key, entry)?;
            refuse_counter_sig(entry)?;
            verify_key_sig(
                device_verifying_key,
                &device_key_message(&state.account_fp, device_verifying_key, *kind, public_key),
                device_signature,
            )?;

            state.devices.get_mut(device_verifying_key).unwrap().encryption_key = Some(*public_key);
        }

        EntryBody::RotateRoot { new_root_key, recovery_box_key, device_verifying_key, device_signature } => {
            let root = state.root("RotateRoot")?;
            if *new_root_key == root {
                return Err(format("root rotation must change the root"));
            }
            if !state.is_active_device(device_verifying_key) {
                return Err(format("root rotation co-signed by a device that is not active"));
            }
            verify_sig(&root, entry)?;
            verify_counter_sig(new_root_key, entry)?;
            verify_key_sig(
                device_verifying_key,
                &rotate_root_message(&state.account_fp, entry.seq, &entry.prev_hash, new_root_key, recovery_box_key),
                device_signature,
            )?;

            state.root_verifying_key = Some(*new_root_key);
            state.recovery_box_key = Some(*recovery_box_key);
        }

        EntryBody::AccountKey { generation, verifying_key, encryption_key, set_digest, authorizer_key, recipients } => {
            state.root("AccountKey")?;
            if !state.root_rotated() {
                return Err(format("account key before the root rotates"));
            }
            if !state.is_active_device(authorizer_key) {
                return Err(format("unauthorized account key writer"));
            }
            let expected_generation = state.account_key().map_or(1, |k| k.generation + 1);
            if *generation != expected_generation {
                return Err(format("account key generation out of order"));
            }
            if *recipients != state.coverage() {
                return Err(format("account key recipients differ from the account's coverage"));
            }
            verify_sig(authorizer_key, entry)?;
            verify_counter_sig(verifying_key, entry)?;

            state.account_keys.push(AccountKeyState {
                generation: *generation,
                verifying_key: *verifying_key,
                encryption_key: *encryption_key,
                set_digest: *set_digest,
                recipients: recipients.clone(),
                writer: *authorizer_key,
                entry_hash: entry_hash(entry),
            });
        }
    }

    state.head_seq = entry.seq;
    state.head_hash = entry_hash(entry);
    Ok(())
}

// ── Forks ───────────────────────────────────────────────────────────

/// What to do when a received branch conflicts with the held chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchChoice {
    /// Keep the held chain; a valid incoming branch is evidence of equivocation.
    Keep,
    /// Replace the held suffix with the incoming branch.
    Replace,
}

/// Settle a fork after the common prefix whose state is `prefix`: `held` is the chain
/// already kept from the fork point, `incoming` the conflicting branch from the same
/// point. Root-signed history beats device-signed history; between two histories
/// with root-signed entries, or two without, the held one stays, since no rule can
/// say which root holder or which equivocating home is rightful. Errors if the
/// incoming branch is invalid.
pub fn choose_branch(prefix: &LogState, held: &[LogEntry], incoming: &[LogEntry]) -> IdlogResult<BranchChoice> {
    let first = incoming
        .first()
        .ok_or_else(|| IdlogError::Format("idlog: empty branch".into()))?;
    let mut incoming_state = prefix.clone();
    for entry in incoming {
        validate_entry(&mut incoming_state, entry)?;
    }

    let mut held_state = prefix.clone();
    let mut held_has_root = false;
    for entry in held {
        held_has_root |= held_state.is_root_signed(entry);
        validate_entry(&mut held_state, entry)?;
    }

    if !held_has_root && prefix.is_root_signed(first) {
        Ok(BranchChoice::Replace)
    } else {
        Ok(BranchChoice::Keep)
    }
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
        put_prefixed32(&mut buf, &body_bytes);
        buf.extend_from_slice(&self.signature);
        buf.push(has_counter);
        if let Some(cs) = &self.counter_signature {
            buf.extend_from_slice(cs);
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> IdlogResult<Self> {
        let err = |msg: &str| IdlogError::Format(format!("idlog: {msg}"));
        let mut r = Reader::new(data);
        let seq = r.u64()?;
        let prev_hash = r.array()?;
        let account_fp = r.array()?;
        let entry_type = EntryType::try_from(r.u8()?).map_err(|v| err(&format!("unknown entry type: {v:#x}")))?;
        let timestamp = r.u64()?;
        let body = decode_body(entry_type, r.prefixed32()?)?;
        let signature = r.array()?;
        let counter_signature = match r.u8()? {
            1 => Some(r.array()?),
            0 => None,
            _ => return Err(err("invalid counter-signature flag")),
        };
        r.finish()?;
        Ok(LogEntry { seq, prev_hash, account_fp, entry_type, timestamp, body, signature, counter_signature })
    }
}

/// A device label, bounded like the entries that carry one.
fn read_label(r: &mut Reader) -> IdlogResult<String> {
    let label = r.string()?;
    if label.len() > MAX_DEVICE_LABEL_BYTES {
        return Err(IdlogError::Format("device label too long".into()));
    }
    Ok(label)
}

impl From<ReadError> for IdlogError {
    fn from(e: ReadError) -> Self {
        IdlogError::Format(e.to_string())
    }
}

/// A body is consumed exactly, so bytes the signature does not cover can never ride along.
fn decode_body(entry_type: EntryType, data: &[u8]) -> IdlogResult<EntryBody> {
    read_body(entry_type, data).map_err(|e| match e {
        IdlogError::Format(msg) => IdlogError::Format(format!("{entry_type:?} body: {msg}")),
        other => other,
    })
}

fn read_body(entry_type: EntryType, data: &[u8]) -> IdlogResult<EntryBody> {
    let mut r = Reader::new(data);
    let body = match entry_type {
        EntryType::Genesis => EntryBody::Genesis {
            genesis_verifying_key: r.array()?,
            device_verifying_key: r.array()?,
            device_label: read_label(&mut r)?,
        },
        EntryType::AddDevice => EntryBody::AddDevice {
            device_verifying_key: r.array()?,
            device_label: read_label(&mut r)?,
            authorizer_key: r.array()?,
        },
        EntryType::RevokeDevice => EntryBody::RevokeDevice { device_verifying_key: r.array()?, revoker_key: r.array()? },
        EntryType::RenameDevice => EntryBody::RenameDevice {
            device_verifying_key: r.array()?,
            device_label: read_label(&mut r)?,
            authorizer_key: r.array()?,
        },
        EntryType::Recovery => EntryBody::Recovery { device_verifying_key: r.array()?, device_label: read_label(&mut r)? },
        EntryType::SetHomeRelay => {
            let relay_vk = r.array()?;
            let authorizer_key = r.array()?;
            let relay_ref = RelayRef::from_bytes(r.prefixed16()?).map_err(|e| IdlogError::Format(e.to_string()))?;
            EntryBody::SetHomeRelay { relay_vk, authorizer_key, relay_ref }
        }
        EntryType::DeviceKey => {
            let device_verifying_key = r.array()?;
            let kind = DeviceKeyKind::try_from(r.u8()?).map_err(|v| IdlogError::Format(format!("unknown device key kind {v:#x}")))?;
            let public_key = <[u8; 32]>::try_from(r.prefixed16()?)
                .map_err(|_| IdlogError::Format("public key must be 32 bytes".into()))?;
            EntryBody::DeviceKey { device_verifying_key, kind, public_key, authorizer_key: r.array()?, device_signature: r.array()? }
        }
        EntryType::RotateRoot => EntryBody::RotateRoot {
            new_root_key: r.array()?,
            recovery_box_key: r.array()?,
            device_verifying_key: r.array()?,
            device_signature: r.array()?,
        },
        EntryType::AccountKey => {
            let generation = r.u32()?;
            let verifying_key = r.array()?;
            let encryption_key = r.array()?;
            let set_digest = r.array()?;
            let authorizer_key = r.array()?;
            let count = r.u8()? as usize;
            let mut recipients = Vec::with_capacity(count);
            for _ in 0..count {
                let kind = RecipientKind::try_from(r.u8()?).map_err(|v| IdlogError::Format(format!("unknown recipient kind {v:#x}")))?;
                recipients.push(Recipient { kind, id: r.array()? });
            }
            EntryBody::AccountKey { generation, verifying_key, encryption_key, set_digest, authorizer_key, recipients }
        }
    };
    r.finish()?;
    Ok(body)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_entries::*;
    use crate::test_support::*;

    // ── Genesis ─────────────────────────────────────────────────

    #[test]
    fn genesis_creates_valid_chain() {
        let (state, mk, dk) = build_genesis();
        assert_eq!(state.head_seq, 1);
        assert!(state.is_active_device(&dk.verifying_key().to_bytes()));
        assert_eq!(state.genesis_verifying_key.unwrap(), mk.verifying_key().to_bytes());
        assert_eq!(state.active_devices().count(), 1);
    }

    #[test]
    fn genesis_must_be_seq_1() {
        let (mk, _) = genesis_key_and_fp();
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
    fn add_device_by_genesis_key_before_rotation() {
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
        let entry2 = create_add_device(&state, &dk, &dk2, "device-2-again");
        assert!(validate_entry(&mut state, &entry2).is_err());
    }

    // ── RenameDevice ────────────────────────────────────────────

    #[test]
    fn rename_device_by_an_active_device() {
        let (state, _mk, dk) = build_genesis();
        let dk2 = random_key();
        let add = create_add_device(&state, &dk, &dk2, "device-2");
        let mut state = state;
        validate_entry(&mut state, &add).unwrap();

        let dk2_vk = dk2.verifying_key().to_bytes();
        let entry = create_rename_device(&state, &dk2, &dk2_vk, "my phone");
        validate_entry(&mut state, &entry).unwrap();
        assert_eq!(state.devices[&dk2_vk].label, "my phone");
        assert_eq!(state.active_devices().count(), 2, "a rename changes nothing else");

        let roundtrip = LogEntry::from_bytes(&entry.to_bytes()).unwrap();
        assert_eq!(entry_hash(&roundtrip), entry_hash(&entry));
    }

    #[test]
    fn rename_device_rejects_an_outsider_and_a_revoked_target() {
        let (state, _mk, dk) = build_genesis();
        let dk2 = random_key();
        let add = create_add_device(&state, &dk, &dk2, "device-2");
        let mut state = state;
        validate_entry(&mut state, &add).unwrap();
        let dk2_vk = dk2.verifying_key().to_bytes();

        let rogue = random_key();
        assert!(validate_entry(&mut state.clone(), &create_rename_device(&state, &rogue, &dk2_vk, "mine now")).is_err());

        let revoke = create_revoke_device(&state, &dk, &dk2_vk);
        validate_entry(&mut state, &revoke).unwrap();
        let rename_revoked = create_rename_device(&state, &dk, &dk2_vk, "gone");
        assert!(validate_entry(&mut state, &rename_revoked).is_err());
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
    fn revoke_by_genesis_key_before_rotation() {
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
    fn recovery_requires_the_root() {
        let (state, _mk, dk) = build_genesis();
        let recovery_dk = random_key();
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

    // ── SetHomeRelay ────────────────────────────────────────────

    #[test]
    fn set_home_relay_by_device_records_home() {
        let (mut state, _mk, dk) = build_genesis();
        assert!(state.home_relay_vk.is_none());
        let relay_ref = RelayRef::https([0x77; 32], "http://relay-a:7700");
        let entry = create_set_home_relay(&state, &dk, relay_ref.clone());
        validate_entry(&mut state, &entry).unwrap();
        assert_eq!(state.home_relay_vk, Some([0x77; 32]));
        assert_eq!(state.home_relay_ref, Some(relay_ref));
        assert_eq!(state.home_set_at_seq, 2);
    }

    #[test]
    fn set_home_relay_by_genesis_key_before_rotation() {
        let (mut state, mk, _dk) = build_genesis();
        let entry = create_set_home_relay(&state, &mk, RelayRef::key_only([0x78; 32]));
        validate_entry(&mut state, &entry).unwrap();
        assert_eq!(state.home_relay_vk, Some([0x78; 32]));
    }

    #[test]
    fn set_home_relay_replaces_previous_home() {
        let (mut state, _mk, dk) = build_genesis();
        let first = create_set_home_relay(&state, &dk, RelayRef::https([0x01; 32], "http://a"));
        validate_entry(&mut state, &first).unwrap();
        let second = create_set_home_relay(&state, &dk, RelayRef::https([0x02; 32], "http://b"));
        validate_entry(&mut state, &second).unwrap();
        assert_eq!(state.home_relay_vk, Some([0x02; 32]));
        assert_eq!(state.home_set_at_seq, 3);
    }

    #[test]
    fn set_home_relay_rejects_unauthorized_signer() {
        let (mut state, _mk, _dk) = build_genesis();
        let rogue = random_key();
        let entry = create_set_home_relay(&state, &rogue, RelayRef::key_only([0x77; 32]));
        assert!(validate_entry(&mut state, &entry).is_err());
        assert!(state.home_relay_vk.is_none());
    }

    #[test]
    fn set_home_relay_rejects_revoked_authorizer() {
        let (mut state, _mk, dk) = build_genesis();
        let dk2 = random_key();
        let add = create_add_device(&state, &dk, &dk2, "d2");
        validate_entry(&mut state, &add).unwrap();
        let revoke = create_revoke_device(&state, &dk, &dk2.verifying_key().to_bytes());
        validate_entry(&mut state, &revoke).unwrap();
        let entry = create_set_home_relay(&state, &dk2, RelayRef::key_only([0x77; 32]));
        assert!(validate_entry(&mut state, &entry).is_err());
    }

    #[test]
    fn set_home_relay_rejects_ref_naming_other_relay() {
        let (mut state, _mk, dk) = build_genesis();
        let mut entry = create_set_home_relay(&state, &dk, RelayRef::key_only([0x77; 32]));
        if let EntryBody::SetHomeRelay { relay_vk, .. } = &mut entry.body {
            *relay_vk = [0x78; 32];
        }
        sign_entry(&dk, &mut entry);
        assert!(validate_entry(&mut state, &entry).is_err());
    }

    #[test]
    fn set_home_relay_before_genesis_rejected() {
        let dk = random_key();
        let state = LogState::empty([0x33; 32]);
        let entry = create_set_home_relay(&state, &dk, RelayRef::key_only([0x77; 32]));
        let mut state = state;
        assert!(validate_entry(&mut state, &entry).is_err());
    }

    #[test]
    fn set_home_relay_roundtrips_wire_format() {
        let (state, _mk, dk) = build_genesis();
        let relay_ref = RelayRef::https([0x77; 32], "http://relay-a:7700");
        let entry = create_set_home_relay(&state, &dk, relay_ref.clone());
        let decoded = LogEntry::from_bytes(&entry.to_bytes()).unwrap();
        assert_eq!(decoded.entry_type, EntryType::SetHomeRelay);
        assert_eq!(entry_hash(&decoded), entry_hash(&entry));
        match decoded.body {
            EntryBody::SetHomeRelay { relay_vk, authorizer_key, relay_ref: r } => {
                assert_eq!(relay_vk, [0x77; 32]);
                assert_eq!(authorizer_key, dk.verifying_key().to_bytes());
                assert_eq!(r, relay_ref);
            }
            other => panic!("wrong body: {other:?}"),
        }
    }

    // ── Chain integrity ─────────────────────────────────────────

    #[test]
    fn tampered_signature_rejected() {
        let (mk, _) = genesis_key_and_fp();
        let dk = random_key();
        let mut entry = create_genesis(&mk, &dk, "d1");
        entry.signature[0] ^= 0xFF;
        assert!(validate_chain(&[entry]).is_err());
    }

    #[test]
    fn tampered_body_rejected() {
        let (mk, _) = genesis_key_and_fp();
        let dk = random_key();
        let mut entry = create_genesis(&mk, &dk, "d1");
        entry.body = EntryBody::Genesis {
            genesis_verifying_key: mk.verifying_key().to_bytes(),
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
        let (mk, _) = genesis_key_and_fp();
        let dk = random_key();
        let entry = create_genesis(&mk, &dk, "my-laptop");
        let bytes = entry.to_bytes();
        let restored = LogEntry::from_bytes(&bytes).unwrap();
        validate_chain(&[restored]).unwrap();
    }

    #[test]
    fn full_chain_roundtrip() {
        let (mk, _) = genesis_key_and_fp();
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

        let entries = [genesis, add, revoke, recovery];
        let serialized: Vec<Vec<u8>> = entries.iter().map(|e| e.to_bytes()).collect();
        let restored: Vec<LogEntry> = serialized.iter().map(|b| LogEntry::from_bytes(b).unwrap()).collect();

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
        let (mk, _) = genesis_key_and_fp();
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
        let (mk, _) = genesis_key_and_fp();
        let dk = random_key();
        let genesis = create_genesis(&mk, &dk, "d1");
        let state = validate_chain(&[genesis.clone()]).unwrap();

        let dk2 = random_key();
        let mut entry = LogEntry {
            seq: 2,
            prev_hash: state.head_hash,
            account_fp: state.account_fp,
            entry_type: EntryType::Genesis,
            timestamp: now_millis(),
            body: EntryBody::Genesis {
                genesis_verifying_key: mk.verifying_key().to_bytes(),
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

        let readd = create_add_device(&state, &dk, &dk2, "device-2-again");
        let err = validate_entry(&mut state, &readd).unwrap_err();
        assert!(err.to_string().contains("duplicate device key"));
    }

    // ── Revoke edge cases ────────────────────────────────────────

    #[test]
    fn revoke_nonexistent_device_rejected() {
        let (state, _mk, dk) = build_genesis();
        let phantom = random_key();
        let entry = create_revoke_device(&state, &dk, &phantom.verifying_key().to_bytes());
        let mut state = state;
        let err = validate_entry(&mut state, &entry).unwrap_err();
        assert!(err.to_string().contains("device not active"));
    }

    #[test]
    fn double_revoke_rejected() {
        let (state, _mk, dk) = build_genesis();
        let dk2 = random_key();
        let add2 = create_add_device(&state, &dk, &dk2, "device-2");
        let mut state = state;
        validate_entry(&mut state, &add2).unwrap();

        let revoke = create_revoke_device(&state, &dk, &dk2.verifying_key().to_bytes());
        validate_entry(&mut state, &revoke).unwrap();

        let revoke_again = create_revoke_device(&state, &dk, &dk2.verifying_key().to_bytes());
        let err = validate_entry(&mut state, &revoke_again).unwrap_err();
        assert!(err.to_string().contains("device not active"));
    }

    // ── Missing counter-signatures ──────────────────────────────

    #[test]
    fn missing_counter_sig_on_genesis_rejected() {
        let (mk, _) = genesis_key_and_fp();
        let dk = random_key();
        let mut entry = create_genesis(&mk, &dk, "d1");
        entry.counter_signature = None;
        assert!(validate_chain(&[entry]).is_err());
    }

    #[test]
    fn missing_counter_sig_on_add_device_rejected() {
        let (state, _mk, dk) = build_genesis();
        let dk2 = random_key();
        let mut entry = create_add_device(&state, &dk, &dk2, "device-2");
        entry.counter_signature = None;
        let mut state = state;
        assert!(validate_entry(&mut state, &entry).is_err());
    }

    // ── account_fp mismatch on non-genesis entry ───────────────

    #[test]
    fn account_fp_mismatch_on_add_device_rejected() {
        let (state, _mk, dk) = build_genesis();
        let new_dk = random_key();

        let mut entry = LogEntry {
            seq: state.head_seq + 1,
            prev_hash: state.head_hash,
            account_fp: [0xFF; 32],
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

    // ── Root rotation ───────────────────────────────────────────

    #[test]
    fn rotate_root_needs_the_current_root_and_an_active_device() {
        let (mut state, genesis, device) = build_genesis();
        let root = random_key();

        let by_device = create_rotate_root(&state, &device, &root, [0x02; 32], &device);
        assert!(validate_entry(&mut state.clone(), &by_device).is_err(), "a device is not the root");

        let outsider = random_key();
        let unknown_cosigner = create_rotate_root(&state, &genesis, &root, [0x02; 32], &outsider);
        assert!(validate_entry(&mut state.clone(), &unknown_cosigner).is_err(), "co-signer must be active");

        let mut unproven = create_rotate_root(&state, &genesis, &root, [0x02; 32], &device);
        counter_sign(&outsider, &mut unproven);
        assert!(validate_entry(&mut state.clone(), &unproven).is_err(), "new root must prove possession");

        let same = create_rotate_root(&state, &genesis, &genesis, [0x02; 32], &device);
        assert!(validate_entry(&mut state.clone(), &same).is_err(), "rotation must change the root");

        let good = create_rotate_root(&state, &genesis, &root, [0x02; 32], &device);
        validate_entry(&mut state, &good).unwrap();
        assert_eq!(state.root_verifying_key, Some(root.verifying_key().to_bytes()));
        assert_eq!(state.genesis_verifying_key, Some(genesis.verifying_key().to_bytes()));
        assert_eq!(state.recovery_box_key, Some([0x02; 32]));
        assert!(state.root_rotated());
    }

    #[test]
    fn genesis_key_has_no_authority_once_rotated() {
        let rotated = build_rotated();
        let state = rotated.state;
        let device_vk = rotated.device.verifying_key().to_bytes();
        let new_device = random_key();
        let attempts = [
            create_recovery(&state, &rotated.genesis, &new_device, "takeover"),
            create_add_device(&state, &rotated.genesis, &new_device, "minted"),
            create_revoke_device(&state, &rotated.genesis, &device_vk),
            create_set_home_relay(&state, &rotated.genesis, RelayRef::key_only([0x66; 32])),
            create_rotate_root(&state, &rotated.genesis, &random_key(), [0x03; 32], &rotated.device),
        ];
        for entry in attempts {
            assert!(validate_entry(&mut state.clone(), &entry).is_err(), "{:?} signed by the genesis key", entry.entry_type);
        }
        let recovery = create_recovery(&state, &rotated.root, &new_device, "owner");
        validate_entry(&mut state.clone(), &recovery).unwrap();
    }

    #[test]
    fn only_the_root_moves_the_home_once_rotated() {
        let rotated = build_rotated();
        let by_device = create_set_home_relay(&rotated.state, &rotated.device, RelayRef::key_only([0x66; 32]));
        assert!(validate_entry(&mut rotated.state.clone(), &by_device).is_err());
        let mut state = rotated.state;
        let by_root = create_set_home_relay(&state, &rotated.root, RelayRef::key_only([0x66; 32]));
        validate_entry(&mut state, &by_root).unwrap();
        assert_eq!(state.home_relay_vk, Some([0x66; 32]));
    }

    #[test]
    fn recovery_cannot_reuse_a_revoked_device_key() {
        let rotated = build_rotated();
        let mut state = rotated.state;
        let second = random_key();
        let add = create_add_device(&state, &rotated.device, &second, "phone");
        validate_entry(&mut state, &add).unwrap();
        let revoke = create_revoke_device(&state, &rotated.device, &second.verifying_key().to_bytes());
        validate_entry(&mut state, &revoke).unwrap();
        let resurrect = create_recovery(&state, &rotated.root, &second, "phone again");
        let err = validate_entry(&mut state, &resurrect).unwrap_err();
        assert!(err.to_string().contains("duplicate device key"));
    }

    // ── Device keys ─────────────────────────────────────────────

    #[test]
    fn device_key_needs_the_devices_signature_and_never_changes() {
        let (mut state, _genesis, device) = build_genesis();
        let second = random_key();
        let add = create_add_device(&state, &device, &second, "phone");
        validate_entry(&mut state, &add).unwrap();

        let mut forged = create_device_key(&state, &device, &second, [0x09; 32]);
        if let EntryBody::DeviceKey { device_signature, .. } = &mut forged.body {
            device_signature[0] ^= 1;
        }
        sign_entry(&device, &mut forged);
        assert!(validate_entry(&mut state.clone(), &forged).is_err(), "the device must consent");

        let by_outsider = create_device_key(&state, &random_key(), &second, [0x09; 32]);
        assert!(validate_entry(&mut state.clone(), &by_outsider).is_err(), "publisher must be active");

        let by_other_device = create_device_key(&state, &device, &second, [0x09; 32]);
        validate_entry(&mut state, &by_other_device).unwrap();
        assert_eq!(state.devices[&second.verifying_key().to_bytes()].encryption_key, Some([0x09; 32]));

        let again = create_device_key(&state, &second, &second, [0x0A; 32]);
        assert!(validate_entry(&mut state, &again).is_err(), "keys never change");
    }

    // ── Account keys and coverage ───────────────────────────────

    #[test]
    fn account_key_only_after_the_root_rotates() {
        let (mut state, _genesis, device) = build_genesis();
        let key = create_device_key(&state, &device, &device, [0x01; 32]);
        validate_entry(&mut state, &key).unwrap();
        let (entry, _) = rekey(&state, &device);
        assert!(validate_entry(&mut state, &entry).is_err());
        assert!(!state.rekey_needed(), "nothing to cover before the root rotates");
    }

    #[test]
    fn account_key_must_cover_exactly_the_active_devices_and_the_recovery_box() {
        let rotated = build_rotated();
        let mut state = rotated.state;
        assert_eq!(state.account_key().unwrap().generation, 1);
        assert!(!state.rekey_needed());
        let device_vk = rotated.device.verifying_key().to_bytes();
        assert_eq!(state.coverage(), vec![Recipient::device(device_vk), Recipient::recovery([0x02; 32])]);

        let mut missing_recovery = key_set_for(&state);
        missing_recovery.copies.retain(|c| c.recipient.kind == RecipientKind::Device);
        let entry = create_account_key(&state, &rotated.device, &random_key(), [0x77; 32], &missing_recovery);
        assert!(validate_entry(&mut state.clone(), &entry).is_err());

        let mut stranger = key_set_for(&state);
        stranger.copies[0].recipient = Recipient::device([0xEE; 32]);
        stranger.copies.sort_by_key(|c| c.recipient);
        let entry = create_account_key(&state, &rotated.device, &random_key(), [0x77; 32], &stranger);
        assert!(validate_entry(&mut state.clone(), &entry).is_err());

        let mut skipped = key_set_for(&state);
        skipped.generation = 3;
        let entry = create_account_key(&state, &rotated.device, &random_key(), [0x77; 32], &skipped);
        assert!(validate_entry(&mut state.clone(), &entry).is_err(), "generations go up by one");

        let (entry, _) = rekey(&state, &rotated.device);
        validate_entry(&mut state, &entry).unwrap();
        assert_eq!(state.account_key().unwrap().generation, 2);
        assert_eq!(state.account_keys.len(), 2);
    }

    #[test]
    fn revocation_leaves_rekey_needed_until_an_account_key_covers_the_rest() {
        let rotated = build_rotated();
        let mut state = rotated.state;
        let second = random_key();
        let add = create_add_device(&state, &rotated.device, &second, "phone");
        validate_entry(&mut state, &add).unwrap();
        assert!(!state.rekey_needed(), "a device without an encryption key is outside coverage");

        let key = create_device_key(&state, &rotated.device, &second, [0x03; 32]);
        validate_entry(&mut state, &key).unwrap();
        assert!(state.rekey_needed(), "its key brings it into coverage");
        let (entry, _) = rekey(&state, &rotated.device);
        validate_entry(&mut state, &entry).unwrap();
        assert!(!state.rekey_needed());

        let revoke = create_revoke_device(&state, &rotated.device, &second.verifying_key().to_bytes());
        validate_entry(&mut state, &revoke).unwrap();
        assert!(state.rekey_needed(), "the current generation still covers the revoked device");
        let (entry, _) = rekey(&state, &rotated.device);
        validate_entry(&mut state, &entry).unwrap();
        assert!(!state.rekey_needed());
        assert!(!state.account_key().unwrap().recipients.contains(&Recipient::device(second.verifying_key().to_bytes())));
    }

    #[test]
    fn rotation_changes_coverage_to_the_new_recovery_box() {
        let rotated = build_rotated();
        let mut state = rotated.state;
        let rotate = create_rotate_root(&state, &rotated.root, &random_key(), [0x04; 32], &rotated.device);
        validate_entry(&mut state, &rotate).unwrap();
        assert!(state.rekey_needed());
        assert!(state.coverage().contains(&Recipient::recovery([0x04; 32])));
    }

    #[test]
    fn new_entry_types_roundtrip_wire_format() {
        let rotated = build_rotated();
        for entry in &rotated.entries {
            let decoded = LogEntry::from_bytes(&entry.to_bytes()).unwrap();
            assert_eq!(entry_hash(&decoded), entry_hash(entry));
        }
        let decoded: Vec<LogEntry> = rotated.entries.iter().map(|e| LogEntry::from_bytes(&e.to_bytes()).unwrap()).collect();
        let state = validate_chain(&decoded).unwrap();
        assert_eq!(state.head_hash, rotated.state.head_hash);
    }

    #[test]
    fn bodies_with_trailing_bytes_are_rejected() {
        let (mk, _) = genesis_key_and_fp();
        let entry = create_genesis(&mk, &random_key(), "d1");
        let mut bytes = entry.to_bytes();
        let body_len = u32::from_be_bytes(bytes[81..85].try_into().unwrap());
        bytes[81..85].copy_from_slice(&(body_len + 1).to_be_bytes());
        bytes.insert(85 + body_len as usize, 0);
        let err = LogEntry::from_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("trailing bytes"));
    }

    // ── Forks ───────────────────────────────────────────────────

    #[test]
    fn a_recovery_branch_replaces_a_device_only_suffix() {
        let rotated = build_rotated();
        let prefix = rotated.state;
        let mut held_state = prefix.clone();
        let second = random_key();
        let held = vec![create_add_device(&held_state, &rotated.device, &second, "thief")];
        validate_entry(&mut held_state, &held[0]).unwrap();

        let incoming = vec![create_recovery(&prefix, &rotated.root, &random_key(), "owner")];
        assert_eq!(choose_branch(&prefix, &held, &incoming).unwrap(), BranchChoice::Replace);
        assert_eq!(choose_branch(&prefix, &incoming, &held).unwrap(), BranchChoice::Keep, "device history never replaces root history");
    }

    #[test]
    fn a_held_root_signed_suffix_is_never_replaced() {
        let rotated = build_rotated();
        let prefix = rotated.state;
        let held = vec![create_rotate_root(&prefix, &rotated.root, &random_key(), [0x05; 32], &rotated.device)];
        let incoming = vec![create_recovery(&prefix, &rotated.root, &random_key(), "old key")];
        assert_eq!(choose_branch(&prefix, &held, &incoming).unwrap(), BranchChoice::Keep);
    }

    #[test]
    fn an_invalid_branch_is_an_error_not_a_choice() {
        let rotated = build_rotated();
        let prefix = rotated.state;
        let held = vec![create_add_device(&prefix, &rotated.device, &random_key(), "phone")];
        let forged = vec![create_recovery(&prefix, &rotated.genesis, &random_key(), "genesis key")];
        assert!(choose_branch(&prefix, &held, &forged).is_err());
    }
}

