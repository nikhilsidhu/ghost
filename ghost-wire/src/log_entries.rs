//! Building and signing identity log entries. Each builder extends a given state, so
//! the entry lands at its next position; the validator in `idlog` is the judge.

use crate::now_millis;
use ed25519_dalek::{Signer, SigningKey};

use crate::account_key::AccountKeySet;
use crate::idlog::{
    device_key_message, rotate_root_message, sign_message, DeviceKeyKind, EntryBody, EntryType, LogEntry, LogState,
    MAX_DEVICE_LABEL_BYTES,
};
use crate::relay_ref::RelayRef;

/// A device label as an entry carries it: cut to `MAX_DEVICE_LABEL_BYTES` on a character
/// boundary, so what a user typed never makes an entry no relay accepts.
pub fn clamp_label(label: &str) -> String {
    let mut end = label.len().min(MAX_DEVICE_LABEL_BYTES);
    while !label.is_char_boundary(end) {
        end -= 1;
    }
    label[..end].to_string()
}

pub fn sign_entry(key: &SigningKey, entry: &mut LogEntry) {
    entry.signature = key.sign(&sign_message(entry)).to_bytes();
}

pub fn counter_sign(key: &SigningKey, entry: &mut LogEntry) {
    entry.counter_signature = Some(key.sign(&sign_message(entry)).to_bytes());
}

/// An unsigned entry at `state`'s next position.
fn next_entry(state: &LogState, entry_type: EntryType, body: EntryBody) -> LogEntry {
    LogEntry {
        seq: state.head_seq + 1,
        prev_hash: state.head_hash,
        account_fp: state.account_fp,
        entry_type,
        timestamp: now_millis(),
        body,
        signature: [0u8; 64],
        counter_signature: None,
    }
}

/// The first entry of an account: `genesis_key` fixes the fingerprint and signs,
/// the first device counter-signs.
pub fn create_genesis(genesis_key: &SigningKey, device_key: &SigningKey, device_label: &str) -> LogEntry {
    let genesis_vk = genesis_key.verifying_key().to_bytes();
    let mut entry = LogEntry {
        seq: 1,
        prev_hash: [0u8; 32],
        account_fp: blake3::hash(&genesis_vk).into(),
        entry_type: EntryType::Genesis,
        timestamp: now_millis(),
        body: EntryBody::Genesis {
            genesis_verifying_key: genesis_vk,
            device_verifying_key: device_key.verifying_key().to_bytes(),
            device_label: clamp_label(device_label),
        },
        signature: [0u8; 64],
        counter_signature: None,
    };
    sign_entry(genesis_key, &mut entry);
    counter_sign(device_key, &mut entry);
    entry
}

/// An `AddDevice` signed by `authorizer` and still waiting for the new device's
/// counter-signature, which the new device adds itself.
pub fn draft_add_device(state: &LogState, authorizer: &SigningKey, new_device_vk: [u8; 32], device_label: &str) -> LogEntry {
    let mut entry = next_entry(state, EntryType::AddDevice, EntryBody::AddDevice {
        device_verifying_key: new_device_vk,
        device_label: clamp_label(device_label),
        authorizer_key: authorizer.verifying_key().to_bytes(),
    });
    sign_entry(authorizer, &mut entry);
    entry
}

/// A complete `AddDevice`, for when both keys are at hand.
pub fn create_add_device(state: &LogState, authorizer: &SigningKey, new_device: &SigningKey, device_label: &str) -> LogEntry {
    let mut entry = draft_add_device(state, authorizer, new_device.verifying_key().to_bytes(), device_label);
    counter_sign(new_device, &mut entry);
    entry
}

pub fn create_revoke_device(state: &LogState, revoker: &SigningKey, target_vk: &[u8; 32]) -> LogEntry {
    let mut entry = next_entry(state, EntryType::RevokeDevice, EntryBody::RevokeDevice {
        device_verifying_key: *target_vk,
        revoker_key: revoker.verifying_key().to_bytes(),
    });
    sign_entry(revoker, &mut entry);
    entry
}

/// Give a device a new label. `authorizer` is an active device of the account, or
/// before the root rotates also the root.
pub fn create_rename_device(state: &LogState, authorizer: &SigningKey, target_vk: &[u8; 32], device_label: &str) -> LogEntry {
    let mut entry = next_entry(state, EntryType::RenameDevice, EntryBody::RenameDevice {
        device_verifying_key: *target_vk,
        device_label: clamp_label(device_label),
        authorizer_key: authorizer.verifying_key().to_bytes(),
    });
    sign_entry(authorizer, &mut entry);
    entry
}

/// Revoke every device and add `new_device`, signed by the account's root.
pub fn create_recovery(state: &LogState, root: &SigningKey, new_device: &SigningKey, device_label: &str) -> LogEntry {
    let mut entry = next_entry(state, EntryType::Recovery, EntryBody::Recovery {
        device_verifying_key: new_device.verifying_key().to_bytes(),
        device_label: clamp_label(device_label),
    });
    sign_entry(root, &mut entry);
    counter_sign(new_device, &mut entry);
    entry
}

/// Name the relay that sequences this account's log. `authorizer` is the root, or
/// before the root rotates also an active device.
pub fn create_set_home_relay(state: &LogState, authorizer: &SigningKey, relay_ref: RelayRef) -> LogEntry {
    let mut entry = next_entry(state, EntryType::SetHomeRelay, EntryBody::SetHomeRelay {
        relay_vk: relay_ref.relay_vk,
        authorizer_key: authorizer.verifying_key().to_bytes(),
        relay_ref,
    });
    sign_entry(authorizer, &mut entry);
    entry
}

/// A device's consent to publishing `public_key` as its encryption key in `account_fp`.
pub fn device_key_signature(account_fp: &[u8; 32], device: &SigningKey, public_key: &[u8; 32]) -> [u8; 64] {
    let device_vk = device.verifying_key().to_bytes();
    device.sign(&device_key_message(account_fp, &device_vk, DeviceKeyKind::Encryption, public_key)).to_bytes()
}

/// Publish a device's encryption key with the consent it signed earlier; `authorizer`
/// is any active device, which may be the device itself.
pub fn create_device_key_with_signature(
    state: &LogState,
    authorizer: &SigningKey,
    device_vk: [u8; 32],
    public_key: [u8; 32],
    device_signature: [u8; 64],
) -> LogEntry {
    let mut entry = next_entry(state, EntryType::DeviceKey, EntryBody::DeviceKey {
        device_verifying_key: device_vk,
        kind: DeviceKeyKind::Encryption,
        public_key,
        authorizer_key: authorizer.verifying_key().to_bytes(),
        device_signature,
    });
    sign_entry(authorizer, &mut entry);
    entry
}

/// Publish `device`'s encryption key, written by `authorizer`.
pub fn create_device_key(state: &LogState, authorizer: &SigningKey, device: &SigningKey, public_key: [u8; 32]) -> LogEntry {
    let signature = device_key_signature(&state.account_fp, device, &public_key);
    create_device_key_with_signature(state, authorizer, device.verifying_key().to_bytes(), public_key, signature)
}

/// Move the account's authority from `root` to `new_root`, co-signed by an active device.
pub fn create_rotate_root(
    state: &LogState,
    root: &SigningKey,
    new_root: &SigningKey,
    recovery_box_key: [u8; 32],
    device: &SigningKey,
) -> LogEntry {
    let new_root_key = new_root.verifying_key().to_bytes();
    let message =
        rotate_root_message(&state.account_fp, state.head_seq + 1, &state.head_hash, &new_root_key, &recovery_box_key);
    let mut entry = next_entry(state, EntryType::RotateRoot, EntryBody::RotateRoot {
        new_root_key,
        recovery_box_key,
        device_verifying_key: device.verifying_key().to_bytes(),
        device_signature: device.sign(&message).to_bytes(),
    });
    sign_entry(root, &mut entry);
    counter_sign(new_root, &mut entry);
    entry
}

/// The `AccountKey` entry committing to `set`, written by `authorizer` and
/// counter-signed by the generation's own signing key.
pub fn create_account_key(
    state: &LogState,
    authorizer: &SigningKey,
    account_signing_key: &SigningKey,
    encryption_key: [u8; 32],
    set: &AccountKeySet,
) -> LogEntry {
    let mut entry = next_entry(state, EntryType::AccountKey, EntryBody::AccountKey {
        generation: set.generation,
        verifying_key: account_signing_key.verifying_key().to_bytes(),
        encryption_key,
        set_digest: set.digest(),
        authorizer_key: authorizer.verifying_key().to_bytes(),
        recipients: set.recipients(),
    });
    sign_entry(authorizer, &mut entry);
    counter_sign(account_signing_key, &mut entry);
    entry
}

