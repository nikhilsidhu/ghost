// Re-export all types and validation from ghost-wire so existing callers don't break.
pub use ghost_wire::idlog::{
    DeviceInfo, EntryBody, EntryType, IdlogError, IdlogResult, LogEntry, LogState,
    entry_hash, sign_message, validate_chain, validate_entry,
};

use ed25519_dalek::SigningKey;

// ── Entry creation helpers ──────────────────────────────────────────

fn sign_entry(key: &SigningKey, entry: &mut LogEntry) {
    use ed25519_dalek::Signer;
    entry.signature = key.sign(&sign_message(entry)).to_bytes();
}

fn counter_sign(key: &SigningKey, entry: &mut LogEntry) {
    use ed25519_dalek::Signer;
    entry.counter_signature = Some(key.sign(&sign_message(entry)).to_bytes());
}

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

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
