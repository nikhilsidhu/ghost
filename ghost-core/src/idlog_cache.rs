use std::collections::HashMap;

use ghost_wire::idlog::{LogEntry, LogState, validate_chain};

use crate::error::{GhostError, Result};
use crate::storage::GhostStore;

/// In-memory cache of validated identity log states, keyed by account fingerprint.
/// Must be populated before processing inbound MLS messages so that credential
/// validation is a pure lookup with no I/O.
pub struct IdLogCache {
    states: HashMap<[u8; 32], LogState>,
}

impl IdLogCache {
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
        }
    }

    /// Insert a pre-validated LogState directly (e.g. for our own account).
    pub fn insert(&mut self, state: LogState) {
        self.states.insert(state.account_fp, state);
    }

    /// Check if a device is authorized for an account. Returns Err if the
    /// account's identity log hasn't been cached yet.
    pub fn is_active_device(
        &self,
        account_fp: &[u8; 32],
        device_vk: &[u8; 32],
    ) -> Result<bool> {
        let state = self.states.get(account_fp).ok_or_else(|| {
            GhostError::IdentityLog(format!(
                "no cached identity log for account {}",
                hex::encode(&account_fp[..8])
            ))
        })?;
        Ok(state.is_active_device(device_vk))
    }

    /// Get the cached LogState for an account, if present.
    pub fn get(&self, account_fp: &[u8; 32]) -> Option<&LogState> {
        self.states.get(account_fp)
    }

    /// Load an identity log from the local DB cache, validate the chain,
    /// and store the resulting LogState in memory.
    pub fn load_from_store(
        &mut self,
        store: &GhostStore,
        account_fp: &[u8; 32],
    ) -> Result<Option<&LogState>> {
        let raw_entries = store.get_cached_idlog_entries(account_fp)?;
        if raw_entries.is_empty() {
            return Ok(None);
        }

        let entries: Vec<LogEntry> = raw_entries
            .iter()
            .map(|(_seq, payload)| LogEntry::from_bytes(payload))
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let state = validate_chain(&entries)?;
        self.states.insert(*account_fp, state);
        Ok(self.states.get(account_fp))
    }

    /// Cache identity log entries from the relay into the local DB, validate
    /// the full chain, and store the resulting LogState in memory.
    pub fn cache_and_validate(
        &mut self,
        store: &GhostStore,
        account_fp: &[u8; 32],
        raw_entries: &[(u64, Vec<u8>)],
    ) -> Result<()> {
        if raw_entries.is_empty() {
            return Ok(());
        }

        // Persist to local DB first
        store.cache_idlog_entries(account_fp, raw_entries)?;

        // Load all entries (including any previously cached) and validate
        let all_entries = store.get_cached_idlog_entries(account_fp)?;
        let entries: Vec<LogEntry> = all_entries
            .iter()
            .map(|(_seq, payload)| LogEntry::from_bytes(payload))
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let state = validate_chain(&entries)?;
        store.upsert_idlog_state(account_fp, &state)?;
        self.states.insert(*account_fp, state);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use ghost_wire::idlog::*;
    use rand::rngs::OsRng;

    fn random_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn sign_entry(key: &SigningKey, entry: &mut LogEntry) {
        entry.signature = key.sign(&sign_message(entry)).to_bytes();
    }

    fn counter_sign(key: &SigningKey, entry: &mut LogEntry) {
        entry.counter_signature = Some(key.sign(&sign_message(entry)).to_bytes());
    }

    /// Create a valid genesis entry and return (entry_bytes, account_fp, master_sk, device_sk).
    fn make_genesis() -> (Vec<u8>, [u8; 32], SigningKey, SigningKey) {
        let mk = random_key();
        let dk = random_key();
        let account_fp: [u8; 32] = blake3::hash(mk.verifying_key().as_bytes()).into();
        let mut entry = LogEntry {
            seq: 1,
            prev_hash: [0u8; 32],
            account_fp,
            entry_type: EntryType::Genesis,
            timestamp: 1000,
            body: EntryBody::Genesis {
                master_verifying_key: mk.verifying_key().to_bytes(),
                device_verifying_key: dk.verifying_key().to_bytes(),
                device_label: "test-device".to_string(),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        sign_entry(&mk, &mut entry);
        counter_sign(&dk, &mut entry);
        (entry.to_bytes(), account_fp, mk, dk)
    }

    #[test]
    fn cache_and_lookup_active_device() {
        let (genesis_bytes, account_fp, _mk, dk) = make_genesis();
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        let mut cache = IdLogCache::new();

        cache
            .cache_and_validate(&store, &account_fp, &[(1, genesis_bytes)])
            .unwrap();

        let device_vk = dk.verifying_key().to_bytes();
        assert!(cache.is_active_device(&account_fp, &device_vk).unwrap());
    }

    #[test]
    fn revoked_device_rejected() {
        let (genesis_bytes, account_fp, mk, dk) = make_genesis();
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        let mut cache = IdLogCache::new();

        // Add a second device then revoke it
        let dk2 = random_key();
        let state = validate_chain(&[LogEntry::from_bytes(&genesis_bytes).unwrap()]).unwrap();

        let mut add_entry = LogEntry {
            seq: 2,
            prev_hash: state.head_hash,
            account_fp,
            entry_type: EntryType::AddDevice,
            timestamp: 2000,
            body: EntryBody::AddDevice {
                device_verifying_key: dk2.verifying_key().to_bytes(),
                device_label: "phone".to_string(),
                authorizer_key: mk.verifying_key().to_bytes(),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        sign_entry(&mk, &mut add_entry);
        counter_sign(&dk2, &mut add_entry);
        let add_bytes = add_entry.to_bytes();

        let mut state2 = state;
        validate_entry(&mut state2, &add_entry).unwrap();

        let mut revoke_entry = LogEntry {
            seq: 3,
            prev_hash: state2.head_hash,
            account_fp,
            entry_type: EntryType::RevokeDevice,
            timestamp: 3000,
            body: EntryBody::RevokeDevice {
                device_verifying_key: dk2.verifying_key().to_bytes(),
                revoker_key: dk.verifying_key().to_bytes(),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        sign_entry(&dk, &mut revoke_entry);
        let revoke_bytes = revoke_entry.to_bytes();

        cache
            .cache_and_validate(
                &store,
                &account_fp,
                &[
                    (1, genesis_bytes),
                    (2, add_bytes),
                    (3, revoke_bytes),
                ],
            )
            .unwrap();

        let dk2_vk = dk2.verifying_key().to_bytes();
        assert!(!cache.is_active_device(&account_fp, &dk2_vk).unwrap());
        // Original device still active
        assert!(cache.is_active_device(&account_fp, &dk.verifying_key().to_bytes()).unwrap());
    }

    #[test]
    fn unknown_account_returns_error() {
        let cache = IdLogCache::new();
        let result = cache.is_active_device(&[0xFF; 32], &[0xAA; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn direct_insert_works() {
        let mut cache = IdLogCache::new();
        let fp = [0x11; 32];
        let state = LogState {
            account_fp: fp,
            master_verifying_key: Some([0x22; 32]),
            devices: HashMap::new(),
            head_seq: 1,
            head_hash: [0x33; 32],
        };
        cache.insert(state);
        assert!(cache.get(&fp).is_some());
    }

    #[test]
    fn load_from_store_validates_chain() {
        let (genesis_bytes, account_fp, _mk, dk) = make_genesis();
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        store.cache_idlog_entries(&account_fp, &[(1, genesis_bytes)]).unwrap();

        let mut cache = IdLogCache::new();
        let state = cache.load_from_store(&store, &account_fp).unwrap().unwrap();
        assert_eq!(state.head_seq, 1);
        assert!(state.is_active_device(&dk.verifying_key().to_bytes()));
    }
}
