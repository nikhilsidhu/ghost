use std::collections::HashMap;

use ghost_wire::anchor::{validate_anchored_entry, AnchoredEntry};
use ghost_wire::idlog::{validate_chain, LogEntry, LogState};
use ghost_wire::merkle::Checkpoint;

use crate::error::{GhostError, Result};
use crate::relay::AnchoredLog;
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

    /// Whether the cached log shows this device revoked. An account or device the
    /// cache has not seen is not reported as revoked.
    pub fn is_revoked(&self, account_fp: &[u8; 32], device_vk: &[u8; 32]) -> bool {
        self.states
            .get(account_fp)
            .and_then(|state| state.devices.get(device_vk))
            .is_some_and(|device| !device.is_active())
    }

    /// Get the cached LogState for an account, if present.
    pub fn get(&self, account_fp: &[u8; 32]) -> Option<&LogState> {
        self.states.get(account_fp)
    }

    /// Load an identity log from the local DB cache, validate the chain,
    /// and store the resulting LogState in memory. Anchors were verified when
    /// the rows were cached; offline only the chain itself is rechecked.
    pub fn load_from_store(
        &mut self,
        store: &GhostStore,
        account_fp: &[u8; 32],
    ) -> Result<Option<&LogState>> {
        let rows = store.get_cached_idlog_entries(account_fp)?;
        if rows.is_empty() {
            return Ok(None);
        }

        let mut entries = Vec::with_capacity(rows.len());
        for row in rows {
            let entry = if row.anchored {
                AnchoredEntry::from_bytes(&row.payload)
                    .map_err(|e| GhostError::IdentityLog(format!("cached entry {}: {e}", row.seq)))?
                    .entry
            } else {
                LogEntry::from_bytes(&row.payload)?
            };
            entries.push(entry);
        }

        let state = validate_chain(&entries)?;
        self.states.insert(*account_fp, state);
        Ok(self.states.get(account_fp))
    }

    /// Merge a fetched anchored log with what is already cached, validate the
    /// whole chain together with every anchor, persist, and keep the state in
    /// memory. Nothing is written if any entry or anchor fails, so the local
    /// cache can never hold an entry its home did not sequence.
    ///
    /// Cached rows that predate anchoring are discarded and replaced by the
    /// fetched entries; a fetch always starts at seq 1 today.
    pub fn cache_and_validate(
        &mut self,
        store: &GhostStore,
        account_fp: &[u8; 32],
        log: &AnchoredLog,
    ) -> Result<LogState> {
        if log.entries.is_empty() {
            return Ok(LogState::empty(*account_fp));
        }

        let cached_rows = store.get_cached_idlog_entries(account_fp)?;
        let has_legacy_rows = cached_rows.iter().any(|r| !r.anchored);
        let mut all: Vec<AnchoredEntry> = if has_legacy_rows {
            Vec::new()
        } else {
            store.get_cached_anchored_entries(account_fp)?
        };
        let mut new_entries = Vec::new();
        for anchored in &log.entries {
            if !all.iter().any(|a| a.entry.seq == anchored.entry.seq) {
                all.push(anchored.clone());
                new_entries.push(anchored.clone());
            }
        }
        all.sort_by_key(|a| a.entry.seq);

        let state = validate_anchored_chain(*account_fp, &all, Some(&log.home_relay_vk))?;

        if has_legacy_rows {
            store.clear_idlog_cache(account_fp)?;
            store.cache_anchored_entries(account_fp, &all)?;
        } else {
            store.cache_anchored_entries(account_fp, &new_entries)?;
        }
        store.upsert_idlog_state(account_fp, &state)?;
        self.states.insert(*account_fp, state.clone());
        Ok(state)
    }
}

/// Validate a full anchored chain from genesis. Each entry must be anchored by
/// the home in effect after it, and each home's checkpoints must not move
/// backwards. Entries before the first `SetHomeRelay` were anchored by the relay
/// that entry names, where the account was created; only a chain that names no
/// home at all falls back to `claimed_home`, the serving relay's word.
pub fn validate_anchored_chain(
    account_fp: [u8; 32],
    entries: &[AnchoredEntry],
    claimed_home: Option<&[u8; 32]>,
) -> Result<LogState> {
    if entries.is_empty() {
        return Err(GhostError::IdentityLog("identity log is empty".into()));
    }
    let first_home = entries.iter().find_map(|a| match &a.entry.body {
        ghost_wire::idlog::EntryBody::SetHomeRelay { relay_vk, .. } => Some(*relay_vk),
        _ => None,
    });
    let implied_home = first_home.as_ref().or(claimed_home);
    let mut state = LogState::empty(account_fp);
    let mut last_checkpoint: HashMap<[u8; 32], Checkpoint> = HashMap::new();
    for anchored in entries {
        validate_anchored_entry(&mut state, anchored, implied_home, |home| {
            last_checkpoint.get(home).cloned()
        })
        .map_err(|e| GhostError::IdentityLog(format!("entry {}: {e}", anchored.entry.seq)))?;
        let home = state
            .home_relay_vk
            .or(implied_home.copied())
            .expect("anchored validation succeeded, so a home was known");
        last_checkpoint.insert(home, anchored.checkpoint.clone());
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use ghost_wire::idlog::*;
    use ghost_wire::merkle::{leaf_hash, InclusionProof, MerkleTree};
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

    /// Stand-in for a home relay's KT tree.
    struct FakeHome {
        sk: SigningKey,
        leaves: Vec<[u8; 32]>,
    }

    impl FakeHome {
        fn new() -> Self {
            Self { sk: random_key(), leaves: Vec::new() }
        }

        fn vk(&self) -> [u8; 32] {
            self.sk.verifying_key().to_bytes()
        }

        fn anchor(&mut self, entry: &LogEntry) -> AnchoredEntry {
            self.leaves.push(leaf_hash(&entry.to_bytes()));
            let mut tree = MerkleTree::new();
            for l in &self.leaves {
                tree.append(*l);
            }
            AnchoredEntry {
                entry: entry.clone(),
                inclusion_proof: InclusionProof::generate(self.leaves.len() as u64 - 1, &self.leaves),
                checkpoint: Checkpoint::sign(tree.size(), tree.root(), 1000, &self.sk),
            }
        }

        fn log(&self, entries: Vec<AnchoredEntry>) -> AnchoredLog {
            AnchoredLog { home_relay_vk: self.vk(), entries }
        }
    }

    /// Create a valid genesis entry and return (entry, account_fp, master_sk, device_sk).
    fn make_genesis() -> (LogEntry, [u8; 32], SigningKey, SigningKey) {
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
        (entry, account_fp, mk, dk)
    }

    fn make_add(state: &LogState, auth: &SigningKey, new: &SigningKey) -> LogEntry {
        let mut entry = LogEntry {
            seq: state.head_seq + 1,
            prev_hash: state.head_hash,
            account_fp: state.account_fp,
            entry_type: EntryType::AddDevice,
            timestamp: 2000,
            body: EntryBody::AddDevice {
                device_verifying_key: new.verifying_key().to_bytes(),
                device_label: "phone".to_string(),
                authorizer_key: auth.verifying_key().to_bytes(),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        sign_entry(auth, &mut entry);
        counter_sign(new, &mut entry);
        entry
    }

    fn make_revoke(state: &LogState, revoker: &SigningKey, target: &[u8; 32]) -> LogEntry {
        let mut entry = LogEntry {
            seq: state.head_seq + 1,
            prev_hash: state.head_hash,
            account_fp: state.account_fp,
            entry_type: EntryType::RevokeDevice,
            timestamp: 3000,
            body: EntryBody::RevokeDevice { device_verifying_key: *target, revoker_key: revoker.verifying_key().to_bytes() },
            signature: [0u8; 64],
            counter_signature: None,
        };
        sign_entry(revoker, &mut entry);
        entry
    }

    #[test]
    fn cache_and_lookup_active_device() {
        let (genesis, account_fp, _mk, dk) = make_genesis();
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        let mut cache = IdLogCache::new();
        let mut home = FakeHome::new();

        let anchored = home.anchor(&genesis);
        cache.cache_and_validate(&store, &account_fp, &home.log(vec![anchored])).unwrap();

        let device_vk = dk.verifying_key().to_bytes();
        assert!(cache.is_active_device(&account_fp, &device_vk).unwrap());
        assert_eq!(store.get_cached_anchored_entries(&account_fp).unwrap().len(), 1);
    }

    #[test]
    fn revoked_device_rejected_and_incremental_fetch_merges() {
        let (genesis, account_fp, mk, dk) = make_genesis();
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        let mut cache = IdLogCache::new();
        let mut home = FakeHome::new();

        let dk2 = random_key();
        let state = validate_chain(std::slice::from_ref(&genesis)).unwrap();
        let add = make_add(&state, &mk, &dk2);
        let mut state2 = state;
        validate_entry(&mut state2, &add).unwrap();
        let revoke = make_revoke(&state2, &dk, &dk2.verifying_key().to_bytes());

        let a1 = home.anchor(&genesis);
        let a2 = home.anchor(&add);
        let a3 = home.anchor(&revoke);
        cache.cache_and_validate(&store, &account_fp, &home.log(vec![a1.clone(), a2.clone()])).unwrap();
        assert!(cache.is_active_device(&account_fp, &dk2.verifying_key().to_bytes()).unwrap());

        // Second fetch repeats the known entries and adds the revocation.
        let state = cache.cache_and_validate(&store, &account_fp, &home.log(vec![a1, a2, a3])).unwrap();
        assert_eq!(state.head_seq, 3);
        assert!(!cache.is_active_device(&account_fp, &dk2.verifying_key().to_bytes()).unwrap());
        assert!(cache.is_active_device(&account_fp, &dk.verifying_key().to_bytes()).unwrap());
        assert_eq!(store.get_cached_anchored_entries(&account_fp).unwrap().len(), 3);
    }

    #[test]
    fn bad_anchor_writes_nothing() {
        let (genesis, account_fp, _mk, _dk) = make_genesis();
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        let mut cache = IdLogCache::new();
        let home = FakeHome::new();
        let mut impostor = FakeHome::new();

        // Anchored by a relay other than the one the response names.
        let forged = AnchoredLog { home_relay_vk: home.vk(), entries: vec![impostor.anchor(&genesis)] };
        assert!(cache.cache_and_validate(&store, &account_fp, &forged).is_err());
        assert!(cache.get(&account_fp).is_none());
        assert!(store.get_cached_idlog_entries(&account_fp).unwrap().is_empty());
        assert!(store.get_cached_idlog_state(&account_fp).unwrap().is_none());
    }

    #[test]
    fn legacy_rows_are_replaced_by_anchored_fetch() {
        let (genesis, account_fp, _mk, dk) = make_genesis();
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        store
            .conn()
            .execute(
                "INSERT INTO idlog_cache (account_fp, seq, payload) VALUES (?1, 1, ?2)",
                rusqlite::params![account_fp.as_slice(), genesis.to_bytes()],
            )
            .unwrap();

        let mut cache = IdLogCache::new();
        // Offline load still works on the legacy row.
        let state = cache.load_from_store(&store, &account_fp).unwrap().unwrap();
        assert!(state.is_active_device(&dk.verifying_key().to_bytes()));

        let mut home = FakeHome::new();
        let anchored = home.anchor(&genesis);
        cache.cache_and_validate(&store, &account_fp, &home.log(vec![anchored])).unwrap();
        let rows = store.get_cached_idlog_entries(&account_fp).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].anchored);
    }

    fn make_set_home(state: &LogState, auth: &SigningKey, relay_vk: [u8; 32]) -> LogEntry {
        let mut entry = LogEntry {
            seq: state.head_seq + 1,
            prev_hash: state.head_hash,
            account_fp: state.account_fp,
            entry_type: EntryType::SetHomeRelay,
            timestamp: 4000,
            body: EntryBody::SetHomeRelay {
                relay_vk,
                authorizer_key: auth.verifying_key().to_bytes(),
                relay_ref: ghost_wire::relay_ref::RelayRef::key_only(relay_vk),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        sign_entry(auth, &mut entry);
        entry
    }

    #[test]
    fn rehomed_chain_validates_with_each_entry_anchored_by_its_home() {
        let (genesis, account_fp, _mk, dk) = make_genesis();
        let mut old_home = FakeHome::new();
        let mut new_home = FakeHome::new();

        let mut state = validate_chain(std::slice::from_ref(&genesis)).unwrap();
        let stay = make_set_home(&state, &dk, old_home.vk());
        validate_entry(&mut state, &stay).unwrap();
        let moved = make_set_home(&state, &dk, new_home.vk());

        let entries = vec![old_home.anchor(&genesis), old_home.anchor(&stay), new_home.anchor(&moved)];
        // The serving relay names the current home; genesis is still checked against the old one.
        let state = validate_anchored_chain(account_fp, &entries, Some(&new_home.vk())).unwrap();
        assert_eq!(state.home_relay_vk, Some(new_home.vk()));
        assert_eq!(state.head_seq, 3);

        // A genesis anchored by the new home instead fails: it was never sequenced there.
        let wrong = vec![new_home.anchor(&genesis), old_home.anchor(&stay), new_home.anchor(&moved)];
        assert!(validate_anchored_chain(account_fp, &wrong, Some(&new_home.vk())).is_err());
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
        let mut state = LogState::empty(fp);
        state.master_verifying_key = Some([0x22; 32]);
        state.head_seq = 1;
        state.head_hash = [0x33; 32];
        cache.insert(state);
        assert!(cache.get(&fp).is_some());
    }

    #[test]
    fn load_from_store_validates_anchored_rows() {
        let (genesis, account_fp, _mk, dk) = make_genesis();
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        let mut home = FakeHome::new();
        store.cache_anchored_entries(&account_fp, &[home.anchor(&genesis)]).unwrap();

        let mut cache = IdLogCache::new();
        let state = cache.load_from_store(&store, &account_fp).unwrap().unwrap();
        assert_eq!(state.head_seq, 1);
        assert!(state.is_active_device(&dk.verifying_key().to_bytes()));
    }
}
