//! Identity logs as this device has checked them: a cache of validated logs that device
//! checks consult without I/O, the local database behind it, and the key-transparency
//! heads accepted from relays.

use std::collections::HashMap;

use ghost_wire::anchor::{validate_anchored_entry, AnchoredEntry};
use ghost_wire::idlog::{choose_branch, entry_hash, validate_chain, BranchChoice, LogEntry, LogState};
use ghost_wire::merkle::{Checkpoint, ConsistencyProof};
use ghost_wire::{now_millis, short_id};

use crate::error::{GhostError, Result};
use crate::relay::AnchoredLog;
use crate::storage::{GhostStore, ReplacedHistory};

/// What a device's credential claims: its account, its key, and the identity log
/// entry that added it.
#[derive(Debug, Clone, Copy)]
pub struct CredentialClaim {
    pub account_fp: [u8; 32],
    pub device_vk: [u8; 32],
    pub add_seq: u64,
    pub add_entry_hash: [u8; 32],
}

/// What the receiver's identity log says about a claimed device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    Active,
    Revoked,
    /// The log is not cached, or does not list the device yet: fetch and ask again.
    Unknown,
    /// The log lists the device as added by a different entry than the credential
    /// names: a forged credential, or a fork in the account's log.
    Contradicted,
}

/// What a sender's claim of its own log head says against the cached copy of that log.
/// Every message carries the head its sender sees; a head this device was never served
/// is how a relay showing the two of them different logs comes to light.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadClaim {
    /// The claim is the cached head.
    Current,
    /// The claim is an earlier entry of the cached chain: the sender has not caught up
    /// with its own log.
    Behind,
    /// The sender claimed nothing: it held no copy of its own log.
    None,
    /// The account's log is not cached, so nothing can be said.
    Unknown,
    /// The claim is no entry of the cached chain: the sender sees a history this device
    /// was not served, or this device holds one the sender never saw.
    Fork,
}

/// One account's validated chain as cached: its state and the hash of every entry.
struct CachedLog {
    state: LogState,
    /// `entry_hashes[i]` is the hash of the entry at seq `i + 1`.
    entry_hashes: Vec<[u8; 32]>,
}

impl CachedLog {
    fn from_entries(entries: &[LogEntry]) -> Result<Self> {
        let state = validate_chain(entries)?;
        Ok(Self { state, entry_hashes: entries.iter().map(entry_hash).collect() })
    }
}

/// In-memory cache of validated identity logs, keyed by account fingerprint, so a
/// device check while processing a message is a lookup with no I/O. A device the
/// cache does not know is reported as unknown, and the caller fetches the log.
pub struct IdLogCache {
    logs: HashMap<[u8; 32], CachedLog>,
}

impl IdLogCache {
    pub fn new() -> Self {
        Self { logs: HashMap::new() }
    }

    /// Validate a chain held locally (e.g. one this device just appended to) and
    /// keep it in memory.
    pub fn insert_chain(&mut self, entries: &[LogEntry]) -> Result<()> {
        let first = entries.first().ok_or_else(|| GhostError::IdentityLog("identity log is empty".into()))?;
        let account_fp = first.account_fp;
        self.logs.insert(account_fp, CachedLog::from_entries(entries)?);
        Ok(())
    }

    /// Check if a device is authorized for an account. Returns Err if the
    /// account's identity log hasn't been cached yet.
    pub fn is_active_device(
        &self,
        account_fp: &[u8; 32],
        device_vk: &[u8; 32],
    ) -> Result<bool> {
        let log = self.logs.get(account_fp).ok_or_else(|| {
            GhostError::IdentityLog(format!(
                "no cached identity log for account {}",
                short_id(account_fp)
            ))
        })?;
        Ok(log.state.is_active_device(device_vk))
    }

    /// Judge a device by its credential's claim against the cached log.
    pub fn status(&self, claim: &CredentialClaim) -> DeviceStatus {
        let Some(log) = self.logs.get(&claim.account_fp) else { return DeviceStatus::Unknown };
        let Some(device) = log.state.devices.get(&claim.device_vk) else { return DeviceStatus::Unknown };
        let hash_at_add = log.entry_hashes.get(device.added_at_seq.saturating_sub(1) as usize);
        let contradicted = device.added_at_seq != claim.add_seq
            || Some(&claim.add_entry_hash) != hash_at_add;
        if contradicted {
            DeviceStatus::Contradicted
        } else if device.is_active() {
            DeviceStatus::Active
        } else {
            DeviceStatus::Revoked
        }
    }

    /// Get the cached LogState for an account, if present.
    pub fn get(&self, account_fp: &[u8; 32]) -> Option<&LogState> {
        self.logs.get(account_fp).map(|log| &log.state)
    }

    /// The cached state for an account, loaded from the local database when it is not
    /// in memory yet. `None` if this device never cached it.
    pub fn get_or_load(&mut self, store: &GhostStore, account_fp: &[u8; 32]) -> Result<Option<&LogState>> {
        if self.logs.contains_key(account_fp) {
            return Ok(self.get(account_fp));
        }
        self.load_from_store(store, account_fp)
    }

    /// Hash of the cached entry at `seq`, if held.
    pub fn entry_hash_at(&self, account_fp: &[u8; 32], seq: u64) -> Option<[u8; 32]> {
        self.logs.get(account_fp)?.entry_hashes.get(seq.checked_sub(1)? as usize).copied()
    }

    /// Judge the head a device of `account_fp` claims for its own log.
    pub fn judge_head(&self, account_fp: &[u8; 32], claimed: &[u8; 32]) -> HeadClaim {
        if *claimed == [0u8; 32] {
            return HeadClaim::None;
        }
        let Some(log) = self.logs.get(account_fp) else { return HeadClaim::Unknown };
        if log.state.head_hash == *claimed {
            HeadClaim::Current
        } else if log.entry_hashes.contains(claimed) {
            HeadClaim::Behind
        } else {
            HeadClaim::Fork
        }
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

        self.logs.insert(*account_fp, CachedLog::from_entries(&entries)?);
        Ok(self.get(account_fp))
    }

    /// Merge a fetched anchored log with what is already cached, validate the
    /// whole chain together with every anchor, persist, and keep the state in
    /// memory. Nothing is written if any entry or anchor fails, so the local
    /// cache can never hold an entry its home did not sequence.
    ///
    /// A fetched entry that differs from a cached one at the same position is a
    /// fork, settled by the shared rule: a root-signed branch replaces a cached
    /// device-only suffix; otherwise the cached chain stays and the fetch fails as
    /// equivocation. Cached rows that predate anchoring are discarded and replaced
    /// by the fetched entries; a fetch always starts at seq 1 today. A replaced suffix
    /// is reported with what it held, for the caller to tell the user.
    pub fn cache_and_validate(
        &mut self,
        store: &GhostStore,
        account_fp: &[u8; 32],
        log: &AnchoredLog,
    ) -> Result<(LogState, Option<ReplacedHistory>)> {
        if log.entries.is_empty() {
            // A fetch from the cached head that brought nothing: the cache is current.
            let state = match self.load_from_store(store, account_fp)? {
                Some(state) => state.clone(),
                None => LogState::empty(*account_fp),
            };
            return Ok((state, None));
        }

        let cached_rows = store.get_cached_idlog_entries(account_fp)?;
        let has_legacy_rows = cached_rows.iter().any(|r| !r.anchored);
        let mut all: Vec<AnchoredEntry> = if has_legacy_rows {
            Vec::new()
        } else {
            store.get_cached_anchored_entries(account_fp)?
        };
        all.sort_by_key(|a| a.entry.seq);

        let mut fetched = log.entries.clone();
        fetched.sort_by_key(|a| a.entry.seq);
        let fork_at = fetched.iter().find_map(|f| {
            let held = all.iter().find(|a| a.entry.seq == f.entry.seq)?;
            (entry_hash(&held.entry) != entry_hash(&f.entry)).then_some(f.entry.seq)
        });
        let replaced_from = match fork_at {
            Some(seq) => {
                settle_fork(&all, &fetched, seq)?;
                let held: Vec<LogEntry> = all.iter().map(|a| a.entry.clone()).collect();
                all.retain(|a| a.entry.seq < seq);
                Some((seq, held))
            }
            None => None,
        };

        let mut new_entries = Vec::new();
        for anchored in &fetched {
            if !all.iter().any(|a| a.entry.seq == anchored.entry.seq) {
                all.push(anchored.clone());
                new_entries.push(anchored.clone());
            }
        }
        all.sort_by_key(|a| a.entry.seq);

        let state = validate_anchored_chain(*account_fp, &all, Some(&log.home_relay_vk))?;

        let replaced = replaced_from.as_ref().map(|(seq, held)| replaced_history(*seq, held, &state));
        if let Some((seq, _)) = replaced_from {
            store.delete_cached_idlog_from(account_fp, seq)?;
        }
        if has_legacy_rows {
            store.clear_idlog_cache(account_fp)?;
            store.cache_anchored_entries(account_fp, &all)?;
        } else {
            store.cache_anchored_entries(account_fp, &new_entries)?;
        }
        store.upsert_idlog_state(account_fp, &state)?;
        let entries: Vec<LogEntry> = all.into_iter().map(|a| a.entry).collect();
        self.logs.insert(*account_fp, CachedLog { state: state.clone(), entry_hashes: entries.iter().map(entry_hash).collect() });
        Ok((state, replaced))
    }

    /// `cache_and_validate`, telling of history it replaced: `own_account`'s is recorded
    /// for the next account check to report; another account's is only logged.
    pub fn cache_anchored_log(&mut self, store: &GhostStore, own_account: &[u8; 32], account_fp: &[u8; 32], log: &AnchoredLog) -> Result<LogState> {
        let (state, replaced) = self.cache_and_validate(store, account_fp, log)?;
        if let Some(replaced) = replaced {
            if account_fp == own_account {
                store.record_replaced_history(&replaced, now_millis())?;
            } else {
                tracing::warn!("identity log of {}: cached history from entry {} replaced by a root-signed branch", short_id(account_fp), replaced.from_seq);
            }
        }
        Ok(state)
    }
}

/// The last key-transparency head accepted from `relay_vk`, if any.
pub fn kt_head(store: &GhostStore, relay_vk: &[u8; 32]) -> Result<Option<Checkpoint>> {
    match store.get_kt_state(relay_vk)? {
        Some(state) => Checkpoint::from_bytes(&state.checkpoint).map(Some).map_err(|e| GhostError::IdentityLog(format!("stored kt head: {e}"))),
        None => Ok(None),
    }
}

/// Accept a new key-transparency head from `relay_vk`: it must be signed by that relay
/// and extend the last head accepted from it (`proof` covers the growth). A relay that
/// shows two clients different trees fails this check on one of them.
pub fn accept_kt_head(store: &GhostStore, relay_vk: &[u8; 32], head: &Checkpoint, proof: Option<&ConsistencyProof>) -> Result<()> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(relay_vk).map_err(|e| GhostError::IdentityLog(format!("bad relay vk: {e}")))?;
    head.verify(&vk).map_err(|_| GhostError::IdentityLog("kt head signature invalid".into()))?;
    if let Some(prior) = kt_head(store, relay_vk)? {
        ghost_wire::merkle::verify_extension(&prior, head, proof)
            .map_err(|e| GhostError::IdentityLog(format!("kt head does not extend the last one seen ({e}); possible split view")))?;
    }
    store.set_kt_state(relay_vk, head.tree_size, &head.root_hash, &head.to_bytes())
}

/// What replacing the cached chain `held` from `from_seq` took away: the entries past
/// the fork, and the devices active in `held` that `now` does not know at all. A device
/// the new branch revoked is not among them; the branch's own entries report that.
fn replaced_history(from_seq: u64, held: &[LogEntry], now: &LogState) -> ReplacedHistory {
    let discarded = held.iter().filter(|e| e.seq >= from_seq).count() as u32;
    let mut lost_devices: Vec<String> = match validate_chain(held) {
        Ok(before) => before
            .devices
            .values()
            .filter(|d| d.revoked_at_seq.is_none() && !now.devices.contains_key(&d.verifying_key))
            .map(|d| d.label.clone())
            .collect(),
        Err(e) => {
            tracing::warn!("replaced history: the discarded chain no longer validates: {e}");
            Vec::new()
        }
    };
    lost_devices.sort();
    ReplacedHistory { from_seq, discarded, lost_devices }
}

/// Decide a fork at `seq` between the cached chain and a fetched one with the shared
/// rule. Errors unless the fetched branch replaces the cached suffix.
fn settle_fork(cached: &[AnchoredEntry], fetched: &[AnchoredEntry], seq: u64) -> Result<()> {
    let prefix: Vec<LogEntry> = cached.iter().filter(|a| a.entry.seq < seq).map(|a| a.entry.clone()).collect();
    if prefix.is_empty() {
        return Err(GhostError::IdentityLog("two different genesis entries for one account".into()));
    }
    let prefix_state = validate_chain(&prefix)?;
    let held: Vec<LogEntry> = cached.iter().filter(|a| a.entry.seq >= seq).map(|a| a.entry.clone()).collect();
    let incoming: Vec<LogEntry> = fetched.iter().filter(|a| a.entry.seq >= seq).map(|a| a.entry.clone()).collect();
    match choose_branch(&prefix_state, &held, &incoming)? {
        BranchChoice::Replace => Ok(()),
        BranchChoice::Keep => Err(GhostError::IdentityLog(format!(
            "the relay serves a different history from entry {seq} than this device holds; possible equivocation"
        ))),
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
    use ed25519_dalek::SigningKey;
    use ghost_wire::idlog::validate_entry;
    use ghost_wire::log_entries::{create_add_device, create_genesis, create_recovery, create_revoke_device, create_set_home_relay};
    use ghost_wire::merkle::{leaf_hash, InclusionProof, MerkleTree};
    use ghost_wire::relay_ref::RelayRef;
    use rand::rngs::OsRng;

    fn random_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
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
            AnchoredLog { home_relay_vk: self.vk(), relay_vk: self.vk(), kt_head: None, entries }
        }
    }

    /// A genesis entry and (account_fp, genesis key, device key).
    fn make_genesis() -> (LogEntry, [u8; 32], SigningKey, SigningKey) {
        let mk = random_key();
        let dk = random_key();
        let entry = create_genesis(&mk, &dk, "test-device");
        (entry.clone(), entry.account_fp, mk, dk)
    }

    fn claim(account_fp: [u8; 32], device: &SigningKey, add_seq: u64, add_entry_hash: [u8; 32]) -> CredentialClaim {
        CredentialClaim { account_fp, device_vk: device.verifying_key().to_bytes(), add_seq, add_entry_hash }
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
    fn status_follows_the_log_and_the_claimed_add_entry() {
        let (genesis, account_fp, mk, dk) = make_genesis();
        let mut cache = IdLogCache::new();
        assert_eq!(cache.status(&claim(account_fp, &dk, 1, [0; 32])), DeviceStatus::Unknown, "nothing cached");

        let phone = random_key();
        let mut state = validate_chain(std::slice::from_ref(&genesis)).unwrap();
        let add = create_add_device(&state, &mk, &phone, "phone");
        validate_entry(&mut state, &add).unwrap();
        cache.insert_chain(&[genesis.clone(), add.clone()]).unwrap();

        let genesis_hash = entry_hash(&genesis);
        assert_eq!(cache.status(&claim(account_fp, &dk, 1, genesis_hash)), DeviceStatus::Active);
        assert_eq!(cache.status(&claim(account_fp, &dk, 2, genesis_hash)), DeviceStatus::Contradicted, "wrong add entry");
        assert_eq!(cache.status(&claim(account_fp, &dk, 1, [0xEE; 32])), DeviceStatus::Contradicted, "forked add entry");
        assert_eq!(cache.status(&claim(account_fp, &random_key(), 1, genesis_hash)), DeviceStatus::Unknown, "device not in the log");

        let revoke = create_revoke_device(&state, &dk, &phone.verifying_key().to_bytes());
        cache.insert_chain(&[genesis, add.clone(), revoke]).unwrap();
        assert_eq!(cache.status(&claim(account_fp, &phone, 2, entry_hash(&add))), DeviceStatus::Revoked);
    }

    #[test]
    fn a_claimed_head_is_judged_against_the_cached_chain() {
        let (genesis, account_fp, mk, _dk) = make_genesis();
        let mut cache = IdLogCache::new();
        assert_eq!(cache.judge_head(&account_fp, &[0xEE; 32]), HeadClaim::Unknown, "nothing cached");

        let state = validate_chain(std::slice::from_ref(&genesis)).unwrap();
        let add = create_add_device(&state, &mk, &random_key(), "phone");
        cache.insert_chain(&[genesis.clone(), add.clone()]).unwrap();

        assert_eq!(cache.judge_head(&account_fp, &entry_hash(&add)), HeadClaim::Current);
        assert_eq!(cache.judge_head(&account_fp, &entry_hash(&genesis)), HeadClaim::Behind, "the sender has not seen its own newest entry");
        assert_eq!(cache.judge_head(&account_fp, &[0u8; 32]), HeadClaim::None, "a sender without its own log claims nothing");
        assert_eq!(cache.judge_head(&account_fp, &[0xEE; 32]), HeadClaim::Fork, "a head on neither side's chain");
    }

    #[test]
    fn revoked_device_rejected_and_incremental_fetch_merges() {
        let (genesis, account_fp, mk, dk) = make_genesis();
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        let mut cache = IdLogCache::new();
        let mut home = FakeHome::new();

        let dk2 = random_key();
        let state = validate_chain(std::slice::from_ref(&genesis)).unwrap();
        let add = create_add_device(&state, &mk, &dk2, "phone");
        let mut state2 = state;
        validate_entry(&mut state2, &add).unwrap();
        let revoke = create_revoke_device(&state2, &dk, &dk2.verifying_key().to_bytes());

        let a1 = home.anchor(&genesis);
        let a2 = home.anchor(&add);
        let a3 = home.anchor(&revoke);
        cache.cache_and_validate(&store, &account_fp, &home.log(vec![a1.clone(), a2.clone()])).unwrap();
        assert!(cache.is_active_device(&account_fp, &dk2.verifying_key().to_bytes()).unwrap());

        // Second fetch repeats the known entries and adds the revocation.
        let (state, replaced) = cache.cache_and_validate(&store, &account_fp, &home.log(vec![a1, a2, a3])).unwrap();
        assert_eq!(replaced, None, "an extension replaces nothing");
        assert_eq!(state.head_seq, 3);
        assert!(!cache.is_active_device(&account_fp, &dk2.verifying_key().to_bytes()).unwrap());
        assert!(cache.is_active_device(&account_fp, &dk.verifying_key().to_bytes()).unwrap());
        assert_eq!(store.get_cached_anchored_entries(&account_fp).unwrap().len(), 3);
    }

    #[test]
    fn a_fetched_recovery_replaces_a_cached_device_only_suffix() {
        let (genesis, account_fp, mk, dk) = make_genesis();
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        let mut cache = IdLogCache::new();
        let mut home = FakeHome::new();

        let state = validate_chain(std::slice::from_ref(&genesis)).unwrap();
        let set_home = create_set_home_relay(&state, &dk, RelayRef::key_only(home.vk()));
        let mut prefix = state;
        validate_entry(&mut prefix, &set_home).unwrap();
        let thief = random_key();
        let add = create_add_device(&prefix, &dk, &thief, "thief");
        let a1 = home.anchor(&genesis);
        let a2 = home.anchor(&set_home);
        let a3 = home.anchor(&add);
        cache.cache_and_validate(&store, &account_fp, &home.log(vec![a1.clone(), a2.clone(), a3])).unwrap();

        // The genesis key is the root until it rotates.
        let owner = random_key();
        let recovery = create_recovery(&prefix, &mk, &owner, "owner");
        let a3 = home.anchor(&recovery);
        let (state, replaced) = cache.cache_and_validate(&store, &account_fp, &home.log(vec![a1, a2, a3])).unwrap();
        assert_eq!(replaced, Some(ReplacedHistory { from_seq: 3, discarded: 1, lost_devices: vec!["thief".into()] }), "the discarded device is reported");
        assert!(state.is_active_device(&owner.verifying_key().to_bytes()));
        assert!(!state.devices.contains_key(&thief.verifying_key().to_bytes()), "the thief's entry is gone");
        let rows = store.get_cached_anchored_entries(&account_fp).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(entry_hash(&rows[2].entry), entry_hash(&recovery));
    }

    #[test]
    fn a_fetched_device_branch_never_replaces_cached_history() {
        let (genesis, account_fp, _mk, dk) = make_genesis();
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        let mut cache = IdLogCache::new();
        let mut home = FakeHome::new();

        let state = validate_chain(std::slice::from_ref(&genesis)).unwrap();
        let a1 = home.anchor(&genesis);
        let held = create_add_device(&state, &dk, &random_key(), "phone");
        let a2 = home.anchor(&held);
        cache.cache_and_validate(&store, &account_fp, &home.log(vec![a1.clone(), a2])).unwrap();

        let other = create_add_device(&state, &dk, &random_key(), "laptop");
        let a2 = home.anchor(&other);
        let err = cache.cache_and_validate(&store, &account_fp, &home.log(vec![a1, a2])).unwrap_err();
        assert!(err.to_string().contains("equivocation"), "{err}");
        assert_eq!(entry_hash(&store.get_cached_anchored_entries(&account_fp).unwrap()[1].entry), entry_hash(&held));
    }

    #[test]
    fn bad_anchor_writes_nothing() {
        let (genesis, account_fp, _mk, _dk) = make_genesis();
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        let mut cache = IdLogCache::new();
        let home = FakeHome::new();
        let mut impostor = FakeHome::new();

        // Anchored by a relay other than the one the response names.
        let forged = AnchoredLog { home_relay_vk: home.vk(), relay_vk: home.vk(), kt_head: None, entries: vec![impostor.anchor(&genesis)] };
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

    #[test]
    fn rehomed_chain_validates_with_each_entry_anchored_by_its_home() {
        let (genesis, account_fp, _mk, dk) = make_genesis();
        let mut old_home = FakeHome::new();
        let mut new_home = FakeHome::new();

        let mut state = validate_chain(std::slice::from_ref(&genesis)).unwrap();
        let stay = create_set_home_relay(&state, &dk, RelayRef::key_only(old_home.vk()));
        validate_entry(&mut state, &stay).unwrap();
        let moved = create_set_home_relay(&state, &dk, RelayRef::key_only(new_home.vk()));

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
    fn load_from_store_validates_anchored_rows() {
        let (genesis, account_fp, _mk, dk) = make_genesis();
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        let mut home = FakeHome::new();
        store.cache_anchored_entries(&account_fp, &[home.anchor(&genesis)]).unwrap();

        let mut cache = IdLogCache::new();
        let state = cache.load_from_store(&store, &account_fp).unwrap().unwrap();
        assert_eq!(state.head_seq, 1);
        assert!(state.is_active_device(&dk.verifying_key().to_bytes()));
        assert_eq!(cache.entry_hash_at(&account_fp, 1), Some(entry_hash(&genesis)));
    }
}
