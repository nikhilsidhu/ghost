use ghost_wire::anchor::AnchoredEntry;
use super::db;
use ghost_wire::idlog::LogState;
use ghost_wire::relay_ref::RelayRef;

use crate::error::{GhostError, Result};

use super::GhostStore;

/// Cached identity log state loaded from the local DB.
pub struct CachedIdLogState {
    pub head_seq: u64,
    pub head_hash: [u8; 32],
    pub home_relay_vk: Option<[u8; 32]>,
    pub home_set_at_seq: u64,
}

/// One cached entry. `anchored` rows hold `AnchoredEntry` bytes; legacy rows
/// hold bare `LogEntry` bytes and are replaced on the next fetch.
pub struct CachedIdLogEntry {
    pub seq: u64,
    pub payload: Vec<u8>,
    pub anchored: bool,
}

impl GhostStore {
    /// Store anchored entries for an account. Skips sequence numbers already held.
    pub fn cache_anchored_entries(
        &self,
        account_fp: &[u8; 32],
        entries: &[AnchoredEntry],
    ) -> Result<()> {
        self.write_whole(|| {
            let mut stmt = self
                .conn()
                .prepare_cached(
                    "INSERT OR IGNORE INTO idlog_cache (account_fp, seq, payload, anchored) VALUES (?1, ?2, ?3, 1)",
                )
                .map_err(db("idlog cache insert"))?;
            for anchored in entries {
                stmt.execute(rusqlite::params![
                    account_fp.as_slice(),
                    anchored.entry.seq as i64,
                    anchored.to_bytes(),
                ])
                .map_err(db("idlog cache insert"))?;
            }
            Ok(())
        })
    }

    /// Save the validated identity log state summary for an account.
    pub fn upsert_idlog_state(&self, account_fp: &[u8; 32], state: &LogState) -> Result<()> {
        let home_relay_vk = state.home_relay_vk.as_ref().map(|k| k.as_slice());
        let home_relay_ref = state.home_relay_ref.as_ref().map(RelayRef::to_bytes);
        self.conn
            .execute(
                "INSERT OR REPLACE INTO idlog_state
                     (account_fp, head_seq, head_hash, home_relay_vk, home_relay_ref, home_set_at_seq)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    account_fp.as_slice(),
                    state.head_seq as i64,
                    state.head_hash.as_slice(),
                    home_relay_vk,
                    home_relay_ref,
                    state.home_set_at_seq as i64,
                ],
            )
            .map_err(db("upsert idlog state"))?;
        Ok(())
    }

    /// Load the cached identity log state summary for an account.
    pub fn get_cached_idlog_state(
        &self,
        account_fp: &[u8; 32],
    ) -> Result<Option<CachedIdLogState>> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT head_seq, head_hash, home_relay_vk, home_set_at_seq
                 FROM idlog_state WHERE account_fp = ?1",
            )
            .map_err(db("get idlog state"))?;

        let result = stmt.query_row(rusqlite::params![account_fp.as_slice()], |row| {
            let head_seq: i64 = row.get(0)?;
            let head_hash: Vec<u8> = row.get(1)?;
            let home_relay_vk: Option<Vec<u8>> = row.get(2)?;
            let home_set_at_seq: i64 = row.get(3)?;
            Ok((head_seq as u64, head_hash, home_relay_vk, home_set_at_seq as u64))
        });

        let to_key = |v: Vec<u8>, what: &str| -> Result<[u8; 32]> {
            <[u8; 32]>::try_from(v.as_slice())
                .map_err(|_| GhostError::Database(format!("idlog state: bad {what} length")))
        };
        match result {
            Ok((head_seq, head_hash, home_relay_vk, home_set_at_seq)) => {
                Ok(Some(CachedIdLogState {
                    head_seq,
                    head_hash: to_key(head_hash, "head_hash")?,
                    home_relay_vk: home_relay_vk.map(|v| to_key(v, "home_relay_vk")).transpose()?,
                    home_set_at_seq,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(GhostError::Database(format!("get idlog state: {e}"))),
        }
    }

    /// Load all cached entries for an account, ordered by seq.
    pub fn get_cached_idlog_entries(&self, account_fp: &[u8; 32]) -> Result<Vec<CachedIdLogEntry>> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT seq, payload, anchored FROM idlog_cache WHERE account_fp = ?1 ORDER BY seq",
            )
            .map_err(db("get idlog entries"))?;
        let rows = stmt
            .query_map(rusqlite::params![account_fp.as_slice()], |row| {
                let seq: i64 = row.get(0)?;
                let payload: Vec<u8> = row.get(1)?;
                let anchored: i64 = row.get(2)?;
                Ok(CachedIdLogEntry { seq: seq as u64, payload, anchored: anchored == 1 })
            })
            .map_err(db("get idlog entries"))?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(db("read idlog entry"))?);
        }
        Ok(entries)
    }

    /// The account's cached chain as anchored entries, which is what another
    /// relay needs to register the account. Errors if any cached row predates
    /// anchoring; the caller must refetch from the home first.
    pub fn get_cached_anchored_entries(&self, account_fp: &[u8; 32]) -> Result<Vec<AnchoredEntry>> {
        self.get_cached_idlog_entries(account_fp)?
            .into_iter()
            .map(|row| {
                if !row.anchored {
                    return Err(GhostError::IdentityLog(format!(
                        "cached entry {} has no anchor; refetch the log from the home relay",
                        row.seq
                    )));
                }
                AnchoredEntry::from_bytes(&row.payload)
                    .map_err(|e| GhostError::IdentityLog(format!("cached entry {}: {e}", row.seq)))
            })
            .collect()
    }

    /// Drop cached entries from `seq` on, which a fork's winning branch replaces.
    pub fn delete_cached_idlog_from(&self, account_fp: &[u8; 32], seq: u64) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM idlog_cache WHERE account_fp = ?1 AND seq >= ?2",
                rusqlite::params![account_fp.as_slice(), seq as i64],
            )
            .map_err(db("drop replaced idlog entries"))?;
        Ok(())
    }

    /// Remove all cached identity log data for an account.
    pub fn clear_idlog_cache(&self, account_fp: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM idlog_cache WHERE account_fp = ?1",
                rusqlite::params![account_fp.as_slice()],
            )
            .map_err(db("clear idlog cache"))?;
        self.conn
            .execute(
                "DELETE FROM idlog_state WHERE account_fp = ?1",
                rusqlite::params![account_fp.as_slice()],
            )
            .map_err(db("clear idlog state"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_wire::idlog::{EntryBody, EntryType, LogEntry};
    use ghost_wire::merkle::{Checkpoint, InclusionProof};

    fn test_store() -> GhostStore {
        GhostStore::open_in_memory(&[0xABu8; 32]).unwrap()
    }

    /// Structurally valid anchored entry; this module stores bytes, it does not verify them.
    fn dummy_anchored(fp: [u8; 32], seq: u64, marker: u8) -> AnchoredEntry {
        let entry = LogEntry {
            seq,
            prev_hash: [marker; 32],
            account_fp: fp,
            entry_type: EntryType::RevokeDevice,
            timestamp: seq,
            body: EntryBody::RevokeDevice { device_verifying_key: [marker; 32], revoker_key: [1; 32] },
            signature: [0u8; 64],
            counter_signature: None,
        };
        AnchoredEntry {
            entry,
            inclusion_proof: InclusionProof { leaf_index: seq - 1, tree_size: seq, path: vec![] },
            checkpoint: Checkpoint { tree_size: seq, root_hash: [marker; 32], timestamp: 0, signature: [0u8; 64] },
        }
    }

    fn state_for(fp: [u8; 32], head_seq: u64, head_hash: [u8; 32]) -> LogState {
        LogState { head_seq, head_hash, ..LogState::empty(fp) }
    }

    #[test]
    fn cache_entries_roundtrip() {
        let store = test_store();
        let fp = [0x11u8; 32];
        let entries = vec![dummy_anchored(fp, 1, 0xAA), dummy_anchored(fp, 2, 0xBB)];
        store.cache_anchored_entries(&fp, &entries).unwrap();

        let loaded = store.get_cached_idlog_entries(&fp).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].seq, 1);
        assert!(loaded[0].anchored);
        assert_eq!(loaded[0].payload, entries[0].to_bytes());
        assert_eq!(loaded[1].seq, 2);

        let anchored = store.get_cached_anchored_entries(&fp).unwrap();
        assert_eq!(anchored.len(), 2);
        assert_eq!(anchored[1].checkpoint.root_hash, [0xBB; 32]);
    }

    #[test]
    fn cache_entries_skips_duplicates() {
        let store = test_store();
        let fp = [0x22u8; 32];
        store.cache_anchored_entries(&fp, &[dummy_anchored(fp, 1, 0xAA)]).unwrap();
        store.cache_anchored_entries(&fp, &[dummy_anchored(fp, 1, 0xBB)]).unwrap(); // duplicate seq
        let loaded = store.get_cached_anchored_entries(&fp).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].checkpoint.root_hash, [0xAA; 32]); // first insert wins
    }

    #[test]
    fn legacy_unanchored_rows_are_reported_and_block_export() {
        let store = test_store();
        let fp = [0x23u8; 32];
        store
            .conn()
            .execute(
                "INSERT INTO idlog_cache (account_fp, seq, payload) VALUES (?1, 1, ?2)",
                rusqlite::params![fp.as_slice(), vec![0u8; 10]],
            )
            .unwrap();
        let loaded = store.get_cached_idlog_entries(&fp).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(!loaded[0].anchored);
        assert!(store.get_cached_anchored_entries(&fp).is_err());
    }

    #[test]
    fn upsert_state_roundtrip() {
        let store = test_store();
        let fp = [0x33u8; 32];
        let mut state = state_for(fp, 5, [0xEE; 32]);
        state.home_relay_vk = Some([0x77; 32]);
        state.home_relay_ref = Some(RelayRef::key_only([0x77; 32]));
        state.home_set_at_seq = 2;
        store.upsert_idlog_state(&fp, &state).unwrap();

        let cached = store.get_cached_idlog_state(&fp).unwrap().unwrap();
        assert_eq!(cached.head_seq, 5);
        assert_eq!(cached.head_hash, [0xEE; 32]);
        assert_eq!(cached.home_relay_vk.unwrap(), [0x77; 32]);
        assert_eq!(cached.home_set_at_seq, 2);
    }

    #[test]
    fn deleting_from_a_seq_keeps_the_prefix() {
        let store = test_store();
        let fp = [0x34u8; 32];
        let entries: Vec<_> = (1..=4).map(|seq| dummy_anchored(fp, seq, seq as u8)).collect();
        store.cache_anchored_entries(&fp, &entries).unwrap();
        store.delete_cached_idlog_from(&fp, 3).unwrap();
        let kept: Vec<u64> = store.get_cached_idlog_entries(&fp).unwrap().iter().map(|r| r.seq).collect();
        assert_eq!(kept, vec![1, 2]);
    }

    #[test]
    fn clear_idlog_cache_removes_all() {
        let store = test_store();
        let fp = [0x55u8; 32];
        store.cache_anchored_entries(&fp, &[dummy_anchored(fp, 1, 0xAA)]).unwrap();
        store.upsert_idlog_state(&fp, &state_for(fp, 1, [0xBB; 32])).unwrap();

        store.clear_idlog_cache(&fp).unwrap();
        assert!(store.get_cached_idlog_entries(&fp).unwrap().is_empty());
        assert!(store.get_cached_idlog_state(&fp).unwrap().is_none());
    }

    #[test]
    fn state_without_home() {
        let store = test_store();
        let fp = [0x66u8; 32];
        store.upsert_idlog_state(&fp, &state_for(fp, 1, [0xCC; 32])).unwrap();
        let cached = store.get_cached_idlog_state(&fp).unwrap().unwrap();
        assert!(cached.home_relay_vk.is_none());
        assert_eq!(cached.home_set_at_seq, 0);
    }
}
