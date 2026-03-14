use ghost_wire::idlog::LogState;

use crate::error::{GhostError, Result};

use super::GhostStore;

/// Cached identity log state loaded from the local DB.
pub struct CachedIdLogState {
    pub head_seq: u64,
    pub head_hash: [u8; 32],
    pub master_vk: Option<[u8; 32]>,
}

impl GhostStore {
    /// Store identity log entry payloads for an account. Skips duplicates.
    pub fn cache_idlog_entries(
        &self,
        account_fp: &[u8; 32],
        entries: &[(u64, Vec<u8>)],
    ) -> Result<()> {
        let tx = self.conn().unchecked_transaction()
            .map_err(|e| GhostError::Database(format!("idlog cache tx: {e}")))?;
        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT OR IGNORE INTO idlog_cache (account_fp, seq, payload) VALUES (?1, ?2, ?3)",
                )
                .map_err(|e| GhostError::Database(format!("idlog cache insert: {e}")))?;
            for (seq, payload) in entries {
                stmt.execute(rusqlite::params![account_fp.as_slice(), seq, payload])
                    .map_err(|e| GhostError::Database(format!("idlog cache insert: {e}")))?;
            }
        }
        tx.commit()
            .map_err(|e| GhostError::Database(format!("idlog cache commit: {e}")))?;
        Ok(())
    }

    /// Save the validated identity log state summary for an account.
    pub fn upsert_idlog_state(&self, account_fp: &[u8; 32], state: &LogState) -> Result<()> {
        let master_vk = state.master_verifying_key.as_ref().map(|k| k.as_slice());
        self.conn
            .execute(
                "INSERT OR REPLACE INTO idlog_state (account_fp, head_seq, head_hash, master_vk)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    account_fp.as_slice(),
                    state.head_seq as i64,
                    state.head_hash.as_slice(),
                    master_vk,
                ],
            )
            .map_err(|e| GhostError::Database(format!("upsert idlog state: {e}")))?;
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
                "SELECT head_seq, head_hash, master_vk FROM idlog_state WHERE account_fp = ?1",
            )
            .map_err(|e| GhostError::Database(format!("get idlog state: {e}")))?;

        let result = stmt.query_row(rusqlite::params![account_fp.as_slice()], |row| {
            let head_seq: i64 = row.get(0)?;
            let head_hash: Vec<u8> = row.get(1)?;
            let master_vk: Option<Vec<u8>> = row.get(2)?;
            Ok((head_seq as u64, head_hash, master_vk))
        });

        match result {
            Ok((head_seq, head_hash, master_vk)) => {
                let head_hash: [u8; 32] = head_hash.try_into().map_err(|_| {
                    GhostError::Database("idlog state: bad head_hash length".into())
                })?;
                let master_vk = master_vk
                    .map(|v| {
                        <[u8; 32]>::try_from(v.as_slice()).map_err(|_| {
                            GhostError::Database("idlog state: bad master_vk length".into())
                        })
                    })
                    .transpose()?;
                Ok(Some(CachedIdLogState {
                    head_seq,
                    head_hash,
                    master_vk,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(GhostError::Database(format!("get idlog state: {e}"))),
        }
    }

    /// Get the highest cached sequence number for an account (0 if none).
    pub fn get_cached_head_seq(&self, account_fp: &[u8; 32]) -> Result<u64> {
        let seq: Option<i64> = self
            .conn
            .query_row(
                "SELECT MAX(seq) FROM idlog_cache WHERE account_fp = ?1",
                rusqlite::params![account_fp.as_slice()],
                |row| row.get(0),
            )
            .map_err(|e| GhostError::Database(format!("get head seq: {e}")))?;
        Ok(seq.unwrap_or(0) as u64)
    }

    /// Load all cached entry payloads for an account, ordered by seq.
    pub fn get_cached_idlog_entries(
        &self,
        account_fp: &[u8; 32],
    ) -> Result<Vec<(u64, Vec<u8>)>> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT seq, payload FROM idlog_cache WHERE account_fp = ?1 ORDER BY seq",
            )
            .map_err(|e| GhostError::Database(format!("get idlog entries: {e}")))?;
        let rows = stmt
            .query_map(rusqlite::params![account_fp.as_slice()], |row| {
                let seq: i64 = row.get(0)?;
                let payload: Vec<u8> = row.get(1)?;
                Ok((seq as u64, payload))
            })
            .map_err(|e| GhostError::Database(format!("get idlog entries: {e}")))?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(
                row.map_err(|e| GhostError::Database(format!("read idlog entry: {e}")))?,
            );
        }
        Ok(entries)
    }

    /// Remove all cached identity log data for an account.
    pub fn clear_idlog_cache(&self, account_fp: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM idlog_cache WHERE account_fp = ?1",
                rusqlite::params![account_fp.as_slice()],
            )
            .map_err(|e| GhostError::Database(format!("clear idlog cache: {e}")))?;
        self.conn
            .execute(
                "DELETE FROM idlog_state WHERE account_fp = ?1",
                rusqlite::params![account_fp.as_slice()],
            )
            .map_err(|e| GhostError::Database(format!("clear idlog state: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> GhostStore {
        GhostStore::open_in_memory(&[0xABu8; 32]).unwrap()
    }

    #[test]
    fn cache_entries_roundtrip() {
        let store = test_store();
        let fp = [0x11u8; 32];
        let entries = vec![
            (1u64, vec![0xAA; 100]),
            (2u64, vec![0xBB; 80]),
        ];
        store.cache_idlog_entries(&fp, &entries).unwrap();

        let loaded = store.get_cached_idlog_entries(&fp).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].0, 1);
        assert_eq!(loaded[0].1, vec![0xAA; 100]);
        assert_eq!(loaded[1].0, 2);
    }

    #[test]
    fn cache_entries_skips_duplicates() {
        let store = test_store();
        let fp = [0x22u8; 32];
        store.cache_idlog_entries(&fp, &[(1, vec![0xAA])]).unwrap();
        store.cache_idlog_entries(&fp, &[(1, vec![0xBB])]).unwrap(); // duplicate seq
        let loaded = store.get_cached_idlog_entries(&fp).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].1, vec![0xAA]); // first insert wins
    }

    #[test]
    fn upsert_state_roundtrip() {
        let store = test_store();
        let fp = [0x33u8; 32];
        let state = LogState {
            account_fp: fp,
            master_verifying_key: Some([0xDD; 32]),
            devices: Default::default(),
            head_seq: 5,
            head_hash: [0xEE; 32],
        };
        store.upsert_idlog_state(&fp, &state).unwrap();

        let cached = store.get_cached_idlog_state(&fp).unwrap().unwrap();
        assert_eq!(cached.head_seq, 5);
        assert_eq!(cached.head_hash, [0xEE; 32]);
        assert_eq!(cached.master_vk.unwrap(), [0xDD; 32]);
    }

    #[test]
    fn get_cached_head_seq_empty() {
        let store = test_store();
        assert_eq!(store.get_cached_head_seq(&[0xFF; 32]).unwrap(), 0);
    }

    #[test]
    fn get_cached_head_seq_returns_max() {
        let store = test_store();
        let fp = [0x44u8; 32];
        store.cache_idlog_entries(&fp, &[(3, vec![0xAA]), (7, vec![0xBB])]).unwrap();
        assert_eq!(store.get_cached_head_seq(&fp).unwrap(), 7);
    }

    #[test]
    fn clear_idlog_cache_removes_all() {
        let store = test_store();
        let fp = [0x55u8; 32];
        store.cache_idlog_entries(&fp, &[(1, vec![0xAA])]).unwrap();
        let state = LogState {
            account_fp: fp,
            master_verifying_key: None,
            devices: Default::default(),
            head_seq: 1,
            head_hash: [0xBB; 32],
        };
        store.upsert_idlog_state(&fp, &state).unwrap();

        store.clear_idlog_cache(&fp).unwrap();
        assert!(store.get_cached_idlog_entries(&fp).unwrap().is_empty());
        assert!(store.get_cached_idlog_state(&fp).unwrap().is_none());
    }

    #[test]
    fn state_without_master_vk() {
        let store = test_store();
        let fp = [0x66u8; 32];
        let state = LogState {
            account_fp: fp,
            master_verifying_key: None,
            devices: Default::default(),
            head_seq: 1,
            head_hash: [0xCC; 32],
        };
        store.upsert_idlog_state(&fp, &state).unwrap();
        let cached = store.get_cached_idlog_state(&fp).unwrap().unwrap();
        assert!(cached.master_vk.is_none());
    }
}
