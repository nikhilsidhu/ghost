use rusqlite::params;

use crate::error::{GhostError, Result};

use super::GhostStore;

/// Max clock skew allowed: 5 minutes in the future.
const MAX_FUTURE_MS: u64 = 5 * 60 * 1000;

fn clamp_sync_ts(ts: u64) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    ts.min(now + MAX_FUTURE_MS)
}

impl GhostStore {
    /// Set a key. Returns true if the row was actually written (ts was newer).
    /// Timestamps are clamped to now + 5 minutes to prevent poisoning.
    pub fn sync_set(&self, key: &str, value: &[u8], ts: u64) -> Result<bool> {
        let ts = clamp_sync_ts(ts);
        let rows = self
            .conn
            .execute(
                "INSERT INTO sync_state (key, value, ts) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value = ?2, ts = ?3 WHERE ts < ?3",
                params![key, value, ts as i64],
            )
            .map_err(|e| GhostError::Database(format!("sync_set: {e}")))?;
        Ok(rows > 0)
    }

    /// Remove a key (tombstone). Returns true if the row was actually updated.
    /// Timestamps are clamped to now + 5 minutes to prevent poisoning.
    pub fn sync_remove(&self, key: &str, ts: u64) -> Result<bool> {
        let ts = clamp_sync_ts(ts);
        let rows = self
            .conn
            .execute(
                "INSERT INTO sync_state (key, value, ts) VALUES (?1, NULL, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = NULL, ts = ?2 WHERE ts < ?2",
                params![key, ts as i64],
            )
            .map_err(|e| GhostError::Database(format!("sync_remove: {e}")))?;
        Ok(rows > 0)
    }

    /// Get a key's value and timestamp, if it exists.
    pub fn sync_get(&self, key: &str) -> Result<Option<(Option<Vec<u8>>, u64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT value, ts FROM sync_state WHERE key = ?1")
            .map_err(|e| GhostError::Database(format!("sync_get prepare: {e}")))?;
        let mut rows = stmt
            .query_map(params![key], |row| {
                let value: Option<Vec<u8>> = row.get(0)?;
                let ts: i64 = row.get(1)?;
                Ok((value, ts as u64))
            })
            .map_err(|e| GhostError::Database(format!("sync_get: {e}")))?;
        match rows.next() {
            Some(Ok(v)) => Ok(Some(v)),
            Some(Err(e)) => Err(GhostError::Database(format!("sync_get read: {e}"))),
            None => Ok(None),
        }
    }

    /// Dump all entries for provision blob or debugging.
    pub fn sync_dump(&self) -> Result<Vec<(String, Option<Vec<u8>>, u64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, value, ts FROM sync_state")
            .map_err(|e| GhostError::Database(format!("sync_dump prepare: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                let key: String = row.get(0)?;
                let value: Option<Vec<u8>> = row.get(1)?;
                let ts: i64 = row.get(2)?;
                Ok((key, value, ts as u64))
            })
            .map_err(|e| GhostError::Database(format!("sync_dump: {e}")))?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(|e| GhostError::Database(format!("sync_dump read: {e}")))?);
        }
        Ok(entries)
    }

    /// Bulk import, skipping entries where ts <= existing per key.
    /// Timestamps are clamped to now + 5 minutes to prevent poisoning.
    pub fn sync_import(&self, entries: &[(String, Option<Vec<u8>>, u64)]) -> Result<()> {
        for (key, value, ts) in entries {
            let ts = clamp_sync_ts(*ts);
            self.conn
                .execute(
                    "INSERT INTO sync_state (key, value, ts) VALUES (?1, ?2, ?3)
                     ON CONFLICT(key) DO UPDATE SET value = ?2, ts = ?3 WHERE ts < ?3",
                    params![key, value.as_deref(), ts as i64],
                )
                .map_err(|e| GhostError::Database(format!("sync_import: {e}")))?;
        }
        Ok(())
    }
}
