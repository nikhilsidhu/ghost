use rusqlite::params;

use super::db;
use crate::error::{GhostError, Result};
use crate::wire::SyncEntry;

use super::GhostStore;

/// How a key's values from different devices combine: by the clock of the write, or for
/// read positions by the position itself, so a device with a slow clock cannot move a
/// channel back to unread.
fn newest_by_value(key: &str) -> bool {
    key.starts_with(crate::wire::SYNC_KEY_READ_PREFIX)
}

/// Whether a value from another device replaces what is held, both at `ts`.
fn replaces(key: &str, held: Option<(Option<Vec<u8>>, u64)>, value: Option<&[u8]>, ts: u64) -> bool {
    let Some((held_value, held_ts)) = held else { return true };
    if newest_by_value(key) {
        // A tombstone has no position: it wins over a position only by clock.
        match (held_value, value) {
            (Some(held), Some(value)) => value > held.as_slice() || (value == held.as_slice() && ts > held_ts),
            _ => ts > held_ts,
        }
    } else {
        ts > held_ts
    }
}

impl GhostStore {
    /// Set a key. Returns true if the row was actually written (the new value wins).
    pub fn sync_set(&self, key: &str, value: &[u8], ts: u64) -> Result<bool> {
        self.sync_merge(key, Some(value), ts)
    }

    /// Remove a key (tombstone). Returns true if the row was actually updated.
    pub fn sync_remove(&self, key: &str, ts: u64) -> Result<bool> {
        self.sync_merge(key, None, ts)
    }

    /// Clocks are taken as given: the client clamps what other devices wrote before it
    /// gets here, and its own writes are never behind its clock.
    fn sync_merge(&self, key: &str, value: Option<&[u8]>, ts: u64) -> Result<bool> {
        if !replaces(key, self.sync_get(key)?, value, ts) {
            return Ok(false);
        }
        self.conn
            .execute(
                "INSERT INTO sync_state (key, value, ts) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value = ?2, ts = ?3",
                params![key, value, ts as i64],
            )
            .map_err(db("sync merge"))?;
        Ok(true)
    }

    /// Get a key's value and timestamp, if it exists.
    pub fn sync_get(&self, key: &str) -> Result<Option<(Option<Vec<u8>>, u64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT value, ts FROM sync_state WHERE key = ?1")
            .map_err(db("sync_get prepare"))?;
        let mut rows = stmt
            .query_map(params![key], |row| {
                let value: Option<Vec<u8>> = row.get(0)?;
                let ts: i64 = row.get(1)?;
                Ok((value, ts as u64))
            })
            .map_err(db("sync_get"))?;
        match rows.next() {
            Some(Ok(v)) => Ok(Some(v)),
            Some(Err(e)) => Err(GhostError::Database(format!("sync_get read: {e}"))),
            None => Ok(None),
        }
    }

    /// Dump all entries for provision blob or debugging.
    pub fn sync_dump(&self) -> Result<Vec<SyncEntry>> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, value, ts FROM sync_state")
            .map_err(db("sync_dump prepare"))?;
        let rows = stmt
            .query_map([], |row| {
                let key: String = row.get(0)?;
                let value: Option<Vec<u8>> = row.get(1)?;
                let ts: i64 = row.get(2)?;
                Ok((key, value, ts as u64))
            })
            .map_err(db("sync_dump"))?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(db("sync_dump read"))?);
        }
        Ok(entries)
    }

    /// Merge every entry by its key's rule. Returns the entries that changed this device's
    /// state, for applying.
    pub fn sync_import(&self, entries: &[SyncEntry]) -> Result<Vec<SyncEntry>> {
        let mut changed = Vec::new();
        for (key, value, ts) in entries {
            if self.sync_merge(key, value.as_deref(), *ts)? {
                changed.push((key.clone(), value.clone(), *ts));
            }
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::clock::from_millis;

    #[test]
    fn newer_clocks_win_and_tombstones_hold_against_older_sets() {
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        assert!(store.sync_set("pref:a", b"1", from_millis(10)).unwrap());
        assert!(!store.sync_set("pref:a", b"0", from_millis(9)).unwrap());
        assert!(store.sync_remove("pref:a", from_millis(11)).unwrap());
        assert!(!store.sync_set("pref:a", b"2", from_millis(10)).unwrap(), "a replayed older set never resurrects a deleted key");
        assert_eq!(store.sync_get("pref:a").unwrap(), Some((None, from_millis(11))));
    }

    #[test]
    fn read_positions_merge_by_position_not_by_clock() {
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        let key = format!("{}{}", crate::wire::SYNC_KEY_READ_PREFIX, "ab");
        assert!(store.sync_set(&key, &500u64.to_be_bytes(), from_millis(100)).unwrap());
        // A device with a slow clock read further: its position wins despite the older clock.
        assert!(store.sync_set(&key, &900u64.to_be_bytes(), from_millis(50)).unwrap());
        // A device with a fast clock read less: it does not move the channel back.
        assert!(!store.sync_set(&key, &700u64.to_be_bytes(), from_millis(200)).unwrap());
        assert_eq!(store.sync_get(&key).unwrap().unwrap().0.unwrap(), 900u64.to_be_bytes());
    }

    #[test]
    fn import_reports_only_what_changed() {
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        store.sync_set("pref:a", b"1", from_millis(10)).unwrap();
        let changed = store
            .sync_import(&[
                ("pref:a".into(), Some(b"0".to_vec()), from_millis(5)),
                ("pref:b".into(), Some(b"x".to_vec()), from_millis(5)),
            ])
            .unwrap();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].0, "pref:b");
    }

}
