//! Replacements of this account's own cached log, kept until the account check tells
//! the user: the replacement can happen in any fetch, the telling only in the check.

use crate::error::{GhostError, Result};

use super::{db, GhostStore, ReplacedHistory};

impl GhostStore {
    pub fn record_replaced_history(&self, replaced: &ReplacedHistory, at: u64) -> Result<()> {
        let lost = serde_json::to_string(&replaced.lost_devices).map_err(|e| GhostError::Database(format!("replaced history: {e}")))?;
        self.conn
            .execute(
                "INSERT INTO replaced_history (from_seq, discarded, lost_devices, at) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![replaced.from_seq as i64, replaced.discarded, lost, at as i64],
            )
            .map_err(db("record replaced history"))?;
        Ok(())
    }

    /// Every replacement not told yet, oldest first; each is told once.
    pub fn take_replaced_history(&self) -> Result<Vec<ReplacedHistory>> {
        let rows = self.write_whole(|| {
            let mut stmt = self.conn.prepare("SELECT from_seq, discarded, lost_devices FROM replaced_history ORDER BY id").map_err(db("take replaced history"))?;
            let rows = stmt
                .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, u32>(1)?, row.get::<_, String>(2)?)))
                .map_err(db("take replaced history"))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(db("take replaced history"))?;
            self.conn.execute("DELETE FROM replaced_history", []).map_err(db("take replaced history"))?;
            Ok(rows)
        })?;
        rows.into_iter()
            .map(|(from_seq, discarded, lost)| {
                let lost_devices = serde_json::from_str(&lost).map_err(|e| GhostError::Database(format!("replaced history: {e}")))?;
                Ok(ReplacedHistory { from_seq: from_seq as u64, discarded, lost_devices })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacements_are_told_once_in_order() {
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        let first = ReplacedHistory { from_seq: 3, discarded: 1, lost_devices: vec!["thief".into()] };
        let second = ReplacedHistory { from_seq: 7, discarded: 2, lost_devices: Vec::new() };
        store.record_replaced_history(&first, 10).unwrap();
        store.record_replaced_history(&second, 20).unwrap();
        assert_eq!(store.take_replaced_history().unwrap(), vec![first, second]);
        assert!(store.take_replaced_history().unwrap().is_empty());
    }
}
