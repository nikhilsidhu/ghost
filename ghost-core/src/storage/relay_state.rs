use rusqlite::OptionalExtension;

use crate::error::{GhostError, Result};

use super::GhostStore;

impl GhostStore {
    pub fn get_last_seen_seq(&self, mailbox_id: &[u8; 32]) -> Result<u64> {
        let seq: Option<i64> = self
            .conn
            .query_row(
                "SELECT last_seen_seq FROM relay_state WHERE mailbox_id = ?1",
                rusqlite::params![mailbox_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| GhostError::Database(format!("get last_seen_seq: {e}")))?;
        Ok(seq.unwrap_or(0) as u64)
    }

    pub fn set_last_seen_seq(&self, mailbox_id: &[u8; 32], seq: u64) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO relay_state (mailbox_id, last_seen_seq) VALUES (?1, ?2)
                 ON CONFLICT(mailbox_id) DO UPDATE SET last_seen_seq = excluded.last_seen_seq",
                rusqlite::params![mailbox_id.as_slice(), seq as i64],
            )
            .map_err(|e| GhostError::Database(format!("set last_seen_seq: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> GhostStore {
        GhostStore::open_in_memory(&[0xAB; 32]).unwrap()
    }

    #[test]
    fn default_zero_for_unknown_mailbox() {
        let store = test_store();
        let mid = [0x01; 32];
        assert_eq!(store.get_last_seen_seq(&mid).unwrap(), 0);
    }

    #[test]
    fn set_then_get() {
        let store = test_store();
        let mid = [0x02; 32];
        store.set_last_seen_seq(&mid, 42).unwrap();
        assert_eq!(store.get_last_seen_seq(&mid).unwrap(), 42);
    }

    #[test]
    fn upsert_overwrites() {
        let store = test_store();
        let mid = [0x03; 32];
        store.set_last_seen_seq(&mid, 10).unwrap();
        store.set_last_seen_seq(&mid, 20).unwrap();
        assert_eq!(store.get_last_seen_seq(&mid).unwrap(), 20);
    }

    #[test]
    fn independent_mailboxes() {
        let store = test_store();
        let a = [0x0A; 32];
        let b = [0x0B; 32];
        store.set_last_seen_seq(&a, 100).unwrap();
        store.set_last_seen_seq(&b, 200).unwrap();
        assert_eq!(store.get_last_seen_seq(&a).unwrap(), 100);
        assert_eq!(store.get_last_seen_seq(&b).unwrap(), 200);
    }
}
