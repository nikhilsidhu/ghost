use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;

use crate::error::RelayError;
use crate::util::now_millis;

pub struct LogEntry {
    pub seq: u64,
    pub received_at: u64,
    pub envelope_type: u8,
    pub epoch: u64,
    pub payload: Vec<u8>,
}

pub struct Storage {
    conn: Mutex<Connection>,
}

impl Storage {
    pub fn open(path: &Path) -> Result<Self, RelayError> {
        let conn = Connection::open(path).map_err(|e| RelayError::Storage(e.to_string()))?;
        let s = Self { conn: Mutex::new(conn) };
        s.init()?;
        Ok(s)
    }

    pub fn open_in_memory() -> Result<Self, RelayError> {
        let conn = Connection::open_in_memory().map_err(|e| RelayError::Storage(e.to_string()))?;
        let s = Self { conn: Mutex::new(conn) };
        s.init()?;
        Ok(s)
    }

    fn init(&self) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA cache_size = -8000;

             CREATE TABLE IF NOT EXISTS log (
                 mailbox_id BLOB NOT NULL,
                 seq INTEGER NOT NULL,
                 received_at INTEGER NOT NULL,
                 envelope_type INTEGER NOT NULL,
                 epoch INTEGER NOT NULL,
                 payload BLOB NOT NULL,
                 PRIMARY KEY (mailbox_id, seq)
             ) WITHOUT ROWID;

             CREATE INDEX IF NOT EXISTS idx_log_expiry ON log(received_at);

             CREATE TABLE IF NOT EXISTS mailbox_state (
                 mailbox_id BLOB NOT NULL PRIMARY KEY,
                 current_epoch INTEGER NOT NULL DEFAULT 0,
                 next_seq INTEGER NOT NULL DEFAULT 1
             );",
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Store a blob and return its sequence number.
    pub fn append(
        &self,
        mailbox_id: &[u8; 32],
        envelope_type: u8,
        epoch: u64,
        payload: &[u8],
    ) -> Result<(u64, u64), RelayError> {
        let conn = self.conn.lock().unwrap();
        let received_at = now_millis();

        let tx = conn
            .unchecked_transaction()
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        tx.execute(
            "INSERT INTO mailbox_state (mailbox_id, current_epoch, next_seq)
             VALUES (?1, 0, 1)
             ON CONFLICT (mailbox_id) DO NOTHING",
            params![mailbox_id.as_slice()],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;

        let seq: u64 = tx
            .query_row(
                "UPDATE mailbox_state SET next_seq = next_seq + 1
                 WHERE mailbox_id = ?1
                 RETURNING next_seq - 1",
                params![mailbox_id.as_slice()],
                |row| row.get(0),
            )
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        tx.execute(
            "INSERT INTO log (mailbox_id, seq, received_at, envelope_type, epoch, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                mailbox_id.as_slice(),
                seq,
                received_at as i64,
                envelope_type as i64,
                epoch as i64,
                payload,
            ],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;

        tx.commit()
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        Ok((seq, received_at))
    }

    /// Read log entries after a given sequence number.
    pub fn read_from(
        &self,
        mailbox_id: &[u8; 32],
        after_seq: u64,
        limit: u32,
    ) -> Result<Vec<LogEntry>, RelayError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached(
                "SELECT seq, received_at, envelope_type, epoch, payload
                 FROM log
                 WHERE mailbox_id = ?1 AND seq > ?2
                 ORDER BY seq
                 LIMIT ?3",
            )
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(params![mailbox_id.as_slice(), after_seq, limit], |row| {
                Ok(LogEntry {
                    seq: row.get(0)?,
                    received_at: row.get::<_, i64>(1)? as u64,
                    envelope_type: row.get::<_, i64>(2)? as u8,
                    epoch: row.get::<_, i64>(3)? as u64,
                    payload: row.get(4)?,
                })
            })
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| RelayError::Storage(e.to_string()))
    }

    /// Get the current epoch for a mailbox, or 0 if untracked.
    pub fn get_epoch(&self, mailbox_id: &[u8; 32]) -> Result<u64, RelayError> {
        let conn = self.conn.lock().unwrap();
        let epoch: Option<i64> = conn
            .query_row(
                "SELECT current_epoch FROM mailbox_state WHERE mailbox_id = ?1",
                params![mailbox_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(epoch.unwrap_or(0) as u64)
    }

    /// Set the epoch for a mailbox, never going backward.
    pub fn set_epoch(&self, mailbox_id: &[u8; 32], epoch: u64) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE mailbox_state SET current_epoch = MAX(current_epoch, ?2)
             WHERE mailbox_id = ?1",
            params![mailbox_id.as_slice(), epoch as i64],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Get the minimum sequence number still in the log for a mailbox, or None if empty.
    pub fn min_seq(&self, mailbox_id: &[u8; 32]) -> Result<Option<u64>, RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT MIN(seq) FROM log WHERE mailbox_id = ?1",
            params![mailbox_id.as_slice()],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map(|v| v.map(|n| n as u64))
        .map_err(|e| RelayError::Storage(e.to_string()))
    }

    /// Delete log entries older than `cutoff_millis`.
    pub fn sweep_expired(&self, cutoff_millis: u64) -> Result<usize, RelayError> {
        let conn = self.conn.lock().unwrap();
        let deleted = conn
            .execute(
                "DELETE FROM log WHERE received_at < ?1",
                params![cutoff_millis as i64],
            )
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_wire::EnvelopeType;

    const APP: u8 = EnvelopeType::Application as u8;
    const COMMIT: u8 = EnvelopeType::Commit as u8;

    fn test_mailbox() -> [u8; 32] {
        [0xAA; 32]
    }

    #[test]
    fn append_assigns_sequential_seqs() {
        let store = Storage::open_in_memory().unwrap();
        let mb = test_mailbox();
        let (seq1, _) = store.append(&mb, APP, 0, b"first").unwrap();
        let (seq2, _) = store.append(&mb, APP, 0, b"second").unwrap();
        let (seq3, _) = store.append(&mb, COMMIT, 0, b"commit").unwrap();
        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        assert_eq!(seq3, 3);
    }

    #[test]
    fn separate_mailboxes_have_independent_seqs() {
        let store = Storage::open_in_memory().unwrap();
        let mb_a = [0xAA; 32];
        let mb_b = [0xBB; 32];
        let (a1, _) = store.append(&mb_a, APP, 0, b"a1").unwrap();
        let (b1, _) = store.append(&mb_b, APP, 0, b"b1").unwrap();
        let (a2, _) = store.append(&mb_a, APP, 0, b"a2").unwrap();
        assert_eq!(a1, 1);
        assert_eq!(b1, 1);
        assert_eq!(a2, 2);
    }

    #[test]
    fn read_from_returns_entries_after_seq() {
        let store = Storage::open_in_memory().unwrap();
        let mb = test_mailbox();
        store.append(&mb, APP, 0, b"one").unwrap();
        store.append(&mb, APP, 0, b"two").unwrap();
        store.append(&mb, APP, 0, b"three").unwrap();

        let entries = store.read_from(&mb, 1, 100).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].seq, 2);
        assert_eq!(entries[0].payload, b"two");
        assert_eq!(entries[1].seq, 3);
        assert_eq!(entries[1].payload, b"three");
    }

    #[test]
    fn read_from_zero_returns_all() {
        let store = Storage::open_in_memory().unwrap();
        let mb = test_mailbox();
        store.append(&mb, APP, 0, b"one").unwrap();
        store.append(&mb, APP, 0, b"two").unwrap();

        let entries = store.read_from(&mb, 0, 100).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn read_from_respects_limit() {
        let store = Storage::open_in_memory().unwrap();
        let mb = test_mailbox();
        for i in 0..10 {
            store.append(&mb, APP, 0, format!("msg{i}").as_bytes()).unwrap();
        }

        let entries = store.read_from(&mb, 0, 3).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].seq, 1);
        assert_eq!(entries[2].seq, 3);
    }

    #[test]
    fn epoch_tracking() {
        let store = Storage::open_in_memory().unwrap();
        let mb = test_mailbox();

        assert_eq!(store.get_epoch(&mb).unwrap(), 0);

        // Append creates the mailbox_state row
        store.append(&mb, COMMIT, 0, b"commit").unwrap();
        assert_eq!(store.get_epoch(&mb).unwrap(), 0);

        // set_epoch advances forward
        store.set_epoch(&mb, 1).unwrap();
        assert_eq!(store.get_epoch(&mb).unwrap(), 1);

        store.set_epoch(&mb, 3).unwrap();
        assert_eq!(store.get_epoch(&mb).unwrap(), 3);

        // set_epoch never goes backward
        store.set_epoch(&mb, 1).unwrap();
        assert_eq!(store.get_epoch(&mb).unwrap(), 3);
    }

    #[test]
    fn min_seq_empty_mailbox() {
        let store = Storage::open_in_memory().unwrap();
        let mb = test_mailbox();
        assert_eq!(store.min_seq(&mb).unwrap(), None);
    }

    #[test]
    fn min_seq_after_append() {
        let store = Storage::open_in_memory().unwrap();
        let mb = test_mailbox();
        store.append(&mb, APP, 0, b"one").unwrap();
        store.append(&mb, APP, 0, b"two").unwrap();
        assert_eq!(store.min_seq(&mb).unwrap(), Some(1));
    }

    #[test]
    fn sweep_removes_old_entries() {
        let store = Storage::open_in_memory().unwrap();
        let mb = test_mailbox();
        store.append(&mb, APP, 0, b"old").unwrap();
        store.append(&mb, APP, 0, b"new").unwrap();

        let entries = store.read_from(&mb, 0, 100).unwrap();
        let cutoff = entries[0].received_at + 1;

        // Both have ~same timestamp, so sweep with future cutoff removes all
        let deleted = store.sweep_expired(cutoff + 1000).unwrap();
        assert_eq!(deleted, 2);

        let remaining = store.read_from(&mb, 0, 100).unwrap();
        assert!(remaining.is_empty());
    }
}
