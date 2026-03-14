use ghost_wire::idlog;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
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

pub struct IdLogRow {
    pub seq: u64,
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

             CREATE TABLE IF NOT EXISTS server_info (
                 mailbox_id BLOB PRIMARY KEY,
                 data BLOB NOT NULL,
                 updated_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS avatar (
                 mailbox_id BLOB NOT NULL,
                 fingerprint BLOB NOT NULL,
                 data BLOB NOT NULL,
                 updated_at INTEGER NOT NULL,
                 PRIMARY KEY (mailbox_id, fingerprint)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS mailbox_state (
                 mailbox_id BLOB NOT NULL PRIMARY KEY,
                 current_epoch INTEGER NOT NULL DEFAULT 0,
                 next_seq INTEGER NOT NULL DEFAULT 1
             );

             CREATE TABLE IF NOT EXISTS identity_log (
                 account_fp BLOB NOT NULL,
                 seq INTEGER NOT NULL,
                 prev_hash BLOB NOT NULL,
                 payload BLOB NOT NULL,
                 received_at INTEGER NOT NULL,
                 PRIMARY KEY (account_fp, seq)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS device_keys (
                 account_fp BLOB NOT NULL,
                 device_vk BLOB NOT NULL,
                 active INTEGER NOT NULL DEFAULT 1,
                 added_seq INTEGER NOT NULL,
                 revoked_seq INTEGER,
                 PRIMARY KEY (account_fp, device_vk)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS recovery_blob (
                 account_fp BLOB NOT NULL PRIMARY KEY,
                 data BLOB NOT NULL,
                 updated_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS sync_state (
                 account_fp BLOB NOT NULL PRIMARY KEY,
                 data BLOB NOT NULL,
                 updated_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS mls_public_group (
                 group_id BLOB NOT NULL,
                 component TEXT NOT NULL,
                 data BLOB NOT NULL,
                 PRIMARY KEY (group_id, component)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS mls_proposals (
                 group_id BLOB NOT NULL,
                 proposal_ref BLOB NOT NULL,
                 data BLOB NOT NULL,
                 PRIMARY KEY (group_id, proposal_ref)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS mailbox_members (
                 mailbox_id BLOB NOT NULL,
                 account_fp BLOB NOT NULL,
                 PRIMARY KEY (mailbox_id, account_fp)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS relay_keypair (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 signing_key BLOB NOT NULL,
                 verifying_key BLOB NOT NULL
             );

             CREATE TABLE IF NOT EXISTS kt_leaves (
                 leaf_index INTEGER PRIMARY KEY,
                 leaf_hash  BLOB NOT NULL
             );

             CREATE TABLE IF NOT EXISTS kt_frontier (
                 level INTEGER PRIMARY KEY,
                 hash  BLOB NOT NULL
             );

             CREATE TABLE IF NOT EXISTS kt_head (
                 id         INTEGER PRIMARY KEY CHECK (id = 1),
                 tree_size  INTEGER NOT NULL,
                 root_hash  BLOB NOT NULL,
                 checkpoint BLOB NOT NULL
             );

             CREATE TABLE IF NOT EXISTS kt_nodes (
                 start  INTEGER NOT NULL,
                 count  INTEGER NOT NULL,
                 hash   BLOB NOT NULL,
                 PRIMARY KEY (start, count)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS kt_entry_index (
                 account_fp BLOB NOT NULL,
                 seq        INTEGER NOT NULL,
                 leaf_index INTEGER NOT NULL,
                 PRIMARY KEY (account_fp, seq)
             ) WITHOUT ROWID;",
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn conn(&self) -> &Mutex<Connection> {
        &self.conn
    }

    /// Store a blob, enforcing epoch ordering for commits.
    ///
    /// Commits whose epoch doesn't match the relay's current epoch are rejected
    /// with `Conflict` — the sender must re-fetch GroupInfo and retry.
    /// Application messages are always accepted (epoch mismatch is informational).
    pub fn append(
        &self,
        mailbox_id: &[u8; 32],
        envelope_type: u8,
        epoch: u64,
        payload: &[u8],
    ) -> Result<(u64, u64, bool), RelayError> {
        let conn = self.conn.lock().unwrap();
        let received_at = now_millis();
        let is_commit = envelope_type == ghost_wire::EnvelopeType::Commit as u8;

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

        let relay_epoch: u64 = tx
            .query_row(
                "SELECT current_epoch FROM mailbox_state WHERE mailbox_id = ?1",
                params![mailbox_id.as_slice()],
                |row| row.get::<_, i64>(0).map(|v| v as u64),
            )
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        let epoch_mismatch = epoch != relay_epoch;

        if is_commit && epoch_mismatch {
            return Err(RelayError::Conflict);
        }

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

        if is_commit {
            tx.execute(
                "UPDATE mailbox_state SET current_epoch = MAX(current_epoch, ?2)
                 WHERE mailbox_id = ?1",
                params![mailbox_id.as_slice(), epoch.saturating_add(1) as i64],
            )
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        }

        tx.commit()
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        Ok((seq, received_at, epoch_mismatch))
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

    pub fn put_server_info(&self, mailbox_id: &[u8; 32], data: &[u8]) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO server_info (mailbox_id, data, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (mailbox_id) DO UPDATE SET data = ?2, updated_at = ?3",
            params![mailbox_id.as_slice(), data, now_millis() as i64],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_server_info(&self, mailbox_id: &[u8; 32]) -> Result<Option<Vec<u8>>, RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT data FROM server_info WHERE mailbox_id = ?1",
            params![mailbox_id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| RelayError::Storage(e.to_string()))
    }

    pub fn put_avatar(
        &self,
        mailbox_id: &[u8; 32],
        fingerprint: &[u8; 32],
        data: &[u8],
    ) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO avatar (mailbox_id, fingerprint, data, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (mailbox_id, fingerprint) DO UPDATE SET data = ?3, updated_at = ?4",
            params![mailbox_id.as_slice(), fingerprint.as_slice(), data, now_millis() as i64],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_avatar(
        &self,
        mailbox_id: &[u8; 32],
        fingerprint: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT data FROM avatar WHERE mailbox_id = ?1 AND fingerprint = ?2",
            params![mailbox_id.as_slice(), fingerprint.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| RelayError::Storage(e.to_string()))
    }

    pub fn delete_avatar(
        &self,
        mailbox_id: &[u8; 32],
        fingerprint: &[u8; 32],
    ) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM avatar WHERE mailbox_id = ?1 AND fingerprint = ?2",
            params![mailbox_id.as_slice(), fingerprint.as_slice()],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Append a validated identity log entry. Returns (revoked device keys, entry seq).
    pub fn append_idlog_entry(
        &self,
        account_fp: &[u8; 32],
        payload: &[u8],
    ) -> Result<(Vec<[u8; 32]>, u64), RelayError> {
        let entry = idlog::LogEntry::from_bytes(payload)
            .map_err(|e| RelayError::BadRequest(format!("invalid entry: {e}")))?;

        if entry.account_fp != *account_fp {
            return Err(RelayError::BadRequest("account_fp mismatch with URL".into()));
        }

        let conn = self.conn.lock().unwrap();

        // Build log state from point-reads instead of replaying the full chain
        let mut state = Self::build_log_state(&conn, account_fp)?;

        // Validate the new entry (signatures, authority, seq, prev_hash)
        idlog::validate_entry(&mut state, &entry)
            .map_err(|e| RelayError::BadRequest(format!("validation failed: {e}")))?;

        // Collect device keys that will be revoked by this entry
        let revoked = Self::collect_revoked_keys(&conn, account_fp, &entry)?;

        // Store entry + update device_keys atomically
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        tx.execute(
            "INSERT INTO identity_log (account_fp, seq, prev_hash, payload, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                account_fp.as_slice(),
                entry.seq as i64,
                entry.prev_hash.as_slice(),
                payload,
                now_millis() as i64,
            ],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;

        // Update device_keys table based on entry type
        Self::update_device_keys(&tx, account_fp, &entry)?;

        tx.commit().map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok((revoked, entry.seq))
    }

    /// Reconstruct LogState from point-reads: last entry (head_seq, head_hash),
    /// genesis (master_vk), and device_keys table (devices).
    fn build_log_state(
        conn: &Connection,
        account_fp: &[u8; 32],
    ) -> Result<idlog::LogState, RelayError> {
        let map_err = |e: rusqlite::Error| RelayError::Storage(e.to_string());

        // Read last entry for head_seq and head_hash
        let last: Option<(i64, Vec<u8>)> = conn
            .query_row(
                "SELECT seq, payload FROM identity_log
                 WHERE account_fp = ?1 ORDER BY seq DESC LIMIT 1",
                params![account_fp.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(map_err)?;

        let (head_seq, head_hash) = match &last {
            Some((seq, payload)) => {
                let hash: [u8; 32] = blake3::hash(payload).into();
                (*seq as u64, hash)
            }
            None => return Ok(idlog::LogState::empty(*account_fp)),
        };

        // Read genesis entry for master_vk
        let genesis_payload: Vec<u8> = conn
            .query_row(
                "SELECT payload FROM identity_log
                 WHERE account_fp = ?1 AND seq = 1",
                params![account_fp.as_slice()],
                |row| row.get(0),
            )
            .map_err(map_err)?;

        let genesis = idlog::LogEntry::from_bytes(&genesis_payload)
            .map_err(|e| RelayError::Storage(format!("corrupt genesis: {e}")))?;
        let master_vk = match &genesis.body {
            idlog::EntryBody::Genesis { master_verifying_key, .. } => *master_verifying_key,
            _ => return Err(RelayError::Storage("seq 1 is not genesis".into())),
        };

        // Read device state from device_keys table
        let mut stmt = conn
            .prepare_cached(
                "SELECT device_vk, added_seq, revoked_seq
                 FROM device_keys WHERE account_fp = ?1",
            )
            .map_err(map_err)?;

        let rows: Vec<(Vec<u8>, i64, Option<i64>)> = stmt
            .query_map(params![account_fp.as_slice()], |row| {
                let vk_bytes: Vec<u8> = row.get(0)?;
                let added_seq: i64 = row.get(1)?;
                let revoked_seq: Option<i64> = row.get(2)?;
                Ok((vk_bytes, added_seq, revoked_seq))
            })
            .map_err(map_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_err)?;

        let mut devices = HashMap::new();
        for (vk_bytes, added_seq, revoked_seq) in rows {
            let vk: [u8; 32] = vk_bytes.try_into().map_err(|_| {
                RelayError::Storage("corrupt device_vk in device_keys table".into())
            })?;
            devices.insert(vk, idlog::DeviceInfo {
                verifying_key: vk,
                label: String::new(),
                added_at_seq: added_seq as u64,
                revoked_at_seq: revoked_seq.map(|s| s as u64),
            });
        }

        Ok(idlog::LogState {
            account_fp: *account_fp,
            master_verifying_key: Some(master_vk),
            devices,
            head_seq,
            head_hash,
        })
    }

    /// Return device keys that this entry will revoke.
    fn collect_revoked_keys(
        conn: &Connection,
        account_fp: &[u8; 32],
        entry: &idlog::LogEntry,
    ) -> Result<Vec<[u8; 32]>, RelayError> {
        match &entry.body {
            idlog::EntryBody::RevokeDevice { device_verifying_key, .. } => {
                Ok(vec![*device_verifying_key])
            }
            idlog::EntryBody::Recovery { .. } => {
                let map_err = |e: rusqlite::Error| RelayError::Storage(e.to_string());
                let mut stmt = conn
                    .prepare_cached(
                        "SELECT device_vk FROM device_keys
                         WHERE account_fp = ?1 AND active = 1",
                    )
                    .map_err(map_err)?;
                let rows: Vec<Vec<u8>> = stmt
                    .query_map(params![account_fp.as_slice()], |row| row.get(0))
                    .map_err(map_err)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(map_err)?;
                let mut keys = Vec::with_capacity(rows.len());
                for vk in rows {
                    let arr: [u8; 32] = vk.try_into().map_err(|_| {
                        RelayError::Storage("corrupt device_vk in device_keys table".into())
                    })?;
                    keys.push(arr);
                }
                Ok(keys)
            }
            _ => Ok(vec![]),
        }
    }

    fn update_device_keys(
        conn: &Connection,
        account_fp: &[u8; 32],
        entry: &idlog::LogEntry,
    ) -> Result<(), RelayError> {
        let map_err = |e: rusqlite::Error| RelayError::Storage(e.to_string());
        match &entry.body {
            idlog::EntryBody::Genesis { device_verifying_key, .. } => {
                conn.execute(
                    "INSERT INTO device_keys (account_fp, device_vk, active, added_seq)
                     VALUES (?1, ?2, 1, ?3)",
                    params![account_fp.as_slice(), device_verifying_key.as_slice(), entry.seq as i64],
                ).map_err(map_err)?;
            }
            idlog::EntryBody::AddDevice { device_verifying_key, .. } => {
                conn.execute(
                    "INSERT INTO device_keys (account_fp, device_vk, active, added_seq)
                     VALUES (?1, ?2, 1, ?3)",
                    params![account_fp.as_slice(), device_verifying_key.as_slice(), entry.seq as i64],
                ).map_err(map_err)?;
            }
            idlog::EntryBody::RevokeDevice { device_verifying_key, .. } => {
                conn.execute(
                    "UPDATE device_keys SET active = 0, revoked_seq = ?3
                     WHERE account_fp = ?1 AND device_vk = ?2",
                    params![account_fp.as_slice(), device_verifying_key.as_slice(), entry.seq as i64],
                ).map_err(map_err)?;
            }
            idlog::EntryBody::Recovery { device_verifying_key, .. } => {
                // Revoke all active devices
                conn.execute(
                    "UPDATE device_keys SET active = 0, revoked_seq = ?2
                     WHERE account_fp = ?1 AND active = 1",
                    params![account_fp.as_slice(), entry.seq as i64],
                ).map_err(map_err)?;
                // Add the new recovery device (may re-use a previously revoked key)
                conn.execute(
                    "INSERT OR REPLACE INTO device_keys (account_fp, device_vk, active, added_seq)
                     VALUES (?1, ?2, 1, ?3)",
                    params![account_fp.as_slice(), device_verifying_key.as_slice(), entry.seq as i64],
                ).map_err(map_err)?;
            }
        }
        Ok(())
    }

    /// Check if a device key is currently active for an account.
    pub fn is_active_device(
        &self,
        account_fp: &[u8; 32],
        device_vk: &[u8; 32],
    ) -> Result<bool, RelayError> {
        let conn = self.conn.lock().unwrap();
        let active: Option<i64> = conn
            .query_row(
                "SELECT active FROM device_keys
                 WHERE account_fp = ?1 AND device_vk = ?2",
                params![account_fp.as_slice(), device_vk.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(active == Some(1))
    }

    /// Get identity log entries for an account, optionally after a given seq.
    pub fn get_idlog(
        &self,
        account_fp: &[u8; 32],
        after_seq: u64,
    ) -> Result<Vec<IdLogRow>, RelayError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached(
                "SELECT seq, payload FROM identity_log
                 WHERE account_fp = ?1 AND seq > ?2
                 ORDER BY seq",
            )
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(params![account_fp.as_slice(), after_seq as i64], |row| {
                Ok(IdLogRow {
                    seq: row.get::<_, i64>(0)? as u64,
                    payload: row.get(1)?,
                })
            })
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| RelayError::Storage(e.to_string()))
    }

    /// Store or update a recovery blob for an account.
    pub fn put_recovery_blob(
        &self,
        account_fp: &[u8; 32],
        data: &[u8],
    ) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO recovery_blob (account_fp, data, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (account_fp) DO UPDATE SET data = ?2, updated_at = ?3",
            params![account_fp.as_slice(), data, now_millis() as i64],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Get a recovery blob for an account.
    pub fn get_recovery_blob(
        &self,
        account_fp: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT data FROM recovery_blob WHERE account_fp = ?1",
            params![account_fp.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| RelayError::Storage(e.to_string()))
    }

    pub fn put_sync_state(&self, account_fp: &[u8; 32], data: &[u8]) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sync_state (account_fp, data, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (account_fp) DO UPDATE SET data = ?2, updated_at = ?3",
            params![account_fp.as_slice(), data, now_millis() as i64],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(())
    }

    pub fn get_sync_state(&self, account_fp: &[u8; 32]) -> Result<Option<Vec<u8>>, RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT data FROM sync_state WHERE account_fp = ?1",
            params![account_fp.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| RelayError::Storage(e.to_string()))
    }

    /// Return distinct serialized group_ids from the mls_public_group table.
    pub fn stored_mls_group_ids(&self) -> Result<Vec<Vec<u8>>, RelayError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT DISTINCT group_id FROM mls_public_group")
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| RelayError::Storage(e.to_string()))
    }

    /// Replace the member set for a mailbox with the given account fingerprints.
    pub fn update_mailbox_members(
        &self,
        mailbox_id: &[u8; 32],
        members: &[[u8; 32]],
    ) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        tx.execute(
            "DELETE FROM mailbox_members WHERE mailbox_id = ?1",
            params![mailbox_id.as_slice()],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;
        for fp in members {
            tx.execute(
                "INSERT OR IGNORE INTO mailbox_members (mailbox_id, account_fp) VALUES (?1, ?2)",
                params![mailbox_id.as_slice(), fp.as_slice()],
            )
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        }
        tx.commit().map_err(|e| RelayError::Storage(e.to_string()))
    }

    pub fn is_mailbox_member(
        &self,
        mailbox_id: &[u8; 32],
        account_fp: &[u8; 32],
    ) -> Result<bool, RelayError> {
        let conn = self.conn.lock().unwrap();
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM mailbox_members WHERE mailbox_id = ?1 AND account_fp = ?2)",
                params![mailbox_id.as_slice(), account_fp.as_slice()],
                |row| row.get(0),
            )
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(exists)
    }

    /// Returns true if any membership rows exist for this mailbox (i.e., the relay has ACL data).
    pub fn has_mailbox_members(&self, mailbox_id: &[u8; 32]) -> Result<bool, RelayError> {
        let conn = self.conn.lock().unwrap();
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM mailbox_members WHERE mailbox_id = ?1)",
                params![mailbox_id.as_slice()],
                |row| row.get(0),
            )
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(exists)
    }

    /// Load or generate the relay Ed25519 keypair.
    pub fn get_or_create_relay_keypair(&self) -> Result<([u8; 32], [u8; 64]), RelayError> {
        let conn = self.conn.lock().unwrap();
        let existing: Option<(Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT signing_key, verifying_key FROM relay_keypair WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        if let Some((sk, vk)) = existing {
            let vk: [u8; 32] = vk.try_into().map_err(|_| RelayError::Storage("corrupt relay vk".into()))?;
            let sk: [u8; 64] = sk.try_into().map_err(|_| RelayError::Storage("corrupt relay sk".into()))?;
            return Ok((vk, sk));
        }

        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let sk_bytes = sk.to_keypair_bytes();
        let vk_bytes = vk.to_bytes();

        conn.execute(
            "INSERT INTO relay_keypair (id, signing_key, verifying_key) VALUES (1, ?1, ?2)",
            params![sk_bytes.as_slice(), vk_bytes.as_slice()],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;

        Ok((vk_bytes, sk_bytes))
    }

    /// Get all mailbox IDs where an account is a member.
    pub fn mailboxes_for_account(&self, account_fp: &[u8; 32]) -> Result<Vec<[u8; 32]>, RelayError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT mailbox_id FROM mailbox_members WHERE account_fp = ?1")
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        let rows: Vec<Vec<u8>> = stmt
            .query_map(params![account_fp.as_slice()], |row| row.get(0))
            .map_err(|e| RelayError::Storage(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        let mut result = Vec::with_capacity(rows.len());
        for r in rows {
            let arr: [u8; 32] = r.try_into().map_err(|_| RelayError::Storage("corrupt mailbox_id".into()))?;
            result.push(arr);
        }
        Ok(result)
    }

    // ── Key transparency ────────────────────────────────────────────────

    /// Append a leaf hash to the KT tree and record the (account_fp, seq) mapping.
    /// Returns the assigned leaf index.
    pub fn kt_append_leaf(
        &self,
        leaf_hash: &[u8; 32],
        account_fp: &[u8; 32],
        seq: u64,
    ) -> Result<u64, RelayError> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        let leaf_index: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(leaf_index), -1) + 1 FROM kt_leaves",
                [],
                |row| row.get(0),
            )
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        tx.execute(
            "INSERT INTO kt_leaves (leaf_index, leaf_hash) VALUES (?1, ?2)",
            params![leaf_index, leaf_hash.as_slice()],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;

        tx.execute(
            "INSERT INTO kt_entry_index (account_fp, seq, leaf_index) VALUES (?1, ?2, ?3)",
            params![account_fp.as_slice(), seq as i64, leaf_index],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;

        tx.commit().map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(leaf_index as u64)
    }

    /// Load the persisted Merkle tree frontier and tree size.
    pub fn kt_load_frontier(&self) -> Result<(Vec<Option<[u8; 32]>>, u64), RelayError> {
        let conn = self.conn.lock().unwrap();
        let tree_size: i64 = conn
            .query_row(
                "SELECT COALESCE(tree_size, 0) FROM kt_head WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| RelayError::Storage(e.to_string()))?
            .unwrap_or(0);

        if tree_size == 0 {
            return Ok((Vec::new(), 0));
        }

        let mut stmt = conn
            .prepare_cached("SELECT level, hash FROM kt_frontier ORDER BY level")
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        let rows: Vec<(i64, Vec<u8>)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| RelayError::Storage(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        let max_level = rows.iter().map(|(l, _)| *l).max().unwrap_or(0) as usize;
        let mut frontier = vec![None; max_level + 1];
        for (level, hash_bytes) in rows {
            let mut h = [0u8; 32];
            h.copy_from_slice(&hash_bytes);
            frontier[level as usize] = Some(h);
        }

        Ok((frontier, tree_size as u64))
    }

    /// Atomically persist the frontier and checkpoint in a single transaction.
    pub fn kt_persist_state(
        &self,
        frontier: &[Option<[u8; 32]>],
        tree_size: u64,
        root_hash: &[u8; 32],
        checkpoint_bytes: &[u8],
    ) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        tx.execute("DELETE FROM kt_frontier", [])
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        for (level, slot) in frontier.iter().enumerate() {
            if let Some(h) = slot {
                tx.execute(
                    "INSERT INTO kt_frontier (level, hash) VALUES (?1, ?2)",
                    params![level as i64, h.as_slice()],
                )
                .map_err(|e| RelayError::Storage(e.to_string()))?;
            }
        }

        tx.execute(
            "INSERT INTO kt_head (id, tree_size, root_hash, checkpoint)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT (id) DO UPDATE SET tree_size = ?1, root_hash = ?2, checkpoint = ?3",
            params![tree_size as i64, root_hash.as_slice(), checkpoint_bytes],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;

        tx.commit()
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Load the latest signed checkpoint.
    pub fn kt_load_checkpoint(&self) -> Result<Option<Vec<u8>>, RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT checkpoint FROM kt_head WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| RelayError::Storage(e.to_string()))
    }

    /// Load checkpoint bytes and tree_size atomically (single query).
    pub fn kt_load_checkpoint_with_size(&self) -> Result<(Vec<u8>, u64), RelayError> {
        let conn = self.conn.lock().unwrap();
        let result: Option<(Vec<u8>, i64)> = conn
            .query_row(
                "SELECT checkpoint, tree_size FROM kt_head WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        match result {
            Some((cp, size)) => Ok((cp, size as u64)),
            None => Ok((Vec::new(), 0)),
        }
    }

    /// Load leaf hashes in [from, to) range for proof generation.
    pub fn kt_load_leaves(
        &self,
        from: u64,
        to: u64,
    ) -> Result<Vec<[u8; 32]>, RelayError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached(
                "SELECT leaf_hash FROM kt_leaves
                 WHERE leaf_index >= ?1 AND leaf_index < ?2
                 ORDER BY leaf_index",
            )
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        let rows: Vec<Vec<u8>> = stmt
            .query_map(params![from as i64, to as i64], |row| row.get(0))
            .map_err(|e| RelayError::Storage(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        rows.into_iter()
            .map(|h| {
                h.try_into()
                    .map_err(|_| RelayError::Storage("corrupt leaf hash".into()))
            })
            .collect()
    }

    /// Look up the KT leaf index for a given identity log entry.
    pub fn kt_get_leaf_index(
        &self,
        account_fp: &[u8; 32],
        seq: u64,
    ) -> Result<Option<u64>, RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT leaf_index FROM kt_entry_index WHERE account_fp = ?1 AND seq = ?2",
            params![account_fp.as_slice(), seq as i64],
            |row| Ok(row.get::<_, i64>(0)? as u64),
        )
        .optional()
        .map_err(|e| RelayError::Storage(e.to_string()))
    }

    /// Load a stored Merkle tree node by the leaf range it covers.
    pub fn kt_load_node(
        &self,
        start: u64,
        count: u64,
    ) -> Result<Option<[u8; 32]>, RelayError> {
        let conn = self.conn.lock().unwrap();
        let result: Option<Vec<u8>> = conn
            .query_row(
                "SELECT hash FROM kt_nodes WHERE start = ?1 AND count = ?2",
                params![start as i64, count as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        match result {
            Some(h) => {
                let arr: [u8; 32] = h
                    .try_into()
                    .map_err(|_| RelayError::Storage("corrupt node hash".into()))?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }

    /// Load the hash for a subtree range: leaf hashes for count==1,
    /// internal nodes for count>1.
    pub fn kt_load_hash(&self, start: u64, count: u64) -> Result<Option<[u8; 32]>, RelayError> {
        if count == 1 {
            self.kt_load_leaf_hash(start)
        } else {
            self.kt_load_node(start, count)
        }
    }

    /// Load a single leaf hash by index from kt_leaves.
    pub fn kt_load_leaf_hash(&self, index: u64) -> Result<Option<[u8; 32]>, RelayError> {
        let conn = self.conn.lock().unwrap();
        let result: Option<Vec<u8>> = conn
            .query_row(
                "SELECT leaf_hash FROM kt_leaves WHERE leaf_index = ?1",
                params![index as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        match result {
            Some(h) => {
                let arr: [u8; 32] = h
                    .try_into()
                    .map_err(|_| RelayError::Storage("corrupt leaf hash".into()))?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }

    /// Batch-store multiple Merkle tree nodes in a single transaction.
    /// Each entry is (start, count, hash).
    pub fn kt_store_nodes(
        &self,
        nodes: &[(u64, u64, [u8; 32])],
    ) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO kt_nodes (start, count, hash) VALUES (?1, ?2, ?3)
                     ON CONFLICT (start, count) DO UPDATE SET hash = ?3",
                )
                .map_err(|e| RelayError::Storage(e.to_string()))?;
            for &(start, count, ref hash) in nodes {
                stmt.execute(params![start as i64, count as i64, hash.as_slice()])
                    .map_err(|e| RelayError::Storage(e.to_string()))?;
            }
        }
        tx.commit().map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(())
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
        let (seq1, _, _) = store.append(&mb, APP, 0, b"first").unwrap();
        let (seq2, _, _) = store.append(&mb, APP, 0, b"second").unwrap();
        let (seq3, _, _) = store.append(&mb, COMMIT, 0, b"commit").unwrap();
        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        assert_eq!(seq3, 3);
    }

    #[test]
    fn separate_mailboxes_have_independent_seqs() {
        let store = Storage::open_in_memory().unwrap();
        let mb_a = [0xAA; 32];
        let mb_b = [0xBB; 32];
        let (a1, _, _) = store.append(&mb_a, APP, 0, b"a1").unwrap();
        let (b1, _, _) = store.append(&mb_b, APP, 0, b"b1").unwrap();
        let (a2, _, _) = store.append(&mb_a, APP, 0, b"a2").unwrap();
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

        // Commit at epoch 0 advances relay epoch to 1
        store.append(&mb, COMMIT, 0, b"commit").unwrap();
        assert_eq!(store.get_epoch(&mb).unwrap(), 1);

        // Commit at epoch 1 advances to 2
        store.append(&mb, COMMIT, 1, b"commit2").unwrap();
        assert_eq!(store.get_epoch(&mb).unwrap(), 2);

        // set_epoch never goes backward
        store.set_epoch(&mb, 1).unwrap();
        assert_eq!(store.get_epoch(&mb).unwrap(), 2);

        // set_epoch can jump forward
        store.set_epoch(&mb, 5).unwrap();
        assert_eq!(store.get_epoch(&mb).unwrap(), 5);
    }

    #[test]
    fn commit_at_stale_epoch_rejected() {
        let store = Storage::open_in_memory().unwrap();
        let mb = test_mailbox();

        // First commit at epoch 0 succeeds, advances to 1
        store.append(&mb, COMMIT, 0, b"commit-a").unwrap();
        assert_eq!(store.get_epoch(&mb).unwrap(), 1);

        // Second commit at epoch 0 is rejected (stale)
        let err = store.append(&mb, COMMIT, 0, b"commit-b").unwrap_err();
        assert!(matches!(err, RelayError::Conflict));

        // Application message at stale epoch still accepted
        let (seq, _, mismatch) = store.append(&mb, APP, 0, b"app-msg").unwrap();
        assert!(mismatch);
        assert_eq!(seq, 2); // seq 1 was the first commit

        // Commit at correct epoch succeeds
        let (seq, _, mismatch) = store.append(&mb, COMMIT, 1, b"commit-c").unwrap();
        assert!(!mismatch);
        assert_eq!(seq, 3);
        assert_eq!(store.get_epoch(&mb).unwrap(), 2);
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
    fn avatar_put_get_delete() {
        let store = Storage::open_in_memory().unwrap();
        let mb = test_mailbox();
        let fp = [0xBB; 32];

        assert!(store.get_avatar(&mb, &fp).unwrap().is_none());

        store.put_avatar(&mb, &fp, b"avatar-data").unwrap();
        assert_eq!(store.get_avatar(&mb, &fp).unwrap().unwrap(), b"avatar-data");

        // Upsert replaces
        store.put_avatar(&mb, &fp, b"updated").unwrap();
        assert_eq!(store.get_avatar(&mb, &fp).unwrap().unwrap(), b"updated");

        store.delete_avatar(&mb, &fp).unwrap();
        assert!(store.get_avatar(&mb, &fp).unwrap().is_none());
    }

    #[test]
    fn avatar_different_fingerprints_independent() {
        let store = Storage::open_in_memory().unwrap();
        let mb = test_mailbox();
        let fp_a = [0xAA; 32];
        let fp_b = [0xBB; 32];

        store.put_avatar(&mb, &fp_a, b"alice").unwrap();
        store.put_avatar(&mb, &fp_b, b"bob").unwrap();

        assert_eq!(store.get_avatar(&mb, &fp_a).unwrap().unwrap(), b"alice");
        assert_eq!(store.get_avatar(&mb, &fp_b).unwrap().unwrap(), b"bob");

        store.delete_avatar(&mb, &fp_a).unwrap();
        assert!(store.get_avatar(&mb, &fp_a).unwrap().is_none());
        assert_eq!(store.get_avatar(&mb, &fp_b).unwrap().unwrap(), b"bob");
    }

    fn test_account() -> ([u8; 32], ed25519_dalek::SigningKey, ed25519_dalek::SigningKey) {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let mk = SigningKey::generate(&mut OsRng);
        let dk = SigningKey::generate(&mut OsRng);
        let fp: [u8; 32] = blake3::hash(mk.verifying_key().as_bytes()).into();
        (fp, mk, dk)
    }

    fn make_genesis(mk: &ed25519_dalek::SigningKey, dk: &ed25519_dalek::SigningKey) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let master_vk = mk.verifying_key();
        let device_vk = dk.verifying_key();
        let fp: [u8; 32] = blake3::hash(master_vk.as_bytes()).into();
        let mut entry = ghost_wire::idlog::LogEntry {
            seq: 1,
            prev_hash: [0u8; 32],
            account_fp: fp,
            entry_type: ghost_wire::idlog::EntryType::Genesis,
            timestamp: 1000,
            body: ghost_wire::idlog::EntryBody::Genesis {
                master_verifying_key: master_vk.to_bytes(),
                device_verifying_key: device_vk.to_bytes(),
                device_label: "test".to_string(),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        let msg = ghost_wire::idlog::sign_message(&entry);
        entry.signature = mk.sign(&msg).to_bytes();
        entry.counter_signature = Some(dk.sign(&msg).to_bytes());
        entry.to_bytes()
    }

    fn make_add_device(
        state: &ghost_wire::idlog::LogState,
        auth: &ed25519_dalek::SigningKey,
        new: &ed25519_dalek::SigningKey,
    ) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let mut entry = ghost_wire::idlog::LogEntry {
            seq: state.head_seq + 1,
            prev_hash: state.head_hash,
            account_fp: state.account_fp,
            entry_type: ghost_wire::idlog::EntryType::AddDevice,
            timestamp: 2000,
            body: ghost_wire::idlog::EntryBody::AddDevice {
                device_verifying_key: new.verifying_key().to_bytes(),
                device_label: "device-2".to_string(),
                authorizer_key: auth.verifying_key().to_bytes(),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        let msg = ghost_wire::idlog::sign_message(&entry);
        entry.signature = auth.sign(&msg).to_bytes();
        entry.counter_signature = Some(new.sign(&msg).to_bytes());
        entry.to_bytes()
    }

    fn make_revoke_device(
        state: &ghost_wire::idlog::LogState,
        revoker: &ed25519_dalek::SigningKey,
        target_vk: &[u8; 32],
    ) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let mut entry = ghost_wire::idlog::LogEntry {
            seq: state.head_seq + 1,
            prev_hash: state.head_hash,
            account_fp: state.account_fp,
            entry_type: ghost_wire::idlog::EntryType::RevokeDevice,
            timestamp: 3000,
            body: ghost_wire::idlog::EntryBody::RevokeDevice {
                device_verifying_key: *target_vk,
                revoker_key: revoker.verifying_key().to_bytes(),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        let msg = ghost_wire::idlog::sign_message(&entry);
        entry.signature = revoker.sign(&msg).to_bytes();
        entry.to_bytes()
    }

    #[test]
    fn idlog_append_and_fetch() {
        let store = Storage::open_in_memory().unwrap();
        let (fp, mk, dk) = test_account();

        let genesis = make_genesis(&mk, &dk);
        store.append_idlog_entry(&fp, &genesis).unwrap();

        // Parse genesis to get state for building next entry
        let parsed = ghost_wire::idlog::LogEntry::from_bytes(&genesis).unwrap();
        let state = ghost_wire::idlog::validate_chain(&[parsed]).unwrap();

        let dk2 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let add = make_add_device(&state, &dk, &dk2);
        store.append_idlog_entry(&fp, &add).unwrap();

        let all = store.get_idlog(&fp, 0).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].seq, 1);
        assert_eq!(all[1].seq, 2);

        let after1 = store.get_idlog(&fp, 1).unwrap();
        assert_eq!(after1.len(), 1);
        assert_eq!(after1[0].seq, 2);
    }

    #[test]
    fn idlog_rejects_bad_signature() {
        let store = Storage::open_in_memory().unwrap();
        let (fp, mk, dk) = test_account();

        let mut genesis = make_genesis(&mk, &dk);
        // Tamper with the signature (last 64 bytes before counter-sig flag)
        let parsed = ghost_wire::idlog::LogEntry::from_bytes(&genesis).unwrap();
        let body_len = {
            let mut buf = Vec::new();
            ghost_wire::idlog::encode_body(&mut buf, &parsed.body);
            buf.len()
        };
        let sig_offset = 85 + body_len;
        genesis[sig_offset] ^= 0xFF;

        let err = store.append_idlog_entry(&fp, &genesis).unwrap_err();
        assert!(matches!(err, RelayError::BadRequest(_)));
    }

    #[test]
    fn idlog_rejects_bad_seq() {
        let store = Storage::open_in_memory().unwrap();
        let (fp, mk, dk) = test_account();

        let genesis = make_genesis(&mk, &dk);
        store.append_idlog_entry(&fp, &genesis).unwrap();

        // Try to append genesis again (seq 1 when head is already 1)
        let err = store.append_idlog_entry(&fp, &genesis).unwrap_err();
        assert!(matches!(err, RelayError::BadRequest(_)));
    }

    #[test]
    fn idlog_separate_accounts_independent() {
        let store = Storage::open_in_memory().unwrap();
        let (fp_a, mk_a, dk_a) = test_account();
        let (fp_b, mk_b, dk_b) = test_account();

        store.append_idlog_entry(&fp_a, &make_genesis(&mk_a, &dk_a)).unwrap();
        store.append_idlog_entry(&fp_b, &make_genesis(&mk_b, &dk_b)).unwrap();

        assert_eq!(store.get_idlog(&fp_a, 0).unwrap().len(), 1);
        assert_eq!(store.get_idlog(&fp_b, 0).unwrap().len(), 1);
    }

    #[test]
    fn idlog_empty_returns_empty() {
        let store = Storage::open_in_memory().unwrap();
        assert!(store.get_idlog(&[0xCC; 32], 0).unwrap().is_empty());
    }

    #[test]
    fn idlog_device_keys_tracked() {
        let store = Storage::open_in_memory().unwrap();
        let (fp, mk, dk) = test_account();

        // No devices before genesis
        assert!(!store.is_active_device(&fp, &dk.verifying_key().to_bytes()).unwrap());

        let genesis = make_genesis(&mk, &dk);
        store.append_idlog_entry(&fp, &genesis).unwrap();

        // Device active after genesis
        assert!(store.is_active_device(&fp, &dk.verifying_key().to_bytes()).unwrap());

        // Add second device
        let parsed = ghost_wire::idlog::LogEntry::from_bytes(&genesis).unwrap();
        let state = ghost_wire::idlog::validate_chain(&[parsed]).unwrap();
        let dk2 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let add = make_add_device(&state, &dk, &dk2);
        store.append_idlog_entry(&fp, &add).unwrap();
        assert!(store.is_active_device(&fp, &dk2.verifying_key().to_bytes()).unwrap());

        // Revoke second device
        let all = store.get_idlog(&fp, 0).unwrap();
        let entries: Vec<_> = all.iter()
            .map(|r| ghost_wire::idlog::LogEntry::from_bytes(&r.payload).unwrap())
            .collect();
        let state2 = ghost_wire::idlog::validate_chain(&entries).unwrap();
        let revoke = make_revoke_device(&state2, &dk, &dk2.verifying_key().to_bytes());
        store.append_idlog_entry(&fp, &revoke).unwrap();

        assert!(!store.is_active_device(&fp, &dk2.verifying_key().to_bytes()).unwrap());
        assert!(store.is_active_device(&fp, &dk.verifying_key().to_bytes()).unwrap());
    }

    #[test]
    fn idlog_rejects_unauthorized_signer() {
        let store = Storage::open_in_memory().unwrap();
        let (fp, mk, dk) = test_account();

        let genesis = make_genesis(&mk, &dk);
        store.append_idlog_entry(&fp, &genesis).unwrap();

        let parsed = ghost_wire::idlog::LogEntry::from_bytes(&genesis).unwrap();
        let state = ghost_wire::idlog::validate_chain(&[parsed]).unwrap();

        // Rogue key tries to add a device
        let rogue = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let dk2 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let bad_add = make_add_device(&state, &rogue, &dk2);
        let err = store.append_idlog_entry(&fp, &bad_add).unwrap_err();
        assert!(matches!(err, RelayError::BadRequest(_)));
    }

    // -- Mailbox members tests --

    #[test]
    fn mailbox_members_set_check_replace() {
        let store = Storage::open_in_memory().unwrap();
        let mb = [0xAA; 32];
        let fp_a = [0x01; 32];
        let fp_b = [0x02; 32];
        let fp_c = [0x03; 32];

        // No members initially
        assert!(!store.has_mailbox_members(&mb).unwrap());
        assert!(!store.is_mailbox_member(&mb, &fp_a).unwrap());

        // Set members [A, B]
        store.update_mailbox_members(&mb, &[fp_a, fp_b]).unwrap();
        assert!(store.has_mailbox_members(&mb).unwrap());
        assert!(store.is_mailbox_member(&mb, &fp_a).unwrap());
        assert!(store.is_mailbox_member(&mb, &fp_b).unwrap());
        assert!(!store.is_mailbox_member(&mb, &fp_c).unwrap());

        // Replace with [B, C] — A should be gone
        store.update_mailbox_members(&mb, &[fp_b, fp_c]).unwrap();
        assert!(!store.is_mailbox_member(&mb, &fp_a).unwrap());
        assert!(store.is_mailbox_member(&mb, &fp_b).unwrap());
        assert!(store.is_mailbox_member(&mb, &fp_c).unwrap());
    }

    #[test]
    fn mailboxes_for_account_cross_mailbox() {
        let store = Storage::open_in_memory().unwrap();
        let mb1 = [0xAA; 32];
        let mb2 = [0xBB; 32];
        let fp = [0x01; 32];

        store.update_mailbox_members(&mb1, &[fp]).unwrap();
        store.update_mailbox_members(&mb2, &[fp]).unwrap();

        let mailboxes = store.mailboxes_for_account(&fp).unwrap();
        assert_eq!(mailboxes.len(), 2);
        assert!(mailboxes.contains(&mb1));
        assert!(mailboxes.contains(&mb2));
    }

    // -- Relay keypair tests --

    #[test]
    fn relay_keypair_idempotent() {
        let store = Storage::open_in_memory().unwrap();
        let (vk1, sk1) = store.get_or_create_relay_keypair().unwrap();
        let (vk2, sk2) = store.get_or_create_relay_keypair().unwrap();
        assert_eq!(vk1, vk2);
        assert_eq!(sk1, sk2);
    }

    #[test]
    fn relay_keypair_signs_verifies() {
        let store = Storage::open_in_memory().unwrap();
        let (vk_bytes, sk_bytes) = store.get_or_create_relay_keypair().unwrap();

        let sk = ed25519_dalek::SigningKey::from_keypair_bytes(&sk_bytes).unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes).unwrap();
        use ed25519_dalek::Signer;
        let sig = sk.sign(b"test");
        vk.verify_strict(b"test", &sig).unwrap();
    }
}
