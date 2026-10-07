use ghost_wire::anchor::{validate_anchored_entry, AnchoredEntry};
use ghost_wire::idlog;
use ghost_wire::merkle::Checkpoint;
use ghost_wire::relay_ref::RelayRef;
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

/// One identity log entry as stored. The anchor columns are empty only for
/// entries this relay sequenced before anchoring existed; the home regenerates
/// those from its KT tree on read.
pub struct IdLogRow {
    pub seq: u64,
    pub payload: Vec<u8>,
    pub inclusion_proof: Option<Vec<u8>>,
    pub checkpoint: Option<Vec<u8>>,
}

/// What this relay knows about an account whose log it holds or mirrors.
#[derive(Debug, Clone)]
pub struct AccountRow {
    pub account_fp: [u8; 32],
    pub home_relay_vk: [u8; 32],
    pub home_relay_ref: Vec<u8>,
    pub home_set_at_seq: u64,
    pub is_home: bool,
    pub head_seq: u64,
    /// Devices of this account may authenticate here until this time (millis)
    /// even without a mailbox membership; set when an invite admits the account.
    pub guest_until: u64,
}

/// One device-linking rendezvous, addressed by account and a random token that
/// only the pairing code carries.
pub struct PairingRow {
    pub offer: Vec<u8>,
    pub response: Option<Vec<u8>>,
    pub provision: Option<Vec<u8>>,
}

/// Result of accepting one identity log entry.
#[derive(Debug)]
pub struct IdlogAppend {
    pub seq: u64,
    pub revoked: Vec<[u8; 32]>,
    pub home_relay_vk: [u8; 32],
    pub is_home: bool,
}

pub struct Storage {
    conn: Mutex<Connection>,
    relay_vk: [u8; 32],
}

impl Storage {
    pub fn open(path: &Path) -> Result<Self, RelayError> {
        let conn = Connection::open(path).map_err(|e| RelayError::Storage(e.to_string()))?;
        Self::from_connection(conn)
    }

    pub fn open_in_memory() -> Result<Self, RelayError> {
        let conn = Connection::open_in_memory().map_err(|e| RelayError::Storage(e.to_string()))?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self, RelayError> {
        let mut s = Self { conn: Mutex::new(conn), relay_vk: [0u8; 32] };
        s.init()?;
        s.relay_vk = s.get_or_create_relay_keypair()?.0;
        s.backfill_accounts()?;
        Ok(s)
    }

    /// This relay's Ed25519 verifying key, which names it in RelayRefs.
    pub fn relay_vk(&self) -> [u8; 32] {
        self.relay_vk
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

             CREATE TABLE IF NOT EXISTS mailbox_group_map (
                 mailbox_id BLOB PRIMARY KEY,
                 group_id BLOB NOT NULL
             );

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
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS pairing (
                 account_fp BLOB NOT NULL,
                 token      BLOB NOT NULL,
                 offer      BLOB NOT NULL,
                 response   BLOB,
                 provision  BLOB,
                 expires_at INTEGER NOT NULL,
                 PRIMARY KEY (account_fp, token)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS mirror_grants (
                 account_fp BLOB NOT NULL,
                 relay_vk   BLOB NOT NULL,
                 PRIMARY KEY (account_fp, relay_vk)
             ) WITHOUT ROWID;

             CREATE TABLE IF NOT EXISTS accounts (
                 account_fp      BLOB PRIMARY KEY,
                 home_relay_vk   BLOB NOT NULL,
                 home_relay_ref  BLOB NOT NULL,
                 home_set_at_seq INTEGER NOT NULL,
                 is_home         INTEGER NOT NULL,
                 head_seq        INTEGER NOT NULL,
                 guest_until     INTEGER NOT NULL DEFAULT 0,
                 last_refresh    INTEGER NOT NULL
             );",
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;

        Self::add_column_if_missing(&conn, "identity_log", "inclusion_proof", "BLOB")?;
        Self::add_column_if_missing(&conn, "identity_log", "checkpoint", "BLOB")?;
        Self::add_column_if_missing(&conn, "recovery_blob", "generation", "INTEGER NOT NULL DEFAULT 0")?;
        Self::add_column_if_missing(&conn, "sync_state", "generation", "INTEGER NOT NULL DEFAULT 0")?;
        Ok(())
    }

    fn add_column_if_missing(
        conn: &Connection,
        table: &str,
        column: &str,
        decl: &str,
    ) -> Result<(), RelayError> {
        let map_err = |e: rusqlite::Error| RelayError::Storage(e.to_string());
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})")).map_err(map_err)?;
        let exists = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(map_err)?
            .filter_map(|r| r.ok())
            .any(|name| name == column);
        if !exists {
            conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"), [])
                .map_err(map_err)?;
        }
        Ok(())
    }

    /// Accounts whose logs predate the accounts table were all created here,
    /// so this relay is their home.
    fn backfill_accounts(&self) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        let map_err = |e: rusqlite::Error| RelayError::Storage(e.to_string());
        let mut stmt = conn
            .prepare(
                "SELECT account_fp, MAX(seq) FROM identity_log
                 WHERE account_fp NOT IN (SELECT account_fp FROM accounts)
                 GROUP BY account_fp",
            )
            .map_err(map_err)?;
        let rows: Vec<(Vec<u8>, i64)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(map_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_err)?;
        let home_ref = RelayRef::key_only(self.relay_vk).to_bytes();
        for (fp, head_seq) in rows {
            conn.execute(
                "INSERT INTO accounts (account_fp, home_relay_vk, home_relay_ref, home_set_at_seq,
                                       is_home, head_seq, guest_until, last_refresh)
                 VALUES (?1, ?2, ?3, 0, 1, ?4, 0, ?5)",
                params![fp, self.relay_vk.as_slice(), home_ref, head_seq, now_millis() as i64],
            )
            .map_err(map_err)?;
        }
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

    /// Sweep log entries older than `cutoff_ms` while keeping at least `min_entries` per mailbox.
    pub fn sweep_log(&self, cutoff_ms: u64, min_entries: u64) -> Result<u64, RelayError> {
        let conn = self.conn.lock().unwrap();
        let deleted: usize = conn
            .execute(
                "DELETE FROM log WHERE received_at < ?1
                 AND seq <= (
                     SELECT MAX(ms.next_seq - ?2 - 1, 0)
                     FROM mailbox_state ms
                     WHERE ms.mailbox_id = log.mailbox_id
                 )",
                params![cutoff_ms as i64, min_entries as i64],
            )
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(deleted as u64)
    }

    /// Delete all persistent state for a mailbox (logs, state, ACL, GroupInfo, proposals, avatars).
    pub fn delete_mailbox(&self, mailbox_id: &[u8; 32]) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        let mid = mailbox_id.as_slice();
        let tx = conn.unchecked_transaction()
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        // Look up the MLS group_id for this mailbox so we can clean MLS tables
        let group_id: Option<Vec<u8>> = tx.query_row(
            "SELECT group_id FROM mailbox_group_map WHERE mailbox_id = ?1",
            params![mid],
            |row| row.get(0),
        ).optional().map_err(|e| RelayError::Storage(e.to_string()))?;

        tx.execute("DELETE FROM log WHERE mailbox_id = ?1", params![mid])
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        tx.execute("DELETE FROM mailbox_state WHERE mailbox_id = ?1", params![mid])
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        tx.execute("DELETE FROM server_info WHERE mailbox_id = ?1", params![mid])
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        tx.execute("DELETE FROM mailbox_members WHERE mailbox_id = ?1", params![mid])
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        if let Some(gid) = &group_id {
            tx.execute("DELETE FROM mls_public_group WHERE group_id = ?1", params![gid.as_slice()])
                .map_err(|e| RelayError::Storage(e.to_string()))?;
            tx.execute("DELETE FROM mls_proposals WHERE group_id = ?1", params![gid.as_slice()])
                .map_err(|e| RelayError::Storage(e.to_string()))?;
        }
        tx.execute("DELETE FROM mailbox_group_map WHERE mailbox_id = ?1", params![mid])
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        tx.execute("DELETE FROM avatar WHERE mailbox_id = ?1", params![mid])
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        tx.commit().map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(())
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

    /// Home path: accept a raw entry from one of the account's devices, sequence
    /// it, and record this relay as home. Mirrors must use `append_anchored_entries`.
    pub fn append_idlog_entry(
        &self,
        account_fp: &[u8; 32],
        payload: &[u8],
    ) -> Result<IdlogAppend, RelayError> {
        let entry = idlog::LogEntry::from_bytes(payload)
            .map_err(|e| RelayError::BadRequest(format!("invalid entry: {e}")))?;

        if entry.account_fp != *account_fp {
            return Err(RelayError::BadRequest("account_fp mismatch with URL".into()));
        }

        let conn = self.conn.lock().unwrap();

        if let Some(account) = Self::load_account(&conn, account_fp)? {
            if !account.is_home {
                return Err(RelayError::WrongHome(format!(
                    "account is homed at relay {}; this relay only mirrors it",
                    hex::encode(account.home_relay_vk),
                )));
            }
        }
        if let idlog::EntryBody::SetHomeRelay { relay_vk, .. } = &entry.body {
            if *relay_vk != self.relay_vk {
                return Err(RelayError::WrongHome(
                    "a move to another relay must be imported at that relay".into(),
                ));
            }
        }

        // Build log state from point-reads instead of replaying the full chain
        let mut state = Self::build_log_state(&conn, account_fp)?;
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        let result = Self::apply_home_entry(&tx, account_fp, &mut state, &entry, self.relay_vk)?;
        tx.commit().map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(result)
    }

    /// Validate one raw entry against `state` and store it unanchored, as the
    /// entry's home. The caller anchors it through the KT tree afterwards.
    fn apply_home_entry(
        tx: &Connection,
        account_fp: &[u8; 32],
        state: &mut idlog::LogState,
        entry: &idlog::LogEntry,
        own_vk: [u8; 32],
    ) -> Result<IdlogAppend, RelayError> {
        // Validate the new entry (signatures, authority, seq, prev_hash)
        idlog::validate_entry(state, entry)
            .map_err(|e| RelayError::BadRequest(format!("validation failed: {e}")))?;

        // Read before device_keys changes: a Recovery revokes whatever is active now
        let revoked = Self::collect_revoked_keys(tx, account_fp, entry)?;

        tx.execute(
            "INSERT INTO identity_log (account_fp, seq, prev_hash, payload, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                account_fp.as_slice(),
                entry.seq as i64,
                entry.prev_hash.as_slice(),
                entry.to_bytes(),
                now_millis() as i64,
            ],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;

        Self::update_device_keys(tx, account_fp, entry)?;
        let (home_relay_vk, is_home) = Self::upsert_account(tx, account_fp, state, Some(own_vk), own_vk)?;
        Ok(IdlogAppend { seq: entry.seq, revoked, home_relay_vk, is_home })
    }

    /// Attach the home's inclusion proof and checkpoint to an entry this relay
    /// sequenced, once the KT tree has absorbed it.
    pub fn store_anchor(
        &self,
        account_fp: &[u8; 32],
        seq: u64,
        inclusion_proof: &[u8],
        checkpoint: &[u8],
    ) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE identity_log SET inclusion_proof = ?3, checkpoint = ?4
             WHERE account_fp = ?1 AND seq = ?2",
            params![account_fp.as_slice(), seq as i64, inclusion_proof, checkpoint],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Mirror path: accept entries another relay sequenced, each carrying that
    /// home's proof. Also the path for registering a foreign account (full
    /// chain from genesis) and for learning that an account moved home.
    /// Entries already held are skipped if identical and rejected if not.
    pub fn append_anchored_entries(
        &self,
        account_fp: &[u8; 32],
        entries: &[AnchoredEntry],
    ) -> Result<Vec<IdlogAppend>, RelayError> {
        let conn = self.conn.lock().unwrap();
        let mut state = Self::build_log_state(&conn, account_fp)?;
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        let results = Self::apply_anchored_entries(&tx, account_fp, &mut state, entries, self.relay_vk)?;
        tx.commit().map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(results)
    }

    /// Make this relay the account's home: store the existing chain with the
    /// anchors its previous home issued, then sequence `new_entries` here. The
    /// first new entry must be a `SetHomeRelay` naming this relay, so every entry
    /// this relay anchors comes after the move that makes it home; at most a
    /// `Recovery` may follow it. All or nothing.
    pub fn import_account(
        &self,
        account_fp: &[u8; 32],
        prefix: &[AnchoredEntry],
        new_entries: &[idlog::LogEntry],
    ) -> Result<Vec<IdlogAppend>, RelayError> {
        let Some((first, rest)) = new_entries.split_first() else {
            return Err(RelayError::BadRequest("import carries no new entries".into()));
        };
        match &first.body {
            idlog::EntryBody::SetHomeRelay { relay_vk, .. } if *relay_vk == self.relay_vk => {}
            _ => {
                return Err(RelayError::BadRequest(
                    "the first imported entry must be a SetHomeRelay naming this relay".into(),
                ))
            }
        }
        if rest.len() > 1 || rest.iter().any(|e| !matches!(e.body, idlog::EntryBody::Recovery { .. })) {
            return Err(RelayError::BadRequest("only a Recovery may follow the SetHomeRelay".into()));
        }
        if new_entries.iter().chain(prefix.iter().map(|a| &a.entry)).any(|e| e.account_fp != *account_fp) {
            return Err(RelayError::BadRequest("account_fp mismatch with URL".into()));
        }

        let conn = self.conn.lock().unwrap();
        let mut state = Self::build_log_state(&conn, account_fp)?;
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        let mut results = Self::apply_anchored_entries(&tx, account_fp, &mut state, prefix, self.relay_vk)?;
        for entry in new_entries {
            results.push(Self::apply_home_entry(&tx, account_fp, &mut state, entry, self.relay_vk)?);
        }
        tx.commit().map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(results)
    }

    /// Validate anchored entries against `state` and store them with their anchors.
    /// Only accounts whose chain names a home are accepted: a chain without a
    /// `SetHomeRelay` gives no relay key to verify its anchors against.
    fn apply_anchored_entries(
        tx: &Connection,
        account_fp: &[u8; 32],
        state: &mut idlog::LogState,
        entries: &[AnchoredEntry],
        own_vk: [u8; 32],
    ) -> Result<Vec<IdlogAppend>, RelayError> {
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        // Entries before the chain's first SetHomeRelay were anchored by the
        // relay that entry names, which is where the account was created.
        let first_home = Self::first_home_relay(tx, account_fp)?.or_else(|| {
            entries.iter().find_map(|a| match &a.entry.body {
                idlog::EntryBody::SetHomeRelay { relay_vk, .. } => Some(*relay_vk),
                _ => None,
            })
        });
        let implied = first_home.ok_or_else(|| {
            RelayError::Unprocessable(
                "account names no home relay; it must append SetHomeRelay at its home first".into(),
            )
        })?;

        let mut results = Vec::with_capacity(entries.len());
        for anchored in entries {
            let entry = &anchored.entry;
            if entry.account_fp != *account_fp {
                return Err(RelayError::BadRequest("account_fp mismatch with URL".into()));
            }
            if entry.seq <= state.head_seq {
                let stored_hash: Option<Vec<u8>> = tx
                    .query_row(
                        "SELECT payload FROM identity_log WHERE account_fp = ?1 AND seq = ?2",
                        params![account_fp.as_slice(), entry.seq as i64],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|e| RelayError::Storage(e.to_string()))?
                    .map(|payload: Vec<u8>| blake3::hash(&payload).as_bytes().to_vec());
                if stored_hash.as_deref() == Some(idlog::entry_hash(entry).as_slice()) {
                    continue;
                }
                return Err(RelayError::Conflict);
            }

            let revoked = Self::collect_revoked_keys(tx, account_fp, entry)?;
            let prior_for_home = |home: &[u8; 32]| Self::last_checkpoint_from(tx, account_fp, home);
            validate_anchored_entry(state, anchored, Some(&implied), prior_for_home)
                .map_err(|e| RelayError::Unprocessable(format!("anchored entry {}: {e}", entry.seq)))?;

            tx.execute(
                "INSERT INTO identity_log (account_fp, seq, prev_hash, payload, received_at,
                                           inclusion_proof, checkpoint)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    account_fp.as_slice(),
                    entry.seq as i64,
                    entry.prev_hash.as_slice(),
                    entry.to_bytes(),
                    now_millis() as i64,
                    anchored.inclusion_proof.to_bytes(),
                    anchored.checkpoint.to_bytes().as_slice(),
                ],
            )
            .map_err(|e| RelayError::Storage(e.to_string()))?;
            Self::update_device_keys(tx, account_fp, entry)?;
            let (home_relay_vk, is_home) = Self::upsert_account(tx, account_fp, state, Some(implied), own_vk)?;
            results.push(IdlogAppend { seq: entry.seq, revoked, home_relay_vk, is_home });
        }
        Ok(results)
    }

    /// Relay named by the account's earliest stored `SetHomeRelay`, if any.
    fn first_home_relay(conn: &Connection, account_fp: &[u8; 32]) -> Result<Option<[u8; 32]>, RelayError> {
        let mut stmt = conn
            .prepare_cached("SELECT payload FROM identity_log WHERE account_fp = ?1 ORDER BY seq")
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        let payloads: Vec<Vec<u8>> = stmt
            .query_map(params![account_fp.as_slice()], |row| row.get(0))
            .map_err(|e| RelayError::Storage(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        for payload in payloads {
            let entry = idlog::LogEntry::from_bytes(&payload)
                .map_err(|e| RelayError::Storage(format!("corrupt idlog entry: {e}")))?;
            if let idlog::EntryBody::SetHomeRelay { relay_vk, .. } = entry.body {
                return Ok(Some(relay_vk));
            }
        }
        Ok(None)
    }

    /// Newest stored checkpoint for the account that was signed by `home`.
    fn last_checkpoint_from(
        conn: &Connection,
        account_fp: &[u8; 32],
        home: &[u8; 32],
    ) -> Option<Checkpoint> {
        let vk = ed25519_dalek::VerifyingKey::from_bytes(home).ok()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT checkpoint FROM identity_log
                 WHERE account_fp = ?1 AND checkpoint IS NOT NULL
                 ORDER BY seq DESC",
            )
            .ok()?;
        let stored: Vec<Vec<u8>> = stmt
            .query_map(params![account_fp.as_slice()], |row| row.get(0))
            .ok()?
            .filter_map(|r| r.ok())
            .collect();
        stored
            .iter()
            .filter_map(|bytes| Checkpoint::from_bytes(bytes).ok())
            .find(|cp| cp.verify(&vk).is_ok())
    }

    /// Record the chain's current home and head. A chain that names no home
    /// is homed at `implied_home`, falling back to this relay. Returns
    /// (home_relay_vk, is_home).
    fn upsert_account(
        conn: &Connection,
        account_fp: &[u8; 32],
        state: &idlog::LogState,
        implied_home: Option<[u8; 32]>,
        own_vk: [u8; 32],
    ) -> Result<([u8; 32], bool), RelayError> {
        let home_relay_vk = state.home_relay_vk.or(implied_home).unwrap_or(own_vk);
        let home_relay_ref = state
            .home_relay_ref
            .clone()
            .unwrap_or_else(|| RelayRef::key_only(home_relay_vk))
            .to_bytes();
        let is_home = home_relay_vk == own_vk;
        conn.execute(
            "INSERT INTO accounts (account_fp, home_relay_vk, home_relay_ref, home_set_at_seq,
                                   is_home, head_seq, guest_until, last_refresh)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)
             ON CONFLICT (account_fp) DO UPDATE SET
                 home_relay_vk = ?2, home_relay_ref = ?3, home_set_at_seq = ?4,
                 is_home = ?5, head_seq = ?6, last_refresh = ?7",
            params![
                account_fp.as_slice(),
                home_relay_vk.as_slice(),
                home_relay_ref,
                state.home_set_at_seq as i64,
                is_home as i64,
                state.head_seq as i64,
                now_millis() as i64,
            ],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok((home_relay_vk, is_home))
    }

    fn load_account(
        conn: &Connection,
        account_fp: &[u8; 32],
    ) -> Result<Option<AccountRow>, RelayError> {
        conn.query_row(
            "SELECT home_relay_vk, home_relay_ref, home_set_at_seq, is_home, head_seq, guest_until
             FROM accounts WHERE account_fp = ?1",
            params![account_fp.as_slice()],
            |row| {
                let vk: Vec<u8> = row.get(0)?;
                Ok(AccountRow {
                    account_fp: *account_fp,
                    home_relay_vk: vk.try_into().map_err(|_| {
                        rusqlite::Error::InvalidColumnType(0, "home_relay_vk".into(), rusqlite::types::Type::Blob)
                    })?,
                    home_relay_ref: row.get(1)?,
                    home_set_at_seq: row.get::<_, i64>(2)? as u64,
                    is_home: row.get::<_, i64>(3)? == 1,
                    head_seq: row.get::<_, i64>(4)? as u64,
                    guest_until: row.get::<_, i64>(5)? as u64,
                })
            },
        )
        .optional()
        .map_err(|e| RelayError::Storage(e.to_string()))
    }

    /// Accounts this relay holds but does not home, for pulling from their homes.
    pub fn mirrored_accounts(&self) -> Result<Vec<AccountRow>, RelayError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare_cached("SELECT account_fp FROM accounts WHERE is_home = 0")
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        let fps: Vec<Vec<u8>> = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| RelayError::Storage(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        let mut rows = Vec::with_capacity(fps.len());
        for fp in fps {
            let fp: [u8; 32] = fp
                .try_into()
                .map_err(|_| RelayError::Storage("corrupt account_fp in accounts".into()))?;
            if let Some(row) = Self::load_account(&conn, &fp)? {
                rows.push(row);
            }
        }
        Ok(rows)
    }

    pub fn get_account(&self, account_fp: &[u8; 32]) -> Result<Option<AccountRow>, RelayError> {
        let conn = self.conn.lock().unwrap();
        Self::load_account(&conn, account_fp)
    }

    /// Let the account's devices authenticate here until `until` (millis),
    /// which an invite grants so a joiner can post its first commits.
    pub fn set_account_guest_until(&self, account_fp: &[u8; 32], until: u64) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        let updated = conn
            .execute(
                "UPDATE accounts SET guest_until = MAX(guest_until, ?2) WHERE account_fp = ?1",
                params![account_fp.as_slice(), until as i64],
            )
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        if updated == 0 {
            return Err(RelayError::NotFound);
        }
        Ok(())
    }

    /// Whether a device may make authenticated requests here: it must be an
    /// active device of an account this relay homes, that belongs to a mailbox
    /// here, or that an invite admitted recently.
    pub fn may_authenticate(
        &self,
        account_fp: &[u8; 32],
        device_vk: &[u8; 32],
        now: u64,
    ) -> Result<bool, RelayError> {
        let conn = self.conn.lock().unwrap();
        let active: Option<i64> = conn
            .query_row(
                "SELECT active FROM device_keys WHERE account_fp = ?1 AND device_vk = ?2",
                params![account_fp.as_slice(), device_vk.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        if active != Some(1) {
            return Ok(false);
        }
        let Some(account) = Self::load_account(&conn, account_fp)? else {
            return Ok(false);
        };
        if account.is_home || account.guest_until > now {
            return Ok(true);
        }
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM mailbox_members WHERE account_fp = ?1)",
            params![account_fp.as_slice()],
            |row| row.get(0),
        )
        .map_err(|e| RelayError::Storage(e.to_string()))
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

        // A v1 account never set a home, so the accounts row carries this
        // relay's own key and `home_set_at_seq` 0; the chain state stays None.
        let account = Self::load_account(conn, account_fp)?;
        let (home_relay_vk, home_relay_ref, home_set_at_seq) = match account {
            Some(a) if a.home_set_at_seq > 0 => {
                let r = RelayRef::from_bytes(&a.home_relay_ref)
                    .map_err(|e| RelayError::Storage(format!("corrupt home_relay_ref: {e}")))?;
                (Some(a.home_relay_vk), Some(r), a.home_set_at_seq)
            }
            _ => (None, None, 0),
        };

        Ok(idlog::LogState {
            account_fp: *account_fp,
            master_verifying_key: Some(master_vk),
            devices,
            head_seq,
            head_hash,
            home_relay_vk,
            home_relay_ref,
            home_set_at_seq,
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
            idlog::EntryBody::SetHomeRelay { .. } => {}
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
                "SELECT seq, payload, inclusion_proof, checkpoint FROM identity_log
                 WHERE account_fp = ?1 AND seq > ?2
                 ORDER BY seq",
            )
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(params![account_fp.as_slice(), after_seq as i64], |row| {
                Ok(IdLogRow {
                    seq: row.get::<_, i64>(0)? as u64,
                    payload: row.get(1)?,
                    inclusion_proof: row.get(2)?,
                    checkpoint: row.get(3)?,
                })
            })
            .map_err(|e| RelayError::Storage(e.to_string()))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| RelayError::Storage(e.to_string()))
    }

    /// Replace the set of relays the account allows to pull its log from here.
    pub fn set_mirror_grants(&self, account_fp: &[u8; 32], relays: &[[u8; 32]]) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction().map_err(|e| RelayError::Storage(e.to_string()))?;
        tx.execute("DELETE FROM mirror_grants WHERE account_fp = ?1", params![account_fp.as_slice()])
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        for relay_vk in relays {
            tx.execute(
                "INSERT OR IGNORE INTO mirror_grants (account_fp, relay_vk) VALUES (?1, ?2)",
                params![account_fp.as_slice(), relay_vk.as_slice()],
            )
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        }
        tx.commit().map_err(|e| RelayError::Storage(e.to_string()))
    }

    pub fn is_mirror_granted(&self, account_fp: &[u8; 32], relay_vk: &[u8; 32]) -> Result<bool, RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM mirror_grants WHERE account_fp = ?1 AND relay_vk = ?2)",
            params![account_fp.as_slice(), relay_vk.as_slice()],
            |row| row.get(0),
        )
        .map_err(|e| RelayError::Storage(e.to_string()))
    }

    /// The account's master key, from the genesis entry this relay holds.
    pub fn account_master_vk(&self, account_fp: &[u8; 32]) -> Result<Option<[u8; 32]>, RelayError> {
        let conn = self.conn.lock().unwrap();
        let genesis: Option<Vec<u8>> = conn
            .query_row(
                "SELECT payload FROM identity_log WHERE account_fp = ?1 AND seq = 1",
                params![account_fp.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        let Some(genesis) = genesis else { return Ok(None) };
        match idlog::LogEntry::from_bytes(&genesis).map(|e| e.body) {
            Ok(idlog::EntryBody::Genesis { master_verifying_key, .. }) => Ok(Some(master_verifying_key)),
            _ => Err(RelayError::Storage("seq 1 is not a valid genesis".into())),
        }
    }

    /// Open a pairing session, replacing any other session for the account.
    pub fn pairing_open(&self, account_fp: &[u8; 32], token: &[u8], offer: &[u8], expires_at: u64) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction().map_err(|e| RelayError::Storage(e.to_string()))?;
        tx.execute("DELETE FROM pairing WHERE account_fp = ?1", params![account_fp.as_slice()])
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        tx.execute(
            "INSERT INTO pairing (account_fp, token, offer, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![account_fp.as_slice(), token, offer, expires_at as i64],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;
        tx.commit().map_err(|e| RelayError::Storage(e.to_string()))
    }

    /// A live (unexpired) pairing session.
    pub fn pairing_get(&self, account_fp: &[u8; 32], token: &[u8], now: u64) -> Result<Option<PairingRow>, RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT offer, response, provision FROM pairing
             WHERE account_fp = ?1 AND token = ?2 AND expires_at > ?3",
            params![account_fp.as_slice(), token, now as i64],
            |row| Ok(PairingRow { offer: row.get(0)?, response: row.get(1)?, provision: row.get(2)? }),
        )
        .optional()
        .map_err(|e| RelayError::Storage(e.to_string()))
    }

    /// Record the new device's response. Only the first response is kept, so
    /// nobody can replace it once the new device has answered.
    pub fn pairing_set_response(&self, account_fp: &[u8; 32], token: &[u8], response: &[u8], now: u64) -> Result<(), RelayError> {
        self.pairing_fill(account_fp, token, "response", response, now)
    }

    pub fn pairing_set_provision(&self, account_fp: &[u8; 32], token: &[u8], provision: &[u8], now: u64) -> Result<(), RelayError> {
        self.pairing_fill(account_fp, token, "provision", provision, now)
    }

    /// Set a column of a live session once: 404 for no live session, 409 if already set.
    fn pairing_fill(&self, account_fp: &[u8; 32], token: &[u8], column: &str, data: &[u8], now: u64) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        let updated = conn
            .execute(
                &format!(
                    "UPDATE pairing SET {column} = ?4
                     WHERE account_fp = ?1 AND token = ?2 AND expires_at > ?3 AND {column} IS NULL"
                ),
                params![account_fp.as_slice(), token, now as i64, data],
            )
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        if updated == 1 {
            return Ok(());
        }
        let live: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pairing WHERE account_fp = ?1 AND token = ?2 AND expires_at > ?3)",
                params![account_fp.as_slice(), token, now as i64],
                |row| row.get(0),
            )
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        Err(if live { RelayError::Conflict } else { RelayError::NotFound })
    }

    /// Delete expired pairing sessions; returns how many.
    pub fn pairing_sweep(&self, now: u64) -> Result<usize, RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM pairing WHERE expires_at <= ?1", params![now as i64])
            .map_err(|e| RelayError::Storage(e.to_string()))
    }

    /// Store a recovery bundle unless the stored one has an equal or newer generation.
    pub fn put_recovery_bundle(&self, account_fp: &[u8; 32], generation: u64, bundle: &[u8]) -> Result<(), RelayError> {
        self.put_generational("recovery_blob", account_fp, generation, bundle)
    }

    /// Stored recovery data and its generation; generation 0 marks a bare blob
    /// written before bundles existed.
    pub fn get_recovery_bundle(&self, account_fp: &[u8; 32]) -> Result<Option<(u64, Vec<u8>)>, RelayError> {
        self.get_generational("recovery_blob", account_fp)
    }

    /// Store a sealed sync snapshot unless the stored one has an equal or newer generation.
    pub fn put_sync_state(&self, account_fp: &[u8; 32], generation: u64, data: &[u8]) -> Result<(), RelayError> {
        self.put_generational("sync_state", account_fp, generation, data)
    }

    pub fn get_sync_state(&self, account_fp: &[u8; 32]) -> Result<Option<(u64, Vec<u8>)>, RelayError> {
        self.get_generational("sync_state", account_fp)
    }

    /// Last-writer-wins upsert for per-account replicated objects. Devices write
    /// these to every relay they use, so a stale copy must never replace a newer one.
    fn put_generational(&self, table: &str, account_fp: &[u8; 32], generation: u64, data: &[u8]) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction().map_err(|e| RelayError::Storage(e.to_string()))?;
        let stored: Option<i64> = tx
            .query_row(
                &format!("SELECT generation FROM {table} WHERE account_fp = ?1"),
                params![account_fp.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| RelayError::Storage(e.to_string()))?;
        if let Some(stored) = stored {
            if generation <= stored as u64 {
                return Err(RelayError::Conflict);
            }
        }
        tx.execute(
            &format!(
                "INSERT INTO {table} (account_fp, data, updated_at, generation) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (account_fp) DO UPDATE SET data = ?2, updated_at = ?3, generation = ?4"
            ),
            params![account_fp.as_slice(), data, now_millis() as i64, generation as i64],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;
        tx.commit().map_err(|e| RelayError::Storage(e.to_string()))
    }

    fn get_generational(&self, table: &str, account_fp: &[u8; 32]) -> Result<Option<(u64, Vec<u8>)>, RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            &format!("SELECT generation, data FROM {table} WHERE account_fp = ?1"),
            params![account_fp.as_slice()],
            |row| Ok((row.get::<_, i64>(0)? as u64, row.get(1)?)),
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

    /// Store the mapping from mailbox_id to MLS group_id for cleanup.
    pub fn set_mailbox_group_id(
        &self,
        mailbox_id: &[u8; 32],
        group_id: &[u8],
    ) -> Result<(), RelayError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO mailbox_group_map (mailbox_id, group_id) VALUES (?1, ?2)",
            params![mailbox_id.as_slice(), group_id],
        )
        .map_err(|e| RelayError::Storage(e.to_string()))?;
        Ok(())
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

    // ── Anchored (mirror) path ──────────────────────────────────────────

    /// Stand-in for another relay's KT tree: anchors entries under its own key.
    struct FakeHome {
        sk: ed25519_dalek::SigningKey,
        leaves: Vec<[u8; 32]>,
    }

    impl FakeHome {
        fn new() -> Self {
            Self { sk: ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng), leaves: Vec::new() }
        }

        fn vk(&self) -> [u8; 32] {
            self.sk.verifying_key().to_bytes()
        }

        fn anchor(&mut self, entry_bytes: &[u8]) -> AnchoredEntry {
            use ghost_wire::merkle::{leaf_hash, InclusionProof, MerkleTree};
            self.leaves.push(leaf_hash(entry_bytes));
            let mut tree = MerkleTree::new();
            for l in &self.leaves {
                tree.append(*l);
            }
            let index = self.leaves.len() as u64 - 1;
            AnchoredEntry {
                entry: ghost_wire::idlog::LogEntry::from_bytes(entry_bytes).unwrap(),
                inclusion_proof: InclusionProof::generate(index, &self.leaves),
                checkpoint: Checkpoint::sign(tree.size(), tree.root(), 1000, &self.sk),
            }
        }
    }

    fn make_set_home_relay(
        state: &ghost_wire::idlog::LogState,
        auth: &ed25519_dalek::SigningKey,
        relay_vk: [u8; 32],
    ) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let mut entry = ghost_wire::idlog::LogEntry {
            seq: state.head_seq + 1,
            prev_hash: state.head_hash,
            account_fp: state.account_fp,
            entry_type: ghost_wire::idlog::EntryType::SetHomeRelay,
            timestamp: 4000,
            body: ghost_wire::idlog::EntryBody::SetHomeRelay {
                relay_vk,
                authorizer_key: auth.verifying_key().to_bytes(),
                relay_ref: RelayRef::key_only(relay_vk),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        let msg = ghost_wire::idlog::sign_message(&entry);
        entry.signature = auth.sign(&msg).to_bytes();
        entry.to_bytes()
    }

    fn chain_state(entries: &[Vec<u8>]) -> ghost_wire::idlog::LogState {
        let parsed: Vec<_> = entries
            .iter()
            .map(|b| ghost_wire::idlog::LogEntry::from_bytes(b).unwrap())
            .collect();
        ghost_wire::idlog::validate_chain(&parsed).unwrap()
    }

    /// A v2 account created at `home`: genesis + SetHomeRelay, both anchored.
    fn foreign_account(home: &mut FakeHome) -> ([u8; 32], ed25519_dalek::SigningKey, Vec<AnchoredEntry>, Vec<Vec<u8>>) {
        let (fp, mk, dk) = test_account();
        let genesis = make_genesis(&mk, &dk);
        let set_home = make_set_home_relay(&chain_state(std::slice::from_ref(&genesis)), &dk, home.vk());
        let anchored = vec![home.anchor(&genesis), home.anchor(&set_home)];
        (fp, dk, anchored, vec![genesis, set_home])
    }

    #[test]
    fn home_append_records_account_as_homed_here() {
        let store = Storage::open_in_memory().unwrap();
        let (fp, mk, dk) = test_account();
        let result = store.append_idlog_entry(&fp, &make_genesis(&mk, &dk)).unwrap();
        assert!(result.is_home);
        assert_eq!(result.home_relay_vk, store.relay_vk());
        let account = store.get_account(&fp).unwrap().unwrap();
        assert!(account.is_home);
        assert_eq!(account.head_seq, 1);
        assert_eq!(account.home_set_at_seq, 0, "v1 chain names no home");
    }

    #[test]
    fn home_accepts_set_home_relay_naming_itself_and_rejects_others() {
        let store = Storage::open_in_memory().unwrap();
        let (fp, mk, dk) = test_account();
        let genesis = make_genesis(&mk, &dk);
        store.append_idlog_entry(&fp, &genesis).unwrap();
        let state = chain_state(std::slice::from_ref(&genesis));

        let elsewhere = make_set_home_relay(&state, &dk, [0x99; 32]);
        let err = store.append_idlog_entry(&fp, &elsewhere).unwrap_err();
        assert!(matches!(err, RelayError::WrongHome(_)), "{err}");

        let here = make_set_home_relay(&state, &dk, store.relay_vk());
        let result = store.append_idlog_entry(&fp, &here).unwrap();
        assert!(result.is_home);
        let account = store.get_account(&fp).unwrap().unwrap();
        assert_eq!(account.home_set_at_seq, 2);
        // The chain state now carries the home for later validation.
        let conn = store.conn.lock().unwrap();
        let rebuilt = Storage::build_log_state(&conn, &fp).unwrap();
        assert_eq!(rebuilt.home_relay_vk, Some(store.relay_vk()));
        assert_eq!(rebuilt.home_set_at_seq, 2);
    }

    #[test]
    fn anchored_chain_registers_mirrored_account() {
        let store = Storage::open_in_memory().unwrap();
        let mut home = FakeHome::new();
        let (fp, dk, anchored, _) = foreign_account(&mut home);

        let results = store.append_anchored_entries(&fp, &anchored).unwrap();
        assert_eq!(results.len(), 2);
        assert!(!results[1].is_home);
        assert_eq!(results[1].home_relay_vk, home.vk());

        let account = store.get_account(&fp).unwrap().unwrap();
        assert!(!account.is_home);
        assert_eq!(account.head_seq, 2);
        assert!(store.is_active_device(&fp, &dk.verifying_key().to_bytes()).unwrap());

        let rows = store.get_idlog(&fp, 0).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.inclusion_proof.is_some() && r.checkpoint.is_some()));
    }

    #[test]
    fn anchored_chain_rejected_when_checkpoint_not_from_home() {
        let store = Storage::open_in_memory().unwrap();
        let mut home = FakeHome::new();
        let mut impostor = FakeHome::new();
        let (fp, _dk, _, raw) = foreign_account(&mut home);
        // Same chain, but anchored by a relay the chain does not name.
        let forged = vec![impostor.anchor(&raw[0]), impostor.anchor(&raw[1])];
        let err = store.append_anchored_entries(&fp, &forged).unwrap_err();
        assert!(matches!(err, RelayError::Unprocessable(_)), "{err}");
        assert!(store.get_account(&fp).unwrap().is_none(), "nothing persisted");
        assert!(store.get_idlog(&fp, 0).unwrap().is_empty());
    }

    #[test]
    fn anchored_chain_without_home_is_rejected() {
        let store = Storage::open_in_memory().unwrap();
        let mut home = FakeHome::new();
        let (fp, mk, dk) = test_account();
        let anchored = vec![home.anchor(&make_genesis(&mk, &dk))];
        let err = store.append_anchored_entries(&fp, &anchored).unwrap_err();
        assert!(matches!(err, RelayError::Unprocessable(_)), "{err}");
        assert!(store.get_account(&fp).unwrap().is_none());
    }

    #[test]
    fn mirror_rejects_raw_entries_and_replays_are_idempotent() {
        let store = Storage::open_in_memory().unwrap();
        let mut home = FakeHome::new();
        let (fp, dk, anchored, raw) = foreign_account(&mut home);
        store.append_anchored_entries(&fp, &anchored).unwrap();

        // A device must append at the home, not here.
        let dk2 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let add = make_add_device(&chain_state(&raw), &dk, &dk2);
        let err = store.append_idlog_entry(&fp, &add).unwrap_err();
        assert!(matches!(err, RelayError::WrongHome(_)), "{err}");

        // Pushing the same anchored chain again is a no-op.
        let again = store.append_anchored_entries(&fp, &anchored).unwrap();
        assert!(again.is_empty());
        assert_eq!(store.get_idlog(&fp, 0).unwrap().len(), 2);

        // A different entry at a held seq is a fork.
        let mut forked = anchored[1].clone();
        forked.entry.timestamp += 1;
        let err = store.append_anchored_entries(&fp, &[forked]).unwrap_err();
        assert!(matches!(err, RelayError::Conflict));
    }

    #[test]
    fn anchored_revocation_updates_device_keys_and_reports_revoked() {
        let store = Storage::open_in_memory().unwrap();
        let mut home = FakeHome::new();
        let (fp, dk, anchored, mut raw) = foreign_account(&mut home);
        store.append_anchored_entries(&fp, &anchored).unwrap();

        let dk2 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let add = make_add_device(&chain_state(&raw), &dk, &dk2);
        raw.push(add.clone());
        let revoke = make_revoke_device(&chain_state(&raw), &dk, &dk2.verifying_key().to_bytes());
        let tail = vec![home.anchor(&add), home.anchor(&revoke)];

        let results = store.append_anchored_entries(&fp, &tail).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].revoked.is_empty());
        assert_eq!(results[1].revoked, vec![dk2.verifying_key().to_bytes()]);
        assert!(!store.is_active_device(&fp, &dk2.verifying_key().to_bytes()).unwrap());
        assert!(store.is_active_device(&fp, &dk.verifying_key().to_bytes()).unwrap());
    }

    #[test]
    fn accept_p6_anchored_entry_rejected_on_checkpoint_regression() {
        let store = Storage::open_in_memory().unwrap();
        let mut home = FakeHome::new();
        let (fp, dk, anchored, raw) = foreign_account(&mut home);
        store.append_anchored_entries(&fp, &anchored).unwrap();

        // Anchor the next entry with a checkpoint older than the one already held.
        let dk2 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let add = make_add_device(&chain_state(&raw), &dk, &dk2);
        let mut stale = home.anchor(&add);
        stale.checkpoint = anchored[0].checkpoint.clone();
        stale.inclusion_proof.tree_size = stale.checkpoint.tree_size;
        let err = store.append_anchored_entries(&fp, &[stale]).unwrap_err();
        assert!(matches!(err, RelayError::Unprocessable(_)), "{err}");
    }

    #[test]
    fn anchored_rehome_switches_home_on_old_home_and_mirror() {
        let old_home_store = Storage::open_in_memory().unwrap();
        let mirror = Storage::open_in_memory().unwrap();
        let mut new_home = FakeHome::new();

        // Account lives at old_home_store, which anchors with its real KT key.
        let (fp, mk, dk) = test_account();
        let genesis = make_genesis(&mk, &dk);
        old_home_store.append_idlog_entry(&fp, &genesis).unwrap();
        let set_home = make_set_home_relay(&chain_state(std::slice::from_ref(&genesis)), &dk, old_home_store.relay_vk());
        old_home_store.append_idlog_entry(&fp, &set_home).unwrap();

        // Build the old home's anchors the way kt_append_and_sign would.
        let (_vk, sk_bytes) = old_home_store.get_or_create_relay_keypair().unwrap();
        let mut old_home_tree = FakeHome {
            sk: ed25519_dalek::SigningKey::from_keypair_bytes(&sk_bytes).unwrap(),
            leaves: Vec::new(),
        };
        let a1 = old_home_tree.anchor(&genesis);
        let a2 = old_home_tree.anchor(&set_home);
        old_home_store.store_anchor(&fp, 1, &a1.inclusion_proof.to_bytes(), &a1.checkpoint.to_bytes()).unwrap();
        old_home_store.store_anchor(&fp, 2, &a2.inclusion_proof.to_bytes(), &a2.checkpoint.to_bytes()).unwrap();
        mirror.append_anchored_entries(&fp, &[a1.clone(), a2.clone()]).unwrap();

        // The device moves to new_home; the new home anchors the whole chain.
        let move_entry = make_set_home_relay(&chain_state(&[genesis.clone(), set_home.clone()]), &dk, new_home.vk());
        let _ = new_home.anchor(&genesis);
        let _ = new_home.anchor(&set_home);
        let moved = new_home.anchor(&move_entry);

        for store in [&old_home_store, &mirror] {
            let results = store.append_anchored_entries(&fp, std::slice::from_ref(&moved)).unwrap();
            assert_eq!(results.len(), 1);
            assert!(!results[0].is_home);
            assert_eq!(results[0].home_relay_vk, new_home.vk());
            let account = store.get_account(&fp).unwrap().unwrap();
            assert!(!account.is_home);
            assert_eq!(account.home_relay_vk, new_home.vk());
            assert_eq!(account.home_set_at_seq, 3);
        }

        // The old home no longer sequences raw entries for the account.
        let dk2 = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let add = make_add_device(&chain_state(&[genesis, set_home, move_entry]), &dk, &dk2);
        let err = old_home_store.append_idlog_entry(&fp, &add).unwrap_err();
        assert!(matches!(err, RelayError::WrongHome(_)));
    }

    #[test]
    fn may_authenticate_requires_home_membership_or_guest_window() {
        let store = Storage::open_in_memory().unwrap();
        let mut home = FakeHome::new();
        let (fp, dk, anchored, _) = foreign_account(&mut home);
        let dk_vk = dk.verifying_key().to_bytes();
        let now = 10_000;

        assert!(!store.may_authenticate(&fp, &dk_vk, now).unwrap(), "unknown account");
        store.append_anchored_entries(&fp, &anchored).unwrap();
        assert!(!store.may_authenticate(&fp, &dk_vk, now).unwrap(), "mirrored but not a member");

        store.set_account_guest_until(&fp, now + 1).unwrap();
        assert!(store.may_authenticate(&fp, &dk_vk, now).unwrap(), "guest window");
        assert!(!store.may_authenticate(&fp, &dk_vk, now + 1).unwrap(), "guest window closed");

        store.update_mailbox_members(&[0xAB; 32], &[fp]).unwrap();
        assert!(store.may_authenticate(&fp, &dk_vk, now + 1).unwrap(), "mailbox member");
        assert!(!store.may_authenticate(&fp, &[0x55; 32], now + 1).unwrap(), "unknown device");

        // Accounts homed here always authenticate.
        let (fp2, mk2, dk2) = test_account();
        store.append_idlog_entry(&fp2, &make_genesis(&mk2, &dk2)).unwrap();
        assert!(store.may_authenticate(&fp2, &dk2.verifying_key().to_bytes(), now).unwrap());
    }

    #[test]
    fn backfill_marks_legacy_accounts_as_homed_here() {
        let store = Storage::open_in_memory().unwrap();
        let (fp, mk, dk) = test_account();
        store.append_idlog_entry(&fp, &make_genesis(&mk, &dk)).unwrap();
        {
            let conn = store.conn.lock().unwrap();
            conn.execute("DELETE FROM accounts", []).unwrap();
        }
        store.backfill_accounts().unwrap();
        let account = store.get_account(&fp).unwrap().unwrap();
        assert!(account.is_home);
        assert_eq!(account.home_relay_vk, store.relay_vk());
        assert_eq!(account.head_seq, 1);
    }
}
