pub mod account_keys;
pub mod channels;
pub mod deleted_channels;
pub mod device_config;
pub mod former_homes;
pub mod idlog_cache;
pub mod kt_state;
pub mod servers;
pub mod server_views;
pub mod shown_moves;
pub mod members;
pub mod messages;
pub mod pending_revocations;
pub mod profile_owed;
pub mod read_state;
pub mod relay_state;
pub mod relays;
pub mod replaced_history;
pub mod role_names;
pub mod server_state;
pub mod sync_cursors;
pub mod sync_state;
mod schema;

use ghost_wire::short_id;
use std::path::Path;

use rusqlite::Connection;

use rusqlite::types::Type;

use crate::error::{GhostError, Result};

// Extract a 32-byte BLOB from a row column into a fixed-size array.
pub(crate) fn blob32(row: &rusqlite::Row, idx: usize) -> rusqlite::Result<[u8; 32]> {
    let bytes: Vec<u8> = row.get(idx)?;
    bytes.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(idx, Type::Blob, "expected 32 bytes".into())
    })
}

/// Encrypted local database for servers, channels, members, and messages.
pub struct GhostStore {
    conn: Connection,
}

impl GhostStore {
    /// Open (or create) an encrypted database at `path`.
    pub fn open(db_key: &[u8; 32], path: &Path) -> Result<Self> {
        let conn =
            Connection::open(path).map_err(db("open"))?;

        // Unlock the encrypted database
        conn.pragma_update(None, "key", format!("x'{}'", hex::encode(db_key)))
            .map_err(db("set key"))?;

        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(db("enable foreign keys"))?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(db("set WAL"))?;

        schema::initialize(&conn)?;

        Ok(Self { conn })
    }

    /// Open an in-memory encrypted database (useful for testing).
    pub fn open_in_memory(db_key: &[u8; 32]) -> Result<Self> {
        let conn = Connection::open_in_memory()
            .map_err(db("open in-memory"))?;

        conn.pragma_update(None, "key", format!("x'{}'", hex::encode(db_key)))
            .map_err(db("set key"))?;

        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(db("enable foreign keys"))?;

        schema::initialize(&conn)?;

        Ok(Self { conn })
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// For what needs the connection to itself, as OpenMLS's migrations do.
    pub(crate) fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// Run `f` as one write: all of its statements land, or none if it fails or the
    /// process ends meanwhile. Inside another such write it becomes part of that one.
    pub(crate) fn write_whole<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        self.begin_whole()?;
        let written = f().and_then(|value| self.end_whole().map(|()| value));
        if written.is_err() {
            self.abandon_whole();
        }
        written
    }

    /// Begin a write made of several store calls that must land together, for a caller
    /// that cannot pass them as one closure; `end_whole` lands them. Nests like
    /// `write_whole`.
    pub fn begin_whole(&self) -> Result<()> {
        self.conn.execute_batch("SAVEPOINT whole").map_err(db("begin write"))
    }

    /// Land what was written since the matching `begin_whole`.
    pub fn end_whole(&self) -> Result<()> {
        self.conn.execute_batch("RELEASE whole").map_err(db("end write"))
    }

    /// Undo what was written since the matching `begin_whole`, after it failed or its end
    /// did. Nothing to undo, as when a failed end already rolled it back, is no error.
    pub fn abandon_whole(&self) {
        let _ = self.conn.execute_batch("ROLLBACK TO whole; RELEASE whole");
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ServerKind {
    Server,
    Group,
    Dm,
}

impl ServerKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ServerKind::Server => "server",
            ServerKind::Group => "group",
            ServerKind::Dm => "dm",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "server" => Ok(ServerKind::Server),
            "group" => Ok(ServerKind::Group),
            "dm" => Ok(ServerKind::Dm),
            other => Err(GhostError::Database(format!("unknown server kind: {other}"))),
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            ServerKind::Server => 0,
            ServerKind::Group => 2,
            ServerKind::Dm => 1,
        }
    }

    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(ServerKind::Server),
            2 => Ok(ServerKind::Group),
            1 => Ok(ServerKind::Dm),
            _ => Err(GhostError::Format(format!("unknown server kind byte: {b}"))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Server {
    pub server_id: [u8; 32],
    pub name: String,
    pub kind: ServerKind,
    pub created_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ChannelKind {
    Text,
    Voice,
}

impl ChannelKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChannelKind::Text => "text",
            ChannelKind::Voice => "voice",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "text" => Ok(ChannelKind::Text),
            "voice" => Ok(ChannelKind::Voice),
            other => Err(GhostError::Database(format!(
                "unknown channel kind: {other}"
            ))),
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            ChannelKind::Text => 0,
            ChannelKind::Voice => 1,
        }
    }

    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(ChannelKind::Text),
            1 => Ok(ChannelKind::Voice),
            _ => Err(GhostError::Format(format!("unknown channel kind byte: {b}"))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Channel {
    pub channel_id: [u8; 32],
    pub server_id: [u8; 32],
    pub name: String,
    pub kind: ChannelKind,
    pub position: i32,
}

#[derive(Debug, Clone)]
pub struct Member {
    pub server_id: [u8; 32],
    pub fingerprint: [u8; 32],
    pub display_name: String,
    pub joined_at: u64,
    pub avatar_hash: Option<[u8; 32]>,
    pub avatar_key: Option<[u8; 32]>,
}

/// When, and by whom when known, this account was removed from a server it still shows,
/// read-only. Another device of the account may learn of it only from sync,
/// which does not say who.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerRemoval {
    pub at: u64,
    pub by: Option<[u8; 32]>,
}

/// Part of this account's own log a device had cached that a root-signed branch (a
/// recovery or a move signed with the recovery key) replaced: where it diverged, how
/// many cached entries went, and the devices that existed only in what went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplacedHistory {
    pub from_seq: u64,
    pub discarded: u32,
    pub lost_devices: Vec<String>,
}

/// Why this device stopped following a server: its relay accepted a change the server's
/// rules forbid, so the device keeps its copy from before it until the person decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHalt {
    pub at: u64,
    pub reason: String,
}

/// The name a member is stored under until their own announcement arrives.
pub fn placeholder_name(fingerprint: &[u8; 32]) -> String {
    short_id(fingerprint)
}

impl Member {
    /// Whether their real name has reached this device.
    pub fn has_name(&self) -> bool {
        self.display_name != placeholder_name(&self.fingerprint)
    }
}

#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub message_id: [u8; 32],
    pub channel_id: [u8; 32],
    pub sender_fp: [u8; 32],
    pub message_type: u8,
    pub timestamp: u64,
    pub received_at: u64,
    pub content: Vec<u8>,
    pub expires_at: Option<u64>,
    pub references: Vec<[u8; 32]>,
    pub delivery: Delivery,
}

/// What an insert does when the row is already there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnConflict {
    /// The write fails.
    Fail,
    /// The row stays as it is.
    Keep,
}

impl OnConflict {
    /// The SQL verb for the insert.
    pub(crate) fn verb(self) -> &'static str {
        match self {
            OnConflict::Fail => "INSERT",
            OnConflict::Keep => "INSERT OR IGNORE",
        }
    }
}

/// The error a failed statement becomes, named after what it was doing.
pub(crate) fn db(context: &'static str) -> impl Fn(rusqlite::Error) -> GhostError {
    move |e| GhostError::Database(format!("{context}: {e}"))
}

/// Where a message stands between this device and the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Received from the relay, or acknowledged by it.
    Delivered = 0,
    /// This device's own, waiting for a connection: sent when the mailbox connects or,
    /// after a refusal for an epoch the group has left, when the epoch comes back.
    Pending = 1,
    /// The relay refused it for good; the user may try again.
    Failed = 2,
    /// This device's own, handed to a connection and awaiting the relay's answer.
    Sent = 3,
}

impl Delivery {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Pending,
            2 => Self::Failed,
            3 => Self::Sent,
            _ => Self::Delivered,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MessageType;

    fn test_store() -> GhostStore {
        GhostStore::open_in_memory(&[0xABu8; 32]).unwrap()
    }

    fn rand_id() -> [u8; 32] {
        use rand::RngCore;
        let mut id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    fn make_server(name: &str) -> Server {
        Server {
            server_id: rand_id(),
            name: name.to_string(),
            kind: ServerKind::Server,
            created_at: 1000,
        }
    }

    fn make_channel(server_id: [u8; 32], name: &str, pos: i32) -> Channel {
        Channel {
            channel_id: rand_id(),
            server_id,
            name: name.to_string(),
            kind: ChannelKind::Text,
            position: pos,
        }
    }

    fn make_member(server_id: [u8; 32]) -> Member {
        Member {
            server_id,
            fingerprint: rand_id(),
            display_name: "user".to_string(),
            joined_at: 2000,
            avatar_hash: None,
            avatar_key: None,
        }
    }

    fn make_message(channel_id: [u8; 32], ts: u64, text: &str) -> StoredMessage {
        StoredMessage {
            message_id: rand_id(),
            channel_id,
            sender_fp: rand_id(),
            message_type: MessageType::Text as u8,
            timestamp: ts,
            received_at: ts,
            content: text.as_bytes().to_vec(),
            expires_at: None,
            references: vec![],
            delivery: Delivery::Delivered,
        }
    }

    // -- Server tests --

    #[test]
    fn server_insert_get_list() {
        let store = test_store();
        let s = make_server("test-server");
        store.insert_server(&s, OnConflict::Fail).unwrap();

        let got = store.get_server(&s.server_id).unwrap();
        assert_eq!(got.name, "test-server");
        assert_eq!(got.server_id, s.server_id);

        let all = store.list_servers().unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn server_rename() {
        let store = test_store();
        let s = make_server("old-name");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        store.rename_server(&s.server_id, "new-name").unwrap();

        let got = store.get_server(&s.server_id).unwrap();
        assert_eq!(got.name, "new-name");
    }

    // -- Channel tests --

    #[test]
    fn channel_insert_list_by_server() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();

        let c1 = make_channel(s.server_id, "general", 0);
        let c2 = make_channel(s.server_id, "random", 1);
        store.insert_channel(&c1, OnConflict::Fail).unwrap();
        store.insert_channel(&c2, OnConflict::Fail).unwrap();

        let channels = store.list_channels(&s.server_id).unwrap();
        assert_eq!(channels.len(), 2);
        assert_eq!(channels[0].name, "general");
        assert_eq!(channels[1].name, "random");
    }

    #[test]
    fn channel_rename() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let c = make_channel(s.server_id, "old", 0);
        store.insert_channel(&c, OnConflict::Fail).unwrap();

        store.rename_channel(&c.channel_id, "new").unwrap();
        let got = store.get_channel(&c.channel_id).unwrap();
        assert_eq!(got.name, "new");
    }

    // -- Member tests --

    #[test]
    fn member_insert_list_remove() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();

        let m = make_member(s.server_id);
        store.insert_member(&m, OnConflict::Fail).unwrap();

        let members = store.list_members(&s.server_id).unwrap();
        assert_eq!(members.len(), 1);

        store.remove_member(&s.server_id, &m.fingerprint).unwrap();
        let members = store.list_members(&s.server_id).unwrap();
        assert_eq!(members.len(), 0);
    }

    // -- Message tests --

    #[test]
    fn message_insert_get_paginate() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c, OnConflict::Fail).unwrap();

        for i in 0..5 {
            let msg = make_message(c.channel_id, 1000 + i, &format!("msg {i}"));
            store.insert_message(&msg).unwrap();
        }

        // Get newest 3
        let page1 = store.get_messages(&c.channel_id, None, 3).unwrap();
        assert_eq!(page1.len(), 3);
        assert_eq!(page1[0].received_at, 1004); // newest first

        // Paginate: before the oldest in page1
        let page2 = store
            .get_messages(&c.channel_id, Some(page1[2].received_at), 3)
            .unwrap();
        assert_eq!(page2.len(), 2);
    }

    #[test]
    fn message_references() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c, OnConflict::Fail).unwrap();

        let original = make_message(c.channel_id, 1000, "hello");
        store.insert_message(&original).unwrap();

        let mut reply = make_message(c.channel_id, 1001, "reply");
        reply.message_type = MessageType::Text as u8;
        reply.references = vec![original.message_id];
        store.insert_message(&reply).unwrap();

        let got = store.get_message(&reply.message_id).unwrap();
        assert_eq!(got.references.len(), 1);
        assert_eq!(got.references[0], original.message_id);
    }

    #[test]
    fn delete_message_clears_content() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c, OnConflict::Fail).unwrap();

        let msg = make_message(c.channel_id, 1000, "secret");
        store.insert_message(&msg).unwrap();

        store.delete_message(&msg.message_id).unwrap();
        let got = store.get_message(&msg.message_id).unwrap();
        assert_eq!(got.content, b"");
        assert_eq!(got.message_type, MessageType::Delete as u8);
    }

    #[test]
    fn fts_search() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c, OnConflict::Fail).unwrap();

        let m1 = make_message(c.channel_id, 1000, "hello world");
        let m2 = make_message(c.channel_id, 1001, "goodbye world");
        let m3 = make_message(c.channel_id, 1002, "hello again");
        store.insert_message(&m1).unwrap();
        store.insert_message(&m2).unwrap();
        store.insert_message(&m3).unwrap();

        let results = store.search_messages(&c.channel_id, "hello").unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn deleted_message_excluded_from_search() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c, OnConflict::Fail).unwrap();

        let m1 = make_message(c.channel_id, 1000, "sensitive data");
        let m2 = make_message(c.channel_id, 1001, "keep this");
        store.insert_message(&m1).unwrap();
        store.insert_message(&m2).unwrap();

        assert_eq!(
            store
                .search_messages(&c.channel_id, "sensitive")
                .unwrap()
                .len(),
            1
        );

        store.delete_message(&m1.message_id).unwrap();

        // Deleted message must not appear in search results
        assert_eq!(
            store
                .search_messages(&c.channel_id, "sensitive")
                .unwrap()
                .len(),
            0
        );
        // Other messages still searchable
        assert_eq!(
            store.search_messages(&c.channel_id, "keep").unwrap().len(),
            1
        );
    }

    // -- Cascade delete tests --

    #[test]
    fn cascade_delete_server_removes_children() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();

        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c, OnConflict::Fail).unwrap();

        let m = make_member(s.server_id);
        store.insert_member(&m, OnConflict::Fail).unwrap();

        let msg = make_message(c.channel_id, 1000, "hi");
        store.insert_message(&msg).unwrap();

        store.delete_server(&s.server_id).unwrap();

        assert!(store.get_channel(&c.channel_id).is_err());
        assert!(store.list_members(&s.server_id).unwrap().is_empty());
        assert!(store.get_message(&msg.message_id).is_err());
    }

    #[test]
    fn cascade_delete_channel_removes_messages() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c, OnConflict::Fail).unwrap();

        let msg = make_message(c.channel_id, 1000, "hi");
        store.insert_message(&msg).unwrap();

        store.delete_channel(&c.channel_id).unwrap();
        assert!(store.get_message(&msg.message_id).is_err());
    }

    #[test]
    fn remove_member_keeps_messages() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c, OnConflict::Fail).unwrap();

        let m = make_member(s.server_id);
        store.insert_member(&m, OnConflict::Fail).unwrap();

        let mut msg = make_message(c.channel_id, 1000, "hi");
        msg.sender_fp = m.fingerprint;
        store.insert_message(&msg).unwrap();

        store.remove_member(&s.server_id, &m.fingerprint).unwrap();

        // Message still exists after member removal
        let got = store.get_message(&msg.message_id).unwrap();
        assert_eq!(got.sender_fp, m.fingerprint);
    }

    // -- Encrypted DB tests --

    #[test]
    fn encrypted_db_not_plain_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let db_key = [0xABu8; 32];

        {
            let store = GhostStore::open(&db_key, &path).unwrap();
            let s = make_server("grp");
            store.insert_server(&s, OnConflict::Fail).unwrap();
        }

        // Try opening the file without encryption — should fail
        let plain = Connection::open(&path).unwrap();
        let result = plain.execute_batch("SELECT * FROM servers");
        assert!(result.is_err());
    }

    #[test]
    fn data_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("persist.db");
        let db_key = [0xABu8; 32];
        let server_id;

        {
            let store = GhostStore::open(&db_key, &path).unwrap();
            let s = make_server("survivors");
            server_id = s.server_id;
            store.insert_server(&s, OnConflict::Fail).unwrap();
        }

        // Reopen with same key, data should be there
        let store = GhostStore::open(&db_key, &path).unwrap();
        let got = store.get_server(&server_id).unwrap();
        assert_eq!(got.name, "survivors");
    }

    // -- Error path tests --

    // -- Transaction tests --

    #[test]
    fn duplicate_references_deduped() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c, OnConflict::Fail).unwrap();

        let target = rand_id();
        let mut msg = make_message(c.channel_id, 1000, "dup refs");
        msg.references = vec![target, target];

        store.insert_message(&msg).unwrap();
        let got = store.get_message(&msg.message_id).unwrap();
        assert_eq!(got.references.len(), 1);
    }

    #[test]
    fn duplicate_message_id_is_idempotent() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c, OnConflict::Fail).unwrap();

        let msg = make_message(c.channel_id, 1000, "hello");
        store.insert_message(&msg).unwrap();
        // Re-inserting the same message_id succeeds silently
        store.insert_message(&msg).unwrap();

        let got = store.get_message(&msg.message_id).unwrap();
        assert_eq!(got.content, b"hello");
    }

    #[test]
    fn a_received_message_marks_its_blob_seen_in_the_same_write() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c, OnConflict::Fail).unwrap();
        let mailbox = [0x5A; 32];

        store.insert_message_seen(&make_message(c.channel_id, 1000, "hello"), Some((&mailbox, 7))).unwrap();
        assert_eq!(store.get_last_seen_seq(&mailbox).unwrap(), 7);

        // A message that cannot be stored (its channel is not here) marks nothing seen.
        let orphan = make_message([0x99; 32], 2000, "lost");
        assert!(store.insert_message_seen(&orphan, Some((&mailbox, 8))).is_err());
        assert_eq!(store.get_last_seen_seq(&mailbox).unwrap(), 7);
    }

    #[test]
    fn an_answer_taken_in_before_the_hand_over_returns_is_not_undone() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c, OnConflict::Fail).unwrap();
        let msg = StoredMessage { delivery: Delivery::Pending, ..make_message(c.channel_id, 1000, "hello") };
        store.insert_message(&msg).unwrap();

        store.set_delivery(&msg.message_id, Delivery::Delivered).unwrap();
        store.mark_sent(&msg.message_id).unwrap();
        assert_eq!(store.get_message(&msg.message_id).unwrap().delivery, Delivery::Delivered);

        store.set_delivery(&msg.message_id, Delivery::Pending).unwrap();
        store.mark_sent(&msg.message_id).unwrap();
        assert_eq!(store.get_message(&msg.message_id).unwrap().delivery, Delivery::Sent);
    }

    #[test]
    fn writes_made_whole_nest_and_a_failure_undoes_only_its_own() {
        let store = test_store();
        let (outer, inner) = ([1; 32], [2; 32]);
        store
            .write_whole(|| {
                store.set_last_seen_seq(&outer, 1)?;
                let failed: Result<()> = store.write_whole(|| {
                    store.set_last_seen_seq(&inner, 2)?;
                    Err(GhostError::Database("refused".into()))
                });
                assert!(failed.is_err());
                Ok(())
            })
            .unwrap();
        assert_eq!(store.get_last_seen_seq(&outer).unwrap(), 1);
        assert_eq!(store.get_last_seen_seq(&inner).unwrap(), 0);

        store.begin_whole().unwrap();
        store.set_last_seen_seq(&inner, 3).unwrap();
        store.end_whole().unwrap();
        assert_eq!(store.get_last_seen_seq(&inner).unwrap(), 3);
    }

    // -- FTS edge cases --

    #[test]
    fn fts_special_characters_dont_crash() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c, OnConflict::Fail).unwrap();

        let m = make_message(c.channel_id, 1000, "normal message");
        store.insert_message(&m).unwrap();

        // These are valid FTS5 syntax — should not panic
        let _ = store.search_messages(&c.channel_id, "normal*");
        let _ = store.search_messages(&c.channel_id, "\"normal message\"");
        // Unbalanced quote — FTS5 may error, but must not panic
        let _ = store.search_messages(&c.channel_id, "\"unclosed");
        let _ = store.search_messages(&c.channel_id, "OR AND NOT");
    }

    // -- Sync state tests --

    #[test]
    fn sync_set_get_roundtrip() {
        let store = test_store();
        let applied = store.sync_set("order:servers", b"hello", 100).unwrap();
        assert!(applied);
        let (value, ts) = store.sync_get("order:servers").unwrap().unwrap();
        assert_eq!(value.unwrap(), b"hello");
        assert_eq!(ts, 100);
    }

    #[test]
    fn sync_set_newer_wins() {
        let store = test_store();
        store.sync_set("k", b"old", 100).unwrap();
        let applied = store.sync_set("k", b"new", 200).unwrap();
        assert!(applied);
        let (value, ts) = store.sync_get("k").unwrap().unwrap();
        assert_eq!(value.unwrap(), b"new");
        assert_eq!(ts, 200);
    }

    #[test]
    fn sync_set_older_loses() {
        let store = test_store();
        store.sync_set("k", b"winner", 200).unwrap();
        let applied = store.sync_set("k", b"loser", 100).unwrap();
        assert!(!applied);
        let (value, _) = store.sync_get("k").unwrap().unwrap();
        assert_eq!(value.unwrap(), b"winner");
    }

    #[test]
    fn sync_remove_tombstone() {
        let store = test_store();
        store.sync_set("k", b"val", 100).unwrap();
        let applied = store.sync_remove("k", 200).unwrap();
        assert!(applied);
        let (value, ts) = store.sync_get("k").unwrap().unwrap();
        assert!(value.is_none());
        assert_eq!(ts, 200);
    }

    #[test]
    fn sync_remove_older_loses() {
        let store = test_store();
        store.sync_set("k", b"val", 200).unwrap();
        let applied = store.sync_remove("k", 100).unwrap();
        assert!(!applied);
        let (value, _) = store.sync_get("k").unwrap().unwrap();
        assert_eq!(value.unwrap(), b"val");
    }

    #[test]
    fn sync_dump_import_roundtrip() {
        let store1 = test_store();
        store1.sync_set("order:servers", b"\x01", 100).unwrap();
        store1.sync_set("read:bb", b"\x02", 200).unwrap();
        store1.sync_remove("order:channels", 150).unwrap();

        let dump = store1.sync_dump().unwrap();
        assert_eq!(dump.len(), 3);

        let store2 = test_store();
        store2.sync_import(&dump).unwrap();

        let (v1, t1) = store2.sync_get("order:servers").unwrap().unwrap();
        assert_eq!(v1.unwrap(), b"\x01");
        assert_eq!(t1, 100);

        let (v2, _) = store2.sync_get("read:bb").unwrap().unwrap();
        assert_eq!(v2.unwrap(), b"\x02");

        let (v3, _) = store2.sync_get("order:channels").unwrap().unwrap();
        assert!(v3.is_none()); // tombstone
    }

    // -- Config blob tests --

    #[test]
    fn config_blob_roundtrip() {
        let store = test_store();
        store.set_config_blob("theme", b"dark").unwrap();
        assert_eq!(store.get_config_blob("theme").unwrap().unwrap(), b"dark");
    }

    // -- conflict mode tests --

    #[test]
    fn keeping_a_server_on_conflict_is_idempotent() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Keep).unwrap();
        store.insert_server(&s, OnConflict::Keep).unwrap();
        let got = store.get_server(&s.server_id).unwrap();
        assert_eq!(got.name, "grp");
    }

    #[test]
    fn failing_on_conflict_rejects_a_second_insert() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        assert!(store.insert_server(&s, OnConflict::Fail).is_err());
    }

    #[test]
    fn keeping_a_channel_on_conflict_is_idempotent() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c, OnConflict::Keep).unwrap();
        store.insert_channel(&c, OnConflict::Keep).unwrap();
        assert_eq!(store.list_channels(&s.server_id).unwrap().len(), 1);
    }

    #[test]
    fn keeping_a_member_on_conflict_is_idempotent() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let m = make_member(s.server_id);
        store.insert_member(&m, OnConflict::Keep).unwrap();
        store.insert_member(&m, OnConflict::Keep).unwrap();
        assert_eq!(store.list_members(&s.server_id).unwrap().len(), 1);
    }

    // -- Member avatar tests --

    #[test]
    fn member_avatar_set_get_clear_cycle() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let m = make_member(s.server_id);
        store.insert_member(&m, OnConflict::Fail).unwrap();

        // Initially no avatar
        assert!(store.get_member_avatar_key(&s.server_id, &m.fingerprint).unwrap().is_none());

        let hash = [0x11u8; 32];
        let key = [0x22u8; 32];
        store.update_member_avatar(&s.server_id, &m.fingerprint, &hash, &key).unwrap();

        let got_key = store.get_member_avatar_key(&s.server_id, &m.fingerprint).unwrap();
        assert_eq!(got_key.unwrap(), key);

        let member = store.get_member(&s.server_id, &m.fingerprint).unwrap();
        assert_eq!(member.avatar_hash.unwrap(), hash);

        store.clear_member_avatar(&s.server_id, &m.fingerprint).unwrap();
        assert!(store.get_member_avatar_key(&s.server_id, &m.fingerprint).unwrap().is_none());
    }

    #[test]
    fn update_member_name() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let m = make_member(s.server_id);
        store.insert_member(&m, OnConflict::Fail).unwrap();

        store.update_member_name(&s.server_id, &m.fingerprint, "new-name").unwrap();
        let got = store.get_member(&s.server_id, &m.fingerprint).unwrap();
        assert_eq!(got.display_name, "new-name");
    }

    // -- Rename error paths --

    // -- Read state tests --

    #[test]
    fn unread_counts_all_unread() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c, OnConflict::Fail).unwrap();
        let msg = make_message(c.channel_id, 1000, "hi");
        store.insert_message(&msg).unwrap();

        let counts = store.get_unread_counts(&s.server_id).unwrap();
        assert_eq!(counts.len(), 1);
        assert_eq!(counts[0].1, 1);
    }

    #[test]
    fn mark_read_clears_unread() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c, OnConflict::Fail).unwrap();
        let msg = make_message(c.channel_id, 1000, "hi");
        store.insert_message(&msg).unwrap();

        store.mark_channel_read(&c.channel_id, 1000).unwrap();
        let counts = store.get_unread_counts(&s.server_id).unwrap();
        assert_eq!(counts[0].1, 0);
    }

    #[test]
    fn new_message_after_read_shows_unread() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c, OnConflict::Fail).unwrap();

        let m1 = make_message(c.channel_id, 1000, "old");
        store.insert_message(&m1).unwrap();
        store.mark_channel_read(&c.channel_id, 1000).unwrap();

        let m2 = make_message(c.channel_id, 2000, "new");
        store.insert_message(&m2).unwrap();

        let counts = store.get_unread_counts(&s.server_id).unwrap();
        assert_eq!(counts[0].1, 1);
    }

    #[test]
    fn servers_with_unread() {
        let store = test_store();
        let s1 = make_server("has-unread");
        let s2 = make_server("all-read");
        store.insert_server(&s1, OnConflict::Fail).unwrap();
        store.insert_server(&s2, OnConflict::Fail).unwrap();

        let c1 = make_channel(s1.server_id, "ch", 0);
        let c2 = make_channel(s2.server_id, "ch", 0);
        store.insert_channel(&c1, OnConflict::Fail).unwrap();
        store.insert_channel(&c2, OnConflict::Fail).unwrap();

        store.insert_message(&make_message(c1.channel_id, 1000, "hi")).unwrap();
        store.insert_message(&make_message(c2.channel_id, 1000, "hi")).unwrap();

        store.mark_channel_read(&c2.channel_id, 1000).unwrap();

        let unread = store.servers_with_unread().unwrap();
        assert!(unread.contains(&s1.server_id));
        assert!(!unread.contains(&s2.server_id));
    }

    // -- Sync edge cases --

    #[test]
    fn sync_get_nonexistent_returns_none() {
        let store = test_store();
        assert!(store.sync_get("nonexistent").unwrap().is_none());
    }

    #[test]
    fn sync_set_equal_timestamp_rejected() {
        let store = test_store();
        store.sync_set("k", b"first", 100).unwrap();
        let applied = store.sync_set("k", b"second", 100).unwrap();
        assert!(!applied);
        let (value, _) = store.sync_get("k").unwrap().unwrap();
        assert_eq!(value.unwrap(), b"first");
    }

    #[test]
    fn get_messages_empty_channel() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s, OnConflict::Fail).unwrap();
        let c = make_channel(s.server_id, "empty", 0);
        store.insert_channel(&c, OnConflict::Fail).unwrap();
        assert!(store.get_messages(&c.channel_id, None, 10).unwrap().is_empty());
    }
}
