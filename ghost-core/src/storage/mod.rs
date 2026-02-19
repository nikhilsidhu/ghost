pub mod channels;
pub mod servers;
pub mod members;
pub mod messages;
pub mod pins;
pub mod read_state;
pub mod relay_state;
mod schema;

use std::path::Path;

use rusqlite::Connection;

use rusqlite::types::Type;

use crate::crypto::{derive_key, DB_KEY_DERIVE_LABEL};
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
    /// Open (or create) an encrypted database at `path`, keyed from the identity seed.
    pub fn open(seed: &[u8; 32], path: &Path) -> Result<Self> {
        let db_key = derive_key(seed, DB_KEY_DERIVE_LABEL)?;

        let conn =
            Connection::open(path).map_err(|e| GhostError::Database(format!("open: {e}")))?;

        // Unlock the encrypted database
        conn.pragma_update(None, "key", format!("x'{}'", hex::encode(db_key)))
            .map_err(|e| GhostError::Database(format!("set key: {e}")))?;

        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| GhostError::Database(format!("enable foreign keys: {e}")))?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| GhostError::Database(format!("set WAL: {e}")))?;

        schema::initialize(&conn)?;

        Ok(Self { conn })
    }

    /// Open an in-memory encrypted database (useful for testing).
    pub fn open_in_memory(seed: &[u8; 32]) -> Result<Self> {
        let db_key = derive_key(seed, DB_KEY_DERIVE_LABEL)?;

        let conn = Connection::open_in_memory()
            .map_err(|e| GhostError::Database(format!("open in-memory: {e}")))?;

        conn.pragma_update(None, "key", format!("x'{}'", hex::encode(db_key)))
            .map_err(|e| GhostError::Database(format!("set key: {e}")))?;

        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| GhostError::Database(format!("enable foreign keys: {e}")))?;

        schema::initialize(&conn)?;

        Ok(Self { conn })
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ServerKind {
    Server,
    Dm,
}

impl ServerKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ServerKind::Server => "server",
            ServerKind::Dm => "dm",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "server" => Ok(ServerKind::Server),
            "dm" => Ok(ServerKind::Dm),
            other => Err(GhostError::Database(format!("unknown server kind: {other}"))),
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            ServerKind::Server => 0,
            ServerKind::Dm => 1,
        }
    }

    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(ServerKind::Server),
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
    pub creator_fp: [u8; 32],
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemberRole {
    Creator,
    Member,
}

impl MemberRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemberRole::Creator => "creator",
            MemberRole::Member => "member",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "creator" => Ok(MemberRole::Creator),
            "member" => Ok(MemberRole::Member),
            other => Err(GhostError::Database(format!("unknown role: {other}"))),
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            MemberRole::Creator => 0,
            MemberRole::Member => 1,
        }
    }

    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(MemberRole::Creator),
            1 => Ok(MemberRole::Member),
            _ => Err(GhostError::Format(format!("unknown role byte: {b}"))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Member {
    pub server_id: [u8; 32],
    pub fingerprint: [u8; 32],
    pub display_name: String,
    pub role: MemberRole,
    pub joined_at: u64,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MessageType;

    fn test_store() -> GhostStore {
        let seed = [0xABu8; 32];
        GhostStore::open_in_memory(&seed).unwrap()
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
            creator_fp: rand_id(),
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

    fn make_member(server_id: [u8; 32], role: MemberRole) -> Member {
        Member {
            server_id,
            fingerprint: rand_id(),
            display_name: "user".to_string(),
            role,
            joined_at: 2000,
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
        }
    }

    // -- Server tests --

    #[test]
    fn server_insert_get_list() {
        let store = test_store();
        let s = make_server("test-server");
        store.insert_server(&s).unwrap();

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
        store.insert_server(&s).unwrap();
        store.rename_server(&s.server_id, "new-name").unwrap();

        let got = store.get_server(&s.server_id).unwrap();
        assert_eq!(got.name, "new-name");
    }

    // -- Channel tests --

    #[test]
    fn channel_insert_list_by_server() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s).unwrap();

        let c1 = make_channel(s.server_id, "general", 0);
        let c2 = make_channel(s.server_id, "random", 1);
        store.insert_channel(&c1).unwrap();
        store.insert_channel(&c2).unwrap();

        let channels = store.list_channels(&s.server_id).unwrap();
        assert_eq!(channels.len(), 2);
        assert_eq!(channels[0].name, "general");
        assert_eq!(channels[1].name, "random");
    }

    #[test]
    fn channel_rename() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s).unwrap();
        let c = make_channel(s.server_id, "old", 0);
        store.insert_channel(&c).unwrap();

        store.rename_channel(&c.channel_id, "new").unwrap();
        let got = store.get_channel(&c.channel_id).unwrap();
        assert_eq!(got.name, "new");
    }

    // -- Member tests --

    #[test]
    fn member_insert_list_remove() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s).unwrap();

        let m = make_member(s.server_id, MemberRole::Creator);
        store.insert_member(&m).unwrap();

        let members = store.list_members(&s.server_id).unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].role, MemberRole::Creator);

        store.remove_member(&s.server_id, &m.fingerprint).unwrap();
        let members = store.list_members(&s.server_id).unwrap();
        assert_eq!(members.len(), 0);
    }

    // -- Message tests --

    #[test]
    fn message_insert_get_paginate() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c).unwrap();

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
        store.insert_server(&s).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c).unwrap();

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
        store.insert_server(&s).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c).unwrap();

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
        store.insert_server(&s).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c).unwrap();

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
        store.insert_server(&s).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c).unwrap();

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
        store.insert_server(&s).unwrap();

        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c).unwrap();

        let m = make_member(s.server_id, MemberRole::Member);
        store.insert_member(&m).unwrap();

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
        store.insert_server(&s).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c).unwrap();

        let msg = make_message(c.channel_id, 1000, "hi");
        store.insert_message(&msg).unwrap();

        store.delete_channel(&c.channel_id).unwrap();
        assert!(store.get_message(&msg.message_id).is_err());
    }

    #[test]
    fn remove_member_keeps_messages() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c).unwrap();

        let m = make_member(s.server_id, MemberRole::Member);
        store.insert_member(&m).unwrap();

        let mut msg = make_message(c.channel_id, 1000, "hi");
        msg.sender_fp = m.fingerprint;
        store.insert_message(&msg).unwrap();

        store.remove_member(&s.server_id, &m.fingerprint).unwrap();

        // Message still exists after member removal
        let got = store.get_message(&msg.message_id).unwrap();
        assert_eq!(got.sender_fp, m.fingerprint);
    }

    // -- Pin tests --

    #[test]
    fn pin_unpin_server() {
        let store = test_store();
        let s = make_server("pinnable");
        store.insert_server(&s).unwrap();

        store.pin_server(&s.server_id, 5000).unwrap();
        assert!(store.is_pinned(&s.server_id).unwrap());

        let pins = store.list_pinned_server_ids().unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0], s.server_id);

        store.unpin_server(&s.server_id).unwrap();
        assert!(!store.is_pinned(&s.server_id).unwrap());
        assert!(store.list_pinned_server_ids().unwrap().is_empty());
    }

    #[test]
    fn pin_cascades_on_server_delete() {
        let store = test_store();
        let s = make_server("temp");
        store.insert_server(&s).unwrap();
        store.pin_server(&s.server_id, 5000).unwrap();
        store.delete_server(&s.server_id).unwrap();
        assert!(store.list_pinned_server_ids().unwrap().is_empty());
    }

    // -- Encrypted DB tests --

    #[test]
    fn encrypted_db_not_plain_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let seed = [0xABu8; 32];

        {
            let store = GhostStore::open(&seed, &path).unwrap();
            let s = make_server("grp");
            store.insert_server(&s).unwrap();
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
        let seed = [0xABu8; 32];
        let server_id;

        {
            let store = GhostStore::open(&seed, &path).unwrap();
            let s = make_server("survivors");
            server_id = s.server_id;
            store.insert_server(&s).unwrap();
        }

        // Reopen with same seed, data should be there
        let store = GhostStore::open(&seed, &path).unwrap();
        let got = store.get_server(&server_id).unwrap();
        assert_eq!(got.name, "survivors");
    }

    // -- Error path tests --

    #[test]
    fn get_nonexistent_returns_error() {
        let store = test_store();
        let fake = rand_id();

        assert!(store.get_server(&fake).is_err());
        assert!(store.get_channel(&fake).is_err());
        assert!(store.get_message(&fake).is_err());
        assert!(store.get_member(&fake, &fake).is_err());
        assert!(store.delete_message(&fake).is_err());
    }

    // -- Transaction tests --

    #[test]
    fn duplicate_references_deduped() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c).unwrap();

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
        store.insert_server(&s).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c).unwrap();

        let msg = make_message(c.channel_id, 1000, "hello");
        store.insert_message(&msg).unwrap();
        // Re-inserting the same message_id succeeds silently
        store.insert_message(&msg).unwrap();

        let got = store.get_message(&msg.message_id).unwrap();
        assert_eq!(got.content, b"hello");
    }

    // -- FTS edge cases --

    #[test]
    fn fts_special_characters_dont_crash() {
        let store = test_store();
        let s = make_server("grp");
        store.insert_server(&s).unwrap();
        let c = make_channel(s.server_id, "general", 0);
        store.insert_channel(&c).unwrap();

        let m = make_message(c.channel_id, 1000, "normal message");
        store.insert_message(&m).unwrap();

        // These are valid FTS5 syntax — should not panic
        let _ = store.search_messages(&c.channel_id, "normal*");
        let _ = store.search_messages(&c.channel_id, "\"normal message\"");
        // Unbalanced quote — FTS5 may error, but must not panic
        let _ = store.search_messages(&c.channel_id, "\"unclosed");
        let _ = store.search_messages(&c.channel_id, "OR AND NOT");
    }
}
