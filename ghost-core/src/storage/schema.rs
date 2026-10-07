use rusqlite::Connection;

use crate::crypto::MessageType;
use crate::error::{GhostError, Result};

pub fn initialize(conn: &Connection) -> Result<()> {
    let text = MessageType::Text as u8;

    // kt_state was keyed by relay URL; it is now keyed by relay key. The old rows
    // cannot be re-keyed offline, so the first fetch after upgrading starts a fresh
    // consistency chain, exactly as a new install does.
    if has_column(conn, "kt_state", "relay_url")? {
        conn.execute_batch("DROP TABLE kt_state;")
            .map_err(|e| GhostError::Database(format!("drop legacy kt_state: {e}")))?;
    }

    conn.execute_batch(&format!(
        "
        CREATE TABLE IF NOT EXISTS servers (
            server_id  BLOB    PRIMARY KEY,
            name       TEXT    NOT NULL,
            kind       TEXT    NOT NULL DEFAULT 'server' CHECK(kind IN ('server', 'group', 'dm')),
            creator_fp BLOB    NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS channels (
            channel_id BLOB    PRIMARY KEY,
            server_id  BLOB    NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
            name       TEXT    NOT NULL,
            kind       TEXT    NOT NULL CHECK(kind IN ('text', 'voice')),
            position   INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS members (
            server_id    BLOB    NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
            fingerprint  BLOB    NOT NULL,
            display_name TEXT    NOT NULL,
            role         TEXT    NOT NULL CHECK(role IN ('creator', 'member')),
            joined_at    INTEGER NOT NULL,
            avatar_hash  BLOB,
            avatar_key   BLOB,
            PRIMARY KEY (server_id, fingerprint)
        );

        CREATE TABLE IF NOT EXISTS messages (
            message_id   BLOB    PRIMARY KEY,
            channel_id   BLOB    NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
            sender_fp    BLOB    NOT NULL,
            message_type INTEGER NOT NULL,
            timestamp    INTEGER NOT NULL,
            received_at  INTEGER NOT NULL,
            content      BLOB    NOT NULL,
            expires_at   INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_messages_channel_recv ON messages(channel_id, received_at DESC);
        CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages(expires_at) WHERE expires_at IS NOT NULL;

        CREATE TABLE IF NOT EXISTS message_references (
            message_id    BLOB NOT NULL REFERENCES messages(message_id) ON DELETE CASCADE,
            referenced_id BLOB NOT NULL,
            PRIMARY KEY (message_id, referenced_id)
        );

        CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
            content,
            content='messages',
            content_rowid='rowid'
        );

        CREATE TRIGGER IF NOT EXISTS messages_fts_insert AFTER INSERT ON messages
        WHEN NEW.message_type = {text}
        BEGIN
            INSERT INTO messages_fts(rowid, content) VALUES (NEW.rowid, NEW.content);
        END;

        CREATE TRIGGER IF NOT EXISTS messages_fts_delete AFTER DELETE ON messages
        WHEN OLD.message_type = {text}
        BEGIN
            INSERT INTO messages_fts(messages_fts, rowid, content) VALUES ('delete', OLD.rowid, OLD.content);
        END;

        CREATE TRIGGER IF NOT EXISTS messages_fts_update_del BEFORE UPDATE ON messages
        WHEN OLD.message_type = {text}
        BEGIN
            INSERT INTO messages_fts(messages_fts, rowid, content) VALUES ('delete', OLD.rowid, OLD.content);
        END;

        CREATE TRIGGER IF NOT EXISTS messages_fts_update_ins AFTER UPDATE ON messages
        WHEN NEW.message_type = {text}
        BEGIN
            INSERT INTO messages_fts(rowid, content) VALUES (NEW.rowid, NEW.content);
        END;

        CREATE TABLE IF NOT EXISTS channel_read_state (
            channel_id   BLOB PRIMARY KEY REFERENCES channels(channel_id) ON DELETE CASCADE,
            last_read_ts INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS relay_state (
            mailbox_id    BLOB PRIMARY KEY,
            last_seen_seq INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS device_config (
            key   TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sync_state (
            key   TEXT PRIMARY KEY,
            value BLOB,
            ts    INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS idlog_cache (
            account_fp BLOB NOT NULL,
            seq        INTEGER NOT NULL,
            payload    BLOB NOT NULL,
            PRIMARY KEY (account_fp, seq)
        );

        CREATE TABLE IF NOT EXISTS idlog_state (
            account_fp      BLOB PRIMARY KEY,
            head_seq        INTEGER NOT NULL,
            head_hash       BLOB NOT NULL,
            master_vk       BLOB,
            home_relay_vk   BLOB,
            home_relay_ref  BLOB,
            home_set_at_seq INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS kt_state (
            relay_vk   BLOB PRIMARY KEY,
            tree_size  INTEGER NOT NULL,
            root_hash  BLOB NOT NULL,
            checkpoint BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS relays (
            relay_vk  BLOB PRIMARY KEY,
            ref_bytes BLOB NOT NULL,
            last_seen INTEGER NOT NULL
        );
        "
    ))
    .map_err(|e| GhostError::Database(format!("create tables: {e}")))?;

    add_column_if_missing(conn, "idlog_cache", "anchored", "INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(conn, "idlog_state", "home_relay_vk", "BLOB")?;
    add_column_if_missing(conn, "idlog_state", "home_relay_ref", "BLOB")?;
    add_column_if_missing(conn, "idlog_state", "home_set_at_seq", "INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(conn, "servers", "relay_vk", "BLOB")?;
    add_column_if_missing(conn, "servers", "location_generation", "INTEGER NOT NULL DEFAULT 0")?;

    Ok(())
}

fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| GhostError::Database(format!("table_info {table}: {e}")))?;
    let names: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| GhostError::Database(format!("table_info {table}: {e}")))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(names.iter().any(|name| name == column))
}

fn add_column_if_missing(conn: &Connection, table: &str, column: &str, decl: &str) -> Result<()> {
    if !has_column(conn, table, column)? {
        conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"), [])
            .map_err(|e| GhostError::Database(format!("add {table}.{column}: {e}")))?;
    }
    Ok(())
}
