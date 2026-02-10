use rusqlite::Connection;

use crate::crypto::{MSG_TYPE_REPLY, MSG_TYPE_TEXT};
use crate::error::{GhostError, Result};

const CURRENT_VERSION: u32 = 1;

pub fn initialize(conn: &Connection) -> Result<()> {
    let version = get_version(conn)?;
    if version == 0 {
        create_tables(conn)?;
        set_version(conn, CURRENT_VERSION)?;
    } else if version < CURRENT_VERSION {
        migrate(conn, version)?;
    }
    Ok(())
}

fn get_version(conn: &Connection) -> Result<u32> {
    // schema_version table may not exist yet
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);"
    )
    .map_err(|e| GhostError::Database(format!("create schema_version: {e}")))?;

    let count: u32 = conn
        .query_row("SELECT COUNT(*) FROM schema_version", [], |row| row.get(0))
        .map_err(|e| GhostError::Database(format!("query schema_version: {e}")))?;

    if count == 0 {
        return Ok(0);
    }

    conn.query_row("SELECT version FROM schema_version", [], |row| row.get(0))
        .map_err(|e| GhostError::Database(format!("read version: {e}")))
}

fn set_version(conn: &Connection, version: u32) -> Result<()> {
    conn.execute("DELETE FROM schema_version", [])
        .map_err(|e| GhostError::Database(format!("clear version: {e}")))?;
    conn.execute("INSERT INTO schema_version (version) VALUES (?1)", [version])
        .map_err(|e| GhostError::Database(format!("set version: {e}")))?;
    Ok(())
}

fn create_tables(conn: &Connection) -> Result<()> {
    let text = MSG_TYPE_TEXT;
    let reply = MSG_TYPE_REPLY;

    conn.execute_batch(&format!(
        "
        CREATE TABLE groups (
            group_id   BLOB    PRIMARY KEY,
            name       TEXT    NOT NULL,
            creator_fp BLOB    NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE channels (
            channel_id BLOB    PRIMARY KEY,
            group_id   BLOB    NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
            name       TEXT    NOT NULL,
            kind       TEXT    NOT NULL CHECK(kind IN ('text', 'voice')),
            position   INTEGER NOT NULL
        );

        CREATE TABLE members (
            group_id     BLOB    NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
            fingerprint  BLOB    NOT NULL,
            display_name TEXT    NOT NULL,
            role         TEXT    NOT NULL CHECK(role IN ('creator', 'member')),
            joined_at    INTEGER NOT NULL,
            PRIMARY KEY (group_id, fingerprint)
        );

        CREATE TABLE messages (
            message_id   BLOB    PRIMARY KEY,
            channel_id   BLOB    NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
            sender_fp    BLOB    NOT NULL,
            message_type INTEGER NOT NULL,
            timestamp    INTEGER NOT NULL,
            content      BLOB    NOT NULL,
            expires_at   INTEGER
        );

        CREATE INDEX idx_messages_channel_ts ON messages(channel_id, timestamp DESC);
        CREATE INDEX idx_messages_expires ON messages(expires_at) WHERE expires_at IS NOT NULL;

        CREATE TABLE message_references (
            message_id    BLOB NOT NULL REFERENCES messages(message_id) ON DELETE CASCADE,
            referenced_id BLOB NOT NULL,
            PRIMARY KEY (message_id, referenced_id)
        );

        CREATE VIRTUAL TABLE messages_fts USING fts5(
            content,
            content='messages',
            content_rowid='rowid'
        );

        -- Keep FTS index in sync for searchable message types
        CREATE TRIGGER messages_fts_insert AFTER INSERT ON messages
        WHEN NEW.message_type IN ({text}, {reply})
        BEGIN
            INSERT INTO messages_fts(rowid, content) VALUES (NEW.rowid, NEW.content);
        END;

        CREATE TRIGGER messages_fts_delete AFTER DELETE ON messages
        WHEN OLD.message_type IN ({text}, {reply})
        BEGIN
            INSERT INTO messages_fts(messages_fts, rowid, content) VALUES ('delete', OLD.rowid, OLD.content);
        END;

        -- On UPDATE, remove old FTS entry if it was searchable
        CREATE TRIGGER messages_fts_update_del BEFORE UPDATE ON messages
        WHEN OLD.message_type IN ({text}, {reply})
        BEGIN
            INSERT INTO messages_fts(messages_fts, rowid, content) VALUES ('delete', OLD.rowid, OLD.content);
        END;

        -- On UPDATE, add new FTS entry if the new content is searchable
        CREATE TRIGGER messages_fts_update_ins AFTER UPDATE ON messages
        WHEN NEW.message_type IN ({text}, {reply})
        BEGIN
            INSERT INTO messages_fts(rowid, content) VALUES (NEW.rowid, NEW.content);
        END;
        "
    ))
    .map_err(|e| GhostError::Database(format!("create tables: {e}")))?;

    Ok(())
}

// Run sequential migrations from `from_version` to CURRENT_VERSION.
#[allow(unused)]
fn migrate(_conn: &Connection, from_version: u32) -> Result<()> {
    // Future migrations go here as match arms:
    //   1 => { migrate_v1_to_v2(conn)?; }
    //   2 => { migrate_v2_to_v3(conn)?; }
    // For now, no migrations exist — any unknown version is an error.
    Err(GhostError::Database(format!(
        "no migration from version {from_version}"
    )))
}
