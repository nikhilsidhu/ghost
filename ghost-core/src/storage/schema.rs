use rusqlite::Connection;

use super::db;
use crate::crypto::MessageType;
use crate::error::{GhostError, Result};

pub fn initialize(conn: &Connection) -> Result<()> {
    let text = MessageType::Text as u8;

    // kt_state was keyed by relay URL; it is now keyed by relay key. The old rows
    // cannot be re-keyed offline, so the first fetch after upgrading starts a fresh
    // consistency chain, exactly as a new install does.
    if has_column(conn, "kt_state", "relay_url")? {
        conn.execute_batch("DROP TABLE kt_state;")
            .map_err(db("drop legacy kt_state"))?;
    }

    conn.execute_batch(&format!(
        "
        CREATE TABLE IF NOT EXISTS servers (
            server_id  BLOB    PRIMARY KEY,
            name       TEXT    NOT NULL,
            kind       TEXT    NOT NULL DEFAULT 'server' CHECK(kind IN ('server', 'group', 'dm')),
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS channels (
            channel_id BLOB    PRIMARY KEY,
            server_id  BLOB    NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
            name       TEXT    NOT NULL,
            kind       TEXT    NOT NULL CHECK(kind IN ('text', 'voice')),
            position   INTEGER NOT NULL
        );

        -- The group epoch this device joined a channel's group at: messages sealed
        -- before it were never for this device.
        CREATE TABLE IF NOT EXISTS group_joins (
            channel_id   BLOB    PRIMARY KEY REFERENCES channels(channel_id) ON DELETE CASCADE,
            joined_epoch INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS members (
            server_id    BLOB    NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
            fingerprint  BLOB    NOT NULL,
            display_name TEXT    NOT NULL,
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

        -- The server group's policy and members from each epoch where they changed,
        -- against which private channel commits naming that epoch are checked.
        -- Display names of a server's roles, which the policy in group state identifies
        -- only by number.
        CREATE TABLE IF NOT EXISTS role_names (
            server_id BLOB    NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
            role_id   INTEGER NOT NULL,
            name      TEXT    NOT NULL,
            PRIMARY KEY (server_id, role_id)
        );

        -- Names of members who left or were removed, for showing whom a server keeps out.
        CREATE TABLE IF NOT EXISTS former_members (
            server_id    BLOB    NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
            fingerprint  BLOB    NOT NULL,
            display_name TEXT    NOT NULL,
            PRIMARY KEY (server_id, fingerprint)
        );

        CREATE TABLE IF NOT EXISTS server_views (
            server_id BLOB    NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
            epoch     INTEGER NOT NULL,
            view      BLOB    NOT NULL,
            PRIMARY KEY (server_id, epoch)
        );

        CREATE TABLE IF NOT EXISTS account_key_seeds (
            generation INTEGER PRIMARY KEY,
            seed       BLOB    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS pending_revocations (
            device_vk    BLOB    PRIMARY KEY,
            requested_at INTEGER NOT NULL,
            -- Why the home last refused it, when it refused for a reason a retry does
            -- not change by itself.
            refused      TEXT
        );

        CREATE TABLE IF NOT EXISTS former_homes_told (
            relay_vk     BLOB    NOT NULL,
            ended_at_seq INTEGER NOT NULL,
            PRIMARY KEY (relay_vk, ended_at_seq)
        );

        CREATE TABLE IF NOT EXISTS sync_cursors (
            device_vk BLOB    PRIMARY KEY,
            high_seq  INTEGER NOT NULL,
            window    INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS relay_mailbox_state (
            relay_url     TEXT    NOT NULL,
            mailbox_id    BLOB    NOT NULL,
            last_seen_seq INTEGER NOT NULL,
            PRIMARY KEY (relay_url, mailbox_id)
        );

        CREATE TABLE IF NOT EXISTS replaced_history (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            from_seq     INTEGER NOT NULL,
            discarded    INTEGER NOT NULL,
            lost_devices TEXT    NOT NULL,
            at           INTEGER NOT NULL
        );

        -- Private channels deleted while this device held them, by mailbox: discovery
        -- skips them, and the deleting device retries the relay-side deletion it owes.
        CREATE TABLE IF NOT EXISTS deleted_channels (
            mailbox_id          BLOB    PRIMARY KEY,
            server_id           BLOB    NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
            relay_deletion_owed INTEGER NOT NULL
        );

        -- Servers this device made whose group state no relay holds yet.
        CREATE TABLE IF NOT EXISTS unpublished_servers (
            server_id BLOB PRIMARY KEY REFERENCES servers(server_id) ON DELETE CASCADE
        );

        -- Servers this device joined by invite and waits for the current state of: its
        -- request's sequence once the relay took it, and the last change it saw since.
        CREATE TABLE IF NOT EXISTS server_state_waits (
            server_id       BLOB    PRIMARY KEY REFERENCES servers(server_id) ON DELETE CASCADE,
            request_seq     INTEGER,
            last_change_seq INTEGER NOT NULL
        );

        -- Server moves this device was shown and could not follow yet; tried again at
        -- the account check.
        CREATE TABLE IF NOT EXISTS shown_moves (
            server_id BLOB PRIMARY KEY REFERENCES servers(server_id) ON DELETE CASCADE,
            record    BLOB NOT NULL
        );

        -- Parts of this account's profile (its name, its avatar) a server has not been
        -- told yet; told as they are then when its mailbox next connects.
        CREATE TABLE IF NOT EXISTS profile_owed (
            server_id BLOB    NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
            part      INTEGER NOT NULL,
            PRIMARY KEY (server_id, part)
        );
        "
    ))
    .map_err(db("create tables"))?;

    add_column_if_missing(conn, "idlog_cache", "anchored", "INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(conn, "idlog_state", "home_relay_vk", "BLOB")?;
    add_column_if_missing(conn, "idlog_state", "home_relay_ref", "BLOB")?;
    add_column_if_missing(conn, "idlog_state", "home_set_at_seq", "INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(conn, "servers", "relay_vk", "BLOB")?;
    add_column_if_missing(conn, "servers", "location_generation", "INTEGER NOT NULL DEFAULT 0")?;
    // Set on a device whose account was removed from the server: it stays, read-only.
    add_column_if_missing(conn, "servers", "removed_at", "INTEGER")?;
    add_column_if_missing(conn, "servers", "removed_by", "BLOB")?;
    // A server whose relay accepted a change the rules forbid: this device holds its copy
    // from before it until the person accepts the relay's state or leaves.
    add_column_if_missing(conn, "servers", "halted_at", "INTEGER")?;
    add_column_if_missing(conn, "servers", "halted_reason", "TEXT")?;
    // Where this device's own messages stand with the relay (see `Delivery`).
    add_column_if_missing(conn, "messages", "delivery", "INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_missing(conn, "pending_revocations", "refused", "TEXT")?;
    // Servers once named their creator and members a creator/member role; the server
    // group's policy names the owner and roles now.
    drop_column_if_present(conn, "servers", "creator_fp")?;
    drop_column_if_present(conn, "members", "role")?;

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

/// Drop a column an earlier schema had; SQLite rewrites the table behind the scenes.
fn drop_column_if_present(conn: &Connection, table: &str, column: &str) -> Result<()> {
    if has_column(conn, table, column)? {
        conn.execute(&format!("ALTER TABLE {table} DROP COLUMN {column}"), [])
            .map_err(|e| GhostError::Database(format!("drop {table}.{column}: {e}")))?;
    }
    Ok(())
}

fn add_column_if_missing(conn: &Connection, table: &str, column: &str, decl: &str) -> Result<()> {
    if !has_column(conn, table, column)? {
        conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"), [])
            .map_err(|e| GhostError::Database(format!("add {table}.{column}: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod migration_tests {
    use super::*;

    #[test]
    fn a_role_column_from_an_earlier_schema_is_dropped() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE members (
                server_id BLOB NOT NULL,
                fingerprint BLOB NOT NULL,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('creator', 'member')),
                joined_at INTEGER NOT NULL
            );
            INSERT INTO members VALUES (x'01', x'02', 'ann', 'creator', 1);",
        )
        .unwrap();
        drop_column_if_present(&conn, "members", "role").unwrap();
        assert!(!has_column(&conn, "members", "role").unwrap());
        let name: String = conn.query_row("SELECT display_name FROM members", [], |row| row.get(0)).unwrap();
        assert_eq!(name, "ann");
    }
}
