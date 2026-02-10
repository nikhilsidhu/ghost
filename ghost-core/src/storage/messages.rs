use crate::error::{GhostError, Result};

use crate::crypto::MessageType;

use super::{blob32, GhostStore, StoredMessage};

fn row_to_raw_message(row: &rusqlite::Row) -> rusqlite::Result<RawMessage> {
    Ok(RawMessage {
        message_id: blob32(row, 0)?,
        channel_id: blob32(row, 1)?,
        sender_fp: blob32(row, 2)?,
        message_type: row.get(3)?,
        timestamp: row.get(4)?,
        received_at: row.get(5)?,
        content: row.get(6)?,
        expires_at: row.get(7)?,
    })
}

impl GhostStore {
    /// Insert a message and its references atomically. FTS index is updated via trigger.
    pub fn insert_message(&self, msg: &StoredMessage) -> Result<()> {
        let tx = self.conn.unchecked_transaction()
            .map_err(|e| GhostError::Database(format!("begin transaction: {e}")))?;

        tx.execute(
            "INSERT INTO messages (message_id, channel_id, sender_fp, message_type, timestamp, received_at, content, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                msg.message_id.as_slice(),
                msg.channel_id.as_slice(),
                msg.sender_fp.as_slice(),
                msg.message_type,
                msg.timestamp,
                msg.received_at,
                msg.content,
                msg.expires_at,
            ],
        )
        .map_err(|e| GhostError::Database(format!("insert message: {e}")))?;

        for ref_id in &msg.references {
            tx.execute(
                "INSERT INTO message_references (message_id, referenced_id) VALUES (?1, ?2)",
                rusqlite::params![msg.message_id.as_slice(), ref_id.as_slice()],
            )
            .map_err(|e| GhostError::Database(format!("insert reference: {e}")))?;
        }

        tx.commit()
            .map_err(|e| GhostError::Database(format!("commit message: {e}")))?;
        Ok(())
    }

    /// Fetch messages in a channel, newest first, with cursor-based pagination.
    pub fn get_messages(
        &self,
        channel_id: &[u8; 32],
        before_received_at: Option<u64>,
        limit: u32,
    ) -> Result<Vec<StoredMessage>> {
        let (sql, params): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match before_received_at {
            Some(ts) => (
                "SELECT message_id, channel_id, sender_fp, message_type, timestamp, received_at, content, expires_at
                 FROM messages WHERE channel_id = ?1 AND received_at < ?2
                 ORDER BY received_at DESC LIMIT ?3",
                vec![
                    Box::new(channel_id.to_vec()),
                    Box::new(ts),
                    Box::new(limit),
                ],
            ),
            None => (
                "SELECT message_id, channel_id, sender_fp, message_type, timestamp, received_at, content, expires_at
                 FROM messages WHERE channel_id = ?1
                 ORDER BY received_at DESC LIMIT ?2",
                vec![
                    Box::new(channel_id.to_vec()),
                    Box::new(limit),
                ],
            ),
        };

        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| GhostError::Database(format!("prepare get messages: {e}")))?;

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();

        let rows = stmt
            .query_map(params_refs.as_slice(), row_to_raw_message)
            .map_err(|e| GhostError::Database(format!("get messages: {e}")))?;

        let mut messages = Vec::new();
        for row in rows {
            let raw = row.map_err(|e| GhostError::Database(format!("read message row: {e}")))?;
            let references = self.get_references(&raw.message_id)?;
            messages.push(raw.into_stored(references));
        }
        Ok(messages)
    }

    pub fn get_message(&self, message_id: &[u8; 32]) -> Result<StoredMessage> {
        let raw = self
            .conn
            .query_row(
                "SELECT message_id, channel_id, sender_fp, message_type, timestamp, received_at, content, expires_at
                 FROM messages WHERE message_id = ?1",
                [message_id.as_slice()],
                row_to_raw_message,
            )
            .map_err(|e| GhostError::Database(format!("get message: {e}")))?;

        let references = self.get_references(&raw.message_id)?;
        Ok(raw.into_stored(references))
    }

    /// Full-text search across messages in a channel.
    pub fn search_messages(
        &self,
        channel_id: &[u8; 32],
        query: &str,
    ) -> Result<Vec<StoredMessage>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT m.message_id, m.channel_id, m.sender_fp, m.message_type, m.timestamp, m.received_at, m.content, m.expires_at
                 FROM messages m
                 JOIN messages_fts fts ON m.rowid = fts.rowid
                 WHERE m.channel_id = ?1 AND messages_fts MATCH ?2
                 ORDER BY m.received_at DESC",
            )
            .map_err(|e| GhostError::Database(format!("prepare search: {e}")))?;

        let rows = stmt
            .query_map(
                rusqlite::params![channel_id.as_slice(), query],
                row_to_raw_message,
            )
            .map_err(|e| GhostError::Database(format!("search messages: {e}")))?;

        let mut messages = Vec::new();
        for row in rows {
            let raw = row.map_err(|e| GhostError::Database(format!("read search row: {e}")))?;
            let references = self.get_references(&raw.message_id)?;
            messages.push(raw.into_stored(references));
        }
        Ok(messages)
    }

    /// Tombstone a message — clear content but keep the row so references still resolve.
    pub fn delete_message(&self, message_id: &[u8; 32]) -> Result<()> {
        let updated = self
            .conn
            .execute(
                "UPDATE messages SET content = X'', message_type = ?1 WHERE message_id = ?2",
                rusqlite::params![MessageType::Delete as u8, message_id.as_slice()],
            )
            .map_err(|e| GhostError::Database(format!("delete message: {e}")))?;

        if updated == 0 {
            return Err(GhostError::Database("message not found".into()));
        }
        Ok(())
    }

    fn get_references(&self, message_id: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        let mut stmt = self
            .conn
            .prepare("SELECT referenced_id FROM message_references WHERE message_id = ?1")
            .map_err(|e| GhostError::Database(format!("prepare refs: {e}")))?;

        let rows = stmt
            .query_map([message_id.as_slice()], |row| blob32(row, 0))
            .map_err(|e| GhostError::Database(format!("get refs: {e}")))?;

        let mut refs = Vec::new();
        for row in rows {
            refs.push(row.map_err(|e| GhostError::Database(format!("read ref: {e}")))?);
        }
        Ok(refs)
    }
}

struct RawMessage {
    message_id: [u8; 32],
    channel_id: [u8; 32],
    sender_fp: [u8; 32],
    message_type: u8,
    timestamp: u64,
    received_at: u64,
    content: Vec<u8>,
    expires_at: Option<u64>,
}

impl RawMessage {
    fn into_stored(self, references: Vec<[u8; 32]>) -> StoredMessage {
        StoredMessage {
            message_id: self.message_id,
            channel_id: self.channel_id,
            sender_fp: self.sender_fp,
            message_type: self.message_type,
            timestamp: self.timestamp,
            received_at: self.received_at,
            content: self.content,
            expires_at: self.expires_at,
            references,
        }
    }
}
