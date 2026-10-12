use crate::error::{GhostError, Result};

use crate::crypto::MessageType;

use super::{db, blob32, Delivery, GhostStore, StoredMessage};

/// The columns every message query selects, in the order `row_to_raw_message` reads.
const MESSAGE_COLUMNS: &str = "message_id, channel_id, sender_fp, message_type, timestamp, received_at, content, expires_at, delivery";

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
        delivery: row.get(8)?,
    })
}

impl GhostStore {
    /// Insert a message and its references in one transaction. Idempotent — relay
    /// re-deliveries are harmless.
    pub fn insert_message(&self, msg: &StoredMessage) -> Result<()> {
        self.insert_message_seen(msg, None)
    }

    /// Insert a message received at `seq` of `mailbox_id`, marking that blob seen in the
    /// same transaction: a restart never replays a blob whose key decrypting it spent.
    pub fn insert_message_seen(&self, msg: &StoredMessage, seen: Option<(&[u8; 32], u64)>) -> Result<()> {
        self.write_whole(|| self.insert_message_rows(msg, seen))
    }

    fn insert_message_rows(&self, msg: &StoredMessage, seen: Option<(&[u8; 32], u64)>) -> Result<()> {
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO messages (message_id, channel_id, sender_fp, message_type, timestamp, received_at, content, expires_at, delivery)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                msg.message_id.as_slice(),
                msg.channel_id.as_slice(),
                msg.sender_fp.as_slice(),
                msg.message_type,
                msg.timestamp,
                msg.received_at,
                msg.content,
                msg.expires_at,
                msg.delivery as u8,
            ],
        )
        .map_err(db("insert message"))?;

        // Skip references if message already existed
        if inserted > 0 {
            for ref_id in &msg.references {
                self.conn.execute(
                    "INSERT OR IGNORE INTO message_references (message_id, referenced_id) VALUES (?1, ?2)",
                    rusqlite::params![msg.message_id.as_slice(), ref_id.as_slice()],
                )
                .map_err(db("insert reference"))?;
            }
        }
        if let Some((mailbox_id, seq)) = seen {
            self.set_last_seen_seq(mailbox_id, seq)?;
        }
        Ok(())
    }

    /// How many messages are stored for a channel.
    pub fn count_messages(&self, channel_id: &[u8; 32]) -> Result<u32> {
        self.conn
            .query_row("SELECT COUNT(*) FROM messages WHERE channel_id = ?1", [channel_id.as_slice()], |row| row.get(0))
            .map_err(db("count messages"))
    }

    /// Fetch messages in a channel, newest first, with cursor-based pagination.
    pub fn get_messages(
        &self,
        channel_id: &[u8; 32],
        before_received_at: Option<u64>,
        limit: u32,
    ) -> Result<Vec<StoredMessage>> {
        let (sql, params): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match before_received_at {
            Some(ts) => (
                format!(
                    "SELECT {MESSAGE_COLUMNS} FROM messages WHERE channel_id = ?1 AND received_at < ?2
                     ORDER BY received_at DESC LIMIT ?3"
                ),
                vec![
                    Box::new(channel_id.to_vec()),
                    Box::new(ts),
                    Box::new(limit),
                ],
            ),
            None => (
                format!(
                    "SELECT {MESSAGE_COLUMNS} FROM messages WHERE channel_id = ?1
                     ORDER BY received_at DESC LIMIT ?2"
                ),
                vec![
                    Box::new(channel_id.to_vec()),
                    Box::new(limit),
                ],
            ),
        };

        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(db("prepare get messages"))?;

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();

        let rows = stmt
            .query_map(params_refs.as_slice(), row_to_raw_message)
            .map_err(db("get messages"))?;

        let mut messages = Vec::new();
        for row in rows {
            let raw = row.map_err(db("read message row"))?;
            let references = self.get_references(&raw.message_id)?;
            messages.push(raw.into_stored(references));
        }
        Ok(messages)
    }

    pub fn get_message(&self, message_id: &[u8; 32]) -> Result<StoredMessage> {
        let raw = self
            .conn
            .query_row(
                &format!("SELECT {MESSAGE_COLUMNS} FROM messages WHERE message_id = ?1"),
                [message_id.as_slice()],
                row_to_raw_message,
            )
            .map_err(db("get message"))?;

        let references = self.get_references(&raw.message_id)?;
        Ok(raw.into_stored(references))
    }

    /// Record where a message stands with the relay.
    pub fn set_delivery(&self, message_id: &[u8; 32], delivery: Delivery) -> Result<()> {
        self.conn
            .execute(
                "UPDATE messages SET delivery = ?1 WHERE message_id = ?2",
                rusqlite::params![delivery as u8, message_id.as_slice()],
            )
            .map_err(db("set delivery"))?;
        Ok(())
    }

    /// Mark a message handed to a connection as sent, unless the relay's answer was
    /// recorded first: an acknowledgement can be taken in before the hand-over returns.
    pub fn mark_sent(&self, message_id: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(
                "UPDATE messages SET delivery = ?1 WHERE message_id = ?2 AND delivery = ?3",
                rusqlite::params![Delivery::Sent as u8, message_id.as_slice(), Delivery::Pending as u8],
            )
            .map_err(db("mark sent"))?;
        Ok(())
    }

    /// Messages handed to a connection that no longer exists go back to waiting for one.
    pub fn reset_in_flight(&self) -> Result<()> {
        self.conn
            .execute(
                "UPDATE messages SET delivery = ?1 WHERE delivery = ?2",
                rusqlite::params![Delivery::Pending as u8, Delivery::Sent as u8],
            )
            .map_err(db("reset in-flight messages"))?;
        Ok(())
    }

    /// This device's messages in the given channels that wait for a connection, oldest
    /// first, for sending again in order.
    pub fn pending_messages(&self, channel_ids: &[[u8; 32]]) -> Result<Vec<StoredMessage>> {
        let mut stmt = self
            .conn
            .prepare(&format!(
                "SELECT {MESSAGE_COLUMNS} FROM messages WHERE channel_id = ?1 AND delivery = ?2 ORDER BY received_at"
            ))
            .map_err(db("prepare pending messages"))?;
        let mut messages = Vec::new();
        for channel_id in channel_ids {
            let rows = stmt
                .query_map(rusqlite::params![channel_id.as_slice(), Delivery::Pending as u8], row_to_raw_message)
                .map_err(db("pending messages"))?;
            for row in rows {
                let raw = row.map_err(db("read pending row"))?;
                let references = self.get_references(&raw.message_id)?;
                messages.push(raw.into_stored(references));
            }
        }
        messages.sort_by_key(|m| m.received_at);
        Ok(messages)
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
                "SELECT m.message_id, m.channel_id, m.sender_fp, m.message_type, m.timestamp, m.received_at, m.content, m.expires_at, m.delivery
                 FROM messages m
                 JOIN messages_fts fts ON m.rowid = fts.rowid
                 WHERE m.channel_id = ?1 AND messages_fts MATCH ?2
                 ORDER BY m.received_at DESC",
            )
            .map_err(db("prepare search"))?;

        let rows = stmt
            .query_map(
                rusqlite::params![channel_id.as_slice(), query],
                row_to_raw_message,
            )
            .map_err(db("search messages"))?;

        let mut messages = Vec::new();
        for row in rows {
            let raw = row.map_err(db("read search row"))?;
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
            .map_err(db("delete message"))?;

        if updated == 0 {
            return Err(GhostError::Database("message not found".into()));
        }
        Ok(())
    }

    fn get_references(&self, message_id: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        let mut stmt = self
            .conn
            .prepare("SELECT referenced_id FROM message_references WHERE message_id = ?1")
            .map_err(db("prepare refs"))?;

        let rows = stmt
            .query_map([message_id.as_slice()], |row| blob32(row, 0))
            .map_err(db("get refs"))?;

        let mut refs = Vec::new();
        for row in rows {
            refs.push(row.map_err(db("read ref"))?);
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
    delivery: u8,
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
            delivery: Delivery::from_u8(self.delivery),
        }
    }
}
