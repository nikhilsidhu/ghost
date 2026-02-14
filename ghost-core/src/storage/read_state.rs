use std::collections::HashSet;

use crate::error::{GhostError, Result};

use super::{blob32, GhostStore};

impl GhostStore {
    pub fn mark_channel_read(&self, channel_id: &[u8; 32], ts: u64) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO channel_read_state (channel_id, last_read_ts) VALUES (?1, ?2)
                 ON CONFLICT(channel_id) DO UPDATE SET last_read_ts = excluded.last_read_ts",
                rusqlite::params![channel_id.as_slice(), ts],
            )
            .map_err(|e| GhostError::Database(format!("mark channel read: {e}")))?;
        Ok(())
    }

    /// Returns (channel_id, unread_count) for every channel in a group.
    pub fn get_unread_counts(&self, group_id: &[u8; 32]) -> Result<Vec<([u8; 32], u32)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT c.channel_id, COUNT(m.message_id)
                 FROM channels c
                 LEFT JOIN messages m
                   ON m.channel_id = c.channel_id
                   AND m.received_at > COALESCE(
                     (SELECT last_read_ts FROM channel_read_state WHERE channel_id = c.channel_id), 0
                   )
                 WHERE c.group_id = ?1
                 GROUP BY c.channel_id",
            )
            .map_err(|e| GhostError::Database(format!("prepare unread counts: {e}")))?;

        let rows = stmt
            .query_map([group_id.as_slice()], |row| {
                Ok((blob32(row, 0)?, row.get::<_, u32>(1)?))
            })
            .map_err(|e| GhostError::Database(format!("get unread counts: {e}")))?;

        let mut counts = Vec::new();
        for row in rows {
            counts.push(row.map_err(|e| GhostError::Database(format!("read unread row: {e}")))?);
        }
        Ok(counts)
    }

    /// Returns group_ids that have at least one unread message in any channel.
    pub fn groups_with_unread(&self) -> Result<HashSet<[u8; 32]>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT DISTINCT c.group_id
                 FROM channels c
                 JOIN messages m
                   ON m.channel_id = c.channel_id
                   AND m.received_at > COALESCE(
                     (SELECT last_read_ts FROM channel_read_state WHERE channel_id = c.channel_id), 0
                   )",
            )
            .map_err(|e| GhostError::Database(format!("prepare groups_with_unread: {e}")))?;

        let rows = stmt
            .query_map([], |row| blob32(row, 0))
            .map_err(|e| GhostError::Database(format!("groups_with_unread: {e}")))?;

        let mut ids = HashSet::new();
        for row in rows {
            ids.insert(row.map_err(|e| GhostError::Database(format!("read unread group: {e}")))?);
        }
        Ok(ids)
    }
}
