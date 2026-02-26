use crate::error::{GhostError, Result};

use super::{blob32, Channel, ChannelKind, GhostStore};

impl GhostStore {
    pub fn insert_channel(&self, channel: &Channel) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO channels (channel_id, server_id, name, kind, position) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    channel.channel_id.as_slice(),
                    channel.server_id.as_slice(),
                    channel.name,
                    channel.kind.as_str(),
                    channel.position,
                ],
            )
            .map_err(|e| GhostError::Database(format!("insert channel: {e}")))?;
        Ok(())
    }

    pub fn insert_channel_if_not_exists(&self, channel: &Channel) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO channels (channel_id, server_id, name, kind, position) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    channel.channel_id.as_slice(),
                    channel.server_id.as_slice(),
                    channel.name,
                    channel.kind.as_str(),
                    channel.position,
                ],
            )
            .map_err(|e| GhostError::Database(format!("insert channel if not exists: {e}")))?;
        Ok(())
    }

    pub fn get_channel(&self, channel_id: &[u8; 32]) -> Result<Channel> {
        self.conn
            .query_row(
                "SELECT channel_id, server_id, name, kind, position FROM channels WHERE channel_id = ?1",
                [channel_id.as_slice()],
                |row| {
                    Ok(RawChannel {
                        channel_id: blob32(row, 0)?,
                        server_id: blob32(row, 1)?,
                        name: row.get(2)?,
                        kind_str: row.get(3)?,
                        position: row.get(4)?,
                    })
                },
            )
            .map_err(|e| GhostError::Database(format!("get channel: {e}")))
            .and_then(|r| r.into_channel())
    }

    pub fn list_channels(&self, server_id: &[u8; 32]) -> Result<Vec<Channel>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT channel_id, server_id, name, kind, position FROM channels WHERE server_id = ?1 ORDER BY position",
            )
            .map_err(|e| GhostError::Database(format!("prepare list channels: {e}")))?;

        let rows = stmt
            .query_map([server_id.as_slice()], |row| {
                Ok(RawChannel {
                    channel_id: blob32(row, 0)?,
                    server_id: blob32(row, 1)?,
                    name: row.get(2)?,
                    kind_str: row.get(3)?,
                    position: row.get(4)?,
                })
            })
            .map_err(|e| GhostError::Database(format!("list channels: {e}")))?;

        let mut channels = Vec::new();
        for row in rows {
            let raw = row.map_err(|e| GhostError::Database(format!("read channel row: {e}")))?;
            channels.push(raw.into_channel()?);
        }
        Ok(channels)
    }

    pub fn rename_channel(&self, channel_id: &[u8; 32], name: &str) -> Result<()> {
        let updated = self
            .conn
            .execute(
                "UPDATE channels SET name = ?1 WHERE channel_id = ?2",
                rusqlite::params![name, channel_id.as_slice()],
            )
            .map_err(|e| GhostError::Database(format!("rename channel: {e}")))?;

        if updated == 0 {
            return Err(GhostError::Database("channel not found".into()));
        }
        Ok(())
    }

    pub fn delete_channel(&self, channel_id: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM channels WHERE channel_id = ?1",
                [channel_id.as_slice()],
            )
            .map_err(|e| GhostError::Database(format!("delete channel: {e}")))?;
        Ok(())
    }
}

// Intermediate struct to avoid complex tuples with String in rusqlite closures.
struct RawChannel {
    channel_id: [u8; 32],
    server_id: [u8; 32],
    name: String,
    kind_str: String,
    position: i32,
}

impl RawChannel {
    fn into_channel(self) -> Result<Channel> {
        Ok(Channel {
            channel_id: self.channel_id,
            server_id: self.server_id,
            name: self.name,
            kind: ChannelKind::parse(&self.kind_str)?,
            position: self.position,
        })
    }
}
