use rusqlite::OptionalExtension;

use crate::error::{GhostError, Result};

use super::{blob32, db, Channel, ChannelKind, GhostStore, OnConflict};

impl GhostStore {
    pub fn insert_channel(&self, channel: &Channel, on_conflict: OnConflict) -> Result<()> {
        self.conn
            .execute(
                &format!("{} INTO channels (channel_id, server_id, name, kind, position) VALUES (?1, ?2, ?3, ?4, ?5)", on_conflict.verb()),
                rusqlite::params![
                    channel.channel_id.as_slice(),
                    channel.server_id.as_slice(),
                    channel.name,
                    channel.kind.as_str(),
                    channel.position,
                ],
            )
            .map_err(db("insert channel"))?;
        Ok(())
    }

    /// Record the epoch this device joined a channel's group at, once: a rejoin after
    /// falling behind keeps the first, since what was missed in between was for this device.
    pub fn record_group_join(&self, channel_id: &[u8; 32], epoch: u64) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO group_joins (channel_id, joined_epoch) VALUES (?1, ?2)",
                rusqlite::params![channel_id.as_slice(), epoch as i64],
            )
            .map_err(db("record group join"))?;
        Ok(())
    }

    /// The epoch this device joined a channel's group at; 0 for a group it made.
    pub fn joined_epoch(&self, channel_id: &[u8; 32]) -> Result<u64> {
        let epoch: Option<i64> = self
            .conn
            .query_row("SELECT joined_epoch FROM group_joins WHERE channel_id = ?1", rusqlite::params![channel_id.as_slice()], |row| row.get(0))
            .optional()
            .map_err(db("joined epoch"))?;
        Ok(epoch.unwrap_or(0) as u64)
    }

    /// Give each listed channel of the server its position; ones not listed keep theirs.
    pub fn set_channel_positions(&self, server_id: &[u8; 32], positions: &[([u8; 32], i32)]) -> Result<()> {
        let mut stmt = self
            .conn
            .prepare("UPDATE channels SET position = ?1 WHERE channel_id = ?2 AND server_id = ?3")
            .map_err(db("prepare channel positions"))?;
        for (channel_id, position) in positions {
            stmt.execute(rusqlite::params![position, channel_id.as_slice(), server_id.as_slice()])
                .map_err(db("set channel position"))?;
        }
        Ok(())
    }

    /// The position after the server's last channel, so a new one never shares one.
    pub fn next_channel_position(&self, server_id: &[u8; 32]) -> Result<i32> {
        self.conn
            .query_row("SELECT COALESCE(MAX(position) + 1, 0) FROM channels WHERE server_id = ?1", [server_id.as_slice()], |row| row.get(0))
            .map_err(db("next channel position"))
    }

    /// Insert a channel, or update the name, kind and position of one already stored.
    pub fn upsert_channel(&self, channel: &Channel) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO channels (channel_id, server_id, name, kind, position) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(channel_id) DO UPDATE SET name = excluded.name, kind = excluded.kind, position = excluded.position",
                rusqlite::params![
                    channel.channel_id.as_slice(),
                    channel.server_id.as_slice(),
                    channel.name,
                    channel.kind.as_str(),
                    channel.position,
                ],
            )
            .map_err(db("upsert channel"))?;
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
            .map_err(db("get channel"))
            .and_then(|r| r.into_channel())
    }

    pub fn list_channels(&self, server_id: &[u8; 32]) -> Result<Vec<Channel>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT channel_id, server_id, name, kind, position FROM channels WHERE server_id = ?1 ORDER BY position",
            )
            .map_err(db("prepare list channels"))?;

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
            .map_err(db("list channels"))?;

        let mut channels = Vec::new();
        for row in rows {
            let raw = row.map_err(db("read channel row"))?;
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
            .map_err(db("rename channel"))?;

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
            .map_err(db("delete channel"))?;
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
