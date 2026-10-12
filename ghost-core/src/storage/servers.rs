use crate::error::{GhostError, Result};

use rusqlite::OptionalExtension;

use super::{blob32, db, Channel, GhostStore, Member, OnConflict, Server, ServerHalt, ServerKind, ServerRemoval};

impl GhostStore {
    /// Store a server this device just made, its default channel and its creator as one
    /// change, marked unpublished until its relay holds the group state.
    pub fn insert_created_server(&self, server: &Server, channel: &Channel, creator: &Member) -> Result<()> {
        self.write_whole(|| {
            self.insert_server(server, OnConflict::Fail)?;
            self.insert_channel(channel, OnConflict::Fail)?;
            self.insert_member(creator, OnConflict::Fail)?;
            self.conn
                .execute("INSERT INTO unpublished_servers (server_id) VALUES (?1)", [server.server_id.as_slice()])
                .map_err(db("insert created server"))?;
            Ok(())
        })
    }

    /// The relay holds the server's group state.
    pub fn server_published(&self, server_id: &[u8; 32]) -> Result<()> {
        self.conn
            .execute("DELETE FROM unpublished_servers WHERE server_id = ?1", [server_id.as_slice()])
            .map_err(db("server published"))?;
        Ok(())
    }

    /// Servers this device made whose group state no relay was given: the process ended
    /// between making one and uploading it.
    pub fn unpublished_servers(&self) -> Result<Vec<[u8; 32]>> {
        let mut stmt = self.conn.prepare("SELECT server_id FROM unpublished_servers").map_err(db("unpublished servers"))?;
        let rows = stmt
            .query_map([], |row| blob32(row, 0))
            .map_err(db("unpublished servers"))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db("unpublished servers"))?;
        Ok(rows)
    }

    pub fn insert_server(&self, server: &Server, on_conflict: OnConflict) -> Result<()> {
        self.conn
            .execute(
                &format!("{} INTO servers (server_id, name, kind, created_at) VALUES (?1, ?2, ?3, ?4)", on_conflict.verb()),
                rusqlite::params![
                    server.server_id.as_slice(),
                    server.name,
                    server.kind.as_str(),
                    server.created_at,
                ],
            )
            .map_err(db("insert server"))?;
        Ok(())
    }

    pub fn get_server(&self, server_id: &[u8; 32]) -> Result<Server> {
        self.conn
            .query_row(
                "SELECT server_id, name, kind, created_at FROM servers WHERE server_id = ?1",
                [server_id.as_slice()],
                |row| {
                    let kind_str: String = row.get(2)?;
                    Ok(Server {
                        server_id: blob32(row, 0)?,
                        name: row.get(1)?,
                        kind: ServerKind::parse(&kind_str).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
                        })?,
                        created_at: row.get(3)?,
                    })
                },
            )
            .map_err(db("get server"))
    }

    pub fn list_servers(&self) -> Result<Vec<Server>> {
        let mut stmt = self
            .conn
            .prepare("SELECT server_id, name, kind, created_at FROM servers ORDER BY created_at")
            .map_err(db("prepare list servers"))?;

        let rows = stmt
            .query_map([], |row| {
                let kind_str: String = row.get(2)?;
                Ok(Server {
                    server_id: blob32(row, 0)?,
                    name: row.get(1)?,
                    kind: ServerKind::parse(&kind_str).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
                    })?,
                    created_at: row.get(3)?,
                })
            })
            .map_err(db("list servers"))?;

        let mut servers = Vec::new();
        for row in rows {
            servers.push(row.map_err(db("read server row"))?);
        }
        Ok(servers)
    }

    pub fn rename_server(&self, server_id: &[u8; 32], name: &str) -> Result<()> {
        let updated = self
            .conn
            .execute(
                "UPDATE servers SET name = ?1 WHERE server_id = ?2",
                rusqlite::params![name, server_id.as_slice()],
            )
            .map_err(db("rename server"))?;

        if updated == 0 {
            return Err(GhostError::Database("server not found".into()));
        }
        Ok(())
    }

    /// Record that this account was removed from the server at `at`, by `by` when known.
    /// A later record keeps an earlier one's remover when it knows none.
    pub fn mark_server_removed(&self, server_id: &[u8; 32], by: Option<&[u8; 32]>, at: u64) -> Result<()> {
        self.conn
            .execute(
                "UPDATE servers SET removed_at = COALESCE(removed_at, ?1), removed_by = COALESCE(?2, removed_by) WHERE server_id = ?3",
                rusqlite::params![at, by.map(|b| b.to_vec()), server_id.as_slice()],
            )
            .map_err(db("mark server removed"))?;
        Ok(())
    }

    /// The account is back in the server, let back in and rejoined.
    pub fn clear_server_removed(&self, server_id: &[u8; 32]) -> Result<()> {
        self.conn
            .execute("UPDATE servers SET removed_at = NULL, removed_by = NULL WHERE server_id = ?1", [server_id.as_slice()])
            .map_err(db("clear server removed"))?;
        Ok(())
    }

    /// When and by whom this account was removed from the server, if it was.
    pub fn server_removal(&self, server_id: &[u8; 32]) -> Result<Option<ServerRemoval>> {
        self.conn
            .query_row(
                "SELECT removed_at, removed_by FROM servers WHERE server_id = ?1 AND removed_at IS NOT NULL",
                [server_id.as_slice()],
                |row| {
                    let by: Option<Vec<u8>> = row.get(1)?;
                    Ok(ServerRemoval { at: row.get(0)?, by: by.and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()) })
                },
            )
            .optional()
            .map_err(db("server removal"))
    }

    /// Stop following the server: its relay accepted a change the rules forbid. The first
    /// refusal is the one kept.
    pub fn halt_server(&self, server_id: &[u8; 32], reason: &str, at: u64) -> Result<()> {
        self.conn
            .execute(
                "UPDATE servers SET halted_at = COALESCE(halted_at, ?1), halted_reason = COALESCE(halted_reason, ?2) WHERE server_id = ?3",
                rusqlite::params![at, reason, server_id.as_slice()],
            )
            .map_err(db("halt server"))?;
        Ok(())
    }

    /// Follow the server again: the person accepted the relay's state, or the server moved.
    pub fn clear_server_halt(&self, server_id: &[u8; 32]) -> Result<()> {
        self.conn
            .execute("UPDATE servers SET halted_at = NULL, halted_reason = NULL WHERE server_id = ?1", [server_id.as_slice()])
            .map_err(db("clear server halt"))?;
        Ok(())
    }

    /// Why and when this device stopped following the server, if it did.
    pub fn server_halt(&self, server_id: &[u8; 32]) -> Result<Option<ServerHalt>> {
        self.conn
            .query_row(
                "SELECT halted_at, halted_reason FROM servers WHERE server_id = ?1 AND halted_at IS NOT NULL",
                [server_id.as_slice()],
                |row| Ok(ServerHalt { at: row.get(0)?, reason: row.get::<_, Option<String>>(1)?.unwrap_or_default() }),
            )
            .optional()
            .map_err(db("server halt"))
    }

    pub fn delete_server(&self, server_id: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM servers WHERE server_id = ?1",
                [server_id.as_slice()],
            )
            .map_err(db("delete server"))?;
        Ok(())
    }
}
