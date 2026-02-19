use crate::error::{GhostError, Result};

use super::{blob32, GhostStore, Server, ServerKind};

impl GhostStore {
    pub fn insert_server(&self, server: &Server) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO servers (server_id, name, kind, creator_fp, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    server.server_id.as_slice(),
                    server.name,
                    server.kind.as_str(),
                    server.creator_fp.as_slice(),
                    server.created_at,
                ],
            )
            .map_err(|e| GhostError::Database(format!("insert server: {e}")))?;
        Ok(())
    }

    pub fn get_server(&self, server_id: &[u8; 32]) -> Result<Server> {
        self.conn
            .query_row(
                "SELECT server_id, name, kind, creator_fp, created_at FROM servers WHERE server_id = ?1",
                [server_id.as_slice()],
                |row| {
                    let kind_str: String = row.get(2)?;
                    Ok(Server {
                        server_id: blob32(row, 0)?,
                        name: row.get(1)?,
                        kind: ServerKind::parse(&kind_str).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
                        })?,
                        creator_fp: blob32(row, 3)?,
                        created_at: row.get(4)?,
                    })
                },
            )
            .map_err(|e| GhostError::Database(format!("get server: {e}")))
    }

    pub fn list_servers(&self) -> Result<Vec<Server>> {
        let mut stmt = self
            .conn
            .prepare("SELECT server_id, name, kind, creator_fp, created_at FROM servers ORDER BY created_at")
            .map_err(|e| GhostError::Database(format!("prepare list servers: {e}")))?;

        let rows = stmt
            .query_map([], |row| {
                let kind_str: String = row.get(2)?;
                Ok(Server {
                    server_id: blob32(row, 0)?,
                    name: row.get(1)?,
                    kind: ServerKind::parse(&kind_str).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
                    })?,
                    creator_fp: blob32(row, 3)?,
                    created_at: row.get(4)?,
                })
            })
            .map_err(|e| GhostError::Database(format!("list servers: {e}")))?;

        let mut servers = Vec::new();
        for row in rows {
            servers.push(row.map_err(|e| GhostError::Database(format!("read server row: {e}")))?);
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
            .map_err(|e| GhostError::Database(format!("rename server: {e}")))?;

        if updated == 0 {
            return Err(GhostError::Database("server not found".into()));
        }
        Ok(())
    }

    pub fn delete_server(&self, server_id: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM servers WHERE server_id = ?1",
                [server_id.as_slice()],
            )
            .map_err(|e| GhostError::Database(format!("delete server: {e}")))?;
        Ok(())
    }
}
