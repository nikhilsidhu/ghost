use crate::error::{GhostError, Result};

use super::GhostStore;

impl GhostStore {
    pub fn pin_server(&self, server_id: &[u8; 32], pinned_at: u64) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO pinned_servers (server_id, pinned_at) VALUES (?1, ?2)",
                rusqlite::params![server_id.as_slice(), pinned_at],
            )
            .map_err(|e| GhostError::Database(format!("pin server: {e}")))?;
        Ok(())
    }

    pub fn unpin_server(&self, server_id: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM pinned_servers WHERE server_id = ?1",
                [server_id.as_slice()],
            )
            .map_err(|e| GhostError::Database(format!("unpin server: {e}")))?;
        Ok(())
    }

    pub fn list_pinned_server_ids(&self) -> Result<Vec<[u8; 32]>> {
        let mut stmt = self
            .conn
            .prepare("SELECT server_id FROM pinned_servers ORDER BY pinned_at")
            .map_err(|e| GhostError::Database(format!("prepare list pins: {e}")))?;

        let rows = stmt
            .query_map([], |row| super::blob32(row, 0))
            .map_err(|e| GhostError::Database(format!("list pins: {e}")))?;

        let mut ids = Vec::new();
        for row in rows {
            ids.push(row.map_err(|e| GhostError::Database(format!("read pin row: {e}")))?);
        }
        Ok(ids)
    }

    pub fn is_pinned(&self, server_id: &[u8; 32]) -> Result<bool> {
        let count: u32 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM pinned_servers WHERE server_id = ?1",
                [server_id.as_slice()],
                |row| row.get(0),
            )
            .map_err(|e| GhostError::Database(format!("check pin: {e}")))?;
        Ok(count > 0)
    }
}
