use rusqlite::OptionalExtension;

use crate::error::Result;

use super::{db, GhostStore};

impl GhostStore {
    pub fn get_config_blob(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT value FROM device_config WHERE key = ?1",
                [key],
                |row| row.get(0),
            )
            .optional()
            .map_err(db("get device_config"))
    }

    pub fn delete_config_blob(&self, key: &str) -> Result<()> {
        self.conn.execute("DELETE FROM device_config WHERE key = ?1", [key]).map_err(db("delete device_config"))?;
        Ok(())
    }

    pub fn set_config_blob(&self, key: &str, value: &[u8]) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO device_config (key, value) VALUES (?1, ?2)
                 ON CONFLICT (key) DO UPDATE SET value = ?2",
                rusqlite::params![key, value],
            )
            .map_err(db("set device_config"))?;
        Ok(())
    }
}
