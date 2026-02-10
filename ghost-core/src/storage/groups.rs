use crate::error::{GhostError, Result};

use super::{blob32, GhostStore, Group};

impl GhostStore {
    pub fn insert_group(&self, group: &Group) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO groups (group_id, name, creator_fp, created_at) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    group.group_id.as_slice(),
                    group.name,
                    group.creator_fp.as_slice(),
                    group.created_at,
                ],
            )
            .map_err(|e| GhostError::Database(format!("insert group: {e}")))?;
        Ok(())
    }

    pub fn get_group(&self, group_id: &[u8; 32]) -> Result<Group> {
        self.conn
            .query_row(
                "SELECT group_id, name, creator_fp, created_at FROM groups WHERE group_id = ?1",
                [group_id.as_slice()],
                |row| {
                    Ok(Group {
                        group_id: blob32(row, 0)?,
                        name: row.get(1)?,
                        creator_fp: blob32(row, 2)?,
                        created_at: row.get(3)?,
                    })
                },
            )
            .map_err(|e| GhostError::Database(format!("get group: {e}")))
    }

    pub fn list_groups(&self) -> Result<Vec<Group>> {
        let mut stmt = self
            .conn
            .prepare("SELECT group_id, name, creator_fp, created_at FROM groups ORDER BY created_at")
            .map_err(|e| GhostError::Database(format!("prepare list groups: {e}")))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(Group {
                    group_id: blob32(row, 0)?,
                    name: row.get(1)?,
                    creator_fp: blob32(row, 2)?,
                    created_at: row.get(3)?,
                })
            })
            .map_err(|e| GhostError::Database(format!("list groups: {e}")))?;

        let mut groups = Vec::new();
        for row in rows {
            groups.push(row.map_err(|e| GhostError::Database(format!("read group row: {e}")))?);
        }
        Ok(groups)
    }

    pub fn rename_group(&self, group_id: &[u8; 32], name: &str) -> Result<()> {
        let updated = self
            .conn
            .execute(
                "UPDATE groups SET name = ?1 WHERE group_id = ?2",
                rusqlite::params![name, group_id.as_slice()],
            )
            .map_err(|e| GhostError::Database(format!("rename group: {e}")))?;

        if updated == 0 {
            return Err(GhostError::Database("group not found".into()));
        }
        Ok(())
    }

    pub fn delete_group(&self, group_id: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM groups WHERE group_id = ?1",
                [group_id.as_slice()],
            )
            .map_err(|e| GhostError::Database(format!("delete group: {e}")))?;
        Ok(())
    }
}
