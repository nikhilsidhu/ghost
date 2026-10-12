use crate::error::Result;

use super::{db, GhostStore};

impl GhostStore {
    pub fn set_role_name(&self, server_id: &[u8; 32], role_id: u8, name: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO role_names (server_id, role_id, name) VALUES (?1, ?2, ?3)",
                rusqlite::params![server_id.as_slice(), role_id, name],
            )
            .map_err(db("set role name"))?;
        Ok(())
    }

    pub fn list_role_names(&self, server_id: &[u8; 32]) -> Result<Vec<(u8, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT role_id, name FROM role_names WHERE server_id = ?1 ORDER BY role_id")
            .map_err(db("list role names"))?;
        let rows = stmt
            .query_map([server_id.as_slice()], |row| Ok((row.get::<_, u8>(0)?, row.get::<_, String>(1)?)))
            .map_err(db("list role names"))?;
        rows.collect::<std::result::Result<_, _>>()
            .map_err(db("list role names"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{Server, ServerKind};

    #[test]
    fn role_names_replace_by_id() {
        let server_id = [0x05; 32];
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        store
            .insert_server(&Server { server_id, name: "s".into(), kind: ServerKind::Server, created_at: 1 }, crate::storage::OnConflict::Fail)
            .unwrap();
        store.set_role_name(&server_id, 2, "mods").unwrap();
        store.set_role_name(&server_id, 1, "admins").unwrap();
        store.set_role_name(&server_id, 2, "moderators").unwrap();
        assert_eq!(
            store.list_role_names(&server_id).unwrap(),
            vec![(1, "admins".to_string()), (2, "moderators".to_string())]
        );
    }
}
