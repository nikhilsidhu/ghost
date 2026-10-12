use ghost_wire::policy::ServerView;
use super::db;
use rusqlite::OptionalExtension;

use crate::error::{GhostError, Result};

use super::GhostStore;

impl GhostStore {
    /// Record the server group's view from `epoch` on, unless it equals the view
    /// already in force there.
    pub fn record_server_view(&self, server_id: &[u8; 32], epoch: u64, view: &ServerView) -> Result<()> {
        if self.server_view_at(server_id, epoch)?.as_ref() == Some(view) {
            return Ok(());
        }
        self.conn
            .execute(
                "INSERT OR REPLACE INTO server_views (server_id, epoch, view) VALUES (?1, ?2, ?3)",
                rusqlite::params![server_id.as_slice(), epoch as i64, view.to_bytes()],
            )
            .map_err(db("record server view"))?;
        Ok(())
    }

    /// The server group's view at `epoch`: the latest one recorded at or before it.
    pub fn server_view_at(&self, server_id: &[u8; 32], epoch: u64) -> Result<Option<ServerView>> {
        let bytes: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT view FROM server_views WHERE server_id = ?1 AND epoch <= ?2 ORDER BY epoch DESC LIMIT 1",
                rusqlite::params![server_id.as_slice(), epoch as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(db("server view"))?;
        bytes
            .map(|b| ServerView::from_bytes(&b).map_err(|e| GhostError::Format(format!("stored server view: {e}"))))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use ghost_wire::policy::ServerPolicy;

    use super::*;
    use crate::storage::{Server, ServerKind};

    #[test]
    fn views_apply_from_their_epoch_until_the_next_change() {
        let server_id = [0x05; 32];
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        store
            .insert_server(&Server { server_id, name: "s".into(), kind: ServerKind::Server, created_at: 1 }, crate::storage::OnConflict::Fail)
            .unwrap();
        let first = ServerView { policy: ServerPolicy::new([1; 32]), members: vec![[1; 32]] };
        let second = ServerView { members: vec![[1; 32], [2; 32]], ..first.clone() };
        store.record_server_view(&server_id, 3, &first).unwrap();
        store.record_server_view(&server_id, 5, &first).unwrap();
        store.record_server_view(&server_id, 7, &second).unwrap();

        assert_eq!(store.server_view_at(&server_id, 2).unwrap(), None);
        assert_eq!(store.server_view_at(&server_id, 6).unwrap(), Some(first));
        assert_eq!(store.server_view_at(&server_id, 9).unwrap(), Some(second));
    }
}
