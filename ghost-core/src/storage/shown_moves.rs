//! Server moves this device was shown (a move link) and could not follow yet, because
//! the named relay or the owner's home did not answer. Each is tried again at the
//! account check until it is followed, a newer one replaces it, or the server goes.

use rusqlite::OptionalExtension;

use super::{db, GhostStore};
use crate::error::Result;

impl GhostStore {
    /// Keep the move record shown for its server, in place of an older one.
    pub fn keep_shown_move(&self, server_id: &[u8; 32], record: &[u8]) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO shown_moves (server_id, record) VALUES (?1, ?2)
                 ON CONFLICT (server_id) DO UPDATE SET record = ?2",
                rusqlite::params![server_id.as_slice(), record],
            )
            .map_err(db("keep shown move"))?;
        Ok(())
    }

    pub fn forget_shown_move(&self, server_id: &[u8; 32]) -> Result<()> {
        self.conn
            .execute("DELETE FROM shown_moves WHERE server_id = ?1", [server_id.as_slice()])
            .map_err(db("forget shown move"))?;
        Ok(())
    }

    /// The move record kept for a server, if one is.
    pub fn shown_move(&self, server_id: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        self.conn
            .query_row("SELECT record FROM shown_moves WHERE server_id = ?1", [server_id.as_slice()], |row| row.get(0))
            .optional()
            .map_err(db("shown move"))
    }

    /// Every kept move record.
    pub fn shown_moves(&self) -> Result<Vec<Vec<u8>>> {
        let mut stmt = self.conn.prepare("SELECT record FROM shown_moves").map_err(db("shown moves"))?;
        let records = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(db("shown moves"))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db("shown moves"))?;
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{OnConflict, Server, ServerKind};

    #[test]
    fn a_shown_move_is_kept_once_per_server_and_goes_with_it() {
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        let server_id = [1; 32];
        store.insert_server(&Server { server_id, name: "club".into(), kind: ServerKind::Server, created_at: 0 }, OnConflict::Fail).unwrap();
        store.keep_shown_move(&server_id, b"first").unwrap();
        store.keep_shown_move(&server_id, b"newer").unwrap();
        assert_eq!(store.shown_moves().unwrap(), vec![b"newer".to_vec()]);
        assert_eq!(store.shown_move(&server_id).unwrap().as_deref(), Some(b"newer".as_slice()));
        store.delete_server(&server_id).unwrap();
        assert!(store.shown_moves().unwrap().is_empty(), "a server's kept move goes with it");
    }
}
