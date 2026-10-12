//! A joiner's wait for a server's current state: its invite payload is from when the
//! invite was made, so it asks the server's managers and takes the first answer that
//! no change it saw since has outdated.

use rusqlite::OptionalExtension;

use crate::error::Result;

use super::{blob32, db, GhostStore};

/// What a joiner waiting for a server's state knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerStateWait {
    /// The sequence of this device's request in the server's mailbox, once the relay took it.
    pub request_seq: Option<u64>,
    /// The sequence of the last change to the server's channels or role names this
    /// device saw; an answer as of an earlier point would undo it.
    pub last_change_seq: u64,
}

impl GhostStore {
    /// Start waiting for the server's state, as a device that just joined it.
    pub fn begin_server_state_wait(&self, server_id: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO server_state_waits (server_id, request_seq, last_change_seq) VALUES (?1, NULL, 0)
                 ON CONFLICT(server_id) DO UPDATE SET request_seq = NULL, last_change_seq = 0",
                [server_id.as_slice()],
            )
            .map_err(db("begin server state wait"))?;
        Ok(())
    }

    /// The relay took this device's request for the server's state at `seq`.
    pub fn server_state_requested(&self, server_id: &[u8; 32], seq: u64) -> Result<()> {
        self.conn
            .execute("UPDATE server_state_waits SET request_seq = ?2 WHERE server_id = ?1", rusqlite::params![server_id.as_slice(), seq as i64])
            .map_err(db("server state requested"))?;
        Ok(())
    }

    /// A change to the server's channels or role names at `seq`, seen while waiting.
    pub fn note_server_change(&self, server_id: &[u8; 32], seq: u64) -> Result<()> {
        self.conn
            .execute(
                "UPDATE server_state_waits SET last_change_seq = MAX(last_change_seq, ?2) WHERE server_id = ?1",
                rusqlite::params![server_id.as_slice(), seq as i64],
            )
            .map_err(db("note server change"))?;
        Ok(())
    }

    pub fn server_state_wait(&self, server_id: &[u8; 32]) -> Result<Option<ServerStateWait>> {
        self.conn
            .query_row(
                "SELECT request_seq, last_change_seq FROM server_state_waits WHERE server_id = ?1",
                [server_id.as_slice()],
                |row| Ok(ServerStateWait { request_seq: row.get::<_, Option<i64>>(0)?.map(|s| s as u64), last_change_seq: row.get::<_, i64>(1)? as u64 }),
            )
            .optional()
            .map_err(db("server state wait"))
    }

    pub fn end_server_state_wait(&self, server_id: &[u8; 32]) -> Result<()> {
        self.conn
            .execute("DELETE FROM server_state_waits WHERE server_id = ?1", [server_id.as_slice()])
            .map_err(db("end server state wait"))?;
        Ok(())
    }

    /// Servers whose state this device waits for without the relay having taken its request.
    pub fn unrequested_server_states(&self) -> Result<Vec<[u8; 32]>> {
        let mut stmt = self
            .conn
            .prepare("SELECT server_id FROM server_state_waits WHERE request_seq IS NULL")
            .map_err(db("unrequested server states"))?;
        let rows = stmt
            .query_map([], |row| blob32(row, 0))
            .map_err(db("unrequested server states"))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db("unrequested server states"))?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{OnConflict, Server, ServerKind};

    #[test]
    fn a_wait_records_the_request_and_the_latest_change_until_it_ends() {
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        let server_id = [1; 32];
        store.insert_server(&Server { server_id, name: "club".into(), kind: ServerKind::Server, created_at: 0 }, OnConflict::Fail).unwrap();
        store.note_server_change(&server_id, 5).unwrap();
        assert_eq!(store.server_state_wait(&server_id).unwrap(), None, "changes before a wait are not kept");

        store.begin_server_state_wait(&server_id).unwrap();
        assert_eq!(store.unrequested_server_states().unwrap(), vec![server_id]);
        store.server_state_requested(&server_id, 9).unwrap();
        store.note_server_change(&server_id, 12).unwrap();
        store.note_server_change(&server_id, 10).unwrap();
        assert_eq!(store.server_state_wait(&server_id).unwrap(), Some(ServerStateWait { request_seq: Some(9), last_change_seq: 12 }));
        assert!(store.unrequested_server_states().unwrap().is_empty());

        store.end_server_state_wait(&server_id).unwrap();
        assert_eq!(store.server_state_wait(&server_id).unwrap(), None);
    }
}
