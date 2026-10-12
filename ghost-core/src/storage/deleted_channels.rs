//! Private channels deleted while this device held them: discovery must not join one
//! again while the relay still lists it, and the deleting device owes the relay the
//! deletion of its mailbox until the relay confirms it.

use rusqlite::OptionalExtension;

use super::{blob32, db, GhostStore};

/// A deleted private channel whose mailbox this device still has to delete at the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwedDeletion {
    pub mailbox_id: [u8; 32],
    pub server_id: [u8; 32],
}

impl GhostStore {
    /// Remember a deleted private channel by its mailbox; `owed` when this device must
    /// still delete the mailbox at the relay.
    pub fn record_deleted_channel(&self, mailbox_id: &[u8; 32], server_id: &[u8; 32], owed: bool) -> crate::error::Result<()> {
        self.conn
            .execute(
                "INSERT INTO deleted_channels (mailbox_id, server_id, relay_deletion_owed) VALUES (?1, ?2, ?3)
                 ON CONFLICT(mailbox_id) DO UPDATE SET relay_deletion_owed = MAX(relay_deletion_owed, excluded.relay_deletion_owed)",
                rusqlite::params![mailbox_id.as_slice(), server_id.as_slice(), owed as i64],
            )
            .map_err(db("record deleted channel"))?;
        Ok(())
    }

    pub fn is_deleted_channel(&self, mailbox_id: &[u8; 32]) -> crate::error::Result<bool> {
        let found = self
            .conn
            .query_row("SELECT 1 FROM deleted_channels WHERE mailbox_id = ?1", [mailbox_id.as_slice()], |_| Ok(()))
            .optional()
            .map_err(db("is deleted channel"))?;
        Ok(found.is_some())
    }

    /// The relay-side deletions this device still owes for the server's channels.
    pub fn owed_channel_deletions(&self, server_id: &[u8; 32]) -> crate::error::Result<Vec<OwedDeletion>> {
        let mut stmt = self
            .conn
            .prepare("SELECT mailbox_id, server_id FROM deleted_channels WHERE server_id = ?1 AND relay_deletion_owed = 1")
            .map_err(db("owed channel deletions"))?;
        let rows = stmt
            .query_map([server_id.as_slice()], |row| Ok(OwedDeletion { mailbox_id: blob32(row, 0)?, server_id: blob32(row, 1)? }))
            .map_err(db("owed channel deletions"))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db("owed channel deletions"))?;
        Ok(rows)
    }

    /// The relay deleted the mailbox, or will not: nothing more is owed for it.
    pub fn settle_channel_deletion(&self, mailbox_id: &[u8; 32]) -> crate::error::Result<()> {
        self.conn
            .execute("UPDATE deleted_channels SET relay_deletion_owed = 0 WHERE mailbox_id = ?1", [mailbox_id.as_slice()])
            .map_err(db("settle channel deletion"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{OnConflict, Server, ServerKind};

    fn store_with_server(server_id: [u8; 32]) -> GhostStore {
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        store.insert_server(&Server { server_id, name: "club".into(), kind: ServerKind::Server, created_at: 0 }, OnConflict::Fail).unwrap();
        store
    }

    #[test]
    fn an_owed_deletion_stays_owed_until_settled_and_the_tombstone_stays_after() {
        let server_id = [1; 32];
        let store = store_with_server(server_id);
        let mailbox_id = [2; 32];
        assert!(!store.is_deleted_channel(&mailbox_id).unwrap());

        store.record_deleted_channel(&mailbox_id, &server_id, true).unwrap();
        // Told of the deletion by another member as well: still owed.
        store.record_deleted_channel(&mailbox_id, &server_id, false).unwrap();
        assert_eq!(store.owed_channel_deletions(&server_id).unwrap(), vec![OwedDeletion { mailbox_id, server_id }]);

        store.settle_channel_deletion(&mailbox_id).unwrap();
        assert!(store.owed_channel_deletions(&server_id).unwrap().is_empty());
        assert!(store.is_deleted_channel(&mailbox_id).unwrap());
    }

    #[test]
    fn tombstones_go_with_their_server() {
        let server_id = [1; 32];
        let store = store_with_server(server_id);
        store.record_deleted_channel(&[2; 32], &server_id, true).unwrap();
        store.delete_server(&server_id).unwrap();
        assert!(!store.is_deleted_channel(&[2; 32]).unwrap());
    }
}
