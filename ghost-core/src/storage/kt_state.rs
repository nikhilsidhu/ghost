use rusqlite::{params, OptionalExtension};

use crate::error::{GhostError, Result};

use super::GhostStore;

/// Persisted key transparency state for a relay.
pub struct KtState {
    pub tree_size: u64,
    pub root_hash: [u8; 32],
    pub checkpoint: Vec<u8>,
}

impl GhostStore {
    /// Get the last verified KT checkpoint for a relay.
    pub fn get_kt_state(&self, relay_vk: &[u8; 32]) -> Result<Option<KtState>> {
        self.conn()
            .query_row(
                "SELECT tree_size, root_hash, checkpoint FROM kt_state WHERE relay_vk = ?1",
                params![relay_vk.as_slice()],
                |row| {
                    let tree_size = row.get::<_, i64>(0)? as u64;
                    let root_bytes: Vec<u8> = row.get(1)?;
                    let checkpoint: Vec<u8> = row.get(2)?;
                    let mut root_hash = [0u8; 32];
                    root_hash.copy_from_slice(&root_bytes);
                    Ok(KtState {
                        tree_size,
                        root_hash,
                        checkpoint,
                    })
                },
            )
            .optional()
            .map_err(|e| GhostError::Database(e.to_string()))
    }

    /// Store the latest verified KT checkpoint for a relay.
    pub fn set_kt_state(
        &self,
        relay_vk: &[u8; 32],
        tree_size: u64,
        root_hash: &[u8; 32],
        checkpoint: &[u8],
    ) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO kt_state (relay_vk, tree_size, root_hash, checkpoint)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (relay_vk) DO UPDATE
                 SET tree_size = ?2, root_hash = ?3, checkpoint = ?4",
                params![
                    relay_vk.as_slice(),
                    tree_size as i64,
                    root_hash.as_slice(),
                    checkpoint,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> GhostStore {
        GhostStore::open_in_memory(&[0xABu8; 32]).unwrap()
    }

    #[test]
    fn kt_state_roundtrip() {
        let store = test_store();
        let root = [0x42u8; 32];
        let cp = vec![1, 2, 3, 4];
        store
            .set_kt_state(&[0x11; 32], 100, &root, &cp)
            .unwrap();

        let got = store
            .get_kt_state(&[0x11; 32])
            .unwrap()
            .unwrap();
        assert_eq!(got.tree_size, 100);
        assert_eq!(got.root_hash, root);
        assert_eq!(got.checkpoint, cp);
    }

    #[test]
    fn kt_state_missing_returns_none() {
        let store = test_store();
        assert!(store.get_kt_state(&[0xEE; 32]).unwrap().is_none());
    }

    #[test]
    fn kt_state_upsert_updates() {
        let store = test_store();
        let relay = [0x22; 32];
        store.set_kt_state(&relay, 10, &[0x11; 32], &[1]).unwrap();
        store.set_kt_state(&relay, 20, &[0x22; 32], &[2]).unwrap();

        let got = store.get_kt_state(&relay).unwrap().unwrap();
        assert_eq!(got.tree_size, 20);
        assert_eq!(got.root_hash, [0x22; 32]);
    }

    #[test]
    fn accept_p6_kt_state_migration_from_url_to_relay_vk() {
        // A database written before kt_state was keyed by relay key.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE kt_state (relay_url TEXT PRIMARY KEY, tree_size INTEGER NOT NULL,
                                    root_hash BLOB NOT NULL, checkpoint BLOB NOT NULL);
             INSERT INTO kt_state VALUES ('https://relay.example', 7, x'00', x'00');",
        )
        .unwrap();
        super::super::schema::initialize(&conn).unwrap();

        let store = GhostStore { conn };
        // The URL-keyed rows are gone and the table now takes relay keys.
        assert!(store.get_kt_state(&[0x11; 32]).unwrap().is_none());
        store.set_kt_state(&[0x11; 32], 3, &[0xAB; 32], &[9]).unwrap();
        assert_eq!(store.get_kt_state(&[0x11; 32]).unwrap().unwrap().tree_size, 3);
        // Re-running the schema on a migrated database keeps the data.
        super::super::schema::initialize(&store.conn).unwrap();
        assert!(store.get_kt_state(&[0x11; 32]).unwrap().is_some());
    }
}
