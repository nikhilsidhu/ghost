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
    pub fn get_kt_state(&self, relay_url: &str) -> Result<Option<KtState>> {
        self.conn()
            .query_row(
                "SELECT tree_size, root_hash, checkpoint FROM kt_state WHERE relay_url = ?1",
                params![relay_url],
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
        relay_url: &str,
        tree_size: u64,
        root_hash: &[u8; 32],
        checkpoint: &[u8],
    ) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO kt_state (relay_url, tree_size, root_hash, checkpoint)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (relay_url) DO UPDATE
                 SET tree_size = ?2, root_hash = ?3, checkpoint = ?4",
                params![
                    relay_url,
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
            .set_kt_state("https://relay.example.com", 100, &root, &cp)
            .unwrap();

        let got = store
            .get_kt_state("https://relay.example.com")
            .unwrap()
            .unwrap();
        assert_eq!(got.tree_size, 100);
        assert_eq!(got.root_hash, root);
        assert_eq!(got.checkpoint, cp);
    }

    #[test]
    fn kt_state_missing_returns_none() {
        let store = test_store();
        assert!(store.get_kt_state("https://missing.com").unwrap().is_none());
    }

    #[test]
    fn kt_state_upsert_updates() {
        let store = test_store();
        let url = "https://relay.example.com";
        store.set_kt_state(url, 10, &[0x11; 32], &[1]).unwrap();
        store.set_kt_state(url, 20, &[0x22; 32], &[2]).unwrap();

        let got = store.get_kt_state(url).unwrap().unwrap();
        assert_eq!(got.tree_size, 20);
        assert_eq!(got.root_hash, [0x22; 32]);
    }
}
