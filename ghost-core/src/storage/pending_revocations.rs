//! Devices this device removed while the home relay was unreachable. They are already
//! out of every group; the log entry and the account key that leaves them out wait
//! here until the home takes them. A removal the home refused for a reason a retry does
//! not change keeps that reason, for the user to see.

use super::db;
use crate::error::{GhostError, Result};

use super::GhostStore;

/// A removal waiting for the home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRemoval {
    pub device_vk: [u8; 32],
    pub requested_at: u64,
    /// Why the home last refused it, if it did.
    pub refused: Option<String>,
}

impl GhostStore {
    pub fn add_pending_revocation(&self, device_vk: &[u8; 32], requested_at: u64) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO pending_revocations (device_vk, requested_at) VALUES (?1, ?2)
                 ON CONFLICT (device_vk) DO NOTHING",
                rusqlite::params![device_vk.as_slice(), requested_at as i64],
            )
            .map_err(db("record pending revocation"))?;
        Ok(())
    }

    pub fn remove_pending_revocation(&self, device_vk: &[u8; 32]) -> Result<()> {
        self.conn
            .execute("DELETE FROM pending_revocations WHERE device_vk = ?1", [device_vk.as_slice()])
            .map_err(db("clear pending revocation"))?;
        Ok(())
    }

    /// The home refused the removal for `reason`. Whether that is news: a reason already
    /// recorded is not told again.
    pub fn set_pending_refused(&self, device_vk: &[u8; 32], reason: &str) -> Result<bool> {
        let changed = self
            .conn
            .execute(
                "UPDATE pending_revocations SET refused = ?2 WHERE device_vk = ?1 AND refused IS NOT ?2",
                rusqlite::params![device_vk.as_slice(), reason],
            )
            .map_err(db("record pending revocation refusal"))?;
        Ok(changed > 0)
    }

    /// Every waiting removal, oldest first.
    pub fn pending_removals(&self) -> Result<Vec<PendingRemoval>> {
        let mut stmt = self
            .conn
            .prepare("SELECT device_vk, requested_at, refused FROM pending_revocations ORDER BY requested_at")
            .map_err(db("list pending revocations"))?;
        let rows = stmt
            .query_map([], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?, row.get::<_, Option<String>>(2)?)))
            .map_err(db("list pending revocations"))?;
        rows.map(|row| {
            let (device_vk, requested_at, refused) = row.map_err(db("read pending revocation"))?;
            let device_vk = device_vk.try_into().map_err(|_| GhostError::Database("pending revocation key is not 32 bytes".into()))?;
            Ok(PendingRemoval { device_vk, requested_at: requested_at as u64, refused })
        })
        .collect()
    }

    /// Oldest first.
    pub fn pending_revocations(&self) -> Result<Vec<[u8; 32]>> {
        let mut stmt = self
            .conn
            .prepare("SELECT device_vk FROM pending_revocations ORDER BY requested_at")
            .map_err(db("list pending revocations"))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(db("list pending revocations"))?;
        rows.map(|row| {
            row.map_err(db("read pending revocation"))?
                .try_into()
                .map_err(|_| GhostError::Database("pending revocation key is not 32 bytes".into()))
        })
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_revocations_are_kept_once_in_order_until_cleared() {
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        store.add_pending_revocation(&[2; 32], 20).unwrap();
        store.add_pending_revocation(&[1; 32], 10).unwrap();
        store.add_pending_revocation(&[2; 32], 30).unwrap();
        assert_eq!(store.pending_revocations().unwrap(), vec![[1; 32], [2; 32]]);
        store.remove_pending_revocation(&[1; 32]).unwrap();
        assert_eq!(store.pending_revocations().unwrap(), vec![[2; 32]]);
    }

    #[test]
    fn a_refusal_is_news_once_per_reason() {
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        store.add_pending_revocation(&[1; 32], 10).unwrap();
        assert!(store.set_pending_refused(&[1; 32], "bad copy").unwrap());
        assert!(!store.set_pending_refused(&[1; 32], "bad copy").unwrap(), "the same reason again is not news");
        assert!(store.set_pending_refused(&[1; 32], "fork").unwrap());
        assert!(!store.set_pending_refused(&[9; 32], "fork").unwrap(), "no such removal");
        let pending = store.pending_removals().unwrap();
        assert_eq!(pending, vec![PendingRemoval { device_vk: [1; 32], requested_at: 10, refused: Some("fork".into()) }]);
    }
}
