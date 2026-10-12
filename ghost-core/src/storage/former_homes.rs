//! Former homes this device has told about the move that ended their time as home. A
//! home that was down during a move still believes it sequences the account until told.

use crate::error::Result;

use super::{db, GhostStore};

impl GhostStore {
    /// `ended_at_seq` is the `SetHomeRelay` that moved the account away from `relay_vk`.
    pub fn former_home_told(&self, relay_vk: &[u8; 32], ended_at_seq: u64) -> Result<bool> {
        self.conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM former_homes_told WHERE relay_vk = ?1 AND ended_at_seq = ?2)",
                rusqlite::params![relay_vk.as_slice(), ended_at_seq as i64],
                |row| row.get(0),
            )
            .map_err(db("read former home"))
    }

    pub fn record_former_home_told(&self, relay_vk: &[u8; 32], ended_at_seq: u64) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO former_homes_told (relay_vk, ended_at_seq) VALUES (?1, ?2)",
                rusqlite::params![relay_vk.as_slice(), ended_at_seq as i64],
            )
            .map_err(db("record former home"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_move_away_from_a_home_is_recorded_separately() {
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        assert!(!store.former_home_told(&[1; 32], 6).unwrap());
        store.record_former_home_told(&[1; 32], 6).unwrap();
        store.record_former_home_told(&[1; 32], 6).unwrap();
        assert!(store.former_home_told(&[1; 32], 6).unwrap());
        assert!(!store.former_home_told(&[1; 32], 9).unwrap(), "moving back and away again is a new move to tell");
    }
}
