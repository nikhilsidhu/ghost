//! Where this device stands in every other device's sync messages: the replay window
//! per sender, plus this device's own counter and clock. Kept so a restart replays
//! nothing and never reuses a sequence number.

use super::db;
use rusqlite::OptionalExtension;

use crate::error::{GhostError, Result};
use crate::sync::window::ReplayWindow;

use super::GhostStore;

const CONFIG_OWN_SYNC_SEQ: &str = "sync_seq";
const CONFIG_SYNC_CLOCK: &str = "sync_clock";

impl GhostStore {
    pub fn sync_cursor(&self, device_vk: &[u8; 32]) -> Result<ReplayWindow> {
        let row: Option<(i64, i64)> = self
            .conn
            .query_row(
                "SELECT high_seq, window FROM sync_cursors WHERE device_vk = ?1",
                [device_vk.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(db("read sync cursor"))?;
        Ok(row.map_or_else(ReplayWindow::default, |(high, bits)| ReplayWindow::new(high as u64, bits as u64)))
    }

    pub fn set_sync_cursor(&self, device_vk: &[u8; 32], window: &ReplayWindow) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO sync_cursors (device_vk, high_seq, window) VALUES (?1, ?2, ?3)
                 ON CONFLICT (device_vk) DO UPDATE SET high_seq = ?2, window = ?3",
                rusqlite::params![device_vk.as_slice(), window.high() as i64, window.bits() as i64],
            )
            .map_err(db("store sync cursor"))?;
        Ok(())
    }

    /// Every sender's highest sequence number seen, for a snapshot's version vector.
    pub fn sync_cursors(&self) -> Result<Vec<([u8; 32], u64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT device_vk, high_seq FROM sync_cursors ORDER BY device_vk")
            .map_err(db("list sync cursors"))?;
        let rows = stmt
            .query_map([], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)))
            .map_err(db("list sync cursors"))?;
        rows.map(|row| {
            let (vk, high) = row.map_err(db("read sync cursor"))?;
            let vk: [u8; 32] = vk.try_into().map_err(|_| GhostError::Database("sync cursor key is not 32 bytes".into()))?;
            Ok((vk, high as u64))
        })
        .collect()
    }

    /// The next sequence number for a message this device sends, reserved before the
    /// message leaves so a crash in between never repeats one.
    pub fn next_sync_seq(&self) -> Result<u64> {
        let last = self.config_u64(CONFIG_OWN_SYNC_SEQ)?.unwrap_or(0);
        let next = last + 1;
        self.set_config_blob(CONFIG_OWN_SYNC_SEQ, &next.to_be_bytes())?;
        Ok(next)
    }

    pub fn own_sync_seq(&self) -> Result<u64> {
        Ok(self.config_u64(CONFIG_OWN_SYNC_SEQ)?.unwrap_or(0))
    }

    pub fn sync_clock(&self) -> Result<u64> {
        Ok(self.config_u64(CONFIG_SYNC_CLOCK)?.unwrap_or(0))
    }

    pub fn set_sync_clock(&self, clock: u64) -> Result<()> {
        self.set_config_blob(CONFIG_SYNC_CLOCK, &clock.to_be_bytes())
    }

    fn config_u64(&self, key: &str) -> Result<Option<u64>> {
        Ok(self
            .get_config_blob(key)?
            .and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok())
            .map(u64::from_be_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::window::Arrival;

    #[test]
    fn cursors_resume_where_they_stopped() {
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        let mut window = store.sync_cursor(&[1; 32]).unwrap();
        assert_eq!(window.accept(7), Arrival::New { gap: 6 });
        store.set_sync_cursor(&[1; 32], &window).unwrap();
        let mut again = store.sync_cursor(&[1; 32]).unwrap();
        assert_eq!(again.accept(7), Arrival::Seen);
        assert_eq!(again.accept(3), Arrival::New { gap: 0 });
        assert_eq!(store.sync_cursors().unwrap(), vec![([1; 32], 7)]);
    }

    #[test]
    fn own_sequence_numbers_are_reserved_one_at_a_time() {
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        assert_eq!(store.own_sync_seq().unwrap(), 0);
        assert_eq!(store.next_sync_seq().unwrap(), 1);
        assert_eq!(store.next_sync_seq().unwrap(), 2);
        assert_eq!(store.own_sync_seq().unwrap(), 2);
    }

    #[test]
    fn the_clock_persists() {
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        assert_eq!(store.sync_clock().unwrap(), 0);
        store.set_sync_clock(99).unwrap();
        assert_eq!(store.sync_clock().unwrap(), 99);
    }
}
