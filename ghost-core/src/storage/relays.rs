use ghost_wire::relay_ref::RelayRef;
use rusqlite::OptionalExtension;

use crate::error::{GhostError, Result};

use super::{blob32, db, GhostStore};

impl GhostStore {
    /// Remember how to reach a relay; a newer ref for the same key replaces the old one.
    pub fn upsert_relay(&self, relay_ref: &RelayRef, now: u64) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO relays (relay_vk, ref_bytes, last_seen) VALUES (?1, ?2, ?3)
                 ON CONFLICT (relay_vk) DO UPDATE SET ref_bytes = ?2, last_seen = ?3",
                rusqlite::params![relay_ref.relay_vk.as_slice(), relay_ref.to_bytes(), now as i64],
            )
            .map_err(db("upsert relay"))?;
        Ok(())
    }

    pub fn get_relay(&self, relay_vk: &[u8; 32]) -> Result<Option<RelayRef>> {
        let bytes: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT ref_bytes FROM relays WHERE relay_vk = ?1",
                [relay_vk.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(db("get relay"))?;
        bytes
            .map(|b| RelayRef::from_bytes(&b).map_err(|e| GhostError::Database(format!("stored relay ref: {e}"))))
            .transpose()
    }

    /// Record which relay hosts a server's mailboxes.
    pub fn set_server_relay(&self, server_id: &[u8; 32], relay_vk: &[u8; 32]) -> Result<()> {
        let updated = self
            .conn
            .execute(
                "UPDATE servers SET relay_vk = ?2 WHERE server_id = ?1",
                rusqlite::params![server_id.as_slice(), relay_vk.as_slice()],
            )
            .map_err(db("set server relay"))?;
        if updated == 0 {
            return Err(GhostError::Database("server not found".into()));
        }
        Ok(())
    }

    /// Relay hosting a server; `None` for servers recorded before relays were tracked,
    /// which all live on the account's home relay.
    pub fn server_relay(&self, server_id: &[u8; 32]) -> Result<Option<[u8; 32]>> {
        let vk: Option<Option<Vec<u8>>> = self
            .conn
            .query_row(
                "SELECT relay_vk FROM servers WHERE server_id = ?1",
                [server_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(db("server relay"))?;
        match vk.flatten() {
            Some(bytes) => bytes
                .try_into()
                .map(Some)
                .map_err(|_| GhostError::Database("server relay_vk is not 32 bytes".into())),
            None => Ok(None),
        }
    }

    /// Generation of the newest server location record accepted for a server (0 if none).
    pub fn server_location_generation(&self, server_id: &[u8; 32]) -> Result<u64> {
        self.conn
            .query_row(
                "SELECT location_generation FROM servers WHERE server_id = ?1",
                [server_id.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .map(|g| g as u64)
            .map_err(db("server location generation"))
    }

    pub fn set_server_location_generation(&self, server_id: &[u8; 32], generation: u64) -> Result<()> {
        let updated = self
            .conn
            .execute(
                "UPDATE servers SET location_generation = ?2 WHERE server_id = ?1",
                rusqlite::params![server_id.as_slice(), generation as i64],
            )
            .map_err(db("set server location generation"))?;
        if updated == 0 {
            return Err(GhostError::Database("server not found".into()));
        }
        Ok(())
    }

    /// Every relay that hosts at least one of this account's servers.
    pub fn server_relays(&self) -> Result<Vec<RelayRef>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT r.relay_vk, r.ref_bytes FROM relays r
                 WHERE r.relay_vk IN (SELECT relay_vk FROM servers WHERE relay_vk IS NOT NULL)
                 ORDER BY r.relay_vk",
            )
            .map_err(db("server relays"))?;
        let rows = stmt
            .query_map([], |row| Ok((blob32(row, 0)?, row.get::<_, Vec<u8>>(1)?)))
            .map_err(db("server relays"))?;
        let mut refs = Vec::new();
        for row in rows {
            let (_vk, bytes) = row.map_err(db("server relay row"))?;
            refs.push(RelayRef::from_bytes(&bytes).map_err(|e| GhostError::Database(format!("stored relay ref: {e}")))?);
        }
        Ok(refs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{Server, ServerKind};

    fn store_with_server(server_id: [u8; 32]) -> GhostStore {
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        store
            .insert_server(&Server {
                server_id,
                name: "s".into(),
                kind: ServerKind::Server,
                created_at: 1,
            }, crate::storage::OnConflict::Fail)
            .unwrap();
        store
    }

    #[test]
    fn relay_upsert_replaces_endpoints() {
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        store.upsert_relay(&RelayRef::https([0x07; 32], "http://old"), 1).unwrap();
        store.upsert_relay(&RelayRef::https([0x07; 32], "http://new"), 2).unwrap();
        let got = store.get_relay(&[0x07; 32]).unwrap().unwrap();
        assert_eq!(got.primary_https_url(), Some("http://new"));
        assert!(store.get_relay(&[0x08; 32]).unwrap().is_none());
    }

    #[test]
    fn server_relay_roundtrip_and_listing() {
        let sid = [0x55; 32];
        let store = store_with_server(sid);
        assert_eq!(store.server_relay(&sid).unwrap(), None);

        let relay = RelayRef::https([0x07; 32], "http://foreign");
        store.upsert_relay(&relay, 1).unwrap();
        store.upsert_relay(&RelayRef::https([0x09; 32], "http://unused"), 1).unwrap();
        store.set_server_relay(&sid, &relay.relay_vk).unwrap();

        assert_eq!(store.server_relay(&sid).unwrap(), Some([0x07; 32]));
        assert_eq!(store.server_relays().unwrap(), vec![relay]);
        assert!(store.set_server_relay(&[0x66; 32], &[0x07; 32]).is_err());
    }

    #[test]
    fn server_location_generation_roundtrip() {
        let sid = [0x56; 32];
        let store = store_with_server(sid);
        assert_eq!(store.server_location_generation(&sid).unwrap(), 0);
        store.set_server_location_generation(&sid, 9).unwrap();
        assert_eq!(store.server_location_generation(&sid).unwrap(), 9);
        assert!(store.set_server_location_generation(&[0x67; 32], 1).is_err());
    }
}
