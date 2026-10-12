//! The parts of this account's profile a server has not been told: its members still see
//! the old name or avatar, and this device tells them the profile as it is then when the
//! server's mailbox next connects.

use super::{db, GhostStore};
use crate::error::Result;

/// A part of the profile a server is told as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfilePart {
    Name,
    Avatar,
}

impl ProfilePart {
    fn code(self) -> i64 {
        match self {
            Self::Name => 1,
            Self::Avatar => 2,
        }
    }

    fn from_code(code: i64) -> Option<Self> {
        match code {
            1 => Some(Self::Name),
            2 => Some(Self::Avatar),
            _ => None,
        }
    }
}

impl GhostStore {
    /// The server is owed `part` until it is told.
    pub fn owe_profile(&self, server_id: &[u8; 32], part: ProfilePart) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO profile_owed (server_id, part) VALUES (?1, ?2)",
                rusqlite::params![server_id.as_slice(), part.code()],
            )
            .map_err(db("owe profile"))?;
        Ok(())
    }

    /// The server was told `part`: nothing of it is owed any more.
    pub fn profile_told(&self, server_id: &[u8; 32], part: ProfilePart) -> Result<()> {
        self.conn
            .execute("DELETE FROM profile_owed WHERE server_id = ?1 AND part = ?2", rusqlite::params![server_id.as_slice(), part.code()])
            .map_err(db("profile told"))?;
        Ok(())
    }

    /// What the server is still owed.
    pub fn profile_owed(&self, server_id: &[u8; 32]) -> Result<Vec<ProfilePart>> {
        let mut stmt = self.conn.prepare("SELECT part FROM profile_owed WHERE server_id = ?1 ORDER BY part").map_err(db("profile owed"))?;
        let codes = stmt
            .query_map([server_id.as_slice()], |row| row.get::<_, i64>(0))
            .map_err(db("profile owed"))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db("profile owed"))?;
        Ok(codes.into_iter().filter_map(ProfilePart::from_code).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{OnConflict, Server, ServerKind};

    #[test]
    fn a_part_owed_stays_owed_until_told_and_goes_with_its_server() {
        let store = GhostStore::open_in_memory(&[0xAB; 32]).unwrap();
        let server_id = [1; 32];
        store.insert_server(&Server { server_id, name: "club".into(), kind: ServerKind::Server, created_at: 0 }, OnConflict::Fail).unwrap();
        store.owe_profile(&server_id, ProfilePart::Avatar).unwrap();
        store.owe_profile(&server_id, ProfilePart::Name).unwrap();
        store.owe_profile(&server_id, ProfilePart::Name).unwrap();
        assert_eq!(store.profile_owed(&server_id).unwrap(), vec![ProfilePart::Name, ProfilePart::Avatar]);

        store.profile_told(&server_id, ProfilePart::Name).unwrap();
        assert_eq!(store.profile_owed(&server_id).unwrap(), vec![ProfilePart::Avatar]);
        store.delete_server(&server_id).unwrap();
        assert!(store.profile_owed(&server_id).unwrap().is_empty(), "a server's debts go with it");
    }
}
