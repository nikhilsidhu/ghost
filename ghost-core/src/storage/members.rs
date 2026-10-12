use rusqlite::OptionalExtension;

use crate::error::Result;

use super::{blob32, db, GhostStore, Member, OnConflict};

fn opt_blob32(row: &rusqlite::Row, idx: usize) -> rusqlite::Result<Option<[u8; 32]>> {
    let bytes: Option<Vec<u8>> = row.get(idx)?;
    match bytes {
        None => Ok(None),
        Some(b) => {
            let arr: [u8; 32] = b.try_into().map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    idx,
                    rusqlite::types::Type::Blob,
                    "expected 32 bytes".into(),
                )
            })?;
            Ok(Some(arr))
        }
    }
}

impl GhostStore {
    pub fn insert_member(&self, member: &Member, on_conflict: OnConflict) -> Result<()> {
        self.conn
            .execute(
                &format!(
                    "{} INTO members (server_id, fingerprint, display_name, joined_at, avatar_hash, avatar_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    on_conflict.verb()
                ),
                rusqlite::params![
                    member.server_id.as_slice(),
                    member.fingerprint.as_slice(),
                    member.display_name,
                    member.joined_at,
                    member.avatar_hash.map(|h| h.to_vec()),
                    member.avatar_key.map(|k| k.to_vec()),
                ],
            )
            .map_err(db("insert member"))?;
        Ok(())
    }

    pub fn get_member(&self, server_id: &[u8; 32], fingerprint: &[u8; 32]) -> Result<Member> {
        self.conn
            .query_row(
                "SELECT server_id, fingerprint, display_name, joined_at, avatar_hash, avatar_key FROM members WHERE server_id = ?1 AND fingerprint = ?2",
                rusqlite::params![server_id.as_slice(), fingerprint.as_slice()],
                |row| {
                    Ok(RawMember {
                        server_id: blob32(row, 0)?,
                        fingerprint: blob32(row, 1)?,
                        display_name: row.get(2)?,
                        joined_at: row.get(3)?,
                        avatar_hash: opt_blob32(row, 4)?,
                        avatar_key: opt_blob32(row, 5)?,
                    })
                },
            )
            .map_err(db("get member"))
            .and_then(|r| r.into_member())
    }

    pub fn list_members(&self, server_id: &[u8; 32]) -> Result<Vec<Member>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT server_id, fingerprint, display_name, joined_at, avatar_hash, avatar_key FROM members WHERE server_id = ?1 ORDER BY joined_at",
            )
            .map_err(db("prepare list members"))?;

        let rows = stmt
            .query_map([server_id.as_slice()], |row| {
                Ok(RawMember {
                    server_id: blob32(row, 0)?,
                    fingerprint: blob32(row, 1)?,
                    display_name: row.get(2)?,
                    joined_at: row.get(3)?,
                    avatar_hash: opt_blob32(row, 4)?,
                    avatar_key: opt_blob32(row, 5)?,
                })
            })
            .map_err(db("list members"))?;

        let mut members = Vec::new();
        for row in rows {
            let raw = row.map_err(db("read member row"))?;
            members.push(raw.into_member()?);
        }
        Ok(members)
    }

    pub fn update_member_name(&self, server_id: &[u8; 32], fingerprint: &[u8; 32], name: &str) -> Result<()> {
        self.conn
            .execute(
                "UPDATE members SET display_name = ?1 WHERE server_id = ?2 AND fingerprint = ?3",
                rusqlite::params![name, server_id.as_slice(), fingerprint.as_slice()],
            )
            .map_err(db("update member name"))?;
        Ok(())
    }

    pub fn update_member_avatar(
        &self,
        server_id: &[u8; 32],
        fingerprint: &[u8; 32],
        avatar_hash: &[u8; 32],
        avatar_key: &[u8; 32],
    ) -> Result<()> {
        self.conn
            .execute(
                "UPDATE members SET avatar_hash = ?1, avatar_key = ?2 WHERE server_id = ?3 AND fingerprint = ?4",
                rusqlite::params![
                    avatar_hash.as_slice(),
                    avatar_key.as_slice(),
                    server_id.as_slice(),
                    fingerprint.as_slice(),
                ],
            )
            .map_err(db("update member avatar"))?;
        Ok(())
    }

    pub fn clear_member_avatar(
        &self,
        server_id: &[u8; 32],
        fingerprint: &[u8; 32],
    ) -> Result<()> {
        self.conn
            .execute(
                "UPDATE members SET avatar_hash = NULL, avatar_key = NULL WHERE server_id = ?1 AND fingerprint = ?2",
                rusqlite::params![server_id.as_slice(), fingerprint.as_slice()],
            )
            .map_err(db("clear member avatar"))?;
        Ok(())
    }

    pub fn get_member_avatar_key(
        &self,
        server_id: &[u8; 32],
        fingerprint: &[u8; 32],
    ) -> Result<Option<[u8; 32]>> {
        self.conn
            .query_row(
                "SELECT avatar_key FROM members WHERE server_id = ?1 AND fingerprint = ?2",
                rusqlite::params![server_id.as_slice(), fingerprint.as_slice()],
                |row| opt_blob32(row, 0),
            )
            .map_err(db("get member avatar key"))
    }

    /// Drop a member, keeping their name among the server's former members.
    pub fn remove_member(&self, server_id: &[u8; 32], fingerprint: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO former_members (server_id, fingerprint, display_name)
                 SELECT server_id, fingerprint, display_name FROM members WHERE server_id = ?1 AND fingerprint = ?2",
                rusqlite::params![server_id.as_slice(), fingerprint.as_slice()],
            )
            .map_err(db("keep former member"))?;
        self.conn
            .execute(
                "DELETE FROM members WHERE server_id = ?1 AND fingerprint = ?2",
                rusqlite::params![server_id.as_slice(), fingerprint.as_slice()],
            )
            .map_err(db("remove member"))?;
        Ok(())
    }

    /// The name a former member had when they left, if this device saw them.
    pub fn former_member_name(&self, server_id: &[u8; 32], fingerprint: &[u8; 32]) -> Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT display_name FROM former_members WHERE server_id = ?1 AND fingerprint = ?2",
                rusqlite::params![server_id.as_slice(), fingerprint.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(db("former member name"))
    }
}

struct RawMember {
    server_id: [u8; 32],
    fingerprint: [u8; 32],
    display_name: String,
    joined_at: u64,
    avatar_hash: Option<[u8; 32]>,
    avatar_key: Option<[u8; 32]>,
}

impl RawMember {
    fn into_member(self) -> Result<Member> {
        Ok(Member {
            server_id: self.server_id,
            fingerprint: self.fingerprint,
            display_name: self.display_name,
            joined_at: self.joined_at,
            avatar_hash: self.avatar_hash,
            avatar_key: self.avatar_key,
        })
    }
}
