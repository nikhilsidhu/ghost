use crate::error::{GhostError, Result};

use super::{blob32, GhostStore, Member, MemberRole};

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
    pub fn insert_member(&self, member: &Member) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO members (server_id, fingerprint, display_name, role, joined_at, avatar_hash, avatar_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    member.server_id.as_slice(),
                    member.fingerprint.as_slice(),
                    member.display_name,
                    member.role.as_str(),
                    member.joined_at,
                    member.avatar_hash.map(|h| h.to_vec()),
                    member.avatar_key.map(|k| k.to_vec()),
                ],
            )
            .map_err(|e| GhostError::Database(format!("insert member: {e}")))?;
        Ok(())
    }

    pub fn get_member(&self, server_id: &[u8; 32], fingerprint: &[u8; 32]) -> Result<Member> {
        self.conn
            .query_row(
                "SELECT server_id, fingerprint, display_name, role, joined_at, avatar_hash, avatar_key FROM members WHERE server_id = ?1 AND fingerprint = ?2",
                rusqlite::params![server_id.as_slice(), fingerprint.as_slice()],
                |row| {
                    Ok(RawMember {
                        server_id: blob32(row, 0)?,
                        fingerprint: blob32(row, 1)?,
                        display_name: row.get(2)?,
                        role_str: row.get(3)?,
                        joined_at: row.get(4)?,
                        avatar_hash: opt_blob32(row, 5)?,
                        avatar_key: opt_blob32(row, 6)?,
                    })
                },
            )
            .map_err(|e| GhostError::Database(format!("get member: {e}")))
            .and_then(|r| r.into_member())
    }

    pub fn list_members(&self, server_id: &[u8; 32]) -> Result<Vec<Member>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT server_id, fingerprint, display_name, role, joined_at, avatar_hash, avatar_key FROM members WHERE server_id = ?1 ORDER BY joined_at",
            )
            .map_err(|e| GhostError::Database(format!("prepare list members: {e}")))?;

        let rows = stmt
            .query_map([server_id.as_slice()], |row| {
                Ok(RawMember {
                    server_id: blob32(row, 0)?,
                    fingerprint: blob32(row, 1)?,
                    display_name: row.get(2)?,
                    role_str: row.get(3)?,
                    joined_at: row.get(4)?,
                    avatar_hash: opt_blob32(row, 5)?,
                    avatar_key: opt_blob32(row, 6)?,
                })
            })
            .map_err(|e| GhostError::Database(format!("list members: {e}")))?;

        let mut members = Vec::new();
        for row in rows {
            let raw = row.map_err(|e| GhostError::Database(format!("read member row: {e}")))?;
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
            .map_err(|e| GhostError::Database(format!("update member name: {e}")))?;
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
            .map_err(|e| GhostError::Database(format!("update member avatar: {e}")))?;
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
            .map_err(|e| GhostError::Database(format!("clear member avatar: {e}")))?;
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
            .map_err(|e| GhostError::Database(format!("get member avatar key: {e}")))
    }

    pub fn remove_member(&self, server_id: &[u8; 32], fingerprint: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM members WHERE server_id = ?1 AND fingerprint = ?2",
                rusqlite::params![server_id.as_slice(), fingerprint.as_slice()],
            )
            .map_err(|e| GhostError::Database(format!("remove member: {e}")))?;
        Ok(())
    }
}

struct RawMember {
    server_id: [u8; 32],
    fingerprint: [u8; 32],
    display_name: String,
    role_str: String,
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
            role: MemberRole::parse(&self.role_str)?,
            joined_at: self.joined_at,
            avatar_hash: self.avatar_hash,
            avatar_key: self.avatar_key,
        })
    }
}
