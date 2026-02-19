use crate::error::{GhostError, Result};

use super::{blob32, GhostStore, Member, MemberRole};

impl GhostStore {
    pub fn insert_member(&self, member: &Member) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO members (server_id, fingerprint, display_name, role, joined_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    member.server_id.as_slice(),
                    member.fingerprint.as_slice(),
                    member.display_name,
                    member.role.as_str(),
                    member.joined_at,
                ],
            )
            .map_err(|e| GhostError::Database(format!("insert member: {e}")))?;
        Ok(())
    }

    pub fn get_member(&self, server_id: &[u8; 32], fingerprint: &[u8; 32]) -> Result<Member> {
        self.conn
            .query_row(
                "SELECT server_id, fingerprint, display_name, role, joined_at FROM members WHERE server_id = ?1 AND fingerprint = ?2",
                rusqlite::params![server_id.as_slice(), fingerprint.as_slice()],
                |row| {
                    Ok(RawMember {
                        server_id: blob32(row, 0)?,
                        fingerprint: blob32(row, 1)?,
                        display_name: row.get(2)?,
                        role_str: row.get(3)?,
                        joined_at: row.get(4)?,
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
                "SELECT server_id, fingerprint, display_name, role, joined_at FROM members WHERE server_id = ?1 ORDER BY joined_at",
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
}

impl RawMember {
    fn into_member(self) -> Result<Member> {
        Ok(Member {
            server_id: self.server_id,
            fingerprint: self.fingerprint,
            display_name: self.display_name,
            role: MemberRole::parse(&self.role_str)?,
            joined_at: self.joined_at,
        })
    }
}
