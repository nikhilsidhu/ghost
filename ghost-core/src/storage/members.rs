use crate::error::{GhostError, Result};

use super::{blob32, GhostStore, Member, MemberRole};

impl GhostStore {
    pub fn insert_member(&self, member: &Member) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO members (group_id, fingerprint, display_name, role, joined_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    member.group_id.as_slice(),
                    member.fingerprint.as_slice(),
                    member.display_name,
                    member.role.as_str(),
                    member.joined_at,
                ],
            )
            .map_err(|e| GhostError::Database(format!("insert member: {e}")))?;
        Ok(())
    }

    pub fn get_member(&self, group_id: &[u8; 32], fingerprint: &[u8; 32]) -> Result<Member> {
        self.conn
            .query_row(
                "SELECT group_id, fingerprint, display_name, role, joined_at FROM members WHERE group_id = ?1 AND fingerprint = ?2",
                rusqlite::params![group_id.as_slice(), fingerprint.as_slice()],
                |row| {
                    Ok(RawMember {
                        group_id: blob32(row, 0)?,
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

    pub fn list_members(&self, group_id: &[u8; 32]) -> Result<Vec<Member>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT group_id, fingerprint, display_name, role, joined_at FROM members WHERE group_id = ?1 ORDER BY joined_at",
            )
            .map_err(|e| GhostError::Database(format!("prepare list members: {e}")))?;

        let rows = stmt
            .query_map([group_id.as_slice()], |row| {
                Ok(RawMember {
                    group_id: blob32(row, 0)?,
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

    pub fn remove_member(&self, group_id: &[u8; 32], fingerprint: &[u8; 32]) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM members WHERE group_id = ?1 AND fingerprint = ?2",
                rusqlite::params![group_id.as_slice(), fingerprint.as_slice()],
            )
            .map_err(|e| GhostError::Database(format!("remove member: {e}")))?;
        Ok(())
    }
}

struct RawMember {
    group_id: [u8; 32],
    fingerprint: [u8; 32],
    display_name: String,
    role_str: String,
    joined_at: u64,
}

impl RawMember {
    fn into_member(self) -> Result<Member> {
        Ok(Member {
            group_id: self.group_id,
            fingerprint: self.fingerprint,
            display_name: self.display_name,
            role: MemberRole::parse(&self.role_str)?,
            joined_at: self.joined_at,
        })
    }
}
