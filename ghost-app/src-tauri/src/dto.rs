use serde::Serialize;

use ghost_core::identity::Identity;
use ghost_core::storage::{Channel, ChannelKind, Group, Member, MemberRole};

#[derive(Serialize)]
pub struct IdentityDto {
    pub fingerprint: String,
    pub fingerprint_short: String,
    pub display_name: String,
}

#[derive(Serialize)]
pub struct GroupDto {
    pub group_id: String,
    pub name: String,
    pub creator_fp: String,
    pub created_at: u64,
}

#[derive(Serialize)]
pub struct ChannelDto {
    pub channel_id: String,
    pub group_id: String,
    pub name: String,
    pub kind: String,
    pub position: i32,
}

#[derive(Serialize)]
pub struct MemberDto {
    pub group_id: String,
    pub fingerprint: String,
    pub display_name: String,
    pub role: String,
    pub joined_at: u64,
}

impl From<&Identity> for IdentityDto {
    fn from(id: &Identity) -> Self {
        Self {
            fingerprint: hex::encode(id.fingerprint),
            fingerprint_short: id.fingerprint_short(),
            display_name: id.display_name.clone(),
        }
    }
}

impl From<&Group> for GroupDto {
    fn from(g: &Group) -> Self {
        Self {
            group_id: hex::encode(g.group_id),
            name: g.name.clone(),
            creator_fp: hex::encode(g.creator_fp),
            created_at: g.created_at,
        }
    }
}

impl From<&Channel> for ChannelDto {
    fn from(c: &Channel) -> Self {
        Self {
            channel_id: hex::encode(c.channel_id),
            group_id: hex::encode(c.group_id),
            name: c.name.clone(),
            kind: match c.kind {
                ChannelKind::Text => "text",
                ChannelKind::Voice => "voice",
            }
            .to_string(),
            position: c.position,
        }
    }
}

impl From<&Member> for MemberDto {
    fn from(m: &Member) -> Self {
        Self {
            group_id: hex::encode(m.group_id),
            fingerprint: hex::encode(m.fingerprint),
            display_name: m.display_name.clone(),
            role: match m.role {
                MemberRole::Creator => "creator",
                MemberRole::Member => "member",
            }
            .to_string(),
            joined_at: m.joined_at,
        }
    }
}
