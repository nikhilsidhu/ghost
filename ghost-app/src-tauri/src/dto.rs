use serde::Serialize;

use ghost_core::identity::Identity;
use ghost_core::storage::{Channel, ChannelKind, Group, Member, MemberRole, StoredMessage};
use ghost_core::wire::ApplicationMessage;

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
    pub has_unread: bool,
}

#[derive(Serialize)]
pub struct ChannelDto {
    pub channel_id: String,
    pub group_id: String,
    pub name: String,
    pub kind: String,
    pub position: i32,
    pub unread_count: u32,
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

impl GroupDto {
    pub fn from_group(g: &Group, has_unread: bool) -> Self {
        Self {
            group_id: hex::encode(g.group_id),
            name: g.name.clone(),
            creator_fp: hex::encode(g.creator_fp),
            created_at: g.created_at,
            has_unread,
        }
    }
}

impl ChannelDto {
    pub fn from_channel(c: &Channel, unread_count: u32) -> Self {
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
            unread_count,
        }
    }
}

#[derive(Clone, Serialize)]
pub struct MessageDto {
    pub message_id: String,
    pub channel_id: String,
    pub sender_fp: String,
    pub message_type: u8,
    pub timestamp: u64,
    pub received_at: u64,
    pub content: String,
}

impl MessageDto {
    pub fn from_incoming(msg: &ApplicationMessage, received_at: u64) -> Self {
        Self {
            message_id: hex::encode(msg.message_id),
            channel_id: hex::encode(msg.channel_id),
            sender_fp: hex::encode(msg.sender_fp),
            message_type: msg.message_type as u8,
            timestamp: msg.timestamp,
            received_at,
            content: String::from_utf8_lossy(&msg.content).into_owned(),
        }
    }
}

impl From<&StoredMessage> for MessageDto {
    fn from(m: &StoredMessage) -> Self {
        Self {
            message_id: hex::encode(m.message_id),
            channel_id: hex::encode(m.channel_id),
            sender_fp: hex::encode(m.sender_fp),
            message_type: m.message_type,
            timestamp: m.timestamp,
            received_at: m.received_at,
            content: String::from_utf8_lossy(&m.content).into_owned(),
        }
    }
}

#[derive(Serialize)]
pub struct InviteDto {
    pub token: String,
    pub link: String,
}

#[derive(Serialize)]
pub struct ConfigDto {
    pub display_name: Option<String>,
    pub relay_url: Option<String>,
    pub input_device: Option<String>,
    pub output_device: Option<String>,
    pub noise_suppression: String,
    pub agc: String,
    pub input_mode: String,
}

#[derive(Serialize)]
pub struct KeybindConfigDto {
    pub push_to_talk: Option<String>,
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
