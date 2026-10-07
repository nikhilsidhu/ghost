use serde::{Deserialize, Serialize};

use ghost_core::client::GhostClient;
use ghost_core::identity::Identity;
use ghost_core::storage::{Channel, ChannelKind, Server, Member, MemberRole, StoredMessage};
use ghost_core::wire::ApplicationMessage;

#[derive(Serialize)]
pub struct IdentityDto {
    pub fingerprint: String,
    pub fingerprint_short: String,
    pub display_name: String,
}

#[derive(Serialize)]
pub struct ServerDto {
    pub server_id: String,
    pub name: String,
    pub kind: String,
    pub creator_fp: String,
    /// Owner under the server's policy, who may do everything.
    pub owner_fp: String,
    /// This account's permission bits in the server (see `ghost_wire::policy`).
    pub permissions: u32,
    pub created_at: u64,
    pub has_unread: bool,
}

#[derive(Serialize)]
pub struct ChannelDto {
    pub channel_id: String,
    pub server_id: String,
    pub name: String,
    pub kind: String,
    pub position: i32,
    pub unread_count: u32,
    /// Only the members its policy admits can see it.
    pub private: bool,
}

#[derive(Serialize)]
pub struct MemberDto {
    pub server_id: String,
    pub fingerprint: String,
    pub display_name: String,
    pub role: String,
    pub joined_at: u64,
    /// Ids of the server roles assigned to this member, highest first.
    pub roles: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct RoleDto {
    pub id: u8,
    pub name: String,
    pub permissions: u32,
}

#[derive(Serialize, Deserialize)]
pub struct AssignmentDto {
    pub fingerprint: String,
    pub roles: Vec<u8>,
}

/// A server's policy with role names. Roles are listed by rank, highest first.
#[derive(Serialize, Deserialize)]
pub struct PolicyDto {
    pub owner_fp: String,
    pub everyone: u32,
    pub roles: Vec<RoleDto>,
    pub assignments: Vec<AssignmentDto>,
}

#[derive(Serialize)]
pub struct ServerRolesDto {
    pub policy: PolicyDto,
    pub my_permissions: u32,
    /// False while the server is still under the implicit policy of a group made
    /// before roles existed.
    pub explicit: bool,
    /// Members whose app must update before the server can have roles.
    pub members_missing_support: Vec<String>,
}

/// Who a private channel admits besides the server's channel managers.
#[derive(Serialize, Deserialize)]
pub struct ChannelAccessDto {
    pub roles: Vec<u8>,
    pub accounts: Vec<String>,
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

impl ServerDto {
    pub fn from_server(s: &Server, has_unread: bool, client: &GhostClient) -> Self {
        let policy = client.server_policy(&s.server_id).ok();
        let own = client.fingerprint();
        Self {
            server_id: hex::encode(s.server_id),
            name: s.name.clone(),
            kind: s.kind.as_str().to_string(),
            creator_fp: hex::encode(s.creator_fp),
            owner_fp: policy.as_ref().map(|p| hex::encode(p.owner)).unwrap_or_default(),
            permissions: policy.as_ref().map_or(0, |p| p.permissions(own)),
            created_at: s.created_at,
            has_unread,
        }
    }
}

impl ChannelDto {
    pub fn from_channel(c: &Channel, unread_count: u32, private: bool) -> Self {
        Self {
            channel_id: hex::encode(c.channel_id),
            server_id: hex::encode(c.server_id),
            name: c.name.clone(),
            kind: match c.kind {
                ChannelKind::Text => "text",
                ChannelKind::Voice => "voice",
            }
            .to_string(),
            position: c.position,
            unread_count,
            private,
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
    pub vad_threshold: f32,
    pub input_gain: f32,
    pub status: String,
    pub status_message: Option<String>,
}

#[derive(Serialize)]
pub struct KeybindConfigDto {
    pub push_to_talk: Option<String>,
}

#[derive(Serialize)]
pub struct DeviceDto {
    pub device_key: String,
    pub label: String,
    pub added_at_seq: u64,
    pub is_active: bool,
    pub is_current: bool,
}

impl MemberDto {
    pub fn from_member(m: &Member, roles: Vec<u8>) -> Self {
        Self {
            server_id: hex::encode(m.server_id),
            fingerprint: hex::encode(m.fingerprint),
            display_name: m.display_name.clone(),
            role: match m.role {
                MemberRole::Creator => "creator",
                MemberRole::Member => "member",
            }
            .to_string(),
            joined_at: m.joined_at,
            roles,
        }
    }
}
