use openmls::prelude::{Credential, ProcessedMessageContent, Sender};

use crate::crypto::{
    DEFAULT_CHANNEL_TAG, GhostProvider, MessageType, MLS_GROUP_ID_TAG,
    PROTOCOL_VERSION,
};
use crate::error::{GhostError, Result};
use crate::idlog_cache::{CredentialClaim, DeviceStatus};
use crate::mls::group::GhostGroup;
use crate::storage::{ChannelKind, ServerKind};
use ghost_wire::bytes::{put_prefixed16, put_prefixed32, put_string, Reader};
use ghost_wire::policy::PolicyError;
use ghost_wire::policy_mls::{self, GroupFacts, ServerAt};
use ghost_wire::relay_ref::RelayRef;

const MAX_REFERENCES: usize = 255;

/// version + type + channel_id + sender_fp + timestamp + message_id + kt_head_hash + ref_count + content_len
const FIXED_HEADER_LEN: usize = 1 + 1 + 32 + 32 + 8 + 32 + 32 + 1 + 4;

/// Application-layer message — the plaintext unit before MLS encryption.
#[derive(Debug, Clone)]
pub struct ApplicationMessage {
    pub message_type: MessageType,
    pub channel_id: [u8; 32],
    pub sender_fp: [u8; 32],
    pub timestamp: u64,
    pub message_id: [u8; 32],
    /// Sender's view of their own identity log head hash (key transparency gossip).
    /// Receivers compare this against their cached copy to detect split-view attacks.
    pub kt_head_hash: [u8; 32],
    pub references: Vec<[u8; 32]>,
    pub content: Vec<u8>,
}

impl ApplicationMessage {
    pub fn new(
        message_type: MessageType,
        channel_id: [u8; 32],
        sender_fp: [u8; 32],
        timestamp: u64,
        kt_head_hash: [u8; 32],
        references: Vec<[u8; 32]>,
        content: Vec<u8>,
    ) -> Result<Self> {
        if references.len() > MAX_REFERENCES {
            return Err(GhostError::Format(format!(
                "too many references: {} (max {})",
                references.len(),
                MAX_REFERENCES
            )));
        }
        if content.len() > u32::MAX as usize {
            return Err(GhostError::Format("content exceeds u32::MAX".into()));
        }
        let message_id = derive_message_id(&channel_id, &sender_fp, timestamp, &content);
        Ok(Self {
            message_type,
            channel_id,
            sender_fp,
            timestamp,
            message_id,
            kt_head_hash,
            references,
            content,
        })
    }

    /// Serialize to wire format (big-endian).
    pub fn to_bytes(&self) -> Vec<u8> {
        let ref_count = self.references.len() as u8;
        let content_len = self.content.len() as u32;
        let total = FIXED_HEADER_LEN + (ref_count as usize * 32) + self.content.len();

        let mut buf = Vec::with_capacity(total);
        buf.push(PROTOCOL_VERSION);
        buf.push(self.message_type as u8);
        buf.extend_from_slice(&self.channel_id);
        buf.extend_from_slice(&self.sender_fp);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.message_id);
        buf.extend_from_slice(&self.kt_head_hash);
        buf.push(ref_count);
        for r in &self.references {
            buf.extend_from_slice(r);
        }
        buf.extend_from_slice(&content_len.to_be_bytes());
        buf.extend_from_slice(&self.content);
        buf
    }

    /// Deserialize from wire format.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);

        let version = r.u8()?;
        if version != PROTOCOL_VERSION {
            return Err(GhostError::Format(format!(
                "unsupported version: {version:#04x}"
            )));
        }

        let message_type = MessageType::try_from(r.u8()?)
            .map_err(|v| GhostError::Format(format!("unknown message type: {v:#04x}")))?;
        if message_type.is_local() {
            return Err(GhostError::Format(format!("message type {message_type:?} is made by receivers, never sent")));
        }

        let channel_id = r.array()?;
        let sender_fp = r.array()?;
        let timestamp = r.u64()?;
        let message_id = r.array()?;
        let kt_head_hash = r.array()?;

        let ref_count = r.u8()? as usize;
        let mut references = Vec::with_capacity(ref_count);
        for _ in 0..ref_count {
            references.push(r.array()?);
        }

        let content = r.prefixed32()?.to_vec();
        r.finish()?;

        let expected_id = derive_message_id(&channel_id, &sender_fp, timestamp, &content);
        if message_id != expected_id {
            return Err(GhostError::Format("message_id does not match content".into()));
        }

        Ok(Self {
            message_type,
            channel_id,
            sender_fp,
            timestamp,
            message_id,
            kt_head_hash,
            references,
            content,
        })
    }
}

pub fn derive_message_id(
    channel_id: &[u8; 32],
    sender_fp: &[u8; 32],
    timestamp: u64,
    content: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(channel_id);
    hasher.update(sender_fp);
    hasher.update(&timestamp.to_be_bytes());
    hasher.update(content);
    hasher.finalize().into()
}

pub fn derive_mls_group_id(server_id: &[u8; 32], channel_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(server_id);
    hasher.update(channel_id);
    hasher.update(MLS_GROUP_ID_TAG);
    hasher.finalize().into()
}

pub fn mls_group_mailbox_id(mls_group_id: &[u8]) -> [u8; 32] {
    ghost_wire::mls_group_mailbox_id(mls_group_id)
}

/// Mailbox of a server channel's MLS group, derivable without holding the group.
pub fn channel_mailbox_id(server_id: &[u8; 32], channel_id: &[u8; 32]) -> [u8; 32] {
    mls_group_mailbox_id(&derive_mls_group_id(server_id, channel_id))
}

pub fn derive_default_channel_id(server_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(server_id);
    hasher.update(DEFAULT_CHANNEL_TAG);
    hasher.finalize().into()
}

// --- InvitePayload: metadata + GroupInfo for external commit joins ---

#[derive(Clone)]
pub struct InviteMember {
    pub fingerprint: [u8; 32],
    pub display_name: String,
}

#[derive(Debug, Clone)]
pub struct InviteChannel {
    pub channel_id: [u8; 32],
    pub name: String,
    pub kind: ChannelKind,
    pub position: i32,
    /// GroupInfo for an external-commit join into the channel's group, when the payload
    /// carries one; invites leave it empty, as joiners read the server group's from the relay.
    pub group_info_bytes: Vec<u8>,
}

/// What an invite link opens: the server's public face and the grant that admits
/// the holder. Stored on the relay sealed under a key only the link carries.
#[derive(Clone)]
pub struct InvitePayload {
    pub server_id: [u8; 32],
    pub server_name: String,
    pub kind: ServerKind,
    pub members: Vec<InviteMember>,
    pub channels: Vec<InviteChannel>,
    pub role_names: Vec<(u8, String)>,
    pub grant: ghost_wire::policy::InviteGrant,
}

fn write_role_names(buf: &mut Vec<u8>, role_names: &[(u8, String)]) {
    buf.push(role_names.len() as u8);
    for (role_id, name) in role_names {
        buf.push(*role_id);
        put_string(buf, name);
    }
}

fn read_role_names(r: &mut Reader) -> Result<Vec<(u8, String)>> {
    let count = r.u8()? as usize;
    (0..count).map(|_| Ok((r.u8()?, r.string()?))).collect()
}

/// Names the invite payload in seal and open errors.
pub const INVITE_PAYLOAD_CONTEXT: &str = "invite payload";

/// Trailing `[len:2][RelayRef]` naming the relay that hosts a server; length 0
/// means the account's home relay.
fn write_relay_ref(buf: &mut Vec<u8>, relay_ref: Option<&RelayRef>) {
    put_prefixed16(buf, &relay_ref.map(RelayRef::to_bytes).unwrap_or_default());
}

/// Reads what `write_relay_ref` wrote.
fn read_relay_ref(r: &mut Reader) -> Result<Option<RelayRef>> {
    let bytes = r.prefixed16()?;
    if bytes.is_empty() {
        return Ok(None);
    }
    RelayRef::from_bytes(bytes).map(Some).map_err(|e| GhostError::Format(e.to_string()))
}

impl InvitePayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.server_id);
        put_string(&mut buf, &self.server_name);
        buf.push(self.kind.to_byte());

        buf.extend_from_slice(&(self.members.len() as u16).to_be_bytes());
        for m in &self.members {
            buf.extend_from_slice(&m.fingerprint);
            put_string(&mut buf, &m.display_name);
        }

        buf.extend_from_slice(&(self.channels.len() as u16).to_be_bytes());
        for c in &self.channels {
            buf.extend_from_slice(&c.channel_id);
            put_string(&mut buf, &c.name);
            buf.push(c.kind.to_byte());
            buf.extend_from_slice(&c.position.to_be_bytes());
            put_prefixed32(&mut buf, &c.group_info_bytes);
        }

        write_role_names(&mut buf, &self.role_names);
        put_prefixed16(&mut buf, &self.grant.to_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);

        let server_id = r.array()?;
        let server_name = r.string()?;
        let kind = ServerKind::from_byte(r.u8()?)?;

        let member_count = r.u16()? as usize;
        let mut members = Vec::with_capacity(member_count);
        for _ in 0..member_count {
            members.push(InviteMember {
                fingerprint: r.array()?,
                display_name: r.string()?,
            });
        }

        let channel_count = r.u16()? as usize;
        let mut channels = Vec::with_capacity(channel_count);
        for _ in 0..channel_count {
            channels.push(InviteChannel {
                channel_id: r.array()?,
                name: r.string()?,
                kind: ChannelKind::from_byte(r.u8()?)?,
                position: r.i32()?,
                group_info_bytes: r.prefixed32()?.to_vec(),
            });
        }

        let role_names = read_role_names(&mut r)?;
        let grant = ghost_wire::policy::InviteGrant::from_bytes(r.prefixed16()?)
            .map_err(|e| GhostError::Format(format!("invite grant: {e}")))?;

        r.finish()?;

        Ok(Self { server_id, server_name, kind, members, channels, role_names, grant })
    }
}

// --- Device sync ---

/// Sync message types sent between a user's devices.
#[repr(u8)]
pub enum SyncMessageType {
    /// A server joined, with what the other devices need to join it too. The `server:`
    /// state entry is the truth; this carries members' names, too large for state.
    ServerProvisioned = 0x01,
    /// A state change: `encode_mutation`.
    MutationSync = 0x04,
    /// A removal waits for the home: every device stops sending sync until it lands.
    /// Body: the device being removed.
    SyncPause = 0x06,
    /// The account's log changed through this device (a device linked or removed, the
    /// recovery key replaced, a new account key generation, the home moved): read it now.
    /// No body.
    AccountChanged = 0x07,
}

/// Result of taking in a sync blob.
#[derive(Debug)]
pub enum SyncReceiveResult {
    /// Opened: `[msg_type:1][payload...]`, with the sending device and its sequence
    /// number, and how many of its earlier messages are still missing.
    Application { plaintext: Vec<u8>, sender: [u8; 32], gap: u64 },
    /// A copy of a message this device already took in, or its own message back.
    Seen,
}

/// Encrypt a sync message with AES-256-GCM. Returns nonce || ciphertext.
pub fn sync_seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    crate::crypto::aead::seal(key, plaintext, "sync")
}

/// Decrypt a sync message (nonce || ciphertext).
pub fn sync_open(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    crate::crypto::aead::open(key, blob, "sync")
}

// --- Mutation sync wire format ---

pub const MUTATION_SET: u8 = 0x01;
pub const MUTATION_REMOVE: u8 = 0x02;
pub const SYNC_KEY_SERVER_ORDER: &str = "order:servers";
pub const SYNC_KEY_READ_PREFIX: &str = "read:";
pub const SYNC_KEY_DISPLAY_NAME: &str = "profile:display_name";
pub const SYNC_KEY_NOISE_SUPPRESSION: &str = "pref:noise_suppression";
pub const SYNC_KEY_AGC: &str = "pref:agc";
pub const SYNC_KEY_INPUT_MODE: &str = "pref:input_mode";
/// The voice activity threshold, a decimal number.
pub const SYNC_KEY_VAD_THRESHOLD: &str = "pref:vad_threshold";
/// The microphone gain, a decimal number.
pub const SYNC_KEY_INPUT_GAIN: &str = "pref:input_gain";
pub const SYNC_KEY_STATUS: &str = "status:current";
pub const SYNC_KEY_STATUS_MESSAGE: &str = "status:message";
pub const SYNC_KEY_SERVER_PREFIX: &str = "server:";

/// Encode a mutation: [op:1][ts:8 BE][key_len:2 BE][key bytes][value bytes]
pub fn encode_mutation(op: u8, ts: u64, key: &str, value: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 8 + 2 + key.len() + value.len());
    buf.push(op);
    buf.extend_from_slice(&ts.to_be_bytes());
    put_string(&mut buf, key);
    buf.extend_from_slice(value);
    buf
}

/// Decode a mutation. Returns (op, ts, key, value).
pub fn decode_mutation(data: &[u8]) -> Result<(u8, u64, String, Vec<u8>)> {
    let mut r = Reader::new(data);
    let op = r.u8()?;
    let ts = r.u64()?;
    let key = r.string()?;
    Ok((op, ts, key, r.rest().to_vec()))
}
/// One key of the sync state: its value (`None` for a tombstone) and the clock of the
/// write that set it.
pub type SyncEntry = (String, Option<Vec<u8>>, u64);

/// A device's sync state as carried in snapshots and provisions, with what it covers:
/// for each device whose messages it includes, the highest sequence number.
pub struct SyncDump {
    pub covered: Vec<([u8; 32], u64)>,
    pub entries: Vec<SyncEntry>,
}

/// The version a dump starts with.
const SYNC_DUMP_VERSION: u8 = 0xFE;
/// The value length that marks a deleted key.
const SYNC_TOMBSTONE: u16 = 0xFFFF;

/// Encode a sync state dump.
/// Wire: `[0xFE][covered:2 BE] covered × ([device_vk:32][high_seq:8])` then the entries as
/// `[count:2 BE]` and for each `[key_len:2 BE][key][ts:8 BE][value_len:2 BE][value]`,
/// value_len 0xFFFF = NULL tombstone.
pub fn encode_sync_dump(dump: &SyncDump) -> Result<Vec<u8>> {
    let mut buf = vec![SYNC_DUMP_VERSION];
    buf.extend_from_slice(&(dump.covered.len() as u16).to_be_bytes());
    for (device_vk, high) in &dump.covered {
        buf.extend_from_slice(device_vk);
        buf.extend_from_slice(&high.to_be_bytes());
    }
    buf.extend_from_slice(&encode_sync_state_dump(&dump.entries)?);
    Ok(buf)
}

pub fn decode_sync_dump(data: &[u8]) -> Result<SyncDump> {
    if data.first() != Some(&SYNC_DUMP_VERSION) {
        return Err(GhostError::Format("sync state from an older app; update every device".into()));
    }
    let mut r = Reader::new(&data[1..]);
    let count = r.u16()? as usize;
    let mut covered = Vec::with_capacity(count);
    for _ in 0..count {
        covered.push((r.array()?, r.u64()?));
    }
    Ok(SyncDump { covered, entries: decode_sync_state_dump(r.rest())? })
}
/// Encode the entries of a sync state dump.
/// Wire: [count:2 BE] then for each: [key_len:2 BE][key][ts:8 BE][value_len:2 BE][value]
/// value_len 0xFFFF = NULL tombstone.
pub fn encode_sync_state_dump(entries: &[SyncEntry]) -> Result<Vec<u8>> {
    if entries.len() >= SYNC_DUMP_VERSION as usize * 256 {
        return Err(GhostError::Format("too many sync entries for one dump".into()));
    }
    let mut buf = Vec::new();
    buf.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for (key, value, ts) in entries {
        put_string(&mut buf, key);
        buf.extend_from_slice(&ts.to_be_bytes());
        match value {
            Some(v) => {
                if v.len() >= SYNC_TOMBSTONE as usize {
                    return Err(GhostError::Format("sync value too large".into()));
                }
                put_prefixed16(&mut buf, v);
            }
            None => buf.extend_from_slice(&SYNC_TOMBSTONE.to_be_bytes()),
        }
    }
    Ok(buf)
}

/// Decode a sync state dump from provision blob.
pub fn decode_sync_state_dump(data: &[u8]) -> Result<Vec<SyncEntry>> {
    let mut r = Reader::new(data);
    let count = r.u16()? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let key = r.string()?;
        let ts = r.u64()?;
        let value = match r.u16()? {
            SYNC_TOMBSTONE => None,
            len => Some(r.take(len as usize)?.to_vec()),
        };
        entries.push((key, value, ts));
    }
    r.finish()?;
    Ok(entries)
}
// --- Provision payload: server metadata for device provisioning ---

pub struct ProvisionPayload {
    pub server_id: [u8; 32],
    pub server_name: String,
    pub kind: ServerKind,
    pub members: Vec<InviteMember>,
    pub channels: Vec<InviteChannel>,
    pub mailbox_id: [u8; 32],
    /// Relay hosting the server; `None` for the account's home relay.
    pub relay_ref: Option<RelayRef>,
    pub role_names: Vec<(u8, String)>,
}

impl ProvisionPayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.server_id);
        put_string(&mut buf, &self.server_name);
        buf.push(self.kind.to_byte());

        buf.extend_from_slice(&(self.members.len() as u16).to_be_bytes());
        for m in &self.members {
            buf.extend_from_slice(&m.fingerprint);
            put_string(&mut buf, &m.display_name);
        }

        buf.extend_from_slice(&(self.channels.len() as u16).to_be_bytes());
        for c in &self.channels {
            buf.extend_from_slice(&c.channel_id);
            put_string(&mut buf, &c.name);
            buf.push(c.kind.to_byte());
            buf.extend_from_slice(&c.position.to_be_bytes());
        }

        buf.extend_from_slice(&self.mailbox_id);
        write_relay_ref(&mut buf, self.relay_ref.as_ref());
        write_role_names(&mut buf, &self.role_names);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);

        let server_id = r.array()?;
        let server_name = r.string()?;
        let kind = ServerKind::from_byte(r.u8()?)?;

        let member_count = r.u16()? as usize;
        let mut members = Vec::with_capacity(member_count);
        for _ in 0..member_count {
            members.push(InviteMember {
                fingerprint: r.array()?,
                display_name: r.string()?,
            });
        }

        let channel_count = r.u16()? as usize;
        let mut channels = Vec::with_capacity(channel_count);
        for _ in 0..channel_count {
            channels.push(InviteChannel {
                channel_id: r.array()?,
                name: r.string()?,
                kind: ChannelKind::from_byte(r.u8()?)?,
                position: r.i32()?,
                group_info_bytes: vec![],
            });
        }

        let mailbox_id = r.array()?;
        let relay_ref = read_relay_ref(&mut r)?;
        let role_names = read_role_names(&mut r)?;

        r.finish()?;

        Ok(Self { server_id, server_name, kind, members, channels, mailbox_id, relay_ref, role_names })
    }
}

// --- Sync server metadata: lightweight group entry for sync_state (no members) ---

#[derive(Debug, Clone)]
pub struct SyncServerMeta {
    pub server_name: String,
    pub kind: ServerKind,
    pub mailbox_id: [u8; 32],
    pub channels: Vec<InviteChannel>,
    /// Relay hosting the server; `None` for the account's home relay.
    pub relay_ref: Option<RelayRef>,
    pub role_names: Vec<(u8, String)>,
    /// The account's removal from the server, once it happened: the server stays listed,
    /// read-only. Encoded last; absent means not removed.
    pub removal: Option<SyncRemoval>,
}

/// The account was removed from a server, by whom when the device that saw it knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncRemoval {
    pub by: Option<[u8; 32]>,
}

/// Tags of the removal at the end of a server entry.
const SYNC_REMOVED_BY_UNKNOWN: u8 = 1;
const SYNC_REMOVED_BY: u8 = 2;

impl SyncServerMeta {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        put_string(&mut buf, &self.server_name);
        buf.push(self.kind.to_byte());
        buf.extend_from_slice(&self.mailbox_id);
        buf.extend_from_slice(&(self.channels.len() as u16).to_be_bytes());
        for c in &self.channels {
            buf.extend_from_slice(&c.channel_id);
            put_string(&mut buf, &c.name);
            buf.push(c.kind.to_byte());
            buf.extend_from_slice(&c.position.to_be_bytes());
        }
        write_relay_ref(&mut buf, self.relay_ref.as_ref());
        write_role_names(&mut buf, &self.role_names);
        match self.removal {
            None => {}
            Some(SyncRemoval { by: None }) => buf.push(SYNC_REMOVED_BY_UNKNOWN),
            Some(SyncRemoval { by: Some(by) }) => {
                buf.push(SYNC_REMOVED_BY);
                buf.extend_from_slice(&by);
            }
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = Reader::new(data);
        let server_name = r.string()?;
        let kind = ServerKind::from_byte(r.u8()?)?;
        let mailbox_id = r.array()?;
        let channel_count = r.u16()? as usize;
        let mut channels = Vec::with_capacity(channel_count);
        for _ in 0..channel_count {
            channels.push(InviteChannel {
                channel_id: r.array()?,
                name: r.string()?,
                kind: ChannelKind::from_byte(r.u8()?)?,
                position: r.i32()?,
                group_info_bytes: vec![],
            });
        }
        let relay_ref = read_relay_ref(&mut r)?;
        let role_names = read_role_names(&mut r)?;
        let removal = match (!r.is_empty()).then(|| r.u8()).transpose()? {
            None => None,
            Some(SYNC_REMOVED_BY_UNKNOWN) => Some(SyncRemoval { by: None }),
            Some(SYNC_REMOVED_BY) => Some(SyncRemoval { by: Some(r.array()?) }),
            Some(tag) => return Err(GhostError::Format(format!("server entry: unknown removal tag {tag}"))),
        };
        r.finish()?;

        Ok(Self { server_name, kind, mailbox_id, channels, relay_ref, role_names, removal })
    }
}

// --- Channel operation payloads (carried in Metadata messages) ---

pub enum ChannelOpPayload {
    Create { channel_id: [u8; 32], name: String, kind: ChannelKind, position: i32 },
    Rename { channel_id: [u8; 32], name: String },
    Delete { channel_id: [u8; 32] },
    /// Sent inside a private channel by a device that just joined it: it cannot read
    /// anything from before its join, so members answer with `Create`.
    InfoRequest { channel_id: [u8; 32] },
    /// Where the server's public channels go, from a member who may manage them: each
    /// with its place in the whole list, which every device then stores as sent. Private
    /// channels take their place through their own groups.
    Reorder { positions: Vec<([u8; 32], i32)> },
}

const CHANNEL_OP_CREATE: u8 = 0x01;
const CHANNEL_OP_RENAME: u8 = 0x02;
const CHANNEL_OP_DELETE: u8 = 0x03;
const CHANNEL_OP_INFO_REQUEST: u8 = 0x04;
const CHANNEL_OP_REORDER: u8 = 0x05;

/// What a private channel is called until a member tells a newly joined device.
pub const UNNAMED_PRIVATE_CHANNEL: &str = "private channel";

pub fn encode_channel_op(op: &ChannelOpPayload) -> Vec<u8> {
    let mut buf = Vec::new();
    match op {
        ChannelOpPayload::Create { channel_id, name, kind, position } => {
            buf.push(CHANNEL_OP_CREATE);
            buf.extend_from_slice(channel_id);
            buf.push(kind.to_byte());
            buf.extend_from_slice(&position.to_be_bytes());
            put_string(&mut buf, name);
        }
        ChannelOpPayload::Rename { channel_id, name } => {
            buf.push(CHANNEL_OP_RENAME);
            buf.extend_from_slice(channel_id);
            put_string(&mut buf, name);
        }
        ChannelOpPayload::Delete { channel_id } => {
            buf.push(CHANNEL_OP_DELETE);
            buf.extend_from_slice(channel_id);
        }
        ChannelOpPayload::InfoRequest { channel_id } => {
            buf.push(CHANNEL_OP_INFO_REQUEST);
            buf.extend_from_slice(channel_id);
        }
        ChannelOpPayload::Reorder { positions } => {
            buf.push(CHANNEL_OP_REORDER);
            buf.extend_from_slice(&(positions.len() as u16).to_be_bytes());
            for (channel_id, position) in positions {
                buf.extend_from_slice(channel_id);
                buf.extend_from_slice(&position.to_be_bytes());
            }
        }
    }
    buf
}

pub fn decode_channel_op(data: &[u8]) -> Result<ChannelOpPayload> {
    let mut r = Reader::new(data);
    let op = r.u8()?;
    match op {
        CHANNEL_OP_CREATE => {
            let channel_id = r.array()?;
            let kind = ChannelKind::from_byte(r.u8()?)?;
            let position = r.i32()?;
            let name = r.string()?;
            Ok(ChannelOpPayload::Create { channel_id, name, kind, position })
        }
        CHANNEL_OP_RENAME => {
            let channel_id = r.array()?;
            let name = r.string()?;
            Ok(ChannelOpPayload::Rename { channel_id, name })
        }
        CHANNEL_OP_DELETE => {
            let channel_id = r.array()?;
            Ok(ChannelOpPayload::Delete { channel_id })
        }
        CHANNEL_OP_INFO_REQUEST => {
            let channel_id = r.array()?;
            Ok(ChannelOpPayload::InfoRequest { channel_id })
        }
        CHANNEL_OP_REORDER => {
            let count = r.u16()?;
            let positions = (0..count).map(|_| Ok((r.array()?, r.i32()?))).collect::<Result<Vec<_>>>()?;
            Ok(ChannelOpPayload::Reorder { positions })
        }
        _ => Err(GhostError::Format(format!("unknown channel op: {op:#04x}"))),
    }
}

// --- Member announce payload (carried in Metadata messages) ---

const MEMBER_ANNOUNCE: u8 = 0x10;
const AVATAR_UPDATE: u8 = 0x11;
const AVATAR_CLEAR: u8 = 0x12;
const SERVER_MOVED: u8 = 0x13;
const ROLE_NAMES: u8 = 0x14;
const SERVER_STATE_REQUEST: u8 = 0x15;
const SERVER_STATE: u8 = 0x16;

/// The server as a member who may manage its channels holds it, answering a joiner: its
/// invite payload is from when the invite was made, and it cannot read the messages that
/// changed the server before its join.
#[derive(Clone)]
pub struct ServerStatePayload {
    /// The sequence of the request answered; the state is as of it.
    pub request_seq: u64,
    /// The public channels; private ones are found through discovery.
    pub channels: Vec<InviteChannel>,
    pub role_names: Vec<(u8, String)>,
    /// The members whose names the answering device knows.
    pub members: Vec<InviteMember>,
}

/// A joiner asks the server's members for the server's current state.
pub fn encode_server_state_request() -> Vec<u8> {
    vec![SERVER_STATE_REQUEST]
}

pub fn encode_server_state(state: &ServerStatePayload) -> Vec<u8> {
    let mut buf = vec![SERVER_STATE];
    buf.extend_from_slice(&state.request_seq.to_be_bytes());
    buf.extend_from_slice(&(state.channels.len() as u16).to_be_bytes());
    for c in &state.channels {
        buf.extend_from_slice(&c.channel_id);
        put_string(&mut buf, &c.name);
        buf.push(c.kind.to_byte());
        buf.extend_from_slice(&c.position.to_be_bytes());
    }
    write_role_names(&mut buf, &state.role_names);
    buf.extend_from_slice(&(state.members.len() as u16).to_be_bytes());
    for m in &state.members {
        buf.extend_from_slice(&m.fingerprint);
        put_string(&mut buf, &m.display_name);
    }
    buf
}

fn decode_server_state(data: &[u8]) -> Result<ServerStatePayload> {
    let mut r = Reader::new(data);
    let request_seq = r.u64()?;
    let channel_count = r.u16()? as usize;
    let mut channels = Vec::with_capacity(channel_count);
    for _ in 0..channel_count {
        channels.push(InviteChannel {
            channel_id: r.array()?,
            name: r.string()?,
            kind: ChannelKind::from_byte(r.u8()?)?,
            position: r.i32()?,
            group_info_bytes: Vec::new(),
        });
    }
    let role_names = read_role_names(&mut r)?;
    let member_count = r.u16()? as usize;
    let mut members = Vec::with_capacity(member_count);
    for _ in 0..member_count {
        members.push(InviteMember { fingerprint: r.array()?, display_name: r.string()? });
    }
    r.finish()?;
    Ok(ServerStatePayload { request_seq, channels, role_names, members })
}

/// Roles' display names. Roles live in the server policy, which the relay can read, so
/// their names travel only in encrypted metadata like this, all of them at once.
pub fn encode_role_names(names: &[(u8, String)]) -> Vec<u8> {
    let mut buf = vec![ROLE_NAMES];
    write_role_names(&mut buf, names);
    buf
}

/// The server's creator announces that the server now lives on another relay.
pub fn encode_server_moved(location: &ghost_wire::server_location::ServerLocation) -> Vec<u8> {
    let mut buf = vec![SERVER_MOVED];
    buf.extend_from_slice(&location.to_bytes());
    buf
}

pub fn encode_member_announce(display_name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(MEMBER_ANNOUNCE);
    put_string(&mut buf, display_name);
    buf
}

pub fn encode_avatar_update(avatar_hash: &[u8; 32], avatar_key: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 32 + 32);
    buf.push(AVATAR_UPDATE);
    buf.extend_from_slice(avatar_hash);
    buf.extend_from_slice(avatar_key);
    buf
}

pub fn encode_avatar_clear() -> Vec<u8> {
    vec![AVATAR_CLEAR]
}

/// Decode a Metadata payload.
pub fn decode_metadata(data: &[u8]) -> Result<MetadataPayload> {
    let tag = *data.first().ok_or_else(|| GhostError::Format("empty metadata".into()))?;
    match tag {
        CHANNEL_OP_CREATE | CHANNEL_OP_RENAME | CHANNEL_OP_DELETE | CHANNEL_OP_INFO_REQUEST | CHANNEL_OP_REORDER => {
            Ok(MetadataPayload::ChannelOp(decode_channel_op(data)?))
        }
        ROLE_NAMES => Ok(MetadataPayload::RoleNames(read_role_names(&mut Reader::new(&data[1..]))?)),
        SERVER_STATE_REQUEST => Ok(MetadataPayload::ServerStateRequest),
        SERVER_STATE => Ok(MetadataPayload::ServerState(decode_server_state(&data[1..])?)),
        MEMBER_ANNOUNCE => Ok(MetadataPayload::MemberAnnounce { display_name: Reader::new(&data[1..]).string()? }),
        AVATAR_UPDATE => {
            let mut r = Reader::new(&data[1..]);
            Ok(MetadataPayload::AvatarUpdate { avatar_hash: r.array()?, avatar_key: r.array()? })
        }
        AVATAR_CLEAR => Ok(MetadataPayload::AvatarClear),
        SERVER_MOVED => ghost_wire::server_location::ServerLocation::from_bytes(&data[1..])
            .map(MetadataPayload::ServerMoved)
            .map_err(|e| GhostError::Format(e.to_string())),
        _ => Err(GhostError::Format(format!("unknown metadata tag: {tag:#04x}"))),
    }
}

pub enum MetadataPayload {
    ChannelOp(ChannelOpPayload),
    MemberAnnounce { display_name: String },
    AvatarUpdate { avatar_hash: [u8; 32], avatar_key: [u8; 32] },
    AvatarClear,
    /// Only meaningful from the server's owner; receivers verify the record.
    ServerMoved(ghost_wire::server_location::ServerLocation),
    /// Only meaningful from a member who may manage roles.
    RoleNames(Vec<(u8, String)>),
    /// From a joiner, for the server's current state.
    ServerStateRequest,
    /// Only meaningful from a member who may manage channels, to a device that asked.
    ServerState(ServerStatePayload),
}

// --- open_any: handle both app messages and commits from the relay ---

pub enum InboundMessage {
    Application(ApplicationMessage),
    /// A commit was merged: the members it removed (fingerprints) and the account that
    /// made it.
    Commit { removed: Vec<[u8; 32]>, committer: [u8; 32] },
    /// A proposal was queued (e.g. relay-generated Remove). Pending proposals
    /// should be committed by the group creator to advance the epoch.
    ProposalProcessed,
}

/// Extract account fingerprint and device verifying key from MLS sender info.
fn extract_sender_identity(
    group: &GhostGroup,
    credential: &Credential,
    sender: &Sender,
) -> Result<([u8; 32], [u8; 32])> {
    let account_fp = crate::mls::credential::parse_credential(credential)?.account_fp;

    let leaf_index = match sender {
        Sender::Member(idx) => idx.u32(),
        Sender::External(_) => return Err(GhostError::Mls("external sender".into())),
        _ => return Err(GhostError::Mls("unexpected sender type".into())),
    };

    let device_vk = group
        .members()
        .find(|m| m.index.u32() == leaf_index)
        .map(|m| {
            <[u8; 32]>::try_from(m.signature_key.as_slice()).map_err(|_| {
                GhostError::Format("member signature key is not 32 bytes".into())
            })
        })
        .ok_or_else(|| GhostError::Mls("sender leaf not found in group".into()))??;

    Ok((account_fp, device_vk))
}

/// What the receiver's identity log says about the device a credential claims to be.
pub type DeviceLookup<'a> = &'a dyn Fn(&CredentialClaim) -> DeviceStatus;

/// What a receiver checks a commit against beyond MLS itself, so every member
/// enforces the rules the relay enforces and a relay cannot slip a forbidden
/// change past them.
pub struct CommitChecks<'a> {
    pub devices: DeviceLookup<'a>,
    /// The group's mailbox, which invite grants for it name.
    pub mailbox: [u8; 32],
    /// When the relay received the commit, against which invite grants expire.
    pub received_at: u64,
    /// The server group's view at a given epoch of it, for private channel commits.
    pub server_at: ServerAt<'a>,
}

/// Decide a received commit under the group's policy, as the relay did.
pub(crate) fn check_policy(
    group: &GhostGroup,
    sender: &Sender,
    staged: &openmls::prelude::StagedCommit,
    aad: &[u8],
    checks: &CommitChecks,
) -> Result<()> {
    let members: Vec<openmls::prelude::Member> = group.members().collect();
    let facts = GroupFacts {
        extensions: group.context_extensions(),
        members: &members,
        mailbox: checks.mailbox,
        now_millis: checks.received_at,
    };
    policy_mls::check_commit(sender, staged, aad, &facts, checks.server_at).map_err(|e| match e {
        PolicyError::ContextBehind { server_mailbox, epoch } => GhostError::PolicyBehind { server_mailbox, epoch },
        other => GhostError::PolicyRefused(other.to_string()),
    })
}

/// The claim a credential makes for the device holding `device_vk`.
pub(crate) fn claim_of(credential: &Credential, device_vk: &[u8; 32]) -> Result<CredentialClaim> {
    let parsed = crate::mls::credential::parse_credential(credential)?;
    Ok(CredentialClaim {
        account_fp: parsed.account_fp,
        device_vk: *device_vk,
        add_seq: parsed.add_seq,
        add_entry_hash: parsed.add_entry_hash,
    })
}

/// Accept a device only if the account's identity log lists it as active, added by
/// the entry its credential names. A credential proves nothing by itself, so a device
/// the receiver's log does not list yet is not accepted: the caller fetches the
/// account's log and asks again.
fn validate_device_credential(credential: &Credential, device_vk: &[u8; 32], devices: DeviceLookup) -> Result<()> {
    let claim = claim_of(credential, device_vk)?;
    match devices(&claim) {
        DeviceStatus::Active => Ok(()),
        DeviceStatus::Revoked => Err(GhostError::SenderRefused("sender device has been revoked".into())),
        DeviceStatus::Unknown => Err(GhostError::UnknownDevice { account_fp: claim.account_fp }),
        DeviceStatus::Contradicted => Err(GhostError::SenderRefused(
            "sender's credential names a different identity log entry than its account's log holds; possible fork".into(),
        )),
    }
}

/// Extract account fingerprint and device key from a leaf node's credential.
fn extract_leaf_identity(leaf: &openmls::prelude::LeafNode) -> Result<([u8; 32], [u8; 32])> {
    let account_fp = crate::mls::credential::parse_credential(leaf.credential())?.account_fp;
    let device_vk: [u8; 32] = leaf.signature_key().as_slice().try_into()
        .map_err(|_| GhostError::Format("signature key is not 32 bytes".into()))?;
    Ok((account_fp, device_vk))
}

/// Check every device a message or commit vouches for against the identity logs: its
/// sender, and for a commit the members it adds.
pub(crate) fn validate_sender(
    group: &GhostGroup,
    credential: &Credential,
    sender: &Sender,
    staged_commit: Option<&openmls::prelude::StagedCommit>,
    devices: DeviceLookup,
) -> Result<()> {
    match sender {
        Sender::Member(_) => {
            let (_account_fp, device_vk) = extract_sender_identity(group, credential, sender)?;
            validate_device_credential(credential, &device_vk, devices)?;
        }
        Sender::NewMemberCommit => {
            let staged = staged_commit
                .ok_or_else(|| GhostError::Mls("NewMemberCommit without staged commit".into()))?;
            let leaf = staged.update_path_leaf_node()
                .ok_or_else(|| GhostError::Mls("external commit missing update path".into()))?;
            let (_account_fp, device_vk) = extract_leaf_identity(leaf)?;
            validate_device_credential(leaf.credential(), &device_vk, devices)?;
        }
        Sender::External(_) => {}
        Sender::NewMemberProposal => {}
    }

    if let Some(staged) = staged_commit {
        for add in staged.add_proposals() {
            let leaf = add.add_proposal().key_package().leaf_node();
            let (_fp, vk) = extract_leaf_identity(leaf)?;
            validate_device_credential(leaf.credential(), &vk, devices)?;
        }
    }

    Ok(())
}

/// Process an inbound blob that could be an application message or a commit.
/// Strips the envelope header, then decrypts. App messages are returned;
/// commits are merged into the group automatically. Every device involved is checked
/// against the identity logs; a message from, or a commit naming, a device the
/// receiver's log does not list fails with `UnknownDevice`, a commit before merging,
/// so it can be processed again once the log is fetched. The caller rolls a message's
/// decryption back, so its key is still unspent then.
pub fn open_any(
    group: &mut GhostGroup,
    provider: &GhostProvider,
    blob: &[u8],
    checks: &CommitChecks,
) -> Result<InboundMessage> {
    ghost_wire::decode_envelope(blob)
        .map_err(|e| GhostError::Format(format!("envelope: {e}")))?;
    let mls_bytes = ghost_wire::envelope_payload(blob);
    let processed = group.process_message_bytes(provider, mls_bytes)?;
    let credential = processed.credential().clone();
    let sender = processed.sender().clone();
    let aad = processed.aad().to_vec();
    let devices = checks.devices;

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => {
            let sender_account_fp = crate::mls::credential::parse_credential(&credential)?.account_fp;
            let msg = ApplicationMessage::from_bytes(&app_msg.into_bytes())?;
            if msg.sender_fp != sender_account_fp {
                return Err(GhostError::Format(
                    "sender_fp does not match MLS credential".into(),
                ));
            }

            validate_sender(group, &credential, &sender, None, devices)?;
            Ok(InboundMessage::Application(msg))
        }
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            validate_sender(group, &credential, &sender, Some(&staged_commit), devices)?;
            check_policy(group, &sender, &staged_commit, &aad, checks)?;

            let removed = extract_removed_fps(group, &staged_commit);
            let committer = crate::mls::credential::parse_credential(&credential)?.account_fp;
            group.merge_staged_commit(provider, *staged_commit)?;
            Ok(InboundMessage::Commit { removed, committer })
        }
        ProcessedMessageContent::ProposalMessage(proposal) => {
            // Which proposals a commit may include is decided when committing.
            group.store_pending_proposal(provider, *proposal)?;
            Ok(InboundMessage::ProposalProcessed)
        }
        ProcessedMessageContent::ExternalJoinProposalMessage(_proposal) => {
            Ok(InboundMessage::ProposalProcessed)
        }
    }
}

/// Read remove proposals from a staged commit, resolve leaf indices to fingerprints.
fn extract_removed_fps(group: &GhostGroup, staged: &openmls::prelude::StagedCommit) -> Vec<[u8; 32]> {
    use std::collections::HashMap;
    let member_map: HashMap<u32, [u8; 32]> = group
        .members()
        .filter_map(|m| {
            crate::mls::credential::parse_credential(&m.credential)
                .ok()
                .map(|pc| (m.index.u32(), pc.account_fp))
        })
        .collect();

    staged
        .remove_proposals()
        .filter_map(|rp| {
            let idx = rp.remove_proposal().removed().u32();
            member_map.get(&idx).copied()
        })
        .collect()
}

/// Encrypted blob addressed to a relay mailbox.
pub struct Outbound {
    pub channel_id: [u8; 32],
    pub mailbox_id: [u8; 32],
    pub blob: Vec<u8>,
}

/// Serialize an ApplicationMessage, MLS-encrypt it, and prepend an envelope header.
pub fn seal(
    group: &mut GhostGroup,
    provider: &GhostProvider,
    msg: &ApplicationMessage,
) -> Result<Vec<u8>> {
    let plaintext = msg.to_bytes();
    let mls_out = group.encrypt(provider, &plaintext)?;
    let mls_bytes = mls_out
        .to_bytes()
        .map_err(|e| GhostError::Mls(format!("serialize ciphertext: {e}")))?;
    let header = ghost_wire::encode_envelope(ghost_wire::EnvelopeType::Application, group.epoch());
    let mut out = Vec::with_capacity(ghost_wire::ENVELOPE_HEADER_SIZE + mls_bytes.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&mls_bytes);
    Ok(out)
}

/// Strip envelope header, MLS-decrypt, and deserialize into an ApplicationMessage,
/// accepting it only from a device the identity logs list as active.
pub fn open(
    group: &mut GhostGroup,
    provider: &GhostProvider,
    blob: &[u8],
    devices: DeviceLookup,
) -> Result<ApplicationMessage> {
    ghost_wire::decode_envelope(blob)
        .map_err(|e| GhostError::Format(format!("envelope: {e}")))?;
    let mls_bytes = ghost_wire::envelope_payload(blob);
    let processed = group.process_message_bytes(provider, mls_bytes)?;

    let credential = processed.credential().clone();
    let sender = processed.sender().clone();
    let sender_account_fp = crate::mls::credential::parse_credential(&credential)?.account_fp;

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => {
            let msg = ApplicationMessage::from_bytes(&app_msg.into_bytes())?;
            if msg.sender_fp != sender_account_fp {
                return Err(GhostError::Format("sender_fp does not match MLS credential".into()));
            }
            validate_sender(group, &credential, &sender, None, devices)?;
            Ok(msg)
        }
        _ => Err(GhostError::Mls("expected application message".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    const MESSAGE_ID_OFFSET: usize = 1 + 1 + 32 + 32 + 8;

    /// A lookup for tests without identity logs: every device is active.
    fn all_active(_: &CredentialClaim) -> DeviceStatus {
        DeviceStatus::Active
    }

    /// Two members of one group: A made it and took in B's external join.
    fn two_member_group() -> (GhostProvider, GhostGroup, GhostProvider, GhostGroup, Identity, Identity) {
        let provider_a = GhostProvider::new_in_memory().unwrap();
        let provider_b = GhostProvider::new_in_memory().unwrap();
        let id_a = Identity::from_seed([0x01; 32]).unwrap();
        let id_b = Identity::from_seed([0x02; 32]).unwrap();
        let server_id = [0x42; 32];
        let channel_id = derive_default_channel_id(&server_id);
        let mut group_a = GhostGroup::create(&provider_a, &id_a, &server_id, &channel_id, None, None).unwrap();
        let group_info = group_a.export_group_info(&provider_a).unwrap();
        let (group_b, commit) =
            GhostGroup::join_by_external_commit(&provider_b, &id_b, &group_info, &ghost_wire::policy::CommitAad::default()).unwrap();
        let processed = group_a.process_message_bytes(&provider_a, &commit[ghost_wire::ENVELOPE_HEADER_SIZE..]).unwrap();
        match processed.into_content() {
            openmls::prelude::ProcessedMessageContent::StagedCommitMessage(staged) => {
                group_a.merge_staged_commit(&provider_a, *staged).unwrap()
            }
            _ => panic!("B's join is a commit"),
        }
        (provider_a, group_a, provider_b, group_b, id_a, id_b)
    }

    fn test_channel() -> [u8; 32] {
        [0xAA; 32]
    }

    fn test_sender() -> [u8; 32] {
        [0xBB; 32]
    }

    fn make_text(content: &[u8]) -> ApplicationMessage {
        ApplicationMessage::new(
            MessageType::Text,
            test_channel(),
            test_sender(),
            1000,
            [0u8; 32],
            vec![],
            content.to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn roundtrip_text() {
        let msg = make_text(b"hello ghost");
        let bytes = msg.to_bytes();
        let decoded = ApplicationMessage::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.message_type, MessageType::Text);
        assert_eq!(decoded.channel_id, test_channel());
        assert_eq!(decoded.sender_fp, test_sender());
        assert_eq!(decoded.timestamp, 1000);
        assert_eq!(decoded.message_id, msg.message_id);
        assert!(decoded.references.is_empty());
        assert_eq!(decoded.content, b"hello ghost");
    }

    #[test]
    fn roundtrip_with_references() {
        let target = [0xCC; 32];
        let msg = ApplicationMessage::new(
            MessageType::Text,
            test_channel(),
            test_sender(),
            2000,
            [0u8; 32],
            vec![target],
            b"replying".to_vec(),
        )
        .unwrap();
        let decoded = ApplicationMessage::from_bytes(&msg.to_bytes()).unwrap();

        assert_eq!(decoded.references.len(), 1);
        assert_eq!(decoded.references[0], target);
        assert_eq!(decoded.content, b"replying");
    }

    #[test]
    fn a_message_type_only_receivers_make_is_refused_from_a_sender() {
        for local in [MessageType::Undecryptable, MessageType::HistoryGap] {
            let msg = ApplicationMessage::new(local, test_channel(), test_sender(), 1000, [0u8; 32], vec![], b"forged".to_vec()).unwrap();
            assert!(matches!(ApplicationMessage::from_bytes(&msg.to_bytes()), Err(GhostError::Format(_))), "{local:?} accepted from a sender");
        }
    }

    #[test]
    fn roundtrip_channel_reorder() {
        let positions = vec![([0x11; 32], 0), ([0x22; 32], 2), ([0x33; 32], 3)];
        let encoded = encode_channel_op(&ChannelOpPayload::Reorder { positions: positions.clone() });
        match decode_channel_op(&encoded).unwrap() {
            ChannelOpPayload::Reorder { positions: decoded } => assert_eq!(decoded, positions),
            _ => panic!("decoded as another channel op"),
        }
    }

    #[test]
    fn roundtrip_empty_content() {
        let target = [0xDD; 32];
        let msg = ApplicationMessage::new(
            MessageType::Delete,
            test_channel(),
            test_sender(),
            3000,
            [0u8; 32],
            vec![target],
            vec![],
        )
        .unwrap();
        let decoded = ApplicationMessage::from_bytes(&msg.to_bytes()).unwrap();

        assert_eq!(decoded.message_type, MessageType::Delete);
        assert!(decoded.content.is_empty());
        assert_eq!(decoded.references[0], target);
    }

    #[test]
    fn roundtrip_max_references() {
        let refs: Vec<[u8; 32]> = (0..255u8).map(|i| [i; 32]).collect();
        let msg = ApplicationMessage::new(
            MessageType::Text,
            test_channel(),
            test_sender(),
            4000,
            [0u8; 32],
            refs.clone(),
            b"many refs".to_vec(),
        )
        .unwrap();
        let decoded = ApplicationMessage::from_bytes(&msg.to_bytes()).unwrap();
        assert_eq!(decoded.references.len(), 255);
        assert_eq!(decoded.references[254], [254; 32]);
    }

    #[test]
    fn too_many_references_rejected() {
        let refs: Vec<[u8; 32]> = (0..=255u16).map(|i| [i as u8; 32]).collect();
        assert!(ApplicationMessage::new(
            MessageType::Text,
            test_channel(),
            test_sender(),
            1000,
            [0u8; 32],
            refs,
            vec![],
        )
        .is_err());
    }

    #[test]
    fn message_id_changes_with_input() {
        let base = derive_message_id(&test_channel(), &test_sender(), 1000, b"hello");
        let diff_content = derive_message_id(&test_channel(), &test_sender(), 1000, b"world");
        let diff_ts = derive_message_id(&test_channel(), &test_sender(), 1001, b"hello");
        let diff_sender = derive_message_id(&test_channel(), &[0xFF; 32], 1000, b"hello");
        let diff_channel = derive_message_id(&[0xFF; 32], &test_sender(), 1000, b"hello");

        assert_ne!(base, diff_content);
        assert_ne!(base, diff_ts);
        assert_ne!(base, diff_sender);
        assert_ne!(base, diff_channel);
    }

    #[test]
    fn default_channel_id_deterministic() {
        let gid = [0x11; 32];
        let a = derive_default_channel_id(&gid);
        let b = derive_default_channel_id(&gid);
        assert_eq!(a, b);

        let different = derive_default_channel_id(&[0x22; 32]);
        assert_ne!(a, different);

        // Must differ from MLS group ID derivation for same input
        assert_ne!(a, derive_mls_group_id(&gid, &gid));
    }

    #[test]
    fn reject_truncated() {
        let msg = make_text(b"hello");
        let bytes = msg.to_bytes();
        assert!(ApplicationMessage::from_bytes(&bytes[..50]).is_err());
    }

    #[test]
    fn reject_wrong_version() {
        let msg = make_text(b"hello");
        let mut bytes = msg.to_bytes();
        bytes[0] = 0xFF;
        assert!(ApplicationMessage::from_bytes(&bytes).is_err());
    }

    #[test]
    fn reject_trailing_bytes() {
        let msg = make_text(b"hello");
        let mut bytes = msg.to_bytes();
        bytes.push(0x00);
        assert!(ApplicationMessage::from_bytes(&bytes).is_err());
    }

    #[test]
    fn reject_unknown_message_type() {
        let msg = make_text(b"hello");
        let mut bytes = msg.to_bytes();
        bytes[1] = 0xFF;
        assert!(ApplicationMessage::from_bytes(&bytes).is_err());
    }

    #[test]
    fn reject_tampered_message_id() {
        let msg = make_text(b"hello");
        let mut bytes = msg.to_bytes();
        bytes[MESSAGE_ID_OFFSET] ^= 0xFF;
        assert!(ApplicationMessage::from_bytes(&bytes).is_err());
    }

    #[test]
    fn reject_truncated_references() {
        let target = [0xCC; 32];
        let msg = ApplicationMessage::new(
            MessageType::Text,
            test_channel(),
            test_sender(),
            1000,
            [0u8; 32],
            vec![target],
            b"hello".to_vec(),
        )
        .unwrap();
        let bytes = msg.to_bytes();
        // Cut mid-way through the references section
        assert!(ApplicationMessage::from_bytes(&bytes[..FIXED_HEADER_LEN + 10]).is_err());
    }

    #[test]
    fn reject_content_len_overflow() {
        let msg = make_text(b"hello");
        let mut bytes = msg.to_bytes();
        let content_len_pos = FIXED_HEADER_LEN - 4;
        bytes[content_len_pos..content_len_pos + 4].copy_from_slice(&9999u32.to_be_bytes());
        assert!(ApplicationMessage::from_bytes(&bytes).is_err());
    }

    #[test]
    fn create_uses_derived_group_id() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01; 32]).unwrap();
        let server_id = [0x42; 32];
        let channel_id = derive_default_channel_id(&server_id);
        let group = GhostGroup::create(&provider, &id, &server_id, &channel_id, None, None).unwrap();

        let expected = derive_mls_group_id(&server_id, &channel_id);
        assert_eq!(group.group_id(), expected);
    }

    #[test]
    fn seal_open_roundtrip() {
        let (provider_a, mut group_a, provider_b, mut group_b, id_a, _id_b) = two_member_group();

        let kt_hash = [0x42; 32];
        let msg = ApplicationMessage::new(
            MessageType::Text,
            test_channel(),
            id_a.fingerprint,
            1000,
            kt_hash,
            vec![],
            b"hello from sender".to_vec(),
        )
        .unwrap();

        let blob = seal(&mut group_a, &provider_a, &msg).unwrap();

        let decrypted = open(&mut group_b, &provider_b, &blob, &all_active).unwrap();

        assert_eq!(decrypted.message_type, MessageType::Text);
        assert_eq!(decrypted.channel_id, test_channel());
        assert_eq!(decrypted.sender_fp, id_a.fingerprint);
        assert_eq!(decrypted.content, b"hello from sender");
        assert_eq!(decrypted.message_id, msg.message_id);
        assert_eq!(decrypted.kt_head_hash, kt_hash);
    }

    #[test]
    fn reject_spoofed_sender_fp() {
        let (provider_a, mut group_a, provider_b, mut group_b, _id_a, id_b) = two_member_group();

        // Sender crafts a message claiming to be the other member
        let msg = ApplicationMessage::new(
            MessageType::Text,
            test_channel(),
            id_b.fingerprint, // lying about sender
            1000,
            [0u8; 32],
            vec![],
            b"forged".to_vec(),
        )
        .unwrap();

        let blob = seal(&mut group_a, &provider_a, &msg).unwrap();

        let result = open(&mut group_b, &provider_b, &blob, &all_active);
        assert!(result.is_err());
    }

    #[test]
    fn reject_message_from_revoked_device() {
        let (provider_a, mut group_a, provider_b, mut group_b, id_a, _id_b) = two_member_group();

        let msg = ApplicationMessage::new(
            MessageType::Text, test_channel(), id_a.fingerprint, 1000, [0u8; 32], vec![], b"still here".to_vec(),
        )
        .unwrap();
        let blob = seal(&mut group_a, &provider_a, &msg).unwrap();

        // B's log shows A's device revoked.
        let a_fp = id_a.fingerprint;
        let a_vk = id_a.verifying_key.to_bytes();
        let devices = move |claim: &CredentialClaim| {
            if claim.account_fp == a_fp && claim.device_vk == a_vk { DeviceStatus::Revoked } else { DeviceStatus::Active }
        };
        let Err(err) = open(&mut group_b, &provider_b, &blob, &devices) else {
            panic!("a message from a revoked device was accepted");
        };
        assert!(matches!(err, GhostError::SenderRefused(_)), "{err}");
    }

    #[test]
    fn a_message_from_an_unlisted_device_names_its_account() {
        let (provider_a, mut group_a, provider_b, mut group_b, id_a, _id_b) = two_member_group();

        let msg = ApplicationMessage::new(
            MessageType::Text, test_channel(), id_a.fingerprint, 1000, [0u8; 32], vec![], b"who am I".to_vec(),
        )
        .unwrap();
        let blob = seal(&mut group_a, &provider_a, &msg).unwrap();

        let unknown = |_: &CredentialClaim| DeviceStatus::Unknown;
        let no_server = |_: &[u8; 32], _: u64| Err(PolicyError::Denied("no server".into()));
        let checks = CommitChecks { devices: &unknown, mailbox: [0u8; 32], received_at: 0, server_at: &no_server };
        match open_any(&mut group_b, &provider_b, &blob, &checks) {
            Err(GhostError::UnknownDevice { account_fp }) => assert_eq!(account_fp, id_a.fingerprint),
            _ => panic!("an unlisted device's message was accepted"),
        }
    }

    #[test]
    fn avatar_update_roundtrip() {
        let hash = [0xAA; 32];
        let key = [0xBB; 32];
        let encoded = encode_avatar_update(&hash, &key);
        let decoded = decode_metadata(&encoded).unwrap();
        match decoded {
            MetadataPayload::AvatarUpdate { avatar_hash, avatar_key } => {
                assert_eq!(avatar_hash, hash);
                assert_eq!(avatar_key, key);
            }
            _ => panic!("expected AvatarUpdate"),
        }
    }

    #[test]
    fn mutation_encode_decode_set() {
        let encoded = encode_mutation(MUTATION_SET, 12345, "order:servers", &[0x01, 0x02]);
        let (op, ts, key, value) = decode_mutation(&encoded).unwrap();
        assert_eq!(op, MUTATION_SET);
        assert_eq!(ts, 12345);
        assert_eq!(key, "order:servers");
        assert_eq!(value, &[0x01, 0x02]);
    }

    #[test]
    fn mutation_encode_decode_remove() {
        let encoded = encode_mutation(MUTATION_REMOVE, 99999, "read:ccdd", &[]);
        let (op, ts, key, value) = decode_mutation(&encoded).unwrap();
        assert_eq!(op, MUTATION_REMOVE);
        assert_eq!(ts, 99999);
        assert_eq!(key, "read:ccdd");
        assert!(value.is_empty());
    }

    #[test]
    fn sync_state_dump_roundtrip() {
        let entries = vec![
            ("order:servers".to_string(), Some(vec![0x01]), 100),
            ("read:bb".to_string(), Some(vec![0x02, 0x03]), 200),
            ("order:channels".to_string(), None, 150), // tombstone
        ];
        let encoded = encode_sync_state_dump(&entries).unwrap();
        let decoded = decode_sync_state_dump(&encoded).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], entries[0]);
        assert_eq!(decoded[1], entries[1]);
        assert_eq!(decoded[2], entries[2]);
    }

    // --- Sync seal/open crypto tests ---

    // --- Sync state dump edge cases ---

    #[test]
    fn sync_state_dump_decode_truncated_entry() {
        // Says 1 entry but no data follows
        let data = [0x00, 0x01];
        assert!(decode_sync_state_dump(&data).is_err());
    }

    // --- Mutation edge cases ---

    #[test]
    fn mutation_decode_too_short() {
        assert!(decode_mutation(&[0u8; 10]).is_err()); // needs 11
    }

    #[test]
    fn mutation_decode_truncated_key() {
        // Says key_len=100 but only has a few bytes
        let mut buf = vec![MUTATION_SET];
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.extend_from_slice(&100u16.to_be_bytes());
        buf.extend_from_slice(b"short");
        assert!(decode_mutation(&buf).is_err());
    }

    // --- Provision payload tests ---

    #[test]
    fn provision_payload_roundtrip() {
        let pp = ProvisionPayload {
            server_id: [0x11; 32],
            server_name: "Test Server".to_string(),
            kind: ServerKind::Server,
            members: vec![
                InviteMember {
                    fingerprint: [0x22; 32],
                    display_name: "Alice".to_string(),
                },
                InviteMember {
                    fingerprint: [0x33; 32],
                    display_name: "Bob".to_string(),
                },
            ],
            channels: vec![
                InviteChannel {
                    channel_id: [0x44; 32],
                    name: "general".to_string(),
                    kind: ChannelKind::Text,
                    position: 0,
                    group_info_bytes: vec![],
                },
                InviteChannel {
                    channel_id: [0x55; 32],
                    name: "voice".to_string(),
                    kind: ChannelKind::Voice,
                    position: 1,
                    group_info_bytes: vec![],
                },
            ],
            mailbox_id: [0x66; 32],
            relay_ref: Some(RelayRef::https([0x77; 32], "https://relay.example")),
            role_names: vec![(3, "mods".to_string())],
        };
        let bytes = pp.to_bytes();
        let decoded = ProvisionPayload::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.relay_ref, pp.relay_ref);
        assert_eq!(decoded.server_id, pp.server_id);
        assert_eq!(decoded.server_name, pp.server_name);
        assert_eq!(decoded.members.len(), 2);
        assert_eq!(decoded.members[0].display_name, "Alice");
        assert_eq!(decoded.members[1].fingerprint, [0x33; 32]);
        assert_eq!(decoded.channels.len(), 2);
        assert_eq!(decoded.channels[0].name, "general");
        assert_eq!(decoded.channels[1].name, "voice");
        assert_eq!(decoded.mailbox_id, pp.mailbox_id);
        assert_eq!(decoded.role_names, pp.role_names);
    }

    // --- Provision blob (the full envelope: sync_key + payloads + sync state) ---

    #[test]
    fn provision_blob_build_and_parse() {
        let sync_key = [0xAA; 32];
        let pp = ProvisionPayload {
            server_id: [0x11; 32],
            server_name: "srv".to_string(),
            kind: ServerKind::Server,
            members: vec![],
            channels: vec![InviteChannel {
                channel_id: [0x22; 32],
                name: "gen".to_string(),
                kind: ChannelKind::Text,
                position: 0,
                group_info_bytes: vec![],
            }],
            mailbox_id: [0x33; 32],
            relay_ref: None,
            role_names: vec![],
        };
        let sync_entries = vec![
            ("order:servers".to_string(), Some(vec![0x01, 0x02]), 100),
            ("read:abc".to_string(), None, 200),
        ];

        // Build provision blob (same format as check_pairing)
        let pp_bytes = pp.to_bytes();
        let mut blob = Vec::new();
        blob.extend_from_slice(&sync_key);
        blob.extend_from_slice(&1u16.to_be_bytes()); // 1 server
        blob.extend_from_slice(&(pp_bytes.len() as u32).to_be_bytes());
        blob.extend_from_slice(&pp_bytes);
        blob.extend_from_slice(&encode_sync_state_dump(&sync_entries).unwrap());

        // Parse it back (same logic as consume_provision)
        assert!(blob.len() >= 34);
        let recovered_sync_key: [u8; 32] = blob[..32].try_into().unwrap();
        assert_eq!(recovered_sync_key, sync_key);

        let count = u16::from_be_bytes(blob[32..34].try_into().unwrap()) as usize;
        assert_eq!(count, 1);

        let mut pos = 34;
        let payload_len = u32::from_be_bytes(blob[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let recovered_pp = ProvisionPayload::from_bytes(&blob[pos..pos + payload_len]).unwrap();
        assert_eq!(recovered_pp.server_id, pp.server_id);
        assert_eq!(recovered_pp.server_name, "srv");
        pos += payload_len;

        let recovered_sync = decode_sync_state_dump(&blob[pos..]).unwrap();
        assert_eq!(recovered_sync.len(), 2);
        assert_eq!(recovered_sync[0].0, "order:servers");
        assert_eq!(recovered_sync[1].0, "read:abc");
        assert!(recovered_sync[1].1.is_none()); // tombstone preserved
    }

    // --- Domain separation ---

    #[test]
    fn derivation_domain_separation() {
        // All derivation functions must produce different outputs for the same input
        let id = [0xAA; 32];
        let ch = [0xBB; 32];
        let mls_gid = derive_mls_group_id(&id, &ch);
        let channel = derive_default_channel_id(&id);
        let mailbox = mls_group_mailbox_id(&id);
        let sync_mailbox = ghost_wire::sync_mailbox_id(&id);
        // All four must be different (domain tags prevent collisions)
        let all = [mls_gid, channel, mailbox, sync_mailbox];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "domain separation failed between derivation {i} and {j}");
            }
        }
    }

    // --- InvitePayload tests ---

    fn test_grant() -> ghost_wire::policy::InviteGrant {
        let device = ed25519_dalek::SigningKey::from_bytes(&[0x55; 32]);
        ghost_wire::policy::InviteGrant::sign([0x66; 32], [0x22; 32], 9_000, [0x77; 16], &device)
    }

    #[test]
    fn invite_payload_roundtrip() {
        let payload = InvitePayload {
            server_id: [0x11; 32],
            server_name: "My Server".to_string(),
            kind: ServerKind::Server,
            members: vec![
                InviteMember {
                    fingerprint: [0x22; 32],
                    display_name: "Alice".to_string(),
                },
                InviteMember {
                    fingerprint: [0x33; 32],
                    display_name: "Bob".to_string(),
                },
            ],
            channels: vec![InviteChannel {
                channel_id: [0x44; 32],
                name: "general".to_string(),
                kind: ChannelKind::Text,
                position: 5,
                group_info_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
            }],
            role_names: vec![(3, "mods".to_string())],
            grant: test_grant(),
        };

        let bytes = payload.to_bytes();
        let decoded = InvitePayload::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.server_id, [0x11; 32]);
        assert_eq!(decoded.server_name, "My Server");
        assert_eq!(decoded.members.len(), 2);
        assert_eq!(decoded.members[0].fingerprint, [0x22; 32]);
        assert_eq!(decoded.members[0].display_name, "Alice");
        assert_eq!(decoded.members[1].fingerprint, [0x33; 32]);
        assert_eq!(decoded.members[1].display_name, "Bob");
        assert_eq!(decoded.channels.len(), 1);
        assert_eq!(decoded.channels[0].channel_id, [0x44; 32]);
        assert_eq!(decoded.channels[0].name, "general");
        assert_eq!(decoded.channels[0].position, 5);
        assert_eq!(decoded.channels[0].group_info_bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(decoded.role_names, vec![(3, "mods".to_string())]);
        assert_eq!(decoded.grant, test_grant());
    }

    #[test]
    fn invite_payload_truncated_rejected() {
        let payload = InvitePayload {
            server_id: [0x11; 32],
            server_name: "Test".to_string(),
            kind: ServerKind::Server,
            members: vec![],
            channels: vec![],
            role_names: vec![],
            grant: test_grant(),
        };
        let bytes = payload.to_bytes();
        assert!(InvitePayload::from_bytes(&bytes[..bytes.len() - 4]).is_err());
    }

    #[test]
    fn invite_payload_trailing_bytes_rejected() {
        let payload = InvitePayload {
            server_id: [0x11; 32],
            server_name: "Test".to_string(),
            kind: ServerKind::Server,
            members: vec![],
            channels: vec![],
            role_names: vec![],
            grant: test_grant(),
        };
        let mut bytes = payload.to_bytes();
        bytes.push(0xFF);
        assert!(InvitePayload::from_bytes(&bytes).is_err());
    }

    // --- Metadata encode/decode tests ---

    #[test]
    fn member_announce_roundtrip() {
        let encoded = encode_member_announce("ghostuser");
        let decoded = decode_metadata(&encoded).unwrap();
        match decoded {
            MetadataPayload::MemberAnnounce { display_name } => {
                assert_eq!(display_name, "ghostuser");
            }
            _ => panic!("expected MemberAnnounce"),
        }
    }

    #[test]
    fn server_state_roundtrip() {
        assert!(matches!(decode_metadata(&encode_server_state_request()).unwrap(), MetadataPayload::ServerStateRequest));
        let state = ServerStatePayload {
            request_seq: 41,
            channels: vec![InviteChannel { channel_id: [1; 32], name: "news".into(), kind: ChannelKind::Voice, position: 3, group_info_bytes: Vec::new() }],
            role_names: vec![(1, "staff".into())],
            members: vec![InviteMember { fingerprint: [2; 32], display_name: "bob".into() }],
        };
        match decode_metadata(&encode_server_state(&state)).unwrap() {
            MetadataPayload::ServerState(decoded) => {
                assert_eq!(decoded.request_seq, 41);
                assert_eq!(decoded.channels.len(), 1);
                assert_eq!((decoded.channels[0].channel_id, decoded.channels[0].name.as_str(), decoded.channels[0].kind, decoded.channels[0].position), ([1; 32], "news", ChannelKind::Voice, 3));
                assert_eq!(decoded.role_names, state.role_names);
                assert_eq!((decoded.members[0].fingerprint, decoded.members[0].display_name.as_str()), ([2; 32], "bob"));
            }
            _ => panic!("decoded as other metadata"),
        }
    }

    #[test]
    fn avatar_clear_roundtrip() {
        let encoded = encode_avatar_clear();
        let decoded = decode_metadata(&encoded).unwrap();
        assert!(matches!(decoded, MetadataPayload::AvatarClear));
    }

    #[test]
    fn roundtrip_sync_server_meta() {
        let meta = SyncServerMeta {
            server_name: "test server".into(),
            kind: ServerKind::Server,
            mailbox_id: [0xAA; 32],
            channels: vec![
                InviteChannel {
                    channel_id: [0xBB; 32],
                    name: "general".into(),
                    kind: ChannelKind::Text,
                    position: 0,
                    group_info_bytes: vec![],
                },
                InviteChannel {
                    channel_id: [0xCC; 32],
                    name: "voice".into(),
                    kind: ChannelKind::Voice,
                    position: 1,
                    group_info_bytes: vec![],
                },
            ],
            relay_ref: Some(RelayRef::https([0x77; 32], "https://relay.example")),
            role_names: vec![],
            removal: None,
        };
        let bytes = meta.to_bytes();
        let decoded = SyncServerMeta::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.relay_ref, meta.relay_ref);
        assert_eq!(decoded.server_name, "test server");
        assert_eq!(decoded.kind, ServerKind::Server);
        assert_eq!(decoded.mailbox_id, [0xAA; 32]);
        assert_eq!(decoded.channels.len(), 2);
        assert_eq!(decoded.channels[0].name, "general");
        assert_eq!(decoded.channels[1].name, "voice");
        assert_eq!(decoded.channels[1].kind, ChannelKind::Voice);
        assert_eq!(decoded.channels[1].position, 1);
    }

    #[test]
    fn sync_server_meta_carries_the_removal_and_who_made_it() {
        let mut meta = SyncServerMeta {
            server_name: "club".into(),
            kind: ServerKind::Server,
            mailbox_id: [0x44; 32],
            channels: vec![],
            relay_ref: None,
            role_names: vec![(1, "mod".into())],
            removal: Some(SyncRemoval { by: Some([0x55; 32]) }),
        };
        let decoded = SyncServerMeta::from_bytes(&meta.to_bytes()).unwrap();
        assert_eq!(decoded.removal, Some(SyncRemoval { by: Some([0x55; 32]) }));
        assert_eq!(decoded.role_names, vec![(1, "mod".to_string())]);

        // A removal the relay reported without the removing commit names nobody.
        meta.removal = Some(SyncRemoval { by: None });
        assert_eq!(SyncServerMeta::from_bytes(&meta.to_bytes()).unwrap().removal, Some(SyncRemoval { by: None }));
    }

    #[test]
    fn sync_server_meta_trailing_bytes_rejected() {
        let meta = SyncServerMeta {
            server_name: "x".into(),
            kind: ServerKind::Dm,
            mailbox_id: [0x11; 32],
            channels: vec![],
            relay_ref: None,
            role_names: vec![],
            removal: None,
        };
        let mut bytes = meta.to_bytes();
        bytes.push(0xFF);
        assert!(SyncServerMeta::from_bytes(&bytes).is_err());
    }

    #[test]
    fn sync_server_meta_empty_channels() {
        let meta = SyncServerMeta {
            server_name: "empty".into(),
            kind: ServerKind::Dm,
            mailbox_id: [0x22; 32],
            channels: vec![],
            relay_ref: None,
            role_names: vec![],
            removal: None,
        };
        let bytes = meta.to_bytes();
        let decoded = SyncServerMeta::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.server_name, "empty");
        assert!(decoded.channels.is_empty());
    }
}
