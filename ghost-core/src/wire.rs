use openmls::prelude::ProcessedMessageContent;
use openmls::prelude::BasicCredential;

use crate::crypto::{
    DEFAULT_CHANNEL_TAG, GhostProvider, MessageType, MAILBOX_ID_TAG, MLS_GROUP_ID_TAG,
    PROTOCOL_VERSION,
};
use crate::error::{GhostError, Result};
use crate::mls::group::GhostGroup;
use crate::storage::{ChannelKind, ServerKind, MemberRole};

const MAX_REFERENCES: usize = 255;

/// version + type + channel_id + sender_fp + timestamp + message_id + ref_count + content_len
const FIXED_HEADER_LEN: usize = 1 + 1 + 32 + 32 + 8 + 32 + 1 + 4;

/// Application-layer message — the plaintext unit before MLS encryption.
pub struct ApplicationMessage {
    pub message_type: MessageType,
    pub channel_id: [u8; 32],
    pub sender_fp: [u8; 32],
    pub timestamp: u64,
    pub message_id: [u8; 32],
    pub references: Vec<[u8; 32]>,
    pub content: Vec<u8>,
}

impl ApplicationMessage {
    pub fn new(
        message_type: MessageType,
        channel_id: [u8; 32],
        sender_fp: [u8; 32],
        timestamp: u64,
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
        let mut pos = 0;

        let version = read_u8(data, &mut pos)?;
        if version != PROTOCOL_VERSION {
            return Err(GhostError::Format(format!(
                "unsupported version: {version:#04x}"
            )));
        }

        let type_byte = read_u8(data, &mut pos)?;
        let message_type = MessageType::try_from(type_byte)
            .map_err(|v| GhostError::Format(format!("unknown message type: {v:#04x}")))?;

        let channel_id = read_blob32(data, &mut pos)?;
        let sender_fp = read_blob32(data, &mut pos)?;
        let timestamp = read_u64(data, &mut pos)?;
        let message_id = read_blob32(data, &mut pos)?;

        let ref_count = read_u8(data, &mut pos)? as usize;
        let mut references = Vec::with_capacity(ref_count);
        for _ in 0..ref_count {
            references.push(read_blob32(data, &mut pos)?);
        }

        let content_len = read_u32(data, &mut pos)? as usize;
        if pos + content_len != data.len() {
            return Err(GhostError::Format(format!(
                "expected {} bytes, got {}",
                pos + content_len,
                data.len()
            )));
        }
        let content = data[pos..].to_vec();

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

pub fn derive_mls_group_id(server_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(server_id);
    hasher.update(MLS_GROUP_ID_TAG);
    hasher.finalize().into()
}

pub fn mls_group_mailbox_id(mls_group_id: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(mls_group_id);
    hasher.update(MAILBOX_ID_TAG);
    hasher.finalize().into()
}

pub fn derive_default_channel_id(server_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(server_id);
    hasher.update(DEFAULT_CHANNEL_TAG);
    hasher.finalize().into()
}

// --- InvitePayload: metadata + GroupInfo for external commit joins ---

pub struct InviteMember {
    pub fingerprint: [u8; 32],
    pub display_name: String,
    pub role: MemberRole,
}

#[derive(Debug, Clone)]
pub struct InviteChannel {
    pub channel_id: [u8; 32],
    pub name: String,
    pub kind: ChannelKind,
    pub position: i32,
}

pub struct InvitePayload {
    pub server_id: [u8; 32],
    pub server_name: String,
    pub kind: ServerKind,
    pub members: Vec<InviteMember>,
    pub channels: Vec<InviteChannel>,
    pub group_info_bytes: Vec<u8>,
}

fn write_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn read_string(data: &[u8], pos: &mut usize) -> Result<String> {
    if *pos + 2 > data.len() {
        return Err(GhostError::Format("truncated string length".into()));
    }
    let len = u16::from_be_bytes(data[*pos..*pos + 2].try_into().unwrap()) as usize;
    *pos += 2;
    if *pos + len > data.len() {
        return Err(GhostError::Format("truncated string".into()));
    }
    let s = String::from_utf8(data[*pos..*pos + len].to_vec())
        .map_err(|_| GhostError::Format("invalid UTF-8".into()))?;
    *pos += len;
    Ok(s)
}

fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8> {
    if *pos >= data.len() {
        return Err(GhostError::Format("truncated u8".into()));
    }
    let val = data[*pos];
    *pos += 1;
    Ok(val)
}

fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16> {
    if *pos + 2 > data.len() {
        return Err(GhostError::Format("truncated u16".into()));
    }
    let val = u16::from_be_bytes(data[*pos..*pos + 2].try_into().unwrap());
    *pos += 2;
    Ok(val)
}

fn read_u64(data: &[u8], pos: &mut usize) -> Result<u64> {
    if *pos + 8 > data.len() {
        return Err(GhostError::Format("truncated u64".into()));
    }
    let val = u64::from_be_bytes(data[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    Ok(val)
}

fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 4 > data.len() {
        return Err(GhostError::Format("truncated u32".into()));
    }
    let val = u32::from_be_bytes(data[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(val)
}

fn read_i32(data: &[u8], pos: &mut usize) -> Result<i32> {
    if *pos + 4 > data.len() {
        return Err(GhostError::Format("truncated i32".into()));
    }
    let val = i32::from_be_bytes(data[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(val)
}

fn read_blob32(data: &[u8], pos: &mut usize) -> Result<[u8; 32]> {
    if *pos + 32 > data.len() {
        return Err(GhostError::Format("truncated blob32".into()));
    }
    let blob: [u8; 32] = data[*pos..*pos + 32].try_into().unwrap();
    *pos += 32;
    Ok(blob)
}

impl InvitePayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.server_id);
        write_string(&mut buf, &self.server_name);
        buf.push(self.kind.to_byte());

        buf.extend_from_slice(&(self.members.len() as u16).to_be_bytes());
        for m in &self.members {
            buf.extend_from_slice(&m.fingerprint);
            write_string(&mut buf, &m.display_name);
            buf.push(m.role.to_byte());
        }

        buf.extend_from_slice(&(self.channels.len() as u16).to_be_bytes());
        for c in &self.channels {
            buf.extend_from_slice(&c.channel_id);
            write_string(&mut buf, &c.name);
            buf.push(c.kind.to_byte());
            buf.extend_from_slice(&c.position.to_be_bytes());
        }

        buf.extend_from_slice(&(self.group_info_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.group_info_bytes);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut pos = 0;

        let server_id = read_blob32(data, &mut pos)?;
        let server_name = read_string(data, &mut pos)?;
        let kind = ServerKind::from_byte(read_u8(data, &mut pos)?)?;

        let member_count = read_u16(data, &mut pos)? as usize;
        let mut members = Vec::with_capacity(member_count);
        for _ in 0..member_count {
            members.push(InviteMember {
                fingerprint: read_blob32(data, &mut pos)?,
                display_name: read_string(data, &mut pos)?,
                role: MemberRole::from_byte(read_u8(data, &mut pos)?)?,
            });
        }

        let channel_count = read_u16(data, &mut pos)? as usize;
        let mut channels = Vec::with_capacity(channel_count);
        for _ in 0..channel_count {
            channels.push(InviteChannel {
                channel_id: read_blob32(data, &mut pos)?,
                name: read_string(data, &mut pos)?,
                kind: ChannelKind::from_byte(read_u8(data, &mut pos)?)?,
                position: read_i32(data, &mut pos)?,
            });
        }

        let gi_len = read_u32(data, &mut pos)? as usize;
        if pos + gi_len != data.len() {
            return Err(GhostError::Format(format!(
                "group info: expected {} bytes, got {}",
                gi_len,
                data.len() - pos
            )));
        }
        let group_info_bytes = data[pos..].to_vec();

        Ok(Self { server_id, server_name, kind, members, channels, group_info_bytes })
    }
}

// --- Sync mailbox: device-to-device communication ---

const SYNC_MAILBOX_TAG: &[u8] = b"ghost-sync-mailbox-v1";

/// Deterministic mailbox ID for device sync, derived from account fingerprint.
pub fn sync_mailbox_id(account_fp: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(account_fp);
    hasher.update(SYNC_MAILBOX_TAG);
    hasher.finalize().into()
}

/// Sync message types sent between a user's devices.
#[repr(u8)]
pub enum SyncMessageType {
    ServerProvisioned = 0x01,
    ServerLeft = 0x02,
    VoiceTakeover = 0x03,
    MutationSync = 0x04,
}

/// Encrypt a sync message with AES-256-GCM. Returns nonce || ciphertext.
pub fn sync_seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, AeadCore, OsRng};
    use aes_gcm::{Aes256Gcm, KeyInit};
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| GhostError::Format(format!("sync seal: {e}")))?;
    let mut blob = Vec::with_capacity(12 + ct.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Decrypt a sync message (nonce || ciphertext).
pub fn sync_open(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    if blob.len() < 12 {
        return Err(GhostError::Format("sync blob too short".into()));
    }
    let nonce = Nonce::from_slice(&blob[..12]);
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(nonce, &blob[12..])
        .map_err(|e| GhostError::Format(format!("sync open: {e}")))
}

/// Sign a sync plaintext with the device signing key.
/// Output: [device_vk:32][ed25519_sig:64][plaintext...]
pub fn sync_sign(signing_key: &ed25519_dalek::SigningKey, plaintext: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let sig = signing_key.sign(plaintext);
    let vk = signing_key.verifying_key();
    let mut out = Vec::with_capacity(32 + 64 + plaintext.len());
    out.extend_from_slice(vk.as_bytes());
    out.extend_from_slice(&sig.to_bytes());
    out.extend_from_slice(plaintext);
    out
}

/// Verify and extract a signed sync plaintext.
/// Returns (device_verifying_key, plaintext) on success.
pub fn sync_verify(signed: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
    if signed.len() < 96 {
        return Err(GhostError::Format("signed sync too short".into()));
    }
    let vk_bytes: [u8; 32] = signed[..32].try_into().unwrap();
    let sig_bytes: [u8; 64] = signed[32..96].try_into().unwrap();
    let payload = &signed[96..];

    let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes)
        .map_err(|e| GhostError::Format(format!("bad device key: {e}")))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    vk.verify_strict(payload, &sig)
        .map_err(|e| GhostError::Format(format!("sync signature invalid: {e}")))?;

    Ok((vk_bytes, payload.to_vec()))
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
pub const SYNC_KEY_STATUS: &str = "status:current";
pub const SYNC_KEY_STATUS_MESSAGE: &str = "status:message";
pub const SYNC_KEY_SERVER_PREFIX: &str = "server:";

/// Encode a mutation: [op:1][ts:8 BE][key_len:2 BE][key bytes][value bytes]
pub fn encode_mutation(op: u8, ts: u64, key: &str, value: &[u8]) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    let mut buf = Vec::with_capacity(1 + 8 + 2 + key_bytes.len() + value.len());
    buf.push(op);
    buf.extend_from_slice(&ts.to_be_bytes());
    buf.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(key_bytes);
    buf.extend_from_slice(value);
    buf
}

/// Decode a mutation. Returns (op, ts, key, value).
pub fn decode_mutation(data: &[u8]) -> Result<(u8, u64, String, Vec<u8>)> {
    if data.len() < 11 {
        return Err(GhostError::Format("mutation too short".into()));
    }
    let op = data[0];
    let ts = u64::from_be_bytes(data[1..9].try_into().unwrap());
    let key_len = u16::from_be_bytes(data[9..11].try_into().unwrap()) as usize;
    if data.len() < 11 + key_len {
        return Err(GhostError::Format("mutation key truncated".into()));
    }
    let key = std::str::from_utf8(&data[11..11 + key_len])
        .map_err(|e| GhostError::Format(format!("mutation key: {e}")))?
        .to_string();
    let value = data[11 + key_len..].to_vec();
    Ok((op, ts, key, value))
}

/// Encode a sync state dump for provision blob.
/// Wire: [count:2 BE] then for each: [key_len:2 BE][key][ts:8 BE][value_len:2 BE][value]
/// value_len 0xFFFF = NULL tombstone.
pub fn encode_sync_state_dump(entries: &[(String, Option<Vec<u8>>, u64)]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for (key, value, ts) in entries {
        let kb = key.as_bytes();
        buf.extend_from_slice(&(kb.len() as u16).to_be_bytes());
        buf.extend_from_slice(kb);
        buf.extend_from_slice(&ts.to_be_bytes());
        match value {
            Some(v) => {
                buf.extend_from_slice(&(v.len() as u16).to_be_bytes());
                buf.extend_from_slice(v);
            }
            None => {
                buf.extend_from_slice(&0xFFFFu16.to_be_bytes());
            }
        }
    }
    buf
}

/// Decode a sync state dump from provision blob.
pub fn decode_sync_state_dump(data: &[u8]) -> Result<Vec<(String, Option<Vec<u8>>, u64)>> {
    if data.len() < 2 {
        return Err(GhostError::Format("sync dump too short".into()));
    }
    let count = u16::from_be_bytes(data[0..2].try_into().unwrap()) as usize;
    let mut pos = 2;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 2 > data.len() {
            return Err(GhostError::Format("sync dump: key_len truncated".into()));
        }
        let key_len = u16::from_be_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        if pos + key_len > data.len() {
            return Err(GhostError::Format("sync dump: key truncated".into()));
        }
        let key = std::str::from_utf8(&data[pos..pos + key_len])
            .map_err(|e| GhostError::Format(format!("sync dump key: {e}")))?
            .to_string();
        pos += key_len;
        if pos + 8 > data.len() {
            return Err(GhostError::Format("sync dump: ts truncated".into()));
        }
        let ts = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;
        if pos + 2 > data.len() {
            return Err(GhostError::Format("sync dump: value_len truncated".into()));
        }
        let value_len = u16::from_be_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        if value_len == 0xFFFF {
            entries.push((key, None, ts));
        } else {
            if pos + value_len > data.len() {
                return Err(GhostError::Format("sync dump: value truncated".into()));
            }
            entries.push((key, Some(data[pos..pos + value_len].to_vec()), ts));
            pos += value_len;
        }
    }
    Ok(entries)
}

/// Wrap a sync ciphertext in a relay-compatible envelope.
pub fn wrap_sync_envelope(sealed: &[u8]) -> Vec<u8> {
    let header = ghost_wire::encode_envelope(ghost_wire::EnvelopeType::Application, 0);
    let mut out = Vec::with_capacity(ghost_wire::ENVELOPE_HEADER_SIZE + sealed.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(sealed);
    out
}

// --- Provision payload: server metadata for device provisioning ---

pub struct ProvisionPayload {
    pub server_id: [u8; 32],
    pub server_name: String,
    pub kind: ServerKind,
    pub members: Vec<InviteMember>,
    pub channels: Vec<InviteChannel>,
    pub mailbox_id: [u8; 32],
}

impl ProvisionPayload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.server_id);
        write_string(&mut buf, &self.server_name);
        buf.push(self.kind.to_byte());

        buf.extend_from_slice(&(self.members.len() as u16).to_be_bytes());
        for m in &self.members {
            buf.extend_from_slice(&m.fingerprint);
            write_string(&mut buf, &m.display_name);
            buf.push(m.role.to_byte());
        }

        buf.extend_from_slice(&(self.channels.len() as u16).to_be_bytes());
        for c in &self.channels {
            buf.extend_from_slice(&c.channel_id);
            write_string(&mut buf, &c.name);
            buf.push(c.kind.to_byte());
            buf.extend_from_slice(&c.position.to_be_bytes());
        }

        buf.extend_from_slice(&self.mailbox_id);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut pos = 0;

        let server_id = read_blob32(data, &mut pos)?;
        let server_name = read_string(data, &mut pos)?;
        let kind = ServerKind::from_byte(read_u8(data, &mut pos)?)?;

        let member_count = read_u16(data, &mut pos)? as usize;
        let mut members = Vec::with_capacity(member_count);
        for _ in 0..member_count {
            members.push(InviteMember {
                fingerprint: read_blob32(data, &mut pos)?,
                display_name: read_string(data, &mut pos)?,
                role: MemberRole::from_byte(read_u8(data, &mut pos)?)?,
            });
        }

        let channel_count = read_u16(data, &mut pos)? as usize;
        let mut channels = Vec::with_capacity(channel_count);
        for _ in 0..channel_count {
            channels.push(InviteChannel {
                channel_id: read_blob32(data, &mut pos)?,
                name: read_string(data, &mut pos)?,
                kind: ChannelKind::from_byte(read_u8(data, &mut pos)?)?,
                position: read_i32(data, &mut pos)?,
            });
        }

        let mailbox_id = read_blob32(data, &mut pos)?;

        if pos != data.len() {
            return Err(GhostError::Format(format!(
                "provision payload: {} trailing bytes",
                data.len() - pos
            )));
        }

        Ok(Self { server_id, server_name, kind, members, channels, mailbox_id })
    }
}

// --- Sync server metadata: lightweight group entry for sync_state (no members) ---

#[derive(Debug)]
pub struct SyncServerMeta {
    pub server_name: String,
    pub kind: ServerKind,
    pub mailbox_id: [u8; 32],
    pub channels: Vec<InviteChannel>,
}

impl SyncServerMeta {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_string(&mut buf, &self.server_name);
        buf.push(self.kind.to_byte());
        buf.extend_from_slice(&self.mailbox_id);
        buf.extend_from_slice(&(self.channels.len() as u16).to_be_bytes());
        for c in &self.channels {
            buf.extend_from_slice(&c.channel_id);
            write_string(&mut buf, &c.name);
            buf.push(c.kind.to_byte());
            buf.extend_from_slice(&c.position.to_be_bytes());
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut pos = 0;
        let server_name = read_string(data, &mut pos)?;
        let kind = ServerKind::from_byte(read_u8(data, &mut pos)?)?;
        let mailbox_id = read_blob32(data, &mut pos)?;
        let channel_count = read_u16(data, &mut pos)? as usize;
        let mut channels = Vec::with_capacity(channel_count);
        for _ in 0..channel_count {
            channels.push(InviteChannel {
                channel_id: read_blob32(data, &mut pos)?,
                name: read_string(data, &mut pos)?,
                kind: ChannelKind::from_byte(read_u8(data, &mut pos)?)?,
                position: read_i32(data, &mut pos)?,
            });
        }
        if pos != data.len() {
            return Err(GhostError::Format(format!(
                "sync server meta: {} trailing bytes",
                data.len() - pos
            )));
        }

        Ok(Self { server_name, kind, mailbox_id, channels })
    }
}

// --- Channel operation payloads (carried in Metadata messages) ---

pub enum ChannelOpPayload {
    Create { channel_id: [u8; 32], name: String, kind: ChannelKind, position: i32 },
    Rename { channel_id: [u8; 32], name: String },
    Delete { channel_id: [u8; 32] },
}

const CHANNEL_OP_CREATE: u8 = 0x01;
const CHANNEL_OP_RENAME: u8 = 0x02;
const CHANNEL_OP_DELETE: u8 = 0x03;

pub fn encode_channel_op(op: &ChannelOpPayload) -> Vec<u8> {
    let mut buf = Vec::new();
    match op {
        ChannelOpPayload::Create { channel_id, name, kind, position } => {
            buf.push(CHANNEL_OP_CREATE);
            buf.extend_from_slice(channel_id);
            buf.push(kind.to_byte());
            buf.extend_from_slice(&position.to_be_bytes());
            write_string(&mut buf, name);
        }
        ChannelOpPayload::Rename { channel_id, name } => {
            buf.push(CHANNEL_OP_RENAME);
            buf.extend_from_slice(channel_id);
            write_string(&mut buf, name);
        }
        ChannelOpPayload::Delete { channel_id } => {
            buf.push(CHANNEL_OP_DELETE);
            buf.extend_from_slice(channel_id);
        }
    }
    buf
}

pub fn decode_channel_op(data: &[u8]) -> Result<ChannelOpPayload> {
    let mut pos = 0;
    let op = read_u8(data, &mut pos)?;
    match op {
        CHANNEL_OP_CREATE => {
            let channel_id = read_blob32(data, &mut pos)?;
            let kind = ChannelKind::from_byte(read_u8(data, &mut pos)?)?;
            let position = read_i32(data, &mut pos)?;
            let name = read_string(data, &mut pos)?;
            Ok(ChannelOpPayload::Create { channel_id, name, kind, position })
        }
        CHANNEL_OP_RENAME => {
            let channel_id = read_blob32(data, &mut pos)?;
            let name = read_string(data, &mut pos)?;
            Ok(ChannelOpPayload::Rename { channel_id, name })
        }
        CHANNEL_OP_DELETE => {
            let channel_id = read_blob32(data, &mut pos)?;
            Ok(ChannelOpPayload::Delete { channel_id })
        }
        _ => Err(GhostError::Format(format!("unknown channel op: {op:#04x}"))),
    }
}

// --- Member announce payload (carried in Metadata messages) ---

const MEMBER_ANNOUNCE: u8 = 0x10;
const AVATAR_UPDATE: u8 = 0x11;
const AVATAR_CLEAR: u8 = 0x12;

pub fn encode_member_announce(display_name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(MEMBER_ANNOUNCE);
    write_string(&mut buf, display_name);
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
        CHANNEL_OP_CREATE | CHANNEL_OP_RENAME | CHANNEL_OP_DELETE => {
            Ok(MetadataPayload::ChannelOp(decode_channel_op(data)?))
        }
        MEMBER_ANNOUNCE => {
            let mut pos = 1;
            let name = read_string(data, &mut pos)?;
            Ok(MetadataPayload::MemberAnnounce { display_name: name })
        }
        AVATAR_UPDATE => {
            let mut pos = 1;
            let avatar_hash = read_blob32(data, &mut pos)?;
            let avatar_key = read_blob32(data, &mut pos)?;
            Ok(MetadataPayload::AvatarUpdate { avatar_hash, avatar_key })
        }
        AVATAR_CLEAR => Ok(MetadataPayload::AvatarClear),
        _ => Err(GhostError::Format(format!("unknown metadata tag: {tag:#04x}"))),
    }
}

pub enum MetadataPayload {
    ChannelOp(ChannelOpPayload),
    MemberAnnounce { display_name: String },
    AvatarUpdate { avatar_hash: [u8; 32], avatar_key: [u8; 32] },
    AvatarClear,
}

// --- open_any: handle both app messages and commits from the relay ---

pub enum InboundMessage {
    Application(ApplicationMessage),
    /// A commit was merged. Contains fingerprints of members removed by this commit.
    Commit { removed: Vec<[u8; 32]> },
}

/// Process an inbound blob that could be an application message or a commit.
/// Strips the envelope header, then decrypts. App messages are returned;
/// commits are merged into the group automatically.
pub fn open_any(
    group: &mut GhostGroup,
    provider: &GhostProvider,
    blob: &[u8],
) -> Result<InboundMessage> {
    ghost_wire::decode_envelope(blob)
        .map_err(|e| GhostError::Format(format!("envelope: {e}")))?;
    let mls_bytes = ghost_wire::envelope_payload(blob);
    let processed = group.process_message_bytes(provider, mls_bytes)?;
    let credential = processed.credential().clone();

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => {
            let mls_basic = BasicCredential::try_from(credential)
                .map_err(|_| GhostError::Mls("sender has non-basic credential".into()))?;
            let msg = ApplicationMessage::from_bytes(&app_msg.into_bytes())?;
            if msg.sender_fp != mls_basic.identity() {
                return Err(GhostError::Format(
                    "sender_fp does not match MLS credential".into(),
                ));
            }
            Ok(InboundMessage::Application(msg))
        }
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            // Extract removed member fingerprints before merging
            let removed = extract_removed_fps(group, &staged_commit);
            group.merge_staged_commit(provider, *staged_commit)?;
            Ok(InboundMessage::Commit { removed })
        }
        _ => Err(GhostError::Mls("unexpected message type".into())),
    }
}

/// Read remove proposals from a staged commit, resolve leaf indices to fingerprints.
fn extract_removed_fps(group: &GhostGroup, staged: &openmls::prelude::StagedCommit) -> Vec<[u8; 32]> {
    use std::collections::HashMap;
    let member_map: HashMap<u32, [u8; 32]> = group
        .members()
        .filter_map(|m| {
            BasicCredential::try_from(m.credential)
                .ok()
                .and_then(|bc| <[u8; 32]>::try_from(bc.identity()).ok())
                .map(|fp| (m.index.u32(), fp))
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

/// Strip envelope header, MLS-decrypt, and deserialize into an ApplicationMessage.
pub fn open(
    group: &mut GhostGroup,
    provider: &GhostProvider,
    blob: &[u8],
) -> Result<ApplicationMessage> {
    ghost_wire::decode_envelope(blob)
        .map_err(|e| GhostError::Format(format!("envelope: {e}")))?;
    let mls_bytes = ghost_wire::envelope_payload(blob);
    let processed = group.process_message_bytes(provider, mls_bytes)?;

    // Extract the MLS-authenticated sender fingerprint before consuming the message
    let mls_credential = processed.credential().clone();
    let mls_basic = BasicCredential::try_from(mls_credential)
        .map_err(|_| GhostError::Mls("sender has non-basic credential".into()))?;
    let mls_fp = mls_basic.identity();

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => {
            let msg = ApplicationMessage::from_bytes(&app_msg.into_bytes())?;
            if msg.sender_fp != mls_fp {
                return Err(GhostError::Format("sender_fp does not match MLS credential".into()));
            }
            Ok(msg)
        }
        _ => Err(GhostError::Mls("expected application message".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::mls::credential::generate_key_package;
    use crate::mls::membership::MemberBinding;

    fn test_binding(id: &Identity, seq: u64) -> MemberBinding {
        MemberBinding {
            account_fp: id.fingerprint,
            idlog_seq: seq,
            device_key: id.verifying_key.to_bytes(),
        }
    }

    const MESSAGE_ID_OFFSET: usize = 1 + 1 + 32 + 32 + 8;

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
    fn roundtrip_empty_content() {
        let target = [0xDD; 32];
        let msg = ApplicationMessage::new(
            MessageType::Delete,
            test_channel(),
            test_sender(),
            3000,
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
        assert_ne!(a, derive_mls_group_id(&gid));
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
    fn create_with_id_uses_derived_group_id() {
        let provider = GhostProvider::new_in_memory().unwrap();
        let id = Identity::from_seed([0x01; 32]).unwrap();
        let server_id = [0x42; 32];
        let group = GhostGroup::create_with_id(&provider, &id, &server_id, test_binding(&id, 1)).unwrap();

        let expected = derive_mls_group_id(&server_id);
        assert_eq!(group.group_id(), expected);
    }

    #[test]
    fn seal_open_roundtrip() {
        let provider_a = GhostProvider::new_in_memory().unwrap();
        let provider_b = GhostProvider::new_in_memory().unwrap();
        let id_a = Identity::from_seed([0x01; 32]).unwrap();
        let id_b = Identity::from_seed([0x02; 32]).unwrap();

        let server_id = [0x42; 32];
        let mut group_a =
            GhostGroup::create_with_id(&provider_a, &id_a, &server_id, test_binding(&id_a, 1)).unwrap();
        let kp_b = generate_key_package(&provider_b, &id_b).unwrap();
        let (_commit, welcome) = group_a.add_member(&provider_a, kp_b, test_binding(&id_b, 1)).unwrap();
        let mut group_b =
            GhostGroup::join(&provider_b, &id_b, &welcome.to_bytes().unwrap()).unwrap();

        let msg = ApplicationMessage::new(
            MessageType::Text,
            test_channel(),
            id_a.fingerprint,
            1000,
            vec![],
            b"hello from sender".to_vec(),
        )
        .unwrap();

        let blob = seal(&mut group_a, &provider_a, &msg).unwrap();
        let decrypted = open(&mut group_b, &provider_b, &blob).unwrap();

        assert_eq!(decrypted.message_type, MessageType::Text);
        assert_eq!(decrypted.channel_id, test_channel());
        assert_eq!(decrypted.sender_fp, id_a.fingerprint);
        assert_eq!(decrypted.content, b"hello from sender");
        assert_eq!(decrypted.message_id, msg.message_id);
    }

    #[test]
    fn reject_spoofed_sender_fp() {
        let provider_a = GhostProvider::new_in_memory().unwrap();
        let provider_b = GhostProvider::new_in_memory().unwrap();
        let id_a = Identity::from_seed([0x01; 32]).unwrap();
        let id_b = Identity::from_seed([0x02; 32]).unwrap();

        let server_id = [0x42; 32];
        let mut group_a =
            GhostGroup::create_with_id(&provider_a, &id_a, &server_id, test_binding(&id_a, 1)).unwrap();
        let kp_b = generate_key_package(&provider_b, &id_b).unwrap();
        let (_commit, welcome) = group_a.add_member(&provider_a, kp_b, test_binding(&id_b, 1)).unwrap();
        let mut group_b =
            GhostGroup::join(&provider_b, &id_b, &welcome.to_bytes().unwrap()).unwrap();

        // Sender crafts a message claiming to be the other member
        let msg = ApplicationMessage::new(
            MessageType::Text,
            test_channel(),
            id_b.fingerprint, // lying about sender
            1000,
            vec![],
            b"forged".to_vec(),
        )
        .unwrap();

        let blob = seal(&mut group_a, &provider_a, &msg).unwrap();
        let result = open(&mut group_b, &provider_b, &blob);
        assert!(result.is_err());
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
    fn sync_sign_verify_roundtrip() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let payload = b"hello sync";
        let signed = sync_sign(&sk, payload);
        let (vk, recovered) = sync_verify(&signed).unwrap();
        assert_eq!(vk, sk.verifying_key().to_bytes());
        assert_eq!(recovered, payload);
    }

    #[test]
    fn sync_verify_rejects_tampered() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let mut signed = sync_sign(&sk, b"original");
        // Tamper with the payload
        *signed.last_mut().unwrap() ^= 0xFF;
        assert!(sync_verify(&signed).is_err());
    }

    #[test]
    fn sync_verify_rejects_too_short() {
        assert!(sync_verify(&[0u8; 95]).is_err());
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
        let encoded = encode_sync_state_dump(&entries);
        let decoded = decode_sync_state_dump(&encoded).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], entries[0]);
        assert_eq!(decoded[1], entries[1]);
        assert_eq!(decoded[2], entries[2]);
    }

    // --- Sync seal/open crypto tests ---

    #[test]
    fn sync_seal_open_roundtrip() {
        let key = [0xAA; 32];
        let plaintext = b"hello multi-device";
        let sealed = sync_seal(&key, plaintext).unwrap();
        assert_ne!(&sealed, plaintext); // not plaintext
        assert_eq!(sealed.len(), 12 + plaintext.len() + 16); // nonce + payload + GCM tag
        let opened = sync_open(&key, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn sync_open_wrong_key_fails() {
        let sealed = sync_seal(&[0xAA; 32], b"secret").unwrap();
        assert!(sync_open(&[0xBB; 32], &sealed).is_err());
    }

    #[test]
    fn sync_open_truncated_blob_fails() {
        let sealed = sync_seal(&[0xAA; 32], b"data").unwrap();
        // Cut off the GCM tag
        assert!(sync_open(&[0xAA; 32], &sealed[..sealed.len() - 4]).is_err());
    }

    #[test]
    fn sync_open_too_short_fails() {
        assert!(sync_open(&[0xAA; 32], &[0u8; 11]).is_err()); // less than nonce
    }

    #[test]
    fn sync_seal_produces_different_nonces() {
        let key = [0xCC; 32];
        let a = sync_seal(&key, b"same").unwrap();
        let b = sync_seal(&key, b"same").unwrap();
        assert_ne!(a[..12], b[..12]); // nonces differ
    }

    #[test]
    fn sync_open_tampered_ciphertext_fails() {
        let key = [0xDD; 32];
        let mut sealed = sync_seal(&key, b"authentic").unwrap();
        sealed[14] ^= 0xFF; // flip a ciphertext byte
        assert!(sync_open(&key, &sealed).is_err());
    }

    // --- Sync sign/verify edge cases ---

    #[test]
    fn sync_verify_wrong_key_in_header_fails() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let mut signed = sync_sign(&sk, b"payload");
        // Corrupt the verifying key bytes — signature check will fail
        signed[0] ^= 0xFF;
        assert!(sync_verify(&signed).is_err());
    }

    #[test]
    fn sync_verify_empty_payload_succeeds() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let signed = sync_sign(&sk, b"");
        let (vk, payload) = sync_verify(&signed).unwrap();
        assert_eq!(vk, sk.verifying_key().to_bytes());
        assert!(payload.is_empty());
    }

    // --- Full sync envelope round trip: sign → seal → wrap → unwrap → open → verify ---

    #[test]
    fn sync_full_pipeline_roundtrip() {
        let device_key = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
        let sync_key = [0x88; 32];
        let mutation = encode_mutation(MUTATION_SET, 5000, "read:abc123", &42u64.to_be_bytes());

        // Sender side
        let signed = sync_sign(&device_key, &mutation);
        let sealed = sync_seal(&sync_key, &signed).unwrap();
        let envelope = wrap_sync_envelope(&sealed);

        // Receiver side: strip envelope header, open, verify
        let sealed_recv = &envelope[ghost_wire::ENVELOPE_HEADER_SIZE..];
        let signed_recv = sync_open(&sync_key, sealed_recv).unwrap();
        let (vk, plaintext) = sync_verify(&signed_recv).unwrap();
        assert_eq!(vk, device_key.verifying_key().to_bytes());

        let (op, ts, key, value) = decode_mutation(&plaintext).unwrap();
        assert_eq!(op, MUTATION_SET);
        assert_eq!(ts, 5000);
        assert_eq!(key, "read:abc123");
        assert_eq!(u64::from_be_bytes(value.try_into().unwrap()), 42);
    }

    // --- Sync state dump edge cases ---

    #[test]
    fn sync_state_dump_empty() {
        let encoded = encode_sync_state_dump(&[]);
        let decoded = decode_sync_state_dump(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn sync_state_dump_decode_truncated_header() {
        assert!(decode_sync_state_dump(&[0x00]).is_err()); // 1 byte, need 2
    }

    #[test]
    fn sync_state_dump_decode_truncated_entry() {
        // Says 1 entry but no data follows
        let data = [0x00, 0x01];
        assert!(decode_sync_state_dump(&data).is_err());
    }

    #[test]
    fn sync_state_dump_decode_truncated_value() {
        // Build a valid entry header then cut off the value
        let entries = vec![("k".to_string(), Some(vec![0xAA; 100]), 1)];
        let mut encoded = encode_sync_state_dump(&entries);
        encoded.truncate(encoded.len() - 50); // chop value
        assert!(decode_sync_state_dump(&encoded).is_err());
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
                    role: MemberRole::Creator,
                },
                InviteMember {
                    fingerprint: [0x33; 32],
                    display_name: "Bob".to_string(),
                    role: MemberRole::Member,
                },
            ],
            channels: vec![
                InviteChannel {
                    channel_id: [0x44; 32],
                    name: "general".to_string(),
                    kind: ChannelKind::Text,
                    position: 0,
                },
                InviteChannel {
                    channel_id: [0x55; 32],
                    name: "voice".to_string(),
                    kind: ChannelKind::Voice,
                    position: 1,
                },
            ],
            mailbox_id: [0x66; 32],
        };
        let bytes = pp.to_bytes();
        let decoded = ProvisionPayload::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.server_id, pp.server_id);
        assert_eq!(decoded.server_name, pp.server_name);
        assert_eq!(decoded.members.len(), 2);
        assert_eq!(decoded.members[0].display_name, "Alice");
        assert_eq!(decoded.members[1].fingerprint, [0x33; 32]);
        assert_eq!(decoded.channels.len(), 2);
        assert_eq!(decoded.channels[0].name, "general");
        assert_eq!(decoded.channels[1].name, "voice");
        assert_eq!(decoded.mailbox_id, pp.mailbox_id);
    }

    #[test]
    fn provision_payload_empty_server() {
        let pp = ProvisionPayload {
            server_id: [0xFF; 32],
            server_name: "Empty".to_string(),
            kind: ServerKind::Dm,
            members: vec![],
            channels: vec![],
            mailbox_id: [0xEE; 32],
        };
        let bytes = pp.to_bytes();
        let decoded = ProvisionPayload::from_bytes(&bytes).unwrap();
        assert!(decoded.members.is_empty());
        assert!(decoded.channels.is_empty());
    }

    #[test]
    fn provision_payload_truncated_fails() {
        let pp = ProvisionPayload {
            server_id: [0x11; 32],
            server_name: "Test".to_string(),
            kind: ServerKind::Server,
            members: vec![],
            channels: vec![],
            mailbox_id: [0x22; 32],
        };
        let bytes = pp.to_bytes();
        assert!(ProvisionPayload::from_bytes(&bytes[..bytes.len() - 10]).is_err());
    }

    #[test]
    fn provision_payload_trailing_bytes_rejected() {
        let pp = ProvisionPayload {
            server_id: [0x11; 32],
            server_name: "Test".to_string(),
            kind: ServerKind::Server,
            members: vec![],
            channels: vec![],
            mailbox_id: [0x22; 32],
        };
        let mut bytes = pp.to_bytes();
        bytes.push(0xFF); // trailing junk
        assert!(ProvisionPayload::from_bytes(&bytes).is_err());
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
            }],
            mailbox_id: [0x33; 32],
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
        blob.extend_from_slice(&encode_sync_state_dump(&sync_entries));

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

    #[test]
    fn sync_state_dump_large_roundtrip() {
        // Many entries to stress the count/offset logic
        let entries: Vec<_> = (0..200)
            .map(|i| (format!("key:{i}"), Some(vec![i as u8; 10]), i as u64))
            .collect();
        let encoded = encode_sync_state_dump(&entries);
        let decoded = decode_sync_state_dump(&encoded).unwrap();
        assert_eq!(decoded.len(), 200);
        assert_eq!(decoded[199].0, "key:199");
    }

    // --- Domain separation ---

    #[test]
    fn derivation_domain_separation() {
        // All derivation functions must produce different outputs for the same input
        let id = [0xAA; 32];
        let mls_gid = derive_mls_group_id(&id);
        let channel = derive_default_channel_id(&id);
        let mailbox = mls_group_mailbox_id(&id);
        let sync_mb = sync_mailbox_id(&id);
        // All four must be different (domain tags prevent collisions)
        let all = [mls_gid, channel, mailbox, sync_mb];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "domain separation failed between derivation {i} and {j}");
            }
        }
    }

    // --- InvitePayload tests ---

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
                    role: MemberRole::Creator,
                },
                InviteMember {
                    fingerprint: [0x33; 32],
                    display_name: "Bob".to_string(),
                    role: MemberRole::Member,
                },
            ],
            channels: vec![InviteChannel {
                channel_id: [0x44; 32],
                name: "general".to_string(),
                kind: ChannelKind::Text,
                position: 5,
            }],
            group_info_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
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
        assert_eq!(decoded.group_info_bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn invite_payload_truncated_rejected() {
        let payload = InvitePayload {
            server_id: [0x11; 32],
            server_name: "Test".to_string(),
            kind: ServerKind::Server,
            members: vec![],
            channels: vec![],
            group_info_bytes: vec![0xAA; 16],
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
            group_info_bytes: vec![0xBB; 8],
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
    fn avatar_clear_roundtrip() {
        let encoded = encode_avatar_clear();
        let decoded = decode_metadata(&encoded).unwrap();
        assert!(matches!(decoded, MetadataPayload::AvatarClear));
    }

    // --- Sync envelope header test ---

    #[test]
    fn sync_envelope_header_valid() {
        let payload = b"test-sync-payload";
        let sealed = sync_seal(&[0xCC; 32], payload).unwrap();
        let envelope = wrap_sync_envelope(&sealed);

        // Header is exactly ENVELOPE_HEADER_SIZE bytes
        assert!(envelope.len() == ghost_wire::ENVELOPE_HEADER_SIZE + sealed.len());

        // Payload follows immediately after header
        assert_eq!(&envelope[ghost_wire::ENVELOPE_HEADER_SIZE..], &sealed[..]);
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
                },
                InviteChannel {
                    channel_id: [0xCC; 32],
                    name: "voice".into(),
                    kind: ChannelKind::Voice,
                    position: 1,
                },
            ],
        };
        let bytes = meta.to_bytes();
        let decoded = SyncServerMeta::from_bytes(&bytes).unwrap();

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
    fn sync_server_meta_trailing_bytes_rejected() {
        let meta = SyncServerMeta {
            server_name: "x".into(),
            kind: ServerKind::Dm,
            mailbox_id: [0x11; 32],
            channels: vec![],
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
        };
        let bytes = meta.to_bytes();
        let decoded = SyncServerMeta::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.server_name, "empty");
        assert!(decoded.channels.is_empty());
    }
}
