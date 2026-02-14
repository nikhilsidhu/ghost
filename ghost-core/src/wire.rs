use openmls::prelude::ProcessedMessageContent;
use openmls::prelude::BasicCredential;

use crate::crypto::{
    DEFAULT_CHANNEL_TAG, GhostProvider, MessageType, MAILBOX_ID_TAG, MLS_GROUP_ID_TAG,
    PROTOCOL_VERSION,
};
use crate::error::{GhostError, Result};
use crate::mls::group::GhostGroup;
use crate::storage::{ChannelKind, MemberRole};

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

pub fn derive_mls_group_id(group_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(group_id);
    hasher.update(MLS_GROUP_ID_TAG);
    hasher.finalize().into()
}

pub fn group_mailbox_id(mls_group_id: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(mls_group_id);
    hasher.update(MAILBOX_ID_TAG);
    hasher.finalize().into()
}

pub fn derive_default_channel_id(group_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(group_id);
    hasher.update(DEFAULT_CHANNEL_TAG);
    hasher.finalize().into()
}

// --- InvitePayload: metadata + GroupInfo for external commit joins ---

pub struct InviteMember {
    pub fingerprint: [u8; 32],
    pub display_name: String,
    pub role: MemberRole,
}

pub struct InviteChannel {
    pub channel_id: [u8; 32],
    pub name: String,
    pub kind: ChannelKind,
    pub position: i32,
}

pub struct InvitePayload {
    pub group_id: [u8; 32],
    pub group_name: String,
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
        buf.extend_from_slice(&self.group_id);
        write_string(&mut buf, &self.group_name);

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

        let group_id = read_blob32(data, &mut pos)?;
        let group_name = read_string(data, &mut pos)?;

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

        Ok(Self { group_id, group_name, members, channels, group_info_bytes })
    }
}

// --- open_any: handle both app messages and commits from the relay ---

pub enum InboundMessage {
    Application(ApplicationMessage),
    Commit,
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
            group.merge_staged_commit(provider, *staged_commit)?;
            Ok(InboundMessage::Commit)
        }
        _ => Err(GhostError::Mls("unexpected message type".into())),
    }
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
    fn message_id_deterministic() {
        let a = derive_message_id(&test_channel(), &test_sender(), 1000, b"hello");
        let b = derive_message_id(&test_channel(), &test_sender(), 1000, b"hello");
        assert_eq!(a, b);
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
    fn mls_group_id_deterministic() {
        let gid = [0x11; 32];
        let a = derive_mls_group_id(&gid);
        let b = derive_mls_group_id(&gid);
        assert_eq!(a, b);

        let different = derive_mls_group_id(&[0x22; 32]);
        assert_ne!(a, different);
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
    fn mailbox_id_deterministic() {
        let mls_id = derive_mls_group_id(&[0x33; 32]);
        let a = group_mailbox_id(&mls_id);
        let b = group_mailbox_id(&mls_id);
        assert_eq!(a, b);

        let different = group_mailbox_id(&[0x44; 32]);
        assert_ne!(a, different);
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
        let app_group_id = [0x42; 32];
        let group = GhostGroup::create_with_id(&provider, &id, &app_group_id).unwrap();

        let expected = derive_mls_group_id(&app_group_id);
        assert_eq!(group.group_id(), expected);
    }

    #[test]
    fn seal_open_roundtrip() {
        let provider_a = GhostProvider::new_in_memory().unwrap();
        let provider_b = GhostProvider::new_in_memory().unwrap();
        let id_a = Identity::from_seed([0x01; 32]).unwrap();
        let id_b = Identity::from_seed([0x02; 32]).unwrap();

        let app_group_id = [0x42; 32];
        let mut group_a =
            GhostGroup::create_with_id(&provider_a, &id_a, &app_group_id).unwrap();
        let kp_b = generate_key_package(&provider_b, &id_b).unwrap();
        let (_commit, welcome) = group_a.add_member(&provider_a, kp_b).unwrap();
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
    fn seal_open_with_references() {
        let provider_a = GhostProvider::new_in_memory().unwrap();
        let provider_b = GhostProvider::new_in_memory().unwrap();
        let id_a = Identity::from_seed([0x01; 32]).unwrap();
        let id_b = Identity::from_seed([0x02; 32]).unwrap();

        let app_group_id = [0x42; 32];
        let mut group_a =
            GhostGroup::create_with_id(&provider_a, &id_a, &app_group_id).unwrap();
        let kp_b = generate_key_package(&provider_b, &id_b).unwrap();
        let (_commit, welcome) = group_a.add_member(&provider_a, kp_b).unwrap();
        let mut group_b =
            GhostGroup::join(&provider_b, &id_b, &welcome.to_bytes().unwrap()).unwrap();

        let target = [0xCC; 32];
        let msg = ApplicationMessage::new(
            MessageType::Text,
            test_channel(),
            id_b.fingerprint,
            2000,
            vec![target],
            b"replying".to_vec(),
        )
        .unwrap();

        let blob = seal(&mut group_b, &provider_b, &msg).unwrap();
        let decrypted = open(&mut group_a, &provider_a, &blob).unwrap();

        assert_eq!(decrypted.references.len(), 1);
        assert_eq!(decrypted.references[0], target);
        assert_eq!(decrypted.content, b"replying");
    }

    #[test]
    fn reject_spoofed_sender_fp() {
        let provider_a = GhostProvider::new_in_memory().unwrap();
        let provider_b = GhostProvider::new_in_memory().unwrap();
        let id_a = Identity::from_seed([0x01; 32]).unwrap();
        let id_b = Identity::from_seed([0x02; 32]).unwrap();

        let app_group_id = [0x42; 32];
        let mut group_a =
            GhostGroup::create_with_id(&provider_a, &id_a, &app_group_id).unwrap();
        let kp_b = generate_key_package(&provider_b, &id_b).unwrap();
        let (_commit, welcome) = group_a.add_member(&provider_a, kp_b).unwrap();
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
}
