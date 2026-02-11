use openmls::prelude::ProcessedMessageContent;

use crate::crypto::{
    DEFAULT_CHANNEL_TAG, GhostProvider, MessageType, MAILBOX_ID_TAG, MLS_GROUP_ID_TAG,
    PROTOCOL_VERSION,
};
use crate::error::{GhostError, Result};
use crate::mls::group::GhostGroup;

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
        if data.len() < FIXED_HEADER_LEN {
            return Err(GhostError::Format("message too short".into()));
        }

        let mut pos = 0;

        let version = data[pos];
        pos += 1;
        if version != PROTOCOL_VERSION {
            return Err(GhostError::Format(format!(
                "unsupported version: {version:#04x}"
            )));
        }

        let type_byte = data[pos];
        pos += 1;
        let message_type = MessageType::try_from(type_byte)
            .map_err(|v| GhostError::Format(format!("unknown message type: {v:#04x}")))?;

        let channel_id: [u8; 32] = data[pos..pos + 32]
            .try_into()
            .map_err(|_| GhostError::Format("bad channel_id".into()))?;
        pos += 32;

        let sender_fp: [u8; 32] = data[pos..pos + 32]
            .try_into()
            .map_err(|_| GhostError::Format("bad sender_fp".into()))?;
        pos += 32;

        let timestamp = u64::from_be_bytes(
            data[pos..pos + 8]
                .try_into()
                .map_err(|_| GhostError::Format("bad timestamp".into()))?,
        );
        pos += 8;

        let message_id: [u8; 32] = data[pos..pos + 32]
            .try_into()
            .map_err(|_| GhostError::Format("bad message_id".into()))?;
        pos += 32;

        let ref_count = data[pos] as usize;
        pos += 1;

        if data.len() < pos + ref_count * 32 + 4 {
            return Err(GhostError::Format("truncated references".into()));
        }

        let mut references = Vec::with_capacity(ref_count);
        for _ in 0..ref_count {
            let r: [u8; 32] = data[pos..pos + 32]
                .try_into()
                .map_err(|_| GhostError::Format("bad reference".into()))?;
            pos += 32;
            references.push(r);
        }

        let content_len = u32::from_be_bytes(
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| GhostError::Format("bad content_len".into()))?,
        ) as usize;
        pos += 4;

        if pos + content_len != data.len() {
            return Err(GhostError::Format(format!(
                "expected {} bytes, got {}",
                pos + content_len,
                data.len()
            )));
        }

        let content = data[pos..pos + content_len].to_vec();

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

/// Encrypted blob addressed to a relay mailbox.
pub struct Outbound {
    pub mailbox_id: [u8; 32],
    pub blob: Vec<u8>,
}

/// Serialize an ApplicationMessage and MLS-encrypt it into transport bytes.
pub fn seal(
    group: &mut GhostGroup,
    provider: &GhostProvider,
    msg: &ApplicationMessage,
) -> Result<Vec<u8>> {
    let plaintext = msg.to_bytes();
    let mls_out = group.encrypt(provider, &plaintext)?;
    mls_out
        .to_bytes()
        .map_err(|e| GhostError::Mls(format!("serialize ciphertext: {e}")))
}

/// MLS-decrypt transport bytes and deserialize into an ApplicationMessage.
pub fn open(
    group: &mut GhostGroup,
    provider: &GhostProvider,
    blob: &[u8],
) -> Result<ApplicationMessage> {
    let processed = group.process_message_bytes(provider, blob)?;
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => {
            ApplicationMessage::from_bytes(&app_msg.into_bytes())
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
        let provider = GhostProvider::new();
        let alice = Identity::from_seed([0x01; 32]).unwrap();
        let app_group_id = [0x42; 32];
        let group = GhostGroup::create_with_id(&provider, &alice, &app_group_id).unwrap();

        let expected = derive_mls_group_id(&app_group_id);
        assert_eq!(group.group_id(), expected);
    }

    #[test]
    fn seal_open_roundtrip() {
        let alice_provider = GhostProvider::new();
        let bob_provider = GhostProvider::new();
        let alice = Identity::from_seed([0x01; 32]).unwrap();
        let bob = Identity::from_seed([0x02; 32]).unwrap();

        let app_group_id = [0x42; 32];
        let mut alice_group =
            GhostGroup::create_with_id(&alice_provider, &alice, &app_group_id).unwrap();
        let bob_kp = generate_key_package(&bob_provider, &bob).unwrap();
        let (_commit, welcome) = alice_group.add_member(&alice_provider, bob_kp).unwrap();
        let mut bob_group =
            GhostGroup::join_from_welcome(&bob_provider, &bob, welcome).unwrap();

        let msg = ApplicationMessage::new(
            MessageType::Text,
            test_channel(),
            alice.fingerprint,
            1000,
            vec![],
            b"hello from alice".to_vec(),
        )
        .unwrap();

        let blob = seal(&mut alice_group, &alice_provider, &msg).unwrap();
        let decrypted = open(&mut bob_group, &bob_provider, &blob).unwrap();

        assert_eq!(decrypted.message_type, MessageType::Text);
        assert_eq!(decrypted.channel_id, test_channel());
        assert_eq!(decrypted.sender_fp, alice.fingerprint);
        assert_eq!(decrypted.content, b"hello from alice");
        assert_eq!(decrypted.message_id, msg.message_id);
    }

    #[test]
    fn seal_open_with_references() {
        let alice_provider = GhostProvider::new();
        let bob_provider = GhostProvider::new();
        let alice = Identity::from_seed([0x01; 32]).unwrap();
        let bob = Identity::from_seed([0x02; 32]).unwrap();

        let app_group_id = [0x42; 32];
        let mut alice_group =
            GhostGroup::create_with_id(&alice_provider, &alice, &app_group_id).unwrap();
        let bob_kp = generate_key_package(&bob_provider, &bob).unwrap();
        let (_commit, welcome) = alice_group.add_member(&alice_provider, bob_kp).unwrap();
        let mut bob_group =
            GhostGroup::join_from_welcome(&bob_provider, &bob, welcome).unwrap();

        let target = [0xCC; 32];
        let msg = ApplicationMessage::new(
            MessageType::Text,
            test_channel(),
            bob.fingerprint,
            2000,
            vec![target],
            b"replying".to_vec(),
        )
        .unwrap();

        let blob = seal(&mut bob_group, &bob_provider, &msg).unwrap();
        let decrypted = open(&mut alice_group, &alice_provider, &blob).unwrap();

        assert_eq!(decrypted.references.len(), 1);
        assert_eq!(decrypted.references[0], target);
        assert_eq!(decrypted.content, b"replying");
    }
}
