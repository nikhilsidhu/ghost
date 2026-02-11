use openmls::prelude::Ciphersuite;

/// Which MLS ciphersuite all Ghost groups use.
pub const MLS_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Label used when deriving per-sender voice encryption keys from MLS epoch secrets.
pub const VOICE_EXPORT_LABEL: &str = "ghost-voice";

/// HKDF domain-separation label for deriving X25519 keys from identity seeds.
pub const X25519_DERIVE_LABEL: &[u8] = b"ghost-x25519";

/// How many bytes of a fingerprint to use for short display names (produces 2x hex chars).
pub const FINGERPRINT_SHORT_BYTES: usize = 8;

/// HKDF domain-separation label for deriving the SQLCipher database encryption key from the identity seed.
pub const DB_KEY_DERIVE_LABEL: &[u8] = b"ghost-db-key";

// Wire protocol version
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Wire message type discriminant, serialized as u8 on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    // User content
    Text = 0x01,
    Reaction = 0x03,
    System = 0x05,
    Delete = 0x06,
    // Group management
    Metadata = 0x07,
    // Protocol control
    DmWelcome = 0x08,
    FriendRequest = 0x09,
    FriendAccept = 0x0A,
}

impl From<MessageType> for u8 {
    fn from(mt: MessageType) -> u8 {
        mt as u8
    }
}

impl TryFrom<u8> for MessageType {
    type Error = u8;
    fn try_from(v: u8) -> std::result::Result<Self, u8> {
        match v {
            0x01 => Ok(Self::Text),
            0x03 => Ok(Self::Reaction),
            0x05 => Ok(Self::System),
            0x06 => Ok(Self::Delete),
            0x07 => Ok(Self::Metadata),
            0x08 => Ok(Self::DmWelcome),
            0x09 => Ok(Self::FriendRequest),
            0x0A => Ok(Self::FriendAccept),
            other => Err(other),
        }
    }
}

// BLAKE3 domain-separation tags for ID derivation
pub const MLS_GROUP_ID_TAG: &[u8] = b"ghost-mls";
pub const MAILBOX_ID_TAG: &[u8] = b"ghost-mailbox";
pub const DEFAULT_CHANNEL_TAG: &[u8] = b"ghost-default-channel";
