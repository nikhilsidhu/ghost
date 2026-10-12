use openmls::prelude::Ciphersuite;

/// Which MLS ciphersuite all Ghost groups use.
pub const MLS_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Label used when deriving per-sender voice encryption keys from the MLS group's shared secret.
pub const VOICE_EXPORT_LABEL: &str = "ghost-voice";

/// Label used when deriving per-sender presence encryption keys from the MLS group's shared secret.
pub const VOICE_PRESENCE_EXPORT_LABEL: &str = "ghost-voice-presence";

/// Label used when deriving per-sender online presence keys (server-wide, no channel context).
pub const ONLINE_PRESENCE_EXPORT_LABEL: &str = "ghost-online-presence";

/// Label used when deriving Ed25519 signing keys from identity seeds.
pub const ED25519_DERIVE_LABEL: &[u8] = b"ghost-ed25519";

/// HKDF labels deriving the account's root and recovery box key from its recovery key.
pub const RECOVERY_ROOT_LABEL: &[u8] = b"ghost/recovery-key/root/v1";
pub const RECOVERY_BOX_LABEL: &[u8] = b"ghost/recovery-key/box/v1";

/// HKDF labels deriving one account key generation's keys from its seed.
pub const ACCOUNT_KEY_SIGN_LABEL: &[u8] = b"ghost/account-key/sign/v1";
pub const ACCOUNT_KEY_ENCRYPTION_LABEL: &[u8] = b"ghost/account-key/encryption/v1";
pub const ACCOUNT_KEY_SYNC_LABEL: &[u8] = b"ghost/account-key/sync/v1";
pub const ACCOUNT_KEY_BACKLINK_LABEL: &[u8] = b"ghost/account-key/backlink/v1";

/// Domain separator for a device's signature on a sync message, so only the account's
/// active devices can speak in its sync channel.
pub const SYNC_SIGN_PREFIX: &[u8] = b"ghost-sync-v2:";

/// How many bytes of a fingerprint to use for short display names (produces 2x hex chars).
pub const FINGERPRINT_SHORT_BYTES: usize = 8;

// Wire protocol version
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Wire message type discriminant, serialized as u8 on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Text = 0x01,
    /// A tombstone: the row stays so references to it still resolve.
    Delete = 0x06,
    /// Group management, never stored as chat.
    Metadata = 0x07,
    /// Stands in a channel's history for a message this device could not decrypt. Never
    /// sent: it is made on the receiving device, which has no sender for it.
    Undecryptable = 0x0B,
    /// Marks where a channel's history skips what its relay no longer kept when this
    /// device came back. Never sent, like `Undecryptable`.
    HistoryGap = 0x0C,
}

impl MessageType {
    /// Made by the receiving device for its own history, never sent: one arriving from
    /// a sender is refused.
    pub fn is_local(self) -> bool {
        matches!(self, Self::Undecryptable | Self::HistoryGap)
    }
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
            0x06 => Ok(Self::Delete),
            0x07 => Ok(Self::Metadata),
            0x0B => Ok(Self::Undecryptable),
            0x0C => Ok(Self::HistoryGap),
            other => Err(other),
        }
    }
}

// Tags used to derive unique IDs from a shared seed
pub const MLS_GROUP_ID_TAG: &[u8] = b"ghost-mls";
pub const MAILBOX_ID_TAG: &[u8] = b"ghost-mailbox";
pub const DEFAULT_CHANNEL_TAG: &[u8] = b"ghost-default-channel";
/// Tag deriving the id of the message that stands in for an undecryptable blob from the
/// blob's mailbox and sequence number.
pub const UNDECRYPTABLE_ID_TAG: &[u8] = b"ghost-undecryptable";
/// Tag deriving the id of a history gap marker from the mailbox and the sequence the
/// device resumed after.
pub const HISTORY_GAP_ID_TAG: &[u8] = b"ghost-history-gap";
