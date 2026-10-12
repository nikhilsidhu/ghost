pub mod account_key;
pub mod anchor;
pub mod auth;
pub mod batch;
pub mod bytes;
pub mod idlog;
pub mod log_entries;
pub mod merkle;
pub mod policy;
#[cfg(feature = "mls")]
pub mod policy_mls;
pub mod presence;
pub mod relay_ref;
pub mod server_location;
#[cfg(test)]
mod test_support;
pub mod voice;

/// Envelope framing for blobs transiting the relay.
///
/// Every blob sent to the relay is prefixed with a 10-byte plaintext header
/// that the relay can inspect without decrypting:
///
///   [version:1][type:1][epoch:8 BE][ciphertext...]
///
/// The relay uses `type` and `epoch` for ordering guarantees (epoch gating on
/// commits). Everything after the header is opaque ciphertext.

use thiserror::Error;

pub const ENVELOPE_VERSION: u8 = 0x01;
pub const ENVELOPE_HEADER_SIZE: usize = 10;

/// Tag appended to MLS group ID before hashing to derive the mailbox ID.
pub const MAILBOX_ID_TAG: &[u8] = b"ghost-mailbox-v1";

/// Derive a relay mailbox ID from an MLS group ID.
pub fn mls_group_mailbox_id(mls_group_id: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(mls_group_id);
    hasher.update(MAILBOX_ID_TAG);
    hasher.finalize().into()
}

/// Tag for the group id the account's sync mailbox derives from; kept from when the
/// mailbox carried an MLS group, so existing accounts' mailboxes stay where they are.
const SYNC_GROUP_TAG: &[u8] = b"ghost-sync-group-v1";

/// The mailbox an account's devices sync through, the same on every relay. Relays admit
/// only the account's active devices to it and take no MLS messages there.
/// The first eight bytes of an identifier as hex: how fingerprints, mailbox, server,
/// channel and message ids read in logs and messages.
/// Milliseconds since the Unix epoch: the clock every timestamp in Ghost is read from.
pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn short_id(id: &[u8]) -> String {
    hex::encode(&id[..id.len().min(8)])
}

pub fn sync_mailbox_id(account_fp: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(account_fp);
    hasher.update(SYNC_GROUP_TAG);
    mls_group_mailbox_id(hasher.finalize().as_bytes())
}

// WS frame: [seq:8 BE][received_at:8 BE][payload...]
pub const WS_SEQ_SIZE: usize = 8;
pub const WS_TIMESTAMP_SIZE: usize = 8;
pub const WS_FRAME_HEADER_SIZE: usize = WS_SEQ_SIZE + WS_TIMESTAMP_SIZE;

// WS text signals
/// Sent before anything else on a connection that asked for entries the relay no longer
/// keeps, followed by the sequence the connection resumes after: everything up to it is
/// skipped, as unprocessable once the device rebuilds its group state.
pub const WS_SIGNAL_GAP: &str = "gap ";
/// Sent once everything the mailbox held past the device's resume point when it connected
/// has gone out; only live entries follow. Until then the device is catching up.
pub const WS_SIGNAL_CAUGHT_UP: &str = "caught-up";
/// A posted blob the relay refused is answered `error: <status> <message>`, in the
/// order the blobs were posted; an accepted one is answered with its sequence number.
pub const WS_ERROR_PREFIX: &str = "error: ";
/// Sent on a server mailbox connection when a private channel of that server newly
/// admits the connected account (created, or its access changed), so the device runs
/// discovery. Only admitted accounts receive it, so others learn nothing.
pub const WS_SIGNAL_CHANNELS: &str = "channels";


/// The relay protocol generation that understands account keys: root rotation, device
/// keys, account key sets, batches and the fork rule.
pub const RELAY_PROTOCOL_ACCOUNT_KEYS: u32 = 4;

/// Header on a relay refusal naming why, so the client can explain it.
pub const REFUSAL_HEADER: &str = "X-Ghost-Refusal";
/// Refused because the account was removed from the server and not let back in.
pub const REFUSAL_REMOVED: &str = "removed";
/// Refused because the account's log revokes the signing device. Only a request that
/// device signed is told, so nobody else learns a device's status.
pub const REFUSAL_DEVICE_REVOKED: &str = "device-revoked";
/// Beside a `device-revoked` refusal: what revoked the device (`RevocationCause::encode`).
pub const REVOKED_BY_HEADER: &str = "X-Ghost-Revoked-By";

/// What revoked a device, as relays tell that device alone, on its own signed request or
/// its own connection: the device can read nothing else of its account any more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationCause {
    /// The account was recovered on another device, which revoked every other one.
    Recovery,
    /// The recovery key removed it.
    RecoveryKey,
    /// Another device of the account removed it; that device's label.
    Device(String),
}

impl RevocationCause {
    /// `recovery`, `recovery-key`, or `device ` and the label in base64: a label as
    /// long as an entry allows still fits a WebSocket close reason (123 bytes).
    pub fn encode(&self) -> String {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        match self {
            Self::Recovery => "recovery".into(),
            Self::RecoveryKey => "recovery-key".into(),
            Self::Device(label) => {
                let mut end = label.len().min(idlog::MAX_DEVICE_LABEL_BYTES);
                while !label.is_char_boundary(end) {
                    end -= 1;
                }
                format!("device {}", STANDARD.encode(&label.as_bytes()[..end]))
            }
        }
    }

    pub fn decode(text: &str) -> Option<Self> {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        match text {
            "recovery" => Some(Self::Recovery),
            "recovery-key" => Some(Self::RecoveryKey),
            _ => {
                let label = STANDARD.decode(text.strip_prefix("device ")?).ok()?;
                Some(Self::Device(String::from_utf8(label).ok()?))
            }
        }
    }
}

// WS close codes (4000-4999 = application-defined)
pub const WS_CLOSE_DEVICE_REVOKED: u16 = 4001;
/// The account was removed from the group whose mailbox (or voice room) this was.
pub const WS_CLOSE_REMOVED: u16 = 4002;
/// The relay's grounds for admitting the device are gone (its account moved home away
/// and belongs to no group here). Reconnecting gets the relay's answer for it.
pub const WS_CLOSE_ADMISSION_CHANGED: u16 = 4003;
/// Another device of the account joined the voice room, which holds one per account.
pub const WS_CLOSE_VOICE_REPLACED: u16 = 4004;

/// How long a pairing session lives on the relay. The existing device can complete a link
/// only while it lives, so neither device needs to wait longer, the new one aside: it
/// waits a little more for the batch that lands just after.
pub const PAIRING_TTL_MS: u64 = 10 * 60 * 1000;

/// An invite token is this many random bytes, hex-encoded.
pub const INVITE_TOKEN_LEN: usize = 16;

/// Length of the media packet header (see `voice::MediaHeader`).
pub const VOICE_HEADER_SIZE: usize = 53;
pub const VOICE_MAX_PACKET: usize = 1500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EnvelopeType {
    Application = 0x00,
    Commit = 0x01,
    Proposal = 0x02,
}

impl TryFrom<u8> for EnvelopeType {
    type Error = u8;
    fn try_from(v: u8) -> Result<Self, u8> {
        match v {
            0x00 => Ok(Self::Application),
            0x01 => Ok(Self::Commit),
            0x02 => Ok(Self::Proposal),
            other => Err(other),
        }
    }
}

impl From<EnvelopeType> for u8 {
    fn from(t: EnvelopeType) -> u8 {
        t as u8
    }
}

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("truncated envelope: need {ENVELOPE_HEADER_SIZE} bytes, got {0}")]
    Truncated(usize),
    #[error("unsupported envelope version: {0:#04x}")]
    BadVersion(u8),
    #[error("unknown envelope type: {0:#04x}")]
    BadType(u8),
}

/// Encode a 10-byte envelope header.
pub fn encode_envelope(envelope_type: EnvelopeType, epoch: u64) -> [u8; ENVELOPE_HEADER_SIZE] {
    let mut buf = [0u8; ENVELOPE_HEADER_SIZE];
    buf[0] = ENVELOPE_VERSION;
    buf[1] = envelope_type as u8;
    buf[2..10].copy_from_slice(&epoch.to_be_bytes());
    buf
}

/// Decode the envelope header from a blob. Returns (type, epoch).
pub fn decode_envelope(data: &[u8]) -> Result<(EnvelopeType, u64), EnvelopeError> {
    if data.len() < ENVELOPE_HEADER_SIZE {
        return Err(EnvelopeError::Truncated(data.len()));
    }
    let version = data[0];
    if version != ENVELOPE_VERSION {
        return Err(EnvelopeError::BadVersion(version));
    }
    let envelope_type =
        EnvelopeType::try_from(data[1]).map_err(EnvelopeError::BadType)?;
    let epoch = u64::from_be_bytes(data[2..10].try_into().unwrap());
    Ok((envelope_type, epoch))
}

/// Return the payload after the envelope header.
pub fn envelope_payload(data: &[u8]) -> &[u8] {
    &data[ENVELOPE_HEADER_SIZE..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_mailbox_is_fixed_per_account_and_distinct_between_accounts() {
        assert_eq!(sync_mailbox_id(&[1; 32]), sync_mailbox_id(&[1; 32]));
        assert_ne!(sync_mailbox_id(&[1; 32]), sync_mailbox_id(&[2; 32]));
        assert_ne!(sync_mailbox_id(&[1; 32]), mls_group_mailbox_id(&[1; 32]), "not a group's own mailbox");
    }

    #[test]
    fn a_revocation_cause_survives_a_close_reason() {
        let longest = "é".repeat(idlog::MAX_DEVICE_LABEL_BYTES / 2);
        for cause in [RevocationCause::Recovery, RevocationCause::RecoveryKey, RevocationCause::Device("phone: \"work\"".into()), RevocationCause::Device(longest)] {
            let text = cause.encode();
            assert!(text.len() <= 123, "fits a WebSocket close reason: {text}");
            assert!(header_safe(&text), "fits a header: {text}");
            assert_eq!(RevocationCause::decode(&text), Some(cause));
        }
        assert_eq!(RevocationCause::decode("device revoked"), None, "the bare reason tells no cause");
    }

    fn header_safe(text: &str) -> bool {
        text.bytes().all(|b| b == b' ' || b.is_ascii_graphic())
    }

    #[test]
    fn roundtrip_application() {
        let header = encode_envelope(EnvelopeType::Application, 42);
        let mut blob = header.to_vec();
        blob.extend_from_slice(b"ciphertext");

        let (typ, epoch) = decode_envelope(&blob).unwrap();
        assert_eq!(typ, EnvelopeType::Application);
        assert_eq!(epoch, 42);
        assert_eq!(envelope_payload(&blob), b"ciphertext");
    }

    #[test]
    fn roundtrip_commit() {
        let header = encode_envelope(EnvelopeType::Commit, u64::MAX);
        let (typ, epoch) = decode_envelope(&header).unwrap();
        assert_eq!(typ, EnvelopeType::Commit);
        assert_eq!(epoch, u64::MAX);
    }

    #[test]
    fn roundtrip_proposal() {
        let header = encode_envelope(EnvelopeType::Proposal, 0);
        let (typ, epoch) = decode_envelope(&header).unwrap();
        assert_eq!(typ, EnvelopeType::Proposal);
        assert_eq!(epoch, 0);
    }

    #[test]
    fn reject_truncated() {
        assert!(matches!(
            decode_envelope(&[0x01, 0x00]),
            Err(EnvelopeError::Truncated(2))
        ));
        assert!(matches!(
            decode_envelope(&[]),
            Err(EnvelopeError::Truncated(0))
        ));
    }

    #[test]
    fn reject_bad_version() {
        let mut header = encode_envelope(EnvelopeType::Application, 1);
        header[0] = 0xFF;
        assert!(matches!(
            decode_envelope(&header),
            Err(EnvelopeError::BadVersion(0xFF))
        ));
    }

    #[test]
    fn reject_unknown_type() {
        let mut header = encode_envelope(EnvelopeType::Application, 1);
        header[1] = 0xAA;
        assert!(matches!(
            decode_envelope(&header),
            Err(EnvelopeError::BadType(0xAA))
        ));
    }

    #[test]
    fn epoch_byte_order_preserved() {
        let header = encode_envelope(EnvelopeType::Commit, 0x0102030405060708);
        let (_, epoch) = decode_envelope(&header).unwrap();
        assert_eq!(epoch, 0x0102030405060708);
    }
}

/// Bytes in the generation prefix of a replicated sync snapshot.
pub const SNAPSHOT_GENERATION_LEN: usize = 8;
