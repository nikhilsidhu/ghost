pub mod auth;
pub mod idlog;
pub mod merkle;

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

// WS frame: [seq:8 BE][received_at:8 BE][payload...]
pub const WS_SEQ_SIZE: usize = 8;
pub const WS_TIMESTAMP_SIZE: usize = 8;
pub const WS_FRAME_HEADER_SIZE: usize = WS_SEQ_SIZE + WS_TIMESTAMP_SIZE;

// WS text signals
pub const WS_SIGNAL_GAP: &str = "gap";
pub const WS_SIGNAL_EPOCH_MISMATCH: &str = "epoch_mismatch";

// WS close codes (4000-4999 = application-defined)
pub const WS_CLOSE_DEVICE_REVOKED: u16 = 4001;

// Voice packet: [header_len:2][channel_id:32][slot_id:4][flags:1][seq:4][payload_len:2][payload...]
// Relay reads first 38 bytes (header_len + channel_id + slot_id) for routing.
// slot_id is relay-assigned per WS connection; replaces fingerprint in the header.
pub const VOICE_HEADER_SIZE: usize = 45;
pub const VOICE_RELAY_PREFIX: usize = 38;
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
