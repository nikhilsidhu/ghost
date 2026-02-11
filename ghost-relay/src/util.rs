use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::error::RelayError;

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub fn decode_mailbox_id(encoded: &str) -> crate::error::Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| RelayError::BadRequest("invalid base64url mailbox id".into()))?;
    bytes
        .try_into()
        .map_err(|_| RelayError::BadRequest("mailbox id must be 32 bytes".into()))
}
