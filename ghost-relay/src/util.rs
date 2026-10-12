
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::error::RelayError;

pub use ghost_wire::now_millis;

pub fn decode_mailbox_id(encoded: &str) -> crate::error::Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| RelayError::BadRequest("invalid base64url mailbox id".into()))?;
    bytes
        .try_into()
        .map_err(|_| RelayError::BadRequest("mailbox id must be 32 bytes".into()))
}
