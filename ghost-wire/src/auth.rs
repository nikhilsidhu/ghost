use ed25519_dalek::Signer;

/// Prefix for the signed auth message.
pub const AUTH_PREFIX: &[u8] = b"ghost-auth-v1:";

/// Maximum clock skew allowed between client and relay (seconds).
pub const AUTH_TIMESTAMP_TOLERANCE: u64 = 60;

/// TLS channel binding label (RFC 9266).
pub const TLS_EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";

/// Length of the TLS exporter channel binding value.
pub const TLS_EXPORTER_LEN: usize = 32;

/// Build the message that gets signed for request authentication.
/// Format: `ghost-auth-v1:<METHOD>:<path>:<account_fp_hex>:<device_vk_hex>:<timestamp_secs>[:<cb_hex>]`
///
/// The method and path bind the signature to a specific request, preventing
/// replay of intercepted signatures against different endpoints.
/// When `channel_binding` is Some, the 32-byte TLS exporter value (RFC 9266)
/// is appended, binding the signature to the specific TLS session and
/// preventing MITM replay across different connections.
pub fn auth_message(
    method: &str,
    path: &str,
    account_fp: &[u8; 32],
    device_vk: &[u8; 32],
    timestamp: u64,
    channel_binding: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(AUTH_PREFIX.len() + method.len() + path.len() + 64 + 64 + 20 + 5 + 65);
    msg.extend_from_slice(AUTH_PREFIX);
    msg.extend_from_slice(method.as_bytes());
    msg.push(b':');
    msg.extend_from_slice(path.as_bytes());
    msg.push(b':');
    msg.extend_from_slice(hex::encode(account_fp).as_bytes());
    msg.push(b':');
    msg.extend_from_slice(hex::encode(device_vk).as_bytes());
    msg.push(b':');
    msg.extend_from_slice(timestamp.to_string().as_bytes());
    if let Some(cb) = channel_binding {
        msg.push(b':');
        msg.extend_from_slice(hex::encode(cb).as_bytes());
    }
    msg
}

/// Signed auth header values for a single request.
pub struct AuthHeaders {
    pub account: String,
    pub device: String,
    pub timestamp: String,
    pub signature: String,
}

/// Sign the current timestamp and return the four auth header values.
/// Pass `channel_binding` when the connection is over TLS to bind the
/// signature to this specific session (RFC 9266 tls-exporter).
pub fn sign_request_headers(
    method: &str,
    path: &str,
    account_fp: &[u8; 32],
    device_vk: &[u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
    channel_binding: Option<&[u8; 32]>,
) -> AuthHeaders {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let msg = auth_message(method, path, account_fp, device_vk, timestamp, channel_binding);
    let sig = signing_key.sign(&msg);
    AuthHeaders {
        account: hex::encode(account_fp),
        device: hex::encode(device_vk),
        timestamp: timestamp.to_string(),
        signature: hex::encode(sig.to_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, Verifier};

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32])
    }

    #[test]
    fn auth_message_without_binding() {
        let fp = [0xAA; 32];
        let vk = [0xBB; 32];
        let msg = auth_message("GET", "/box/abc", &fp, &vk, 1000, None);
        let s = std::str::from_utf8(&msg).unwrap();
        assert!(s.starts_with("ghost-auth-v1:GET:/box/abc:"));
        assert!(s.ends_with(":1000"));
        // No trailing colon + cb hex
        assert_eq!(s.matches(':').count(), 5);
    }

    #[test]
    fn auth_message_with_binding() {
        let fp = [0xAA; 32];
        let vk = [0xBB; 32];
        let cb = [0xCC; 32];
        let msg = auth_message("POST", "/box/xyz", &fp, &vk, 2000, Some(&cb));
        let s = std::str::from_utf8(&msg).unwrap();
        assert!(s.ends_with(&hex::encode(cb)));
        // Extra colon for cb field
        assert_eq!(s.matches(':').count(), 6);
    }

    #[test]
    fn different_binding_different_message() {
        let fp = [0xAA; 32];
        let vk = [0xBB; 32];
        let cb1 = [0x11; 32];
        let cb2 = [0x22; 32];
        let m1 = auth_message("GET", "/x", &fp, &vk, 1, Some(&cb1));
        let m2 = auth_message("GET", "/x", &fp, &vk, 1, Some(&cb2));
        assert_ne!(m1, m2);
    }

    #[test]
    fn bound_signature_rejects_different_session() {
        let sk = test_key();
        let vk_bytes = sk.verifying_key().to_bytes();
        let fp = [0xAA; 32];
        let session_a = [0x11; 32];
        let session_b = [0x22; 32];

        // Sign with session A's binding
        let msg_a = auth_message("POST", "/box/m", &fp, &vk_bytes, 100, Some(&session_a));
        let sig = sk.sign(&msg_a);

        // Verify against session B — must fail
        let msg_b = auth_message("POST", "/box/m", &fp, &vk_bytes, 100, Some(&session_b));
        assert!(sk.verifying_key().verify(&msg_b, &sig).is_err());

        // Verify against session A — must succeed
        assert!(sk.verifying_key().verify(&msg_a, &sig).is_ok());
    }

    #[test]
    fn unbound_signature_does_not_verify_as_bound() {
        let sk = test_key();
        let vk_bytes = sk.verifying_key().to_bytes();
        let fp = [0xAA; 32];
        let cb = [0x33; 32];

        // Sign without binding
        let msg_none = auth_message("GET", "/x", &fp, &vk_bytes, 50, None);
        let sig = sk.sign(&msg_none);

        // Try to verify with binding — must fail
        let msg_bound = auth_message("GET", "/x", &fp, &vk_bytes, 50, Some(&cb));
        assert!(sk.verifying_key().verify(&msg_bound, &sig).is_err());
    }
}
