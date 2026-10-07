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

/// Prefix for relay-to-relay request signatures; distinct from device auth so a
/// relay signature can never be replayed as a device signature or vice versa.
pub const RELAY_AUTH_PREFIX: &[u8] = b"ghost-relay-auth-v1:";

/// Header carrying a relay's signature: `<relay_vk_hex>:<timestamp_secs>:<signature_hex>`.
pub const RELAY_AUTH_HEADER: &str = "x-ghost-relay-auth";

/// Message a relay signs for one request: `ghost-relay-auth-v1:<METHOD>:<path>:<timestamp>`.
pub fn relay_auth_message(method: &str, path: &str, timestamp: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(RELAY_AUTH_PREFIX.len() + method.len() + path.len() + 22);
    msg.extend_from_slice(RELAY_AUTH_PREFIX);
    msg.extend_from_slice(method.as_bytes());
    msg.push(b':');
    msg.extend_from_slice(path.as_bytes());
    msg.push(b':');
    msg.extend_from_slice(timestamp.to_string().as_bytes());
    msg
}

/// Header value authenticating a request from the relay holding `signing_key`.
pub fn sign_relay_auth(method: &str, path: &str, signing_key: &ed25519_dalek::SigningKey) -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let sig = signing_key.sign(&relay_auth_message(method, path, timestamp));
    format!(
        "{}:{}:{}",
        hex::encode(signing_key.verifying_key().to_bytes()),
        timestamp,
        hex::encode(sig.to_bytes())
    )
}

/// Check a relay auth header for this request and return the signing relay's key.
pub fn verify_relay_auth(value: &str, method: &str, path: &str, now_secs: u64) -> Result<[u8; 32], &'static str> {
    let mut parts = value.splitn(3, ':');
    let (Some(vk_hex), Some(ts), Some(sig_hex)) = (parts.next(), parts.next(), parts.next()) else {
        return Err("malformed relay auth");
    };
    let relay_vk: [u8; 32] = hex::decode(vk_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("invalid relay key")?;
    let timestamp: u64 = ts.parse().map_err(|_| "invalid timestamp")?;
    if now_secs.abs_diff(timestamp) > AUTH_TIMESTAMP_TOLERANCE {
        return Err("stale timestamp");
    }
    let sig: [u8; 64] = hex::decode(sig_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("invalid signature")?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&relay_vk).map_err(|_| "invalid relay key")?;
    vk.verify_strict(&relay_auth_message(method, path, timestamp), &ed25519_dalek::Signature::from_bytes(&sig))
        .map_err(|_| "bad relay signature")?;
    Ok(relay_vk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, Verifier};

    fn now_secs() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    }

    #[test]
    fn relay_auth_roundtrip_and_binding() {
        let sk = SigningKey::from_bytes(&[0x07u8; 32]);
        let header = sign_relay_auth("GET", "/idlog/abc", &sk);
        assert_eq!(verify_relay_auth(&header, "GET", "/idlog/abc", now_secs()), Ok(sk.verifying_key().to_bytes()));
        assert!(verify_relay_auth(&header, "GET", "/idlog/other", now_secs()).is_err(), "path bound");
        assert!(verify_relay_auth(&header, "PUT", "/idlog/abc", now_secs()).is_err(), "method bound");
        assert!(verify_relay_auth(&header, "GET", "/idlog/abc", now_secs() + 3600).is_err(), "stale");
        assert!(verify_relay_auth("nope", "GET", "/idlog/abc", now_secs()).is_err());
    }

    #[test]
    fn relay_and_device_messages_never_collide() {
        let device = auth_message("GET", "/idlog/abc", &[0; 32], &[0; 32], 1, None);
        assert!(!relay_auth_message("GET", "/idlog/abc", 1).starts_with(AUTH_PREFIX));
        assert!(!device.starts_with(RELAY_AUTH_PREFIX));
    }

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
