//! Request authentication: a device signs each request to a relay with its device key,
//! relays sign their requests to each other, and an account's root signs the few
//! requests it makes before any device of the account is active.

use ed25519_dalek::Signer;

/// Prefix for the signed device auth message.
pub const AUTH_PREFIX: &[u8] = b"ghost-auth-v2:";

/// Maximum clock skew allowed between client and relay (seconds). A relay also refuses
/// a signature it has already seen within this window, so a captured request cannot be
/// sent again.
pub const AUTH_TIMESTAMP_TOLERANCE: u64 = 60;

/// Random bytes in each signed request, so two identical requests in the same second
/// still carry different signatures and the relay's replay check tells them apart.
pub const AUTH_NONCE_LEN: usize = 16;

/// The hash of a request body as the signature names it. An empty body hashes too, so
/// every signature covers exactly one body.
pub fn body_hash(body: &[u8]) -> [u8; 32] {
    blake3::hash(body).into()
}

/// Build the message that gets signed for request authentication.
/// Format: `ghost-auth-v2:<METHOD>:<path>:<account_fp_hex>:<device_vk_hex>:<timestamp_secs>:<nonce_hex>:<body_hash_hex>`
///
/// The method, path and body hash bind the signature to one request: an intercepted
/// signature cannot be replayed against another endpoint or with another body.
pub fn auth_message(
    method: &str,
    path: &str,
    account_fp: &[u8; 32],
    device_vk: &[u8; 32],
    timestamp: u64,
    nonce: &[u8; AUTH_NONCE_LEN],
    body_hash: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(AUTH_PREFIX.len() + method.len() + path.len() + 64 + 64 + 20 + 32 + 64 + 7);
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
    msg.push(b':');
    msg.extend_from_slice(hex::encode(nonce).as_bytes());
    msg.push(b':');
    msg.extend_from_slice(hex::encode(body_hash).as_bytes());
    msg
}

/// Signed auth header values for a single request.
pub struct AuthHeaders {
    pub account: String,
    pub device: String,
    pub timestamp: String,
    pub nonce: String,
    pub signature: String,
}

/// Sign a request made now, with `body` as it will be sent, and return the four auth
/// header values.
pub fn sign_request_headers(
    method: &str,
    path: &str,
    body: &[u8],
    account_fp: &[u8; 32],
    device_vk: &[u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
) -> AuthHeaders {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut nonce = [0u8; AUTH_NONCE_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let msg = auth_message(method, path, account_fp, device_vk, timestamp, &nonce, &body_hash(body));
    let sig = signing_key.sign(&msg);
    AuthHeaders {
        account: hex::encode(account_fp),
        device: hex::encode(device_vk),
        timestamp: timestamp.to_string(),
        nonce: hex::encode(nonce),
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
    key_auth_message(RELAY_AUTH_PREFIX, method, path, timestamp)
}

/// Header value authenticating a request from the relay holding `signing_key`.
pub fn sign_relay_auth(method: &str, path: &str, signing_key: &ed25519_dalek::SigningKey) -> String {
    sign_key_auth(RELAY_AUTH_PREFIX, method, path, signing_key)
}

/// Check a relay auth header for this request and return the signing relay's key.
pub fn verify_relay_auth(value: &str, method: &str, path: &str, now_secs: u64) -> Result<[u8; 32], &'static str> {
    verify_key_auth(RELAY_AUTH_PREFIX, value, method, path, now_secs)
}

/// Prefix for requests signed by an account's root, which acts before any of the
/// account's devices is active (recovery) and before the account is even known
/// (finding it by root). Distinct from device and relay auth.
pub const ROOT_AUTH_PREFIX: &[u8] = b"ghost-root-auth-v1:";

/// Header carrying a root's signature: `<root_vk_hex>:<timestamp_secs>:<signature_hex>`.
pub const ROOT_AUTH_HEADER: &str = "x-ghost-root";

/// Header value authenticating a request from the root holding `signing_key`.
pub fn sign_root_auth(method: &str, path: &str, signing_key: &ed25519_dalek::SigningKey) -> String {
    sign_key_auth(ROOT_AUTH_PREFIX, method, path, signing_key)
}

/// Check a root auth header for this request and return the signing root key. The
/// caller still has to check it is the account's current root.
pub fn verify_root_auth(value: &str, method: &str, path: &str, now_secs: u64) -> Result<[u8; 32], &'static str> {
    verify_key_auth(ROOT_AUTH_PREFIX, value, method, path, now_secs)
}

/// `<prefix><METHOD>:<path>:<timestamp>`, the message behind relay and root auth.
fn key_auth_message(prefix: &[u8], method: &str, path: &str, timestamp: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(prefix.len() + method.len() + path.len() + 22);
    msg.extend_from_slice(prefix);
    msg.extend_from_slice(method.as_bytes());
    msg.push(b':');
    msg.extend_from_slice(path.as_bytes());
    msg.push(b':');
    msg.extend_from_slice(timestamp.to_string().as_bytes());
    msg
}

fn sign_key_auth(prefix: &[u8], method: &str, path: &str, signing_key: &ed25519_dalek::SigningKey) -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let sig = signing_key.sign(&key_auth_message(prefix, method, path, timestamp));
    format!(
        "{}:{}:{}",
        hex::encode(signing_key.verifying_key().to_bytes()),
        timestamp,
        hex::encode(sig.to_bytes())
    )
}

fn verify_key_auth(prefix: &[u8], value: &str, method: &str, path: &str, now_secs: u64) -> Result<[u8; 32], &'static str> {
    let mut parts = value.splitn(3, ':');
    let (Some(vk_hex), Some(ts), Some(sig_hex)) = (parts.next(), parts.next(), parts.next()) else {
        return Err("malformed key auth");
    };
    let signer: [u8; 32] = hex::decode(vk_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("invalid signing key")?;
    let timestamp: u64 = ts.parse().map_err(|_| "invalid timestamp")?;
    if now_secs.abs_diff(timestamp) > AUTH_TIMESTAMP_TOLERANCE {
        return Err("stale timestamp");
    }
    let sig: [u8; 64] = hex::decode(sig_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("invalid signature")?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&signer).map_err(|_| "invalid signing key")?;
    vk.verify_strict(&key_auth_message(prefix, method, path, timestamp), &ed25519_dalek::Signature::from_bytes(&sig))
        .map_err(|_| "bad signature")?;
    Ok(signer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Verifier};

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
        let device = auth_message("GET", "/idlog/abc", &[0; 32], &[0; 32], 1, &[0; AUTH_NONCE_LEN], &body_hash(&[]));
        assert!(!relay_auth_message("GET", "/idlog/abc", 1).starts_with(AUTH_PREFIX));
        assert!(!device.starts_with(RELAY_AUTH_PREFIX));
    }

    #[test]
    fn root_auth_is_not_relay_auth() {
        let sk = SigningKey::from_bytes(&[0x09u8; 32]);
        let header = sign_root_auth("GET", "/accounts/by_root", &sk);
        assert_eq!(verify_root_auth(&header, "GET", "/accounts/by_root", now_secs()), Ok(sk.verifying_key().to_bytes()));
        assert!(verify_relay_auth(&header, "GET", "/accounts/by_root", now_secs()).is_err());
        let relay_header = sign_relay_auth("GET", "/accounts/by_root", &sk);
        assert!(verify_root_auth(&relay_header, "GET", "/accounts/by_root", now_secs()).is_err());
    }

    #[test]
    fn a_device_signature_names_the_method_path_and_body() {
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let vk = sk.verifying_key().to_bytes();
        let fp = [0xAA; 32];
        let nonce = [7; AUTH_NONCE_LEN];
        let message = auth_message("POST", "/box/abc", &fp, &vk, 1000, &nonce, &body_hash(b"hello"));
        let text = std::str::from_utf8(&message).unwrap();
        assert!(text.starts_with("ghost-auth-v2:POST:/box/abc:"));
        assert!(text.ends_with(&format!(":1000:{}:{}", hex::encode(nonce), hex::encode(body_hash(b"hello")))));

        let signature = sk.sign(&message);
        let verifies = |method: &str, path: &str, nonce: &[u8; AUTH_NONCE_LEN], body: &[u8]| {
            sk.verifying_key().verify(&auth_message(method, path, &fp, &vk, 1000, nonce, &body_hash(body)), &signature).is_ok()
        };
        assert!(verifies("POST", "/box/abc", &nonce, b"hello"));
        assert!(!verifies("POST", "/box/abc", &nonce, b"other"), "body bound");
        assert!(!verifies("POST", "/box/abc", &nonce, b""), "a body cannot be dropped either");
        assert!(!verifies("PUT", "/box/abc", &nonce, b"hello"), "method bound");
        assert!(!verifies("POST", "/box/xyz", &nonce, b"hello"), "path bound");
        assert!(!verifies("POST", "/box/abc", &[8; AUTH_NONCE_LEN], b"hello"), "nonce bound");
    }

    #[test]
    fn signed_headers_name_the_signer_and_verify() {
        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let vk = sk.verifying_key().to_bytes();
        let fp = [0xAA; 32];
        let headers = sign_request_headers("GET", "/ws/m", b"", &fp, &vk, &sk);
        assert_eq!(headers.account, hex::encode(fp));
        assert_eq!(headers.device, hex::encode(vk));
        let timestamp: u64 = headers.timestamp.parse().unwrap();
        let nonce: [u8; AUTH_NONCE_LEN] = hex::decode(headers.nonce).unwrap().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&hex::decode(headers.signature).unwrap()).unwrap();
        let message = auth_message("GET", "/ws/m", &fp, &vk, timestamp, &nonce, &body_hash(b""));
        sk.verifying_key().verify_strict(&message, &signature).unwrap();
        let again = sign_request_headers("GET", "/ws/m", b"", &fp, &vk, &sk);
        assert_ne!(again.signature, hex::encode(signature.to_bytes()), "each request signs afresh");
    }
}
