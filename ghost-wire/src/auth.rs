use ed25519_dalek::Signer;

/// Prefix for the signed auth message.
pub const AUTH_PREFIX: &[u8] = b"ghost-auth-v1:";

/// Maximum clock skew allowed between client and relay (seconds).
pub const AUTH_TIMESTAMP_TOLERANCE: u64 = 60;

/// Build the message that gets signed for request authentication.
/// Format: `ghost-auth-v1:<METHOD>:<path>:<account_fp_hex>:<device_vk_hex>:<timestamp_secs>`
///
/// The method and path bind the signature to a specific request, preventing
/// replay of intercepted signatures against different endpoints.
pub fn auth_message(
    method: &str,
    path: &str,
    account_fp: &[u8; 32],
    device_vk: &[u8; 32],
    timestamp: u64,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(AUTH_PREFIX.len() + method.len() + path.len() + 64 + 64 + 20 + 5);
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
pub fn sign_request_headers(
    method: &str,
    path: &str,
    account_fp: &[u8; 32],
    device_vk: &[u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
) -> AuthHeaders {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let msg = auth_message(method, path, account_fp, device_vk, timestamp);
    let sig = signing_key.sign(&msg);
    AuthHeaders {
        account: hex::encode(account_fp),
        device: hex::encode(device_vk),
        timestamp: timestamp.to_string(),
        signature: hex::encode(sig.to_bytes()),
    }
}
