use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::HeaderMap;
use ed25519_dalek::{Signature, VerifyingKey};

use crate::error::RelayError;
use crate::state::AppState;

/// Authenticated device identity extracted from request headers.
pub struct DeviceAuth {
    pub account_fp: [u8; 32],
    pub device_vk: [u8; 32],
}

impl<S: Send + Sync> FromRequestParts<S> for DeviceAuth
where
    AppState: FromRef<S>,
{
    type Rejection = RelayError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let method = parts.method.as_str();
        let path = parts.uri.path();
        validate_auth_headers(&parts.headers, method, path, &app_state)
    }
}

/// AppState is Arc<Inner>, so FromRef is just Clone.
/// Can't use axum's FromRef here due to orphan rules on Arc.
pub trait FromRef<T> {
    fn from_ref(input: &T) -> Self;
}

impl FromRef<AppState> for AppState {
    fn from_ref(input: &AppState) -> Self {
        input.clone()
    }
}

/// Validate auth headers and return the authenticated device identity: a valid
/// signature from a device this relay admits (see `Storage::may_authenticate`).
pub fn validate_auth_headers(
    headers: &HeaderMap,
    method: &str,
    path: &str,
    state: &AppState,
) -> Result<DeviceAuth, RelayError> {
    let auth = verify_signed_headers(headers, method, path)?;
    // The device must be active in an account this relay homes, hosts a group
    // for, or has admitted by invite; revoked or unknown devices stop here.
    let allowed = state
        .storage
        .may_authenticate(&auth.account_fp, &auth.device_vk, crate::util::now_millis())
        .map_err(|e| RelayError::Storage(format!("device lookup: {e}")))?;
    if !allowed {
        return Err(RelayError::Unauthorized("unknown, revoked, or unregistered device".into()));
    }
    Ok(auth)
}

/// Check the auth headers' timestamp and signature only, without asking whether
/// the signing key belongs to an admitted device. Callers that accept other keys
/// (an account's master key) decide that themselves.
pub fn verify_signed_headers(headers: &HeaderMap, method: &str, path: &str) -> Result<DeviceAuth, RelayError> {
    let account_hex = header_str(headers, "x-ghost-account")?;
    let device_hex = header_str(headers, "x-ghost-device")?;
    let timestamp_str = header_str(headers, "x-ghost-timestamp")?;
    let signature_hex = header_str(headers, "x-ghost-signature")?;

    let account_fp = decode_32(account_hex, "account fingerprint")?;
    let device_vk = decode_32(device_hex, "device key")?;

    let timestamp: u64 = timestamp_str
        .parse()
        .map_err(|_| RelayError::Unauthorized("invalid timestamp".into()))?;

    // Check timestamp window
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let diff = if now >= timestamp {
        now - timestamp
    } else {
        timestamp - now
    };
    if diff > ghost_wire::auth::AUTH_TIMESTAMP_TOLERANCE {
        return Err(RelayError::Unauthorized("stale timestamp".into()));
    }

    // Verify signature
    let vk = VerifyingKey::from_bytes(&device_vk)
        .map_err(|_| RelayError::Unauthorized("invalid device key".into()))?;
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|_| RelayError::Unauthorized("invalid signature hex".into()))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|_| RelayError::Unauthorized("invalid signature".into()))?;
    // SECURITY: channel binding is client-asserted via header — no protection until
    // the relay terminates TLS and computes the binding from export_keying_material().
    // Once TLS is added, replace this with the server-side exporter value.
    let cb_hex = headers.get("x-ghost-channel-binding")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| hex::decode(s).ok())
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
    let cb_ref = cb_hex.as_ref();
    let message = ghost_wire::auth::auth_message(method, path, &account_fp, &device_vk, timestamp, cb_ref);
    vk.verify_strict(&message, &signature)
        .map_err(|_| RelayError::Unauthorized("bad signature".into()))?;

    Ok(DeviceAuth {
        account_fp,
        device_vk,
    })
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, RelayError> {
    headers
        .get(name)
        .ok_or_else(|| RelayError::Unauthorized(format!("missing {name}")))?
        .to_str()
        .map_err(|_| RelayError::Unauthorized(format!("invalid {name}")))
}

fn decode_32(hex_str: &str, label: &str) -> Result<[u8; 32], RelayError> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| RelayError::Unauthorized(format!("invalid {label} hex")))?;
    bytes
        .try_into()
        .map_err(|_| RelayError::Unauthorized(format!("{label} must be 32 bytes")))
}
