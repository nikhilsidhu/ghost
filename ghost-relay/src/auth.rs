//! Who is asking. A device signs each request it makes with its device key, over the
//! method, path, timestamp and a hash of the body. `verify_signatures` checks that once
//! per request, before the body reaches a handler, and refuses a signature it has seen
//! before. Extractors then say who signed (`SignedBy`), whether that device may act
//! here and as what (`DeviceAuth`), and where the request came from (`ClientIp`).

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{ConnectInfo, FromRequestParts, OptionalFromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use ed25519_dalek::{Signature, VerifyingKey};
use ghost_wire::auth::{body_hash, AUTH_NONCE_LEN, AUTH_TIMESTAMP_TOLERANCE};

use crate::error::RelayError;
use crate::state::AppState;
use crate::storage::Admission;
use crate::util::now_millis;

const ACCOUNT_HEADER: &str = "x-ghost-account";
const DEVICE_HEADER: &str = "x-ghost-device";
const TIMESTAMP_HEADER: &str = "x-ghost-timestamp";
const NONCE_HEADER: &str = "x-ghost-nonce";
const SIGNATURE_HEADER: &str = "x-ghost-signature";
const FORWARDED_FOR_HEADER: &str = "x-forwarded-for";
/// Signatures remembered against replay. Only a flood of signed requests fills it;
/// then signatures are refused until the sweep clears old ones, which fails closed.
const REPLAY_CACHE_MAX: usize = 1_000_000;

/// A request whose device headers verified: signed by `signer_vk` for `account_fp`. The
/// signer is usually one of the account's devices, but may be its root.
#[derive(Clone, Copy, Debug)]
pub struct SignedBy {
    pub account_fp: [u8; 32],
    pub signer_vk: [u8; 32],
}

/// A device this relay admits, from a verified signature.
#[derive(Clone, Copy, Debug)]
pub struct DeviceAuth {
    pub account_fp: [u8; 32],
    pub device_vk: [u8; 32],
    pub admission: Admission,
}

impl DeviceAuth {
    /// Refuse unless this relay is the account's home: for what only a home holds, such
    /// as pairing sessions, passphrase bundles, server locations and mirror grants.
    pub fn require_home(&self) -> Result<(), RelayError> {
        if self.admission == Admission::Home {
            Ok(())
        } else {
            Err(RelayError::Forbidden("this is kept at the account's home relay".into()))
        }
    }
}

/// Where the request came from, past any trusted proxy.
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub IpAddr);

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

pub(crate) fn missing_signature() -> RelayError {
    RelayError::Unauthorized(format!("missing {ACCOUNT_HEADER}"))
}

impl<S: Send + Sync> FromRequestParts<S> for SignedBy {
    type Rejection = RelayError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<SignedBy>().copied().ok_or_else(missing_signature)
    }
}

impl<S: Send + Sync> OptionalFromRequestParts<S> for SignedBy {
    type Rejection = RelayError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<SignedBy>().copied())
    }
}

impl<S: Send + Sync> FromRequestParts<S> for DeviceAuth
where
    AppState: FromRef<S>,
{
    type Rejection = RelayError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let signed = parts.extensions.get::<SignedBy>().copied().ok_or_else(missing_signature)?;
        admit(&AppState::from_ref(state), signed).await
    }
}

impl<S: Send + Sync> OptionalFromRequestParts<S> for DeviceAuth
where
    AppState: FromRef<S>,
{
    type Rejection = RelayError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Option<Self>, Self::Rejection> {
        match parts.extensions.get::<SignedBy>().copied() {
            Some(signed) => Ok(Some(admit(&AppState::from_ref(state), signed).await?)),
            None => Ok(None),
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = RelayError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<ClientIp>().copied().ok_or_else(|| RelayError::Storage("client address missing".into()))
    }
}

/// Whether this relay admits the signing device, and as what: a device of an account
/// homed here, of a member of a group here, or one an invite admitted for a while.
/// Revoked or unknown devices stop here.
pub async fn admit(state: &AppState, signed: SignedBy) -> Result<DeviceAuth, RelayError> {
    let SignedBy { account_fp, signer_vk: device_vk } = signed;
    if state.config.revoked_devices_for_tests.read().unwrap().contains(&device_vk) {
        return Err(RelayError::DeviceRevoked(None));
    }
    match state.storage.may_authenticate(account_fp, device_vk, now_millis()).await? {
        Some(admission) => Ok(DeviceAuth { account_fp, device_vk, admission }),
        None => {
            // The signature proved the request comes from this device, so it may learn why.
            if state.storage.is_revoked_device(account_fp, device_vk).await? {
                return Err(revoked(state, account_fp, device_vk).await);
            }
            Err(RelayError::Unauthorized("unknown or unregistered device".into()))
        }
    }
}

/// The refusal for a revoked device, saying what revoked it when the log tells.
pub async fn revoked(state: &AppState, account_fp: [u8; 32], device_vk: [u8; 32]) -> RelayError {
    RelayError::DeviceRevoked(state.storage.revocation_cause(account_fp, device_vk).await.ok().flatten())
}

/// The layer every request passes. The body is read in full here, so a device's
/// signature can be checked against it before any handler runs; a request with device
/// headers that do not verify ends here, and counts against the address they came from.
pub async fn verify_signatures(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let ip = client_ip(peer.ip(), request.headers(), &state.config.trusted_proxies);
    if state.ip_limits.is_blocked(ip) {
        return state.ip_limits.blocked(ip).into_response();
    }
    let (mut parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, state.body_limit()).await {
        Ok(bytes) => bytes,
        Err(_) => return RelayError::PayloadTooLarge.into_response(),
    };
    parts.extensions.insert(ClientIp(ip));
    if parts.headers.contains_key(ACCOUNT_HEADER) {
        match verify_signed_request(&parts.headers, parts.method.as_str(), parts.uri.path(), &bytes, &state.replay_cache) {
            Ok(signed) => {
                parts.extensions.insert(signed);
            }
            Err(e) => {
                state.ip_limits.auth_failed(ip);
                return e.into_response();
            }
        }
    }
    next.run(Request::from_parts(parts, Body::from(bytes))).await
}

/// The client behind the connection: the peer itself, or when the peer is a trusted
/// proxy, the last address in `X-Forwarded-For` that is not one of the proxies.
fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted_proxies: &[IpAddr]) -> IpAddr {
    if !trusted_proxies.contains(&peer) {
        return peer;
    }
    headers
        .get(FORWARDED_FOR_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|list| {
            list.rsplit(',')
                .filter_map(|hop| hop.trim().parse::<IpAddr>().ok())
                .find(|hop| !trusted_proxies.contains(hop))
        })
        .unwrap_or(peer)
}

/// Check the device headers' timestamp and signature over this request, and that the
/// signature was not used before. Who the signer is to this relay is decided later.
pub fn verify_signed_request(
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
    replay_cache: &ReplayCache,
) -> Result<SignedBy, RelayError> {
    let account_hex = header_str(headers, ACCOUNT_HEADER)?;
    let device_hex = header_str(headers, DEVICE_HEADER)?;
    let timestamp_str = header_str(headers, TIMESTAMP_HEADER)?;
    let nonce_hex = header_str(headers, NONCE_HEADER)?;
    let signature_hex = header_str(headers, SIGNATURE_HEADER)?;

    let account_fp = decode_32(account_hex, "account fingerprint")?;
    let signer_vk = decode_32(device_hex, "device key")?;
    let nonce: [u8; AUTH_NONCE_LEN] = hex::decode(nonce_hex)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| RelayError::Unauthorized("invalid nonce".into()))?;
    let timestamp: u64 = timestamp_str.parse().map_err(|_| RelayError::Unauthorized("invalid timestamp".into()))?;
    if (now_millis() / 1000).abs_diff(timestamp) > AUTH_TIMESTAMP_TOLERANCE {
        return Err(RelayError::Unauthorized("stale timestamp".into()));
    }

    let vk = VerifyingKey::from_bytes(&signer_vk).map_err(|_| RelayError::Unauthorized("invalid device key".into()))?;
    let sig_bytes = hex::decode(signature_hex).map_err(|_| RelayError::Unauthorized("invalid signature hex".into()))?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| RelayError::Unauthorized("invalid signature".into()))?;
    let message = ghost_wire::auth::auth_message(method, path, &account_fp, &signer_vk, timestamp, &nonce, &body_hash(body));
    vk.verify_strict(&message, &signature).map_err(|_| RelayError::Unauthorized("bad signature".into()))?;
    if !replay_cache.first_sighting(&sig_bytes) {
        return Err(RelayError::Unauthorized("replayed request".into()));
    }
    Ok(SignedBy { account_fp, signer_vk })
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, RelayError> {
    headers
        .get(name)
        .ok_or_else(|| RelayError::Unauthorized(format!("missing {name}")))?
        .to_str()
        .map_err(|_| RelayError::Unauthorized(format!("invalid {name}")))
}

fn decode_32(hex_str: &str, label: &str) -> Result<[u8; 32], RelayError> {
    let bytes = hex::decode(hex_str).map_err(|_| RelayError::Unauthorized(format!("invalid {label} hex")))?;
    bytes
        .try_into()
        .map_err(|_| RelayError::Unauthorized(format!("{label} must be 32 bytes")))
}

/// Signatures seen within the timestamp window, so a captured request cannot be sent
/// again while its timestamp is still fresh.
#[derive(Default)]
pub struct ReplayCache {
    seen: DashMap<[u8; 32], Instant>,
}

impl ReplayCache {
    /// Remember the signature; false if it was already seen.
    pub fn first_sighting(&self, signature: &[u8]) -> bool {
        let key: [u8; 32] = blake3::hash(signature).into();
        if self.seen.len() >= REPLAY_CACHE_MAX {
            self.sweep();
            if self.seen.len() >= REPLAY_CACHE_MAX {
                tracing::warn!("replay cache full; refusing signed requests until it drains");
                return false;
            }
        }
        self.seen.insert(key, Instant::now()).is_none()
    }

    /// Forget signatures whose timestamps can no longer be fresh.
    pub fn sweep(&self) {
        let horizon = Duration::from_secs(2 * AUTH_TIMESTAMP_TOLERANCE);
        self.seen.retain(|_, seen| seen.elapsed() < horizon);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_client_address_is_taken_past_trusted_proxies_only() {
        let proxy: IpAddr = "10.0.0.1".parse().unwrap();
        let client: IpAddr = "203.0.113.9".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_FOR_HEADER, "198.51.100.7, 203.0.113.9, 10.0.0.1".parse().unwrap());
        assert_eq!(client_ip(proxy, &headers, &[proxy]), client, "last hop before the proxy");
        assert_eq!(client_ip(client, &headers, &[proxy]), client, "an untrusted peer's header is ignored");
        assert_eq!(client_ip(proxy, &HeaderMap::new(), &[proxy]), proxy, "no header: the proxy itself");
    }

    #[test]
    fn a_signature_is_accepted_once() {
        let cache = ReplayCache::default();
        assert!(cache.first_sighting(b"sig-a"));
        assert!(!cache.first_sighting(b"sig-a"));
        assert!(cache.first_sighting(b"sig-b"));
    }
}
