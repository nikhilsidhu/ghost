//! Linking a new device to an existing account through a relay rendezvous.
//!
//! The existing device (A) posts a sealed offer. The new device (B) answers with its
//! public keys, and both screens show a code from the pairing secret and B's keys,
//! which A's user compares before anything is signed. A posts a draft `AddDevice`, B
//! counter-signs it, and A appends the addition, B's encryption key and a new account
//! key generation as one batch after uploading the provision. B never sends a private
//! key. All rendezvous payloads are AES-256-GCM sealed with a secret that only travels
//! inside the pairing code.

use ed25519_dalek::{Signer, SigningKey};
use ghost_wire::idlog::{EntryBody, LogEntry, LogState};

use crate::account_keys::DeviceEncryptionKey;
use crate::crypto::aead;
use crate::error::{GhostError, Result};
use crate::identity::batch::BatchBuilder;
use crate::identity::log::{create_device_key_with_signature, device_key_signature, draft_add_device, sign_message};
use crate::identity::{Addition, Identity};
use crate::relay::{PairingToken, RelayClient};
use zeroize::Zeroize;

use super::provision::ProvisionBlob;
use super::{account, account_keys, idlog, SharedClient};

const SEAL_CONTEXT: &str = "pairing";

/// How long after the session's end the new device still waits to find itself in the log:
/// the existing device's batch lands moments after its last write to the session.
const NEW_DEVICE_GRACE_MS: u64 = 60 * 1000;

/// How long the new device waits for the existing one to add it: the session's whole life
/// and the grace after, so it never gives up on a link the other side can still make.
pub const NEW_DEVICE_WAIT: std::time::Duration = std::time::Duration::from_millis(ghost_wire::PAIRING_TTL_MS + NEW_DEVICE_GRACE_MS);

/// Domain separator for the code both screens show.
const COMPARISON_CODE_LABEL: &[u8] = b"ghost-pairing-code-v1";

/// What the new device needs to find and open the rendezvous:
/// `relay_url#account_fp_hex#secret_hex#token_hex`. The token addresses the session on
/// the relay, so knowing the account alone cannot answer or read it; the secret seals
/// every payload. Both exist only in the code.
#[derive(Clone)]
pub struct PairingCode {
    pub relay_url: String,
    pub account_fp: [u8; 32],
    pub secret: [u8; 32],
    pub token: PairingToken,
}

impl Drop for PairingCode {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl PairingCode {
    pub fn encode(&self) -> String {
        format!(
            "{}#{}#{}#{}",
            self.relay_url,
            hex::encode(self.account_fp),
            hex::encode(self.secret),
            hex::encode(self.token)
        )
    }

    pub fn parse(code: &str) -> Result<Self> {
        let parts: Vec<&str> = code.rsplitn(4, '#').collect();
        if parts.len() != 4 {
            return Err(GhostError::Format("invalid pairing code".into()));
        }
        // rsplitn yields the fields last-first; the relay URL may itself contain '#'.
        let token_bytes = hex::decode(parts[0]).map_err(|e| GhostError::Format(format!("pairing code token: {e}")))?;
        let token = token_bytes
            .try_into()
            .map_err(|_| GhostError::Format("pairing code token: must be 16 bytes".into()))?;
        let secret = parse_32(parts[1], "pairing code secret")?;
        let account_fp = parse_32(parts[2], "pairing code fingerprint")?;
        Ok(Self { relay_url: parts[3].to_string(), account_fp, secret, token })
    }

    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        aead::seal(&self.secret, plaintext, SEAL_CONTEXT)
    }

    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        aead::open(&self.secret, sealed, SEAL_CONTEXT)
    }
}

fn parse_32(hex_str: &str, what: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).map_err(|e| GhostError::Format(format!("{what}: {e}")))?;
    bytes.try_into().map_err(|_| GhostError::Format(format!("{what}: must be 32 bytes")))
}

/// The six digits both screens show, from the pairing secret and the new device's
/// keys, as Bluetooth's Numeric Comparison does. Someone who answered the code first
/// has one chance in a million of matching what the real new device shows.
pub fn comparison_code(secret: &[u8; 32], device_vk: &[u8; 32], encryption_key: &[u8; 32]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMPARISON_CODE_LABEL);
    hasher.update(secret);
    hasher.update(device_vk);
    hasher.update(encryption_key);
    let value = u32::from_be_bytes(hasher.finalize().as_bytes()[..4].try_into().unwrap()) % 1_000_000;
    format!("{:03} {:03}", value / 1000, value % 1000)
}

/// Account presentation the new device adopts, sealed inside the offer. The status
/// message is not in it: the provision's sync state carries it with its expiry.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PairingOffer {
    pub relay_url: String,
    pub display_name: String,
    /// The account's avatar, hash and key in hex, which the new device announces too.
    pub avatar_hash: Option<String>,
    pub avatar_key: Option<String>,
}

impl PairingOffer {
    pub fn avatar(&self) -> Option<crate::mls::presence::AvatarRef> {
        let hash = parse_32(self.avatar_hash.as_deref()?, "avatar hash").ok()?;
        let key = parse_32(self.avatar_key.as_deref()?, "avatar key").ok()?;
        Some(crate::mls::presence::AvatarRef { hash, key })
    }
}

/// The new device's answer, its public keys only:
/// `[device_vk:32][encryption_key:32][device_key_signature:64][label utf-8]`.
pub struct PairingResponse {
    pub device_vk: [u8; 32],
    pub encryption_key: [u8; 32],
    /// The new device's consent to publishing `encryption_key`, as its `DeviceKey`
    /// entry carries it.
    pub device_key_signature: [u8; 64],
    pub label: String,
}

impl PairingResponse {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128 + self.label.len());
        buf.extend_from_slice(&self.device_vk);
        buf.extend_from_slice(&self.encryption_key);
        buf.extend_from_slice(&self.device_key_signature);
        buf.extend_from_slice(self.label.as_bytes());
        buf
    }

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 129 {
            return Err(GhostError::Format("pairing response too short".into()));
        }
        let label = String::from_utf8(data[128..].to_vec())
            .map_err(|_| GhostError::Format("pairing response label is not UTF-8".into()))?;
        Ok(Self {
            device_vk: data[..32].try_into().unwrap(),
            encryption_key: data[32..64].try_into().unwrap(),
            device_key_signature: data[64..128].try_into().unwrap(),
            label,
        })
    }
}

/// A new device that has answered and waits for the user to compare codes.
pub struct PendingDevice {
    pub response: PairingResponse,
    /// What both screens should show.
    pub code: String,
}

// ── Existing device (A) ─────────────────────────────────────────────

/// Post a sealed offer and return the pairing code to show the new device.
pub async fn start(client: &SharedClient, relay: &RelayClient, offer: &PairingOffer) -> Result<PairingCode> {
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
    let mut token: PairingToken = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token);

    let plaintext = serde_json::to_vec(offer).map_err(|e| GhostError::Format(format!("offer encode: {e}")))?;
    let sealed = aead::seal(&secret, &plaintext, SEAL_CONTEXT)?;

    let account_fp = {
        let c = client.lock().await;
        *c.fingerprint()
    };
    relay.post_pairing_offer(&account_fp, &token, sealed).await?;
    let relay_url = relay.base_url();
    let code = PairingCode { relay_url, account_fp, secret, token };
    secret.zeroize();
    Ok(code)
}

/// Poll the rendezvous `code` names for the new device's answer. `None` while waiting;
/// once it arrives, show `PendingDevice::code` and go on only if the user confirms
/// the new device shows the same.
pub async fn await_response(rendezvous: &RelayClient, code: &PairingCode) -> Result<Option<PendingDevice>> {
    let sealed = rendezvous.get_pairing_response(&code.account_fp, &code.token).await?;
    let Some(sealed) = sealed else { return Ok(None) };
    let response = PairingResponse::from_bytes(&code.open(&sealed)?)?;
    let shown = comparison_code(&code.secret, &response.device_vk, &response.encryption_key);
    Ok(Some(PendingDevice { response, code: shown }))
}

/// After the user confirmed the codes match: draft the `AddDevice` at the log's head
/// and post it for the new device to counter-sign. Returns the draft.
pub async fn post_draft(
    client: &SharedClient,
    home: &RelayClient,
    rendezvous: &RelayClient,
    code: &PairingCode,
    device: &PendingDevice,
) -> Result<LogEntry> {
    let state = idlog::fetch_and_verify(client, home, &code.account_fp).await?;
    let draft = {
        let c = client.lock().await;
        draft_add_device(&state, &c.signing_key_clone(), device.response.device_vk, &device.response.label)
    };
    let sealed = code.seal(&draft.to_bytes())?;
    rendezvous.put_pairing_draft(&code.account_fp, &code.token, sealed).await?;
    Ok(draft)
}

/// Poll for the new device's counter-signature on `draft`. When it arrives, upload the
/// provision and append the addition, the new device's key and a new account key
/// generation as one batch. Returns the new device's label when linked, `None` while
/// waiting. If the log's head moved since the draft, a fresh draft replaces `draft`
/// and the new device signs again.
pub async fn complete(
    client: &SharedClient,
    home: &RelayClient,
    rendezvous: &RelayClient,
    code: &PairingCode,
    device: &PendingDevice,
    draft: &mut LogEntry,
) -> Result<Option<String>> {
    let sealed = rendezvous.get_pairing_signatures(&code.account_fp, &code.token).await?;
    let Some(sealed) = sealed else { return Ok(None) };
    let signature: [u8; 64] = code
        .open(&sealed)?
        .try_into()
        .map_err(|_| GhostError::Format("pairing signature must be 64 bytes".into()))?;

    let state = idlog::fetch_and_verify(client, home, &code.account_fp).await?;
    if draft.seq != state.head_seq + 1 || draft.prev_hash != state.head_hash {
        *draft = post_draft(client, home, rendezvous, code, device).await?;
        return Ok(None);
    }
    let mut signed = draft.clone();
    signed.counter_signature = Some(signature);

    account_keys::open_missing(client, home, &state).await?;
    let (batch, seed, provision) = {
        let c = client.lock().await;
        let key = c.signing_key_clone();
        let previous = account_keys::newest_held(&c, &state)?;
        let mut batch = BatchBuilder::new(state);
        batch
            .push(signed)
            .map_err(|e| GhostError::IdentityLog(format!("the new device's signature does not check: {e}")))?;
        let response = &device.response;
        batch.push(create_device_key_with_signature(
            batch.state(),
            &key,
            response.device_vk,
            response.encryption_key,
            response.device_key_signature,
        ))?;
        let seed = if batch.state().root_rotated() { Some(batch.push_rekey(&key, previous.as_ref())?) } else { None };

        let servers = c
            .server_mailboxes()
            .into_iter()
            .filter_map(|(server_id, _)| c.export_provision_payload(&server_id).ok())
            .collect();
        let provision = ProvisionBlob { servers, sync_dump: c.sync_dump()? };
        (batch.finish(), seed, provision)
    };

    // The provision must be up before the device sees itself in the log.
    rendezvous.put_provision(&code.account_fp, &code.token, code.seal(&provision.to_bytes()?)?).await?;
    match account::publish_batch(client, home, &batch).await {
        Ok(_) => {}
        Err(GhostError::RelayStatus { status: 409, .. }) => {
            *draft = post_draft(client, home, rendezvous, code, device).await?;
            return Ok(None);
        }
        Err(e) => return Err(e),
    }
    if let Some(seed) = seed {
        let c = client.lock().await;
        c.store_account_seed(&seed)?;
    }
    account::announce_change(client, home).await;
    Ok(Some(device.response.label.clone()))
}

// ── New device (B) ──────────────────────────────────────────────────

/// Fetch and open the offer behind a pairing code. `relay` is unauthenticated.
pub async fn fetch_offer(relay: &RelayClient, code: &PairingCode) -> Result<PairingOffer> {
    let sealed = relay.get_pairing_offer(&code.account_fp, &code.token).await?;
    serde_json::from_slice(&code.open(&sealed)?).map_err(|e| GhostError::Format(format!("offer decode: {e}")))
}

/// Answer with this device's public keys and label. Returns the code to show, which
/// the existing device's user compares with theirs.
pub async fn respond(
    relay: &RelayClient,
    code: &PairingCode,
    device_key: &SigningKey,
    encryption_key: &DeviceEncryptionKey,
    label: &str,
) -> Result<String> {
    let encryption_public = encryption_key.key_pair()?.public();
    let response = PairingResponse {
        device_vk: device_key.verifying_key().to_bytes(),
        encryption_key: encryption_public,
        device_key_signature: device_key_signature(&code.account_fp, device_key, &encryption_public),
        label: label.to_string(),
    };
    relay.post_pairing_response(&code.account_fp, &code.token, code.seal(&response.to_bytes())?).await?;
    Ok(comparison_code(&code.secret, &response.device_vk, &response.encryption_key))
}

/// Counter-sign the existing device's current draft, if it names this device and
/// differs from the last one signed. Returns whether a signature was posted.
async fn sign_draft(relay: &RelayClient, code: &PairingCode, device_key: &SigningKey, label: &str, signed: &mut Option<Vec<u8>>) -> Result<bool> {
    let Some(sealed) = relay.get_pairing_draft(&code.account_fp, &code.token).await? else { return Ok(false) };
    let bytes = code.open(&sealed)?;
    if signed.as_deref() == Some(bytes.as_slice()) {
        return Ok(false);
    }
    let draft = LogEntry::from_bytes(&bytes)?;
    let names_this_device = matches!(
        &draft.body,
        EntryBody::AddDevice { device_verifying_key, device_label, .. }
            if *device_verifying_key == device_key.verifying_key().to_bytes() && device_label == label
    );
    if draft.account_fp != code.account_fp || !names_this_device {
        return Err(GhostError::IdentityLog("the pairing draft does not add this device".into()));
    }
    let signature = device_key.sign(&sign_message(&draft)).to_bytes();
    relay.post_pairing_signatures(&code.account_fp, &code.token, code.seal(&signature)?).await?;
    *signed = Some(bytes);
    Ok(true)
}

/// Poll until this device is active in the account's log, counter-signing each draft
/// the existing device posts meanwhile. Reads are signed with the new device key,
/// which the relay accepts only once the device is added, so until then a poll is
/// refused like a missing entry. Returns the log and the entry that added the device.
/// Ends early when the existing device ended the session (or it expired), or posts a
/// draft that does not add this device.
pub async fn wait_for_device(
    relay: &RelayClient,
    code: &PairingCode,
    device_key: &SigningKey,
    label: &str,
    attempts: usize,
    interval: std::time::Duration,
) -> Result<(LogState, Addition)> {
    let device_vk = device_key.verifying_key().to_bytes();
    let reader = relay.at(&relay.base_url());
    reader.set_auth(code.account_fp, device_vk, device_key.clone());
    let mut signed = None;
    for _ in 0..attempts {
        tokio::time::sleep(interval).await;
        match sign_draft(relay, code, device_key, label, &mut signed).await {
            Ok(_) => {}
            Err(GhostError::RelayStatus { status: 404, .. }) => {
                return Err(GhostError::RelayStatus {
                    status: 404,
                    context: "pairing".into(),
                    message: "the other device ended the pairing, or it expired".into(),
                })
            }
            // Not a draft for this device: nothing waiting longer changes that.
            Err(e @ (GhostError::IdentityLog(_) | GhostError::Crypto(_) | GhostError::Format(_))) => return Err(e),
            Err(e) => tracing::warn!("pairing: draft not signed: {e}"),
        }
        match idlog::fetch_chain(&reader, &code.account_fp).await {
            Ok((log, state)) if state.is_active_device(&device_vk) => {
                let added_at = state.devices[&device_vk].added_at_seq;
                let entry = log
                    .entries
                    .iter()
                    .find(|a| a.entry.seq == added_at)
                    .ok_or_else(|| GhostError::IdentityLog("the entry that added this device is missing".into()))?;
                return Ok((state, Addition::of(&entry.entry)));
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("pairing: identity log not ready: {e}"),
        }
    }
    Err(GhostError::TimedOut("waiting for the other device to add this one".into()))
}

/// Fetch and open the provision blob, retrying while the existing device is still uploading it.
pub async fn fetch_provision(
    relay: &RelayClient,
    code: &PairingCode,
    attempts: usize,
    interval: std::time::Duration,
) -> Result<ProvisionBlob> {
    let mut last_err = GhostError::Network("provision blob unavailable".into());
    for attempt in 0..attempts {
        if attempt > 0 {
            tokio::time::sleep(interval).await;
        }
        match relay.get_provision(&code.account_fp, &code.token).await {
            Ok(Some(sealed)) => return ProvisionBlob::from_bytes(&code.open(&sealed)?),
            Ok(None) => last_err = GhostError::Network("provision blob not uploaded yet".into()),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// The linked device's identity.
pub fn linked_identity(account_fp: [u8; 32], device_key: SigningKey, encryption_key: DeviceEncryptionKey, added_at: Addition) -> Identity {
    Identity::from_device(account_fp, device_key, encryption_key, added_at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_code_roundtrip() {
        let code = PairingCode {
            relay_url: "http://relay:7700".into(),
            account_fp: [0xAB; 32],
            secret: [0xCD; 32],
            token: [0xEF; 16],
        };
        let parsed = PairingCode::parse(&code.encode()).unwrap();
        assert_eq!(parsed.relay_url, "http://relay:7700");
        assert_eq!(parsed.account_fp, [0xAB; 32]);
        assert_eq!(parsed.secret, [0xCD; 32]);
        assert_eq!(parsed.token, [0xEF; 16]);
    }

    #[test]
    fn pairing_code_rejects_malformed() {
        assert!(PairingCode::parse("http://relay#abcd").is_err());
        assert!(PairingCode::parse("http://relay#zz#zz#zz").is_err());
        // A code from before tokens has only three fields.
        let fp = hex::encode([0xAB; 32]);
        let secret = hex::encode([0xCD; 32]);
        assert!(PairingCode::parse(&format!("http://relay#{fp}#{secret}")).is_err());
    }

    #[test]
    fn pairing_response_carries_no_private_key() {
        let r = PairingResponse { device_vk: [1; 32], encryption_key: [2; 32], device_key_signature: [3; 64], label: "phone".into() };
        let bytes = r.to_bytes();
        assert_eq!(bytes.len(), 128 + 5);
        let parsed = PairingResponse::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.device_vk, [1; 32]);
        assert_eq!(parsed.encryption_key, [2; 32]);
        assert_eq!(parsed.device_key_signature, [3; 64]);
        assert_eq!(parsed.label, "phone");
        assert!(PairingResponse::from_bytes(&[0u8; 128]).is_err());
    }

    #[test]
    fn comparison_codes_are_six_digits_bound_to_the_keys() {
        let code = comparison_code(&[1; 32], &[2; 32], &[3; 32]);
        assert_eq!(code.len(), 7);
        assert!(code.chars().filter(|c| *c != ' ').all(|c| c.is_ascii_digit()));
        assert_eq!(code, comparison_code(&[1; 32], &[2; 32], &[3; 32]));
        assert_ne!(code, comparison_code(&[1; 32], &[9; 32], &[3; 32]), "another device's key gives another code");
    }
}
