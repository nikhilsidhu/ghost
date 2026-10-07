//! Linking a new device to an existing account through a relay rendezvous.
//!
//! The existing device (A) posts a sealed offer, the new device (B) answers with its
//! signing key, A uploads a sealed provision blob and appends `AddDevice` to the
//! identity log, and B waits for that entry before fetching the provision.
//! All rendezvous payloads are AES-256-GCM sealed with a secret that only travels
//! inside the pairing code.

use ed25519_dalek::SigningKey;
use ghost_wire::idlog::LogState;

use crate::crypto::aead;
use crate::error::{GhostError, Result};
use crate::identity::log::create_add_device;
use crate::identity::{compute_delegation_sig, Identity};
use crate::relay::{PairingToken, RelayClient};
use zeroize::Zeroize;

use super::idlog;
use super::provision::ProvisionBlob;
use super::{SharedClient, SharedRelay};

const SEAL_CONTEXT: &str = "pairing";

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
}

fn parse_32(hex_str: &str, what: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).map_err(|e| GhostError::Format(format!("{what}: {e}")))?;
    bytes.try_into().map_err(|_| GhostError::Format(format!("{what}: must be 32 bytes")))
}

/// Account presentation the new device adopts, sealed inside the offer.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PairingOffer {
    pub relay_url: String,
    pub display_name: String,
    /// Hex-encoded avatar hash, kept as text for compatibility with existing offers.
    pub avatar_hash: Option<String>,
    pub status_message: Option<String>,
}

impl PairingOffer {
    pub fn avatar_hash_bytes(&self) -> Option<[u8; 32]> {
        self.avatar_hash.as_deref().and_then(|h| parse_32(h, "avatar hash").ok())
    }
}

/// The new device's answer: `[device_sk:32][label utf-8]`.
pub struct PairingResponse {
    pub device_sk: [u8; 32],
    pub label: String,
}

impl PairingResponse {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + self.label.len());
        buf.extend_from_slice(&self.device_sk);
        buf.extend_from_slice(self.label.as_bytes());
        buf
    }

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 33 {
            return Err(GhostError::Format("pairing response too short".into()));
        }
        let device_sk: [u8; 32] = data[..32].try_into().unwrap();
        let label = String::from_utf8(data[32..].to_vec())
            .map_err(|_| GhostError::Format("pairing response label is not UTF-8".into()))?;
        Ok(Self { device_sk, label })
    }
}

// ── Existing device (A) ─────────────────────────────────────────────

/// Post a sealed offer and return the pairing code to show the new device.
pub async fn start(client: &SharedClient, relay: &SharedRelay, offer: &PairingOffer) -> Result<PairingCode> {
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
    let relay_url = {
        let r = relay.lock().await;
        r.post_pairing_offer(&account_fp, &token, sealed).await?;
        r.base_url().to_string()
    };
    let code = PairingCode { relay_url, account_fp, secret, token };
    secret.zeroize();
    Ok(code)
}

/// Poll for the new device's response on the session `code` names. When it has arrived:
/// upload the provision blob, then append `AddDevice` at the home relay. Returns the new
/// device's label, or `None` while still waiting. `relay` is the home relay; `rendezvous`
/// is the relay the code names (the same client when pairing at the home). `genesis_entry`
/// lets the flow re-push the account's genesis if the home has lost the identity log.
pub async fn check(
    client: &SharedClient,
    relay: &SharedRelay,
    rendezvous: &SharedRelay,
    code: &PairingCode,
    genesis_entry: Option<&[u8]>,
) -> Result<Option<String>> {
    let account_fp = {
        let c = client.lock().await;
        *c.fingerprint()
    };

    let sealed = {
        let r = rendezvous.lock().await;
        r.get_pairing_response(&account_fp, &code.token).await?
    };
    let Some(sealed) = sealed else { return Ok(None) };
    let response = PairingResponse::from_bytes(&aead::open(&code.secret, &sealed, SEAL_CONTEXT)?)?;
    let new_device_key = SigningKey::from_bytes(&response.device_sk);

    let log_state = idlog::fetch_own_log_or_republish(client, relay, &account_fp, genesis_entry).await?;

    // The provision goes up first: the new device starts fetching it the moment it sees
    // AddDevice in the identity log.
    let (blob, authorizer_key) = {
        let mut c = client.lock().await;
        let sync_key = c
            .sync_key()
            .ok_or_else(|| GhostError::Crypto("sync key not set; account not initialized".into()))?;
        if !c.has_sync_group() {
            c.create_sync_group()?;
        }
        let sync_group_info = c.sync_group_info()?;
        let mut servers = Vec::new();
        for (server_id, _) in c.server_mailboxes() {
            if let Ok(payload) = c.export_provision_payload(&server_id) {
                servers.push(payload);
            }
        }
        let new_device_seq = log_state.head_seq + 1;
        let identity = c.identity();
        let delegation_sig = compute_delegation_sig(
            &identity.master_sk,
            new_device_key.verifying_key().as_bytes(),
            &account_fp,
            new_device_seq,
        );
        let blob = ProvisionBlob {
            master_sk: identity.master_sk.to_bytes(),
            master_vk: identity.master_vk,
            delegation_sig,
            sync_key,
            sync_group_info,
            servers,
            sync_entries: c.sync_dump().unwrap_or_default(),
        };
        (blob, c.signing_key_clone())
    };
    let sealed_provision = aead::seal(&code.secret, &blob.to_bytes()?, SEAL_CONTEXT)?;

    // The relay needs the sync group's state before it will accept the new device's join commit.
    super::publish_sync_group_info(client, relay).await?;

    let add_entry = create_add_device(&log_state, &authorizer_key, &new_device_key, &response.label);
    {
        let r = rendezvous.lock().await;
        r.put_provision(&account_fp, &code.token, sealed_provision).await?;
    }
    {
        let r = relay.lock().await;
        r.put_idlog_entry(&account_fp, add_entry.to_bytes()).await?;
    }
    // The new device rejoins servers on their own relays, which must know its key first.
    for (relay_vk, e) in super::account::replicate_own_log(client, relay).await? {
        eprintln!("pairing: relay {} not updated yet: {e}", hex::encode(&relay_vk[..8]));
    }
    Ok(Some(response.label))
}

// ── New device (B) ──────────────────────────────────────────────────

/// Fetch and open the offer behind a pairing code. `relay` is unauthenticated.
pub async fn fetch_offer(relay: &RelayClient, code: &PairingCode) -> Result<PairingOffer> {
    let sealed = relay.get_pairing_offer(&code.account_fp, &code.token).await?;
    let plaintext = aead::open(&code.secret, &sealed, SEAL_CONTEXT)?;
    serde_json::from_slice(&plaintext).map_err(|e| GhostError::Format(format!("offer decode: {e}")))
}

/// Send this device's new signing key and label to the existing device.
pub async fn respond(relay: &RelayClient, code: &PairingCode, device_key: &SigningKey, label: &str) -> Result<()> {
    let response = PairingResponse { device_sk: device_key.to_bytes(), label: label.to_string() };
    let sealed = aead::seal(&code.secret, &response.to_bytes(), SEAL_CONTEXT)?;
    relay.post_pairing_response(&code.account_fp, &code.token, sealed).await
}

/// Poll the identity log until this device's key is active, or the attempts run out.
/// Reads are signed with the new device key, which the relay accepts only once the
/// existing device has added it, so until then a poll is refused like a missing entry.
pub async fn wait_for_device(
    relay: &RelayClient,
    account_fp: &[u8; 32],
    device_key: &SigningKey,
    attempts: usize,
    interval: std::time::Duration,
) -> Result<LogState> {
    let device_vk = device_key.verifying_key().to_bytes();
    let mut reader = relay.at(relay.base_url());
    reader.set_auth(*account_fp, device_vk, device_key.clone());
    for _ in 0..attempts {
        tokio::time::sleep(interval).await;
        match idlog::fetch_chain(&reader, account_fp).await {
            Ok((_, state)) if state.is_active_device(&device_vk) => return Ok(state),
            Ok(_) => {}
            Err(e) => eprintln!("pairing: identity log not ready: {e}"),
        }
    }
    Err(GhostError::IdentityLog("timed out waiting for the device to be added".into()))
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
            Ok(Some(sealed)) => {
                let plaintext = aead::open(&code.secret, &sealed, SEAL_CONTEXT)?;
                return ProvisionBlob::from_bytes(&plaintext);
            }
            Ok(None) => last_err = GhostError::Network("provision blob not uploaded yet".into()),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Build the linked device's identity from the validated log and the provision blob.
pub fn linked_identity(
    account_fp: [u8; 32],
    device_key: SigningKey,
    log_state: &LogState,
    blob: &ProvisionBlob,
) -> Identity {
    let device_vk = device_key.verifying_key().to_bytes();
    let idlog_seq = log_state.devices.get(&device_vk).map(|d| d.added_at_seq).unwrap_or(0);
    Identity::from_device(
        account_fp,
        device_key,
        idlog_seq,
        blob.master_vk,
        SigningKey::from_bytes(&blob.master_sk),
        blob.delegation_sig,
    )
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
    fn pairing_response_roundtrip() {
        let r = PairingResponse { device_sk: [7u8; 32], label: "phone".into() };
        let parsed = PairingResponse::from_bytes(&r.to_bytes()).unwrap();
        assert_eq!(parsed.device_sk, [7u8; 32]);
        assert_eq!(parsed.label, "phone");
    }

    #[test]
    fn pairing_response_too_short() {
        assert!(PairingResponse::from_bytes(&[0u8; 32]).is_err());
    }
}
