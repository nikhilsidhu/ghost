use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

use ghost_wire::{WS_FRAME_HEADER_SIZE, WS_SEQ_SIZE, WS_SIGNAL_EPOCH_MISMATCH, WS_SIGNAL_GAP};

use crate::error::{GhostError, Result};

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const RELAY_ERROR_PREFIX: &str = "error: ";

/// Identity log entry with a KT inclusion proof.
pub struct IdLogBlobWithProof {
    pub seq: u64,
    pub payload: Vec<u8>,
    pub inclusion_proof: Vec<u8>,
}

/// Response from GET /idlog with KT proofs.
pub struct IdLogWithProofs {
    pub entries: Vec<IdLogBlobWithProof>,
    pub checkpoint: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct IdLogResponseJson {
    entries: Vec<IdLogEntryJson>,
    checkpoint: String,
}

#[derive(serde::Deserialize)]
struct IdLogEntryJson {
    seq: u64,
    payload: String,
    inclusion_proof: String,
}

pub struct IncomingBlob {
    pub mailbox_id: [u8; 32],
    pub seq: u64,
    pub received_at: u64,
    pub payload: Vec<u8>,
}

pub struct Ack {
    pub seq: u64,
    pub epoch_mismatch: bool,
}

pub enum RelayEvent {
    Blob(IncomingBlob),
    Ack(Ack),
    Error { mailbox_id: [u8; 32], message: String },
    Gap { mailbox_id: [u8; 32] },
    VoiceState { mailbox_id: [u8; 32], json: String },
    Presence { mailbox_id: [u8; 32], json: String },
    ConnectionState { mailbox_id: [u8; 32], connected: bool },
}

pub enum WsOutgoing {
    Binary(Vec<u8>),
    Text(String),
}

struct WsHandle {
    outbox: mpsc::Sender<WsOutgoing>,
    task: JoinHandle<()>,
}

/// Auth context for request signing. Shared with WS tasks via Arc.
#[derive(Clone)]
pub struct AuthContext {
    pub account_fp: [u8; 32],
    pub device_vk: [u8; 32],
    signing_key: SigningKey,
}

impl AuthContext {
    fn sign_for(&self, method: &str, path: &str) -> ghost_wire::auth::AuthHeaders {
        ghost_wire::auth::sign_request_headers(method, path, &self.account_fp, &self.device_vk, &self.signing_key)
    }
}

pub struct RelayClient {
    base_url: String,
    ws_base_url: String,
    http: reqwest::Client,
    event_tx: mpsc::Sender<RelayEvent>,
    connections: HashMap<[u8; 32], WsHandle>,
    auth: Option<Arc<AuthContext>>,
}

impl RelayClient {
    pub fn new(base_url: &str) -> (Self, mpsc::Receiver<RelayEvent>) {
        let base = base_url.trim_end_matches('/').to_string();
        let ws_base = base
            .replace("http://", "ws://")
            .replace("https://", "wss://");
        let (event_tx, event_rx) = mpsc::channel(256);
        let client = Self {
            base_url: base,
            ws_base_url: ws_base,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .connect_timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
            event_tx,
            connections: HashMap::new(),
            auth: None,
        };
        (client, event_rx)
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Set auth credentials for request signing. Called once after identity is loaded.
    pub fn set_auth(&mut self, account_fp: [u8; 32], device_vk: [u8; 32], signing_key: SigningKey) {
        self.auth = Some(Arc::new(AuthContext { account_fp, device_vk, signing_key }));
    }

    /// Fetch the relay's Ed25519 verifying key (hex-encoded, 32 bytes).
    pub async fn get_relay_key(&self) -> Result<[u8; 32]> {
        let resp = self
            .http
            .get(format!("{}/relay_key", self.base_url))
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!("get relay_key: {}", resp.status())));
        }
        let hex_str = resp
            .text()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| GhostError::Network(format!("relay_key hex: {e}")))?;
        bytes
            .try_into()
            .map_err(|_| GhostError::Network("relay_key must be 32 bytes".into()))
    }

    /// Apply auth headers to a request builder if auth is configured.
    fn authenticated(&self, method: &str, path: &str, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            Some(auth) => {
                let h = auth.sign_for(method, path);
                req.header("X-Ghost-Account", &h.account)
                    .header("X-Ghost-Device", &h.device)
                    .header("X-Ghost-Timestamp", &h.timestamp)
                    .header("X-Ghost-Signature", &h.signature)
            }
            None => req,
        }
    }

    /// Subscribe to a mailbox. The connection is established in the background
    /// with automatic reconnection on failure.
    pub fn subscribe(&mut self, mailbox_id: [u8; 32], last_seen_seq: u64) {
        let url = format!(
            "{}/ws/{}",
            self.ws_base_url,
            URL_SAFE_NO_PAD.encode(mailbox_id)
        );

        if let Some(old) = self.connections.remove(&mailbox_id) {
            old.task.abort();
        }

        let (outbox_tx, outbox_rx) = mpsc::channel(64);
        let event_tx = self.event_tx.clone();
        let auth = self.auth.clone();
        let task = tokio::spawn(ws_task(url, mailbox_id, last_seen_seq, event_tx, outbox_rx, auth));
        self.connections
            .insert(mailbox_id, WsHandle { outbox: outbox_tx, task });
    }

    pub fn unsubscribe(&mut self, mailbox_id: &[u8; 32]) {
        if let Some(handle) = self.connections.remove(mailbox_id) {
            handle.task.abort();
        }
    }

    pub async fn send(&self, mailbox_id: &[u8; 32], blob: Vec<u8>) -> Result<()> {
        let handle = self
            .connections
            .get(mailbox_id)
            .ok_or_else(|| GhostError::Network("not subscribed to mailbox".into()))?;
        handle
            .outbox
            .send(WsOutgoing::Binary(blob))
            .await
            .map_err(|_| GhostError::Network("ws connection closed".into()))
    }

    pub async fn send_text(&self, mailbox_id: &[u8; 32], text: String) -> Result<()> {
        let handle = self
            .connections
            .get(mailbox_id)
            .ok_or_else(|| GhostError::Network("not subscribed to mailbox".into()))?;
        handle
            .outbox
            .send(WsOutgoing::Text(text))
            .await
            .map_err(|_| GhostError::Network("ws connection closed".into()))
    }

    /// Send a blob to a mailbox via HTTP POST (no WebSocket subscription required).
    /// Returns the seq assigned by the relay.
    pub async fn post_blob(&self, mailbox_id: &[u8; 32], blob: Vec<u8>) -> Result<u64> {
        let path = format!("/box/{}", URL_SAFE_NO_PAD.encode(mailbox_id));
        let req = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .body(blob);
        let resp = self.authenticated("POST", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!(
                "post blob: {}",
                resp.status()
            )));
        }
        #[derive(serde::Deserialize)]
        struct PostResp { seq: u64 }
        let body: PostResp = resp
            .json()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        Ok(body.seq)
    }

    pub async fn register_invite(&self, token: &str, expires_at: u64) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/invite", self.base_url))
            .json(&serde_json::json!({ "token": token, "expires_at": expires_at }))
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!(
                "register invite: {}",
                resp.status()
            )));
        }
        Ok(())
    }

    pub async fn post_join(&self, token: &str, payload: Vec<u8>) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/invite/{}/join", self.base_url, token))
            .body(payload)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!(
                "post join: {}",
                resp.status()
            )));
        }
        Ok(())
    }

    pub async fn get_join(&self, token: &str) -> Result<Vec<u8>> {
        let resp = self
            .http
            .get(format!("{}/invite/{}/join", self.base_url, token))
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NO_CONTENT {
            return Err(GhostError::Network("join not yet submitted".into()));
        }
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!(
                "get join: {}",
                resp.status()
            )));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| GhostError::Network(e.to_string()))
    }

    pub async fn post_accept(&self, token: &str, payload: Vec<u8>) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/invite/{}/accept", self.base_url, token))
            .body(payload)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!(
                "post accept: {}",
                resp.status()
            )));
        }
        Ok(())
    }

    pub async fn get_accept(&self, token: &str) -> Result<Vec<u8>> {
        let resp = self
            .http
            .get(format!("{}/invite/{}/accept", self.base_url, token))
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NO_CONTENT {
            return Err(GhostError::Network("accept not yet submitted".into()));
        }
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!(
                "get accept: {}",
                resp.status()
            )));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| GhostError::Network(e.to_string()))
    }

    pub async fn put_server_info(&self, mailbox_id: &[u8; 32], data: Vec<u8>) -> Result<()> {
        let path = format!("/box/{}/server_info", URL_SAFE_NO_PAD.encode(mailbox_id));
        let req = self
            .http
            .put(format!("{}{}", self.base_url, path))
            .body(data);
        let resp = self.authenticated("PUT", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!(
                "put server_info: {}",
                resp.status()
            )));
        }
        Ok(())
    }

    pub async fn get_server_info(&self, mailbox_id: &[u8; 32]) -> Result<Vec<u8>> {
        let path = format!("/box/{}/server_info", URL_SAFE_NO_PAD.encode(mailbox_id));
        let req = self
            .http
            .get(format!("{}{}", self.base_url, path));
        let resp = self.authenticated("GET", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!(
                "get server_info: {}",
                resp.status()
            )));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| GhostError::Network(e.to_string()))
    }

    pub async fn put_avatar(
        &self,
        mailbox_id: &[u8; 32],
        fingerprint: &[u8; 32],
        data: Vec<u8>,
    ) -> Result<()> {
        let path = format!("/box/{}/avatar/{}", URL_SAFE_NO_PAD.encode(mailbox_id), hex::encode(fingerprint));
        let req = self
            .http
            .put(format!("{}{}", self.base_url, path))
            .body(data);
        let resp = self.authenticated("PUT", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!("put avatar: {}", resp.status())));
        }
        Ok(())
    }

    pub async fn get_avatar(
        &self,
        mailbox_id: &[u8; 32],
        fingerprint: &[u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        let path = format!("/box/{}/avatar/{}", URL_SAFE_NO_PAD.encode(mailbox_id), hex::encode(fingerprint));
        let req = self
            .http
            .get(format!("{}{}", self.base_url, path));
        let resp = self.authenticated("GET", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!("get avatar: {}", resp.status())));
        }
        resp.bytes()
            .await
            .map(|b| Some(b.to_vec()))
            .map_err(|e| GhostError::Network(e.to_string()))
    }

    pub async fn delete_avatar(
        &self,
        mailbox_id: &[u8; 32],
        fingerprint: &[u8; 32],
    ) -> Result<()> {
        let path = format!("/box/{}/avatar/{}", URL_SAFE_NO_PAD.encode(mailbox_id), hex::encode(fingerprint));
        let req = self
            .http
            .delete(format!("{}{}", self.base_url, path));
        let resp = self.authenticated("DELETE", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!("delete avatar: {}", resp.status())));
        }
        Ok(())
    }

    /// Push an identity log entry to the relay.
    pub async fn put_idlog_entry(
        &self,
        account_fp: &[u8; 32],
        payload: Vec<u8>,
    ) -> Result<()> {
        let resp = self
            .http
            .put(format!(
                "{}/idlog/{}",
                self.base_url,
                hex::encode(account_fp),
            ))
            .body(payload)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!("put idlog: {}", resp.status())));
        }
        Ok(())
    }

    /// Fetch identity log entries with KT inclusion proofs.
    pub async fn get_idlog(
        &self,
        account_fp: &[u8; 32],
        after_seq: u64,
    ) -> Result<IdLogWithProofs> {
        let mut url = format!(
            "{}/idlog/{}",
            self.base_url,
            hex::encode(account_fp),
        );
        if after_seq > 0 {
            url.push_str(&format!("?after_seq={after_seq}"));
        }
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!("get idlog: {}", resp.status())));
        }
        let body: IdLogResponseJson = resp
            .json()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;

        let b64 = &base64::engine::general_purpose::STANDARD;
        let checkpoint = b64
            .decode(&body.checkpoint)
            .map_err(|e| GhostError::Network(format!("base64: {e}")))?;
        let entries = body
            .entries
            .into_iter()
            .map(|e| {
                let payload = b64
                    .decode(&e.payload)
                    .map_err(|e| GhostError::Network(format!("base64: {e}")))?;
                let inclusion_proof = b64
                    .decode(&e.inclusion_proof)
                    .map_err(|e| GhostError::Network(format!("base64: {e}")))?;
                Ok(IdLogBlobWithProof {
                    seq: e.seq,
                    payload,
                    inclusion_proof,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(IdLogWithProofs {
            entries,
            checkpoint,
        })
    }

    /// Fetch a KT consistency proof proving the tree at `from` is a prefix of `to`.
    pub async fn get_consistency_proof(
        &self,
        from: u64,
        to: u64,
    ) -> Result<Vec<u8>> {
        let url = format!(
            "{}/kt/consistency-proof?from={from}&to={to}",
            self.base_url,
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!(
                "get consistency proof: {}",
                resp.status()
            )));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| GhostError::Network(e.to_string()))
    }

    /// Post a pairing offer (existing device → relay).
    pub async fn post_pairing_offer(
        &self,
        account_fp: &[u8; 32],
        payload: Vec<u8>,
    ) -> Result<()> {
        let resp = self
            .http
            .post(format!(
                "{}/pair/{}",
                self.base_url,
                hex::encode(account_fp),
            ))
            .body(payload)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!("post pairing offer: {}", resp.status())));
        }
        Ok(())
    }

    /// Post a pairing response (new device → relay).
    pub async fn post_pairing_response(
        &self,
        account_fp: &[u8; 32],
        payload: Vec<u8>,
    ) -> Result<()> {
        let resp = self
            .http
            .post(format!(
                "{}/pair/{}/respond",
                self.base_url,
                hex::encode(account_fp),
            ))
            .body(payload)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!("post pairing response: {}", resp.status())));
        }
        Ok(())
    }

    /// Poll for a pairing response (existing device polls relay).
    pub async fn get_pairing_response(
        &self,
        account_fp: &[u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        let resp = self
            .http
            .get(format!(
                "{}/pair/{}/response",
                self.base_url,
                hex::encode(account_fp),
            ))
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!("get pairing response: {}", resp.status())));
        }
        resp.bytes()
            .await
            .map(|b| Some(b.to_vec()))
            .map_err(|e| GhostError::Network(e.to_string()))
    }

    /// Store encrypted recovery blob on relay.
    pub async fn put_recovery_blob(
        &self,
        account_fp: &[u8; 32],
        data: Vec<u8>,
    ) -> Result<()> {
        let path = format!("/recovery/{}", hex::encode(account_fp));
        let req = self
            .http
            .put(format!("{}{}", self.base_url, path))
            .body(data);
        let resp = self.authenticated("PUT", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!("put recovery: {}", resp.status())));
        }
        Ok(())
    }

    /// Store encrypted sync state snapshot on relay.
    pub async fn put_sync_state(
        &self,
        account_fp: &[u8; 32],
        data: Vec<u8>,
    ) -> Result<()> {
        let path = format!("/sync_state/{}", hex::encode(account_fp));
        let req = self
            .http
            .put(format!("{}{}", self.base_url, path))
            .body(data);
        let resp = self.authenticated("PUT", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!("put sync_state: {}", resp.status())));
        }
        Ok(())
    }

    /// Fetch encrypted sync state snapshot from relay.
    pub async fn get_sync_state(
        &self,
        account_fp: &[u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        let path = format!("/sync_state/{}", hex::encode(account_fp));
        let req = self
            .http
            .get(format!("{}{}", self.base_url, path));
        let resp = self.authenticated("GET", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!("get sync_state: {}", resp.status())));
        }
        resp.bytes()
            .await
            .map(|b| Some(b.to_vec()))
            .map_err(|e| GhostError::Network(e.to_string()))
    }

    /// Fetch encrypted recovery blob from relay.
    pub async fn get_recovery_blob(
        &self,
        account_fp: &[u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        let resp = self
            .http
            .get(format!(
                "{}/recovery/{}",
                self.base_url,
                hex::encode(account_fp),
            ))
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!("get recovery: {}", resp.status())));
        }
        resp.bytes()
            .await
            .map(|b| Some(b.to_vec()))
            .map_err(|e| GhostError::Network(e.to_string()))
    }
}

impl Drop for RelayClient {
    fn drop(&mut self) {
        for (_, handle) in self.connections.drain() {
            handle.task.abort();
        }
    }
}

/// Persistent task that maintains a WebSocket connection with automatic reconnection.
async fn ws_task(
    url: String,
    mailbox_id: [u8; 32],
    initial_last_seen: u64,
    event_tx: mpsc::Sender<RelayEvent>,
    mut outbox_rx: mpsc::Receiver<WsOutgoing>,
    auth: Option<Arc<AuthContext>>,
) {
    let mut last_seen = initial_last_seen;
    let mut backoff = INITIAL_BACKOFF;
    let mut first_attempt = true;

    loop {
        if !first_attempt {
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
        first_attempt = false;

        let ws = if let Some(ref auth) = auth {
            let ws_path = url.find("//")
                .and_then(|i| url[i+2..].find('/').map(|j| &url[i+2+j..]))
                .unwrap_or("/");
            let h = auth.sign_for("GET", ws_path);
            let req = tokio_tungstenite::tungstenite::http::Request::builder()
                .uri(&url)
                .header("Host", url_host(&url))
                .header("Connection", "Upgrade")
                .header("Upgrade", "websocket")
                .header("Sec-WebSocket-Version", "13")
                .header("Sec-WebSocket-Key", tokio_tungstenite::tungstenite::handshake::client::generate_key())
                .header("X-Ghost-Account", &h.account)
                .header("X-Ghost-Device", &h.device)
                .header("X-Ghost-Timestamp", &h.timestamp)
                .header("X-Ghost-Signature", &h.signature)
                .body(())
                .unwrap();
            match tokio_tungstenite::connect_async(req).await {
                Ok((ws, _)) => ws,
                Err(_) => continue,
            }
        } else {
            match tokio_tungstenite::connect_async(&url).await {
                Ok((ws, _)) => ws,
                Err(_) => continue,
            }
        };

        let (mut sink, mut stream) = ws.split();

        // Handshake: send last_seen_seq so the relay replays missed entries
        if sink
            .send(Message::Binary(last_seen.to_be_bytes().to_vec().into()))
            .await
            .is_err()
        {
            continue;
        }

        let _ = event_tx.send(RelayEvent::ConnectionState { mailbox_id, connected: true }).await;
        let mut got_message = false;

        loop {
            tokio::select! {
                outgoing = outbox_rx.recv() => {
                    match outgoing {
                        Some(WsOutgoing::Binary(data)) => {
                            if sink.send(Message::Binary(data.into())).await.is_err() {
                                break;
                            }
                        }
                        Some(WsOutgoing::Text(text)) => {
                            if sink.send(Message::Text(text.into())).await.is_err() {
                                break;
                            }
                        }
                        None => return,
                    }
                }
                msg = stream.next() => {
                    match msg {
                        Some(Ok(Message::Binary(data))) => {
                            if data.len() < WS_FRAME_HEADER_SIZE {
                                continue;
                            }
                            let seq = u64::from_be_bytes(data[..WS_SEQ_SIZE].try_into().unwrap());
                            let received_at = u64::from_be_bytes(
                                data[WS_SEQ_SIZE..WS_FRAME_HEADER_SIZE].try_into().unwrap(),
                            );
                            let payload = data[WS_FRAME_HEADER_SIZE..].to_vec();
                            last_seen = seq;
                            if !got_message {
                                got_message = true;
                                backoff = INITIAL_BACKOFF;
                            }
                            let _ = event_tx.send(RelayEvent::Blob(IncomingBlob {
                                mailbox_id,
                                seq,
                                received_at,
                                payload,
                            })).await;
                        }
                        Some(Ok(Message::Text(text))) => {
                            if !got_message {
                                got_message = true;
                                backoff = INITIAL_BACKOFF;
                            }
                            let s = text.as_str();
                            if s == WS_SIGNAL_GAP {
                                let _ = event_tx.send(RelayEvent::Gap { mailbox_id }).await;
                            } else if s.starts_with("{\"vs") {
                                let _ = event_tx.send(RelayEvent::VoiceState {
                                    mailbox_id,
                                    json: s.to_string(),
                                }).await;
                            } else if s.starts_with("{\"ps") {
                                let _ = event_tx.send(RelayEvent::Presence {
                                    mailbox_id,
                                    json: s.to_string(),
                                }).await;
                            } else if let Some(err_msg) = s.strip_prefix(RELAY_ERROR_PREFIX) {
                                let _ = event_tx.send(RelayEvent::Error {
                                    mailbox_id,
                                    message: err_msg.to_string(),
                                }).await;
                            } else if let Some(ack) = parse_ack(s) {
                                let _ = event_tx.send(RelayEvent::Ack(ack)).await;
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => break,
                        _ => {}
                    }
                }
            }
        }

        let _ = event_tx.send(RelayEvent::ConnectionState { mailbox_id, connected: false }).await;
    }
}

fn parse_ack(text: &str) -> Option<Ack> {
    let mut parts = text.splitn(2, ' ');
    let seq: u64 = parts.next()?.parse().ok()?;
    let epoch_mismatch = parts.next() == Some(WS_SIGNAL_EPOCH_MISMATCH);
    Some(Ack { seq, epoch_mismatch })
}

/// Extract host[:port] from a ws:// or wss:// URL for the Host header.
fn url_host(url: &str) -> String {
    let without_scheme = url
        .strip_prefix("ws://")
        .or_else(|| url.strip_prefix("wss://"))
        .unwrap_or(url);
    without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .to_string()
}
