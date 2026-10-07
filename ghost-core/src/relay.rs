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

use ghost_wire::anchor::{decode_sequence, encode_sequence, AnchoredEntry, ImportRequest};
use ghost_wire::merkle::Checkpoint;
use ghost_wire::recovery_bundle::RecoveryBundle;
use ghost_wire::relay_ref::RelayRef;
use ghost_wire::server_location::ServerLocation;
use ghost_wire::{
    SNAPSHOT_GENERATION_LEN, WS_FRAME_HEADER_SIZE, WS_SEQ_SIZE, WS_SIGNAL_EPOCH_MISMATCH, WS_SIGNAL_GAP,
};
use serde::Deserialize;

use crate::error::{GhostError, Result};

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const RELAY_ERROR_PREFIX: &str = "error: ";

/// Header carrying the invite payload's optimistic-concurrency sequence number.
pub const INVITE_SEQ_HEADER: &str = "X-Ghost-Seq";

/// Typed error for a non-success response, keeping the relay's explanation.
async fn status_err(context: &str, resp: reqwest::Response) -> GhostError {
    let status = resp.status().as_u16();
    let message = resp.text().await.unwrap_or_default();
    GhostError::RelayStatus { status, context: context.to_string(), message }
}

/// Random id of one pairing session; only the pairing code carries it.
pub type PairingToken = [u8; 16];

/// An account's identity log as a relay serves it: every entry carries the
/// proof its home relay sequenced it.
#[derive(Debug)]
pub struct AnchoredLog {
    /// Relay that sequences the log; the serving relay's own key for a chain
    /// that names no home.
    pub home_relay_vk: [u8; 32],
    pub entries: Vec<AnchoredEntry>,
}

#[derive(serde::Deserialize)]
struct IdLogResponseJson {
    home_relay_vk: String,
    entries: Vec<IdLogEntryJson>,
}

#[derive(serde::Deserialize)]
struct IdLogEntryJson {
    anchored: String,
}

/// What a relay reports about an account it holds or mirrors.
#[derive(Debug, serde::Deserialize)]
pub struct AccountInfo {
    #[serde(deserialize_with = "hex_32")]
    pub home_relay_vk: [u8; 32],
    pub head_seq: u64,
    pub is_home: bool,
}

/// A relay's identity and how to reach it.
pub struct RelayInfo {
    pub relay_vk: [u8; 32],
    pub protocol: u32,
    pub relay_ref: RelayRef,
    pub kt_head: Option<Checkpoint>,
}

#[derive(serde::Deserialize)]
struct RelayInfoJson {
    relay_vk: String,
    protocol: u32,
    r#ref: String,
    kt_head: Option<String>,
}

fn hex_32<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<[u8; 32], D::Error> {
    let text = String::deserialize(d)?;
    decode_hex_32(&text).map_err(serde::de::Error::custom)
}

fn decode_hex_32(text: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(text.trim()).map_err(|e| GhostError::Network(format!("hex: {e}")))?;
    bytes.try_into().map_err(|_| GhostError::Network("expected 32 bytes".into()))
}

pub struct IncomingBlob {
    pub mailbox_id: [u8; 32],
    pub seq: u64,
    pub received_at: u64,
    pub payload: Vec<u8>,
}

pub struct Ack {
    pub mailbox_id: [u8; 32],
    pub seq: u64,
    pub epoch_mismatch: bool,
}

pub struct PostBlobResult {
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
    /// A private channel of the server at this mailbox newly admits this account.
    ChannelsChanged { mailbox_id: [u8; 32] },
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
        // channel_binding: None until TLS termination is added to the relay
        ghost_wire::auth::sign_request_headers(method, path, &self.account_fp, &self.device_vk, &self.signing_key, None)
    }
}

/// Live mailbox connections and where each mailbox lives, shared by a client and
/// every view it opens onto another relay, so one event stream and one set of
/// subscriptions cover all relays the account uses.
#[derive(Default)]
struct Subscriptions {
    connections: HashMap<[u8; 32], WsHandle>,
    /// Relay base URL for each subscribed mailbox and each id added with `add_route`.
    routes: HashMap<[u8; 32], String>,
}

impl Drop for Subscriptions {
    fn drop(&mut self) {
        for (_, handle) in self.connections.drain() {
            handle.task.abort();
        }
    }
}

pub struct RelayClient {
    base_url: String,
    http: reqwest::Client,
    event_tx: mpsc::Sender<RelayEvent>,
    subscriptions: Arc<std::sync::Mutex<Subscriptions>>,
    auth: Option<Arc<AuthContext>>,
}

fn ws_base(base_url: &str) -> String {
    base_url.replace("http://", "ws://").replace("https://", "wss://")
}

impl RelayClient {
    pub fn new(base_url: &str) -> (Self, mpsc::Receiver<RelayEvent>) {
        let base = base_url.trim_end_matches('/').to_string();
        let (event_tx, event_rx) = mpsc::channel(256);
        let client = Self {
            base_url: base,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .connect_timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
            event_tx,
            subscriptions: Arc::new(std::sync::Mutex::new(Subscriptions::default())),
            auth: None,
        };
        (client, event_rx)
    }

    /// A client for another relay that signs as the same device and shares this
    /// client's subscriptions and event stream. Mailboxes subscribed through it
    /// stay connected after it is dropped and are reachable from every view.
    pub fn at(&self, base_url: &str) -> RelayClient {
        let base = base_url.trim_end_matches('/').to_string();
        RelayClient {
            base_url: base,
            http: self.http.clone(),
            event_tx: self.event_tx.clone(),
            subscriptions: self.subscriptions.clone(),
            auth: self.auth.clone(),
        }
    }

    /// Route mailbox-scoped requests for `id` (a mailbox or voice channel) to this view's relay.
    pub fn add_route(&self, id: [u8; 32]) {
        self.subscriptions.lock().unwrap().routes.insert(id, self.base_url.clone());
    }

    /// Base URL of the relay `id` lives on: its recorded route, else this view's relay.
    fn base_for(&self, id: &[u8; 32]) -> String {
        self.subscriptions
            .lock()
            .unwrap()
            .routes
            .get(id)
            .cloned()
            .unwrap_or_else(|| self.base_url.clone())
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Set auth credentials for request signing. Called once after identity is loaded.
    pub fn set_auth(&mut self, account_fp: [u8; 32], device_vk: [u8; 32], signing_key: SigningKey) {
        self.auth = Some(Arc::new(AuthContext { account_fp, device_vk, signing_key }));
    }

    /// Sign as the same device as `other`, for talking to another relay.
    pub fn copy_auth_from(&mut self, other: &RelayClient) {
        self.auth = other.auth.clone();
    }

    /// Fetch the relay's identity, reachability hints and KT head.
    pub async fn get_relay_info(&self) -> Result<RelayInfo> {
        let resp = self
            .http
            .get(format!("{}/relay", self.base_url))
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("get relay info", resp).await);
        }
        let body: RelayInfoJson = resp.json().await.map_err(|e| GhostError::Network(e.to_string()))?;
        let relay_vk = decode_hex_32(&body.relay_vk)?;
        let mut relay_ref = RelayRef::decode(&body.r#ref)
            .map_err(|e| GhostError::Network(format!("relay ref: {e}")))?;
        if relay_ref.relay_vk != relay_vk {
            return Err(GhostError::Network("relay ref names a different relay".into()));
        }
        // A relay without a configured public URL is still reachable where we dialed it.
        if relay_ref.primary_https_url().is_none() {
            relay_ref = RelayRef::https(relay_vk, &self.base_url);
        }
        let kt_head = match body.kt_head {
            Some(b64) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&b64)
                    .map_err(|e| GhostError::Network(format!("base64: {e}")))?;
                Some(Checkpoint::from_bytes(&bytes).map_err(|e| GhostError::Network(format!("kt head: {e}")))?)
            }
            None => None,
        };
        Ok(RelayInfo { relay_vk, protocol: body.protocol, relay_ref, kt_head })
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
    /// with automatic reconnection on failure. A mailbox already routed to a relay
    /// reconnects there, from whichever view this is called on; a new mailbox is
    /// opened on this view's relay and routed to it.
    pub fn subscribe(&mut self, mailbox_id: [u8; 32], last_seen_seq: u64) {
        let base = self.base_for(&mailbox_id);
        let url = format!("{}/ws/{}", ws_base(&base), URL_SAFE_NO_PAD.encode(mailbox_id));

        let (outbox_tx, outbox_rx) = mpsc::channel(64);
        let event_tx = self.event_tx.clone();
        let auth = self.auth.clone();
        let task = tokio::spawn(ws_task(url, mailbox_id, last_seen_seq, event_tx, outbox_rx, auth));

        let mut subs = self.subscriptions.lock().unwrap();
        if let Some(old) = subs.connections.insert(mailbox_id, WsHandle { outbox: outbox_tx, task }) {
            old.task.abort();
        }
        subs.routes.insert(mailbox_id, base);
    }

    /// Signed WebSocket upgrade request for a voice channel's signaling socket, sent to
    /// the relay hosting `mailbox_id`: the group carrying the channel's traffic, whose
    /// members alone may join its voice room.
    pub fn voice_ws_request(
        &self,
        mailbox_id: &[u8; 32],
        channel_id: &[u8; 32],
    ) -> Result<tokio_tungstenite::tungstenite::http::Request<()>> {
        let auth = self
            .auth
            .as_ref()
            .ok_or_else(|| GhostError::Network("relay client has no device auth".into()))?;
        let url = format!(
            "{}/voice/{}/{}",
            ws_base(&self.base_for(mailbox_id)),
            URL_SAFE_NO_PAD.encode(mailbox_id),
            URL_SAFE_NO_PAD.encode(channel_id),
        );
        Ok(signed_ws_request(&url, auth))
    }

    pub fn unsubscribe(&mut self, mailbox_id: &[u8; 32]) {
        if let Some(handle) = self.subscriptions.lock().unwrap().connections.remove(mailbox_id) {
            handle.task.abort();
        }
    }

    /// Outbox of a mailbox's live connection, on whichever relay it was opened.
    fn outbox(&self, mailbox_id: &[u8; 32]) -> Result<mpsc::Sender<WsOutgoing>> {
        self.subscriptions
            .lock()
            .unwrap()
            .connections
            .get(mailbox_id)
            .map(|handle| handle.outbox.clone())
            .ok_or_else(|| GhostError::Network("not subscribed to mailbox".into()))
    }

    pub async fn send(&self, mailbox_id: &[u8; 32], blob: Vec<u8>) -> Result<()> {
        self.outbox(mailbox_id)?
            .send(WsOutgoing::Binary(blob))
            .await
            .map_err(|_| GhostError::Network("ws connection closed".into()))
    }

    pub async fn send_text(&self, mailbox_id: &[u8; 32], text: String) -> Result<()> {
        self.outbox(mailbox_id)?
            .send(WsOutgoing::Text(text))
            .await
            .map_err(|_| GhostError::Network("ws connection closed".into()))
    }

    /// Result of posting a blob via HTTP.
    pub async fn post_blob(&self, mailbox_id: &[u8; 32], blob: Vec<u8>) -> Result<PostBlobResult> {
        let path = format!("/box/{}", URL_SAFE_NO_PAD.encode(mailbox_id));
        let req = self
            .http
            .post(format!("{}{}", self.base_for(mailbox_id), path))
            .body(blob);
        let resp = self.authenticated("POST", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("post blob", resp).await);
        }
        #[derive(serde::Deserialize)]
        struct PostResp { seq: u64, #[serde(default)] epoch_mismatch: bool }
        let body: PostResp = resp
            .json()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        Ok(PostBlobResult { seq: body.seq, epoch_mismatch: body.epoch_mismatch })
    }

    /// Delete every relay-side record of a mailbox: log, group state, membership, server info.
    /// Creator-only on the relay (strict: the relay must hold group state naming this account).
    pub async fn delete_mailbox(&self, mailbox_id: &[u8; 32]) -> Result<()> {
        let path = format!("/box/{}", URL_SAFE_NO_PAD.encode(mailbox_id));
        let req = self.http.delete(format!("{}{}", self.base_for(mailbox_id), path));
        let resp = self.authenticated("DELETE", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("delete mailbox", resp).await);
        }
        Ok(())
    }

    pub async fn register_invite(&self, token: &str, expires_at: u64) -> Result<()> {
        let path = "/invite";
        let req = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .json(&serde_json::json!({ "token": token, "expires_at": expires_at }));
        let resp = self.authenticated("POST", path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("register invite", resp).await);
        }
        Ok(())
    }

    /// Upload (or refresh) the payload joiners fetch for an invite token. `expected_seq`
    /// must equal the relay's current sequence for the token; a stale value yields a 409
    /// `RelayStatus`, meaning another joiner refreshed the payload first.
    pub async fn put_invite_payload(&self, token: &str, expected_seq: u64, payload: Vec<u8>) -> Result<()> {
        let path = format!("/invite/{}/join", token);
        let req = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .header(INVITE_SEQ_HEADER, expected_seq.to_string())
            .body(payload);
        let resp = self.authenticated("POST", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("put invite payload", resp).await);
        }
        Ok(())
    }

    /// Fetch the current invite payload and its sequence number. `None` when the inviter
    /// has not uploaded a payload yet. Works without auth so joiners can call it.
    pub async fn get_invite_payload(&self, token: &str) -> Result<Option<(u64, Vec<u8>)>> {
        let path = format!("/invite/{}/join", token);
        let req = self
            .http
            .get(format!("{}{}", self.base_url, path));
        let resp = self.authenticated("GET", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(status_err("get invite payload", resp).await);
        }
        let seq = resp
            .headers()
            .get(INVITE_SEQ_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        Ok(Some((seq, bytes.to_vec())))
    }

    pub async fn post_accept(&self, token: &str, payload: Vec<u8>) -> Result<()> {
        let path = format!("/invite/{}/accept", token);
        let req = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .body(payload);
        let resp = self.authenticated("POST", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("post accept", resp).await);
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
            return Err(status_err("get accept", resp).await);
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
            .put(format!("{}{}", self.base_for(mailbox_id), path))
            .body(data);
        let resp = self.authenticated("PUT", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("put server_info", resp).await);
        }
        Ok(())
    }

    pub async fn get_server_info(&self, mailbox_id: &[u8; 32]) -> Result<Vec<u8>> {
        let path = format!("/box/{}/server_info", URL_SAFE_NO_PAD.encode(mailbox_id));
        let req = self
            .http
            .get(format!("{}{}", self.base_for(mailbox_id), path));
        let resp = self.authenticated("GET", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("get server_info", resp).await);
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| GhostError::Network(e.to_string()))
    }

    /// The server's private channels this account may enter, with their GroupInfo.
    pub async fn get_admitted_channels(&self, server_mailbox: &[u8; 32]) -> Result<ghost_wire::policy::AdmittedChannels> {
        let path = format!("/servers/{}/channels", URL_SAFE_NO_PAD.encode(server_mailbox));
        let req = self
            .http
            .get(format!("{}{}", self.base_for(server_mailbox), path));
        let resp = self.authenticated("GET", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("get admitted channels", resp).await);
        }
        let body = resp.bytes().await.map_err(|e| GhostError::Network(e.to_string()))?;
        ghost_wire::policy::AdmittedChannels::from_bytes(&body)
            .map_err(|e| GhostError::Format(format!("channel listing: {e}")))
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
            .put(format!("{}{}", self.base_for(mailbox_id), path))
            .body(data);
        let resp = self.authenticated("PUT", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("put avatar", resp).await);
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
            .get(format!("{}{}", self.base_for(mailbox_id), path));
        let resp = self.authenticated("GET", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(status_err("get avatar", resp).await);
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
            .delete(format!("{}{}", self.base_for(mailbox_id), path));
        let resp = self.authenticated("DELETE", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("delete avatar", resp).await);
        }
        Ok(())
    }

    /// Append a raw entry at the account's home relay; returns the home's anchor for it.
    pub async fn put_idlog_entry(
        &self,
        account_fp: &[u8; 32],
        payload: Vec<u8>,
    ) -> Result<AnchoredEntry> {
        let path = format!("/idlog/{}", hex::encode(account_fp));
        let url = format!("{}{}", self.base_url, path);
        let req = self.authenticated("PUT", &path, self.http.put(&url).body(payload));
        let resp = req
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("put idlog", resp).await);
        }
        let bytes = resp.bytes().await.map_err(|e| GhostError::Network(e.to_string()))?;
        AnchoredEntry::from_bytes(&bytes).map_err(|e| GhostError::Network(format!("anchored entry: {e}")))
    }

    /// Push home-anchored entries to a relay that mirrors the account. `invite`
    /// admits an account the relay has not seen; no credentials are needed
    /// because every entry carries its own signatures and anchor.
    pub async fn put_anchored_entries(
        &self,
        account_fp: &[u8; 32],
        entries: &[AnchoredEntry],
        invite: Option<&str>,
    ) -> Result<AccountInfo> {
        let mut url = format!("{}/idlog/{}/anchored", self.base_url, hex::encode(account_fp));
        if let Some(token) = invite {
            url.push_str("?invite=");
            url.push_str(token);
        }
        let resp = self
            .http
            .put(&url)
            .body(encode_sequence(entries))
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("put anchored idlog", resp).await);
        }
        resp.json().await.map_err(|e| GhostError::Network(e.to_string()))
    }

    /// Ask this relay to become the account's home; returns the anchors it issued
    /// for the newly sequenced entries. Needs no credentials.
    pub async fn import_account(&self, account_fp: &[u8; 32], request: &ImportRequest) -> Result<Vec<AnchoredEntry>> {
        let url = format!("{}/accounts/{}/import", self.base_url, hex::encode(account_fp));
        let resp = self
            .http
            .post(&url)
            .body(request.to_bytes())
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("import account", resp).await);
        }
        let bytes = resp.bytes().await.map_err(|e| GhostError::Network(e.to_string()))?;
        decode_sequence(&bytes).map_err(|e| GhostError::Network(format!("import anchors: {e}")))
    }

    /// Tell the home which relays may pull this account's identity log (replaces the set).
    pub async fn put_mirror_grants(&self, account_fp: &[u8; 32], relays: &[[u8; 32]]) -> Result<()> {
        let path = format!("/accounts/{}/mirrors", hex::encode(account_fp));
        let req = self.http.put(format!("{}{}", self.base_url, path)).body(relays.concat());
        let resp = self.authenticated("PUT", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("put mirror grants", resp).await);
        }
        Ok(())
    }

    /// Publish where a server this account created now lives (at the account's home).
    pub async fn put_server_location(&self, account_fp: &[u8; 32], location: &ServerLocation) -> Result<()> {
        let path = format!("/accounts/{}/servers/{}/location", hex::encode(account_fp), hex::encode(location.server_id));
        let req = self.http.put(format!("{}{}", self.base_url, path)).body(location.to_bytes());
        let resp = self.authenticated("PUT", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("put server location", resp).await);
        }
        Ok(())
    }

    /// Where the creator `account_fp` says its server lives; `None` if it never moved it.
    pub async fn get_server_location(&self, account_fp: &[u8; 32], server_id: &[u8; 32]) -> Result<Option<ServerLocation>> {
        let url = format!(
            "{}/accounts/{}/servers/{}/location",
            self.base_url,
            hex::encode(account_fp),
            hex::encode(server_id)
        );
        let resp = self.http.get(url).send().await.map_err(|e| GhostError::Network(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(status_err("get server location", resp).await);
        }
        let bytes = resp.bytes().await.map_err(|e| GhostError::Network(e.to_string()))?;
        ServerLocation::from_bytes(&bytes)
            .map(Some)
            .map_err(|e| GhostError::Network(e.to_string()))
    }

    /// Where this relay believes the account is homed.
    pub async fn get_account(&self, account_fp: &[u8; 32]) -> Result<AccountInfo> {
        let path = format!("/accounts/{}", hex::encode(account_fp));
        let req = self.http.get(format!("{}{}", self.base_url, path));
        let resp = self
            .authenticated("GET", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("get account", resp).await);
        }
        resp.json().await.map_err(|e| GhostError::Network(e.to_string()))
    }

    /// Fetch an account's anchored identity log.
    pub async fn get_idlog(
        &self,
        account_fp: &[u8; 32],
        after_seq: u64,
    ) -> Result<AnchoredLog> {
        let path = format!("/idlog/{}", hex::encode(account_fp));
        let mut url = format!("{}{}", self.base_url, path);
        if after_seq > 0 {
            url.push_str(&format!("?after_seq={after_seq}"));
        }
        let req = self.http.get(&url);
        let resp = self
            .authenticated("GET", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("get idlog", resp).await);
        }
        let body: IdLogResponseJson = resp
            .json()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;

        let b64 = &base64::engine::general_purpose::STANDARD;
        let home_relay_vk = decode_hex_32(&body.home_relay_vk)?;
        let entries = body
            .entries
            .into_iter()
            .map(|e| {
                let bytes = b64
                    .decode(&e.anchored)
                    .map_err(|e| GhostError::Network(format!("base64: {e}")))?;
                AnchoredEntry::from_bytes(&bytes)
                    .map_err(|e| GhostError::Network(format!("anchored entry: {e}")))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(AnchoredLog { home_relay_vk, entries })
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
            return Err(status_err("get consistency proof", resp).await);
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| GhostError::Network(e.to_string()))
    }

    /// Open a pairing session (existing device). Replaces any earlier session for the account.
    pub async fn post_pairing_offer(&self, account_fp: &[u8; 32], token: &PairingToken, sealed_offer: Vec<u8>) -> Result<()> {
        let path = format!("/pair/{}", hex::encode(account_fp));
        let mut body = Vec::with_capacity(token.len() + sealed_offer.len());
        body.extend_from_slice(token);
        body.extend_from_slice(&sealed_offer);
        let req = self.http.post(format!("{}{}", self.base_url, path)).body(body);
        let resp = self.authenticated("POST", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("post pairing offer", resp).await);
        }
        Ok(())
    }

    fn pairing_path(account_fp: &[u8; 32], token: &PairingToken, suffix: &str) -> String {
        format!("/pair/{}/{}{suffix}", hex::encode(account_fp), hex::encode(token))
    }

    /// Answer a pairing offer (new device, unauthenticated). Only the first answer counts.
    pub async fn post_pairing_response(&self, account_fp: &[u8; 32], token: &PairingToken, sealed: Vec<u8>) -> Result<()> {
        let path = Self::pairing_path(account_fp, token, "/respond");
        let resp = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .body(sealed)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("post pairing response", resp).await);
        }
        Ok(())
    }

    /// Poll for the new device's answer (existing device). `None` until it arrives.
    pub async fn get_pairing_response(&self, account_fp: &[u8; 32], token: &PairingToken) -> Result<Option<Vec<u8>>> {
        let path = Self::pairing_path(account_fp, token, "/response");
        let req = self.http.get(format!("{}{}", self.base_url, path));
        let resp = self.authenticated("GET", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(status_err("get pairing response", resp).await);
        }
        resp.bytes()
            .await
            .map(|b| Some(b.to_vec()))
            .map_err(|e| GhostError::Network(e.to_string()))
    }

    /// Fetch the sealed pairing offer (new device, unauthenticated).
    pub async fn get_pairing_offer(&self, account_fp: &[u8; 32], token: &PairingToken) -> Result<Vec<u8>> {
        let path = Self::pairing_path(account_fp, token, "");
        let resp = self
            .http
            .get(format!("{}{}", self.base_url, path))
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("get pairing offer", resp).await);
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| GhostError::Network(e.to_string()))
    }

    /// Upload the sealed provision blob for a new device (existing device, authenticated).
    pub async fn put_provision(&self, account_fp: &[u8; 32], token: &PairingToken, sealed: Vec<u8>) -> Result<()> {
        let path = Self::pairing_path(account_fp, token, "/provision");
        let req = self.http.put(format!("{}{}", self.base_url, path)).body(sealed);
        let resp = self.authenticated("PUT", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("put provision", resp).await);
        }
        Ok(())
    }

    /// Fetch the sealed provision blob (new device, unauthenticated). `None` until uploaded.
    pub async fn get_provision(&self, account_fp: &[u8; 32], token: &PairingToken) -> Result<Option<Vec<u8>>> {
        let path = Self::pairing_path(account_fp, token, "/provision");
        let resp = self
            .http
            .get(format!("{}{}", self.base_url, path))
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(status_err("get provision", resp).await);
        }
        resp.bytes()
            .await
            .map(|b| Some(b.to_vec()))
            .map_err(|e| GhostError::Network(e.to_string()))
    }

    /// Store the account's recovery bundle. 409 means the relay holds an equal
    /// or newer generation.
    pub async fn put_recovery_bundle(&self, account_fp: &[u8; 32], bundle: &RecoveryBundle) -> Result<()> {
        let path = format!("/recovery/{}", hex::encode(account_fp));
        let req = self
            .http
            .put(format!("{}{}", self.base_url, path))
            .body(bundle.to_bytes());
        let resp = self.authenticated("PUT", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("put recovery", resp).await);
        }
        Ok(())
    }

    /// Store a sealed sync snapshot. 409 means the relay holds an equal or newer generation.
    pub async fn put_sync_state(
        &self,
        account_fp: &[u8; 32],
        generation: u64,
        sealed: Vec<u8>,
    ) -> Result<()> {
        let path = format!("/sync_state/{}", hex::encode(account_fp));
        let mut body = Vec::with_capacity(SNAPSHOT_GENERATION_LEN + sealed.len());
        body.extend_from_slice(&generation.to_be_bytes());
        body.extend_from_slice(&sealed);
        let req = self
            .http
            .put(format!("{}{}", self.base_url, path))
            .body(body);
        let resp = self.authenticated("PUT", &path, req)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(status_err("put sync_state", resp).await);
        }
        Ok(())
    }

    /// Fetch the sealed sync snapshot and its generation.
    pub async fn get_sync_state(
        &self,
        account_fp: &[u8; 32],
    ) -> Result<Option<(u64, Vec<u8>)>> {
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
            return Err(status_err("get sync_state", resp).await);
        }
        let body = resp.bytes().await.map_err(|e| GhostError::Network(e.to_string()))?;
        if body.len() < SNAPSHOT_GENERATION_LEN {
            return Err(GhostError::Network("sync_state response missing generation".into()));
        }
        let generation = u64::from_be_bytes(body[..SNAPSHOT_GENERATION_LEN].try_into().unwrap());
        Ok(Some((generation, body[SNAPSHOT_GENERATION_LEN..].to_vec())))
    }

    /// Fetch the account's recovery bundle. Unauthenticated and rate-limited by the relay.
    pub async fn get_recovery_bundle(
        &self,
        account_fp: &[u8; 32],
    ) -> Result<Option<RecoveryBundle>> {
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
            return Err(status_err("get recovery", resp).await);
        }
        let body = resp.bytes().await.map_err(|e| GhostError::Network(e.to_string()))?;
        RecoveryBundle::from_bytes(&body)
            .map(Some)
            .map_err(|e| GhostError::Network(e.to_string()))
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
            let req = signed_ws_request(&url, auth);
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
                            } else if s == ghost_wire::WS_SIGNAL_CHANNELS {
                                let _ = event_tx.send(RelayEvent::ChannelsChanged { mailbox_id }).await;
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
                            } else if let Some(ack) = parse_ack(s, mailbox_id) {
                                let _ = event_tx.send(RelayEvent::Ack(ack)).await;
                            }
                        }
                        Some(Ok(Message::Close(frame))) => {
                            // Removed from the group or revoked: the relay will not serve
                            // this device again, so reconnecting is pointless.
                            let code = frame.as_ref().map(|f| u16::from(f.code));
                            if matches!(code, Some(ghost_wire::WS_CLOSE_REMOVED | ghost_wire::WS_CLOSE_DEVICE_REVOKED)) {
                                let _ = event_tx.send(RelayEvent::ConnectionState { mailbox_id, connected: false }).await;
                                return;
                            }
                            break;
                        }
                        None => break,
                        _ => {}
                    }
                }
            }
        }

        let _ = event_tx.send(RelayEvent::ConnectionState { mailbox_id, connected: false }).await;
    }
}

/// WebSocket upgrade request for `url` carrying Ghost's signed device-auth headers.
fn signed_ws_request(url: &str, auth: &AuthContext) -> tokio_tungstenite::tungstenite::http::Request<()> {
    let ws_path = url
        .find("//")
        .and_then(|i| url[i + 2..].find('/').map(|j| &url[i + 2 + j..]))
        .unwrap_or("/");
    let h = auth.sign_for("GET", ws_path);
    tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(url)
        .header("Host", url_host(url))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", tokio_tungstenite::tungstenite::handshake::client::generate_key())
        .header("X-Ghost-Account", &h.account)
        .header("X-Ghost-Device", &h.device)
        .header("X-Ghost-Timestamp", &h.timestamp)
        .header("X-Ghost-Signature", &h.signature)
        .body(())
        .expect("well-formed upgrade request")
}

fn parse_ack(text: &str, mailbox_id: [u8; 32]) -> Option<Ack> {
    let mut parts = text.splitn(2, ' ');
    let seq: u64 = parts.next()?.parse().ok()?;
    let epoch_mismatch = parts.next() == Some(WS_SIGNAL_EPOCH_MISMATCH);
    Some(Ack { mailbox_id, seq, epoch_mismatch })
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
