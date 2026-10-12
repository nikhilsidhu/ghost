use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

use ghost_wire::account_key::{decode_key_sets, encode_key_sets, AccountKeySet};
use ghost_wire::anchor::{decode_sequence, encode_sequence, AnchoredEntry, ImportRequest};
use ghost_wire::batch::LogBatch;
use ghost_wire::merkle::Checkpoint;
use ghost_wire::relay_ref::RelayRef;
use ghost_wire::server_location::ServerLocation;
use ghost_wire::short_id;
use ghost_wire::{
    SNAPSHOT_GENERATION_LEN, WS_ERROR_PREFIX, WS_FRAME_HEADER_SIZE, WS_SEQ_SIZE, WS_SIGNAL_GAP,
};
use serde::Deserialize;

use crate::error::{GhostError, Result};

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Silence on a mailbox connection past which it is taken for dead: three relay ping
/// intervals, since the relay pings every 15 seconds.
const WS_SILENCE_LIMIT: Duration = Duration::from_secs(45);
/// Messages a mailbox connection holds while its relay is unreachable; they go out on
/// reconnect. Past this many a send is refused rather than waited on, since a sender may
/// be the session loop, which must not stall.
const OUTBOX_CAPACITY: usize = 1024;
/// How long a connection being closed has to send what it holds and its close frame
/// before it is cut off.
const CLOSE_WAIT: Duration = Duration::from_secs(2);

/// Typed error for a non-success response, keeping the relay's explanation.
async fn status_err(context: &str, resp: reqwest::Response) -> GhostError {
    let refusal = resp.headers().get(ghost_wire::REFUSAL_HEADER).and_then(|v| v.to_str().ok());
    if refusal == Some(ghost_wire::REFUSAL_REMOVED) {
        return GhostError::RemovedFromServer;
    }
    if refusal == Some(ghost_wire::REFUSAL_DEVICE_REVOKED) {
        return GhostError::DeviceRevoked(revocation_cause(resp.headers()));
    }
    if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let wait = resp.headers().get(reqwest::header::RETRY_AFTER).and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok());
        return GhostError::RateLimited(wait.map(Duration::from_secs));
    }
    let status = resp.status().as_u16();
    let message = resp.text().await.unwrap_or_default();
    GhostError::RelayStatus { status, context: context.to_string(), message }
}

/// Why a mailbox connection would not take a message.
fn outbox_refused<T>(e: mpsc::error::TrySendError<T>) -> GhostError {
    match e {
        mpsc::error::TrySendError::Full(_) => GhostError::Network("relay unreachable: too many messages waiting to be sent".into()),
        mpsc::error::TrySendError::Closed(_) => GhostError::Network("ws connection closed".into()),
    }
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
    /// The relay that served this.
    pub relay_vk: [u8; 32],
    /// The serving relay's current KT head, which vouches for the entries when the
    /// serving relay is the home.
    pub kt_head: Option<Checkpoint>,
    pub entries: Vec<AnchoredEntry>,
}

#[derive(serde::Deserialize)]
struct IdLogResponseJson {
    home_relay_vk: String,
    relay_vk: String,
    kt_head: Option<String>,
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

/// The account a root key belongs to, as a relay that holds it reports.
#[derive(Debug, serde::Deserialize)]
pub struct RootLookup {
    #[serde(deserialize_with = "hex_32")]
    pub account_fp: [u8; 32],
    #[serde(deserialize_with = "hex_32")]
    pub home_relay_vk: [u8; 32],
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
    let bytes = hex::decode(text.trim()).map_err(|e| GhostError::Format(format!("hex: {e}")))?;
    bytes.try_into().map_err(|_| GhostError::Network("expected 32 bytes".into()))
}

/// A KT checkpoint as relays send it: standard base64.
fn decode_checkpoint(encoded: &str) -> Result<Checkpoint> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| GhostError::Format(format!("kt head base64: {e}")))?;
    Checkpoint::from_bytes(&bytes).map_err(|e| GhostError::Format(format!("kt head: {e}")))
}

pub struct IncomingBlob {
    pub mailbox_id: [u8; 32],
    /// Which relay delivered it; a mailbox open on several is numbered by each.
    pub relay_url: String,
    pub seq: u64,
    pub received_at: u64,
    pub payload: Vec<u8>,
}

/// The relay took a blob this device posted over the mailbox's connection.
pub struct Ack {
    pub mailbox_id: [u8; 32],
    pub seq: u64,
    /// The chat message the blob carried, when it was sent as one.
    pub message_id: Option<[u8; 32]>,
}

pub struct PostBlobResult {
    pub seq: u64,
}

/// How a chat message handed to a connection fared, for whoever waits on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// The relay stored it under `seq`.
    Delivered { seq: u64 },
    /// The relay refused it; `status` is the HTTP status it would have answered with.
    Refused { status: u16, message: String },
    /// The connection ended before the relay answered; the message may or may not have
    /// landed, and goes out again on reconnect.
    Lost,
}

/// A chat message riding on a posted blob: which one, and who waits for the answer.
pub struct Tracking {
    pub message_id: [u8; 32],
    pub reply: oneshot::Sender<SendOutcome>,
}

pub enum RelayEvent {
    Blob(IncomingBlob),
    Ack(Ack),
    /// The relay refused a posted blob; `message_id` names the chat message it carried.
    Error { mailbox_id: [u8; 32], status: u16, message: String, message_id: Option<[u8; 32]> },
    /// The connection ended with a chat message posted but unanswered.
    SendLost { mailbox_id: [u8; 32], message_id: [u8; 32] },
    /// The relay at `relay_url` no longer keeps entries this device had not read: it
    /// resumes after `head`, skipping everything up to it.
    Gap { mailbox_id: [u8; 32], relay_url: String, head: u64 },
    VoiceState { mailbox_id: [u8; 32], json: String },
    Presence { mailbox_id: [u8; 32], json: String },
    /// A mailbox connection came up or went down, on the relay at `relay_url`.
    ConnectionState { mailbox_id: [u8; 32], relay_url: String, connected: bool },
    /// A connection that came up delivered everything the mailbox held for this device;
    /// the blobs before this event are the catch-up, those after it live.
    CaughtUp { mailbox_id: [u8; 32], relay_url: String },
    /// A private channel of the server at this mailbox newly admits this account.
    ChannelsChanged { mailbox_id: [u8; 32] },
    /// The relay refused this device because the account's log revokes it, saying what
    /// revoked it when it could; the mailbox's connection has stopped for good.
    DeviceRevoked { mailbox_id: [u8; 32], relay_url: String, cause: Option<ghost_wire::RevocationCause> },
    /// The relay at `relay_url` does not know this device (the account may have moved
    /// home, or the relay's copy of its log lacks the device). Reported once per run of
    /// refusals; the connection keeps retrying.
    Unauthorized { mailbox_id: [u8; 32], relay_url: String },
    /// The relay at `relay_url` knows this device but does not admit it to the mailbox
    /// (not a member, or the mailbox is not there). Reported once per run of refusals;
    /// the connection keeps retrying.
    Refused { mailbox_id: [u8; 32], relay_url: String },
    /// The relay closed the mailbox for good because the account was removed from its
    /// group, after delivering what it could still read.
    Removed { mailbox_id: [u8; 32], relay_url: String },
}

pub enum WsOutgoing {
    /// A blob for the mailbox's log, tracked when it carries a chat message.
    Binary { data: Vec<u8>, tracking: Option<Tracking> },
    Text(String),
}

struct WsHandle {
    outbox: mpsc::Sender<WsOutgoing>,
    task: JoinHandle<()>,
}

impl WsHandle {
    /// End the connection on purpose: with its outbox gone, the task sends what was
    /// queued and a close frame, so the relay withdraws this device's presence at once.
    /// A task not connected (backing off, or waiting to connect) is cut off after
    /// `CLOSE_WAIT`. Returns the task, for a caller that waits for it to end.
    fn close(self) -> Arc<JoinHandle<()>> {
        let task = Arc::new(self.task);
        drop(self.outbox);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let lingering = task.clone();
            runtime.spawn(async move {
                tokio::time::sleep(CLOSE_WAIT).await;
                lingering.abort();
            });
        } else {
            task.abort();
        }
        task
    }
}

/// Auth context for request signing. Shared with WS tasks via Arc.
#[derive(Clone)]
pub struct AuthContext {
    pub account_fp: [u8; 32],
    pub device_vk: [u8; 32],
    signing_key: SigningKey,
}

impl AuthContext {
    /// Headers signing a request made now, over `body` as it will be sent.
    fn sign_for(&self, method: &str, path: &str, body: &[u8]) -> ghost_wire::auth::AuthHeaders {
        ghost_wire::auth::sign_request_headers(method, path, body, &self.account_fp, &self.device_vk, &self.signing_key)
    }
}

/// Live mailbox connections and where each mailbox lives, shared by a client and
/// every view it opens onto another relay, so one event stream and one set of
/// subscriptions cover all relays the account uses. A mailbox may be open on several
/// relays at once (the sync mailbox is); a send then goes to each.
struct Subscriptions {
    connections: HashMap<(String, [u8; 32]), WsHandle>,
    /// Relay base URL for each subscribed mailbox and each id added with `add_route`.
    routes: HashMap<[u8; 32], String>,
    /// Where connections report. `restart` replaces it, which ends the stream a loop was
    /// reading once the closed connections' last reports are drained.
    events: mpsc::Sender<RelayEvent>,
    /// Each mailbox whose connection came up, for whoever else announces on it (a call's
    /// voice presence). Kept across `restart`.
    connected: broadcast::Sender<[u8; 32]>,
    /// Silence past which a connection is reopened.
    silence_limit: Duration,
}

/// Mailbox connections coming up that a slow listener may fall behind on.
const CONNECTED_CAPACITY: usize = 64;

impl Subscriptions {
    fn new(events: mpsc::Sender<RelayEvent>) -> Self {
        let (connected, _) = broadcast::channel(CONNECTED_CAPACITY);
        Self { connections: HashMap::new(), routes: HashMap::new(), events, connected, silence_limit: WS_SILENCE_LIMIT }
    }
}

impl Drop for Subscriptions {
    fn drop(&mut self) {
        for (_, handle) in self.connections.drain() {
            handle.close();
        }
    }
}

/// How many relay events may wait for the loop reading them.
const EVENT_CAPACITY: usize = 256;

/// This device's door to a relay. Views onto other relays (`at`) share its connections,
/// routes and event stream. Shared as `Arc<RelayClient>` without a lock: nothing here
/// needs exclusive access, and what can change under it, the home client's base URL when
/// the account's home moves and the device credentials when its identity does, is read
/// fresh for each request.
pub struct RelayClient {
    base_url: std::sync::RwLock<String>,
    http: reqwest::Client,
    subscriptions: Arc<std::sync::Mutex<Subscriptions>>,
    auth: std::sync::RwLock<Option<Arc<AuthContext>>>,
}

fn ws_base(base_url: &str) -> String {
    base_url.replace("http://", "ws://").replace("https://", "wss://")
}

impl RelayClient {
    pub fn new(base_url: &str) -> (Self, mpsc::Receiver<RelayEvent>) {
        let base = base_url.trim_end_matches('/').to_string();
        let (events, inbox) = mpsc::channel(EVENT_CAPACITY);
        let client = Self {
            base_url: std::sync::RwLock::new(base),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .connect_timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
            subscriptions: Arc::new(std::sync::Mutex::new(Subscriptions::new(events))),
            auth: std::sync::RwLock::new(None),
        };
        (client, inbox)
    }

    /// Close every connection, forget every route and start a new event stream, whose
    /// receiver this returns. The stream a loop was reading ends once the closed
    /// connections' last reports are drained, so that loop returns on its own; the next
    /// one runs on the new receiver and subscribes afresh.
    pub fn restart(&self) -> mpsc::Receiver<RelayEvent> {
        self.replace_connections(WsHandle::close)
    }

    /// `restart`, but every connection simply drops, without a close frame, as when the
    /// network goes: relays keep this device present for their grace period. For tools
    /// and tests that play a lost connection.
    pub fn restart_cut_off(&self) -> mpsc::Receiver<RelayEvent> {
        self.replace_connections(|handle| handle.task.abort())
    }

    fn replace_connections<T>(&self, end: impl Fn(WsHandle) -> T) -> mpsc::Receiver<RelayEvent> {
        let (events, inbox) = mpsc::channel(EVENT_CAPACITY);
        let mut subs = self.subscriptions.lock().unwrap();
        for (_, handle) in subs.connections.drain() {
            end(handle);
        }
        subs.routes.clear();
        subs.events = events;
        inbox
    }

    /// Close every connection, as on quitting, and wait up to `wait` for their close
    /// frames to go out.
    pub async fn close_all(&self, wait: Duration) {
        let tasks: Vec<Arc<JoinHandle<()>>> = {
            let mut subs = self.subscriptions.lock().unwrap();
            subs.connections.drain().map(|(_, handle)| handle.close()).collect()
        };
        let all_ended = async {
            for task in tasks {
                while !task.is_finished() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        };
        let _ = tokio::time::timeout(wait, all_ended).await;
    }

    /// A client for another relay that signs as the same device and shares this
    /// client's subscriptions and event stream. Mailboxes subscribed through it
    /// stay connected after it is dropped and are reachable from every view.
    pub fn at(&self, base_url: &str) -> RelayClient {
        let base = base_url.trim_end_matches('/').to_string();
        RelayClient {
            base_url: std::sync::RwLock::new(base),
            http: self.http.clone(),
            subscriptions: self.subscriptions.clone(),
            auth: std::sync::RwLock::new(self.auth()),
        }
    }

    /// Each mailbox whose connection comes up from now on, on any relay.
    pub fn connections(&self) -> broadcast::Receiver<[u8; 32]> {
        self.subscriptions.lock().unwrap().connected.subscribe()
    }

    /// How long a mailbox connection may stay silent before it is reopened; the relay's
    /// pings keep a live one from ever reaching it. For tests against a relay that never pings.
    pub fn set_ws_silence_limit(&self, limit: Duration) {
        self.subscriptions.lock().unwrap().silence_limit = limit;
    }

    /// Route mailbox-scoped requests for `id` (a mailbox or voice channel) to this view's relay.
    pub fn add_route(&self, id: [u8; 32]) {
        self.subscriptions.lock().unwrap().routes.insert(id, self.base_url());
    }

    /// Base URL of the relay `id` lives on: its recorded route, else this view's relay.
    fn base_for(&self, id: &[u8; 32]) -> String {
        self.subscriptions
            .lock()
            .unwrap()
            .routes
            .get(id)
            .cloned()
            .unwrap_or_else(|| self.base_url())
    }

    pub fn base_url(&self) -> String {
        self.base_url.read().unwrap().clone()
    }

    /// Point account-level requests and mailboxes opened from now on at another relay,
    /// as when the account's home moves. Mailboxes already routed keep their relay.
    pub fn set_base_url(&self, base_url: &str) {
        *self.base_url.write().unwrap() = base_url.trim_end_matches('/').to_string();
    }

    /// Move a mailbox's connections to this view's relay alone, resuming after
    /// `last_seen_seq` there: its route and connections elsewhere go first.
    pub fn resubscribe_here(&self, mailbox_id: [u8; 32], last_seen_seq: u64) {
        self.unsubscribe(&mailbox_id);
        self.subscribe(mailbox_id, last_seen_seq);
    }

    /// The device credentials requests are signed with, once the identity is loaded.
    pub fn set_auth(&self, account_fp: [u8; 32], device_vk: [u8; 32], signing_key: SigningKey) {
        *self.auth.write().unwrap() = Some(Arc::new(AuthContext { account_fp, device_vk, signing_key }));
    }

    /// Sign as the same device as `other`, for talking to another relay.
    pub fn copy_auth_from(&self, other: &RelayClient) {
        *self.auth.write().unwrap() = other.auth();
    }

    fn auth(&self) -> Option<Arc<AuthContext>> {
        self.auth.read().unwrap().clone()
    }

    /// A request to the relay at `base`: `method` and `path` are what a device signature
    /// covers, `query` goes on the URL unsigned, and `body` is sent as given.
    fn start(&self, base: &str, method: reqwest::Method, path: &str, query: Option<&str>, body: Body, signing: Signing) -> reqwest::RequestBuilder {
        let url = match query {
            Some(query) => format!("{base}{path}?{query}"),
            None => format!("{base}{path}"),
        };
        let mut req = self.http.request(method.clone(), url);
        if signing == Signing::Device {
            req = self.authenticated(method.as_str(), path, body.bytes(), req);
        }
        match body {
            Body::None => req,
            Body::Bytes(bytes) => req.body(bytes),
            Body::Json(bytes) => req.header(reqwest::header::CONTENT_TYPE, "application/json").body(bytes),
        }
    }

    /// The relay's answer: any status but success is a `RelayStatus` error naming
    /// `context`, except those in `expected`, which the caller reads for itself.
    async fn finish(req: reqwest::RequestBuilder, context: &str, expected: &[reqwest::StatusCode]) -> Result<reqwest::Response> {
        let resp = req.send().await.map_err(|e| GhostError::Network(e.to_string()))?;
        if resp.status().is_success() || expected.contains(&resp.status()) {
            Ok(resp)
        } else {
            Err(status_err(context, resp).await)
        }
    }

    /// Fetch the relay's identity, reachability hints and KT head.
    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
    pub async fn get_relay_info(&self) -> Result<RelayInfo> {
        let req = self.start(&self.base_url(), reqwest::Method::GET, "/relay", None, Body::None, Signing::Anonymous);
        let body: RelayInfoJson = body_json(Self::finish(req, "get relay info", &[]).await?).await?;
        let relay_vk = decode_hex_32(&body.relay_vk)?;
        let mut relay_ref = RelayRef::decode(&body.r#ref)
            .map_err(|e| GhostError::Format(format!("relay ref: {e}")))?;
        if relay_ref.relay_vk != relay_vk {
            return Err(GhostError::Format("relay ref names a different relay".into()));
        }
        // A relay without a configured public URL is still reachable where we dialed it.
        if relay_ref.primary_https_url().is_none() {
            relay_ref = RelayRef::https(relay_vk, &self.base_url());
        }
        let kt_head = match body.kt_head {
            Some(b64) => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&b64)
                    .map_err(|e| GhostError::Format(format!("base64: {e}")))?;
                Some(Checkpoint::from_bytes(&bytes).map_err(|e| GhostError::Format(format!("kt head: {e}")))?)
            }
            None => None,
        };
        Ok(RelayInfo { relay_vk, protocol: body.protocol, relay_ref, kt_head })
    }

    /// Apply auth headers to a request builder if auth is configured. `body` is what the
    /// request will carry; the signature covers it, so it goes on the builder afterwards.
    fn authenticated(&self, method: &str, path: &str, body: &[u8], req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.auth.read().unwrap().as_ref() {
            Some(auth) => {
                let h = auth.sign_for(method, path, body);
                req.header("X-Ghost-Account", &h.account)
                    .header("X-Ghost-Device", &h.device)
                    .header("X-Ghost-Timestamp", &h.timestamp)
                    .header("X-Ghost-Nonce", &h.nonce)
                    .header("X-Ghost-Signature", &h.signature)
            }
            None => req,
        }
    }

    /// Subscribe to a mailbox. The connection is established in the background
    /// with automatic reconnection on failure. A mailbox already routed to a relay
    /// reconnects there, from whichever view this is called on; a new mailbox is
    /// opened on this view's relay and routed to it.
    pub fn subscribe(&self, mailbox_id: [u8; 32], last_seen_seq: u64) {
        let base = self.base_for(&mailbox_id);
        self.open_connection(&base, mailbox_id, last_seen_seq);
        self.subscriptions.lock().unwrap().routes.insert(mailbox_id, base);
    }

    /// Open the mailbox on this view's relay as well, without changing where requests
    /// for it are routed: for a mailbox that lives on several relays.
    pub fn subscribe_here_too(&self, mailbox_id: [u8; 32], last_seen_seq: u64) {
        let base = self.base_url();
        self.open_connection(&base, mailbox_id, last_seen_seq);
    }

    fn open_connection(&self, base: &str, mailbox_id: [u8; 32], last_seen_seq: u64) {
        let url = format!("{}/ws/{}", ws_base(base), URL_SAFE_NO_PAD.encode(mailbox_id));
        let (outbox_tx, outbox_rx) = mpsc::channel(OUTBOX_CAPACITY);
        let auth = self.auth();
        let mut subs = self.subscriptions.lock().unwrap();
        let setup = ConnectionSetup {
            url,
            relay_url: base.to_string(),
            mailbox_id,
            last_seen: last_seen_seq,
            auth,
            silence_limit: subs.silence_limit,
            events: subs.events.clone(),
            connected: subs.connected.clone(),
        };
        let task = tokio::spawn(ws_task(setup, outbox_rx));
        if let Some(old) = subs.connections.insert((base.to_string(), mailbox_id), WsHandle { outbox: outbox_tx, task }) {
            old.close();
        }
    }

    /// Signed WebSocket upgrade request for a voice channel's signaling socket, sent to
    /// the relay hosting `mailbox_id`: the group carrying the channel's traffic, whose
    /// members alone may join its voice room.
    pub fn voice_ws_request(
        &self,
        mailbox_id: &[u8; 32],
        channel_id: &[u8; 32],
    ) -> Result<tokio_tungstenite::tungstenite::http::Request<()>> {
        let auth = self.auth().ok_or_else(|| GhostError::Network("relay client has no device auth".into()))?;
        let url = format!(
            "{}/voice/{}/{}",
            ws_base(&self.base_for(mailbox_id)),
            URL_SAFE_NO_PAD.encode(mailbox_id),
            URL_SAFE_NO_PAD.encode(channel_id),
        );
        Ok(signed_ws_request(&url, &auth))
    }

    /// Whether the mailbox is open on the relay at `base_url`.
    pub fn is_subscribed_at(&self, base_url: &str, mailbox_id: &[u8; 32]) -> bool {
        let key = (base_url.trim_end_matches('/').to_string(), *mailbox_id);
        self.subscriptions.lock().unwrap().connections.contains_key(&key)
    }

    /// Close the mailbox's connections on every relay and forget where it lives, so a
    /// later `subscribe` opens it on the view it is called on.
    pub fn unsubscribe(&self, mailbox_id: &[u8; 32]) {
        let mut subs = self.subscriptions.lock().unwrap();
        let keys: Vec<(String, [u8; 32])> = subs.connections.keys().filter(|(_, m)| m == mailbox_id).cloned().collect();
        for key in keys {
            if let Some(handle) = subs.connections.remove(&key) {
                handle.close();
            }
        }
        subs.routes.remove(mailbox_id);
    }

    /// Outboxes of a mailbox's live connections, one per relay it is open on.
    fn outboxes(&self, mailbox_id: &[u8; 32]) -> Result<Vec<mpsc::Sender<WsOutgoing>>> {
        let outboxes: Vec<_> = self
            .subscriptions
            .lock()
            .unwrap()
            .connections
            .iter()
            .filter(|((_, m), _)| m == mailbox_id)
            .map(|(_, handle)| handle.outbox.clone())
            .collect();
        if outboxes.is_empty() {
            return Err(GhostError::Network("not subscribed to mailbox".into()));
        }
        Ok(outboxes)
    }

    /// Queue a blob on each of the mailbox's connections without waiting: it goes out
    /// now, or on reconnect while that relay is unreachable. Fails only if no connection
    /// took it.
    pub fn send(&self, mailbox_id: &[u8; 32], blob: Vec<u8>) -> Result<()> {
        self.send_outgoing(mailbox_id, |blob| WsOutgoing::Binary { data: blob.to_vec(), tracking: None }, &blob)
    }

    /// Queue a chat message's blob on the mailbox's connection and get the relay's
    /// answer back when it comes. The answer also reaches the event loop, which records
    /// it; a caller may drop the receiver.
    pub fn send_message(&self, mailbox_id: &[u8; 32], blob: Vec<u8>, message_id: [u8; 32]) -> Result<oneshot::Receiver<SendOutcome>> {
        let outbox = self.outboxes(mailbox_id)?.into_iter().next().ok_or_else(|| GhostError::Network("not subscribed to mailbox".into()))?;
        let (reply, outcome) = oneshot::channel();
        outbox
            .try_send(WsOutgoing::Binary { data: blob, tracking: Some(Tracking { message_id, reply }) })
            .map_err(outbox_refused)?;
        Ok(outcome)
    }

    pub fn send_text(&self, mailbox_id: &[u8; 32], text: String) -> Result<()> {
        self.send_outgoing(mailbox_id, |text| WsOutgoing::Text(String::from_utf8_lossy(text).into_owned()), text.as_bytes())
    }

    fn send_outgoing(&self, mailbox_id: &[u8; 32], make: impl Fn(&[u8]) -> WsOutgoing, data: &[u8]) -> Result<()> {
        let mut last_refusal = None;
        let mut taken = false;
        for outbox in self.outboxes(mailbox_id)? {
            match outbox.try_send(make(data)) {
                Ok(()) => taken = true,
                Err(e) => last_refusal = Some(outbox_refused(e)),
            }
        }
        match (taken, last_refusal) {
            (true, _) => Ok(()),
            (false, Some(e)) => Err(e),
            (false, None) => Err(GhostError::Network("not subscribed to mailbox".into())),
        }
    }

    /// Result of posting a blob via HTTP.
    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
    pub async fn post_blob(&self, mailbox_id: &[u8; 32], blob: Vec<u8>) -> Result<PostBlobResult> {
        self.post_blob_at(&self.base_for(mailbox_id), mailbox_id, blob).await
    }

    /// Post a blob to this client's relay, wherever the mailbox is routed: for a mailbox
    /// open on several relays, as the sync mailbox is.
    pub async fn post_blob_here(&self, mailbox_id: &[u8; 32], blob: Vec<u8>) -> Result<PostBlobResult> {
        self.post_blob_at(&self.base_url(), mailbox_id, blob).await
    }

    async fn post_blob_at(&self, base: &str, mailbox_id: &[u8; 32], blob: Vec<u8>) -> Result<PostBlobResult> {
        let path = format!("/box/{}", URL_SAFE_NO_PAD.encode(mailbox_id));
        let req = self.start(base, reqwest::Method::POST, &path, None, Body::Bytes(blob), Signing::Device);
        #[derive(serde::Deserialize)]
        struct PostResp {
            seq: u64,
        }
        let body: PostResp = body_json(Self::finish(req, "post blob", &[]).await?).await?;
        Ok(PostBlobResult { seq: body.seq })
    }

    /// Delete every relay-side record of a mailbox: log, group state, membership, server info.
    /// Creator-only on the relay (strict: the relay must hold group state naming this account).
    pub async fn delete_mailbox(&self, mailbox_id: &[u8; 32]) -> Result<()> {
        let path = format!("/box/{}", URL_SAFE_NO_PAD.encode(mailbox_id));
        let req = self.start(&self.base_for(mailbox_id), reqwest::Method::DELETE, &path, None, Body::None, Signing::Device);
        Self::finish(req, "delete mailbox", &[]).await.map(drop)
    }

    /// Open an invite into the server whose mailbox is `mailbox`.
    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
    pub async fn register_invite(&self, token: &str, mailbox: &[u8; 32], expires_at: Option<u64>) -> Result<u64> {
        let body = serde_json::to_vec(&serde_json::json!({
            "token": token,
            "expires_at": expires_at,
            "mailbox": URL_SAFE_NO_PAD.encode(mailbox),
        }))
        .map_err(|e| GhostError::Format(format!("invite body: {e}")))?;
        let req = self.start(&self.base_url(), reqwest::Method::POST, "/invite", None, Body::Json(body), Signing::Device);
        #[derive(serde::Deserialize)]
        struct Registered {
            expires_at: u64,
        }
        let registered: Registered = body_json(Self::finish(req, "register invite", &[]).await?).await?;
        Ok(registered.expires_at)
    }

    /// Upload the payload joiners fetch for an invite token, once: a second upload is
    /// refused with a 409 `RelayStatus`.
    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
    pub async fn put_invite_payload(&self, token: &str, payload: Vec<u8>) -> Result<()> {
        let path = format!("/invite/{token}/join");
        let req = self.start(&self.base_url(), reqwest::Method::POST, &path, None, Body::Bytes(payload), Signing::Device);
        Self::finish(req, "put invite payload", &[]).await.map(drop)
    }

    /// Fetch the invite payload. `None` when the inviter has not uploaded it yet. Works
    /// without auth so joiners can call it.
    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
    pub async fn get_invite_payload(&self, token: &str) -> Result<Option<Vec<u8>>> {
        let path = format!("/invite/{token}/join");
        let req = self.start(&self.base_url(), reqwest::Method::GET, &path, None, Body::None, Signing::Device);
        let resp = Self::finish(req, "get invite payload", &[reqwest::StatusCode::NO_CONTENT]).await?;
        if resp.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }
        body_bytes(resp).await.map(Some)
    }

    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
    pub async fn put_server_info(&self, mailbox_id: &[u8; 32], data: Vec<u8>) -> Result<()> {
        let path = format!("/box/{}/server_info", URL_SAFE_NO_PAD.encode(mailbox_id));
        let req = self.start(&self.base_for(mailbox_id), reqwest::Method::PUT, &path, None, Body::Bytes(data), Signing::Device);
        Self::finish(req, "put server_info", &[]).await.map(drop)
    }

    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
    pub async fn get_server_info(&self, mailbox_id: &[u8; 32]) -> Result<Vec<u8>> {
        self.fetch_server_info(mailbox_id, None).await
    }

    /// The group state a joiner's external commit builds on, which a live invite into the
    /// mailbox lets a device that is not a member yet read.
    pub async fn get_server_info_as_joiner(&self, mailbox_id: &[u8; 32], invite: &str) -> Result<Vec<u8>> {
        self.fetch_server_info(mailbox_id, Some(invite)).await
    }

    async fn fetch_server_info(&self, mailbox_id: &[u8; 32], invite: Option<&str>) -> Result<Vec<u8>> {
        let path = format!("/box/{}/server_info", URL_SAFE_NO_PAD.encode(mailbox_id));
        let query = invite.map(|token| format!("invite={token}"));
        let req = self.start(&self.base_for(mailbox_id), reqwest::Method::GET, &path, query.as_deref(), Body::None, Signing::Device);
        body_bytes(Self::finish(req, "get server_info", &[]).await?).await
    }

    /// The server's private channels this account may enter, with their GroupInfo.
    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
    pub async fn get_admitted_channels(&self, server_mailbox: &[u8; 32]) -> Result<ghost_wire::policy::AdmittedChannels> {
        let path = format!("/servers/{}/channels", URL_SAFE_NO_PAD.encode(server_mailbox));
        let req = self.start(&self.base_for(server_mailbox), reqwest::Method::GET, &path, None, Body::None, Signing::Device);
        let body = body_bytes(Self::finish(req, "get admitted channels", &[]).await?).await?;
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
        let req = self.start(&self.base_for(mailbox_id), reqwest::Method::PUT, &path, None, Body::Bytes(data), Signing::Device);
        Self::finish(req, "put avatar", &[]).await.map(drop)
    }

    pub async fn get_avatar(
        &self,
        mailbox_id: &[u8; 32],
        fingerprint: &[u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        let path = format!("/box/{}/avatar/{}", URL_SAFE_NO_PAD.encode(mailbox_id), hex::encode(fingerprint));
        let req = self.start(&self.base_for(mailbox_id), reqwest::Method::GET, &path, None, Body::None, Signing::Device);
        optional_bytes(Self::finish(req, "get avatar", &[reqwest::StatusCode::NOT_FOUND]).await?).await
    }

    pub async fn delete_avatar(
        &self,
        mailbox_id: &[u8; 32],
        fingerprint: &[u8; 32],
    ) -> Result<()> {
        let path = format!("/box/{}/avatar/{}", URL_SAFE_NO_PAD.encode(mailbox_id), hex::encode(fingerprint));
        let req = self.start(&self.base_for(mailbox_id), reqwest::Method::DELETE, &path, None, Body::None, Signing::Device);
        Self::finish(req, "delete avatar", &[]).await.map(drop)
    }

    /// Append a raw entry at the account's home relay; returns the home's anchor for it.
    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
    pub async fn put_idlog_entry(
        &self,
        account_fp: &[u8; 32],
        payload: Vec<u8>,
    ) -> Result<AnchoredEntry> {
        let path = format!("/idlog/{}", hex::encode(account_fp));
        let req = self.start(&self.base_url(), reqwest::Method::PUT, &path, None, Body::Bytes(payload), Signing::Device);
        let bytes = body_bytes(Self::finish(req, "put idlog", &[]).await?).await?;
        AnchoredEntry::from_bytes(&bytes).map_err(|e| GhostError::Format(format!("anchored entry: {e}")))
    }

    /// Append entries at the account's home together or not at all, with the key sets
    /// their account key entries commit to; returns the home's anchor for each entry.
    /// Batches opening with a genesis or a recovery need no device signature.
    pub async fn post_idlog_batch(&self, account_fp: &[u8; 32], batch: &LogBatch) -> Result<Vec<AnchoredEntry>> {
        let path = format!("/idlog/{}/batch", hex::encode(account_fp));
        let req = self.start(&self.base_url(), reqwest::Method::POST, &path, None, Body::Bytes(batch.to_bytes()), Signing::Device);
        let bytes = body_bytes(Self::finish(req, "post idlog batch", &[]).await?).await?;
        decode_sequence(&bytes).map_err(|e| GhostError::Format(format!("batch anchors: {e}")))
    }

    /// The account key sets of the account's chain from `from_generation` on. Readers
    /// are the account's own devices and its root (signed in the device headers).
    pub async fn get_key_sets(&self, account_fp: &[u8; 32], from_generation: u32) -> Result<Vec<AccountKeySet>> {
        let path = format!("/accounts/{}/key_sets", hex::encode(account_fp));
        let query = format!("from_generation={from_generation}");
        let req = self.start(&self.base_url(), reqwest::Method::GET, &path, Some(&query), Body::None, Signing::Device);
        let bytes = body_bytes(Self::finish(req, "get key sets", &[]).await?).await?;
        decode_key_sets(&bytes).map_err(|e| GhostError::Format(format!("key sets: {e}")))
    }

    /// Give a relay that mirrors the account the key sets its entries commit to. No
    /// credentials: each set must match an account key entry the relay holds.
    pub async fn put_key_sets(&self, account_fp: &[u8; 32], sets: &[AccountKeySet]) -> Result<()> {
        let path = format!("/accounts/{}/key_sets", hex::encode(account_fp));
        let req = self.start(&self.base_url(), reqwest::Method::PUT, &path, None, Body::Bytes(encode_key_sets(sets)), Signing::Anonymous);
        Self::finish(req, "put key sets", &[]).await.map(drop)
    }

    /// The account whose current root is `root`, signed by it. `None` if this relay
    /// holds no account with that root.
    pub async fn find_account_by_root(&self, root: &SigningKey) -> Result<Option<RootLookup>> {
        let path = "/accounts/by_root";
        let req = self
            .start(&self.base_url(), reqwest::Method::GET, path, None, Body::None, Signing::Anonymous)
            .header(ghost_wire::auth::ROOT_AUTH_HEADER, ghost_wire::auth::sign_root_auth("GET", path, root));
        let resp = Self::finish(req, "find account by root", &[reqwest::StatusCode::NOT_FOUND]).await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        body_json(resp).await.map(Some)
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
        let path = format!("/idlog/{}/anchored", hex::encode(account_fp));
        let query = invite.map(|token| format!("invite={token}"));
        let req = self.start(&self.base_url(), reqwest::Method::PUT, &path, query.as_deref(), Body::Bytes(encode_sequence(entries)), Signing::Anonymous);
        body_json(Self::finish(req, "put anchored idlog", &[]).await?).await
    }

    /// Ask this relay to become the account's home; returns the anchors it issued
    /// for the newly sequenced entries. Needs no credentials.
    pub async fn import_account(&self, account_fp: &[u8; 32], request: &ImportRequest) -> Result<Vec<AnchoredEntry>> {
        let path = format!("/accounts/{}/import", hex::encode(account_fp));
        let req = self.start(&self.base_url(), reqwest::Method::POST, &path, None, Body::Bytes(request.to_bytes()), Signing::Anonymous);
        let bytes = body_bytes(Self::finish(req, "import account", &[]).await?).await?;
        decode_sequence(&bytes).map_err(|e| GhostError::Format(format!("import anchors: {e}")))
    }

    /// Tell the home which relays may pull this account's identity log and are pushed
    /// its new entries: adds to the grants, or renews them, which lapse unless renewed.
    pub async fn put_mirror_grants(&self, account_fp: &[u8; 32], relays: &[RelayRef]) -> Result<()> {
        let path = format!("/accounts/{}/mirrors", hex::encode(account_fp));
        let body = ghost_wire::relay_ref::encode_refs(relays);
        let req = self.start(&self.base_url(), reqwest::Method::PUT, &path, None, Body::Bytes(body), Signing::Device);
        Self::finish(req, "put mirror grants", &[]).await.map(drop)
    }

    /// Publish where a server this account created now lives (at the account's home).
    pub async fn put_server_location(&self, account_fp: &[u8; 32], location: &ServerLocation) -> Result<()> {
        let path = format!("/accounts/{}/servers/{}/location", hex::encode(account_fp), hex::encode(location.server_id));
        let req = self.start(&self.base_url(), reqwest::Method::PUT, &path, None, Body::Bytes(location.to_bytes()), Signing::Device);
        Self::finish(req, "put server location", &[]).await.map(drop)
    }

    /// Where the creator `account_fp` says its server lives; `None` if it never moved it.
    pub async fn get_server_location(&self, account_fp: &[u8; 32], server_id: &[u8; 32]) -> Result<Option<ServerLocation>> {
        let path = format!("/accounts/{}/servers/{}/location", hex::encode(account_fp), hex::encode(server_id));
        let req = self.start(&self.base_url(), reqwest::Method::GET, &path, None, Body::None, Signing::Anonymous);
        let Some(bytes) = optional_bytes(Self::finish(req, "get server location", &[reqwest::StatusCode::NOT_FOUND]).await?).await? else {
            return Ok(None);
        };
        ServerLocation::from_bytes(&bytes).map(Some).map_err(|e| GhostError::Format(format!("server location: {e}")))
    }

    /// Where this relay believes the account is homed.
    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
    pub async fn get_account(&self, account_fp: &[u8; 32]) -> Result<AccountInfo> {
        let path = format!("/accounts/{}", hex::encode(account_fp));
        let req = self.start(&self.base_url(), reqwest::Method::GET, &path, None, Body::None, Signing::Device);
        body_json(Self::finish(req, "get account", &[]).await?).await
    }

    /// Fetch an account's anchored identity log.
    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
    pub async fn get_idlog(
        &self,
        account_fp: &[u8; 32],
        after_seq: u64,
    ) -> Result<AnchoredLog> {
        let path = format!("/idlog/{}", hex::encode(account_fp));
        let query = (after_seq > 0).then(|| format!("after_seq={after_seq}"));
        let req = self.start(&self.base_url(), reqwest::Method::GET, &path, query.as_deref(), Body::None, Signing::Device);
        let body: IdLogResponseJson = body_json(Self::finish(req, "get idlog", &[]).await?).await?;

        let b64 = &base64::engine::general_purpose::STANDARD;
        let home_relay_vk = decode_hex_32(&body.home_relay_vk)?;
        let relay_vk = decode_hex_32(&body.relay_vk)?;
        let kt_head = body.kt_head.map(|encoded| decode_checkpoint(&encoded)).transpose()?;
        let entries = body
            .entries
            .into_iter()
            .map(|e| {
                let bytes = b64
                    .decode(&e.anchored)
                    .map_err(|e| GhostError::Format(format!("base64: {e}")))?;
                AnchoredEntry::from_bytes(&bytes)
                    .map_err(|e| GhostError::Format(format!("anchored entry: {e}")))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(AnchoredLog { home_relay_vk, relay_vk, kt_head, entries })
    }

    /// Fetch a KT consistency proof proving the tree at `from` is a prefix of `to`.
    pub async fn get_consistency_proof(
        &self,
        from: u64,
        to: u64,
    ) -> Result<Vec<u8>> {
        let query = format!("from={from}&to={to}");
        let req = self.start(&self.base_url(), reqwest::Method::GET, "/kt/consistency-proof", Some(&query), Body::None, Signing::Anonymous);
        body_bytes(Self::finish(req, "get consistency proof", &[]).await?).await
    }

    /// Open a pairing session (existing device). Replaces any earlier session for the account.
    pub async fn post_pairing_offer(&self, account_fp: &[u8; 32], token: &PairingToken, sealed_offer: Vec<u8>) -> Result<()> {
        let path = format!("/pair/{}", hex::encode(account_fp));
        let mut body = Vec::with_capacity(token.len() + sealed_offer.len());
        body.extend_from_slice(token);
        body.extend_from_slice(&sealed_offer);
        let req = self.start(&self.base_url(), reqwest::Method::POST, &path, None, Body::Bytes(body), Signing::Device);
        Self::finish(req, "post pairing offer", &[]).await.map(drop)
    }

    fn pairing_path(account_fp: &[u8; 32], token: &PairingToken, suffix: &str) -> String {
        format!("/pair/{}/{}{suffix}", hex::encode(account_fp), hex::encode(token))
    }

    /// Answer a pairing offer (new device, unauthenticated). Only the first answer counts.
    pub async fn post_pairing_response(&self, account_fp: &[u8; 32], token: &PairingToken, sealed: Vec<u8>) -> Result<()> {
        let path = Self::pairing_path(account_fp, token, "/respond");
        let req = self.start(&self.base_url(), reqwest::Method::POST, &path, None, Body::Bytes(sealed), Signing::Anonymous);
        Self::finish(req, "post pairing response", &[]).await.map(drop)
    }

    /// Poll for the new device's answer (existing device). `None` until it arrives; a
    /// session that is gone is a 404.
    pub async fn get_pairing_response(&self, account_fp: &[u8; 32], token: &PairingToken) -> Result<Option<Vec<u8>>> {
        let path = Self::pairing_path(account_fp, token, "/response");
        let req = self.start(&self.base_url(), reqwest::Method::GET, &path, None, Body::None, Signing::Device);
        pairing_slot(Self::finish(req, "get pairing response", &[]).await?).await
    }

    /// End a pairing session (existing device): the new device hears it is gone.
    pub async fn close_pairing(&self, account_fp: &[u8; 32], token: &PairingToken) -> Result<()> {
        let path = Self::pairing_path(account_fp, token, "");
        let req = self.start(&self.base_url(), reqwest::Method::DELETE, &path, None, Body::None, Signing::Device);
        Self::finish(req, "close pairing", &[]).await.map(drop)
    }

    /// Fetch the sealed pairing offer (new device, unauthenticated).
    pub async fn get_pairing_offer(&self, account_fp: &[u8; 32], token: &PairingToken) -> Result<Vec<u8>> {
        let path = Self::pairing_path(account_fp, token, "");
        let req = self.start(&self.base_url(), reqwest::Method::GET, &path, None, Body::None, Signing::Anonymous);
        body_bytes(Self::finish(req, "get pairing offer", &[]).await?).await
    }

    /// Post the draft AddDevice for the new device to counter-sign (existing device). A
    /// later draft replaces it and clears the signature made for the old one.
    pub async fn put_pairing_draft(&self, account_fp: &[u8; 32], token: &PairingToken, sealed: Vec<u8>) -> Result<()> {
        let path = Self::pairing_path(account_fp, token, "/draft");
        let req = self.start(&self.base_url(), reqwest::Method::PUT, &path, None, Body::Bytes(sealed), Signing::Device);
        Self::finish(req, "put pairing draft", &[]).await.map(drop)
    }

    /// Fetch the current draft (new device, unauthenticated). `None` until posted.
    pub async fn get_pairing_draft(&self, account_fp: &[u8; 32], token: &PairingToken) -> Result<Option<Vec<u8>>> {
        let path = Self::pairing_path(account_fp, token, "/draft");
        let req = self.start(&self.base_url(), reqwest::Method::GET, &path, None, Body::None, Signing::Anonymous);
        pairing_slot(Self::finish(req, "get pairing draft", &[]).await?).await
    }

    /// Answer the current draft with the new device's counter-signature (new device,
    /// unauthenticated). One answer per draft.
    pub async fn post_pairing_signatures(&self, account_fp: &[u8; 32], token: &PairingToken, sealed: Vec<u8>) -> Result<()> {
        let path = Self::pairing_path(account_fp, token, "/signatures");
        let req = self.start(&self.base_url(), reqwest::Method::POST, &path, None, Body::Bytes(sealed), Signing::Anonymous);
        Self::finish(req, "post pairing signatures", &[]).await.map(drop)
    }

    /// Poll for the counter-signature (existing device). `None` until it arrives.
    pub async fn get_pairing_signatures(&self, account_fp: &[u8; 32], token: &PairingToken) -> Result<Option<Vec<u8>>> {
        let path = Self::pairing_path(account_fp, token, "/signatures");
        let req = self.start(&self.base_url(), reqwest::Method::GET, &path, None, Body::None, Signing::Device);
        pairing_slot(Self::finish(req, "get pairing signatures", &[]).await?).await
    }

    /// Upload the sealed provision blob for a new device (existing device, authenticated).
    pub async fn put_provision(&self, account_fp: &[u8; 32], token: &PairingToken, sealed: Vec<u8>) -> Result<()> {
        let path = Self::pairing_path(account_fp, token, "/provision");
        let req = self.start(&self.base_url(), reqwest::Method::PUT, &path, None, Body::Bytes(sealed), Signing::Device);
        Self::finish(req, "put provision", &[]).await.map(drop)
    }

    /// Fetch the sealed provision blob (new device, unauthenticated). `None` until uploaded.
    pub async fn get_provision(&self, account_fp: &[u8; 32], token: &PairingToken) -> Result<Option<Vec<u8>>> {
        let path = Self::pairing_path(account_fp, token, "/provision");
        let req = self.start(&self.base_url(), reqwest::Method::GET, &path, None, Body::None, Signing::Anonymous);
        pairing_slot(Self::finish(req, "get provision", &[]).await?).await
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
        let req = self.start(&self.base_url(), reqwest::Method::PUT, &path, None, Body::Bytes(body), Signing::Device);
        Self::finish(req, "put sync_state", &[]).await.map(drop)
    }

    /// Fetch the sealed sync snapshot and its generation.
    pub async fn get_sync_state(
        &self,
        account_fp: &[u8; 32],
    ) -> Result<Option<(u64, Vec<u8>)>> {
        let path = format!("/sync_state/{}", hex::encode(account_fp));
        let req = self.start(&self.base_url(), reqwest::Method::GET, &path, None, Body::None, Signing::Device);
        let Some(body) = optional_bytes(Self::finish(req, "get sync_state", &[reqwest::StatusCode::NOT_FOUND]).await?).await? else {
            return Ok(None);
        };
        if body.len() < SNAPSHOT_GENERATION_LEN {
            return Err(GhostError::Format("sync_state response missing generation".into()));
        }
        let generation = u64::from_be_bytes(body[..SNAPSHOT_GENERATION_LEN].try_into().unwrap());
        Ok(Some((generation, body[SNAPSHOT_GENERATION_LEN..].to_vec())))
    }
}


/// What a request carries.
enum Body {
    None,
    Bytes(Vec<u8>),
    Json(Vec<u8>),
}

impl Body {
    fn bytes(&self) -> &[u8] {
        match self {
            Body::None => &[],
            Body::Bytes(bytes) | Body::Json(bytes) => bytes,
        }
    }
}

/// Whether a request is signed as this device. A device the relay does not know yet, or
/// one with no identity, speaks anonymously where the route allows it.
#[derive(PartialEq, Eq)]
enum Signing {
    Device,
    Anonymous,
}

async fn body_bytes(resp: reqwest::Response) -> Result<Vec<u8>> {
    resp.bytes().await.map(|b| b.to_vec()).map_err(|e| GhostError::Network(e.to_string()))
}

async fn body_json<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    resp.json().await.map_err(|e| GhostError::Network(e.to_string()))
}

/// The answer's body, or `None` when the relay answered 404.
/// A pairing session's slot: `None` while it is not filled (204).
async fn pairing_slot(resp: reqwest::Response) -> Result<Option<Vec<u8>>> {
    if resp.status() == reqwest::StatusCode::NO_CONTENT {
        return Ok(None);
    }
    body_bytes(resp).await.map(Some)
}

async fn optional_bytes(resp: reqwest::Response) -> Result<Option<Vec<u8>>> {
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    body_bytes(resp).await.map(Some)
}

/// What a mailbox connection's task starts from.
struct ConnectionSetup {
    url: String,
    relay_url: String,
    mailbox_id: [u8; 32],
    /// The resume point of the first connection.
    last_seen: u64,
    auth: Option<Arc<AuthContext>>,
    silence_limit: Duration,
    /// Where it reports what it hears.
    events: mpsc::Sender<RelayEvent>,
    /// Where it says it came up, each time it does.
    connected: broadcast::Sender<[u8; 32]>,
}

/// Persistent task that maintains a WebSocket connection with automatic reconnection.
async fn ws_task(setup: ConnectionSetup, mut outbox_rx: mpsc::Receiver<WsOutgoing>) {
    let ConnectionSetup { url, relay_url, mailbox_id, last_seen: initial_last_seen, auth, silence_limit, events: event_tx, connected } = setup;
    let mut last_seen = initial_last_seen;
    let mut backoff = INITIAL_BACKOFF;
    let mut first_attempt = true;
    // A refusal is reported once until a connection is made again.
    let mut refusal_reported = false;

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
                // Revoked while away: no relay will serve this device again.
                Err(tokio_tungstenite::tungstenite::Error::Http(resp)) if refuses_revoked_device(resp.headers()) => {
                    let cause = revocation_cause(resp.headers());
                    let _ = event_tx.send(RelayEvent::DeviceRevoked { mailbox_id, relay_url: relay_url.clone(), cause }).await;
                    return;
                }
                Err(tokio_tungstenite::tungstenite::Error::Http(resp)) if resp.status() == 401 => {
                    tracing::debug!("ws {}: {relay_url} does not know this device", short_id(&mailbox_id));
                    if !std::mem::replace(&mut refusal_reported, true) {
                        let _ = event_tx.send(RelayEvent::Unauthorized { mailbox_id, relay_url: relay_url.clone() }).await;
                    }
                    continue;
                }
                Err(tokio_tungstenite::tungstenite::Error::Http(resp)) if resp.status() == 403 => {
                    tracing::debug!("ws {}: {relay_url} does not admit this device to the mailbox", short_id(&mailbox_id));
                    if !std::mem::replace(&mut refusal_reported, true) {
                        let _ = event_tx.send(RelayEvent::Refused { mailbox_id, relay_url: relay_url.clone() }).await;
                    }
                    continue;
                }
                Err(e) => {
                    tracing::debug!("ws {}: connecting to {relay_url} failed: {e}", short_id(&mailbox_id));
                    continue;
                }
            }
        } else {
            match tokio_tungstenite::connect_async(&url).await {
                Ok((ws, _)) => ws,
                Err(e) => {
                    tracing::debug!("ws {}: connecting to {relay_url} failed: {e}", short_id(&mailbox_id));
                    continue;
                }
            }
        };

        let (mut sink, mut stream) = ws.split();

        // Handshake: send last_seen_seq so the relay replays missed entries
        let handshake = Message::Binary(last_seen.to_be_bytes().to_vec().into());
        if !matches!(tokio::time::timeout(silence_limit, sink.send(handshake)).await, Ok(Ok(()))) {
            continue;
        }

        tracing::debug!("ws {}: connected to {relay_url}, resuming after seq {last_seen}", short_id(&mailbox_id));
        refusal_reported = false;
        let _ = event_tx.send(RelayEvent::ConnectionState { mailbox_id, relay_url: relay_url.clone(), connected: true }).await;
        let _ = connected.send(mailbox_id);
        let mut got_message = false;
        // Blobs posted on this connection and not answered yet, oldest first: the relay
        // answers each in turn, so the front is what the next answer is about.
        let mut in_flight: VecDeque<Option<Tracking>> = VecDeque::new();
        // Set when the relay will not have this connection back.
        let mut stop = false;
        // Set when the connection went quiet for too long, or took nothing for that long:
        // it may be dead under us.
        let mut silent = false;
        // Set when the relay closed the connection to judge the device again.
        let mut readmit = false;
        // Silence counts from the last frame heard, however much this side sends.
        let mut heard_at = tokio::time::Instant::now();

        loop {
            tokio::select! {
                outgoing = outbox_rx.recv() => {
                    let message = match outgoing {
                        Some(WsOutgoing::Binary { data, tracking }) => {
                            in_flight.push_back(tracking);
                            Message::Binary(data.into())
                        }
                        Some(WsOutgoing::Text(text)) => Message::Text(text.into()),
                        None => {
                            stop = true;
                            break;
                        }
                    };
                    match tokio::time::timeout(silence_limit, sink.send(message)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(_)) => break,
                        // A relay that takes nothing for that long is as dead as one that
                        // says nothing, and the outbox must not fill behind it.
                        Err(_) => {
                            tracing::debug!("ws {}: {relay_url} took nothing for {silence_limit:?}; reopening", short_id(&mailbox_id));
                            silent = true;
                            break;
                        }
                    }
                }
                msg = tokio::time::timeout_at(heard_at + silence_limit, stream.next()) => {
                    let Ok(msg) = msg else {
                        tracing::debug!("ws {}: nothing from {relay_url} for {silence_limit:?}; reopening", short_id(&mailbox_id));
                        silent = true;
                        break;
                    };
                    heard_at = tokio::time::Instant::now();
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
                            tracing::debug!("ws {}: seq={seq} ({} bytes)", short_id(&mailbox_id), payload.len());
                            last_seen = seq;
                            if !got_message {
                                got_message = true;
                                backoff = INITIAL_BACKOFF;
                            }
                            let _ = event_tx.send(RelayEvent::Blob(IncomingBlob {
                                mailbox_id,
                                relay_url: relay_url.clone(),
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
                            if let Some(head) = s.strip_prefix(WS_SIGNAL_GAP).and_then(|head| head.parse::<u64>().ok()) {
                                // A reconnect resumes after the head, not into the gap again.
                                tracing::debug!("ws {}: {relay_url} reports a gap; resuming after seq {head}", short_id(&mailbox_id));
                                last_seen = head;
                                let _ = event_tx.send(RelayEvent::Gap { mailbox_id, relay_url: relay_url.clone(), head }).await;
                            } else if s == ghost_wire::WS_SIGNAL_CAUGHT_UP {
                                let _ = event_tx.send(RelayEvent::CaughtUp { mailbox_id, relay_url: relay_url.clone() }).await;
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
                            } else if let Some(refusal) = s.strip_prefix(WS_ERROR_PREFIX) {
                                let tracking = in_flight.pop_front().flatten();
                                let message_id = tracking.as_ref().map(|t| t.message_id);
                                match parse_refusal(refusal) {
                                    Some((status, message)) => {
                                        tracing::debug!("ws {}: {relay_url} refused a post: {status} {message}", short_id(&mailbox_id));
                                        if let Some(t) = tracking {
                                            let _ = t.reply.send(SendOutcome::Refused { status, message: message.clone() });
                                        }
                                        let _ = event_tx.send(RelayEvent::Error { mailbox_id, status, message, message_id }).await;
                                    }
                                    // An answer that says no status says neither why nor whether
                                    // for good: the post counts as unanswered.
                                    None => {
                                        tracing::warn!("ws {}: {relay_url} refused a post without a status: {refusal}", short_id(&mailbox_id));
                                        if let Some(t) = tracking {
                                            let _ = t.reply.send(SendOutcome::Lost);
                                            let _ = event_tx.send(RelayEvent::SendLost { mailbox_id, message_id: t.message_id }).await;
                                        }
                                    }
                                }
                            } else if let Some(seq) = parse_seq(s) {
                                tracing::debug!("ws {}: post acknowledged as seq={seq}", short_id(&mailbox_id));
                                let tracking = in_flight.pop_front().flatten();
                                let message_id = tracking.as_ref().map(|t| t.message_id);
                                if let Some(t) = tracking {
                                    let _ = t.reply.send(SendOutcome::Delivered { seq });
                                }
                                let _ = event_tx.send(RelayEvent::Ack(Ack { mailbox_id, seq, message_id })).await;
                            }
                        }
                        Some(Ok(Message::Close(frame))) => {
                            // Removed from the group or revoked: the relay will not serve
                            // this device again, so reconnecting is pointless. No longer
                            // admitted: the reconnect brings the relay's reason at once.
                            let code = frame.as_ref().map(|f| u16::from(f.code));
                            match code {
                                Some(ghost_wire::WS_CLOSE_DEVICE_REVOKED) => {
                                    let cause = frame.as_ref().and_then(|f| ghost_wire::RevocationCause::decode(&f.reason));
                                    let _ = event_tx.send(RelayEvent::DeviceRevoked { mailbox_id, relay_url: relay_url.clone(), cause }).await;
                                    stop = true;
                                }
                                Some(ghost_wire::WS_CLOSE_REMOVED) => {
                                    let _ = event_tx.send(RelayEvent::Removed { mailbox_id, relay_url: relay_url.clone() }).await;
                                    stop = true;
                                }
                                Some(ghost_wire::WS_CLOSE_ADMISSION_CHANGED) => readmit = true,
                                _ => {}
                            }
                            break;
                        }
                        None => break,
                        _ => {}
                    }
                }
            }
        }

        tracing::debug!(
            "ws {}: connection to {relay_url} ended{} with {} posts unanswered",
            short_id(&mailbox_id),
            if stop { " for good" } else { "" },
            in_flight.len()
        );
        // Whatever was posted and not answered is in doubt; the loop sends it again.
        for tracking in in_flight.drain(..).flatten() {
            let _ = tracking.reply.send(SendOutcome::Lost);
            let _ = event_tx.send(RelayEvent::SendLost { mailbox_id, message_id: tracking.message_id }).await;
        }
        let _ = event_tx.send(RelayEvent::ConnectionState { mailbox_id, relay_url: relay_url.clone(), connected: false }).await;
        if stop {
            // Told the relay, so it withdraws this device's presence at once.
            let _ = tokio::time::timeout(CLOSE_WAIT, sink.send(Message::Close(None))).await;
            return;
        }
        // A connection that had been working is reopened at once; one that never got
        // going keeps backing off.
        if got_message || silent || readmit {
            backoff = INITIAL_BACKOFF;
            first_attempt = true;
        }
    }
}

/// Whether a relay's refusal says the account's log revokes this device.
fn refuses_revoked_device(headers: &tokio_tungstenite::tungstenite::http::HeaderMap) -> bool {
    headers.get(ghost_wire::REFUSAL_HEADER).and_then(|v| v.to_str().ok()) == Some(ghost_wire::REFUSAL_DEVICE_REVOKED)
}

/// What revoked this device, as a relay's refusal says.
fn revocation_cause(headers: &reqwest::header::HeaderMap) -> Option<ghost_wire::RevocationCause> {
    headers.get(ghost_wire::REVOKED_BY_HEADER).and_then(|v| v.to_str().ok()).and_then(ghost_wire::RevocationCause::decode)
}

/// WebSocket upgrade request for `url` carrying Ghost's signed device-auth headers.
fn signed_ws_request(url: &str, auth: &AuthContext) -> tokio_tungstenite::tungstenite::http::Request<()> {
    let ws_path = url
        .find("//")
        .and_then(|i| url[i + 2..].find('/').map(|j| &url[i + 2 + j..]))
        .unwrap_or("/");
    let h = auth.sign_for("GET", ws_path, &[]);
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
        .header("X-Ghost-Nonce", &h.nonce)
        .header("X-Ghost-Signature", &h.signature)
        .body(())
        .expect("well-formed upgrade request")
}

/// An acknowledgement: the sequence the relay stored the posted blob under.
fn parse_seq(text: &str) -> Option<u64> {
    text.parse().ok()
}

/// A refusal after `WS_ERROR_PREFIX`: `<status> <message>`; `None` when it carries no
/// status.
fn parse_refusal(text: &str) -> Option<(u16, String)> {
    let (status, message) = text.split_once(' ')?;
    Some((status.parse().ok()?, message.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_names_its_status_or_is_not_read_as_one() {
        assert_eq!(parse_refusal("409 conflict"), Some((409, "conflict".to_string())));
        assert_eq!(parse_refusal("403 removed from this server"), Some((403, "removed from this server".to_string())));
        assert_eq!(parse_refusal("conflict"), None);
        assert_eq!(parse_refusal("teapot at the door"), None);
    }
}
