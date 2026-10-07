use std::net::SocketAddr;
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use reqwest::StatusCode;
use serde_json::Value;
use tokio::net::UdpSocket;
use tokio_tungstenite::tungstenite::Message;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;

use ghost_relay::config::Config;
use ghost_wire::voice::VoiceBind;
use ghost_relay::storage::Storage;
use ghost_relay::{server, state};

// ── Test auth helpers ─────────────────────────────────────────────

/// Test identity that can push genesis and sign requests.
struct TestAuth {
    account_fp: [u8; 32],
    master_key: SigningKey,
    device_key: SigningKey,
}

impl TestAuth {
    fn generate() -> Self {
        let master_key = SigningKey::generate(&mut OsRng);
        let device_key = SigningKey::generate(&mut OsRng);
        let account_fp: [u8; 32] = blake3::hash(master_key.verifying_key().as_bytes()).into();
        Self { account_fp, master_key, device_key }
    }

    fn genesis_bytes(&self) -> Vec<u8> {
        let mut entry = ghost_wire::idlog::LogEntry {
            seq: 1,
            prev_hash: [0u8; 32],
            account_fp: self.account_fp,
            entry_type: ghost_wire::idlog::EntryType::Genesis,
            timestamp: 1000,
            body: ghost_wire::idlog::EntryBody::Genesis {
                master_verifying_key: self.master_key.verifying_key().to_bytes(),
                device_verifying_key: self.device_key.verifying_key().to_bytes(),
                device_label: "test".to_string(),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        let msg = ghost_wire::idlog::sign_message(&entry);
        entry.signature = self.master_key.sign(&msg).to_bytes();
        entry.counter_signature = Some(self.device_key.sign(&msg).to_bytes());
        entry.to_bytes()
    }

    /// Push genesis entry to relay and register this device.
    async fn register(&self, base: &str) {
        let client = reqwest::Client::new();
        let url = format!("{base}/idlog/{}", hex::encode(self.account_fp));
        let resp = client.put(url).body(self.genesis_bytes()).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED, "genesis push failed");
    }

    /// Sign a request builder with fresh auth headers bound to method + path.
    fn sign(&self, method: &str, url: &str, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let path = extract_path(url);
        let h = ghost_wire::auth::sign_request_headers(
            method,
            &path,
            &self.account_fp,
            &self.device_key.verifying_key().to_bytes(),
            &self.device_key,
            None,
        );
        req.header("x-ghost-account", &h.account)
            .header("x-ghost-device", &h.device)
            .header("x-ghost-timestamp", &h.timestamp)
            .header("x-ghost-signature", &h.signature)
    }

    /// Connect to a WebSocket URL with auth headers.
    async fn ws_connect(
        &self,
        url: &str,
    ) -> tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    > {
        let (ws, _) = tokio_tungstenite::connect_async(self.ws_request(url)).await.unwrap();
        ws
    }

    /// A signed WebSocket upgrade request, for tests that expect the relay to refuse it.
    fn ws_request(&self, url: &str) -> tokio_tungstenite::tungstenite::http::Request<()> {
        use tokio_tungstenite::tungstenite::http;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let vk = self.device_key.verifying_key().to_bytes();
        let ws_path = url.find("//")
            .and_then(|i| url[i+2..].find('/').map(|j| &url[i+2+j..]))
            .unwrap_or("/");
        let message = ghost_wire::auth::auth_message("GET", ws_path, &self.account_fp, &vk, timestamp, None);
        let signature = self.device_key.sign(&message);

        let request = http::Request::builder()
            .uri(url)
            .header("Host", url.split("//").nth(1).unwrap().split('/').next().unwrap())
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .header("x-ghost-account", hex::encode(self.account_fp))
            .header("x-ghost-device", hex::encode(vk))
            .header("x-ghost-timestamp", timestamp.to_string())
            .header("x-ghost-signature", hex::encode(signature.to_bytes()))
            .body(())
            .unwrap();
        request
    }
}

// ── Server setup ──────────────────────────────────────────────────

async fn start_server(config: Config) -> String {
    start_server_with_state(config).await.0
}

/// A relay started exactly as the binary starts it; it serves until the test ends.
async fn start_running(config: Config) -> server::RunningRelay {
    let storage = Storage::open_in_memory().unwrap();
    server::start(config, storage, ([127, 0, 0, 1], 0).into()).await.unwrap()
}

async fn start_server_with_state(config: Config) -> (String, state::AppState) {
    let relay = start_running(config).await;
    (relay.url(), relay.state.clone())
}

/// Returns (http_base_url, udp_port).
async fn start_server_with_voice(config: Config) -> (String, u16) {
    let relay = start_running(config).await;
    assert_ne!(relay.voice_port, 0, "voice UDP socket did not bind");
    (relay.url(), relay.voice_port)
}

fn test_config() -> Config {
    Config {
        port: 0,
        max_blob_size: 1024,
        voice_port: 0,
        max_voice_participants: 25,
        db_path: None,
        log_retention_hours: 72,
        log_min_entries: 100,
        public_url: None,
        mirror_refresh_secs: 30,
    }
}

fn mailbox_url(base: &str, id: &[u8; 32]) -> String {
    format!("{base}/box/{}", URL_SAFE_NO_PAD.encode(id))
}

/// Extract the path portion from a full URL (e.g., "http://localhost:1234/box/abc" → "/box/abc")
fn extract_path(url: &str) -> String {
    url.find("//")
        .and_then(|i| url[i+2..].find('/').map(|j| url[i+2+j..].to_string()))
        .unwrap_or_else(|| "/".to_string())
}

fn envelope(typ: ghost_wire::EnvelopeType, epoch: u64, payload: &[u8]) -> Vec<u8> {
    let header = ghost_wire::encode_envelope(typ, epoch);
    let mut out = Vec::with_capacity(header.len() + payload.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    out
}

fn test_envelope(payload: &[u8]) -> Vec<u8> {
    envelope(ghost_wire::EnvelopeType::Application, 0, payload)
}

/// Send the WS catch-up handshake (8-byte BE last_seen_seq).
async fn ws_handshake(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    last_seen: u64,
) {
    ws.send(Message::Binary(last_seen.to_be_bytes().to_vec().into()))
        .await
        .unwrap();
}

/// Consume the vs_snap and ps_snap text frames sent after replay completes.
async fn consume_vs_snap(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) {
    for expected in &["vs_snap", "ps_snap"] {
        let snap = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let m = ws.next().await.unwrap().unwrap();
                if let Message::Text(t) = m {
                    break t.to_string();
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {expected}"));
        assert!(snap.contains(expected), "expected {expected}, got: {snap}");
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn blob_post_and_get() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0x01; 32]);

    // POST
    let resp = auth.sign("POST", &url, client.post(&url).body(test_envelope(b"hello"))).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["seq"], 1);

    // GET returns it
    let blobs: Vec<Value> = auth.sign("GET", &url, client.get(&url)).send().await.unwrap().json().await.unwrap();
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0]["seq"], 1);

    // POST another
    let resp = auth.sign("POST", &url, client.post(&url).body(test_envelope(b"world"))).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["seq"], 2);

    // GET with after=1 returns only second
    let blobs: Vec<Value> = auth.sign("GET", &url, client.get(format!("{url}?after=1")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0]["seq"], 2);
}

#[tokio::test]
async fn long_poll_wakeup() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0x02; 32]);

    let get_url = url.clone();
    let get_req = auth.sign("GET", &get_url, client.get(&get_url).header("X-Ghost-Long-Poll", "5000"));
    let handle = tokio::spawn(async move { get_req.send().await.unwrap() });

    tokio::time::sleep(Duration::from_millis(50)).await;
    auth.sign("POST", &url, client.post(&url).body(test_envelope(b"wake"))).send().await.unwrap();

    let resp = handle.await.unwrap();
    let blobs: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(blobs.len(), 1);
}

#[tokio::test]
async fn ws_fanout() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let ws_base = base.replace("http://", "ws://");
    let mailbox = URL_SAFE_NO_PAD.encode([0x03; 32]);
    let ws_url = format!("{ws_base}/ws/{mailbox}");

    let mut ws_a = auth.ws_connect(&ws_url).await;
    let mut ws_b = auth.ws_connect(&ws_url).await;
    ws_handshake(&mut ws_a, 0).await;
    ws_handshake(&mut ws_b, 0).await;
    consume_vs_snap(&mut ws_a).await;
    consume_vs_snap(&mut ws_b).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    // A sends an envelope-wrapped blob
    ws_a.send(Message::Binary(test_envelope(b"from-a").into())).await.unwrap();

    // B receives: 8-byte seq + 8-byte timestamp + envelope payload
    let data = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let m = ws_b.next().await.unwrap().unwrap();
            if m.is_binary() { break m.into_data(); }
        }
    })
    .await
    .expect("timed out waiting for fan-out");
    // 16-byte frame header + 10-byte envelope header + "from-a"
    assert_eq!(&data[26..], b"from-a");
}

#[tokio::test]
async fn ws_epoch_mismatch_ack() {
    use ghost_wire::EnvelopeType;

    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;

    let relay_vk = fetch_relay_vk(&base).await;
    let provider = OpenMlsRustCrypto::default();
    let id = MlsTestIdentity::new(&auth.account_fp);
    let (mut group, mailbox_id) = create_test_mls_group(&provider, &id, &relay_vk);
    let gi = export_group_info_bytes(&group, &provider, &id.signer);
    upload_group_info(&base, &auth, &mailbox_id, &gi).await;

    let ws_base = base.replace("http://", "ws://");
    let mailbox = URL_SAFE_NO_PAD.encode(mailbox_id);
    let ws_url = format!("{ws_base}/ws/{mailbox}");

    let mut ws = auth.ws_connect(&ws_url).await;
    ws_handshake(&mut ws, 0).await;
    consume_vs_snap(&mut ws).await;

    // Send at epoch 0 — no mismatch, ack is just the seq number
    ws.send(Message::Binary(envelope(EnvelopeType::Application, 0, b"ok").into())).await.unwrap();
    let ack = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let m = ws.next().await.unwrap().unwrap();
            if let Message::Text(t) = m { break t.to_string(); }
        }
    }).await.expect("timed out");
    assert_eq!(ack, "1");

    // Real commit at epoch 0 — advances relay to epoch 1
    let (commit_env, gi) = create_self_update_commit(&mut group, &provider, &id.signer, 0);
    ws.send(Message::Binary(commit_env.into())).await.unwrap();
    let ack = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let m = ws.next().await.unwrap().unwrap();
            if let Message::Text(t) = m { break t.to_string(); }
        }
    }).await.expect("timed out");
    assert_eq!(ack, "2");
    upload_group_info(&base, &auth, &mailbox_id, &gi).await;

    // Send at stale epoch 0 — relay is at 1, expect mismatch hint (app messages still stored)
    ws.send(Message::Binary(envelope(EnvelopeType::Application, 0, b"stale").into())).await.unwrap();
    let ack = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let m = ws.next().await.unwrap().unwrap();
            if let Message::Text(t) = m { break t.to_string(); }
        }
    }).await.expect("timed out");
    assert_eq!(ack, "3 epoch_mismatch");
}

#[tokio::test]
async fn invalid_envelope_rejected() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0x06; 32]);

    let resp = auth.sign("POST", &url, client.post(&url).body(b"not an envelope".to_vec())).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn epoch_gating() {
    use ghost_wire::EnvelopeType;

    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;

    let relay_vk = fetch_relay_vk(&base).await;
    let provider = OpenMlsRustCrypto::default();
    let id = MlsTestIdentity::new(&auth.account_fp);
    let (mut group, mailbox_id) = create_test_mls_group(&provider, &id, &relay_vk);
    let gi = export_group_info_bytes(&group, &provider, &id.signer);
    upload_group_info(&base, &auth, &mailbox_id, &gi).await;

    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &mailbox_id);

    // Application at epoch 0 — relay epoch is 0, no mismatch
    let body: Value = auth.sign("POST", &url, client.post(&url)
        .body(envelope(EnvelopeType::Application, 0, b"msg1")))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(body["seq"], 1);
    assert!(body.get("epoch_mismatch").is_none());

    // Real commit at epoch 0 — advances relay epoch to 1
    let (commit_env, gi) = create_self_update_commit(&mut group, &provider, &id.signer, 0);
    let body: Value = auth.sign("POST", &url, client.post(&url)
        .body(commit_env))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(body["seq"], 2);
    assert!(body.get("epoch_mismatch").is_none());
    upload_group_info(&base, &auth, &mailbox_id, &gi).await;

    // Application at epoch 1 — matches new relay epoch
    let body: Value = auth.sign("POST", &url, client.post(&url)
        .body(envelope(EnvelopeType::Application, 1, b"msg2")))
        .send().await.unwrap().json().await.unwrap();
    assert!(body.get("epoch_mismatch").is_none());

    // Application at epoch 0 — stale, relay expects 1
    let body: Value = auth.sign("POST", &url, client.post(&url)
        .body(envelope(EnvelopeType::Application, 0, b"stale")))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(body["epoch_mismatch"], true);

    // Blob was still stored despite mismatch
    let blobs: Vec<Value> = auth.sign("GET", &url, client.get(&url)).send().await.unwrap().json().await.unwrap();
    assert_eq!(blobs.len(), 4);

    // Application at epoch 1 still matches — relay didn't go backward
    let body: Value = auth.sign("POST", &url, client.post(&url)
        .body(envelope(EnvelopeType::Application, 1, b"still-ok")))
        .send().await.unwrap().json().await.unwrap();
    assert!(body.get("epoch_mismatch").is_none());

    // Real commit at epoch 1 — advances relay to 2
    let (commit_env2, gi2) = create_self_update_commit(&mut group, &provider, &id.signer, 1);
    let body: Value = auth.sign("POST", &url, client.post(&url)
        .body(commit_env2))
        .send().await.unwrap().json().await.unwrap();
    assert!(body.get("epoch_mismatch").is_none());
    upload_group_info(&base, &auth, &mailbox_id, &gi2).await;
}

#[tokio::test]
async fn ws_catchup_replay() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();
    let mailbox_id = [0x09; 32];
    let url = mailbox_url(&base, &mailbox_id);
    let ws_base = base.replace("http://", "ws://");
    let mailbox = URL_SAFE_NO_PAD.encode(mailbox_id);
    let ws_url = format!("{ws_base}/ws/{mailbox}");

    // Post 3 blobs via HTTP
    for i in 0..3u8 {
        let resp = auth.sign("POST", &url, client.post(&url).body(test_envelope(&[i]))).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // Connect with last_seen=0 — should replay all 3
    let mut ws = auth.ws_connect(&ws_url).await;
    ws_handshake(&mut ws, 0).await;

    for i in 0..3u8 {
        let data = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let m = ws.next().await.unwrap().unwrap();
                if m.is_binary() { break m.into_data(); }
            }
        })
        .await
        .expect("timed out waiting for replay");
        let seq = u64::from_be_bytes(data[..8].try_into().unwrap());
        assert_eq!(seq, (i as u64) + 1);
        // 16-byte frame header + 10-byte envelope header + 1-byte payload
        assert_eq!(data[26], i);
    }

    // Connect with last_seen=2 — should replay only seq 3
    let mut ws2 = auth.ws_connect(&ws_url).await;
    ws_handshake(&mut ws2, 2).await;

    let data = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let m = ws2.next().await.unwrap().unwrap();
            if m.is_binary() { break m.into_data(); }
        }
    })
    .await
    .expect("timed out waiting for partial replay");
    let seq = u64::from_be_bytes(data[..8].try_into().unwrap());
    assert_eq!(seq, 3);
    assert_eq!(data[26], 2);
}

#[tokio::test]
async fn blob_size_limit() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0x04; 32]);

    let resp = auth.sign("POST", &url, client.post(&url).body(vec![0u8; 2048])).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn invite_full_flow() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();

    // Register (authenticated)
    let reg_url = format!("{base}/invite");
    let resp = auth.sign("POST", &reg_url, client
        .post(&reg_url)
        .json(&serde_json::json!({ "token": "abc123", "expires_at": u64::MAX })))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Join (authenticated — creator uploads initial payload)
    let join_url = format!("{base}/invite/abc123/join");
    let resp = auth.sign("POST", &join_url, client
        .post(&join_url)
        .body(b"key-package".to_vec()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // Get join payload (unauthenticated — joiner downloads)
    let resp = client.get(format!("{base}/invite/abc123/join")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"key-package");

    // Accept (authenticated)
    let accept_url = format!("{base}/invite/abc123/accept");
    let resp = auth.sign("POST", &accept_url, client
        .post(&accept_url)
        .body(b"welcome".to_vec()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Get accept payload (unauthenticated — joiner polls)
    let resp = client.get(format!("{base}/invite/abc123/accept")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"welcome");
}

#[tokio::test]
async fn expired_invite_rejected() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();

    // Register with already-expired timestamp (authenticated)
    let reg_url = format!("{base}/invite");
    auth.sign("POST", &reg_url, client
        .post(&reg_url)
        .json(&serde_json::json!({ "token": "expired", "expires_at": 1 })))
        .send()
        .await
        .unwrap();

    let join_url = format!("{base}/invite/expired/join");
    let resp = auth.sign("POST", &join_url, client
        .post(&join_url)
        .body(b"kp".to_vec()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::GONE);
}

// --- Voice tests ---

fn build_voice_packet(
    room_id: &[u8; 32],
    slot_id: u32,
    sequence: u32,
    payload: &[u8],
) -> Vec<u8> {
    let header_len = ghost_wire::VOICE_HEADER_SIZE as u16;
    let epoch: u64 = 0;
    [
        &header_len.to_be_bytes()[..],
        room_id,
        &slot_id.to_be_bytes()[..],
        &[0x00], // flags
        &epoch.to_be_bytes(),
        &sequence.to_be_bytes(),
        &(payload.len() as u16).to_be_bytes(),
        payload,
    ]
    .concat()
}

/// Read the next JSON text message, skipping pings. Times out after 5s to prevent hanging tests.
async fn read_voice_msg(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let msg = ws.next().await.unwrap().unwrap();
            if let Message::Text(t) = msg {
                return serde_json::from_str(t.as_str()).unwrap();
            }
        }
    })
    .await
    .expect("timed out waiting for voice WS message")
}

/// A group holding only `auth`'s account, published on the relay, whose voice rooms
/// `auth` may join. Returns the group's mailbox.
async fn voice_group(base: &str, auth: &TestAuth) -> [u8; 32] {
    let provider = OpenMlsRustCrypto::default();
    let identity = MlsTestIdentity::new(&auth.account_fp);
    let relay_vk = fetch_relay_vk(base).await;
    let (group, mailbox_id) = create_test_mls_group(&provider, &identity, &relay_vk);
    let group_info = export_group_info_bytes(&group, &provider, &identity.signer);
    upload_group_info(base, auth, &mailbox_id, &group_info).await;
    mailbox_id
}

fn voice_url(base: &str, mailbox_id: &[u8; 32], channel_id: &[u8; 32]) -> String {
    let ws_base = base.replace("http://", "ws://");
    format!("{ws_base}/voice/{}/{}", URL_SAFE_NO_PAD.encode(mailbox_id), URL_SAFE_NO_PAD.encode(channel_id))
}

/// Room id and bind token from a Welcome.
fn welcome_binding(msg: &Value) -> ([u8; 32], [u8; 32]) {
    let decode = |key: &str| -> [u8; 32] { B64.decode(msg[key].as_str().unwrap()).unwrap().try_into().unwrap() };
    (decode("room"), decode("token"))
}

#[tokio::test]
async fn voice_signaling_join_leave() {
    let (base, _) = start_server_with_voice(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let ws_url = voice_url(&base, &voice_group(&base, &auth).await, &[0x10; 32]);

    let presence_a = B64.encode(b"opaque-presence-a");
    let presence_b = B64.encode(b"opaque-presence-b");

    // A joins
    let mut ws_a = auth.ws_connect(&ws_url).await;
    let join_a = serde_json::json!({"type": "join", "presence": presence_a});
    ws_a.send(Message::Text(join_a.to_string().into())).await.unwrap();

    // A gets Welcome (no peers, has slot_id and port)
    let msg = read_voice_msg(&mut ws_a).await;
    assert_eq!(msg["type"], "welcome");
    assert!(msg["slot_id"].as_u64().unwrap() > 0);
    assert!(msg["port"].as_u64().is_some());
    assert_eq!(msg["peers"].as_array().unwrap().len(), 0);

    // B joins
    let mut ws_b = auth.ws_connect(&ws_url).await;
    let join_b = serde_json::json!({"type": "join", "presence": presence_b});
    ws_b.send(Message::Text(join_b.to_string().into())).await.unwrap();

    // B gets Welcome (A is a peer)
    let msg = read_voice_msg(&mut ws_b).await;
    assert_eq!(msg["type"], "welcome");
    assert_eq!(msg["peers"].as_array().unwrap().len(), 1);
    let slot_b = msg["slot_id"].as_u64().unwrap() as u32;

    // A gets notified that B joined (with presence blob)
    let msg = tokio::time::timeout(Duration::from_secs(2), read_voice_msg(&mut ws_a))
        .await
        .expect("timed out waiting for joined event");
    assert_eq!(msg["type"], "joined");
    assert!(msg["slot_id"].as_u64().is_some());
    assert!(msg["presence"].as_str().is_some());

    // B disconnects
    let leave = serde_json::json!({"type": "leave"});
    ws_b.send(Message::Text(leave.to_string().into())).await.unwrap();
    drop(ws_b);

    // A gets notified that B left
    let msg = tokio::time::timeout(Duration::from_secs(2), read_voice_msg(&mut ws_a))
        .await
        .expect("timed out waiting for left event");
    assert_eq!(msg["type"], "left");
    assert_eq!(msg["slot_id"].as_u64().unwrap() as u32, slot_b);
}

/// Two participants joined to one room with bound UDP sockets: (relay address, room,
/// (socket, slot, token) for A, the same for B, and the WebSockets keeping them joined).
struct VoicePair {
    relay_addr: SocketAddr,
    room: [u8; 32],
    a: (UdpSocket, u32, [u8; 32]),
    b: (UdpSocket, u32, [u8; 32]),
    _ws: Vec<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
}

async fn join_voice(ws_url: &str, auth: &TestAuth, presence: &[u8]) -> (
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    u32,
    [u8; 32],
    [u8; 32],
) {
    let mut ws = auth.ws_connect(ws_url).await;
    ws.send(Message::Text(
        serde_json::json!({"type": "join", "presence": B64.encode(presence)}).to_string().into(),
    )).await.unwrap();
    let welcome = read_voice_msg(&mut ws).await;
    assert_eq!(welcome["type"], "welcome");
    let (room, token) = welcome_binding(&welcome);
    (ws, welcome["slot_id"].as_u64().unwrap() as u32, room, token)
}

async fn bound_voice_pair(base: &str, udp_port: u16, auth: &TestAuth, channel_id: [u8; 32]) -> VoicePair {
    let ws_url = voice_url(base, &voice_group(base, auth).await, &channel_id);
    let relay_addr: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();
    let (mut ws_a, slot_a, room, token_a) = join_voice(&ws_url, auth, b"pa").await;
    let (ws_b, slot_b, room_b, token_b) = join_voice(&ws_url, auth, b"pb").await;
    assert_eq!(room, room_b, "one channel, one room");
    // drain A's "joined" notification for B
    let _ = tokio::time::timeout(Duration::from_secs(1), read_voice_msg(&mut ws_a)).await;

    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock_a.send_to(&VoiceBind::sign(&token_a, room, slot_a, 1).to_bytes(), relay_addr).await.unwrap();
    sock_b.send_to(&VoiceBind::sign(&token_b, room, slot_b, 1).to_bytes(), relay_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    VoicePair { relay_addr, room, a: (sock_a, slot_a, token_a), b: (sock_b, slot_b, token_b), _ws: vec![ws_a, ws_b] }
}

async fn received(sock: &UdpSocket, buf: &mut [u8]) -> Option<usize> {
    tokio::time::timeout(Duration::from_millis(300), sock.recv_from(buf)).await.ok().map(|r| r.unwrap().0)
}

#[tokio::test]
async fn voice_udp_forwarding() {
    let (base, udp_port) = start_server_with_voice(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let pair = bound_voice_pair(&base, udp_port, &auth, [0x20; 32]).await;
    let (sock_a, slot_a, _) = &pair.a;
    let (sock_b, _, _) = &pair.b;
    let (relay_addr, room) = (pair.relay_addr, pair.room);
    let mut recv_buf = [0u8; 1500];

    // A sends a packet — B should receive it
    let pkt_a2 = build_voice_packet(&room, *slot_a, 2, b"frame-2");
    sock_a.send_to(&pkt_a2, relay_addr).await.unwrap();

    let (len, _) = tokio::time::timeout(Duration::from_secs(2), sock_b.recv_from(&mut recv_buf))
        .await
        .expect("timed out waiting for forwarded packet")
        .unwrap();

    // Verify slot_id and payload
    let recv_slot = u32::from_be_bytes(recv_buf[34..38].try_into().unwrap());
    assert_eq!(recv_slot, *slot_a);
    let hdr = ghost_wire::VOICE_HEADER_SIZE;
    assert_eq!(&recv_buf[hdr..len], b"frame-2");

    // A should NOT receive its own packet back
    let result = tokio::time::timeout(Duration::from_millis(200), sock_a.recv_from(&mut recv_buf)).await;
    assert!(result.is_err(), "sender should not receive own packet");
}

#[tokio::test]
async fn voice_media_needs_a_bound_address() {
    let (base, udp_port) = start_server_with_voice(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let pair = bound_voice_pair(&base, udp_port, &auth, [0x21; 32]).await;
    let (_, slot_a, token_a) = &pair.a;
    let (sock_b, _, _) = &pair.b;
    let mut buf = [0u8; 1500];

    // An outsider who knows the room and A's slot sends media, then replays A's bind and
    // forges one: nothing reaches B.
    let outsider = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    outsider.send_to(&build_voice_packet(&pair.room, *slot_a, 3, b"injected"), pair.relay_addr).await.unwrap();
    outsider.send_to(&VoiceBind::sign(token_a, pair.room, *slot_a, 1).to_bytes(), pair.relay_addr).await.unwrap();
    outsider.send_to(&VoiceBind::sign(&[0x66; 32], pair.room, *slot_a, 9).to_bytes(), pair.relay_addr).await.unwrap();
    outsider.send_to(&build_voice_packet(&pair.room, *slot_a, 4, b"injected"), pair.relay_addr).await.unwrap();
    assert!(received(sock_b, &mut buf).await.is_none(), "unbound media was forwarded");

    // Nor does the outsider receive B's media.
    let (sock_b, slot_b, _) = &pair.b;
    sock_b.send_to(&build_voice_packet(&pair.room, *slot_b, 5, b"secret"), pair.relay_addr).await.unwrap();
    assert!(received(&outsider, &mut buf).await.is_none(), "an unbound address received media");
}

#[tokio::test]
async fn voice_join_needs_membership_of_the_named_group() {
    let (base, _) = start_server_with_voice(test_config()).await;
    let member = TestAuth::generate();
    member.register(&base).await;
    let outsider = TestAuth::generate();
    outsider.register(&base).await;
    let ws_url = voice_url(&base, &voice_group(&base, &member).await, &[0x22; 32]);

    let refused = tokio_tungstenite::connect_async(outsider.ws_request(&ws_url)).await;
    match refused {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => assert_eq!(resp.status(), StatusCode::FORBIDDEN),
        other => panic!("expected 403, got {:?}", other.map(|_| "connected")),
    }
    // A mailbox with no group state admits nobody, not even its would-be creator.
    let unknown = voice_url(&base, &[0x99; 32], &[0x22; 32]);
    assert!(tokio_tungstenite::connect_async(member.ws_request(&unknown)).await.is_err());
}

#[tokio::test]
async fn voice_max_participants() {
    let mut config = test_config();
    config.max_voice_participants = 2;
    let (base, _) = start_server_with_voice(config).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let ws_url = voice_url(&base, &voice_group(&base, &auth).await, &[0x30; 32]);

    // Fill to capacity
    let mut ws1 = auth.ws_connect(&ws_url).await;
    ws1.send(Message::Text(
        serde_json::json!({"type": "join", "presence": B64.encode(b"p1")}).to_string().into(),
    )).await.unwrap();
    let _ = read_voice_msg(&mut ws1).await; // welcome

    let mut ws2 = auth.ws_connect(&ws_url).await;
    ws2.send(Message::Text(
        serde_json::json!({"type": "join", "presence": B64.encode(b"p2")}).to_string().into(),
    )).await.unwrap();
    let _ = read_voice_msg(&mut ws2).await; // welcome

    // Third should be rejected
    let mut ws3 = auth.ws_connect(&ws_url).await;
    ws3.send(Message::Text(
        serde_json::json!({"type": "join", "presence": B64.encode(b"p3")}).to_string().into(),
    )).await.unwrap();

    let msg = tokio::time::timeout(Duration::from_secs(2), read_voice_msg(&mut ws3))
        .await
        .expect("timed out waiting for error");
    assert_eq!(msg["type"], "error");
    assert!(msg["message"].as_str().unwrap().contains("full"));
}

// --- Identity log tests ---

fn idlog_url(base: &str, account_fp: &[u8; 32]) -> String {
    format!("{base}/idlog/{}", hex::encode(account_fp))
}

fn make_test_genesis() -> (
    [u8; 32],
    ed25519_dalek::SigningKey,
    ed25519_dalek::SigningKey,
    Vec<u8>,
) {
    let mk = SigningKey::generate(&mut OsRng);
    let dk = SigningKey::generate(&mut OsRng);
    let fp: [u8; 32] = blake3::hash(mk.verifying_key().as_bytes()).into();

    let mut entry = ghost_wire::idlog::LogEntry {
        seq: 1,
        prev_hash: [0u8; 32],
        account_fp: fp,
        entry_type: ghost_wire::idlog::EntryType::Genesis,
        timestamp: 1000,
        body: ghost_wire::idlog::EntryBody::Genesis {
            master_verifying_key: mk.verifying_key().to_bytes(),
            device_verifying_key: dk.verifying_key().to_bytes(),
            device_label: "test".to_string(),
        },
        signature: [0u8; 64],
        counter_signature: None,
    };
    let msg = ghost_wire::idlog::sign_message(&entry);
    entry.signature = mk.sign(&msg).to_bytes();
    entry.counter_signature = Some(dk.sign(&msg).to_bytes());
    (fp, mk, dk, entry.to_bytes())
}

#[tokio::test]
async fn idlog_rejects_bad_seq() {
    let base = start_server(test_config()).await;
    let client = reqwest::Client::new();
    let (fp, _mk, _dk, genesis) = make_test_genesis();

    // Valid genesis
    let resp = client.put(idlog_url(&base, &fp)).body(genesis.clone()).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Duplicate genesis (seq 1 again)
    let resp = client.put(idlog_url(&base, &fp)).body(genesis).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn idlog_rejects_bad_signature() {
    let base = start_server(test_config()).await;
    let client = reqwest::Client::new();
    let (fp, _mk, _dk, mut genesis) = make_test_genesis();

    // Tamper with a byte in the signature area
    let parsed = ghost_wire::idlog::LogEntry::from_bytes(&genesis).unwrap();
    let body_len = {
        let mut buf = Vec::new();
        ghost_wire::idlog::encode_body(&mut buf, &parsed.body);
        buf.len()
    };
    let sig_offset = 85 + body_len;
    genesis[sig_offset] ^= 0xFF;

    let resp = client.put(idlog_url(&base, &fp)).body(genesis).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn idlog_rejects_oversized_entry() {
    let base = start_server(test_config()).await;
    let client = reqwest::Client::new();
    let fp = [0xDD; 32];

    let resp = client
        .put(idlog_url(&base, &fp))
        .body(vec![0u8; 5000])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

// --- Pairing tests ---

fn pair_url(base: &str, fp: &[u8; 32]) -> String {
    format!("{base}/pair/{}", hex::encode(fp))
}

fn session_url(base: &str, fp: &[u8; 32], token: &[u8; 16]) -> String {
    format!("{}/{}", pair_url(base, fp), hex::encode(token))
}

/// Open a pairing session for `auth` with `token`, as the existing device does.
async fn open_pairing(base: &str, auth: &TestAuth, token: &[u8; 16], offer: &[u8]) -> StatusCode {
    let url = pair_url(base, &auth.account_fp);
    let mut body = token.to_vec();
    body.extend_from_slice(offer);
    let client = reqwest::Client::new();
    auth.sign("POST", &url, client.post(&url).body(body)).send().await.unwrap().status()
}

#[tokio::test]
async fn pairing_full_flow() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();
    let token = [0x11; 16];

    assert_eq!(open_pairing(&base, &auth, &token, b"encrypted-offer").await, StatusCode::CREATED);
    let session = session_url(&base, &auth.account_fp, &token);

    // The new device fetches the offer with the token alone.
    let resp = client.get(&session).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"encrypted-offer");

    // Poll for response — none yet (authenticated)
    let resp_url = format!("{session}/response");
    let resp = auth.sign("GET", &resp_url, client.get(&resp_url)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // New device posts response (unauthenticated)
    let resp = client.post(format!("{session}/respond")).body(b"encrypted-response".to_vec()).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Existing device polls — gets response, and the session stays alive
    for _ in 0..2 {
        let resp = auth.sign("GET", &resp_url, client.get(&resp_url)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.bytes().await.unwrap().as_ref(), b"encrypted-response");
    }

    // Provision round trip
    let prov_url = format!("{session}/provision");
    let resp = client.get(&prov_url).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = auth.sign("PUT", &prov_url, client.put(&prov_url).body(b"sealed-provision".to_vec())).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = client.get(&prov_url).send().await.unwrap();
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"sealed-provision");
}

#[tokio::test]
async fn pairing_respond_without_offer_rejected() {
    let base = start_server(test_config()).await;
    let client = reqwest::Client::new();
    let fp = [0xB2; 32];

    let resp = client
        .post(format!("{}/respond", session_url(&base, &fp, &[0x22; 16])))
        .body(b"response".to_vec())
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn pairing_wrong_token_cannot_read_or_answer() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();
    open_pairing(&base, &auth, &[0x33; 16], b"offer").await;

    // Knowing the account fingerprint is not enough without the code's token.
    let wrong = session_url(&base, &auth.account_fp, &[0x34; 16]);
    assert_eq!(client.get(&wrong).send().await.unwrap().status(), StatusCode::NOT_FOUND);
    let resp = client.post(format!("{wrong}/respond")).body(b"hijack".to_vec()).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn pairing_response_cannot_be_replaced() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();
    let token = [0x44; 16];
    open_pairing(&base, &auth, &token, b"offer").await;
    let session = session_url(&base, &auth.account_fp, &token);

    let first = client.post(format!("{session}/respond")).body(b"first".to_vec()).send().await.unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let second = client.post(format!("{session}/respond")).body(b"second".to_vec()).send().await.unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);

    let resp_url = format!("{session}/response");
    let resp = auth.sign("GET", &resp_url, client.get(&resp_url)).send().await.unwrap();
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"first");
}

#[tokio::test]
async fn pairing_offer_overwrite() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();

    // A new session replaces the old one; the old token stops working.
    open_pairing(&base, &auth, &[0x55; 16], b"offer-1").await;
    open_pairing(&base, &auth, &[0x56; 16], b"offer-2").await;

    let old = client.get(session_url(&base, &auth.account_fp, &[0x55; 16])).send().await.unwrap();
    assert_eq!(old.status(), StatusCode::NOT_FOUND);
    let resp = client.get(session_url(&base, &auth.account_fp, &[0x56; 16])).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"offer-2");
}

// --- Auth tests ---

#[tokio::test]
async fn auth_rejects_no_headers() {
    let base = start_server(test_config()).await;
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0xE0; 32]);

    let resp = client.post(&url).body(test_envelope(b"no-auth")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_rejects_revoked_device() {
    let base = start_server(test_config()).await;
    let client = reqwest::Client::new();

    // Create identity with genesis + add device + revoke device
    let mk = SigningKey::generate(&mut OsRng);
    let dk1 = SigningKey::generate(&mut OsRng);
    let dk2 = SigningKey::generate(&mut OsRng);
    let fp: [u8; 32] = blake3::hash(mk.verifying_key().as_bytes()).into();

    // Genesis
    let mut genesis = ghost_wire::idlog::LogEntry {
        seq: 1,
        prev_hash: [0u8; 32],
        account_fp: fp,
        entry_type: ghost_wire::idlog::EntryType::Genesis,
        timestamp: 1000,
        body: ghost_wire::idlog::EntryBody::Genesis {
            master_verifying_key: mk.verifying_key().to_bytes(),
            device_verifying_key: dk1.verifying_key().to_bytes(),
            device_label: "d1".to_string(),
        },
        signature: [0u8; 64],
        counter_signature: None,
    };
    let msg = ghost_wire::idlog::sign_message(&genesis);
    genesis.signature = mk.sign(&msg).to_bytes();
    genesis.counter_signature = Some(dk1.sign(&msg).to_bytes());
    let genesis_bytes = genesis.to_bytes();

    client.put(idlog_url(&base, &fp)).body(genesis_bytes.clone()).send().await.unwrap();

    // Add device 2
    let genesis_hash = ghost_wire::idlog::entry_hash(&genesis);
    let mut add = ghost_wire::idlog::LogEntry {
        seq: 2,
        prev_hash: genesis_hash,
        account_fp: fp,
        entry_type: ghost_wire::idlog::EntryType::AddDevice,
        timestamp: 2000,
        body: ghost_wire::idlog::EntryBody::AddDevice {
            authorizer_key: dk1.verifying_key().to_bytes(),
            device_verifying_key: dk2.verifying_key().to_bytes(),
            device_label: "d2".to_string(),
        },
        signature: [0u8; 64],
        counter_signature: None,
    };
    let msg = ghost_wire::idlog::sign_message(&add);
    add.signature = dk1.sign(&msg).to_bytes();
    add.counter_signature = Some(dk2.sign(&msg).to_bytes());
    let add_bytes = add.to_bytes();
    let dk1_auth = TestAuth { account_fp: fp, master_key: mk.clone(), device_key: dk1.clone() };
    let add_url = idlog_url(&base, &fp);
    dk1_auth.sign("PUT", &add_url, client.put(&add_url).body(add_bytes)).send().await.unwrap();

    // Revoke device 2
    let add_hash = ghost_wire::idlog::entry_hash(&add);
    let mut revoke = ghost_wire::idlog::LogEntry {
        seq: 3,
        prev_hash: add_hash,
        account_fp: fp,
        entry_type: ghost_wire::idlog::EntryType::RevokeDevice,
        timestamp: 3000,
        body: ghost_wire::idlog::EntryBody::RevokeDevice {
            revoker_key: dk1.verifying_key().to_bytes(),
            device_verifying_key: dk2.verifying_key().to_bytes(),
        },
        signature: [0u8; 64],
        counter_signature: None,
    };
    let msg = ghost_wire::idlog::sign_message(&revoke);
    revoke.signature = dk1.sign(&msg).to_bytes();
    let revoke_url = idlog_url(&base, &fp);
    dk1_auth.sign("PUT", &revoke_url, client.put(&revoke_url).body(revoke.to_bytes())).send().await.unwrap();

    // Revoked device 2 should be rejected
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let vk = dk2.verifying_key().to_bytes();
    let url = mailbox_url(&base, &[0xE1; 32]);
    let url_path = extract_path(&url);
    let auth_msg = ghost_wire::auth::auth_message("POST", &url_path, &fp, &vk, timestamp, None);
    let sig = dk2.sign(&auth_msg);

    let resp = client
        .post(&url)
        .header("x-ghost-account", hex::encode(fp))
        .header("x-ghost-device", hex::encode(vk))
        .header("x-ghost-timestamp", timestamp.to_string())
        .header("x-ghost-signature", hex::encode(sig.to_bytes()))
        .body(test_envelope(b"revoked"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Active device 1 should succeed
    let vk1 = dk1.verifying_key().to_bytes();
    let auth_msg1 = ghost_wire::auth::auth_message("POST", &url_path, &fp, &vk1, timestamp, None);
    let sig1 = dk1.sign(&auth_msg1);

    let resp = client
        .post(&url)
        .header("x-ghost-account", hex::encode(fp))
        .header("x-ghost-device", hex::encode(vk1))
        .header("x-ghost-timestamp", timestamp.to_string())
        .header("x-ghost-signature", hex::encode(sig1.to_bytes()))
        .body(test_envelope(b"active"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn auth_rejects_bad_signature() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0xE2; 32]);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let vk = auth.device_key.verifying_key().to_bytes();

    // Use wrong key to sign
    let wrong_key = SigningKey::generate(&mut OsRng);
    let url_path = extract_path(&url);
    let auth_msg = ghost_wire::auth::auth_message("POST", &url_path, &auth.account_fp, &vk, timestamp, None);
    let bad_sig = wrong_key.sign(&auth_msg);

    let resp = client
        .post(&url)
        .header("x-ghost-account", hex::encode(auth.account_fp))
        .header("x-ghost-device", hex::encode(vk))
        .header("x-ghost-timestamp", timestamp.to_string())
        .header("x-ghost-signature", hex::encode(bad_sig.to_bytes()))
        .body(test_envelope(b"bad-sig"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_rejects_stale_timestamp() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0xE3; 32]);

    // Timestamp 120 seconds in the past (beyond 60s tolerance)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 120;
    let vk = auth.device_key.verifying_key().to_bytes();
    let path = extract_path(&url);
    let auth_msg = ghost_wire::auth::auth_message("POST", &path, &auth.account_fp, &vk, timestamp, None);
    let sig = auth.device_key.sign(&auth_msg);

    let resp = client
        .post(&url)
        .header("x-ghost-account", hex::encode(auth.account_fp))
        .header("x-ghost-device", hex::encode(vk))
        .header("x-ghost-timestamp", timestamp.to_string())
        .header("x-ghost-signature", hex::encode(sig.to_bytes()))
        .body(test_envelope(b"stale"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ws_rejects_unauthenticated() {
    let base = start_server(test_config()).await;
    let ws_base = base.replace("http://", "ws://");
    let mailbox = URL_SAFE_NO_PAD.encode([0xE4; 32]);
    let ws_url = format!("{ws_base}/ws/{mailbox}");

    // Connect without auth headers — should get rejected
    let result = tokio_tungstenite::connect_async(&ws_url).await;
    assert!(result.is_err() || {
        let (_, resp) = result.unwrap();
        resp.status() == reqwest::StatusCode::UNAUTHORIZED
    });
}

#[tokio::test]
async fn auth_rejects_future_timestamp() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0xE5; 32]);

    // Timestamp 120 seconds in the future (beyond 60s tolerance)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 120;
    let vk = auth.device_key.verifying_key().to_bytes();
    let path = extract_path(&url);
    let auth_msg = ghost_wire::auth::auth_message("POST", &path, &auth.account_fp, &vk, timestamp, None);
    let sig = auth.device_key.sign(&auth_msg);

    let resp = client
        .post(&url)
        .header("x-ghost-account", hex::encode(auth.account_fp))
        .header("x-ghost-device", hex::encode(vk))
        .header("x-ghost-timestamp", timestamp.to_string())
        .header("x-ghost-signature", hex::encode(sig.to_bytes()))
        .body(test_envelope(b"future"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_cross_account_sync_state_rejected() {
    let base = start_server(test_config()).await;

    // Account A — device that will try cross-account access
    let auth_a = TestAuth::generate();
    auth_a.register(&base).await;

    // Account B — target account
    let auth_b = TestAuth::generate();
    auth_b.register(&base).await;

    // Account B writes its own sync state (should succeed)
    let client = reqwest::Client::new();
    let url_b = format!("{base}/sync_state/{}", hex::encode(auth_b.account_fp));
    let mut b_state = 1u64.to_be_bytes().to_vec();
    b_state.extend_from_slice(b"b-state");
    let resp = auth_b.sign("PUT", &url_b, client.put(&url_b).body(b_state)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Account A tries to read account B's sync state → rejected
    let resp = auth_a.sign("GET", &url_b, client.get(&url_b)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Account A tries to overwrite account B's sync state → rejected
    let mut evil = 2u64.to_be_bytes().to_vec();
    evil.extend_from_slice(b"evil");
    let resp = auth_a.sign("PUT", &url_b, client.put(&url_b).body(evil)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_cross_account_recovery_rejected() {
    let base = start_server(test_config()).await;

    let auth_a = TestAuth::generate();
    auth_a.register(&base).await;

    let auth_b = TestAuth::generate();
    auth_b.register(&base).await;

    // Account B stores its recovery bundle
    let client = reqwest::Client::new();
    let url_b = format!("{base}/recovery/{}", hex::encode(auth_b.account_fp));
    let bundle = |generation: u64, blob: &[u8]| {
        ghost_wire::recovery_bundle::RecoveryBundle { generation, recovery_blob: blob.to_vec(), master_blob: vec![] }.to_bytes()
    };
    let resp = auth_b.sign("PUT", &url_b, client.put(&url_b).body(bundle(5, b"recovery-blob"))).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Account A tries to overwrite B's recovery bundle → rejected
    let resp = auth_a.sign("PUT", &url_b, client.put(&url_b).body(bundle(6, b"evil"))).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // B replaying an older generation is refused too (rollback)
    let resp = auth_b.sign("PUT", &url_b, client.put(&url_b).body(bundle(4, b"old"))).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // Recovery GET is public (no auth needed for bootstrap)
    let resp = reqwest::get(&url_b).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), bundle(5, b"recovery-blob").as_slice());
}

#[tokio::test]
async fn auth_cross_account_provision_rejected() {
    let base = start_server(test_config()).await;

    let auth_a = TestAuth::generate();
    auth_a.register(&base).await;

    let auth_b = TestAuth::generate();
    auth_b.register(&base).await;

    // Account A tries to PUT provision for account B → rejected
    let client = reqwest::Client::new();
    open_pairing(&base, &auth_b, &[0x66; 16], b"offer").await;
    let url_b = format!("{}/provision", session_url(&base, &auth_b.account_fp, &[0x66; 16]));
    let resp = auth_a.sign("PUT", &url_b, client.put(&url_b).body(b"evil-provision".to_vec())).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_get_blobs_requires_auth() {
    let base = start_server(test_config()).await;
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0xE6; 32]);

    // GET without auth → 401
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ws_closed_on_device_revocation() {
    let base = start_server(test_config()).await;
    let ws_base = base.replace("http://", "ws://");
    let client = reqwest::Client::new();

    let mk = SigningKey::generate(&mut OsRng);
    let dk1 = SigningKey::generate(&mut OsRng);
    let dk2 = SigningKey::generate(&mut OsRng);
    let fp: [u8; 32] = blake3::hash(mk.verifying_key().as_bytes()).into();

    // Genesis with dk1
    let mut genesis = ghost_wire::idlog::LogEntry {
        seq: 1,
        prev_hash: [0u8; 32],
        account_fp: fp,
        entry_type: ghost_wire::idlog::EntryType::Genesis,
        timestamp: 1000,
        body: ghost_wire::idlog::EntryBody::Genesis {
            master_verifying_key: mk.verifying_key().to_bytes(),
            device_verifying_key: dk1.verifying_key().to_bytes(),
            device_label: "d1".to_string(),
        },
        signature: [0u8; 64],
        counter_signature: None,
    };
    let msg = ghost_wire::idlog::sign_message(&genesis);
    genesis.signature = mk.sign(&msg).to_bytes();
    genesis.counter_signature = Some(dk1.sign(&msg).to_bytes());
    client.put(idlog_url(&base, &fp)).body(genesis.to_bytes()).send().await.unwrap();

    // Add dk2
    let genesis_hash = ghost_wire::idlog::entry_hash(&genesis);
    let mut add = ghost_wire::idlog::LogEntry {
        seq: 2,
        prev_hash: genesis_hash,
        account_fp: fp,
        entry_type: ghost_wire::idlog::EntryType::AddDevice,
        timestamp: 2000,
        body: ghost_wire::idlog::EntryBody::AddDevice {
            authorizer_key: dk1.verifying_key().to_bytes(),
            device_verifying_key: dk2.verifying_key().to_bytes(),
            device_label: "d2".to_string(),
        },
        signature: [0u8; 64],
        counter_signature: None,
    };
    let msg = ghost_wire::idlog::sign_message(&add);
    add.signature = dk1.sign(&msg).to_bytes();
    add.counter_signature = Some(dk2.sign(&msg).to_bytes());
    let dk1_auth = TestAuth { account_fp: fp, master_key: mk.clone(), device_key: dk1.clone() };
    let dk2_auth = TestAuth { account_fp: fp, master_key: mk.clone(), device_key: dk2.clone() };
    let add_url = idlog_url(&base, &fp);
    let resp = dk1_auth.sign("PUT", &add_url, client.put(&add_url).body(add.to_bytes())).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Connect dk1 to WS
    let mailbox_id = [0xF1; 32];
    let ws_url = format!("{ws_base}/ws/{}", URL_SAFE_NO_PAD.encode(mailbox_id));
    let mut ws = dk1_auth.ws_connect(&ws_url).await;
    ws_handshake(&mut ws, 0).await;

    // Revoke dk1 using dk2
    let add_hash = ghost_wire::idlog::entry_hash(&add);
    let mut revoke = ghost_wire::idlog::LogEntry {
        seq: 3,
        prev_hash: add_hash,
        account_fp: fp,
        entry_type: ghost_wire::idlog::EntryType::RevokeDevice,
        timestamp: 3000,
        body: ghost_wire::idlog::EntryBody::RevokeDevice {
            revoker_key: dk2.verifying_key().to_bytes(),
            device_verifying_key: dk1.verifying_key().to_bytes(),
        },
        signature: [0u8; 64],
        counter_signature: None,
    };
    let msg = ghost_wire::idlog::sign_message(&revoke);
    revoke.signature = dk2.sign(&msg).to_bytes();
    let revoke_url = idlog_url(&base, &fp);
    let resp = dk2_auth.sign("PUT", &revoke_url, client.put(&revoke_url).body(revoke.to_bytes())).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // dk1's WS should receive a close frame with code 4001 (may arrive after other messages)
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let msg = tokio::time::timeout_at(deadline, ws.next())
            .await
            .expect("timed out waiting for close frame")
            .expect("stream ended")
            .expect("ws error");
        if let Message::Close(Some(frame)) = msg {
            let code: u16 = frame.code.into();
            assert_eq!(code, ghost_wire::WS_CLOSE_DEVICE_REVOKED);
            break;
        }
    }
}

// ── MLS enforcement test helpers ─────────────────────────────────

/// Minimal MLS identity for integration tests.
struct MlsTestIdentity {
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

impl MlsTestIdentity {
    fn new(label: &[u8]) -> Self {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let credential = CredentialWithKey {
            credential: Credential::new(CredentialType::Basic, label.to_vec()),
            signature_key: SignaturePublicKey::from(signer.public().to_vec()),
        };
        Self { signer, credential }
    }

}

/// Create an MLS group with ExternalSendersExtension, upload GroupInfo, return (group, mailbox_id).
/// Derive mailbox_id from MLS group_id (same as ghost-core's wire::mls_group_mailbox_id).
fn test_mls_group_mailbox_id(mls_group_id: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(mls_group_id);
    hasher.update(b"ghost-mailbox");
    hasher.finalize().into()
}

fn create_test_mls_group(
    provider: &OpenMlsRustCrypto,
    identity: &MlsTestIdentity,
    relay_vk: &[u8; 32],
) -> (MlsGroup, [u8; 32]) {
    let external_sender = ExternalSender::new(
        SignaturePublicKey::from(relay_vk.to_vec()),
        Credential::new(CredentialType::Basic, b"ghost-relay".to_vec()),
    );
    let extensions = Extensions::single(Extension::ExternalSenders(vec![external_sender])).unwrap();
    let config = MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .max_past_epochs(1)
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .with_group_context_extensions(extensions)
        .build();

    let group = MlsGroup::new(
        provider,
        &identity.signer,
        &config,
        identity.credential.clone(),
    )
    .unwrap();

    let group_id = group.group_id().as_slice();
    let mailbox_id: [u8; 32] = test_mls_group_mailbox_id(group_id);
    (group, mailbox_id)
}

fn export_group_info_bytes(
    group: &MlsGroup,
    provider: &OpenMlsRustCrypto,
    signer: &SignatureKeyPair,
) -> Vec<u8> {
    let msg = group
        .export_group_info(provider.crypto(), signer, true)
        .unwrap();
    msg.to_bytes().unwrap()
}

async fn fetch_relay_vk(base: &str) -> [u8; 32] {
    let client = reqwest::Client::new();
    let resp = client.get(format!("{base}/relay")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    let bytes = hex::decode(body["relay_vk"].as_str().unwrap()).unwrap();
    bytes.try_into().unwrap()
}

async fn upload_group_info(
    base: &str,
    auth: &TestAuth,
    mailbox_id: &[u8; 32],
    group_info: &[u8],
) {
    let client = reqwest::Client::new();
    let url = format!(
        "{base}/box/{}/server_info",
        URL_SAFE_NO_PAD.encode(mailbox_id)
    );
    let resp = auth.sign("PUT", &url, client.put(&url).body(group_info.to_vec()))
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "upload GroupInfo failed");
}

/// Create a self-update commit (simplest way to advance the epoch).
/// Returns (commit_envelope_bytes, new_group_info_bytes).
fn create_self_update_commit(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    signer: &SignatureKeyPair,
    epoch: u64,
) -> (Vec<u8>, Vec<u8>) {
    let bundle = group.commit_builder()
        .load_psks(provider.storage())
        .unwrap()
        .build(provider.rand(), provider.crypto(), signer, |_| true)
        .unwrap()
        .stage_commit(provider)
        .unwrap();

    let commit_bytes = bundle.commit().to_bytes().unwrap();
    group.merge_pending_commit(provider).unwrap();

    let commit_envelope = envelope(
        ghost_wire::EnvelopeType::Commit,
        epoch,
        &commit_bytes,
    );
    let gi = export_group_info_bytes(group, provider, signer);
    (commit_envelope, gi)
}

// ── MLS enforcement tests ────────────────────────────────────────

#[tokio::test]
async fn relay_info_endpoint() {
    let base = start_server(test_config()).await;
    let vk = fetch_relay_vk(&base).await;
    assert_ne!(vk, [0u8; 32]);
    // Second fetch returns same key
    let vk2 = fetch_relay_vk(&base).await;
    assert_eq!(vk, vk2);

    let client = reqwest::Client::new();
    let body: Value = client.get(format!("{base}/relay")).send().await.unwrap().json().await.unwrap();
    assert_eq!(body["protocol"].as_u64().unwrap(), 2);
    assert!(body["kt_head"].is_null(), "no entries yet");
    let relay_ref = ghost_wire::relay_ref::RelayRef::decode(body["ref"].as_str().unwrap()).unwrap();
    assert_eq!(relay_ref.relay_vk, vk);
    assert!(relay_ref.endpoints.is_empty(), "no public_url configured");
}

#[tokio::test]
async fn non_member_blob_rejected_after_acl() {
    let base = start_server(test_config()).await;
    let alice = TestAuth::generate();
    let bob = TestAuth::generate();
    alice.register(&base).await;
    bob.register(&base).await;

    let relay_vk = fetch_relay_vk(&base).await;
    let provider = OpenMlsRustCrypto::default();
    let id = MlsTestIdentity::new(&alice.account_fp);
    let (group, mailbox_id) = create_test_mls_group(&provider, &id, &relay_vk);
    let gi = export_group_info_bytes(&group, &provider, &id.signer);

    // Upload GroupInfo as alice (initializes ACL with alice as sole member)
    upload_group_info(&base, &alice, &mailbox_id, &gi).await;

    // Bob (not a member) tries to POST a blob → 403
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &mailbox_id);
    let resp = bob
        .sign("POST", &url, client.post(&url).body(test_envelope(b"intruder")))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn member_blob_accepted() {
    let base = start_server(test_config()).await;
    let alice = TestAuth::generate();
    alice.register(&base).await;

    let relay_vk = fetch_relay_vk(&base).await;
    let provider = OpenMlsRustCrypto::default();
    let id = MlsTestIdentity::new(&alice.account_fp);
    let (group, mailbox_id) = create_test_mls_group(&provider, &id, &relay_vk);
    let gi = export_group_info_bytes(&group, &provider, &id.signer);

    upload_group_info(&base, &alice, &mailbox_id, &gi).await;

    // Alice (member) can POST application messages
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &mailbox_id);
    let resp = alice
        .sign("POST", &url, client.post(&url).body(test_envelope(b"hello")))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn invalid_commit_rejected() {
    let base = start_server(test_config()).await;
    let alice = TestAuth::generate();
    alice.register(&base).await;

    let relay_vk = fetch_relay_vk(&base).await;
    let provider = OpenMlsRustCrypto::default();
    let id = MlsTestIdentity::new(&alice.account_fp);
    let (group, mailbox_id) = create_test_mls_group(&provider, &id, &relay_vk);
    let gi = export_group_info_bytes(&group, &provider, &id.signer);

    upload_group_info(&base, &alice, &mailbox_id, &gi).await;

    // POST a commit envelope with garbage MLS bytes → 403
    let garbage_commit = envelope(ghost_wire::EnvelopeType::Commit, 0, b"not-valid-mls");
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &mailbox_id);
    let resp = alice
        .sign("POST", &url, client.post(&url).body(garbage_commit))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn desync_recovery_via_group_info_reupload() {
    let base = start_server(test_config()).await;
    let alice = TestAuth::generate();
    alice.register(&base).await;

    let relay_vk = fetch_relay_vk(&base).await;
    let provider = OpenMlsRustCrypto::default();
    let id = MlsTestIdentity::new(&alice.account_fp);
    let (group, mailbox_id) = create_test_mls_group(&provider, &id, &relay_vk);
    let gi = export_group_info_bytes(&group, &provider, &id.signer);

    // Upload GroupInfo
    upload_group_info(&base, &alice, &mailbox_id, &gi).await;

    // Re-upload same GroupInfo (simulate desync recovery)
    upload_group_info(&base, &alice, &mailbox_id, &gi).await;

    // Alice can still POST application messages
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &mailbox_id);
    let resp = alice
        .sign("POST", &url, client.post(&url).body(test_envelope(b"still works")))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn pre_upgrade_group_app_msg_allowed_commit_rejected() {
    // Groups without PublicGroup: application messages still accepted (no ACL),
    // but commits/proposals are rejected (no PublicGroup to validate against).
    let base = start_server(test_config()).await;
    let alice = TestAuth::generate();
    alice.register(&base).await;

    let mailbox_id = [0xAA; 32];
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &mailbox_id);

    // Application messages still pass (no ACL → skip membership check)
    let resp = alice
        .sign("POST", &url, client.post(&url).body(test_envelope(b"legacy")))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Commits are rejected without PublicGroup
    let commit_env = envelope(ghost_wire::EnvelopeType::Commit, 0, b"fake-commit");
    let resp = alice
        .sign("POST", &url, client.post(&url).body(commit_env))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn commit_validated_and_acl_updated() {
    let (base, st) = start_server_with_state(test_config()).await;
    let alice = TestAuth::generate();
    alice.register(&base).await;
    let bob = TestAuth::generate();
    bob.register(&base).await;

    let relay_vk = fetch_relay_vk(&base).await;
    let provider = OpenMlsRustCrypto::default();
    let id_a = MlsTestIdentity::new(&alice.account_fp);
    let (mut group, mailbox_id) = create_test_mls_group(&provider, &id_a, &relay_vk);
    let gi = export_group_info_bytes(&group, &provider, &id_a.signer);

    upload_group_info(&base, &alice, &mailbox_id, &gi).await;

    let commit_envelope = add_member_commit(&mut group, &provider, &id_a.signer, &bob.account_fp);
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &mailbox_id);
    let resp = alice
        .sign("POST", &url, client.post(&url).body(commit_envelope))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Verify ACL was updated: bob should now be a member
    assert!(st.storage.is_mailbox_member(&mailbox_id, &bob.account_fp).unwrap());
}

/// What a test commit changes in the group.
enum Change {
    Add(Box<KeyPackage>),
    Remove(Vec<LeafNodeIndex>),
}

/// A commit adding a fresh device of `account_fp` to `group`, merged locally and wrapped
/// in an envelope for posting.
fn add_member_commit(group: &mut MlsGroup, provider: &OpenMlsRustCrypto, signer: &SignatureKeyPair, account_fp: &[u8; 32]) -> Vec<u8> {
    let joiner = MlsTestIdentity::new(account_fp);
    let key_package = KeyPackage::builder()
        .build(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, provider, &joiner.signer, joiner.credential.clone())
        .unwrap();
    commit_change(group, provider, signer, Change::Add(Box::new(key_package.key_package().clone())))
}

/// A commit removing every leaf of `account_fp` from `group`, merged locally and wrapped.
fn remove_member_commit(group: &mut MlsGroup, provider: &OpenMlsRustCrypto, signer: &SignatureKeyPair, account_fp: &[u8; 32]) -> Vec<u8> {
    let leaves: Vec<LeafNodeIndex> = group
        .members()
        .filter(|m| m.credential.serialized_content().starts_with(account_fp))
        .map(|m| m.index)
        .collect();
    commit_change(group, provider, signer, Change::Remove(leaves))
}

fn commit_change(group: &mut MlsGroup, provider: &OpenMlsRustCrypto, signer: &SignatureKeyPair, change: Change) -> Vec<u8> {
    let epoch = group.epoch().as_u64();
    let builder = group.commit_builder();
    let builder = match change {
        Change::Add(key_package) => builder.propose_adds([*key_package]),
        Change::Remove(leaves) => builder.propose_removals(leaves),
    };
    let bundle = builder
        .load_psks(provider.storage())
        .unwrap()
        .build(provider.rand(), provider.crypto(), signer, |_| true)
        .unwrap()
        .stage_commit(provider)
        .unwrap();
    let commit_bytes = bundle.commit().to_bytes().unwrap();
    group.merge_pending_commit(provider).unwrap();
    envelope(ghost_wire::EnvelopeType::Commit, epoch, &commit_bytes)
}

/// The close code a WebSocket ends with, skipping anything sent before.
async fn close_code(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    saw_binary: &mut bool,
) -> Option<u16> {
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(Ok(msg)) = ws.next().await {
            match msg {
                Message::Close(frame) => return frame.map(|f| f.code.into()),
                Message::Binary(_) => *saw_binary = true,
                _ => {}
            }
        }
        None
    })
    .await
    .expect("connection never closed")
}

#[tokio::test]
async fn removal_ends_the_members_voice_and_mailbox_connections() {
    let (base, _) = start_server_with_voice(test_config()).await;
    let alice = TestAuth::generate();
    alice.register(&base).await;
    let bob = TestAuth::generate();
    bob.register(&base).await;

    let provider = OpenMlsRustCrypto::default();
    let id_a = MlsTestIdentity::new(&alice.account_fp);
    let (mut group, mailbox_id) = create_test_mls_group(&provider, &id_a, &fetch_relay_vk(&base).await);
    upload_group_info(&base, &alice, &mailbox_id, &export_group_info_bytes(&group, &provider, &id_a.signer)).await;
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &mailbox_id);
    let add = add_member_commit(&mut group, &provider, &id_a.signer, &bob.account_fp);
    let resp = alice.sign("POST", &url, client.post(&url).body(add)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Bob is connected to the mailbox and to a voice room of the group.
    let ws_base = base.replace("http://", "ws://");
    let mut mailbox_ws = bob.ws_connect(&format!("{ws_base}/ws/{}", URL_SAFE_NO_PAD.encode(mailbox_id))).await;
    ws_handshake(&mut mailbox_ws, 1).await;
    consume_vs_snap(&mut mailbox_ws).await;
    let (mut voice_ws, _, _, _) = join_voice(&voice_url(&base, &mailbox_id, &[0x40; 32]), &bob, b"pb").await;

    let remove = remove_member_commit(&mut group, &provider, &id_a.signer, &bob.account_fp);
    let resp = alice.sign("POST", &url, client.post(&url).body(remove)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let mut voice_binary = false;
    assert_eq!(close_code(&mut voice_ws, &mut voice_binary).await, Some(ghost_wire::WS_CLOSE_REMOVED));
    // The mailbox delivers the commit that removed Bob, so his device learns of it, then ends.
    let mut saw_commit = false;
    assert_eq!(close_code(&mut mailbox_ws, &mut saw_commit).await, Some(ghost_wire::WS_CLOSE_REMOVED));
    assert!(saw_commit, "the removing commit was not delivered before the close");
}

// ── Key Transparency integration tests ──────────────────────────

#[tokio::test]
async fn idlog_append_creates_kt_leaf() {
    let base = start_server(test_config()).await;
    let alice = TestAuth::generate();
    alice.register(&base).await;

    // KT head should exist after genesis push
    let client = reqwest::Client::new();
    let resp = client.get(format!("{base}/kt/head")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let checkpoint_bytes = resp.bytes().await.unwrap();
    let checkpoint = ghost_wire::merkle::Checkpoint::from_bytes(&checkpoint_bytes).unwrap();
    assert_eq!(checkpoint.tree_size, 1);
}

#[tokio::test]
async fn get_idlog_returns_anchored_entries() {
    let (base, st) = start_server_with_state(test_config()).await;
    let alice = TestAuth::generate();

    // PUT answers with the anchor for the new entry.
    let client = reqwest::Client::new();
    let url = format!("{base}/idlog/{}", hex::encode(alice.account_fp));
    let resp = client.put(&url).body(alice.genesis_bytes()).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let put_anchor = ghost_wire::anchor::AnchoredEntry::from_bytes(&resp.bytes().await.unwrap()).unwrap();
    assert_eq!(put_anchor.entry.seq, 1);
    assert!(put_anchor.verify_anchor(&st.relay_vk, None).is_ok());

    // GET serves the same anchored entry and names this relay as home.
    let req = client.get(&url);
    let resp = alice.sign("GET", &url, req).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["home_relay_vk"].as_str().unwrap(), hex::encode(st.relay_vk));
    let entries = body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["seq"].as_u64().unwrap(), 1);
    let anchored_bytes = B64.decode(entries[0]["anchored"].as_str().unwrap()).unwrap();
    assert_eq!(anchored_bytes, put_anchor.to_bytes());

    let anchored = ghost_wire::anchor::AnchoredEntry::from_bytes(&anchored_bytes).unwrap();
    assert_eq!(anchored.entry.to_bytes(), alice.genesis_bytes());
    assert_eq!(anchored.checkpoint.tree_size, 1);
    let mut state = ghost_wire::idlog::LogState::empty(alice.account_fp);
    ghost_wire::anchor::validate_anchored_entry(&mut state, &anchored, Some(&st.relay_vk), |_| None).unwrap();
    assert_eq!(state.head_seq, 1);
}

#[tokio::test]
async fn anchored_push_registers_foreign_account_with_invite_only() {
    let (home_base, home_state) = start_server_with_state(test_config()).await;
    let (mirror_base, _mirror_state) = start_server_with_state(test_config()).await;
    let client = reqwest::Client::new();

    // Alice is created at the home relay (genesis + SetHomeRelay).
    let alice = TestAuth::generate();
    let home_url = format!("{home_base}/idlog/{}", hex::encode(alice.account_fp));
    let resp = client.put(&home_url).body(alice.genesis_bytes()).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let genesis = ghost_wire::idlog::LogEntry::from_bytes(&alice.genesis_bytes()).unwrap();
    let state = ghost_wire::idlog::validate_chain(&[genesis]).unwrap();
    let mut set_home = ghost_wire::idlog::LogEntry {
        seq: 2,
        prev_hash: state.head_hash,
        account_fp: alice.account_fp,
        entry_type: ghost_wire::idlog::EntryType::SetHomeRelay,
        timestamp: 2000,
        body: ghost_wire::idlog::EntryBody::SetHomeRelay {
            relay_vk: home_state.relay_vk,
            authorizer_key: alice.device_key.verifying_key().to_bytes(),
            relay_ref: ghost_wire::relay_ref::RelayRef::https(home_state.relay_vk, &home_base),
        },
        signature: [0u8; 64],
        counter_signature: None,
    };
    let msg = ghost_wire::idlog::sign_message(&set_home);
    set_home.signature = alice.device_key.sign(&msg).to_bytes();
    let resp = alice
        .sign("PUT", &home_url, client.put(&home_url).body(set_home.to_bytes()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Fetch the anchored chain from the home.
    let resp = alice.sign("GET", &home_url, client.get(&home_url)).send().await.unwrap();
    let body: Value = resp.json().await.unwrap();
    let mut chain = Vec::new();
    for e in body["entries"].as_array().unwrap() {
        chain.extend_from_slice(&B64.decode(e["anchored"].as_str().unwrap()).unwrap());
    }

    // The mirror has never heard of Alice: her device cannot authenticate there.
    let mirror_url = format!("{mirror_base}/idlog/{}", hex::encode(alice.account_fp));
    let probe = format!("{mirror_base}/accounts/{}", hex::encode(alice.account_fp));
    let resp = alice.sign("GET", &probe, client.get(&probe)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Without an invite the anchored push is refused.
    let resp = client.put(format!("{mirror_url}/anchored")).body(chain.clone()).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = client
        .put(format!("{mirror_url}/anchored?invite=nope"))
        .body(chain.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Bob, a member of the mirror, registers an invite there.
    let bob = TestAuth::generate();
    bob.register(&mirror_base).await;
    let invite_url = format!("{mirror_base}/invite");
    let expires_at = ghost_relay::util::now_millis() + 60_000;
    let resp = bob
        .sign("POST", &invite_url, client.post(&invite_url).json(&serde_json::json!({"token": "tok1", "expires_at": expires_at})))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // With the invite the mirror validates the chain and registers Alice as a guest.
    let resp = client
        .put(format!("{mirror_url}/anchored?invite=tok1"))
        .body(chain.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let info: Value = resp.json().await.unwrap();
    assert_eq!(info["home_relay_vk"].as_str().unwrap(), hex::encode(home_state.relay_vk));
    assert_eq!(info["is_home"].as_bool().unwrap(), false);
    assert_eq!(info["head_seq"].as_u64().unwrap(), 2);

    // Alice's device now authenticates at the mirror and sees the same view.
    let resp = alice.sign("GET", &probe, client.get(&probe)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = alice.sign("GET", &mirror_url, client.get(&mirror_url)).send().await.unwrap();
    let mirrored: Value = resp.json().await.unwrap();
    assert_eq!(mirrored["home_relay_vk"].as_str().unwrap(), hex::encode(home_state.relay_vk));
    assert_eq!(mirrored["entries"].as_array().unwrap().len(), 2);

    // Raw appends are refused at the mirror: the home sequences the log.
    let device2 = SigningKey::generate(&mut OsRng);
    let state = {
        let entries: Vec<_> = mirrored["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                ghost_wire::anchor::AnchoredEntry::from_bytes(&B64.decode(e["anchored"].as_str().unwrap()).unwrap())
                    .unwrap()
                    .entry
            })
            .collect();
        ghost_wire::idlog::validate_chain(&entries).unwrap()
    };
    let mut add = ghost_wire::idlog::LogEntry {
        seq: 3,
        prev_hash: state.head_hash,
        account_fp: alice.account_fp,
        entry_type: ghost_wire::idlog::EntryType::AddDevice,
        timestamp: 3000,
        body: ghost_wire::idlog::EntryBody::AddDevice {
            device_verifying_key: device2.verifying_key().to_bytes(),
            device_label: "phone".into(),
            authorizer_key: alice.device_key.verifying_key().to_bytes(),
        },
        signature: [0u8; 64],
        counter_signature: None,
    };
    let msg = ghost_wire::idlog::sign_message(&add);
    add.signature = alice.device_key.sign(&msg).to_bytes();
    add.counter_signature = Some(device2.sign(&msg).to_bytes());
    let resp = alice
        .sign("PUT", &mirror_url, client.put(&mirror_url).body(add.to_bytes()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn kt_consistency_proof_valid() {
    let base = start_server(test_config()).await;
    let alice = TestAuth::generate();
    alice.register(&base).await;

    // Push a second identity log entry (add a device)
    let device2 = SigningKey::generate(&mut OsRng);
    let mut add_entry = ghost_wire::idlog::LogEntry {
        seq: 2,
        prev_hash: {
            let h: [u8; 32] = blake3::hash(&alice.genesis_bytes()).into();
            h
        },
        account_fp: alice.account_fp,
        entry_type: ghost_wire::idlog::EntryType::AddDevice,
        timestamp: 2000,
        body: ghost_wire::idlog::EntryBody::AddDevice {
            device_verifying_key: device2.verifying_key().to_bytes(),
            device_label: "device2".to_string(),
            authorizer_key: alice.master_key.verifying_key().to_bytes(),
        },
        signature: [0u8; 64],
        counter_signature: None,
    };
    let msg = ghost_wire::idlog::sign_message(&add_entry);
    add_entry.signature = alice.master_key.sign(&msg).to_bytes();
    add_entry.counter_signature = Some(device2.sign(&msg).to_bytes());
    let add_bytes = add_entry.to_bytes();

    let client = reqwest::Client::new();
    let url = format!("{}/idlog/{}", base, hex::encode(alice.account_fp));
    let resp = alice.sign("PUT", &url, client.put(&url).body(add_bytes)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Tree should now have 2 leaves. Get consistency proof from 1 to 2
    let resp = client.get(format!("{base}/kt/consistency-proof?from=1&to=2"))
        .send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let proof_bytes = resp.bytes().await.unwrap();
    let proof = ghost_wire::merkle::ConsistencyProof::from_bytes(&proof_bytes).unwrap();

    // Get both checkpoints to verify
    let head_resp = client.get(format!("{base}/kt/head")).send().await.unwrap();
    let head_bytes = head_resp.bytes().await.unwrap();
    let new_checkpoint = ghost_wire::merkle::Checkpoint::from_bytes(&head_bytes).unwrap();
    assert_eq!(new_checkpoint.tree_size, 2);

    // Compute old root from genesis entry alone
    let genesis_hash = ghost_wire::merkle::leaf_hash(&alice.genesis_bytes());
    let old_root = ghost_wire::merkle::compute_root(&[genesis_hash]);

    assert!(proof.verify(&old_root, &new_checkpoint.root_hash));
}

#[tokio::test]
async fn server_location_requires_an_active_device_signature_and_increasing_generation() {
    use ghost_wire::relay_ref::RelayRef;
    use ghost_wire::server_location::ServerLocation;

    let base = start_server(test_config()).await;
    let alice = TestAuth::generate();
    alice.register(&base).await;
    let client = reqwest::Client::new();
    let server_id = [0x5E; 32];
    let url = format!("{base}/accounts/{}/servers/{}/location", hex::encode(alice.account_fp), hex::encode(server_id));
    let put = |body: Vec<u8>| alice.sign("PUT", &url, client.put(&url).body(body));

    // Signed by Alice's device: stored and readable without credentials.
    let first = ServerLocation::sign(server_id, 1, RelayRef::https([0x11; 32], "https://new.example"), &alice.device_key);
    assert_eq!(put(first.to_bytes()).send().await.unwrap().status(), StatusCode::NO_CONTENT);
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), first.to_bytes().as_slice());

    // Replaying the same generation is refused.
    assert_eq!(put(first.to_bytes()).send().await.unwrap().status(), StatusCode::CONFLICT);

    // A record signed by a key that is not one of Alice's devices is refused.
    let stranger = SigningKey::generate(&mut OsRng);
    let forged = ServerLocation::sign(server_id, 2, RelayRef::https([0x22; 32], "https://evil.example"), &stranger);
    assert_eq!(put(forged.to_bytes()).send().await.unwrap().status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Unknown servers have no location.
    let other = format!("{base}/accounts/{}/servers/{}/location", hex::encode(alice.account_fp), hex::encode([0x5F; 32]));
    assert_eq!(client.get(&other).send().await.unwrap().status(), StatusCode::NOT_FOUND);
}
