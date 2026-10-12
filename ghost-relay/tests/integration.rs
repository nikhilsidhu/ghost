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
        self.genesis_entry().to_bytes()
    }

    fn genesis_entry(&self) -> ghost_wire::idlog::LogEntry {
        let mut entry = ghost_wire::idlog::LogEntry {
            seq: 1,
            prev_hash: [0u8; 32],
            account_fp: self.account_fp,
            entry_type: ghost_wire::idlog::EntryType::Genesis,
            timestamp: 1000,
            body: ghost_wire::idlog::EntryBody::Genesis {
                genesis_verifying_key: self.master_key.verifying_key().to_bytes(),
                device_verifying_key: self.device_key.verifying_key().to_bytes(),
                device_label: "test".to_string(),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        let msg = ghost_wire::idlog::sign_message(&entry);
        entry.signature = self.master_key.sign(&msg).to_bytes();
        entry.counter_signature = Some(self.device_key.sign(&msg).to_bytes());
        entry
    }

    /// Another device of this registered account, added to its log on the relay by this
    /// one. For an account whose log holds only its genesis.
    async fn add_device(&self, base: &str) -> TestAuth {
        let device_key = SigningKey::generate(&mut OsRng);
        let mut add = ghost_wire::idlog::LogEntry {
            seq: 2,
            prev_hash: ghost_wire::idlog::entry_hash(&self.genesis_entry()),
            account_fp: self.account_fp,
            entry_type: ghost_wire::idlog::EntryType::AddDevice,
            timestamp: 2000,
            body: ghost_wire::idlog::EntryBody::AddDevice {
                authorizer_key: self.device_key.verifying_key().to_bytes(),
                device_verifying_key: device_key.verifying_key().to_bytes(),
                device_label: "second".to_string(),
            },
            signature: [0u8; 64],
            counter_signature: None,
        };
        let msg = ghost_wire::idlog::sign_message(&add);
        add.signature = self.device_key.sign(&msg).to_bytes();
        add.counter_signature = Some(device_key.sign(&msg).to_bytes());
        let url = format!("{base}/idlog/{}", hex::encode(self.account_fp));
        let resp = self.sign("PUT", &url, add.to_bytes(), reqwest::Client::new().put(&url)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED, "adding a device failed");
        TestAuth { account_fp: self.account_fp, master_key: self.master_key.clone(), device_key }
    }

    /// Push genesis entry to relay and register this device.
    async fn register(&self, base: &str) {
        let client = reqwest::Client::new();
        let url = format!("{base}/idlog/{}", hex::encode(self.account_fp));
        let resp = client.put(url).body(self.genesis_bytes()).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED, "genesis push failed");
    }

    /// Sign a request with fresh auth headers bound to method, path and `body`, which
    /// goes on the request afterwards.
    fn sign(&self, method: &str, url: &str, body: Vec<u8>, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        sign_as(&self.account_fp, &self.device_key, method, url, body, req)
    }

    /// A signed POST of `value` as JSON.
    fn post_json(&self, url: &str, value: &serde_json::Value) -> reqwest::RequestBuilder {
        let body = serde_json::to_vec(value).unwrap();
        self.sign("POST", url, body, reqwest::Client::new().post(url).header("content-type", "application/json"))
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
        let mut nonce = [0u8; ghost_wire::auth::AUTH_NONCE_LEN];
        rand::RngCore::fill_bytes(&mut OsRng, &mut nonce);
        let message = ghost_wire::auth::auth_message("GET", ws_path, &self.account_fp, &vk, timestamp, &nonce, &ghost_wire::auth::body_hash(&[]));
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
            .header("x-ghost-nonce", hex::encode(nonce))
            .header("x-ghost-signature", hex::encode(signature.to_bytes()))
            .body(())
            .unwrap();
        request
    }
}

/// Sign a request for `account_fp` with `key` in the device headers: a device key,
/// or the account's root, which relays accept there for reading the account's data.
fn sign_as(account_fp: &[u8; 32], key: &SigningKey, method: &str, url: &str, body: Vec<u8>, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    let path = extract_path(url);
    let h = ghost_wire::auth::sign_request_headers(method, &path, &body, account_fp, &key.verifying_key().to_bytes(), key);
    req.header("x-ghost-account", &h.account)
        .header("x-ghost-device", &h.device)
        .header("x-ghost-timestamp", &h.timestamp)
        .header("x-ghost-nonce", &h.nonce)
        .header("x-ghost-signature", &h.signature)
        .body(body)
}

/// A mailbox for invites in tests that never upload group state, so anyone is a member.
const INVITE_MAILBOX: [u8; 32] = [0x77; 32];

fn invite_registration(token: &str, expires_at: u64) -> serde_json::Value {
    serde_json::json!({ "token": token, "expires_at": expires_at, "mailbox": URL_SAFE_NO_PAD.encode(INVITE_MAILBOX) })
}

// ── Server setup ──────────────────────────────────────────────────

async fn start_server(config: Config) -> String {
    start_server_with_state(config).await.0
}

/// A relay started exactly as the binary starts it; it serves until the test ends.
async fn start_running(config: Config) -> server::RunningRelay {
    let storage = Storage::open_ephemeral().unwrap();
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
        voice_public_port: None,
        max_voice_participants: 25,
        db_path: None,
        log_retention_hours: 72,
        log_min_entries: 100,
        public_url: None,
        mirror_refresh_secs: 30,
        trusted_proxies: Vec::new(),
        ws_ping_secs: 30,
        presence_grace_secs: 30,
        skip_policy_checks_for_tests: false,
        revoked_devices_for_tests: Default::default(),
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

/// Consume the text frames that end the replay: the caught-up signal, then the vs_snap
/// and ps_snap snapshots.
async fn consume_replay_end(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) {
    for expected in &[ghost_wire::WS_SIGNAL_CAUGHT_UP, "vs_snap", "ps_snap"] {
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
async fn blob_posts_are_numbered_in_order() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0x01; 32]);

    for (expected_seq, payload) in [(1, b"hello".as_slice()), (2, b"world".as_slice())] {
        let resp = auth.sign("POST", &url, test_envelope(payload), client.post(&url)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["seq"], expected_seq);
    }
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
    consume_replay_end(&mut ws_a).await;
    consume_replay_end(&mut ws_b).await;

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

/// The caught-up signal follows the entries held past the resume point, and precedes
/// the live ones.
#[tokio::test]
async fn the_caught_up_signal_ends_the_replay() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0x04; 32]);
    for payload in [b"one".as_slice(), b"two", b"three"] {
        auth.sign("POST", &url, test_envelope(payload), client.post(&url)).send().await.unwrap();
    }

    let ws_url = format!("{}/ws/{}", base.replace("http://", "ws://"), URL_SAFE_NO_PAD.encode([0x04; 32]));
    let mut ws = auth.ws_connect(&ws_url).await;
    ws_handshake(&mut ws, 1).await;
    let replayed = tokio::time::timeout(Duration::from_secs(2), async {
        let mut replayed = 0;
        loop {
            match ws.next().await.unwrap().unwrap() {
                Message::Binary(_) => replayed += 1,
                Message::Text(t) if t.as_str() == ghost_wire::WS_SIGNAL_CAUGHT_UP => break replayed,
                _ => {}
            }
        }
    })
    .await
    .expect("the replay never ended");
    assert_eq!(replayed, 2, "the entries after the resume point, then the signal");
}

#[tokio::test]
async fn ws_refuses_a_stale_message_with_an_error_ack() {
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
    consume_replay_end(&mut ws).await;

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

    // One epoch behind is still open to members: taken.
    ws.send(Message::Binary(envelope(EnvelopeType::Application, 0, b"one behind").into())).await.unwrap();
    let ack = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let m = ws.next().await.unwrap().unwrap();
            if let Message::Text(t) = m { break t.to_string(); }
        }
    }).await.expect("timed out");
    assert_eq!(ack, "3");

    // Another commit moves the relay to epoch 2; a message at epoch 0 is refused, with
    // the status in the reply so the sender knows to seal it again later.
    let (commit_env, gi) = create_self_update_commit(&mut group, &provider, &id.signer, 1);
    ws.send(Message::Binary(commit_env.into())).await.unwrap();
    let ack = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let m = ws.next().await.unwrap().unwrap();
            if let Message::Text(t) = m { break t.to_string(); }
        }
    }).await.expect("timed out");
    assert_eq!(ack, "4");
    upload_group_info(&base, &auth, &mailbox_id, &gi).await;
    ws.send(Message::Binary(envelope(EnvelopeType::Application, 0, b"stale").into())).await.unwrap();
    let ack = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let m = ws.next().await.unwrap().unwrap();
            if let Message::Text(t) = m { break t.to_string(); }
        }
    }).await.expect("timed out");
    assert_eq!(ack, "error: 409 conflict");
}

#[tokio::test]
async fn invalid_envelope_rejected() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0x06; 32]);

    let resp = auth.sign("POST", &url, b"not an envelope".to_vec(), client.post(&url)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn epoch_gating() {
    use ghost_wire::EnvelopeType;

    let (base, st) = start_server_with_state(test_config()).await;
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

    // Application at epoch 0 — relay epoch is 0
    let body: Value = auth.sign("POST", &url, envelope(EnvelopeType::Application, 0, b"msg1"), client.post(&url))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(body["seq"], 1);

    // Real commit at epoch 0 — advances relay epoch to 1
    let (commit_env, gi) = create_self_update_commit(&mut group, &provider, &id.signer, 0);
    let body: Value = auth.sign("POST", &url, commit_env, client.post(&url))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(body["seq"], 2);
    upload_group_info(&base, &auth, &mailbox_id, &gi).await;

    // Application at epoch 1 — matches new relay epoch
    let body: Value = auth.sign("POST", &url, envelope(EnvelopeType::Application, 1, b"msg2"), client.post(&url))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(body["seq"], 3);

    // Application at epoch 0 — one behind, which members still open: taken
    let body: Value = auth.sign("POST", &url, envelope(EnvelopeType::Application, 0, b"one behind"), client.post(&url))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(body["seq"], 4);

    // Real commit at epoch 1 — advances relay to 2
    let (commit_env2, gi2) = create_self_update_commit(&mut group, &provider, &id.signer, 1);
    let body: Value = auth.sign("POST", &url, commit_env2, client.post(&url))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(body["seq"], 5);
    upload_group_info(&base, &auth, &mailbox_id, &gi2).await;

    // Application at epoch 0 — two behind, nobody could open it: refused and not stored
    let resp = auth.sign("POST", &url, envelope(EnvelopeType::Application, 0, b"stale"), client.post(&url)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(st.storage.read_from(mailbox_id, 0, 10).await.unwrap().len(), 5);
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
        let resp = auth.sign("POST", &url, test_envelope(&[i]), client.post(&url)).send().await.unwrap();
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

/// A connection resuming before what the log still keeps is told where it resumes and
/// gets only what follows; one resuming past the log's end, as after the relay's log
/// started over, is served the whole log.
#[tokio::test]
async fn a_gap_names_where_the_connection_resumes_and_a_log_that_started_over_is_served_whole() {
    let (base, st) = start_server_with_state(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();
    let mailbox_id = [0x0A; 32];
    let url = mailbox_url(&base, &mailbox_id);
    let ws_url = format!("{}/ws/{}", base.replace("http://", "ws://"), URL_SAFE_NO_PAD.encode(mailbox_id));
    for i in 0..4u8 {
        let resp = auth.sign("POST", &url, test_envelope(&[i]), client.post(&url)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
    // Keep the last two entries only.
    st.storage.sweep_log(ghost_wire::now_millis() + 3_600_000, 2).await.unwrap();

    async fn next_message(ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>) -> Message {
        tokio::time::timeout(Duration::from_secs(2), ws.next()).await.expect("nothing arrived").unwrap().unwrap()
    }

    let mut behind = auth.ws_connect(&ws_url).await;
    ws_handshake(&mut behind, 1).await;
    let first = next_message(&mut behind).await;
    assert_eq!(first.to_text().unwrap(), format!("{}4", ghost_wire::WS_SIGNAL_GAP));

    let mut ahead = auth.ws_connect(&ws_url).await;
    ws_handshake(&mut ahead, 40).await;
    let mut seqs = Vec::new();
    while seqs.len() < 2 {
        let m = next_message(&mut ahead).await;
        if m.is_binary() {
            seqs.push(u64::from_be_bytes(m.into_data()[..8].try_into().unwrap()));
        }
    }
    assert_eq!(seqs, vec![3, 4]);
}

/// A connection whose first frame is not a resume point is closed with a frame, which
/// the client answers by reconnecting, rather than ended silently.
#[tokio::test]
async fn a_connection_without_a_resume_point_is_closed_with_a_frame() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let ws_url = format!("{}/ws/{}", base.replace("http://", "ws://"), URL_SAFE_NO_PAD.encode([0x0B; 32]));
    let mut ws = auth.ws_connect(&ws_url).await;
    ws.send(Message::text("hello")).await.unwrap();
    let mut saw_binary = false;
    assert_eq!(close_code(&mut ws, &mut saw_binary).await, Some(1002));
}

#[tokio::test]
async fn blob_size_limit() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0x04; 32]);

    let resp = auth.sign("POST", &url, vec![0u8; 2048], client.post(&url)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn invite_full_flow() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();
    let token = hex::encode([0xAB; 16]);

    // A token that is not 16 random bytes is refused.
    let reg_url = format!("{base}/invite");
    let resp = auth.post_json(&reg_url, &invite_registration("abc123", u64::MAX)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Register (authenticated)
    let resp = auth.post_json(&reg_url, &invite_registration(&token, u64::MAX)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Before any payload, a joiner asking without waiting gets nothing.
    let join_url = format!("{base}/invite/{token}/join");
    let resp = client.get(&join_url).header("X-Ghost-Long-Poll", "0").send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Join (authenticated — creator uploads initial payload)
    let resp = auth.sign("POST", &join_url, b"key-package".to_vec(), client.post(&join_url)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // Get join payload (unauthenticated — joiner downloads).
    let resp = client.get(&join_url).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"key-package");

    // The payload is set once; a second upload is refused and changes nothing.
    let resp = auth.sign("POST", &join_url, b"again".to_vec(), client.post(&join_url)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let resp = client.get(&join_url).send().await.unwrap();
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"key-package");
}

/// The relay answers a registration with the expiry it applied: the one asked for when
/// within its limit, its limit otherwise, and its limit when none is asked for.
#[tokio::test]
async fn an_invite_registration_reports_the_expiry_the_relay_applies() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let reg_url = format!("{base}/invite");
    let limit = ghost_relay::constants::MAX_INVITE_LIFETIME_MS;
    let applied = |resp: serde_json::Value| resp["expires_at"].as_u64().unwrap();

    let soon = ghost_wire::now_millis() + 60_000;
    let resp = auth.post_json(&reg_url, &invite_registration(&hex::encode([0xB1; 16]), soon)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(applied(resp.json().await.unwrap()), soon);

    let before = ghost_wire::now_millis();
    let resp = auth.post_json(&reg_url, &invite_registration(&hex::encode([0xB2; 16]), u64::MAX)).send().await.unwrap();
    let clamped = applied(resp.json().await.unwrap());
    assert!(clamped >= before + limit && clamped <= ghost_wire::now_millis() + limit, "{clamped}");

    let unset = serde_json::json!({ "token": hex::encode([0xB3; 16]), "mailbox": URL_SAFE_NO_PAD.encode(INVITE_MAILBOX) });
    let resp = auth.post_json(&reg_url, &unset).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let longest = applied(resp.json().await.unwrap());
    assert!(longest >= before + limit && longest <= ghost_wire::now_millis() + limit, "{longest}");
}

#[tokio::test]
async fn a_joiner_waiting_for_the_payload_is_woken_by_its_upload() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();
    let token = hex::encode([0xAC; 16]);
    let reg_url = format!("{base}/invite");
    auth.post_json(&reg_url, &invite_registration(&token, u64::MAX)).send().await.unwrap();

    let join_url = format!("{base}/invite/{token}/join");
    let waiting = client.get(&join_url).header("X-Ghost-Long-Poll", "5000");
    let handle = tokio::spawn(async move { waiting.send().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    auth.sign("POST", &join_url, b"key-package".to_vec(), client.post(&join_url)).send().await.unwrap();

    let resp = handle.await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"key-package");
}

#[tokio::test]
async fn expired_invite_rejected() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let client = reqwest::Client::new();

    // Register with already-expired timestamp (authenticated)
    let token = hex::encode([0xAD; 16]);
    let reg_url = format!("{base}/invite");
    auth.post_json(&reg_url, &invite_registration(&token, 1)).send().await.unwrap();

    let join_url = format!("{base}/invite/{token}/join");
    let resp = auth.sign("POST", &join_url, b"kp".to_vec(), client.post(&join_url)).send().await.unwrap();
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
    voice_group_with(base, auth, &[]).await
}

/// A group of `owner`'s account and `others`', published on the relay, whose voice rooms
/// they may all join. Returns the group's mailbox.
async fn voice_group_with(base: &str, owner: &TestAuth, others: &[&TestAuth]) -> [u8; 32] {
    let provider = OpenMlsRustCrypto::default();
    let identity = MlsTestIdentity::new(&owner.account_fp);
    let relay_vk = fetch_relay_vk(base).await;
    let (mut group, mailbox_id) = create_test_mls_group(&provider, &identity, &relay_vk);
    let group_info = export_group_info_bytes(&group, &provider, &identity.signer);
    upload_group_info(base, owner, &mailbox_id, &group_info).await;
    let url = mailbox_url(base, &mailbox_id);
    for other in others {
        let add = add_member_commit(&mut group, &provider, &identity.signer, &other.account_fp);
        let resp = owner.sign("POST", &url, add, reqwest::Client::new().post(&url)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED, "adding a member to the voice group failed");
    }
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
    let bob = TestAuth::generate();
    bob.register(&base).await;
    let ws_url = voice_url(&base, &voice_group_with(&base, &auth, &[&bob]).await, &[0x10; 32]);

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
    let mut ws_b = bob.ws_connect(&ws_url).await;
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
    assert_eq!(msg["presence"], presence_b);
    // The relay vouches for who sent the presence, from B's authenticated connection.
    assert_eq!(msg["from"]["a"], B64.encode(bob.account_fp));
    assert!(msg["from"]["d"].as_str().is_some());

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

/// The next voice message of `kind` within `wait`; `None` if none came.
async fn voice_msg_within(ws: &mut TestWs, kind: &str, wait: Duration) -> Option<Value> {
    tokio::time::timeout(wait, next_voice_msg_of(ws, kind)).await.ok()
}

#[tokio::test]
async fn voice_reception_reports_reach_only_the_sender_they_are_about() {
    let (base, _) = start_server_with_voice(test_config()).await;
    let (alice, bob, carol) = (TestAuth::generate(), TestAuth::generate(), TestAuth::generate());
    for auth in [&alice, &bob, &carol] {
        auth.register(&base).await;
    }
    let ws_url = voice_url(&base, &voice_group_with(&base, &alice, &[&bob, &carol]).await, &[0x11; 32]);
    let mut slots = Vec::new();
    let mut sockets = Vec::new();
    for (auth, presence) in [(&alice, "a"), (&bob, "b"), (&carol, "c")] {
        let mut ws = auth.ws_connect(&ws_url).await;
        let join = serde_json::json!({"type": "join", "presence": B64.encode(presence)});
        ws.send(Message::Text(join.to_string().into())).await.unwrap();
        let welcome = read_voice_msg(&mut ws).await;
        slots.push(welcome["slot_id"].as_u64().unwrap() as u32);
        sockets.push(ws);
    }
    let (slot_a, slot_b) = (slots[0], slots[1]);
    let [mut ws_a, mut ws_b, mut ws_c]: [TestWs; 3] = sockets.try_into().ok().unwrap();

    // Bob reports on Alice, on himself and on a slot nobody holds: only Alice hears, and
    // only about herself.
    let report = serde_json::json!({"type": "reception", "reports": [
        {"slot_id": slot_a, "loss_pct": 7}, {"slot_id": slot_b, "loss_pct": 50}, {"slot_id": 999, "loss_pct": 50},
    ]});
    ws_b.send(Message::Text(report.to_string().into())).await.unwrap();
    let told = voice_msg_within(&mut ws_a, "reception", Duration::from_secs(2)).await.expect("alice was told");
    assert_eq!(told, serde_json::json!({"type": "reception", "slot_id": slot_b, "loss_pct": 7}));
    assert!(voice_msg_within(&mut ws_c, "reception", Duration::from_millis(300)).await.is_none(), "carol was not reported on");
    assert!(voice_msg_within(&mut ws_b, "reception", Duration::from_millis(300)).await.is_none(), "nobody reports on bob");

    // A second report within the second is dropped.
    ws_b.send(Message::Text(report.to_string().into())).await.unwrap();
    assert!(voice_msg_within(&mut ws_a, "reception", Duration::from_millis(300)).await.is_none(), "reports are limited to one a second");
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

#[tokio::test]
async fn voice_welcome_names_the_public_port_when_configured() {
    let (base, udp_port) = start_server_with_voice(Config { voice_public_port: Some(40_123), ..test_config() }).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let ws_url = voice_url(&base, &voice_group(&base, &auth).await, &[0x11; 32]);
    let mut ws = auth.ws_connect(&ws_url).await;
    ws.send(Message::Text(serde_json::json!({"type": "join", "presence": B64.encode(b"p")}).to_string().into()))
        .await
        .unwrap();
    let welcome = read_voice_msg(&mut ws).await;
    assert_eq!(welcome["port"], 40_123);
    assert_ne!(udp_port, 40_123, "the relay still binds its own port");
}

/// Two accounts in one room, each with its UDP address bound: the relay answers each
/// bind it accepts, keyed with the slot's token.
async fn bound_voice_pair(base: &str, udp_port: u16, a: &TestAuth, b: &TestAuth, channel_id: [u8; 32]) -> VoicePair {
    let ws_url = voice_url(base, &voice_group_with(base, a, &[b]).await, &channel_id);
    let relay_addr: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();
    let (mut ws_a, slot_a, room, token_a) = join_voice(&ws_url, a, b"pa").await;
    let (ws_b, slot_b, room_b, token_b) = join_voice(&ws_url, b, b"pb").await;
    assert_eq!(room, room_b, "one channel, one room");
    // drain A's "joined" notification for B
    let _ = tokio::time::timeout(Duration::from_secs(1), read_voice_msg(&mut ws_a)).await;

    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = [0u8; 1500];
    for (sock, slot, token) in [(&sock_a, slot_a, &token_a), (&sock_b, slot_b, &token_b)] {
        let bind = VoiceBind::sign(token, room, slot, 1);
        sock.send_to(&bind.to_bytes(), relay_addr).await.unwrap();
        let len = received(sock, &mut buf).await.expect("an accepted bind was not answered");
        let answer = VoiceBind::from_bytes(&buf[..len]).expect("the answer has a bind's layout");
        assert!(answer.verify_answer(token) && answer.counter == 1, "the answer is keyed for the way back");
    }

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
    let bob = TestAuth::generate();
    bob.register(&base).await;
    let pair = bound_voice_pair(&base, udp_port, &auth, &bob, [0x20; 32]).await;
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
    let bob = TestAuth::generate();
    bob.register(&base).await;
    let pair = bound_voice_pair(&base, udp_port, &auth, &bob, [0x21; 32]).await;
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

    // Nor does the outsider receive B's media, or an answer to the binds it sent.
    let (sock_b, slot_b, _) = &pair.b;
    sock_b.send_to(&build_voice_packet(&pair.room, *slot_b, 5, b"secret"), pair.relay_addr).await.unwrap();
    assert!(received(&outsider, &mut buf).await.is_none(), "an unbound address received media or an answer");
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
    let (second, third) = (TestAuth::generate(), TestAuth::generate());
    second.register(&base).await;
    third.register(&base).await;
    let ws_url = voice_url(&base, &voice_group_with(&base, &auth, &[&second, &third]).await, &[0x30; 32]);

    // Fill to capacity
    let mut ws1 = auth.ws_connect(&ws_url).await;
    ws1.send(Message::Text(
        serde_json::json!({"type": "join", "presence": B64.encode(b"p1")}).to_string().into(),
    )).await.unwrap();
    let _ = read_voice_msg(&mut ws1).await; // welcome

    let mut ws2 = second.ws_connect(&ws_url).await;
    ws2.send(Message::Text(
        serde_json::json!({"type": "join", "presence": B64.encode(b"p2")}).to_string().into(),
    )).await.unwrap();
    let _ = read_voice_msg(&mut ws2).await; // welcome

    // Third should be rejected
    let mut ws3 = third.ws_connect(&ws_url).await;
    ws3.send(Message::Text(
        serde_json::json!({"type": "join", "presence": B64.encode(b"p3")}).to_string().into(),
    )).await.unwrap();

    let msg = tokio::time::timeout(Duration::from_secs(2), read_voice_msg(&mut ws3))
        .await
        .expect("timed out waiting for error");
    assert_eq!(msg["type"], "error");
    assert!(msg["message"].as_str().unwrap().contains("full"));
}

/// How a voice connection ended: the close code, if the relay sent one.
async fn voice_close_code(ws: &mut TestWs) -> Option<u16> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Close(frame))) => return frame.map(|f| u16::from(f.code)),
                Some(Ok(_)) => continue,
                _ => return None,
            }
        }
    })
    .await
    .expect("the connection never ended")
}

/// The next voice message of `kind`, skipping others.
async fn next_voice_msg_of(ws: &mut TestWs, kind: &str) -> Value {
    loop {
        let msg = read_voice_msg(ws).await;
        if msg["type"] == kind {
            return msg;
        }
    }
}

/// A room holds one device per account: a second device joining takes the first one's
/// place, and the first is closed with the reason.
#[tokio::test]
async fn a_second_device_of_an_account_takes_the_first_ones_place() {
    let (base, _) = start_server_with_voice(test_config()).await;
    let alice = TestAuth::generate();
    alice.register(&base).await;
    let alice_laptop = alice.add_device(&base).await;
    let bob = TestAuth::generate();
    bob.register(&base).await;
    let ws_url = voice_url(&base, &voice_group_with(&base, &alice, &[&bob]).await, &[0x12; 32]);

    let (mut bob_ws, ..) = join_voice(&ws_url, &bob, b"bob").await;
    let (mut phone, phone_slot, ..) = join_voice(&ws_url, &alice, b"phone").await;
    assert_eq!(next_voice_msg_of(&mut bob_ws, "joined").await["slot_id"], phone_slot);

    let (_laptop, laptop_slot, ..) = join_voice(&ws_url, &alice_laptop, b"laptop").await;
    assert_eq!(voice_close_code(&mut phone).await, Some(ghost_wire::WS_CLOSE_VOICE_REPLACED));
    assert_eq!(next_voice_msg_of(&mut bob_ws, "left").await["slot_id"], phone_slot);
    let joined = next_voice_msg_of(&mut bob_ws, "joined").await;
    assert_eq!(joined["slot_id"], laptop_slot);
    assert_eq!(joined["presence"], B64.encode(b"laptop"));
}

/// A device whose voice connection dropped claims its slot back on a new one with the
/// slot's token: the room hears its presence and no departure, and the connection it
/// lost can no longer end the slot.
#[tokio::test]
async fn a_dropped_voice_connection_is_resumed_on_a_new_one() {
    let (base, _) = start_server_with_voice(test_config()).await;
    let alice = TestAuth::generate();
    alice.register(&base).await;
    let bob = TestAuth::generate();
    bob.register(&base).await;
    let ws_url = voice_url(&base, &voice_group_with(&base, &alice, &[&bob]).await, &[0x13; 32]);
    let (mut bob_ws, ..) = join_voice(&ws_url, &bob, b"bob").await;
    let (mut lost, slot, _, token) = join_voice(&ws_url, &alice, b"before").await;
    next_voice_msg_of(&mut bob_ws, "joined").await;

    let mut again = alice.ws_connect(&ws_url).await;
    let resume = serde_json::json!({ "type": "resume", "slot_id": slot, "token": B64.encode(token), "presence": B64.encode(b"after") });
    again.send(Message::text(resume.to_string())).await.unwrap();
    let welcome = next_voice_msg_of(&mut again, "welcome").await;
    assert_eq!(welcome["slot_id"], slot, "the resumed connection holds the same slot");
    assert_eq!(welcome_binding(&welcome).1, token, "with the same token");
    assert_eq!(welcome["peers"].as_array().unwrap().len(), 1, "and sees the room as it is");
    let presence = read_voice_msg(&mut bob_ws).await;
    assert_eq!((presence["type"].as_str(), presence["blob"].as_str()), (Some("presence"), Some(B64.encode(b"after").as_str())));

    // The connection it lost is let go, and its end takes nothing from the room.
    assert_eq!(voice_close_code(&mut lost).await, None);
    drop(lost);
    let heard = tokio::time::timeout(Duration::from_millis(300), read_voice_msg(&mut bob_ws)).await;
    assert!(heard.is_err(), "the lost connection's end reached the room: {heard:?}");
    again.send(Message::text(serde_json::json!({ "type": "leave" }).to_string())).await.unwrap();
    assert_eq!(read_voice_msg(&mut bob_ws).await["type"], "left");
}

/// Only the slot's device, with the slot's token, claims a slot back, and only while the
/// slot lives.
#[tokio::test]
async fn a_resume_needs_the_slots_device_and_token() {
    let (base, _) = start_server_with_voice(test_config()).await;
    let alice = TestAuth::generate();
    alice.register(&base).await;
    let alice_laptop = alice.add_device(&base).await;
    let ws_url = voice_url(&base, &voice_group(&base, &alice).await, &[0x14; 32]);
    let (holder, slot, _, token) = join_voice(&ws_url, &alice, b"p").await;

    let attempt = |auth: &TestAuth, token: [u8; 32]| {
        let ws_url = ws_url.clone();
        let request = auth.ws_request(&ws_url);
        async move {
            let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
            let resume = serde_json::json!({ "type": "resume", "slot_id": slot, "token": B64.encode(token), "presence": B64.encode(b"p") });
            ws.send(Message::text(resume.to_string())).await.unwrap();
            read_voice_msg(&mut ws).await["type"].as_str().unwrap().to_string()
        }
    };
    assert_eq!(attempt(&alice, [0x55; 32]).await, "not_resumed", "a wrong token");
    assert_eq!(attempt(&alice_laptop, token).await, "not_resumed", "another device of the account");
    drop(holder);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(attempt(&alice, token).await, "not_resumed", "a slot the relay ended");
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
            genesis_verifying_key: mk.verifying_key().to_bytes(),
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
async fn idlog_refuses_a_second_genesis() {
    let base = start_server(test_config()).await;
    let client = reqwest::Client::new();
    let (fp, _mk, _dk, genesis) = make_test_genesis();

    // Valid genesis
    let resp = client.put(idlog_url(&base, &fp)).body(genesis.clone()).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Genesis again: a different claim on a held position is a conflict
    let resp = client.put(idlog_url(&base, &fp)).body(genesis).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
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
    auth.sign("POST", &url, body, client.post(&url)).send().await.unwrap().status()
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

    // Poll for response — none yet (authenticated), in a session that lives
    let resp_url = format!("{session}/response");
    let resp = auth.sign("GET", &resp_url, Vec::new(), client.get(&resp_url)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // New device posts response (unauthenticated)
    let resp = client.post(format!("{session}/respond")).body(b"encrypted-response".to_vec()).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Existing device polls — gets response, and the session stays alive
    for _ in 0..2 {
        let resp = auth.sign("GET", &resp_url, Vec::new(), client.get(&resp_url)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.bytes().await.unwrap().as_ref(), b"encrypted-response");
    }

    // Provision round trip; a redraft uploads it again, which replaces it
    let prov_url = format!("{session}/provision");
    let resp = client.get(&prov_url).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    for provision in [b"sealed-provision".as_slice(), b"after a redraft".as_slice()] {
        let resp = auth.sign("PUT", &prov_url, provision.to_vec(), client.put(&prov_url)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
    let resp = client.get(&prov_url).send().await.unwrap();
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"after a redraft");

    // The existing device ends the session: the code reaches nothing any more.
    let resp = auth.sign("DELETE", &session, Vec::new(), client.delete(&session)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(client.get(&prov_url).send().await.unwrap().status(), StatusCode::NOT_FOUND, "a gone session is told from an empty slot");
    assert_eq!(client.get(&session).send().await.unwrap().status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn only_the_accounts_device_ends_a_pairing_session() {
    let base = start_server(test_config()).await;
    let auth = TestAuth::generate();
    auth.register(&base).await;
    let stranger = TestAuth::generate();
    stranger.register(&base).await;
    let client = reqwest::Client::new();
    let token = [0x12; 16];
    open_pairing(&base, &auth, &token, b"offer").await;
    let session = session_url(&base, &auth.account_fp, &token);

    assert_eq!(client.delete(&session).send().await.unwrap().status(), StatusCode::UNAUTHORIZED, "the code alone cannot end it");
    let resp = stranger.sign("DELETE", &session, Vec::new(), client.delete(&session)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "another account cannot end it");
    assert_eq!(client.get(&session).send().await.unwrap().status(), StatusCode::OK);
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
    let resp = auth.sign("GET", &resp_url, Vec::new(), client.get(&resp_url)).send().await.unwrap();
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
            genesis_verifying_key: mk.verifying_key().to_bytes(),
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
    dk1_auth.sign("PUT", &add_url, add_bytes, client.put(&add_url)).send().await.unwrap();

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
    dk1_auth.sign("PUT", &revoke_url, revoke.to_bytes(), client.put(&revoke_url)).send().await.unwrap();

    // Revoked device 2 should be rejected
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let vk = dk2.verifying_key().to_bytes();
    let url = mailbox_url(&base, &[0xE1; 32]);
    let url_path = extract_path(&url);
    let nonce = [0x11; ghost_wire::auth::AUTH_NONCE_LEN];
    let body = test_envelope(b"revoked");
    let auth_msg = ghost_wire::auth::auth_message("POST", &url_path, &fp, &vk, timestamp, &nonce, &ghost_wire::auth::body_hash(&body));
    let sig = dk2.sign(&auth_msg);

    let resp = client
        .post(&url)
        .header("x-ghost-account", hex::encode(fp))
        .header("x-ghost-device", hex::encode(vk))
        .header("x-ghost-timestamp", timestamp.to_string())
        .header("x-ghost-nonce", hex::encode(nonce))
        .header("x-ghost-signature", hex::encode(sig.to_bytes()))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let cause = resp.headers().get(ghost_wire::REVOKED_BY_HEADER).and_then(|v| v.to_str().ok()).and_then(ghost_wire::RevocationCause::decode);
    assert_eq!(cause, Some(ghost_wire::RevocationCause::Device("d1".into())), "the refusal names the remover to the removed device");

    // Active device 1 should succeed
    let vk1 = dk1.verifying_key().to_bytes();
    let body = test_envelope(b"active");
    let auth_msg1 = ghost_wire::auth::auth_message("POST", &url_path, &fp, &vk1, timestamp, &nonce, &ghost_wire::auth::body_hash(&body));
    let sig1 = dk1.sign(&auth_msg1);

    let resp = client
        .post(&url)
        .header("x-ghost-account", hex::encode(fp))
        .header("x-ghost-device", hex::encode(vk1))
        .header("x-ghost-timestamp", timestamp.to_string())
        .header("x-ghost-nonce", hex::encode(nonce))
        .header("x-ghost-signature", hex::encode(sig1.to_bytes()))
        .body(body)
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
    let nonce = [0x22; ghost_wire::auth::AUTH_NONCE_LEN];
    let body = test_envelope(b"bad-sig");
    let auth_msg = ghost_wire::auth::auth_message("POST", &url_path, &auth.account_fp, &vk, timestamp, &nonce, &ghost_wire::auth::body_hash(&body));
    let bad_sig = wrong_key.sign(&auth_msg);

    let resp = client
        .post(&url)
        .header("x-ghost-account", hex::encode(auth.account_fp))
        .header("x-ghost-device", hex::encode(vk))
        .header("x-ghost-timestamp", timestamp.to_string())
        .header("x-ghost-nonce", hex::encode(nonce))
        .header("x-ghost-signature", hex::encode(bad_sig.to_bytes()))
        .body(body)
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
    let nonce = [0x33; ghost_wire::auth::AUTH_NONCE_LEN];
    let body = test_envelope(b"stale");
    let auth_msg = ghost_wire::auth::auth_message("POST", &path, &auth.account_fp, &vk, timestamp, &nonce, &ghost_wire::auth::body_hash(&body));
    let sig = auth.device_key.sign(&auth_msg);

    let resp = client
        .post(&url)
        .header("x-ghost-account", hex::encode(auth.account_fp))
        .header("x-ghost-device", hex::encode(vk))
        .header("x-ghost-timestamp", timestamp.to_string())
        .header("x-ghost-nonce", hex::encode(nonce))
        .header("x-ghost-signature", hex::encode(sig.to_bytes()))
        .body(body)
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
    let nonce = [0x44; ghost_wire::auth::AUTH_NONCE_LEN];
    let body = test_envelope(b"future");
    let auth_msg = ghost_wire::auth::auth_message("POST", &path, &auth.account_fp, &vk, timestamp, &nonce, &ghost_wire::auth::body_hash(&body));
    let sig = auth.device_key.sign(&auth_msg);

    let resp = client
        .post(&url)
        .header("x-ghost-account", hex::encode(auth.account_fp))
        .header("x-ghost-device", hex::encode(vk))
        .header("x-ghost-timestamp", timestamp.to_string())
        .header("x-ghost-nonce", hex::encode(nonce))
        .header("x-ghost-signature", hex::encode(sig.to_bytes()))
        .body(body)
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
    let resp = auth_b.sign("PUT", &url_b, b_state, client.put(&url_b)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Account A tries to read account B's sync state → rejected
    let resp = auth_a.sign("GET", &url_b, Vec::new(), client.get(&url_b)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Account A tries to overwrite account B's sync state → rejected
    let mut evil = 2u64.to_be_bytes().to_vec();
    evil.extend_from_slice(b"evil");
    let resp = auth_a.sign("PUT", &url_b, evil, client.put(&url_b)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
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
    let resp = auth_a.sign("PUT", &url_b, b"evil-provision".to_vec(), client.put(&url_b)).send().await.unwrap();
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
            genesis_verifying_key: mk.verifying_key().to_bytes(),
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
    let resp = dk1_auth.sign("PUT", &add_url, add.to_bytes(), client.put(&add_url)).send().await.unwrap();
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
    let resp = dk2_auth.sign("PUT", &revoke_url, revoke.to_bytes(), client.put(&revoke_url)).send().await.unwrap();
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
            assert_eq!(ghost_wire::RevocationCause::decode(&frame.reason), Some(ghost_wire::RevocationCause::Device("d2".into())), "the close names the remover");
            break;
        }
    }
}

// ── MLS enforcement test helpers ─────────────────────────────────

/// Minimal MLS identity for integration tests: a credential that names the account, as
/// a Ghost credential's first 32 bytes do.
struct MlsTestIdentity {
    account_fp: [u8; 32],
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

impl MlsTestIdentity {
    fn new(account_fp: &[u8; 32]) -> Self {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let credential = CredentialWithKey {
            credential: Credential::new(CredentialType::Basic, account_fp.to_vec()),
            signature_key: SignaturePublicKey::from(signer.public().to_vec()),
        };
        Self { account_fp: *account_fp, signer, credential }
    }
}

/// The leaf capabilities a Ghost device advertises: a group may carry only the context
/// extensions every member's leaf supports.
fn ghost_capabilities() -> Capabilities {
    let types: Vec<ExtensionType> = [
        ghost_wire::policy::SERVER_POLICY_EXTENSION,
        ghost_wire::policy::CHANNEL_POLICY_EXTENSION,
        ghost_wire::policy::SERVER_REMOVALS_EXTENSION,
    ]
    .into_iter()
    .map(ExtensionType::Unknown)
    .collect();
    Capabilities::new(None, None, Some(&types), None, None)
}

/// The mailbox of an MLS group, derived from its group id as ghost-core's
/// `wire::mls_group_mailbox_id` does.
fn test_mls_group_mailbox_id(mls_group_id: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(mls_group_id);
    hasher.update(b"ghost-mailbox");
    hasher.finalize().into()
}

/// A server group as a Ghost device makes one: the relay as external sender and a server
/// policy owned by the creator's account.
fn create_test_mls_group(
    provider: &OpenMlsRustCrypto,
    identity: &MlsTestIdentity,
    relay_vk: &[u8; 32],
) -> (MlsGroup, [u8; 32]) {
    let external_sender = ExternalSender::new(
        SignaturePublicKey::from(relay_vk.to_vec()),
        Credential::new(CredentialType::Basic, b"ghost-relay".to_vec()),
    );
    let policy = ghost_wire::policy::ServerPolicy::new(identity.account_fp);
    let extensions = Extensions::from_vec(vec![
        Extension::ExternalSenders(vec![external_sender]),
        Extension::Unknown(ghost_wire::policy::SERVER_POLICY_EXTENSION, UnknownExtension(policy.to_bytes())),
    ])
    .unwrap();
    let config = MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .max_past_epochs(1)
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .capabilities(ghost_capabilities())
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
    let resp = auth.sign("PUT", &url, group_info.to_vec(), client.put(&url))
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
    assert_eq!(body["protocol"].as_u64().unwrap(), u64::from(ghost_wire::RELAY_PROTOCOL_ACCOUNT_KEYS));
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
        .sign("POST", &url, test_envelope(b"intruder"), client.post(&url))
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
        .sign("POST", &url, test_envelope(b"hello"), client.post(&url))
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
        .sign("POST", &url, garbage_commit, client.post(&url))
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
        .sign("POST", &url, test_envelope(b"still works"), client.post(&url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn an_owner_behind_on_epochs_does_not_replace_the_newer_group_info() {
    let base = start_server(test_config()).await;
    let alice = TestAuth::generate();
    alice.register(&base).await;

    let relay_vk = fetch_relay_vk(&base).await;
    let provider = OpenMlsRustCrypto::default();
    let id = MlsTestIdentity::new(&alice.account_fp);
    let (mut group, mailbox_id) = create_test_mls_group(&provider, &id, &relay_vk);
    let stale = export_group_info_bytes(&group, &provider, &id.signer);
    upload_group_info(&base, &alice, &mailbox_id, &stale).await;

    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &mailbox_id);
    let (commit_env, current) = create_self_update_commit(&mut group, &provider, &id.signer, 0);
    let resp = alice.sign("POST", &url, commit_env, client.post(&url)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    upload_group_info(&base, &alice, &mailbox_id, &current).await;

    // Another of the owner's devices, still at epoch 0, uploads what it holds.
    upload_group_info(&base, &alice, &mailbox_id, &stale).await;

    let info_url = format!("{base}/box/{}/server_info", URL_SAFE_NO_PAD.encode(mailbox_id));
    let served = alice.sign("GET", &info_url, Vec::new(), client.get(&info_url)).send().await.unwrap().bytes().await.unwrap();
    assert_eq!(served.as_ref(), current.as_slice(), "joiners must get the epoch the relay validates against");
}

#[tokio::test]
async fn an_accounts_sync_mailbox_admits_its_devices_alone_and_takes_no_mls() {
    let (base, st) = start_server_with_state(test_config()).await;
    let alice = TestAuth::generate();
    let bob = TestAuth::generate();
    alice.register(&base).await;
    bob.register(&base).await;
    let mailbox = ghost_wire::sync_mailbox_id(&alice.account_fp);
    let url = mailbox_url(&base, &mailbox);
    let client = reqwest::Client::new();

    // Alice's device posts; the relay never saw group state for this mailbox.
    let resp = alice.sign("POST", &url, test_envelope(b"read marker"), client.post(&url)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(st.storage.read_from(mailbox, 0, 10).await.unwrap().len(), 1);

    // Bob's device is refused, posting and reading alike.
    let resp = bob.sign("POST", &url, test_envelope(b"intruder"), client.post(&url)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = tokio_tungstenite::connect_async(bob.ws_request(&format!("{}/ws/{}", base.replace("http", "ws"), URL_SAFE_NO_PAD.encode(mailbox)))).await;
    assert!(resp.is_err(), "another account's device opens no connection to the sync mailbox");

    // No MLS: a commit, a proposal and a GroupInfo upload are all refused, even from Alice.
    for typ in [ghost_wire::EnvelopeType::Commit, ghost_wire::EnvelopeType::Proposal] {
        let resp = alice.sign("POST", &url, envelope(typ, 0, b"mls"), client.post(&url)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{typ:?}");
    }
    let info_url = format!("{base}/box/{}/server_info", URL_SAFE_NO_PAD.encode(mailbox));
    let resp = alice.sign("PUT", &info_url, vec![0u8; 32], client.put(&info_url)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
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
        .sign("POST", &url, test_envelope(b"legacy"), client.post(&url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Commits are rejected without PublicGroup
    let commit_env = envelope(ghost_wire::EnvelopeType::Commit, 0, b"fake-commit");
    let resp = alice
        .sign("POST", &url, commit_env, client.post(&url))
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
        .sign("POST", &url, commit_envelope, client.post(&url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Verify ACL was updated: bob should now be a member
    assert!(st.storage.is_mailbox_member(mailbox_id, bob.account_fp).await.unwrap());
}

/// A commit whose log entry cannot be written leaves the group as it was, in storage and
/// in memory, so the same commit is taken once the log can be written again; the group
/// is not dropped to wait for a GroupInfo upload.
#[tokio::test]
async fn a_commit_whose_entry_cannot_be_written_leaves_the_group_as_it_was() {
    let (base, st) = start_server_with_state(test_config()).await;
    let alice = TestAuth::generate();
    alice.register(&base).await;
    let bob = TestAuth::generate();
    bob.register(&base).await;
    let relay_vk = fetch_relay_vk(&base).await;
    let provider = OpenMlsRustCrypto::default();
    let id_a = MlsTestIdentity::new(&alice.account_fp);
    let (mut group, mailbox_id) = create_test_mls_group(&provider, &id_a, &relay_vk);
    upload_group_info(&base, &alice, &mailbox_id, &export_group_info_bytes(&group, &provider, &id_a.signer)).await;
    let commit = add_member_commit(&mut group, &provider, &id_a.signer, &bob.account_fp);
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &mailbox_id);

    st.storage.write(|conn| conn.execute_batch("ALTER TABLE log RENAME TO log_aside").map_err(|e| ghost_relay::error::RelayError::Storage(e.to_string()))).await.unwrap();
    let resp = alice.sign("POST", &url, commit.clone(), client.post(&url)).send().await.unwrap();
    assert!(resp.status().is_server_error(), "{}", resp.status());
    st.storage.write(|conn| conn.execute_batch("ALTER TABLE log_aside RENAME TO log").map_err(|e| ghost_relay::error::RelayError::Storage(e.to_string()))).await.unwrap();

    let resp = alice.sign("POST", &url, commit, client.post(&url)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert!(st.storage.is_mailbox_member(mailbox_id, bob.account_fp).await.unwrap());
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
        .leaf_node_capabilities(ghost_capabilities())
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
    let resp = alice.sign("POST", &url, add, client.post(&url)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Bob is connected to the mailbox and to a voice room of the group.
    let ws_base = base.replace("http://", "ws://");
    let mut mailbox_ws = bob.ws_connect(&format!("{ws_base}/ws/{}", URL_SAFE_NO_PAD.encode(mailbox_id))).await;
    ws_handshake(&mut mailbox_ws, 1).await;
    consume_replay_end(&mut mailbox_ws).await;
    let (mut voice_ws, _, _, _) = join_voice(&voice_url(&base, &mailbox_id, &[0x40; 32]), &bob, b"pb").await;

    let remove = remove_member_commit(&mut group, &provider, &id_a.signer, &bob.account_fp);
    let resp = alice.sign("POST", &url, remove, client.post(&url)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let mut voice_binary = false;
    assert_eq!(close_code(&mut voice_ws, &mut voice_binary).await, Some(ghost_wire::WS_CLOSE_REMOVED));
    // The mailbox delivers the commit that removed Bob, so his device learns of it, then ends.
    let mut saw_commit = false;
    assert_eq!(close_code(&mut mailbox_ws, &mut saw_commit).await, Some(ghost_wire::WS_CLOSE_REMOVED));
    assert!(saw_commit, "the removing commit was not delivered before the close");
}

type TestWs = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// The next text frame within `within`, skipping everything else.
async fn next_text(ws: &mut TestWs, within: Duration) -> Option<String> {
    tokio::time::timeout(within, async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(t))) => return Some(t.to_string()),
                Some(Ok(_)) => continue,
                _ => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// A presence announcement as a client sends it, under `key` (`ps` or `vs`).
fn presence_announcement(key: &str, channel: Option<&[u8; 32]>, blob: Option<&[u8]>) -> String {
    let mut body = serde_json::Map::new();
    if let Some(channel) = channel {
        body.insert("ch".into(), B64.encode(channel).into());
    }
    match blob {
        Some(blob) => body.insert("p".into(), B64.encode(blob).into()),
        None => body.insert("leave".into(), true.into()),
    };
    serde_json::json!({ key: body }).to_string()
}

/// A mailbox connection for `auth`, past its catch-up and snapshots.
async fn presence_connection(ws_url: &str, auth: &TestAuth) -> TestWs {
    let mut ws = auth.ws_connect(ws_url).await;
    ws_handshake(&mut ws, 0).await;
    consume_replay_end(&mut ws).await;
    ws
}

/// The relay knows a removed member cannot come back to the mailbox, so its presence goes
/// at once rather than after the grace a blip gets.
#[tokio::test]
async fn a_removed_member_goes_offline_at_once() {
    let (base, _) = start_server_with_state(test_config()).await;
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
    assert_eq!(alice.sign("POST", &url, add, client.post(&url)).send().await.unwrap().status(), StatusCode::CREATED);

    let ws_url = format!("{}/ws/{}", base.replace("http://", "ws://"), URL_SAFE_NO_PAD.encode(mailbox_id));
    let mut alice_ws = presence_connection(&ws_url, &alice).await;
    let mut bob_ws = presence_connection(&ws_url, &bob).await;
    bob_ws.send(Message::text(presence_announcement("ps", None, Some(b"bob")))).await.unwrap();
    let online = next_text(&mut alice_ws, Duration::from_secs(2)).await.expect("bob's presence was not fanned out");
    assert!(online.contains("\"p\""), "expected bob's presence, got {online}");

    let remove = remove_member_commit(&mut group, &provider, &id_a.signer, &bob.account_fp);
    assert_eq!(alice.sign("POST", &url, remove, client.post(&url)).send().await.unwrap().status(), StatusCode::CREATED);
    let gone = next_text(&mut alice_ws, Duration::from_secs(3)).await.expect("bob stayed online after his removal");
    assert!(gone.contains("\"leave\":true") && gone.contains(&B64.encode(bob.account_fp)), "expected bob's leave, got {gone}");
}

/// One entry per device: a device back on a new connection after a blip takes over what
/// its earlier connection announced, so going invisible there takes it offline at once,
/// and announcing again rides out the grace without a leave.
#[tokio::test]
async fn a_device_back_after_a_blip_takes_over_its_presence() {
    let config = Config { presence_grace_secs: 1, ..test_config() };
    let base = start_server(config).await;
    let alice = TestAuth::generate();
    alice.register(&base).await;
    let bob = TestAuth::generate();
    bob.register(&base).await;
    let ws_url = format!("{}/ws/{}", base.replace("http://", "ws://"), URL_SAFE_NO_PAD.encode([0x05; 32]));
    let mut alice_ws = presence_connection(&ws_url, &alice).await;
    let quiet = Duration::from_millis(1600);

    // Bob drops without a close frame and comes back invisible: offline at once, and the
    // grace of the dropped connection has nothing left to withdraw.
    let mut first = presence_connection(&ws_url, &bob).await;
    first.send(Message::text(presence_announcement("ps", None, Some(b"one")))).await.unwrap();
    assert!(next_text(&mut alice_ws, Duration::from_secs(2)).await.is_some_and(|t| t.contains(&B64.encode(b"one"))));
    drop(first);
    let mut second = presence_connection(&ws_url, &bob).await;
    second.send(Message::text(presence_announcement("ps", None, None))).await.unwrap();
    let gone = next_text(&mut alice_ws, Duration::from_millis(500)).await.expect("going invisible waited for the grace");
    assert!(gone.contains("\"leave\":true"), "expected a leave, got {gone}");
    assert_eq!(next_text(&mut alice_ws, quiet).await, None, "a second leave followed the grace");

    // Bob drops again and comes back announcing: the others see the new presence and no leave.
    second.send(Message::text(presence_announcement("ps", None, Some(b"two")))).await.unwrap();
    assert!(next_text(&mut alice_ws, Duration::from_secs(2)).await.is_some_and(|t| t.contains(&B64.encode(b"two"))));
    drop(second);
    let mut third = presence_connection(&ws_url, &bob).await;
    third.send(Message::text(presence_announcement("ps", None, Some(b"three")))).await.unwrap();
    assert!(next_text(&mut alice_ws, Duration::from_secs(2)).await.is_some_and(|t| t.contains(&B64.encode(b"three"))));
    assert_eq!(next_text(&mut alice_ws, quiet).await, None, "a device that came back was withdrawn");
}

/// A connection that falls behind the fan-out of `key` announcements is sent the
/// mailbox's snapshot again, so it ends up seeing the last thing announced.
async fn a_lagging_connection_catches_up_from_a_snapshot(key: &str, snapshot_key: &str) {
    let base = start_server(test_config()).await;
    let alice = TestAuth::generate();
    alice.register(&base).await;
    let bob = TestAuth::generate();
    bob.register(&base).await;
    let ws_url = format!("{}/ws/{}", base.replace("http://", "ws://"), URL_SAFE_NO_PAD.encode([0x06; 32]));
    let mut alice_ws = presence_connection(&ws_url, &alice).await;
    let (mut bob_sink, mut bob_stream) = presence_connection(&ws_url, &bob).await.split();
    tokio::spawn(async move { while bob_stream.next().await.is_some() {} });

    // Alice reads nothing while Bob announces far more than her connection's socket and
    // fan-out hold.
    let channel = [0x41; 32];
    let channel = (key == "vs").then_some(&channel);
    let filler = vec![0xAB; 2000];
    for _ in 0..3000 {
        bob_sink.send(Message::text(presence_announcement(key, channel, Some(&filler)))).await.unwrap();
    }
    bob_sink.send(Message::text(presence_announcement(key, channel, Some(b"last")))).await.unwrap();

    let (mut snapshots, mut latest) = (0, String::new());
    while let Some(text) = next_text(&mut alice_ws, Duration::from_secs(2)).await {
        if text.starts_with(&format!("{{\"{snapshot_key}\"")) {
            snapshots += 1;
        }
        latest = text;
    }
    assert!(snapshots > 0, "alice fell behind but was never sent a snapshot");
    assert!(latest.contains(&B64.encode(b"last")), "alice did not end on bob's last announcement");
}

#[tokio::test]
async fn a_connection_behind_on_online_presence_is_sent_the_snapshot() {
    a_lagging_connection_catches_up_from_a_snapshot("ps", "ps_snap").await;
}

#[tokio::test]
async fn a_connection_behind_on_voice_state_is_sent_the_snapshot() {
    a_lagging_connection_catches_up_from_a_snapshot("vs", "vs_snap").await;
}

/// A device is in one call at most: announcing a channel takes it out of any other.
#[tokio::test]
async fn announcing_a_voice_channel_leaves_the_last_one() {
    let base = start_server(test_config()).await;
    let alice = TestAuth::generate();
    alice.register(&base).await;
    let bob = TestAuth::generate();
    bob.register(&base).await;
    let ws_url = format!("{}/ws/{}", base.replace("http://", "ws://"), URL_SAFE_NO_PAD.encode([0x07; 32]));
    let mut alice_ws = presence_connection(&ws_url, &alice).await;
    let mut bob_ws = presence_connection(&ws_url, &bob).await;
    let (first, second) = ([0x51; 32], [0x52; 32]);

    bob_ws.send(Message::text(presence_announcement("vs", Some(&first), Some(b"in")))).await.unwrap();
    assert!(next_text(&mut alice_ws, Duration::from_secs(2)).await.is_some_and(|t| t.contains(&B64.encode(first))));
    bob_ws.send(Message::text(presence_announcement("vs", Some(&second), Some(b"in")))).await.unwrap();
    let left = next_text(&mut alice_ws, Duration::from_secs(2)).await.expect("no leave for the first channel");
    assert!(left.contains(&B64.encode(first)) && left.contains("\"leave\":true"), "expected a leave of the first channel, got {left}");
    let joined = next_text(&mut alice_ws, Duration::from_secs(2)).await.expect("no announcement of the second channel");
    assert!(joined.contains(&B64.encode(second)) && joined.contains("\"p\""), "expected the second channel, got {joined}");
}

/// A device whose account was just removed cannot post a message on the connection it
/// still holds: the membership the relay checks changes with the removing commit, before
/// the connection hears of the departure.
#[tokio::test]
async fn a_removed_member_cannot_post_on_a_connection_it_still_holds() {
    let (base, state) = start_server_with_state(test_config()).await;
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
    assert_eq!(alice.sign("POST", &url, add, client.post(&url)).send().await.unwrap().status(), StatusCode::CREATED);

    let ws_base = base.replace("http://", "ws://");
    let mut ws = bob.ws_connect(&format!("{ws_base}/ws/{}", URL_SAFE_NO_PAD.encode(mailbox_id))).await;
    ws_handshake(&mut ws, 1).await;
    consume_replay_end(&mut ws).await;

    // Bob is removed and posts at once, at the epoch his message is still accepted at.
    let epoch_before = group.epoch().as_u64();
    let remove = remove_member_commit(&mut group, &provider, &id_a.signer, &bob.account_fp);
    assert_eq!(alice.sign("POST", &url, remove, client.post(&url)).send().await.unwrap().status(), StatusCode::CREATED);
    let _ = ws.send(Message::Binary(envelope(ghost_wire::EnvelopeType::Application, epoch_before, b"after removal").into())).await;

    // Whether the relay refused the post or had already closed the connection, the log
    // ends with the removal.
    let _ = tokio::time::timeout(Duration::from_secs(3), async { while ws.next().await.is_some() {} }).await;
    let entries = state.storage.read_from(mailbox_id, 0, 100).await.unwrap();
    assert!(entries.iter().all(|e| !e.payload.ends_with(b"after removal")), "a removed member's post was stored");
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
    let resp = alice.sign("GET", &url, Vec::new(), req).send().await.unwrap();
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
        .sign("PUT", &home_url, set_home.to_bytes(), client.put(&home_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Fetch the anchored chain from the home.
    let resp = alice.sign("GET", &home_url, Vec::new(), client.get(&home_url)).send().await.unwrap();
    let body: Value = resp.json().await.unwrap();
    let mut chain = Vec::new();
    for e in body["entries"].as_array().unwrap() {
        chain.extend_from_slice(&B64.decode(e["anchored"].as_str().unwrap()).unwrap());
    }

    // The mirror has never heard of Alice: her device cannot authenticate there.
    let mirror_url = format!("{mirror_base}/idlog/{}", hex::encode(alice.account_fp));
    let probe = format!("{mirror_base}/accounts/{}", hex::encode(alice.account_fp));
    let resp = alice.sign("GET", &probe, Vec::new(), client.get(&probe)).send().await.unwrap();
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
    let token = hex::encode([0xAE; 16]);
    let expires_at = ghost_relay::util::now_millis() + 60_000;
    let resp = bob.post_json(&invite_url, &invite_registration(&token, expires_at)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // With the invite the mirror validates the chain and registers Alice as a guest.
    let resp = client
        .put(format!("{mirror_url}/anchored?invite={token}"))
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
    let resp = alice.sign("GET", &probe, Vec::new(), client.get(&probe)).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = alice.sign("GET", &mirror_url, Vec::new(), client.get(&mirror_url)).send().await.unwrap();
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
        .sign("PUT", &mirror_url, add.to_bytes(), client.put(&mirror_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST, "the account is homed elsewhere");
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
    let resp = alice.sign("PUT", &url, add_bytes, client.put(&url)).send().await.unwrap();
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
    let put = |body: Vec<u8>| alice.sign("PUT", &url, body, client.put(&url));

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

// ── Account keys ──────────────────────────────────────────────────

mod account_keys {
    use super::*;
    use ghost_wire::account_key::{decode_key_sets, AccountKeySet, SealedCopy};
    use ghost_wire::batch::LogBatch;
    use ghost_wire::idlog::{validate_chain, LogEntry, LogState};
    use ghost_wire::log_entries::{
        create_account_key, create_add_device, create_device_key, create_genesis, create_recovery, create_rotate_root,
    };

    fn batch_url(base: &str, fp: &[u8; 32]) -> String {
        format!("{base}/idlog/{}/batch", hex::encode(fp))
    }

    /// A set for the generation after `state`'s, with a stand-in copy for everyone
    /// `state` must cover; relays never open copies.
    fn stand_in_key_set(state: &LogState) -> AccountKeySet {
        AccountKeySet {
            account_fp: state.account_fp,
            generation: state.account_key().map_or(1, |k| k.generation + 1),
            copies: state
                .coverage()
                .into_iter()
                .map(|recipient| SealedCopy { recipient, encapsulated_key: [0x5A; 32], ciphertext: vec![0xA5; 48] })
                .collect(),
            back_link: None,
        }
    }

    async fn post_batch(base: &str, fp: &[u8; 32], batch: &LogBatch, auth: Option<&TestAuth>) -> reqwest::Response {
        let url = batch_url(base, fp);
        let body = batch.to_bytes();
        let req = reqwest::Client::new().post(&url);
        let req = match auth {
            Some(auth) => auth.sign("POST", &url, body, req),
            None => req.body(body),
        };
        req.send().await.unwrap()
    }

    /// Create `auth`'s account at `base` the way new clients do: genesis, the device's
    /// encryption key, a rotation to `root` and the first account key, in one batch.
    async fn create_rotated(base: &str, auth: &TestAuth, root: &SigningKey) -> Vec<LogEntry> {
        let mut entries = vec![create_genesis(&auth.master_key, &auth.device_key, "test")];
        entries.push(create_device_key(&validate_chain(&entries).unwrap(), &auth.device_key, &auth.device_key, [0x01; 32]));
        entries.push(create_rotate_root(&validate_chain(&entries).unwrap(), &auth.master_key, root, [0x02; 32], &auth.device_key));
        let state = validate_chain(&entries).unwrap();
        let set = stand_in_key_set(&state);
        entries.push(create_account_key(&state, &auth.device_key, &SigningKey::generate(&mut OsRng), [0x03; 32], &set));
        let batch = LogBatch { entries: entries.clone(), key_sets: vec![set] };
        let resp = post_batch(base, &auth.account_fp, &batch, None).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let anchors = ghost_wire::anchor::decode_sequence(&resp.bytes().await.unwrap()).unwrap();
        assert_eq!(anchors.len(), entries.len(), "one anchor per entry");
        entries
    }

    async fn idlog_len(base: &str, auth: &TestAuth) -> usize {
        let url = idlog_url(base, &auth.account_fp);
        let resp = auth.sign("GET", &url, Vec::new(), reqwest::Client::new().get(&url)).send().await.unwrap();
        let body: Value = resp.json().await.unwrap();
        body["entries"].as_array().unwrap().len()
    }

    #[tokio::test]
    async fn a_batch_is_all_or_nothing() {
        let base = start_server(test_config()).await;
        let alice = TestAuth::generate();
        let root = SigningKey::generate(&mut OsRng);
        let entries = create_rotated(&base, &alice, &root).await;

        // Adding a device brings it into coverage, so the batch needs an account key and its set.
        let phone = SigningKey::generate(&mut OsRng);
        let mut chain = entries.clone();
        chain.push(create_add_device(&validate_chain(&chain).unwrap(), &alice.device_key, &phone, "phone"));
        chain.push(create_device_key(&validate_chain(&chain).unwrap(), &alice.device_key, &phone, [0x04; 32]));
        let state = validate_chain(&chain).unwrap();
        let set = stand_in_key_set(&state);
        chain.push(create_account_key(&state, &alice.device_key, &SigningKey::generate(&mut OsRng), [0x05; 32], &set));
        let tail = chain[entries.len()..].to_vec();

        let without_set = LogBatch { entries: tail.clone(), key_sets: Vec::new() };
        let resp = post_batch(&base, &alice.account_fp, &without_set, Some(&alice)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(idlog_len(&base, &alice).await, entries.len(), "nothing from the refused batch landed");

        let with_set = LogBatch { entries: tail, key_sets: vec![set] };
        let resp = post_batch(&base, &alice.account_fp, &with_set, Some(&alice)).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(idlog_len(&base, &alice).await, chain.len());
    }

    #[tokio::test]
    async fn rate_limits_count_only_valid_recoveries() {
        let base = start_server(test_config()).await;
        let alice = TestAuth::generate();
        let root = SigningKey::generate(&mut OsRng);
        let mut chain = create_rotated(&base, &alice, &root).await;

        // Recoveries signed by the genesis key, no longer the root, never count.
        for _ in 0..5 {
            let junk = create_recovery(&validate_chain(&chain).unwrap(), &alice.master_key, &SigningKey::generate(&mut OsRng), "junk");
            let resp = post_batch(&base, &alice.account_fp, &LogBatch { entries: vec![junk], key_sets: Vec::new() }, None).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }

        // Real recoveries spend the budget of three a day.
        for attempt in 0..4 {
            let recovery = create_recovery(&validate_chain(&chain).unwrap(), &root, &SigningKey::generate(&mut OsRng), "owner");
            let resp = post_batch(&base, &alice.account_fp, &LogBatch { entries: vec![recovery.clone()], key_sets: Vec::new() }, None).await;
            if attempt < 3 {
                assert_eq!(resp.status(), StatusCode::CREATED, "recovery {attempt}");
                chain.push(recovery);
            } else {
                assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
                // The first of the three leaves the day's window in a little under a day.
                let wait: u64 = resp.headers()[reqwest::header::RETRY_AFTER].to_str().unwrap().parse().unwrap();
                assert!((23 * 3600..=24 * 3600).contains(&wait), "Retry-After {wait}");
            }
        }
    }

    #[tokio::test]
    async fn a_rotated_away_root_reads_nothing_and_by_root_finds_the_account() {
        let base = start_server(test_config()).await;
        let alice = TestAuth::generate();
        let root = SigningKey::generate(&mut OsRng);
        create_rotated(&base, &alice, &root).await;
        let client = reqwest::Client::new();

        let url = idlog_url(&base, &alice.account_fp);
        let as_genesis = sign_as(&alice.account_fp, &alice.master_key, "GET", &url, Vec::new(), client.get(&url)).send().await.unwrap();
        assert_eq!(as_genesis.status(), StatusCode::UNAUTHORIZED, "the genesis key reads nothing once rotated");
        let as_root = sign_as(&alice.account_fp, &root, "GET", &url, Vec::new(), client.get(&url)).send().await.unwrap();
        assert_eq!(as_root.status(), StatusCode::OK);

        let lookup = format!("{base}/accounts/by_root");
        let found = client
            .get(&lookup)
            .header(ghost_wire::auth::ROOT_AUTH_HEADER, ghost_wire::auth::sign_root_auth("GET", "/accounts/by_root", &root))
            .send()
            .await
            .unwrap();
        assert_eq!(found.status(), StatusCode::OK);
        let body: Value = found.json().await.unwrap();
        assert_eq!(body["account_fp"].as_str().unwrap(), hex::encode(alice.account_fp));

        let stale = client
            .get(&lookup)
            .header(ghost_wire::auth::ROOT_AUTH_HEADER, ghost_wire::auth::sign_root_auth("GET", "/accounts/by_root", &alice.master_key))
            .send()
            .await
            .unwrap();
        assert_eq!(stale.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn single_entries_are_refused_after_rotation() {
        let base = start_server(test_config()).await;
        let alice = TestAuth::generate();
        let root = SigningKey::generate(&mut OsRng);
        let chain = create_rotated(&base, &alice, &root).await;
        let client = reqwest::Client::new();

        let url = idlog_url(&base, &alice.account_fp);
        let add = create_add_device(&validate_chain(&chain).unwrap(), &alice.device_key, &SigningKey::generate(&mut OsRng), "phone");
        let resp = alice.sign("PUT", &url, add.to_bytes(), client.put(&url)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::GONE);
    }

    #[tokio::test]
    async fn key_sets_are_for_the_account_alone() {
        let base = start_server(test_config()).await;
        let alice = TestAuth::generate();
        let root = SigningKey::generate(&mut OsRng);
        create_rotated(&base, &alice, &root).await;
        let bob = TestAuth::generate();
        bob.register(&base).await;
        let client = reqwest::Client::new();

        let url = format!("{base}/accounts/{}/key_sets", hex::encode(alice.account_fp));
        let resp = alice.sign("GET", &url, Vec::new(), client.get(&url)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let sets = decode_key_sets(&resp.bytes().await.unwrap()).unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].generation, 1);

        let resp = bob.sign("GET", &url, Vec::new(), client.get(&url)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "another account's device");

        // A relay that holds no matching entry stores nothing.
        let other = start_server(test_config()).await;
        let other_url = format!("{other}/accounts/{}/key_sets", hex::encode(alice.account_fp));
        let resp = client.put(&other_url).body(ghost_wire::account_key::encode_key_sets(&sets)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn a_new_pairing_draft_clears_the_old_signature() {
        let base = start_server(test_config()).await;
        let alice = TestAuth::generate();
        alice.register(&base).await;
        let token = [0x42u8; 16];
        assert_eq!(open_pairing(&base, &alice, &token, b"offer").await, StatusCode::CREATED);
        let client = reqwest::Client::new();
        let draft_url = format!("{}/draft", session_url(&base, &alice.account_fp, &token));
        let signatures_url = format!("{}/signatures", session_url(&base, &alice.account_fp, &token));

        let resp = alice.sign("PUT", &draft_url, b"draft one".to_vec(), client.put(&draft_url)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(client.get(&draft_url).send().await.unwrap().bytes().await.unwrap().as_ref(), b"draft one");
        let resp = client.post(&signatures_url).body(b"signed one".to_vec()).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = client.post(&signatures_url).body(b"replaced".to_vec()).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "one signature per draft");

        let resp = alice.sign("PUT", &draft_url, b"draft two".to_vec(), client.put(&draft_url)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = alice.sign("GET", &signatures_url, Vec::new(), client.get(&signatures_url)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT, "the old signature went with the old draft");
        let resp = client.post(&signatures_url).body(b"signed two".to_vec()).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = alice.sign("GET", &signatures_url, Vec::new(), client.get(&signatures_url)).send().await.unwrap();
        assert_eq!(resp.bytes().await.unwrap().as_ref(), b"signed two");
    }
}
