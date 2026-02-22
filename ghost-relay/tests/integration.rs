use std::net::SocketAddr;
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use reqwest::StatusCode;
use serde_json::Value;
use tokio::net::{TcpListener, UdpSocket};
use tokio_tungstenite::tungstenite::Message;

use ghost_relay::config::Config;
use ghost_relay::storage::Storage;
use ghost_relay::{routes, state, udp};

async fn start_server(config: Config) -> String {
    start_server_with_state(config).await.0
}

async fn start_server_with_state(config: Config) -> (String, state::AppState) {
    let storage = Storage::open_in_memory().unwrap();
    let st = state::new_state(config, storage);
    let app = routes::router(st.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://127.0.0.1:{port}"), st)
}

/// Starts relay with UDP voice loop. Returns (http_base_url, udp_port).
async fn start_server_with_voice(config: Config) -> (String, u16) {
    let storage = Storage::open_in_memory().unwrap();
    let st = state::new_state(config, storage);
    let mut voice_rx = st.voice_udp_port_rx.clone();
    tokio::spawn(udp::run(st.clone()));
    let app = routes::router(st);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    voice_rx.changed().await.unwrap();
    let udp_port = *voice_rx.borrow();
    (format!("http://127.0.0.1:{port}"), udp_port)
}

fn test_config() -> Config {
    Config {
        port: 0,
        max_blob_size: 1024,
        ttl: Duration::from_secs(3600),
        voice_port: 0,
        max_voice_participants: 25,
    }
}

fn mailbox_url(base: &str, id: &[u8; 32]) -> String {
    format!("{base}/box/{}", URL_SAFE_NO_PAD.encode(id))
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

#[tokio::test]
async fn health() {
    let base = start_server(test_config()).await;
    let resp = reqwest::get(format!("{base}/health")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body["uptime_secs"].is_number());
}

#[tokio::test]
async fn blob_post_and_get() {
    let base = start_server(test_config()).await;
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0x01; 32]);

    // POST
    let resp = client.post(&url).body(test_envelope(b"hello")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["seq"], 1);

    // GET returns it
    let blobs: Vec<Value> = client.get(&url).send().await.unwrap().json().await.unwrap();
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0]["seq"], 1);

    // POST another
    let resp = client.post(&url).body(test_envelope(b"world")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["seq"], 2);

    // GET with after=1 returns only second
    let blobs: Vec<Value> = client
        .get(format!("{url}?after=1"))
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
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0x02; 32]);

    let get_client = client.clone();
    let get_url = url.clone();
    let handle = tokio::spawn(async move {
        get_client
            .get(&get_url)
            .header("X-Ghost-Long-Poll", "5000")
            .send()
            .await
            .unwrap()
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    client.post(&url).body(test_envelope(b"wake")).send().await.unwrap();

    let resp = handle.await.unwrap();
    let blobs: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(blobs.len(), 1);
}

#[tokio::test]
async fn ws_fanout() {
    let base = start_server(test_config()).await;
    let ws_base = base.replace("http://", "ws://");
    let mailbox = URL_SAFE_NO_PAD.encode([0x03; 32]);
    let ws_url = format!("{ws_base}/ws/{mailbox}");

    let (mut ws_a, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    let (mut ws_b, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
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
    let ws_base = base.replace("http://", "ws://");
    let mailbox = URL_SAFE_NO_PAD.encode([0x08; 32]);
    let ws_url = format!("{ws_base}/ws/{mailbox}");

    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
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

    // Send commit at epoch 0 — advances relay to epoch 1
    ws.send(Message::Binary(envelope(EnvelopeType::Commit, 0, b"commit").into())).await.unwrap();
    let ack = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let m = ws.next().await.unwrap().unwrap();
            if let Message::Text(t) = m { break t.to_string(); }
        }
    }).await.expect("timed out");
    assert_eq!(ack, "2");

    // Send at stale epoch 0 — relay is at 1, expect mismatch hint
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
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0x06; 32]);

    let resp = client.post(&url).body(b"not an envelope".to_vec()).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn epoch_gating() {
    use ghost_wire::EnvelopeType;

    let base = start_server(test_config()).await;
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0x07; 32]);

    // Application at epoch 0 — relay epoch is 0, no mismatch
    let body: Value = client.post(&url)
        .body(envelope(EnvelopeType::Application, 0, b"msg1"))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(body["seq"], 1);
    assert!(body.get("epoch_mismatch").is_none());

    // Commit at epoch 0 — advances relay epoch to 1
    let body: Value = client.post(&url)
        .body(envelope(EnvelopeType::Commit, 0, b"commit"))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(body["seq"], 2);
    assert!(body.get("epoch_mismatch").is_none());

    // Application at epoch 1 — matches new relay epoch
    let body: Value = client.post(&url)
        .body(envelope(EnvelopeType::Application, 1, b"msg2"))
        .send().await.unwrap().json().await.unwrap();
    assert!(body.get("epoch_mismatch").is_none());

    // Application at epoch 0 — stale, relay expects 1
    let body: Value = client.post(&url)
        .body(envelope(EnvelopeType::Application, 0, b"stale"))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(body["epoch_mismatch"], true);

    // Blob was still stored despite mismatch
    let blobs: Vec<Value> = client.get(&url).send().await.unwrap().json().await.unwrap();
    assert_eq!(blobs.len(), 4);

    // Stale commit at epoch 0 — relay stays at 1 (MAX prevents backward)
    let body: Value = client.post(&url)
        .body(envelope(EnvelopeType::Commit, 0, b"stale-commit"))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(body["epoch_mismatch"], true);

    // Application at epoch 1 still matches — relay didn't go backward
    let body: Value = client.post(&url)
        .body(envelope(EnvelopeType::Application, 1, b"still-ok"))
        .send().await.unwrap().json().await.unwrap();
    assert!(body.get("epoch_mismatch").is_none());

    // Commit at epoch 5 — relay jumps from 1 to 6
    let body: Value = client.post(&url)
        .body(envelope(EnvelopeType::Commit, 5, b"future-commit"))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(body["epoch_mismatch"], true); // 5 != 1

    // Application at epoch 6 — matches the jumped relay epoch
    let body: Value = client.post(&url)
        .body(envelope(EnvelopeType::Application, 6, b"after-jump"))
        .send().await.unwrap().json().await.unwrap();
    assert!(body.get("epoch_mismatch").is_none());
}

#[tokio::test]
async fn ws_catchup_replay() {
    let base = start_server(test_config()).await;
    let client = reqwest::Client::new();
    let mailbox_id = [0x09; 32];
    let url = mailbox_url(&base, &mailbox_id);
    let ws_base = base.replace("http://", "ws://");
    let mailbox = URL_SAFE_NO_PAD.encode(mailbox_id);
    let ws_url = format!("{ws_base}/ws/{mailbox}");

    // Post 3 blobs via HTTP
    for i in 0..3u8 {
        let resp = client.post(&url).body(test_envelope(&[i])).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // Connect with last_seen=0 — should replay all 3
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
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
    let (mut ws2, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
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
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0x04; 32]);

    let resp = client.post(&url).body(vec![0u8; 2048]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn invite_full_flow() {
    let base = start_server(test_config()).await;
    let client = reqwest::Client::new();

    // Register
    let resp = client
        .post(format!("{base}/invite"))
        .json(&serde_json::json!({ "token": "abc123", "expires_at": u64::MAX }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Join
    let resp = client
        .post(format!("{base}/invite/abc123/join"))
        .body(b"key-package".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    // Get join payload
    let resp = client.get(format!("{base}/invite/abc123/join")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"key-package");

    // Accept
    let resp = client
        .post(format!("{base}/invite/abc123/accept"))
        .body(b"welcome".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Get accept payload
    let resp = client.get(format!("{base}/invite/abc123/accept")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"welcome");
}

#[tokio::test]
async fn expired_invite_rejected() {
    let base = start_server(test_config()).await;
    let client = reqwest::Client::new();

    // Register with already-expired timestamp
    client
        .post(format!("{base}/invite"))
        .json(&serde_json::json!({ "token": "expired", "expires_at": 1 }))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/invite/expired/join"))
        .body(b"kp".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::GONE);
}

// --- Voice tests ---

fn build_voice_packet(
    channel_id: &[u8; 32],
    slot_id: u32,
    sequence: u32,
    payload: &[u8],
) -> Vec<u8> {
    let header_len = ghost_wire::VOICE_HEADER_SIZE as u16;
    [
        &header_len.to_be_bytes()[..],
        channel_id,
        &slot_id.to_be_bytes()[..],
        &[0x00], // flags
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

#[tokio::test]
async fn voice_signaling_join_leave() {
    let (base, _) = start_server_with_voice(test_config()).await;
    let ws_base = base.replace("http://", "ws://");
    let channel_id = [0x10; 32];
    let channel_b64 = URL_SAFE_NO_PAD.encode(channel_id);
    let ws_url = format!("{ws_base}/voice/{channel_b64}");

    let presence_a = B64.encode(b"opaque-presence-a");
    let presence_b = B64.encode(b"opaque-presence-b");

    // A joins
    let (mut ws_a, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    let join_a = serde_json::json!({"type": "join", "presence": presence_a});
    ws_a.send(Message::Text(join_a.to_string().into())).await.unwrap();

    // A gets Welcome (no peers, has slot_id and port)
    let msg = read_voice_msg(&mut ws_a).await;
    assert_eq!(msg["type"], "welcome");
    assert!(msg["slot_id"].as_u64().unwrap() > 0);
    assert!(msg["port"].as_u64().is_some());
    assert_eq!(msg["peers"].as_array().unwrap().len(), 0);

    // B joins
    let (mut ws_b, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
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

#[tokio::test]
async fn voice_udp_forwarding() {
    let (base, udp_port) = start_server_with_voice(test_config()).await;
    let ws_base = base.replace("http://", "ws://");
    let channel_id = [0x20; 32];
    let channel_b64 = URL_SAFE_NO_PAD.encode(channel_id);
    let ws_url = format!("{ws_base}/voice/{channel_b64}");

    let relay_addr: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();

    // Both join via signaling — extract slot_ids from Welcome
    let (mut ws_a, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws_a.send(Message::Text(
        serde_json::json!({"type": "join", "presence": B64.encode(b"pa")}).to_string().into(),
    )).await.unwrap();
    let msg_a = read_voice_msg(&mut ws_a).await; // welcome
    let slot_a = msg_a["slot_id"].as_u64().unwrap() as u32;

    let (mut ws_b, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws_b.send(Message::Text(
        serde_json::json!({"type": "join", "presence": B64.encode(b"pb")}).to_string().into(),
    )).await.unwrap();
    let msg_b = read_voice_msg(&mut ws_b).await; // welcome
    let slot_b = msg_b["slot_id"].as_u64().unwrap() as u32;

    // drain A's "joined" notification for B
    let _ = tokio::time::timeout(Duration::from_secs(1), read_voice_msg(&mut ws_a)).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    // A sends initial UDP packet to register its address
    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let pkt_a = build_voice_packet(&channel_id, slot_a, 1, b"opus-from-a");
    sock_a.send_to(&pkt_a, relay_addr).await.unwrap();

    // B sends initial UDP packet to register its address
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let pkt_b = build_voice_packet(&channel_id, slot_b, 1, b"opus-from-b");
    sock_b.send_to(&pkt_b, relay_addr).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Drain any forwarded packets from registration
    let mut recv_buf = [0u8; 1500];
    while tokio::time::timeout(Duration::from_millis(100), sock_a.recv_from(&mut recv_buf))
        .await
        .is_ok()
    {}

    // A sends another packet — B should receive it
    let pkt_a2 = build_voice_packet(&channel_id, slot_a, 2, b"frame-2");
    sock_a.send_to(&pkt_a2, relay_addr).await.unwrap();

    let (len, _) = tokio::time::timeout(Duration::from_secs(2), sock_b.recv_from(&mut recv_buf))
        .await
        .expect("timed out waiting for forwarded packet")
        .unwrap();

    // Verify slot_id and payload
    let recv_slot = u32::from_be_bytes(recv_buf[34..38].try_into().unwrap());
    assert_eq!(recv_slot, slot_a);
    let hdr = ghost_wire::VOICE_HEADER_SIZE;
    assert_eq!(&recv_buf[hdr..len], b"frame-2");

    // A should NOT receive its own packet back
    let result = tokio::time::timeout(Duration::from_millis(200), sock_a.recv_from(&mut recv_buf)).await;
    assert!(result.is_err(), "sender should not receive own packet");
}

#[tokio::test]
async fn voice_max_participants() {
    let mut config = test_config();
    config.max_voice_participants = 2;
    let (base, _) = start_server_with_voice(config).await;
    let ws_base = base.replace("http://", "ws://");
    let channel_id = [0x30; 32];
    let channel_b64 = URL_SAFE_NO_PAD.encode(channel_id);
    let ws_url = format!("{ws_base}/voice/{channel_b64}");

    // Fill to capacity
    let (mut ws1, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws1.send(Message::Text(
        serde_json::json!({"type": "join", "presence": B64.encode(b"p1")}).to_string().into(),
    )).await.unwrap();
    let _ = read_voice_msg(&mut ws1).await; // welcome

    let (mut ws2, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws2.send(Message::Text(
        serde_json::json!({"type": "join", "presence": B64.encode(b"p2")}).to_string().into(),
    )).await.unwrap();
    let _ = read_voice_msg(&mut ws2).await; // welcome

    // Third should be rejected
    let (mut ws3, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws3.send(Message::Text(
        serde_json::json!({"type": "join", "presence": B64.encode(b"p3")}).to_string().into(),
    )).await.unwrap();

    let msg = tokio::time::timeout(Duration::from_secs(2), read_voice_msg(&mut ws3))
        .await
        .expect("timed out waiting for error");
    assert_eq!(msg["type"], "error");
    assert!(msg["message"].as_str().unwrap().contains("full"));
}

// --- ServerInfo tests ---

#[tokio::test]
async fn server_info_put_get() {
    let base = start_server(test_config()).await;
    let client = reqwest::Client::new();
    let mailbox_id = URL_SAFE_NO_PAD.encode([0xDD; 32]);

    let resp = client
        .put(format!("{base}/box/{mailbox_id}/server_info"))
        .body(b"group-info-bytes".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = client
        .get(format!("{base}/box/{mailbox_id}/server_info"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"group-info-bytes");
}

#[tokio::test]
async fn server_info_not_found() {
    let base = start_server(test_config()).await;
    let client = reqwest::Client::new();
    let mailbox_id = URL_SAFE_NO_PAD.encode([0xEE; 32]);

    let resp = client
        .get(format!("{base}/box/{mailbox_id}/server_info"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn server_info_overwrite() {
    let base = start_server(test_config()).await;
    let client = reqwest::Client::new();
    let mailbox_id = URL_SAFE_NO_PAD.encode([0xFF; 32]);

    client
        .put(format!("{base}/box/{mailbox_id}/server_info"))
        .body(b"v1".to_vec())
        .send()
        .await
        .unwrap();

    client
        .put(format!("{base}/box/{mailbox_id}/server_info"))
        .body(b"v2".to_vec())
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{base}/box/{mailbox_id}/server_info"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"v2");
}

// --- Gap detection tests ---

#[tokio::test]
async fn ws_gap_indicator() {
    let (base, st) = start_server_with_state(test_config()).await;
    let client = reqwest::Client::new();
    let mailbox_id = [0xAB; 32];
    let url = mailbox_url(&base, &mailbox_id);
    let ws_base = base.replace("http://", "ws://");
    let mailbox_b64 = URL_SAFE_NO_PAD.encode(mailbox_id);
    let ws_url = format!("{ws_base}/ws/{mailbox_b64}");

    // Post blobs, then sweep them to simulate TTL expiry
    for i in 0..3u8 {
        client.post(&url).body(test_envelope(&[i])).send().await.unwrap();
    }
    st.storage.sweep_expired(i64::MAX as u64).unwrap();

    // Connect with last_seen=1 — blobs are gone, should get "gap"
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws_handshake(&mut ws, 1).await;

    let msg = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let m = ws.next().await.unwrap().unwrap();
            if let Message::Text(t) = m { break t; }
        }
    })
    .await
    .expect("timed out waiting for gap indicator");
    assert_eq!(msg.as_str(), "gap");
}

#[tokio::test]
async fn ws_no_gap_on_fresh_subscribe() {
    let (base, st) = start_server_with_state(test_config()).await;
    let client = reqwest::Client::new();
    let mailbox_id = [0xAC; 32];
    let url = mailbox_url(&base, &mailbox_id);
    let ws_base = base.replace("http://", "ws://");
    let mailbox_b64 = URL_SAFE_NO_PAD.encode(mailbox_id);
    let ws_url = format!("{ws_base}/ws/{mailbox_b64}");

    // Post and sweep
    client.post(&url).body(test_envelope(&[0])).send().await.unwrap();
    st.storage.sweep_expired(i64::MAX as u64).unwrap();

    // Connect with last_seen=0 — first subscribe, no gap expected
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws_handshake(&mut ws, 0).await;
    consume_vs_snap(&mut ws).await;

    // Should not receive any text "gap" — only pings should arrive
    let result = tokio::time::timeout(Duration::from_millis(200), async {
        loop {
            let m = ws.next().await.unwrap().unwrap();
            if let Message::Text(t) = m { return t; }
        }
    })
    .await;
    assert!(result.is_err(), "should not receive gap on fresh subscribe");
}
