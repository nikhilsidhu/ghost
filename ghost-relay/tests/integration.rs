use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use reqwest::StatusCode;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

use ghost_relay::config::Config;
use ghost_relay::{routes, state};

async fn start_server(config: Config) -> String {
    let st = state::new_state(config);
    let app = routes::router(st);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://127.0.0.1:{port}")
}

fn test_config() -> Config {
    Config {
        port: 0,
        max_blob_size: 1024,
        max_memory: 4096,
        ttl: Duration::from_secs(3600),
    }
}

fn mailbox_url(base: &str, id: &[u8; 32]) -> String {
    format!("{base}/box/{}", URL_SAFE_NO_PAD.encode(id))
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
async fn blob_post_get_delete() {
    let base = start_server(test_config()).await;
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0x01; 32]);

    // POST
    let resp = client.post(&url).body(b"hello".to_vec()).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let blob_id = resp.json::<Value>().await.unwrap()["blob_id"]
        .as_str()
        .unwrap()
        .to_string();

    // GET returns it
    let blobs: Vec<Value> = client.get(&url).send().await.unwrap().json().await.unwrap();
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0]["blob_id"], blob_id);

    // DELETE
    let resp = client.delete(format!("{url}/{blob_id}")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // GET returns empty
    let blobs: Vec<Value> = client.get(&url).send().await.unwrap().json().await.unwrap();
    assert!(blobs.is_empty());
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
    client.post(&url).body(b"wake".to_vec()).send().await.unwrap();

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

    tokio::time::sleep(Duration::from_millis(50)).await;

    // A sends a binary blob
    ws_a.send(Message::Binary(b"from-a".to_vec().into())).await.unwrap();

    // B receives: 16-byte UUID + 8-byte timestamp + payload (skip pings)
    let data = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let m = ws_b.next().await.unwrap().unwrap();
            if m.is_binary() { break m.into_data(); }
        }
    })
    .await
    .expect("timed out waiting for fan-out");
    assert_eq!(&data[24..], b"from-a");
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
async fn memory_limit() {
    let mut config = test_config();
    config.max_memory = 100;
    let base = start_server(config).await;
    let client = reqwest::Client::new();
    let url = mailbox_url(&base, &[0x05; 32]);

    let resp = client.post(&url).body(vec![0u8; 80]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = client.post(&url).body(vec![0u8; 80]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::INSUFFICIENT_STORAGE);
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
