use tokio::net::TcpListener;

use ghost_relay::config::Config;
use ghost_relay::storage::Storage;
use ghost_relay::{routes, state};

pub async fn start_relay() -> String {
    let config = Config {
        port: 0,
        max_blob_size: 10 * 1024 * 1024,
        voice_port: 0,
        max_voice_participants: 25,
    };
    let storage = Storage::open_in_memory().unwrap();
    let st = state::new_state(config, storage);
    let app = routes::router(st);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://127.0.0.1:{port}")
}

/// Push a genesis identity log entry for a seed-based identity and configure
/// the relay client with auth headers. For seed-based identities, the master
/// key and device key are the same.
pub async fn setup_relay_auth(
    relay_url: &str,
    relay: &mut ghost_core::relay::RelayClient,
    client: &ghost_core::client::GhostClient,
) {
    use ed25519_dalek::Signer;

    let fp = *client.fingerprint();
    let vk_bytes = client.verifying_key_bytes();
    let sk = client.signing_key_clone();

    // Build genesis entry where master key == device key (seed-based identity)
    let mut entry = ghost_wire::idlog::LogEntry {
        seq: 1,
        prev_hash: [0u8; 32],
        account_fp: fp,
        entry_type: ghost_wire::idlog::EntryType::Genesis,
        timestamp: 1000,
        body: ghost_wire::idlog::EntryBody::Genesis {
            master_verifying_key: vk_bytes,
            device_verifying_key: vk_bytes,
            device_label: "test".to_string(),
        },
        signature: [0u8; 64],
        counter_signature: None,
    };
    let msg = ghost_wire::idlog::sign_message(&entry);
    entry.signature = sk.sign(&msg).to_bytes();
    entry.counter_signature = Some(sk.sign(&msg).to_bytes());

    // Push genesis via HTTP
    let http = reqwest::Client::new();
    let url = format!("{}/idlog/{}", relay_url, hex::encode(fp));
    let resp = http.put(url).body(entry.to_bytes()).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED, "genesis push failed");

    // Configure relay client auth
    relay.set_auth(fp, vk_bytes, sk);
}
