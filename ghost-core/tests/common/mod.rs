use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use ghost_core::client::GhostClient;
use ghost_core::flows;
use ghost_core::flows::pairing::{PairingCode, PairingOffer};
use ghost_core::identity::Identity;
use ghost_core::relay::RelayClient;
use ghost_core::storage::ServerKind;
use tokio::sync::Mutex;

use ghost_relay::config::Config;
use ghost_relay::storage::Storage;

/// An in-process relay that serves until the test process ends (dropping the handle
/// detaches its tasks without stopping them).
pub async fn start_relay() -> String {
    start_relay_with_handle().await.url()
}

/// An in-process relay, started exactly as the binary starts it, that a test can stop
/// to simulate the relay disappearing: new connections to its address fail afterwards.
#[allow(dead_code)]
pub async fn start_relay_with_handle() -> ghost_relay::server::RunningRelay {
    let config = Config {
        port: 0,
        max_blob_size: 10 * 1024 * 1024,
        voice_port: 0,
        max_voice_participants: 25,
        db_path: None,
        log_retention_hours: 72,
        log_min_entries: 100,
        public_url: None,
        mirror_refresh_secs: 1,
    };
    let storage = Storage::open_in_memory().unwrap();
    ghost_relay::server::start(config, storage, ([127, 0, 0, 1], 0).into()).await.unwrap()
}

/// Push a genesis identity log entry for a seed-based identity and configure
/// the relay client with auth headers. For seed-based identities, the master
/// key and device key are the same.
#[allow(dead_code)]
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

pub type Shared<T> = Arc<Mutex<T>>;

pub const POLL_ATTEMPTS: usize = 20;
pub const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// A freshly created account whose genesis entry is on the relay and whose first
/// device holds an authenticated relay client.
#[allow(dead_code)]
pub struct Account {
    pub fp: [u8; 32],
    pub seed: [u8; 32],
    pub genesis: Vec<u8>,
    pub device_vk: [u8; 32],
    pub client: Shared<GhostClient>,
    pub relay: Shared<RelayClient>,
    /// What the relay client's subscriptions deliver, for a session loop to consume.
    pub events: std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<ghost_core::relay::RelayEvent>>>,
}

#[allow(dead_code)]
pub async fn create_account(relay_url: &str, label: &str) -> Account {
    let creation = Identity::create_account(label).unwrap();
    let fp = creation.identity.fingerprint;
    let seed = creation.seed;
    let genesis = creation.genesis_entry.to_bytes();
    let device_sk = SigningKey::from_bytes(&creation.identity.signing_key.to_bytes());
    let device_vk = device_sk.verifying_key().to_bytes();
    let identity = Identity::from_device(
        fp,
        SigningKey::from_bytes(&device_sk.to_bytes()),
        1,
        creation.identity.master_vk,
        SigningKey::from_bytes(&creation.identity.master_sk.to_bytes()),
        creation.identity.delegation_sig,
    );
    let db_key = creation.db_key;

    let (mut relay, events) = RelayClient::new(relay_url);
    relay.put_idlog_entry(&fp, genesis.clone()).await.unwrap();
    relay.set_auth(fp, device_vk, device_sk);
    let relay_vk = relay.get_relay_info().await.unwrap().relay_vk;

    let mut client = GhostClient::open_in_memory(identity, db_key).unwrap();
    client.set_relay_vk(relay_vk);
    let mut sync_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut sync_key);
    client.set_sync_key(sync_key).unwrap();

    let client = Arc::new(Mutex::new(client));
    let relay = Arc::new(Mutex::new(relay));
    // As the application does on first start: name the home relay at seq 2.
    let home = flows::account::ensure_home_relay(&client, &relay).await.unwrap();
    assert_eq!(home, relay_vk);

    Account { fp, seed, genesis, device_vk, client, relay, events: std::sync::Mutex::new(Some(events)) }
}

/// Create a server on the account's relay and publish its GroupInfo, as the application does.
#[allow(dead_code)]
pub async fn create_server(account: &Account, name: &str) -> [u8; 32] {
    let (server_id, mailbox_id, group_info) = {
        let mut c = account.client.lock().await;
        let server_id = c.create_server(name, ServerKind::Server, 1000).unwrap();
        let mailbox_id = c.mailbox_id_for_server(&server_id).unwrap();
        let gi = c.export_server_info(&server_id).unwrap();
        (server_id, mailbox_id, gi)
    };
    let r = account.relay.lock().await;
    r.put_server_info(&mailbox_id, group_info).await.unwrap();
    server_id
}

/// Run the full pairing exchange and return the linked device's client, relay and key.
#[allow(dead_code)]
pub async fn pair_second_device(
    relay_url: &str,
    account: &Account,
) -> (Shared<GhostClient>, Shared<RelayClient>, [u8; 32]) {
    let offer = PairingOffer {
        relay_url: relay_url.to_string(),
        display_name: "Alice".into(),
        avatar_hash: None,
        status_message: None,
    };
    let code = flows::pairing::start(&account.client, &account.relay, &offer).await.unwrap();
    assert_eq!(code.account_fp, account.fp);
    let code = PairingCode::parse(&code.encode()).unwrap();

    // New device: no identity yet, so its relay client is unauthenticated.
    let (guest, _events) = RelayClient::new(&code.relay_url);
    let fetched = flows::pairing::fetch_offer(&guest, &code).await.unwrap();
    assert_eq!(fetched.display_name, "Alice");

    let device_b = SigningKey::generate(&mut rand::rngs::OsRng);
    let device_b_vk = device_b.verifying_key().to_bytes();
    flows::pairing::respond(&guest, &code, &device_b, "phone").await.unwrap();

    // Existing device completes its side.
    let label = flows::pairing::check(&account.client, &account.relay, &account.relay, &code, Some(&account.genesis))
        .await
        .unwrap();
    assert_eq!(label.as_deref(), Some("phone"));

    let log_state = flows::pairing::wait_for_device(&guest, &account.fp, &device_b, POLL_ATTEMPTS, POLL_INTERVAL)
        .await
        .unwrap();
    let blob = flows::pairing::fetch_provision(&guest, &code, POLL_ATTEMPTS, POLL_INTERVAL).await.unwrap();

    let identity_b = flows::pairing::linked_identity(
        account.fp,
        SigningKey::from_bytes(&device_b.to_bytes()),
        &log_state,
        &blob,
    );
    let relay_vk = guest.get_relay_info().await.unwrap().relay_vk;
    let mut client_b = GhostClient::open_in_memory(identity_b, [0x22; 32]).unwrap();
    client_b.set_relay_vk(relay_vk);
    let (mut relay_b, _events_b) = RelayClient::new(relay_url);
    relay_b.set_auth(account.fp, device_b_vk, device_b);
    let client_b = Arc::new(Mutex::new(client_b));
    let relay_b = Arc::new(Mutex::new(relay_b));

    flows::provision::consume(&client_b, &relay_b, &blob, 2000).await.unwrap();

    (client_b, relay_b, device_b_vk)
}
