use std::sync::{Arc, Once};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use ghost_core::account_keys::{DeviceEncryptionKey, RecoveryKey};
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
    start_relay_refreshing_every(1).await
}

/// Ghost's log on stderr, filtered by GHOST_LOG, once per test binary.
pub fn logging() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| std::mem::forget(ghost_log::init(None)));
}

/// A relay configuration for tests: ephemeral ports, mirrors pulling from their homes
/// every `mirror_refresh_secs`.
pub fn relay_config(mirror_refresh_secs: u64) -> Config {
    Config {
        port: 0,
        max_blob_size: 10 * 1024 * 1024,
        voice_port: 0,
        voice_public_port: None,
        max_voice_participants: 25,
        db_path: None,
        log_retention_hours: 72,
        log_min_entries: 100,
        public_url: None,
        mirror_refresh_secs,
        trusted_proxies: Vec::new(),
        ws_ping_secs: 1,
        presence_grace_secs: 2,
        skip_policy_checks_for_tests: false,
        revoked_devices_for_tests: Default::default(),
    }
}

/// An in-process relay that pulls mirrored accounts from their homes every
/// `mirror_refresh_secs`; a long interval makes a mirror that lags behind its home.
#[allow(dead_code)]
pub async fn start_relay_refreshing_every(mirror_refresh_secs: u64) -> ghost_relay::server::RunningRelay {
    logging();
    let storage = Storage::open_ephemeral().unwrap();
    ghost_relay::server::start(relay_config(mirror_refresh_secs), storage, ([127, 0, 0, 1], 0).into()).await.unwrap()
}

/// An in-process relay with the given configuration.
#[allow(dead_code)]
pub async fn start_relay_with(config: Config) -> ghost_relay::server::RunningRelay {
    logging();
    ghost_relay::server::start(config, Storage::open_ephemeral().unwrap(), ([127, 0, 0, 1], 0).into()).await.unwrap()
}

/// A relay a test can take down and bring back, as a relay that becomes unreachable.
#[allow(dead_code)]
pub async fn start_switched_relay() -> ghost_relay::outage::SwitchedRelay {
    logging();
    ghost_relay::outage::SwitchedRelay::start(relay_config(1), Storage::open_ephemeral().unwrap()).await.unwrap()
}

/// Put a seed-based identity's account on the relay (its one-entry chain, whose
/// genesis key is the device's own key) and configure the relay client to sign as it.
#[allow(dead_code)]
pub async fn setup_relay_auth(
    relay_url: &str,
    relay: &ghost_core::relay::RelayClient,
    client: &ghost_core::client::GhostClient,
) {
    let fp = *client.fingerprint();
    let genesis = client.identity().own_genesis();
    let http = reqwest::Client::new();
    let url = format!("{}/idlog/{}", relay_url, hex::encode(fp));
    let resp = http.put(url).body(genesis.to_bytes()).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED, "genesis push failed");
    relay.set_auth(fp, client.verifying_key_bytes(), client.signing_key_clone());
}

pub type Shared<T> = Arc<Mutex<T>>;

pub const POLL_ATTEMPTS: usize = 40;
pub const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// A freshly created account, published to its home relay, whose first device holds
/// an authenticated relay client. `recovery_key` is the one the user saved.
#[allow(dead_code)]
pub struct Account {
    pub fp: [u8; 32],
    pub recovery_key: RecoveryKey,
    pub device_vk: [u8; 32],
    pub client: Shared<GhostClient>,
    pub relay: Arc<RelayClient>,
    /// What the relay client's subscriptions deliver, for a session loop to consume.
    pub events: std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<ghost_core::relay::RelayEvent>>>,
}

#[allow(dead_code)]
pub async fn create_account(relay_url: &str, label: &str) -> Account {
    let recovery_key = RecoveryKey::generate();
    let (relay, events) = RelayClient::new(relay_url);
    let info = relay.get_relay_info().await.unwrap();
    let new = Identity::create_account(&info.relay_ref, label, &recovery_key).unwrap();
    let fp = new.identity.fingerprint;
    let device_vk = new.identity.verifying_key.to_bytes();
    relay.set_auth(fp, device_vk, new.identity.signing_key.clone());
    relay.post_idlog_batch(&fp, &new.batch).await.unwrap();

    let mut client = GhostClient::open_in_memory(new.identity, new.db_key).unwrap();
    client.set_relay_vk(info.relay_vk);
    client.store_account_seed(&new.account_seed).unwrap();

    let client = Arc::new(Mutex::new(client));
    let relay = Arc::new(relay);
    let state = flows::idlog::fetch_and_verify(&client, &relay, &fp).await.unwrap();
    assert_eq!(state.home_relay_vk, Some(info.relay_vk));
    assert!(state.root_rotated() && !state.rekey_needed());

    Account { fp, recovery_key, device_vk, client, relay, events: std::sync::Mutex::new(Some(events)) }
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
    account.relay.put_server_info(&mailbox_id, group_info).await.unwrap();
    server_id
}

/// Run the full pairing exchange, both sides as the application runs them (the user
/// confirms the codes match), and return the linked device's client, relay and key.
#[allow(dead_code)]
pub async fn pair_second_device(
    relay_url: &str,
    account: &Account,
) -> (Shared<GhostClient>, Arc<RelayClient>, [u8; 32]) {
    let offer = PairingOffer {
        relay_url: relay_url.to_string(),
        display_name: "Alice".into(),
        avatar_hash: None,
        avatar_key: None,
    };
    let code = flows::pairing::start(&account.client, &account.relay, &offer).await.unwrap();
    assert_eq!(code.account_fp, account.fp);
    let code = PairingCode::parse(&code.encode()).unwrap();

    // New device: no identity yet, so its relay client is unauthenticated.
    let (guest, _events) = RelayClient::new(&code.relay_url);
    let fetched = flows::pairing::fetch_offer(&guest, &code).await.unwrap();
    assert_eq!(fetched.display_name, "Alice");

    let device_b = SigningKey::generate(&mut rand::rngs::OsRng);
    let encryption_b = DeviceEncryptionKey::generate();
    let device_b_vk = device_b.verifying_key().to_bytes();
    let shown_on_b = flows::pairing::respond(&guest, &code, &device_b, &encryption_b, "phone").await.unwrap();

    // The existing device sees the answer; its user compares the codes and confirms.
    let pending = poll(|| flows::pairing::await_response(&account.relay, &code)).await;
    assert_eq!(pending.code, shown_on_b, "both screens show the same code");
    let mut draft = flows::pairing::post_draft(&account.client, &account.relay, &account.relay, &code, &pending).await.unwrap();

    // The new device counter-signs while it waits; the existing device completes.
    let existing = async {
        for _ in 0..POLL_ATTEMPTS {
            let linked = flows::pairing::complete(&account.client, &account.relay, &account.relay, &code, &pending, &mut draft)
                .await
                .unwrap();
            if let Some(label) = linked {
                return label;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        panic!("the new device never signed");
    };
    let new = flows::pairing::wait_for_device(&guest, &code, &device_b, "phone", POLL_ATTEMPTS, POLL_INTERVAL);
    let (label, added) = tokio::join!(existing, new);
    assert_eq!(label, "phone");
    let (_log_state, added_at) = added.unwrap();
    let blob = flows::pairing::fetch_provision(&guest, &code, POLL_ATTEMPTS, POLL_INTERVAL).await.unwrap();

    let identity_b = flows::pairing::linked_identity(account.fp, device_b.clone(), encryption_b, added_at);
    let relay_vk = guest.get_relay_info().await.unwrap().relay_vk;
    let mut client_b = GhostClient::open_in_memory(identity_b, [0x22; 32]).unwrap();
    client_b.set_relay_vk(relay_vk);
    let (relay_b, _events_b) = RelayClient::new(relay_url);
    relay_b.set_auth(account.fp, device_b_vk, device_b);
    let client_b = Arc::new(Mutex::new(client_b));
    let relay_b = Arc::new(relay_b);

    let settings = flows::provision::consume(&client_b, &relay_b, &blob, 2000).await.unwrap();
    if let Some(name) = settings.display_name {
        client_b.lock().await.set_display_name(name);
    }

    (client_b, relay_b, device_b_vk)
}

/// Poll `attempt` until it yields something, failing the test after the poll budget.
#[allow(dead_code)]
pub async fn poll<T, F, Fut>(mut attempt: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ghost_core::error::Result<Option<T>>>,
{
    for _ in 0..POLL_ATTEMPTS {
        if let Some(found) = attempt().await.unwrap() {
            return found;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    panic!("gave up polling");
}

/// Process a blob from a channel's mailbox as the session loop does: a message from, or
/// a commit naming, a device the client's log does not list yet is processed again
/// after fetching that account's log.
#[allow(dead_code)]
pub async fn receive_like_session(
    client: &Shared<GhostClient>,
    relay: &RelayClient,
    channel_id: &[u8; 32],
    blob: &ghost_core::relay::IncomingBlob,
) -> ghost_core::error::Result<ghost_core::client::ReceiveResult> {
    use ghost_core::client::BlobOrigin;
    use ghost_core::error::GhostError;
    let origin = BlobOrigin { mailbox_id: blob.mailbox_id, seq: blob.seq };
    let first = client.lock().await.receive_at(channel_id, &blob.payload, blob.received_at, origin);
    match first {
        Err(GhostError::UnknownDevice { account_fp }) => {
            fetch_sender_log(client, relay, blob, &account_fp).await;
            client.lock().await.receive_at(channel_id, &blob.payload, blob.received_at, origin)
        }
        other => other,
    }
}

/// A sender's identity log from the relay hosting the blob's server, as the session
/// fetches it; from `relay` itself for a mailbox of no server.
async fn fetch_sender_log(client: &Shared<GhostClient>, relay: &RelayClient, blob: &ghost_core::relay::IncomingBlob, account_fp: &[u8; 32]) {
    let server_id = client.lock().await.server_id_for_mailbox(&blob.mailbox_id);
    match server_id {
        Some(server_id) => {
            flows::idlog::refresh_member(client, relay, &server_id, account_fp).await;
        }
        None => {
            if let Err(e) = flows::idlog::fetch_and_verify(client, relay, account_fp).await {
                tracing::warn!("test: log of {} not fetched: {e}", hex::encode(&account_fp[..8]));
            }
        }
    }
}
