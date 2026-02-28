use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use ghost_core::client::GhostClient;
use ghost_core::identity::Identity;
use ghost_core::relay::{RelayClient, RelayEvent};
use tokio::sync::{mpsc, watch, Mutex};

use ghost_core::mls::presence::OnlineStatus;

use crate::config::{self, GhostConfig};
use crate::constants::VOICE_CMD_CHANNEL_SIZE;
use crate::presence::PresenceInfo;
use crate::state::AppState;
use crate::voice_task::{VoiceCommand, VoiceHandle, VoiceStateEvent};

pub(crate) fn ghost_dir() -> PathBuf {
    match std::env::var("GHOST_DATA_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => dirs::home_dir().expect("no home directory").join(".ghost"),
    }
}

pub(crate) fn device_file() -> PathBuf {
    ghost_dir().join("device.key")
}

pub(crate) fn db_path() -> PathBuf {
    ghost_dir().join("ghost.db")
}

pub(crate) fn genesis_pending_path() -> PathBuf {
    ghost_dir().join("genesis.pending")
}

/// Remove all local database and pending-state files.
pub(crate) fn wipe_local_databases() {
    fn try_remove(path: &std::path::Path) {
        if let Err(e) = std::fs::remove_file(path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!("wipe: failed to remove {}: {e}", path.display());
            }
        }
    }
    let db = db_path();
    let mls_db = db.with_extension("mls.db");
    for path in [&db, &mls_db] {
        try_remove(path);
        try_remove(&std::path::PathBuf::from(format!("{}-wal", path.display())));
        try_remove(&std::path::PathBuf::from(format!("{}-shm", path.display())));
    }
    try_remove(&genesis_pending_path());
}

pub(crate) fn device_label() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macOS",
        "windows" => "Windows",
        "linux" => "Linux",
        "ios" => "iOS",
        "android" => "Android",
        other => other,
    }
}

/// In debug builds, store device credentials in a file to avoid keychain popups on every recompile.
#[cfg(debug_assertions)]
fn load_or_create_device() -> (Identity, [u8; 32], [u8; 32], Option<[u8; 32]>) {
    use ghost_core::identity::keyring_store::DEVICE_BLOB_SIZE;

    let path = device_file();
    if let Ok(bytes) = fs::read(&path) {
        assert_eq!(bytes.len(), DEVICE_BLOB_SIZE, "corrupt device.key");
        let idlog_seq = u64::from_be_bytes(bytes[128..136].try_into().unwrap());
        let fingerprint: [u8; 32] = bytes[0..32].try_into().unwrap();
        let sk_bytes: [u8; 32] = bytes[32..64].try_into().unwrap();
        let db_key: [u8; 32] = bytes[64..96].try_into().unwrap();
        let mls_db_key: [u8; 32] = bytes[96..128].try_into().unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
        let identity = Identity::from_device(fingerprint, signing_key, idlog_seq);
        (identity, db_key, mls_db_key, None)
    } else {
        let creation = Identity::create_account(device_label())
            .expect("failed to create account");
        let fingerprint = creation.identity.fingerprint;
        let sk_bytes = creation.identity.signing_key.to_bytes();
        let db_key = creation.db_key;
        let mls_db_key = creation.mls_db_key;
        let seed = creation.seed;
        let genesis_bytes = creation.genesis_entry.to_bytes();
        fs::write(genesis_pending_path(), &genesis_bytes)
            .expect("failed to write genesis.pending");
        let mut blob = Vec::with_capacity(DEVICE_BLOB_SIZE);
        blob.extend_from_slice(&fingerprint);
        blob.extend_from_slice(&sk_bytes);
        blob.extend_from_slice(&db_key);
        blob.extend_from_slice(&mls_db_key);
        blob.extend_from_slice(&1u64.to_be_bytes());
        fs::write(&path, &blob).expect("failed to write device.key");
        drop(creation);
        let identity = Identity::from_device(fingerprint, ed25519_dalek::SigningKey::from_bytes(&sk_bytes), 1);
        (identity, db_key, mls_db_key, Some(seed))
    }
}

/// Release builds use the OS keyring.
#[cfg(not(debug_assertions))]
fn load_or_create_device() -> (Identity, [u8; 32], [u8; 32], Option<[u8; 32]>) {
    use ghost_core::identity::keyring_store::{self, StoredDevice};

    let fp_file = ghost_dir().join("identity.txt");
    match fs::read_to_string(&fp_file) {
        Ok(fp_short) => {
            let device = keyring_store::retrieve(fp_short.trim())
                .expect("device in keyring not found — delete ~/.ghost/identity.txt to reset");
            let identity = Identity::from_device(device.fingerprint, device.signing_key, device.idlog_seq);
            (identity, device.db_key, device.mls_db_key, None)
        }
        Err(_) => {
            let creation = Identity::create_account(device_label())
                .expect("failed to create account");
            // Copy out what we need before AccountCreation drops (zeroizes seed)
            let fingerprint = creation.identity.fingerprint;
            let sk_bytes = creation.identity.signing_key.to_bytes();
            let db_key = creation.db_key;
            let mls_db_key = creation.mls_db_key;
            let seed = creation.seed;
            let fp_short = creation.identity.fingerprint_short();
            let genesis_bytes = creation.genesis_entry.to_bytes();
            let stored = StoredDevice {
                fingerprint,
                signing_key: ed25519_dalek::SigningKey::from_bytes(&sk_bytes),
                db_key,
                mls_db_key,
                idlog_seq: 1,
            };
            fs::write(genesis_pending_path(), &genesis_bytes)
                .expect("failed to write genesis.pending");
            keyring_store::store(&fp_short, &stored)
                .expect("failed to store device in keyring");
            fs::write(&fp_file, &fp_short)
                .expect("failed to write identity.txt");
            drop(creation);
            let identity = Identity::from_device(fingerprint, ed25519_dalek::SigningKey::from_bytes(&sk_bytes), 1);
            (identity, db_key, mls_db_key, Some(seed))
        }
    }
}

pub struct SetupResult {
    pub state: AppState,
    pub inbox_rx: mpsc::Receiver<RelayEvent>,
    pub voice_cmd_rx: mpsc::Receiver<VoiceCommand>,
    pub voice_state_tx: watch::Sender<VoiceStateEvent>,
}

pub fn initialize() -> SetupResult {
    let dir = ghost_dir();
    fs::create_dir_all(&dir).expect("failed to create ~/.ghost");

    let cfg_path = config::config_path(&dir);
    let mut cfg = GhostConfig::load(&cfg_path);

    let (identity, db_key, mls_db_key, recovery_seed) = load_or_create_device();

    let mut client = GhostClient::open(identity, db_key, mls_db_key, &db_path())
        .expect("failed to open database");

    // New account: create sync MLS group + generate snapshot key
    if recovery_seed.is_some() {
        if !client.has_sync_group() {
            client.create_sync_group().expect("failed to create sync group");
        }
        if client.sync_key().is_none() {
            let mut k = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut k);
            client.set_sync_key(k).expect("failed to set sync_key");
        }
    }

    if let Some(name) = &cfg.display_name {
        client.set_display_name(name.clone());
    }

    // Config file takes priority, then env var, then default
    let relay_url = cfg
        .relay_url
        .as_deref()
        .filter(|u| !u.is_empty())
        .map(String::from)
        .or_else(|| std::env::var("GHOST_RELAY_URL").ok())
        .unwrap_or_else(|| "http://localhost:7700".into());

    let (relay, inbox_rx) = RelayClient::new(&relay_url);

    let (voice_cmd_tx, voice_cmd_rx) = mpsc::channel(VOICE_CMD_CHANNEL_SIZE);
    let (voice_state_tx, _voice_state_rx) = watch::channel(VoiceStateEvent::default());

    // Check if persisted status message has expired
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let expired = cfg.status_expiry.map_or(false, |exp| now_ms >= exp);
    if expired {
        cfg.status_message = None;
        cfg.status_expiry = None;
        let _ = cfg.save(&cfg_path);
    }

    // Restore avatar_hash from any server where we have one stored
    let own_fp = *client.fingerprint();
    let avatar_hash = client
        .server_mailboxes()
        .iter()
        .find_map(|(server_id, _)| {
            client.store().get_member(server_id, &own_fp).ok().and_then(|m| m.avatar_hash)
        });

    let initial_presence = PresenceInfo {
        status: match cfg.status.as_deref() {
            Some("away") => OnlineStatus::Away,
            Some("invisible") => OnlineStatus::Invisible,
            _ => OnlineStatus::Online,
        },
        status_message: cfg.status_message.clone(),
        status_expiry: cfg.status_expiry,
        avatar_hash,
    };

    let state = AppState {
        client: Arc::new(Mutex::new(client)),
        relay: Arc::new(Mutex::new(relay)),
        relay_url: Arc::new(Mutex::new(relay_url)),
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap(),
        config_path: cfg_path,
        config: Arc::new(Mutex::new(cfg)),
        voice: VoiceHandle {
            cmd_tx: voice_cmd_tx,
        },
        presence: Arc::new(Mutex::new(initial_presence)),
        pairing_secret: Arc::new(Mutex::new(None)),
        recovery_seed: Arc::new(Mutex::new(recovery_seed.map(zeroize::Zeroizing::new))),
        relay_task_handle: Arc::new(Mutex::new(None)),
    };

    SetupResult {
        state,
        inbox_rx,
        voice_cmd_rx,
        voice_state_tx,
    }
}
