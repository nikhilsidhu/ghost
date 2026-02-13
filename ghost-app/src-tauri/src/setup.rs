use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use ghost_core::client::GhostClient;
use ghost_core::identity::Identity;
use ghost_core::relay::{IncomingBlob, RelayClient};
use tokio::sync::{mpsc, Mutex};

use crate::config::{self, GhostConfig};
use crate::state::AppState;

fn ghost_dir() -> PathBuf {
    match std::env::var("GHOST_DATA_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => dirs::home_dir().expect("no home directory").join(".ghost"),
    }
}

fn seed_file() -> PathBuf {
    ghost_dir().join("seed.key")
}

fn db_path() -> PathBuf {
    ghost_dir().join("ghost.db")
}

// In debug builds, store seed in a file to avoid keychain popups on every recompile.
// Release builds use the OS keyring.
#[cfg(debug_assertions)]
fn load_or_create_seed() -> [u8; 32] {
    let path = seed_file();
    if let Ok(bytes) = fs::read(&path) {
        bytes.try_into().expect("corrupt seed.key")
    } else {
        let identity = Identity::generate().expect("failed to generate identity");
        let seed = *identity.seed();
        fs::write(&path, seed).expect("failed to write seed.key");
        seed
    }
}

#[cfg(not(debug_assertions))]
fn load_or_create_seed() -> [u8; 32] {
    use ghost_core::identity::keyring_store;

    let fp_file = ghost_dir().join("identity.txt");
    match fs::read_to_string(&fp_file) {
        Ok(fp_short) => {
            let identity = keyring_store::retrieve(fp_short.trim())
                .expect("identity in keyring not found — delete ~/.ghost/identity.txt to reset");
            *identity.seed()
        }
        Err(_) => {
            let identity = Identity::generate().expect("failed to generate identity");
            keyring_store::store(&identity).expect("failed to store identity in keyring");
            fs::write(&fp_file, identity.fingerprint_short())
                .expect("failed to write identity.txt");
            *identity.seed()
        }
    }
}

pub fn initialize() -> (AppState, mpsc::Receiver<IncomingBlob>) {
    let dir = ghost_dir();
    fs::create_dir_all(&dir).expect("failed to create ~/.ghost");

    let cfg_path = config::config_path(&dir);
    let cfg = GhostConfig::load(&cfg_path);

    let seed = load_or_create_seed();
    let mut client = GhostClient::open(seed, &db_path()).expect("failed to open database");

    if let Some(name) = &cfg.display_name {
        client.set_display_name(name.clone());
    }

    // Config file takes priority, then env var, then default
    let relay_url = cfg
        .relay_url
        .clone()
        .or_else(|| std::env::var("GHOST_RELAY_URL").ok())
        .unwrap_or_else(|| "http://localhost:7700".into());

    let (relay, inbox_rx) = RelayClient::new(&relay_url);

    let state = AppState {
        client: Arc::new(Mutex::new(client)),
        relay: Arc::new(Mutex::new(relay)),
        relay_url,
        http: reqwest::Client::new(),
        config_path: cfg_path,
    };

    (state, inbox_rx)
}
