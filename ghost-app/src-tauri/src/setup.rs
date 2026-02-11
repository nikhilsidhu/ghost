use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use ghost_core::client::GhostClient;
use ghost_core::identity::keyring_store;
use ghost_core::identity::Identity;

use crate::state::AppState;

fn ghost_dir() -> PathBuf {
    dirs::home_dir().expect("no home directory").join(".ghost")
}

fn identity_file() -> PathBuf {
    ghost_dir().join("identity.txt")
}

fn db_path() -> PathBuf {
    ghost_dir().join("ghost.db")
}

/// Load existing identity from keyring or generate a new one.
/// Returns AppState with an open GhostClient.
pub fn initialize() -> AppState {
    let dir = ghost_dir();
    fs::create_dir_all(&dir).expect("failed to create ~/.ghost");

    let seed = match fs::read_to_string(identity_file()) {
        Ok(fp_short) => {
            let fp_short = fp_short.trim().to_string();
            let identity = keyring_store::retrieve(&fp_short)
                .expect("identity in keyring not found — delete ~/.ghost/identity.txt to reset");
            *identity.seed()
        }
        Err(_) => {
            let identity = Identity::generate().expect("failed to generate identity");
            keyring_store::store(&identity).expect("failed to store identity in keyring");
            fs::write(identity_file(), identity.fingerprint_short())
                .expect("failed to write identity.txt");
            *identity.seed()
        }
    };

    let client = GhostClient::open(seed, &db_path()).expect("failed to open database");
    AppState {
        client: Mutex::new(client),
    }
}
