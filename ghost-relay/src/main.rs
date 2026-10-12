use std::net::SocketAddr;

use ghost_log::LogFile;
use ghost_relay::{config, server, storage};

/// Directory for the relay's daily log files. Unset, it logs to stderr alone, for the
/// service manager to keep.
const LOG_DIR_ENV: &str = "GHOST_LOG_DIR";

#[tokio::main]
async fn main() {
    let _log = ghost_log::init(std::env::var_os(LOG_DIR_ENV).map(|dir| LogFile { dir: dir.into(), stem: "ghost-relay" }));

    let config = config::Config::from_env();
    let port = config.port;
    let storage = match &config.db_path {
        Some(path) => {
            tracing::info!("using persistent storage at {path}");
            storage::Storage::open(std::path::Path::new(path)).expect("failed to open persistent storage")
        }
        None => {
            tracing::warn!("no GHOST_DB_PATH set: storing in a temporary folder that goes with the process");
            storage::Storage::open_ephemeral().expect("failed to open storage")
        }
    };
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let relay = server::start(config, storage, addr).await.expect("failed to start relay");
    tracing::info!("relay listening on {}", relay.addr);
    relay.serve_forever().await;
}
