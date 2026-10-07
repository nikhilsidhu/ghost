use std::net::SocketAddr;

use tracing_subscriber::EnvFilter;

use ghost_relay::{config, server, storage};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = config::Config::from_env();
    let port = config.port;
    let storage = match &config.db_path {
        Some(path) => {
            tracing::info!("using persistent storage at {path}");
            storage::Storage::open(std::path::Path::new(path)).expect("failed to open persistent storage")
        }
        None => {
            tracing::warn!("no GHOST_DB_PATH set — using in-memory storage (state lost on restart)");
            storage::Storage::open_in_memory().expect("failed to open storage")
        }
    };
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let relay = server::start(config, storage, addr).await.expect("failed to start relay");
    tracing::info!("relay listening on {}", relay.addr);
    relay.serve_forever().await;
}
