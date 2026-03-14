use std::net::SocketAddr;

use tracing_subscriber::EnvFilter;

use ghost_relay::{config, routes, state, storage, udp, worker};

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
    let state = state::new_state(config, storage);

    tokio::spawn(worker::run(state.clone()));
    tokio::spawn(udp::run(state.clone()));

    let app = routes::router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("relay listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
