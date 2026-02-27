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
