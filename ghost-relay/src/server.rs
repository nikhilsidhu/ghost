//! Starting a relay: its HTTP and WebSocket server plus the background tasks it needs
//! (expiry sweeps, federation pulls, UDP voice). The binary and the tests both start
//! relays here, so tests run what ships.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::state::{self, AppState};
use crate::storage::Storage;
use crate::{federation, routes, udp, worker};

/// How long to wait for the UDP voice socket to report its port.
const VOICE_BIND_WAIT: Duration = Duration::from_secs(5);

/// A relay serving on `addr`, with its background tasks.
pub struct RunningRelay {
    pub addr: SocketAddr,
    pub state: AppState,
    /// The bound UDP voice port; 0 if the socket could not be bound.
    pub voice_port: u16,
    tasks: Vec<JoinHandle<()>>,
}

impl RunningRelay {
    /// Base URL for clients on this machine.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.addr.port())
    }

    /// Stop serving and end every background task, as if the relay vanished.
    pub async fn stop(self) {
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks {
            let _ = task.await;
        }
    }

    /// Serve until the HTTP server ends (only on error).
    pub async fn serve_forever(mut self) {
        // The HTTP server is the first task; the others run beside it.
        let server = self.tasks.remove(0);
        let _ = server.await;
    }
}

/// Start a relay on `bind` (port 0 picks a free port).
pub async fn start(config: Config, storage: Storage, bind: SocketAddr) -> std::io::Result<RunningRelay> {
    let state = state::new_state(config, storage).await.map_err(std::io::Error::other)?;
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;

    let mut voice_port_rx = state.voice_udp_port_rx.clone();
    // Handlers see each connection's peer address, for the per-address limits.
    let app = routes::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let tasks = vec![
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!("relay server stopped: {e}");
            }
        }),
        tokio::spawn(worker::run(state.clone())),
        tokio::spawn(federation::run(state.clone())),
        tokio::spawn(udp::run(state.clone())),
    ];
    let voice_port = match tokio::time::timeout(VOICE_BIND_WAIT, voice_port_rx.wait_for(|port| *port != 0)).await {
        Ok(Ok(port)) => *port,
        _ => 0,
    };
    Ok(RunningRelay { addr, state, voice_port, tasks })
}
