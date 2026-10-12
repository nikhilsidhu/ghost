//! A relay reached only through a switch, so tests can make it unreachable and bring
//! it back. Going down cuts every open connection, WebSockets included, and drops new
//! ones as they arrive; coming back serves the same relay with everything it held. A
//! blip cuts the connections on the clients' side only, as a network change does. The
//! relay advertises the switch's address, so clients and other relays lose it alike.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::{AbortHandle, JoinHandle};

use crate::config::Config;
use crate::server::{self, RunningRelay};
use crate::storage::Storage;

pub struct SwitchedRelay {
    pub relay: RunningRelay,
    url: String,
    switch: Arc<Mutex<Switch>>,
    accept: JoinHandle<()>,
}

/// Whether the relay is reachable, and the connections to cut when it goes down. One
/// lock covers both, so no connection is let through after the switch goes down.
#[derive(Default)]
struct Switch {
    down: bool,
    open: Vec<Pipe>,
}

/// One connection through the switch.
struct Pipe {
    task: AbortHandle,
    /// Told to drop the client's side alone.
    blip: Arc<Notify>,
}

impl SwitchedRelay {
    /// Start a relay on a free local port behind a switch that is up.
    pub async fn start(config: Config, storage: Storage) -> std::io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let url = format!("http://{}", listener.local_addr()?);
        let config = Config { public_url: Some(url.clone()), ..config };
        let relay = server::start(config, storage, ([127, 0, 0, 1], 0).into()).await?;

        let switch: Arc<Mutex<Switch>> = Arc::default();
        let accept = tokio::spawn(forward(listener, relay.addr, switch.clone()));
        Ok(Self { relay, url, switch, accept })
    }

    /// The address clients and other relays reach the relay at.
    pub fn url(&self) -> String {
        self.url.clone()
    }

    /// Make the relay unreachable: open connections close and new ones are dropped.
    pub fn go_down(&self) {
        let mut switch = self.switch.lock().unwrap();
        switch.down = true;
        for connection in switch.open.drain(..) {
            connection.task.abort();
        }
    }

    /// Cut every open connection on the clients' side only, as when a client's network
    /// changes: the clients see their connections end at once, while the relay keeps its
    /// ends until it notices on its own. New connections go through as before.
    pub fn blip(&self) {
        for connection in &self.switch.lock().unwrap().open {
            connection.blip.notify_one();
        }
    }

    pub fn come_back(&self) {
        self.switch.lock().unwrap().down = false;
    }
}

impl Drop for SwitchedRelay {
    fn drop(&mut self) {
        self.accept.abort();
        self.go_down();
    }
}

/// Accept connections and pipe each to the relay while the switch is up.
async fn forward(listener: TcpListener, relay: SocketAddr, switch: Arc<Mutex<Switch>>) {
    while let Ok((mut inbound, _)) = listener.accept().await {
        let mut switch = switch.lock().unwrap();
        if switch.down {
            continue;
        }
        let blip = Arc::new(Notify::new());
        let cut = blip.clone();
        let pipe = tokio::spawn(async move {
            let Ok(mut outbound) = TcpStream::connect(relay).await else { return };
            let blipped = tokio::select! {
                _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound) => false,
                _ = cut.notified() => true,
            };
            if blipped {
                // The client's side goes; the relay's stays open, unanswered.
                drop(inbound);
                let _relay_side = outbound;
                std::future::pending::<()>().await;
            }
        });
        switch.open.retain(|connection| !connection.task.is_finished());
        switch.open.push(Pipe { task: pipe.abort_handle(), blip });
    }
}
