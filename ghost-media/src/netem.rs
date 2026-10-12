//! A UDP forwarder that stands between clients and a relay's voice port and impairs
//! what passes through: loss, delay, jitter (which reorders) and delay spikes, for
//! everyone or for what one client sends. It gives each client its own upstream
//! socket, as a NAT would, so rebinding those sockets shows the relay new source
//! addresses mid-call. Tests point the relay's advertised voice port at it, so clients
//! run unchanged.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ghost_wire::VOICE_MAX_PACKET;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

/// What happens to each packet, in both directions.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Impairment {
    /// Chance of dropping a packet, 0.0 to 1.0.
    pub loss: f64,
    pub delay: Duration,
    /// Extra delay drawn uniformly up to this, so packets overtake each other.
    pub jitter: Duration,
}

struct Shared {
    listen: Arc<UdpSocket>,
    impairment: Mutex<Impairment>,
    /// Impairment of what particular clients send, instead of `impairment`.
    client_impairments: Mutex<HashMap<SocketAddr, Impairment>>,
    /// Until when every packet is held back (a delay spike).
    held_until: Mutex<Option<Instant>>,
    rng: Mutex<StdRng>,
    /// Each client's upstream socket and the task relaying replies back to it.
    clients: Mutex<HashMap<SocketAddr, (Arc<UdpSocket>, JoinHandle<()>)>>,
    /// Clients in the order they first sent.
    seen: Mutex<Vec<SocketAddr>>,
}

impl Shared {
    /// The delay for one packet from `sender` (a client, or `None` for the relay), or
    /// `None` to drop it.
    fn fate(&self, sender: Option<SocketAddr>) -> Option<Duration> {
        let impairment = sender
            .and_then(|client| self.client_impairments.lock().unwrap().get(&client).copied())
            .unwrap_or(*self.impairment.lock().unwrap());
        let mut rng = self.rng.lock().unwrap();
        if impairment.loss > 0.0 && rng.gen_bool(impairment.loss) {
            return None;
        }
        let jitter = if impairment.jitter.is_zero() { Duration::ZERO } else { impairment.jitter.mul_f64(rng.gen()) };
        let held = self.held_until.lock().unwrap().map_or(Duration::ZERO, |until| until.saturating_duration_since(Instant::now()));
        Some(held + impairment.delay + jitter)
    }

    /// Send `packet` through `socket` to `to` (or the socket's peer) after its fate.
    fn pass(&self, socket: Arc<UdpSocket>, packet: Vec<u8>, to: Option<SocketAddr>, sender: Option<SocketAddr>) {
        let Some(delay) = self.fate(sender) else { return };
        tokio::spawn(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let _ = match to {
                Some(to) => socket.send_to(&packet, to).await,
                None => socket.send(&packet).await,
            };
        });
    }
}

/// A running forwarder. Dropping it stops forwarding.
pub struct Forwarder {
    shared: Arc<Shared>,
    port: u16,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
        for (_, (_, task)) in self.shared.clients.lock().unwrap().drain() {
            task.abort();
        }
    }
}

impl Forwarder {
    /// Listen on a free local port. Nothing is forwarded until `forward_to`, so the
    /// port can be configured into the relay before the relay starts.
    pub async fn bind(seed: u64) -> std::io::Result<Self> {
        let listen = UdpSocket::bind("127.0.0.1:0").await?;
        let port = listen.local_addr()?.port();
        let shared = Arc::new(Shared {
            listen: Arc::new(listen),
            impairment: Mutex::new(Impairment::default()),
            client_impairments: Mutex::new(HashMap::new()),
            held_until: Mutex::new(None),
            rng: Mutex::new(StdRng::seed_from_u64(seed)),
            clients: Mutex::new(HashMap::new()),
            seen: Mutex::new(Vec::new()),
        });
        Ok(Self { shared, port, task: Mutex::new(None) })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Start forwarding to the relay's voice socket.
    pub fn forward_to(&self, relay: SocketAddr) {
        let shared = self.shared.clone();
        let task = tokio::spawn(async move {
            let mut buf = [0u8; VOICE_MAX_PACKET];
            loop {
                let Ok((len, client)) = shared.listen.recv_from(&mut buf).await else { continue };
                let upstream = match upstream_for(&shared, client, relay).await {
                    Ok(upstream) => upstream,
                    Err(e) => {
                        tracing::warn!("netem: upstream socket: {e}");
                        continue;
                    }
                };
                shared.pass(upstream, buf[..len].to_vec(), None, Some(client));
            }
        });
        *self.task.lock().unwrap() = Some(task);
    }

    pub fn set_impairment(&self, impairment: Impairment) {
        *self.shared.impairment.lock().unwrap() = impairment;
    }

    /// Impair what `client` sends differently from everything else.
    pub fn set_client_impairment(&self, client: SocketAddr, impairment: Impairment) {
        self.shared.client_impairments.lock().unwrap().insert(client, impairment);
    }

    /// Clients in the order they first sent.
    pub fn clients(&self) -> Vec<SocketAddr> {
        self.shared.seen.lock().unwrap().clone()
    }

    /// Hold every packet back for `duration`, then let them all go: a delay spike.
    pub fn spike(&self, duration: Duration) {
        *self.shared.held_until.lock().unwrap() = Some(Instant::now() + duration);
    }

    /// Give every client a new upstream socket, as when a NAT drops its mappings: the
    /// relay sees each client arrive from a new address.
    pub fn rebind_all(&self) {
        for (_, (_, task)) in self.shared.clients.lock().unwrap().drain() {
            task.abort();
        }
    }
}

/// The upstream socket for `client`, opened (with its reply task) on first use.
async fn upstream_for(shared: &Arc<Shared>, client: SocketAddr, relay: SocketAddr) -> std::io::Result<Arc<UdpSocket>> {
    if let Some((socket, _)) = shared.clients.lock().unwrap().get(&client) {
        return Ok(socket.clone());
    }
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(relay).await?;
    let socket = Arc::new(socket);
    {
        let mut seen = shared.seen.lock().unwrap();
        if !seen.contains(&client) {
            seen.push(client);
        }
    }
    let replies = {
        let (socket, shared) = (socket.clone(), shared.clone());
        tokio::spawn(async move {
            let mut buf = [0u8; VOICE_MAX_PACKET];
            while let Ok(len) = socket.recv(&mut buf).await {
                shared.pass(shared.listen.clone(), buf[..len].to_vec(), Some(client), None);
            }
        })
    };
    shared.clients.lock().unwrap().insert(client, (socket.clone(), replies));
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WAIT: Duration = Duration::from_secs(2);

    async fn setup() -> (Forwarder, UdpSocket, UdpSocket) {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forwarder = Forwarder::bind(1).await.unwrap();
        forwarder.forward_to(relay.local_addr().unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(("127.0.0.1", forwarder.port())).await.unwrap();
        (forwarder, relay, client)
    }

    async fn recv_from(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buf = [0u8; 64];
        let (len, from) = tokio::time::timeout(WAIT, socket.recv_from(&mut buf)).await.unwrap().unwrap();
        (buf[..len].to_vec(), from)
    }

    #[tokio::test]
    async fn forwards_both_ways_and_rebinds() {
        let (forwarder, relay, client) = setup().await;
        client.send(b"up").await.unwrap();
        let (packet, first_addr) = recv_from(&relay).await;
        assert_eq!(packet, b"up");
        relay.send_to(b"down", first_addr).await.unwrap();
        assert_eq!(recv_from(&client).await.0, b"down");

        forwarder.rebind_all();
        client.send(b"again").await.unwrap();
        let (_, second_addr) = recv_from(&relay).await;
        assert_ne!(first_addr, second_addr, "the relay sees a new source address");
    }

    #[tokio::test]
    async fn drops_what_the_loss_rate_says() {
        let (forwarder, relay, client) = setup().await;
        forwarder.set_impairment(Impairment { loss: 1.0, ..Impairment::default() });
        client.send(b"lost").await.unwrap();
        let mut buf = [0u8; 8];
        assert!(tokio::time::timeout(Duration::from_millis(200), relay.recv_from(&mut buf)).await.is_err());
    }

    #[tokio::test]
    async fn a_spike_holds_everything_then_releases_it() {
        let (forwarder, relay, client) = setup().await;
        forwarder.spike(Duration::from_millis(150));
        let sent = tokio::time::Instant::now();
        client.send(b"held").await.unwrap();
        recv_from(&relay).await;
        assert!(sent.elapsed() >= Duration::from_millis(140));
        client.send(b"after").await.unwrap();
        recv_from(&relay).await;
        assert!(sent.elapsed() < Duration::from_millis(300), "the spike is over");
    }

    #[tokio::test]
    async fn impairs_one_clients_packets_only() {
        let (forwarder, relay, client) = setup().await;
        let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        other.connect(("127.0.0.1", forwarder.port())).await.unwrap();
        client.send(b"first").await.unwrap();
        recv_from(&relay).await;
        other.send(b"second").await.unwrap();
        recv_from(&relay).await;
        assert_eq!(forwarder.clients(), vec![client.local_addr().unwrap(), other.local_addr().unwrap()]);

        forwarder.set_client_impairment(forwarder.clients()[0], Impairment { loss: 1.0, ..Impairment::default() });
        client.send(b"lost").await.unwrap();
        other.send(b"kept").await.unwrap();
        assert_eq!(recv_from(&relay).await.0, b"kept");
    }

    #[tokio::test]
    async fn delays_by_at_least_the_set_delay() {
        let (forwarder, relay, client) = setup().await;
        forwarder.set_impairment(Impairment { delay: Duration::from_millis(150), ..Impairment::default() });
        let sent = tokio::time::Instant::now();
        client.send(b"slow").await.unwrap();
        recv_from(&relay).await;
        assert!(sent.elapsed() >= Duration::from_millis(150));
    }
}
