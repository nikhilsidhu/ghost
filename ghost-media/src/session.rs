//! A participant's media session: one UDP socket to the relay, the binds that let the
//! relay forward for our slot, sealing what we send and opening what others send.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ghost_wire::voice::{MediaHeader, VoiceBind};
use ghost_wire::VOICE_MAX_PACKET;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::constants::{BIND_INTERVAL, BIND_RETRY_DELAYS_MS, INBOUND_QUEUE, OUTBOUND_QUEUE, UNKEYED_FRAME_LIMIT};
use crate::crypto::{FrameOpener, FrameSealer};
use crate::MediaError;

/// What the relay's welcome and our own key give a session.
pub struct SessionConfig {
    /// The relay's voice UDP address.
    pub endpoint: SocketAddr,
    pub room_id: [u8; 32],
    pub slot_id: u32,
    /// Keys our binds; only the relay and we know it.
    pub bind_token: [u8; 32],
    /// The MLS epoch `send_key` was derived in; receivers choose their key by it.
    pub epoch: u64,
    pub send_key: [u8; 32],
}

/// A frame another participant sent, opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedFrame {
    pub slot_id: u32,
    pub sequence: u32,
    pub payload: Vec<u8>,
    /// When its packet came off the socket, for jitter estimates.
    pub arrived: Instant,
}

/// What the session delivers to the track, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    Frame(ReceivedFrame),
    /// The participant in this slot left; drop what is buffered for it.
    PeerLeft(u32),
}

struct PeerKey {
    epoch: u64,
    opener: FrameOpener,
}

/// A packet whose sender's key has not arrived yet.
struct Unkeyed {
    header: MediaHeader,
    sealed: Vec<u8>,
    arrived: Instant,
}

#[derive(Default)]
struct Peers {
    keys: HashMap<u32, PeerKey>,
    /// Packets from senders whose key has not arrived yet, oldest first.
    unkeyed: HashMap<u32, VecDeque<Unkeyed>>,
}

/// Open a frame with its sender's key; `None` when it was sealed in another epoch or
/// does not open (forged, relabeled or corrupted).
fn open(key: &PeerKey, header: &MediaHeader, sealed: &[u8], arrived: Instant) -> Option<ReceivedFrame> {
    if header.epoch != key.epoch {
        return None;
    }
    let payload = key.opener.open(header.sequence, sealed).ok()?;
    Some(ReceivedFrame { slot_id: header.slot_id, sequence: header.sequence, payload, arrived })
}

/// Seals frames and queues them for the socket. Cheap to clone and callable from any
/// thread, so a real-time audio thread can send without awaiting.
#[derive(Clone)]
pub struct FrameSender {
    packets: mpsc::Sender<Vec<u8>>,
    sealer: Arc<FrameSealer>,
    /// Our room, slot and epoch; the sequence is set per frame.
    header: MediaHeader,
}

impl FrameSender {
    /// Seal one frame under `sequence` and queue it. False when it was dropped: the
    /// queue is full or the session has ended.
    pub fn send(&self, sequence: u32, frame: &[u8]) -> bool {
        let Ok(sealed) = self.sealer.seal(sequence, frame) else { return false };
        let packet = MediaHeader { sequence, ..self.header }.packet(&sealed);
        self.packets.try_send(packet).is_ok()
    }

    /// Whether the session has ended, so senders can stop.
    pub fn is_closed(&self) -> bool {
        self.packets.is_closed()
    }
}

/// A running media session. Dropping it closes the socket and ends its tasks.
pub struct MediaSession {
    peers: Arc<Mutex<Peers>>,
    inbound: mpsc::Sender<Inbound>,
    sender: FrameSender,
    local_addr: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for MediaSession {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl MediaSession {
    /// Open the socket and start binding, sending and receiving. Frames arrive on the
    /// returned receiver once their sender's key is set.
    pub async fn start(config: SessionConfig) -> Result<(Self, mpsc::Receiver<Inbound>), MediaError> {
        let unspecified: SocketAddr = if config.endpoint.is_ipv6() {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        };
        let socket = UdpSocket::bind(unspecified).await?;
        socket.connect(config.endpoint).await?;
        let local_addr = socket.local_addr()?;
        let socket = Arc::new(socket);

        let (packets_tx, packets_rx) = mpsc::channel(OUTBOUND_QUEUE);
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE);
        let peers = Arc::new(Mutex::new(Peers::default()));
        let sender = FrameSender {
            packets: packets_tx,
            sealer: Arc::new(FrameSealer::new(&config.send_key)?),
            header: MediaHeader { room_id: config.room_id, slot_id: config.slot_id, epoch: config.epoch, sequence: 0 },
        };

        let tasks = vec![
            tokio::spawn(bind_loop(socket.clone(), config.bind_token, config.room_id, config.slot_id)),
            tokio::spawn(send_loop(socket.clone(), packets_rx)),
            tokio::spawn(receive_loop(socket, config.slot_id, peers.clone(), inbound_tx.clone())),
        ];
        Ok((Self { peers, inbound: inbound_tx, sender, local_addr, tasks }, inbound_rx))
    }

    pub fn sender(&self) -> FrameSender {
        self.sender.clone()
    }

    /// Our end of the UDP path.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Open `slot_id`'s frames with `key` from now on, including any that arrived
    /// before it.
    pub fn set_peer(&self, slot_id: u32, epoch: u64, key: &[u8; 32]) -> Result<(), MediaError> {
        let key = PeerKey { epoch, opener: FrameOpener::new(key)? };
        let early: Vec<ReceivedFrame> = {
            let mut peers = self.peers.lock().unwrap();
            let early = peers.unkeyed.remove(&slot_id).unwrap_or_default();
            let opened = early.iter().filter_map(|packet| open(&key, &packet.header, &packet.sealed, packet.arrived)).collect();
            peers.keys.insert(slot_id, key);
            opened
        };
        for frame in early {
            let _ = self.inbound.try_send(Inbound::Frame(frame));
        }
        Ok(())
    }

    /// Forget a participant who left.
    pub fn remove_peer(&self, slot_id: u32) {
        {
            let mut peers = self.peers.lock().unwrap();
            peers.keys.remove(&slot_id);
            peers.unkeyed.remove(&slot_id);
        }
        let _ = self.inbound.try_send(Inbound::PeerLeft(slot_id));
    }

    /// Forget every participant not in `slots` (after the relay resent the room).
    pub fn retain_peers(&self, slots: &HashSet<u32>) {
        let gone: Vec<u32> = {
            let peers = self.peers.lock().unwrap();
            peers.keys.keys().chain(peers.unkeyed.keys()).filter(|slot| !slots.contains(slot)).copied().collect()
        };
        for slot in gone {
            self.remove_peer(slot);
        }
    }
}

/// Bind our address to our slot, quickly at first, then periodically. Each bind
/// carries a higher counter, so the relay accepts it even after our address changes.
async fn bind_loop(socket: Arc<UdpSocket>, token: [u8; 32], room_id: [u8; 32], slot_id: u32) {
    let retries = BIND_RETRY_DELAYS_MS.windows(2).map(|pair| Duration::from_millis(pair[1] - pair[0]));
    let delays = std::iter::once(Duration::ZERO).chain(retries).chain(std::iter::repeat(BIND_INTERVAL));
    for (counter, delay) in (1u64..).zip(delays) {
        tokio::time::sleep(delay).await;
        let bind = VoiceBind::sign(&token, room_id, slot_id, counter);
        if let Err(e) = socket.send(&bind.to_bytes()).await {
            eprintln!("media: bind send: {e}");
        }
    }
}

async fn send_loop(socket: Arc<UdpSocket>, mut packets: mpsc::Receiver<Vec<u8>>) {
    while let Some(packet) = packets.recv().await {
        if let Err(e) = socket.send(&packet).await {
            eprintln!("media: send: {e}");
        }
    }
}

async fn receive_loop(socket: Arc<UdpSocket>, own_slot: u32, peers: Arc<Mutex<Peers>>, inbound: mpsc::Sender<Inbound>) {
    let mut buf = [0u8; VOICE_MAX_PACKET];
    loop {
        let (len, arrived) = match socket.recv(&mut buf).await {
            Ok(len) => (len, Instant::now()),
            // Connected UDP sockets report ICMP errors from earlier sends; keep going.
            Err(e) => {
                eprintln!("media: receive: {e}");
                continue;
            }
        };
        let Some((header, sealed)) = MediaHeader::parse(&buf[..len]) else { continue };
        if header.slot_id == own_slot || sealed.is_empty() {
            continue;
        }
        let frame = {
            let mut peers = peers.lock().unwrap();
            match peers.keys.get(&header.slot_id) {
                Some(key) => open(key, &header, sealed, arrived),
                None => {
                    let early = peers.unkeyed.entry(header.slot_id).or_default();
                    if early.len() >= UNKEYED_FRAME_LIMIT {
                        early.pop_front();
                    }
                    early.push_back(Unkeyed { header, sealed: sealed.to_vec(), arrived });
                    None
                }
            }
        };
        if let Some(frame) = frame {
            // A full queue means the track is behind; late audio is worth nothing.
            let _ = inbound.try_send(Inbound::Frame(frame));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: [u8; 32] = [1; 32];
    const TOKEN: [u8; 32] = [2; 32];
    const OWN_KEY: [u8; 32] = [3; 32];
    const PEER_KEY: [u8; 32] = [4; 32];
    const EPOCH: u64 = 7;
    const WAIT: Duration = Duration::from_secs(2);

    /// A session toward a plain socket standing in for the relay.
    async fn session() -> (MediaSession, mpsc::Receiver<Inbound>, UdpSocket) {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = SessionConfig {
            endpoint: relay.local_addr().unwrap(),
            room_id: ROOM,
            slot_id: 1,
            bind_token: TOKEN,
            epoch: EPOCH,
            send_key: OWN_KEY,
        };
        let (session, inbound) = MediaSession::start(config).await.unwrap();
        (session, inbound, relay)
    }

    /// A packet from slot 2, sealed with its key.
    fn peer_packet(sequence: u32, payload: &[u8]) -> Vec<u8> {
        let sealed = FrameSealer::new(&PEER_KEY).unwrap().seal(sequence, payload).unwrap();
        MediaHeader { room_id: ROOM, slot_id: 2, epoch: EPOCH, sequence }.packet(&sealed)
    }

    async fn next(inbound: &mut mpsc::Receiver<Inbound>) -> Inbound {
        tokio::time::timeout(WAIT, inbound.recv()).await.expect("nothing arrived").unwrap()
    }

    /// The next delivery, which must be a frame: (slot, sequence, payload).
    async fn next_frame(inbound: &mut mpsc::Receiver<Inbound>) -> (u32, u32, Vec<u8>) {
        match next(inbound).await {
            Inbound::Frame(frame) => (frame.slot_id, frame.sequence, frame.payload),
            other => panic!("expected a frame, got {other:?}"),
        }
    }

    async fn relay_receive(relay: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buf = [0u8; VOICE_MAX_PACKET];
        let (len, from) = tokio::time::timeout(WAIT, relay.recv_from(&mut buf)).await.unwrap().unwrap();
        (buf[..len].to_vec(), from)
    }

    #[tokio::test]
    async fn binds_then_sends_sealed_frames() {
        let (session, _inbound, relay) = session().await;
        let (first, _) = relay_receive(&relay).await;
        let bind = VoiceBind::from_bytes(&first).expect("a bind comes first");
        assert!(bind.verify(&TOKEN));
        assert_eq!((bind.room_id, bind.slot_id, bind.counter), (ROOM, 1, 1));

        assert!(session.sender().send(40, b"opus"));
        let packet = loop {
            let (packet, _) = relay_receive(&relay).await;
            if VoiceBind::from_bytes(&packet).is_none() {
                break packet;
            }
        };
        let (header, sealed) = MediaHeader::parse(&packet).unwrap();
        assert_eq!(header, MediaHeader { room_id: ROOM, slot_id: 1, epoch: EPOCH, sequence: 40 });
        assert_eq!(FrameOpener::new(&OWN_KEY).unwrap().open(40, sealed).unwrap(), b"opus");
    }

    #[tokio::test]
    async fn frames_before_the_key_are_kept_until_it_arrives() {
        let (session, mut inbound, relay) = session().await;
        let (_, client) = relay_receive(&relay).await;
        relay.send_to(&peer_packet(10, b"early"), client).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(inbound.try_recv().is_err(), "no key, nothing delivered yet");

        session.set_peer(2, EPOCH, &PEER_KEY).unwrap();
        assert_eq!(next_frame(&mut inbound).await, (2, 10, b"early".to_vec()));
        relay.send_to(&peer_packet(11, b"later"), client).await.unwrap();
        assert_eq!(next_frame(&mut inbound).await, (2, 11, b"later".to_vec()));
    }

    #[tokio::test]
    async fn drops_own_relabeled_and_other_epoch_frames() {
        let (session, mut inbound, relay) = session().await;
        let (_, client) = relay_receive(&relay).await;
        session.set_peer(2, EPOCH, &PEER_KEY).unwrap();

        let mut own = peer_packet(1, b"mine");
        own[34..38].copy_from_slice(&1u32.to_be_bytes());
        let mut relabeled = peer_packet(2, b"moved");
        relabeled[47..51].copy_from_slice(&9u32.to_be_bytes());
        let mut old_epoch = peer_packet(3, b"stale");
        old_epoch[39..47].copy_from_slice(&(EPOCH - 1).to_be_bytes());
        for packet in [own, relabeled, old_epoch, peer_packet(4, b"good")] {
            relay.send_to(&packet, client).await.unwrap();
        }
        assert_eq!(next_frame(&mut inbound).await, (2, 4, b"good".to_vec()));
    }

    #[tokio::test]
    async fn departures_reach_the_track() {
        let (session, mut inbound, _relay) = session().await;
        session.set_peer(2, EPOCH, &PEER_KEY).unwrap();
        session.set_peer(3, EPOCH, &PEER_KEY).unwrap();
        session.remove_peer(2);
        assert_eq!(next(&mut inbound).await, Inbound::PeerLeft(2));
        session.retain_peers(&HashSet::from([2]));
        assert_eq!(next(&mut inbound).await, Inbound::PeerLeft(3));
    }

    #[tokio::test]
    async fn dropping_the_session_closes_its_senders() {
        let (session, _inbound, _relay) = session().await;
        let sender = session.sender();
        drop(session);
        tokio::time::timeout(WAIT, async {
            while !sender.is_closed() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the sender never closed");
        assert!(!sender.send(1, b"after"));
    }
}
