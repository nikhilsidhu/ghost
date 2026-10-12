//! A participant's media session: one UDP socket to the relay, the binds that let the
//! relay forward for our slot, sealing what we send and opening what others send.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use ghost_wire::voice::{MediaHeader, VoiceBind};
use ghost_wire::VOICE_MAX_PACKET;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::constants::{
    BIND_ANSWER_FRESH, BIND_INTERVAL, BIND_RETRY_DELAYS_MS, INBOUND_QUEUE, OUTBOUND_QUEUE, PATH_VERDICT_AFTER, UNKEYED_FRAME_LIMIT,
};
use crate::crypto::{FrameOpener, FrameSealer};
use crate::track::{TrackEvent, TrackIo};
use crate::MediaError;

/// The slot a loopback session gives its one participant.
const LOOPBACK_SLOT: u32 = 0;

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

/// Whether media reaches the relay, as its answers to our binds show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaPath {
    /// Too early to tell: the first binds are still out.
    Unconfirmed,
    /// The relay answered a bind lately.
    Open,
    /// No answer for a while: UDP to the relay is blocked or lost.
    Blocked,
}

/// When the binds started and when the relay last answered one.
struct PathWatch {
    binding_since: Mutex<Instant>,
    answered: Mutex<Option<Instant>>,
}

impl PathWatch {
    fn new() -> Self {
        Self { binding_since: Mutex::new(Instant::now()), answered: Mutex::new(None) }
    }

    fn path(&self, now: Instant) -> MediaPath {
        match *self.answered.lock().unwrap() {
            Some(at) if now.duration_since(at) <= BIND_ANSWER_FRESH => MediaPath::Open,
            _ if now.duration_since(*self.binding_since.lock().unwrap()) < PATH_VERDICT_AFTER => MediaPath::Unconfirmed,
            _ => MediaPath::Blocked,
        }
    }
}

/// What a bind needs, kept so binding can start over.
#[derive(Clone)]
struct Binding {
    socket: Arc<UdpSocket>,
    token: [u8; 32],
    room_id: [u8; 32],
    slot_id: u32,
    /// The last counter sent; each bind goes higher, across restarts too.
    counter: Arc<AtomicU64>,
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

/// A key and the MLS epoch it was derived in.
struct EpochKey {
    epoch: u64,
    opener: FrameOpener,
}

/// A participant's keys: the newest, and the one before it for frames still in flight
/// from before the participant moved epoch.
struct PeerKey {
    current: EpochKey,
    previous: Option<EpochKey>,
}

impl PeerKey {
    fn for_epoch(&self, epoch: u64) -> Option<&EpochKey> {
        if self.current.epoch == epoch {
            return Some(&self.current);
        }
        self.previous.as_ref().filter(|p| p.epoch == epoch)
    }
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

/// Open a frame with its sender's key for the epoch it names; `None` when no key for that
/// epoch is held or it does not open (forged, relabeled or corrupted).
fn open(key: &PeerKey, header: &MediaHeader, sealed: &[u8], arrived: Instant) -> Option<ReceivedFrame> {
    let payload = key.for_epoch(header.epoch)?.opener.open(header.sequence, sealed).ok()?;
    Some(ReceivedFrame { slot_id: header.slot_id, sequence: header.sequence, payload, arrived })
}

/// Keep a packet whose sender's key for its epoch has not arrived yet, dropping the
/// oldest past the limit.
fn hold(peers: &mut Peers, header: MediaHeader, sealed: &[u8], arrived: Instant) {
    let early = peers.unkeyed.entry(header.slot_id).or_default();
    if early.len() >= UNKEYED_FRAME_LIMIT {
        early.pop_front();
    }
    early.push_back(Unkeyed { header, sealed: sealed.to_vec(), arrived });
}

/// What this participant seals with, swapped whole when its epoch moves.
struct SendKey {
    epoch: u64,
    sealer: FrameSealer,
}

/// Seals frames and queues them for the socket. Cheap to clone and callable from any
/// thread, so a real-time audio thread can send without awaiting.
#[derive(Clone)]
pub struct FrameSender {
    packets: mpsc::Sender<Vec<u8>>,
    /// The key in use and its epoch, which the header names.
    key: Arc<RwLock<Arc<SendKey>>>,
    room_id: [u8; 32],
    slot_id: u32,
}

impl FrameSender {
    fn new(packets: mpsc::Sender<Vec<u8>>, room_id: [u8; 32], slot_id: u32, epoch: u64, key: &[u8; 32]) -> Result<Self, MediaError> {
        let key = Arc::new(SendKey { epoch, sealer: FrameSealer::new(key)? });
        Ok(Self { packets, key: Arc::new(RwLock::new(key)), room_id, slot_id })
    }

    /// Seal one frame under `sequence` and queue it. False when it was dropped: the
    /// queue is full or the session has ended.
    pub fn send(&self, sequence: u32, frame: &[u8]) -> bool {
        let key = self.key.read().unwrap().clone();
        let Ok(sealed) = key.sealer.seal(sequence, frame) else { return false };
        let packet = MediaHeader { room_id: self.room_id, slot_id: self.slot_id, epoch: key.epoch, sequence }.packet(&sealed);
        self.packets.try_send(packet).is_ok()
    }

    /// Whether the session has ended, so senders can stop.
    pub fn is_closed(&self) -> bool {
        self.packets.is_closed()
    }
}

impl TrackIo {
    /// A session that plays this participant's own frames back to them, sealed and
    /// opened as a relay round trip would be: for trying the microphone through the
    /// whole call path. Ends when the sender is dropped; the track reports to `events`.
    pub fn loopback(events: mpsc::UnboundedSender<TrackEvent>) -> Result<Self, MediaError> {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        let (packets_tx, mut packets_rx) = mpsc::channel(OUTBOUND_QUEUE);
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE);
        let sender = FrameSender::new(packets_tx, [0u8; 32], LOOPBACK_SLOT, 0, &key)?;
        let own = PeerKey { current: EpochKey { epoch: 0, opener: FrameOpener::new(&key)? }, previous: None };
        tokio::spawn(async move {
            while let Some(packet) = packets_rx.recv().await {
                let Some((header, sealed)) = MediaHeader::parse(&packet) else { continue };
                if let Some(frame) = open(&own, &header, sealed, Instant::now()) {
                    let _ = inbound_tx.try_send(Inbound::Frame(frame));
                }
            }
        });
        Ok(Self { sender, received: inbound_rx, events })
    }
}

/// A running media session. Dropping it closes the socket and ends its tasks.
pub struct MediaSession {
    peers: Arc<Mutex<Peers>>,
    inbound: mpsc::Sender<Inbound>,
    sender: FrameSender,
    local_addr: SocketAddr,
    binding: Binding,
    path: Arc<PathWatch>,
    bind_task: Mutex<JoinHandle<()>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for MediaSession {
    fn drop(&mut self) {
        self.bind_task.lock().unwrap().abort();
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
        let sender = FrameSender::new(packets_tx, config.room_id, config.slot_id, config.epoch, &config.send_key)?;
        let binding = Binding {
            socket: socket.clone(),
            token: config.bind_token,
            room_id: config.room_id,
            slot_id: config.slot_id,
            counter: Arc::new(AtomicU64::new(0)),
        };
        let path = Arc::new(PathWatch::new());

        let bind_task = Mutex::new(tokio::spawn(bind_loop(binding.clone())));
        let tasks = vec![
            tokio::spawn(send_loop(socket.clone(), packets_rx)),
            tokio::spawn(receive_loop(binding.clone(), path.clone(), peers.clone(), inbound_tx.clone())),
        ];
        Ok((Self { peers, inbound: inbound_tx, sender, local_addr, binding, path, bind_task, tasks }, inbound_rx))
    }

    /// Whether media reaches the relay now.
    pub fn media_path(&self) -> MediaPath {
        self.path.path(Instant::now())
    }

    /// Bind again at the quick pace of a new session: our address may have changed (the
    /// signaling connection had to be reopened), and media should not wait for the next
    /// periodic bind to find out.
    pub fn rebind(&self) {
        *self.path.binding_since.lock().unwrap() = Instant::now();
        let mut task = self.bind_task.lock().unwrap();
        task.abort();
        *task = tokio::spawn(bind_loop(self.binding.clone()));
    }

    pub fn sender(&self) -> FrameSender {
        self.sender.clone()
    }

    /// Our end of the UDP path.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Seal what we send with `key`, derived in `epoch`, from now on: our epoch moved, and
    /// so did our presence, which tells the others the matching key.
    pub fn set_send_key(&self, epoch: u64, key: &[u8; 32]) -> Result<(), MediaError> {
        let key = Arc::new(SendKey { epoch, sealer: FrameSealer::new(key)? });
        *self.sender.key.write().unwrap() = key;
        Ok(())
    }

    /// Open `slot_id`'s frames sealed in `epoch` with `key` from now on, including any
    /// that arrived before it. A newer epoch keeps the participant's last key for frames
    /// still in flight; the epoch already held, or an older one, changes nothing.
    pub fn set_peer(&self, slot_id: u32, epoch: u64, key: &[u8; 32]) -> Result<(), MediaError> {
        let early: Vec<ReceivedFrame> = {
            let mut peers = self.peers.lock().unwrap();
            match peers.keys.get_mut(&slot_id) {
                Some(held) if epoch <= held.current.epoch => return Ok(()),
                Some(held) => {
                    let newer = EpochKey { epoch, opener: FrameOpener::new(key)? };
                    held.previous = Some(std::mem::replace(&mut held.current, newer));
                }
                None => {
                    let current = EpochKey { epoch, opener: FrameOpener::new(key)? };
                    peers.keys.insert(slot_id, PeerKey { current, previous: None });
                }
            }
            // Frames from epochs still ahead wait; the rest open now or never will.
            let early = peers.unkeyed.remove(&slot_id).unwrap_or_default();
            let (ahead, due): (VecDeque<Unkeyed>, VecDeque<Unkeyed>) = early.into_iter().partition(|packet| packet.header.epoch > epoch);
            if !ahead.is_empty() {
                peers.unkeyed.insert(slot_id, ahead);
            }
            let key = &peers.keys[&slot_id];
            due.iter().filter_map(|packet| open(key, &packet.header, &packet.sealed, packet.arrived)).collect()
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
async fn bind_loop(binding: Binding) {
    let retries = BIND_RETRY_DELAYS_MS.windows(2).map(|pair| Duration::from_millis(pair[1] - pair[0]));
    let delays = std::iter::once(Duration::ZERO).chain(retries).chain(std::iter::repeat(BIND_INTERVAL));
    for delay in delays {
        tokio::time::sleep(delay).await;
        let counter = binding.counter.fetch_add(1, Ordering::Relaxed) + 1;
        let bind = VoiceBind::sign(&binding.token, binding.room_id, binding.slot_id, counter);
        if let Err(e) = binding.socket.send(&bind.to_bytes()).await {
            tracing::warn!("media: bind send: {e}");
        }
    }
}

async fn send_loop(socket: Arc<UdpSocket>, mut packets: mpsc::Receiver<Vec<u8>>) {
    while let Some(packet) = packets.recv().await {
        if let Err(e) = socket.send(&packet).await {
            tracing::warn!("media: send: {e}");
        }
    }
}

async fn receive_loop(binding: Binding, path: Arc<PathWatch>, peers: Arc<Mutex<Peers>>, inbound: mpsc::Sender<Inbound>) {
    let own_slot = binding.slot_id;
    let mut buf = [0u8; VOICE_MAX_PACKET];
    loop {
        let (len, arrived) = match binding.socket.recv(&mut buf).await {
            Ok(len) => (len, Instant::now()),
            // Connected UDP sockets report ICMP errors from earlier sends; keep going.
            Err(e) => {
                tracing::debug!("media: receive: {e}");
                continue;
            }
        };
        if let Some(answer) = VoiceBind::from_bytes(&buf[..len]) {
            let ours = answer.room_id == binding.room_id && answer.slot_id == own_slot && answer.verify_answer(&binding.token);
            if ours {
                *path.answered.lock().unwrap() = Some(arrived);
            }
            continue;
        }
        let Some((header, sealed)) = MediaHeader::parse(&buf[..len]) else { continue };
        if header.slot_id == own_slot || sealed.is_empty() {
            continue;
        }
        let frame = {
            let mut peers = peers.lock().unwrap();
            match peers.keys.get(&header.slot_id) {
                // The sender moved epoch before its new presence reached us.
                Some(key) if header.epoch > key.current.epoch => {
                    hold(&mut peers, header, sealed, arrived);
                    None
                }
                Some(key) => open(key, &header, sealed, arrived),
                None => {
                    hold(&mut peers, header, sealed, arrived);
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

    /// A packet from slot 2 sealed in `epoch` with `key`.
    fn peer_packet_in(epoch: u64, key: &[u8; 32], sequence: u32, payload: &[u8]) -> Vec<u8> {
        let sealed = FrameSealer::new(key).unwrap().seal(sequence, payload).unwrap();
        MediaHeader { room_id: ROOM, slot_id: 2, epoch, sequence }.packet(&sealed)
    }

    #[tokio::test]
    async fn a_participant_moving_epoch_is_heard_across_the_change() {
        const NEXT_KEY: [u8; 32] = [5; 32];
        let (session, mut inbound, relay) = session().await;
        let (_, client) = relay_receive(&relay).await;
        session.set_peer(2, EPOCH, &PEER_KEY).unwrap();

        // Frames from the next epoch, before its key, wait for it.
        relay.send_to(&peer_packet_in(EPOCH + 1, &NEXT_KEY, 20, b"ahead"), client).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(inbound.try_recv().is_err(), "a frame from an epoch not keyed yet was delivered");
        session.set_peer(2, EPOCH + 1, &NEXT_KEY).unwrap();
        assert_eq!(next_frame(&mut inbound).await, (2, 20, b"ahead".to_vec()));

        // A frame still in flight from the epoch before opens with the key kept for it.
        relay.send_to(&peer_packet_in(EPOCH, &PEER_KEY, 19, b"late"), client).await.unwrap();
        assert_eq!(next_frame(&mut inbound).await, (2, 19, b"late".to_vec()));

        // Setting the epoch already held changes nothing.
        session.set_peer(2, EPOCH + 1, &NEXT_KEY).unwrap();
        relay.send_to(&peer_packet_in(EPOCH + 1, &NEXT_KEY, 21, b"same"), client).await.unwrap();
        assert_eq!(next_frame(&mut inbound).await, (2, 21, b"same".to_vec()));
    }

    #[tokio::test]
    async fn our_send_key_moves_with_our_epoch() {
        const NEXT_KEY: [u8; 32] = [6; 32];
        let (session, _inbound, relay) = session().await;
        session.set_send_key(EPOCH + 1, &NEXT_KEY).unwrap();
        assert!(session.sender().send(41, b"next"));
        let packet = loop {
            let (packet, _) = relay_receive(&relay).await;
            if VoiceBind::from_bytes(&packet).is_none() {
                break packet;
            }
        };
        let (header, sealed) = MediaHeader::parse(&packet).unwrap();
        assert_eq!(header.epoch, EPOCH + 1);
        assert_eq!(FrameOpener::new(&NEXT_KEY).unwrap().open(41, sealed).unwrap(), b"next");
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

    #[test]
    fn a_path_is_unconfirmed_then_blocked_until_an_answer_comes() {
        let watch = PathWatch::new();
        let start = *watch.binding_since.lock().unwrap();
        assert_eq!(watch.path(start + Duration::from_secs(1)), MediaPath::Unconfirmed);
        assert_eq!(watch.path(start + PATH_VERDICT_AFTER), MediaPath::Blocked);
        let answered = start + Duration::from_secs(6);
        *watch.answered.lock().unwrap() = Some(answered);
        assert_eq!(watch.path(answered + Duration::from_secs(1)), MediaPath::Open);
        assert_eq!(watch.path(answered + BIND_ANSWER_FRESH + Duration::from_secs(1)), MediaPath::Blocked, "answers stopped");
    }

    #[tokio::test]
    async fn the_relays_answer_opens_the_path_and_a_reflected_bind_does_not() {
        let (session, _inbound, relay) = session().await;
        let (first, client) = relay_receive(&relay).await;
        let bind = VoiceBind::from_bytes(&first).unwrap();
        relay.send_to(&first, client).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(session.media_path(), MediaPath::Unconfirmed, "our own bind sent back opened the path");

        relay.send_to(&bind.answer(&TOKEN).to_bytes(), client).await.unwrap();
        tokio::time::timeout(WAIT, async {
            while session.media_path() != MediaPath::Open {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the relay's answer did not open the path");
    }

    #[tokio::test]
    async fn rebinding_starts_the_quick_binds_again_with_higher_counters() {
        let (session, _inbound, relay) = session().await;
        let mut last = 0;
        for _ in BIND_RETRY_DELAYS_MS {
            let (packet, _) = relay_receive(&relay).await;
            last = VoiceBind::from_bytes(&packet).unwrap().counter;
        }
        session.rebind();
        let started = Instant::now();
        let (packet, _) = relay_receive(&relay).await;
        let bind = VoiceBind::from_bytes(&packet).unwrap();
        assert!(started.elapsed() < Duration::from_millis(500), "a rebind waited for the periodic bind");
        assert_eq!(bind.counter, last + 1, "counters keep climbing across a rebind");
        assert!(bind.verify(&TOKEN));
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
