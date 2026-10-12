//! What the relay keeps in memory per mailbox: the live fan-out of its log, and the
//! presence its connections announce, which is never written down.

use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

use ghost_wire::presence::PresenceSender;
use ghost_wire::WS_FRAME_HEADER_SIZE;

use crate::constants::{CHANNELS_FANOUT_CAPACITY, FRAME_FANOUT_CAPACITY, PRESENCE_FANOUT_CAPACITY, VOICE_FANOUT_CAPACITY};

/// One log entry as it goes over a mailbox WebSocket, encoded once for every subscriber.
pub struct Frame {
    pub seq: u64,
    /// `[seq:8][received_at:8][payload]`.
    pub encoded: Vec<u8>,
}

impl Frame {
    pub fn new(seq: u64, received_at: u64, payload: &[u8]) -> Self {
        let mut encoded = Vec::with_capacity(WS_FRAME_HEADER_SIZE + payload.len());
        encoded.extend_from_slice(&seq.to_be_bytes());
        encoded.extend_from_slice(&received_at.to_be_bytes());
        encoded.extend_from_slice(payload);
        Self { seq, encoded }
    }
}

/// A device's voice presence in one channel of the server, held by the connection that
/// announced it last.
pub struct VoicePresence {
    pub channel_id: [u8; 32],
    pub conn_id: u64,
    pub from: PresenceSender,
    pub blob: Vec<u8>,
}

/// A device's online presence in the server, held by the connection that announced it
/// last.
pub struct OnlinePresence {
    pub conn_id: u64,
    pub from: PresenceSender,
    pub blob: Vec<u8>,
}

pub struct Mailbox {
    /// Entries as they are committed to the log. A subscriber that misses one, or gets
    /// them out of order, reads the log from where it was.
    pub frames: broadcast::Sender<Arc<Frame>>,
    /// Voice state announcements (`vs`), relayed as they came, tagged by sender connection.
    pub voice_tx: broadcast::Sender<(u64, String)>,
    /// Online presence announcements (`ps`), the same way.
    pub presence_tx: broadcast::Sender<(u64, String)>,
    /// Accounts a private channel of this (server) mailbox now admits; each account's
    /// connections pass the news on as `WS_SIGNAL_CHANNELS`.
    pub channels_tx: broadcast::Sender<[u8; 32]>,
    /// Who is in which voice channel, as announced on connections to this mailbox: one
    /// entry per device, in one channel at most. Announcements are fanned out under this
    /// lock, so a snapshot taken under it matches the fan-out exactly.
    pub voice_presence: Mutex<Vec<VoicePresence>>,
    /// Who is online, as announced on connections to this mailbox: one entry per device,
    /// fanned out under this lock in the same way.
    pub online_presence: Mutex<Vec<OnlinePresence>>,
}

impl Default for Mailbox {
    fn default() -> Self {
        let (frames, _) = broadcast::channel(FRAME_FANOUT_CAPACITY);
        let (voice_tx, _) = broadcast::channel(VOICE_FANOUT_CAPACITY);
        let (presence_tx, _) = broadcast::channel(PRESENCE_FANOUT_CAPACITY);
        let (channels_tx, _) = broadcast::channel(CHANNELS_FANOUT_CAPACITY);
        Self {
            frames,
            voice_tx,
            presence_tx,
            channels_tx,
            voice_presence: Mutex::new(Vec::new()),
            online_presence: Mutex::new(Vec::new()),
        }
    }
}

impl Mailbox {
    /// Hand a committed entry to every live subscriber.
    pub fn publish(&self, seq: u64, received_at: u64, payload: &[u8]) {
        let _ = self.frames.send(Arc::new(Frame::new(seq, received_at, payload)));
    }
}
