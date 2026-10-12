//! What a call needs from the crate that captures, encodes, decodes and plays its
//! audio. The call owns signaling and the media session and drives the track through
//! this interface, so the desktop app and headless devices run the same call.

use ghost_wire::voice::Reception;
use tokio::sync::mpsc;

use crate::session::{FrameSender, Inbound};

/// The two ends of the media session a running track uses, and where it reports to the
/// call.
pub struct TrackIo {
    /// Where encoded frames go, each with its sequence number.
    pub sender: FrameSender,
    /// Decrypted frames from the other participants, and their departures.
    pub received: mpsc::Receiver<Inbound>,
    /// What the call must know about the track; usable from the track's own threads.
    pub events: mpsc::UnboundedSender<TrackEvent>,
}

/// What a running track tells the call about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackEvent {
    /// Worth telling the user while the track runs on: a device went away and another
    /// took its place.
    Notice(String),
    /// The track stopped for good (its devices failed to open, or failed for good); the
    /// call has no audio.
    Failed(String),
}

/// How playback is going, for the call quality indicator.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct TrackQuality {
    pub packet_loss_pct: f32,
    /// Frames buffered for the deepest sender, and what it aims for.
    pub jitter_depth: u32,
    pub jitter_target: u32,
}

/// The local audio of a voice call. Mute and deafen persist across calls, so they may
/// be set before `start`.
pub trait AudioTrack: Send + Sync + 'static {
    /// Start capturing into `io.sender` and playing what arrives on `io.received`.
    fn start(&self, io: TrackIo) -> Result<(), String>;
    /// Stop capturing and playing; a later `start` begins afresh.
    fn stop(&self);
    fn set_muted(&self, muted: bool);
    fn set_deafened(&self, deafened: bool);
    /// Whether the local user is speaking (and so transmitting) now.
    fn speaking(&self) -> bool;
    fn quality(&self) -> TrackQuality;
    /// How much of each other caller's frames was lost on the way here lately, by slot,
    /// for telling each how much to protect what it sends. Callers not heard enough
    /// lately to tell are left out.
    fn reception(&self) -> Vec<Reception>;
    /// The worst loss (percent) the others report on our frames lately, which what we
    /// send is protected against.
    fn set_expected_loss(&self, loss_pct: u8);
}
