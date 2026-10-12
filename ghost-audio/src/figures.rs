//! Per-stream figures of the current call for the dev builds' profiler: how hard each
//! audio thread works, what goes out, and how each sender's playout is doing. Counts run
//! over the whole call, so a reader that misses a poll loses nothing.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use ghost_media::load::{Load, LoadTimer};

use crate::receiver::PlayoutStats;

/// One sender's playout over the call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerFigures {
    pub slot_id: u32,
    /// Frames buffered, and what its delay policy aims for.
    pub depth: u32,
    pub target: u32,
    pub playout: PlayoutStats,
    /// Every frame that arrived, late ones included, and their encoded size.
    pub received_frames: u64,
    pub received_bytes: u64,
}

/// The call as of a read.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CallFigures {
    /// Since the last read.
    pub capture: Load,
    pub playback: Load,
    /// Over the call: frames sent and their encoded size.
    pub sent_frames: u64,
    pub sent_bytes: u64,
    pub peers: Vec<PeerFigures>,
}

/// Shared by the audio thread, playback and whoever reads.
#[derive(Default)]
pub(crate) struct Figures {
    pub capture: LoadTimer,
    pub playback: LoadTimer,
    sent_frames: AtomicU64,
    sent_bytes: AtomicU64,
    peers: Mutex<Vec<PeerFigures>>,
}

impl Figures {
    /// Afresh for a new call.
    pub fn reset(&self) {
        self.capture.take();
        self.playback.take();
        self.set_sent(0, 0);
        self.peers.lock().unwrap().clear();
    }

    pub fn set_sent(&self, frames: u64, bytes: u64) {
        self.sent_frames.store(frames, Ordering::Relaxed);
        self.sent_bytes.store(bytes, Ordering::Relaxed);
    }

    pub fn set_peers(&self, peers: Vec<PeerFigures>) {
        *self.peers.lock().unwrap() = peers;
    }

    pub fn read(&self) -> CallFigures {
        CallFigures {
            capture: self.capture.take(),
            playback: self.playback.take(),
            sent_frames: self.sent_frames.load(Ordering::Relaxed),
            sent_bytes: self.sent_bytes.load(Ordering::Relaxed),
            peers: self.peers.lock().unwrap().clone(),
        }
    }
}
