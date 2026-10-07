//! Where a call's audio comes from and goes. Devices deliver and take 48 kHz mono;
//! converting to and from what the hardware runs at is theirs to do.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::receiver::Receiver;
use crate::AudioControls;

/// A source of devices for calls.
pub trait AudioDevices: Send + Sync + 'static {
    /// Open capture and playback for a call. Runs on the engine's audio thread, which
    /// keeps the result until the call ends; playback pulls from `playback` at the pace
    /// of its own clock.
    fn open(&self, playback: Playback) -> Result<Box<dyn DeviceStreams>, String>;
}

/// The open devices of one call.
pub trait DeviceStreams {
    /// Wait up to `timeout` for the next frame of capture, `FRAME_SAMPLES` long.
    fn read_frame(&mut self, frame: &mut [f32], timeout: Duration) -> CaptureRead;
}

pub enum CaptureRead {
    /// `frame` holds the next 20 ms.
    Frame,
    /// Nothing yet.
    Waiting,
    /// The devices were reopened (the default device changed); capture continues but
    /// is not continuous with what came before.
    Restarted,
    /// The devices are gone for good; the call's audio ends.
    Failed(String),
}

/// Mixed audio for playback: every sender's playout, summed. Clones share one mixer,
/// so a reopened output stream picks up where the old one left off.
#[derive(Clone)]
pub struct Playback {
    mixer: Arc<Mutex<Mixer>>,
    controls: Arc<AudioControls>,
}

pub(crate) struct Mixer {
    /// Each sender's playout, by slot.
    pub(crate) receivers: HashMap<u32, Receiver>,
}

impl Playback {
    pub(crate) fn new(controls: Arc<AudioControls>) -> Self {
        Self { mixer: Arc::new(Mutex::new(Mixer { receivers: HashMap::new() })), controls }
    }

    pub(crate) fn mixer(&self) -> std::sync::MutexGuard<'_, Mixer> {
        self.mixer.lock().unwrap()
    }

    /// Fill `out` with the next stretch of mixed audio. The device's clock drives this;
    /// each sender's playout keeps its own delay. Deafened, playout runs on unheard so
    /// nothing piles up.
    pub fn fill(&self, out: &mut [f32]) {
        let deafened = self.controls.deafened.load(Ordering::Relaxed);
        out.fill(0.0);
        let len = out.len();
        let mut mixer = self.mixer();
        for receiver in mixer.receivers.values_mut() {
            while receiver.output.len() < len {
                receiver.produce();
            }
            for (mixed, sample) in out.iter_mut().zip(receiver.output.drain(..len)) {
                if !deafened {
                    *mixed += sample;
                }
            }
        }
        for sample in out.iter_mut() {
            *sample = sample.clamp(-1.0, 1.0);
        }
    }
}
