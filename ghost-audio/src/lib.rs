//! A call's audio track: what the microphone hears becomes Opus frames for the media
//! session, and frames from others are buffered, decoded and mixed for playback.
//! Devices plug in through `devices`, at 48 kHz mono.

pub mod constants;
pub mod devices;
mod dsp;
mod engine;
#[cfg(feature = "test-util")]
pub mod fake;
mod policy;
mod receiver;
mod stretch;

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use ghost_media::{AudioTrack, TrackIo, TrackQuality};

use constants::VAD_THRESHOLD;
pub use devices::{AudioDevices, CaptureRead, DeviceStreams, Playback};
pub use receiver::PlayoutStats;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NoiseSuppressionMode {
    Off = 0,
    Nnnoiseless = 1,
}

impl NoiseSuppressionMode {
    /// From the configuration value: "off", or anything else for on.
    pub fn from_config(s: &str) -> Self {
        match s {
            "off" => Self::Off,
            _ => Self::Nnnoiseless,
        }
    }
}

impl From<u8> for NoiseSuppressionMode {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Off,
            _ => Self::Nnnoiseless,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AgcMode {
    Off = 0,
    Auto = 1,
}

impl AgcMode {
    /// From the configuration value: "off", or anything else for automatic.
    pub fn from_config(s: &str) -> Self {
        match s {
            "off" => Self::Off,
            _ => Self::Auto,
        }
    }
}

impl From<u8> for AgcMode {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Off,
            _ => Self::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InputMode {
    VoiceActivity = 0,
    PushToTalk = 1,
}

impl InputMode {
    /// From the configuration value: "push_to_talk", or anything else for voice activity.
    pub fn from_config(s: &str) -> Self {
        match s {
            "push_to_talk" => Self::PushToTalk,
            _ => Self::VoiceActivity,
        }
    }
}

impl From<u8> for InputMode {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::PushToTalk,
            _ => Self::VoiceActivity,
        }
    }
}

/// Settings and readings shared with the audio thread, which reads them every frame.
pub(crate) struct AudioControls {
    pub muted: AtomicBool,
    pub deafened: AtomicBool,
    pub speaking: AtomicBool,
    pub packet_loss_pct: AtomicU32,
    pub jitter_depth: AtomicU32,
    pub jitter_target: AtomicU32,
    pub noise_suppression: AtomicU8,
    pub agc: AtomicU8,
    pub vad_threshold: AtomicU32,
    pub input_gain: AtomicU32,
    pub input_mode: AtomicU8,
    pub ptt_active: AtomicBool,
    /// What playout has done this call, gathered every few seconds.
    pub playout_totals: Mutex<PlayoutStats>,
}

impl AudioControls {
    fn new() -> Self {
        Self {
            muted: AtomicBool::new(false),
            deafened: AtomicBool::new(false),
            speaking: AtomicBool::new(false),
            packet_loss_pct: AtomicU32::new(0),
            jitter_depth: AtomicU32::new(0),
            jitter_target: AtomicU32::new(0),
            noise_suppression: AtomicU8::new(NoiseSuppressionMode::Nnnoiseless as u8),
            agc: AtomicU8::new(AgcMode::Auto as u8),
            vad_threshold: AtomicU32::new(VAD_THRESHOLD.to_bits()),
            input_gain: AtomicU32::new(1.0f32.to_bits()),
            input_mode: AtomicU8::new(InputMode::VoiceActivity as u8),
            ptt_active: AtomicBool::new(false),
            playout_totals: Mutex::new(PlayoutStats::default()),
        }
    }
}

/// The audio thread of the current call.
struct Running {
    stop: Arc<AtomicBool>,
}

/// Voice audio on a set of devices. Settings persist across calls and may change at
/// any time; each call runs its own audio thread.
pub struct VoiceAudio {
    controls: Arc<AudioControls>,
    devices: Arc<dyn AudioDevices>,
    running: Mutex<Option<Running>>,
}

impl VoiceAudio {
    pub fn new(devices: Arc<dyn AudioDevices>) -> Self {
        Self { controls: Arc::new(AudioControls::new()), devices, running: Mutex::new(None) }
    }

    pub fn set_noise_suppression(&self, mode: NoiseSuppressionMode) {
        self.controls.noise_suppression.store(mode as u8, Ordering::Relaxed);
    }

    pub fn set_agc(&self, mode: AgcMode) {
        self.controls.agc.store(mode as u8, Ordering::Relaxed);
    }

    /// Voice probability above which voice activity counts as speech.
    pub fn set_vad_threshold(&self, threshold: f32) {
        self.controls.vad_threshold.store(threshold.to_bits(), Ordering::Relaxed);
    }

    /// Gain applied to the microphone before any processing.
    pub fn set_input_gain(&self, gain: f32) {
        self.controls.input_gain.store(gain.to_bits(), Ordering::Relaxed);
    }

    pub fn set_input_mode(&self, mode: InputMode) {
        self.controls.input_mode.store(mode as u8, Ordering::Relaxed);
    }

    /// Whether the push-to-talk key is held.
    pub fn set_ptt_active(&self, active: bool) {
        self.controls.ptt_active.store(active, Ordering::Relaxed);
    }

    /// What playout has done in the current call, as of the last quality reading.
    pub fn playout_stats(&self) -> PlayoutStats {
        *self.controls.playout_totals.lock().unwrap()
    }
}

impl AudioTrack for VoiceAudio {
    fn start(&self, io: TrackIo) -> Result<(), String> {
        self.stop();
        *self.controls.playout_totals.lock().unwrap() = PlayoutStats::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (controls, devices, thread_stop) = (self.controls.clone(), self.devices.clone(), stop.clone());
        std::thread::Builder::new()
            .name("voice-audio".into())
            .spawn(move || {
                if let Err(e) = engine::run(controls, devices, io, thread_stop) {
                    eprintln!("voice audio thread failed: {e}");
                }
            })
            .map_err(|e| format!("spawn audio thread: {e}"))?;
        *self.running.lock().unwrap() = Some(Running { stop });
        Ok(())
    }

    // The thread is told to stop and left to finish its current frame, rather than
    // joined, so callers on an async runtime never block on device teardown.
    fn stop(&self) {
        if let Some(running) = self.running.lock().unwrap().take() {
            running.stop.store(true, Ordering::Relaxed);
        }
        self.controls.speaking.store(false, Ordering::Relaxed);
    }

    fn set_muted(&self, muted: bool) {
        self.controls.muted.store(muted, Ordering::Relaxed);
    }

    fn set_deafened(&self, deafened: bool) {
        self.controls.deafened.store(deafened, Ordering::Relaxed);
    }

    fn speaking(&self) -> bool {
        self.controls.speaking.load(Ordering::Relaxed)
    }

    fn quality(&self) -> TrackQuality {
        TrackQuality {
            packet_loss_pct: f32::from_bits(self.controls.packet_loss_pct.load(Ordering::Relaxed)),
            jitter_depth: self.controls.jitter_depth.load(Ordering::Relaxed),
            jitter_target: self.controls.jitter_target.load(Ordering::Relaxed),
        }
    }
}
