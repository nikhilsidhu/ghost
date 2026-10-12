//! A call's audio track: what the microphone hears becomes Opus frames for the media
//! session, and frames from others are buffered, decoded and mixed for playback.
//! Devices plug in through `devices`, at 48 kHz mono.

mod codec;
pub mod constants;
pub mod devices;
mod dsp;
mod engine;
#[cfg(any(test, feature = "test-util"))]
pub mod fake;
#[cfg(feature = "devtools")]
mod figures;
mod policy;
mod processing;
mod receiver;
mod stretch;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

pub use ghost_media::{AudioTrack, TrackEvent, TrackIo};
use ghost_media::TrackQuality;
use ghost_wire::voice::Reception;

use constants::{AGC_START_GAIN_DB, VAD_THRESHOLD};
use processing::CaptureProcessing;
pub use devices::{AudioDevices, CaptureRead, DeviceStreams, Playback};
#[cfg(feature = "devtools")]
pub use figures::{CallFigures, PeerFigures};
#[cfg(feature = "devtools")]
pub use ghost_media::load::Load;
pub use receiver::PlayoutStats;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NoiseSuppressionMode {
    Off = 0,
    Nnnoiseless = 1,
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
    /// Everything goes out but digital silence, which no microphone makes: for synthetic
    /// devices, whose tones are not speech but whose pauses are real.
    Continuous = 2,
}

impl From<u8> for InputMode {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::PushToTalk,
            2 => Self::Continuous,
            _ => Self::VoiceActivity,
        }
    }
}

/// Told a microphone's name and the gain the volume normalizer settled on for it.
pub type GainListener = Arc<dyn Fn(&str, f32) + Send + Sync>;

/// Settings and readings shared with the audio thread, which reads them every frame.
pub(crate) struct AudioControls {
    pub muted: AtomicBool,
    pub deafened: AtomicBool,
    pub speaking: AtomicBool,
    pub packet_loss_pct: AtomicU32,
    pub jitter_depth: AtomicU32,
    pub jitter_target: AtomicU32,
    /// Loss heard from each sender over the last quality reading.
    pub reception: Mutex<Vec<Reception>>,
    /// The worst loss (percent) the others report on our frames.
    pub expected_loss: AtomicU8,
    /// Whether what we send is protected against that loss.
    pub loss_protection: AtomicBool,
    pub noise_suppression: AtomicU8,
    pub agc: AtomicU8,
    pub vad_threshold: AtomicU32,
    pub input_gain: AtomicU32,
    pub input_mode: AtomicU8,
    pub ptt_active: AtomicBool,
    pub echo_cancellation: AtomicBool,
    /// RMS of the last captured frame after the input gain, 0 to 1, for a level meter.
    pub input_level: AtomicU32,
    /// The gain the volume normalizer settled on, by microphone, to start from next time.
    pub learned_gains: Mutex<HashMap<String, f32>>,
    pub gain_listener: Mutex<Option<GainListener>>,
    /// Capture processing kept between calls, so each starts where the last left off;
    /// the running call holds it.
    pub processing: Mutex<Option<CaptureProcessing>>,
    /// What playout has done this call, gathered every few seconds.
    pub playout_totals: Mutex<PlayoutStats>,
    #[cfg(feature = "devtools")]
    pub figures: figures::Figures,
}

impl AudioControls {
    pub(crate) fn new() -> Self {
        Self {
            muted: AtomicBool::new(false),
            deafened: AtomicBool::new(false),
            speaking: AtomicBool::new(false),
            packet_loss_pct: AtomicU32::new(0),
            jitter_depth: AtomicU32::new(0),
            jitter_target: AtomicU32::new(0),
            reception: Mutex::new(Vec::new()),
            expected_loss: AtomicU8::new(0),
            loss_protection: AtomicBool::new(true),
            noise_suppression: AtomicU8::new(NoiseSuppressionMode::Nnnoiseless as u8),
            agc: AtomicU8::new(AgcMode::Auto as u8),
            vad_threshold: AtomicU32::new(VAD_THRESHOLD.to_bits()),
            input_gain: AtomicU32::new(1.0f32.to_bits()),
            input_mode: AtomicU8::new(InputMode::VoiceActivity as u8),
            ptt_active: AtomicBool::new(false),
            echo_cancellation: AtomicBool::new(true),
            input_level: AtomicU32::new(0.0f32.to_bits()),
            learned_gains: Mutex::new(HashMap::new()),
            gain_listener: Mutex::new(None),
            processing: Mutex::new(None),
            playout_totals: Mutex::new(PlayoutStats::default()),
            #[cfg(feature = "devtools")]
            figures: figures::Figures::default(),
        }
    }

    /// The gain to start `input`'s volume normalizer at.
    pub(crate) fn start_gain_db(&self, input: &str) -> f32 {
        self.learned_gains.lock().unwrap().get(input).copied().unwrap_or(AGC_START_GAIN_DB)
    }

    /// The normalizer settled on `gain_db` for `input`.
    pub(crate) fn learned(&self, input: &str, gain_db: f32) {
        self.learned_gains.lock().unwrap().insert(input.to_string(), gain_db);
        let listener = self.gain_listener.lock().unwrap().clone();
        if let Some(listener) = listener {
            listener(input, gain_db);
        }
    }
}

/// The audio thread of the current call, and which start it came from.
struct Running {
    stop: Arc<AtomicBool>,
    run: TrackRun,
}

/// One start of the track, so whoever started it can stop that one alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrackRun(u64);

/// Voice audio on a set of devices. Settings persist across calls and may change at
/// any time; each call runs its own audio thread.
pub struct VoiceAudio {
    controls: Arc<AudioControls>,
    devices: Arc<dyn AudioDevices>,
    running: Mutex<Option<Running>>,
    runs: AtomicU64,
}

impl VoiceAudio {
    pub fn new(devices: Arc<dyn AudioDevices>) -> Self {
        Self { controls: Arc::new(AudioControls::new()), devices, running: Mutex::new(None), runs: AtomicU64::new(0) }
    }

    /// Start the track as `AudioTrack::start` does, returning the run to stop later. A
    /// failure of its devices goes to `io.events` unless the run was stopped first.
    pub fn start_run(&self, io: TrackIo) -> Result<TrackRun, String> {
        self.stop();
        *self.controls.playout_totals.lock().unwrap() = PlayoutStats::default();
        // Nobody has reported on this call's frames yet.
        self.controls.expected_loss.store(0, Ordering::Relaxed);
        self.controls.reception.lock().unwrap().clear();
        #[cfg(feature = "devtools")]
        self.controls.figures.reset();
        let stop = Arc::new(AtomicBool::new(false));
        let run = TrackRun(self.runs.fetch_add(1, Ordering::Relaxed) + 1);
        let (controls, devices, thread_stop, events) = (self.controls.clone(), self.devices.clone(), stop.clone(), io.events.clone());
        std::thread::Builder::new()
            .name("voice-audio".into())
            .spawn(move || {
                if let Err(e) = engine::run(controls, devices, io, thread_stop.clone()) {
                    tracing::error!("voice audio thread failed: {e}");
                    if !thread_stop.load(Ordering::Relaxed) {
                        let _ = events.send(TrackEvent::Failed(e));
                    }
                }
            })
            .map_err(|e| format!("spawn audio thread: {e}"))?;
        *self.running.lock().unwrap() = Some(Running { stop, run });
        Ok(run)
    }

    /// Stop the track if `run` is still what runs; a later start is left alone.
    pub fn stop_run(&self, run: TrackRun) {
        let mut running = self.running.lock().unwrap();
        if running.as_ref().is_some_and(|r| r.run == run) {
            self.halt(running.take());
        }
    }

    // The thread is told to stop and left to finish its current frame, rather than
    // joined, so callers on an async runtime never block on device teardown.
    fn halt(&self, running: Option<Running>) {
        if let Some(running) = running {
            running.stop.store(true, Ordering::Relaxed);
        }
        self.controls.speaking.store(false, Ordering::Relaxed);
        self.controls.input_level.store(0.0f32.to_bits(), Ordering::Relaxed);
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

    /// Whether what the speakers play is taken out of the microphone. On by default; a
    /// running call follows a change at once.
    pub fn set_echo_cancellation(&self, enabled: bool) {
        self.controls.echo_cancellation.store(enabled, Ordering::Relaxed);
    }

    /// The gains the volume normalizer settled on before, by microphone, for it to
    /// start from instead of finding the level again.
    pub fn set_learned_gains(&self, gains: HashMap<String, f32>) {
        *self.controls.learned_gains.lock().unwrap() = gains;
    }

    /// Call `listener` whenever the normalizer settles on a microphone's gain (at the
    /// end of a call, and when capture moves to another microphone), so it can be kept
    /// for next time. It runs on the audio thread and should return quickly.
    pub fn on_gain_learned(&self, listener: impl Fn(&str, f32) + Send + Sync + 'static) {
        *self.controls.gain_listener.lock().unwrap() = Some(Arc::new(listener));
    }

    /// How loud the microphone is right now, 0 to 1, after the input gain; 0 between calls.
    pub fn input_level(&self) -> f32 {
        f32::from_bits(self.controls.input_level.load(Ordering::Relaxed))
    }

    /// What playout has done in the current call, as of the last quality reading.
    pub fn playout_stats(&self) -> PlayoutStats {
        *self.controls.playout_totals.lock().unwrap()
    }

    /// Whether what this device sends is protected (Opus FEC) once the others report
    /// losing it. On by default: it carries speech through loss far better than
    /// concealment does. Off for synthetic tones, which Opus's concealment carries
    /// through a loss and its FEC does not.
    pub fn set_loss_protection(&self, enabled: bool) {
        self.controls.loss_protection.store(enabled, Ordering::Relaxed);
    }

    /// The worst loss (percent) the others last reported on what this device sends.
    pub fn expected_loss(&self) -> u8 {
        self.controls.expected_loss.load(Ordering::Relaxed)
    }

    /// The current call's figures, its audio threads' loads since the last read.
    #[cfg(feature = "devtools")]
    pub fn call_figures(&self) -> CallFigures {
        self.controls.figures.read()
    }
}

impl AudioTrack for VoiceAudio {
    fn start(&self, io: TrackIo) -> Result<(), String> {
        self.start_run(io).map(|_| ())
    }

    fn stop(&self) {
        let running = self.running.lock().unwrap().take();
        self.halt(running);
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

    fn reception(&self) -> Vec<Reception> {
        self.controls.reception.lock().unwrap().clone()
    }

    fn set_expected_loss(&self, loss_pct: u8) {
        self.controls.expected_loss.store(loss_pct, Ordering::Relaxed);
    }
}
