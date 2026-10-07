//! The audio thread of a call: paced by capture, it processes and encodes what the
//! microphone hears, and hands received frames to the jitter buffers playback mixes.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ghost_media::{FrameSender, Inbound, TrackIo};
use tokio::sync::mpsc;

use crate::constants::*;
use crate::devices::{AudioDevices, CaptureRead, Playback};
use crate::dsp::{denoise_frame, energy_vad, Agc};
use crate::receiver::{PlayoutStats, Receiver};
use crate::{AgcMode, AudioControls, InputMode, NoiseSuppressionMode};

/// CELT-only fullband 20 ms mono silence; resets the receiver's decoder state cleanly.
const OPUS_SILENCE: [u8; 3] = [0xF8, 0xFF, 0xFE];

const FRAME_DURATION: Duration = Duration::from_millis(FRAME_MS as u64);

fn create_encoder() -> Result<opus::Encoder, String> {
    let mut encoder = opus::Encoder::new(SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip)
        .map_err(|e| format!("opus encoder: {e}"))?;
    encoder.set_bitrate(opus::Bitrate::Bits(OPUS_BITRATE)).map_err(|e| format!("opus bitrate: {e}"))?;
    encoder.set_vbr(true).map_err(|e| format!("opus vbr: {e}"))?;
    encoder.set_complexity(OPUS_COMPLEXITY).map_err(|e| format!("opus complexity: {e}"))?;
    encoder.set_inband_fec(true).map_err(|e| format!("opus fec: {e}"))?;
    encoder.set_packet_loss_perc(OPUS_EXPECTED_LOSS_PCT).map_err(|e| format!("opus loss pct: {e}"))?;
    Ok(encoder)
}

/// Turns captured frames into sent ones: gain, noise suppression, voice activity,
/// normalization, Opus, and the talk-spurt edges (pre-roll, closing silence).
struct Transmitter {
    sender: FrameSender,
    encoder: opus::Encoder,
    denoiser: Box<nnnoiseless::DenoiseState<'static>>,
    /// nnnoiseless's first frame after a reset is unreliable and is not sent.
    denoise_primed: bool,
    last_ns_mode: NoiseSuppressionMode,
    agc: Agc,
    /// The sender's media clock: one step per captured frame, sent or not, so
    /// receivers can tell lateness from silence.
    sequence: u32,
    vad_hangover: u32,
    was_speaking: bool,
    /// Silence frames still to send closing the last talk spurt.
    closing: usize,
    /// Recent encoded frames while silent, sent at speech onset.
    pre_roll: VecDeque<(u32, Vec<u8>)>,
    encode_buf: Vec<u8>,
    denoise_in: [f32; DENOISE_FRAME_SIZE],
    denoise_out: [f32; DENOISE_FRAME_SIZE],
    frames_sent: u32,
}

impl Transmitter {
    fn new(sender: FrameSender) -> Result<Self, String> {
        Ok(Self {
            sender,
            encoder: create_encoder()?,
            denoiser: nnnoiseless::DenoiseState::new(),
            denoise_primed: false,
            last_ns_mode: NoiseSuppressionMode::Nnnoiseless,
            agc: Agc::new(),
            sequence: 0,
            vad_hangover: 0,
            was_speaking: false,
            closing: 0,
            pre_roll: VecDeque::with_capacity(PRE_ROLL_FRAMES),
            encode_buf: vec![0; OPUS_MAX_FRAME_BYTES],
            denoise_in: [0.0; DENOISE_FRAME_SIZE],
            denoise_out: [0.0; DENOISE_FRAME_SIZE],
            frames_sent: 0,
        })
    }

    fn send(&mut self, sequence: u32, frame: &[u8]) {
        let _ = self.sender.send(sequence, frame);
        self.frames_sent += 1;
    }

    fn next_sequence(&mut self) -> u32 {
        let sequence = self.sequence;
        self.sequence = sequence.wrapping_add(1);
        sequence
    }

    /// A frame without speech: a talk spurt that just ended is closed over the next
    /// frames with silence, so receivers' decoders reset cleanly. True when this frame
    /// went out as one of those.
    fn quiet(&mut self, sequence: u32) -> bool {
        if self.was_speaking {
            self.was_speaking = false;
            self.closing = SILENCE_FRAME_COUNT;
        }
        if self.closing == 0 {
            return false;
        }
        self.closing -= 1;
        self.send(sequence, &OPUS_SILENCE);
        true
    }

    fn process(&mut self, frame: &mut [f32], controls: &AudioControls) {
        let sequence = self.next_sequence();
        let muted = controls.muted.load(Ordering::Relaxed);
        let mode = InputMode::from(controls.input_mode.load(Ordering::Relaxed));
        let ptt_active = controls.ptt_active.load(Ordering::Relaxed);
        // Mute always wins; push to talk sends only while the key is held.
        if muted || (mode == InputMode::PushToTalk && !ptt_active) {
            self.vad_hangover = 0;
            controls.speaking.store(false, Ordering::Relaxed);
            self.quiet(sequence);
            self.pre_roll.clear();
            return;
        }

        let gain = f32::from_bits(controls.input_gain.load(Ordering::Relaxed));
        if gain != 1.0 {
            for s in frame.iter_mut() {
                *s = (*s * gain).clamp(-1.0, 1.0);
            }
        }

        let ns_mode = NoiseSuppressionMode::from(controls.noise_suppression.load(Ordering::Relaxed));
        if ns_mode == NoiseSuppressionMode::Nnnoiseless && self.last_ns_mode != NoiseSuppressionMode::Nnnoiseless {
            self.denoise_primed = false;
        }
        self.last_ns_mode = ns_mode;
        let voice_probability = match ns_mode {
            NoiseSuppressionMode::Nnnoiseless => {
                let vad = denoise_frame(&mut self.denoiser, frame, &mut self.denoise_in, &mut self.denoise_out);
                if !self.denoise_primed {
                    self.denoise_primed = true;
                    self.quiet(sequence);
                    return;
                }
                vad
            }
            NoiseSuppressionMode::Off => energy_vad(frame),
        };

        let speaking = match mode {
            InputMode::PushToTalk => true,
            InputMode::VoiceActivity => {
                // Stay "speaking" briefly after the voice drops, so word ends go out.
                let threshold = f32::from_bits(controls.vad_threshold.load(Ordering::Relaxed));
                if voice_probability > threshold {
                    self.vad_hangover = VAD_HANGOVER_FRAMES;
                } else if self.vad_hangover > 0 {
                    self.vad_hangover -= 1;
                }
                self.vad_hangover > 0
            }
        };
        controls.speaking.store(speaking, Ordering::Relaxed);

        if AgcMode::from(controls.agc.load(Ordering::Relaxed)) == AgcMode::Auto {
            self.agc.process(frame);
        }

        // Encode every frame, sent or not, so the encoder's state stays warm.
        let Ok(len) = self.encoder.encode_float(frame, &mut self.encode_buf) else { return };
        if speaking {
            if !self.was_speaking {
                while let Some((pre_sequence, pre_frame)) = self.pre_roll.pop_front() {
                    self.send(pre_sequence, &pre_frame);
                }
            }
            self.was_speaking = true;
            self.closing = 0;
            let encoded = self.encode_buf[..len].to_vec();
            self.send(sequence, &encoded);
        } else if !self.quiet(sequence) {
            if self.pre_roll.len() >= PRE_ROLL_FRAMES {
                self.pre_roll.pop_front();
            }
            self.pre_roll.push_back((sequence, self.encode_buf[..len].to_vec()));
        }
    }
}

/// Hand what the session received to each sender's playout. Returns how many frames.
fn route_inbound(received: &mut mpsc::Receiver<Inbound>, playback: &Playback) -> u32 {
    let mut frames = 0;
    let mut mixer = playback.mixer();
    while let Ok(inbound) = received.try_recv() {
        match inbound {
            Inbound::Frame(frame) => {
                frames += 1;
                let receiver = match mixer.receivers.entry(frame.slot_id) {
                    std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::hash_map::Entry::Vacant(entry) => match Receiver::new() {
                        Ok(receiver) => entry.insert(receiver),
                        Err(e) => {
                            eprintln!("voice: {e}");
                            continue;
                        }
                    },
                };
                receiver.insert(frame.sequence, frame.payload, frame.arrived);
            }
            Inbound::PeerLeft(slot_id) => {
                mixer.receivers.remove(&slot_id);
            }
        }
    }
    frames
}

/// Read playout quality since the last reading into the controls, and drop the
/// playout of senders long gone quiet.
fn read_quality(playback: &Playback, controls: &AudioControls) -> String {
    let mut mixer = playback.mixer();
    let summary: Vec<String> =
        mixer.receivers.values().map(|r| format!("d{}t{}", r.buffered(), r.target())).collect();
    let mut window = PlayoutStats::default();
    let (mut max_depth, mut max_target) = (0u32, 0u32);
    for receiver in mixer.receivers.values_mut() {
        window.add(&receiver.stats);
        receiver.stats = PlayoutStats::default();
        max_depth = max_depth.max(receiver.buffered());
        max_target = max_target.max(receiver.target());
    }
    mixer.receivers.retain(|_, receiver| !receiver.is_idle());
    drop(mixer);
    let heard = window.played + window.recovered + window.concealed + window.dropped_late;
    let lost = window.recovered + window.concealed + window.dropped_late;
    let loss_pct = if heard > 0 { lost as f32 / heard as f32 * 100.0 } else { 0.0 };
    controls.packet_loss_pct.store(loss_pct.to_bits(), Ordering::Relaxed);
    controls.jitter_depth.store(max_depth, Ordering::Relaxed);
    controls.jitter_target.store(max_target, Ordering::Relaxed);
    controls.playout_totals.lock().unwrap().add(&window);
    format!("{} {window:?}", summary.join(","))
}

/// Run a call's audio until `stop` is set, the session ends, or the devices fail.
pub(crate) fn run(
    controls: Arc<AudioControls>,
    devices: Arc<dyn AudioDevices>,
    io: TrackIo,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    let TrackIo { sender, mut received } = io;
    let playback = Playback::new(controls.clone());
    let mut streams = devices.open(playback.clone())?;
    let mut transmitter = Transmitter::new(sender.clone())?;
    let mut frame = vec![0.0f32; FRAME_SAMPLES];

    let (mut ticks, mut frames_received, mut capture_empty) = (0u32, 0u32, 0u32);
    while !stop.load(Ordering::Relaxed) && !sender.is_closed() {
        frames_received += route_inbound(&mut received, &playback);

        // Capture paces the loop: wait for one frame, then take any that queued up.
        let mut timeout = FRAME_DURATION;
        let mut got_capture = false;
        loop {
            match streams.read_frame(&mut frame, timeout) {
                CaptureRead::Frame => {
                    got_capture = true;
                    transmitter.process(&mut frame, &controls);
                    timeout = Duration::ZERO;
                }
                CaptureRead::Waiting => break,
                CaptureRead::Restarted => {
                    eprintln!("voice: audio devices reopened");
                    transmitter.denoise_primed = false;
                }
                CaptureRead::Failed(e) => return Err(e),
            }
        }
        if !got_capture {
            capture_empty += 1;
        }

        ticks += 1;
        if ticks >= DIAG_TICKS {
            let playout = read_quality(&playback, &controls);
            eprintln!(
                "voice diag: sent={} recv={frames_received} cap_empty={capture_empty}/{ticks} playout=[{playout}]",
                transmitter.frames_sent
            );
            (ticks, frames_received, capture_empty, transmitter.frames_sent) = (0, 0, 0, 0);
        }
    }
    read_quality(&playback, &controls);
    controls.speaking.store(false, Ordering::Relaxed);
    Ok(())
}
