//! The audio thread of a call: paced by capture, it processes and encodes what the
//! microphone hears, and hands received frames to the playout playback runs.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ghost_media::{FrameSender, Inbound, TrackEvent, TrackIo};
use tokio::sync::mpsc;

use crate::constants::*;
use crate::devices::{AudioDevices, CaptureRead, Playback, PlayoutLink};
use crate::dsp::denoise_frame;
use crate::processing::{CaptureProcessing, EchoCanceller, VolumeNormalizer};
use crate::receiver::PlayoutStats;
use crate::{AgcMode, AudioControls, InputMode, NoiseSuppressionMode};
use ghost_wire::voice::Reception;

/// CELT-only fullband 20 ms mono silence; resets the receiver's decoder state cleanly.
const OPUS_SILENCE: [u8; 3] = [0xF8, 0xFF, 0xFE];

const FRAME_DURATION: Duration = Duration::from_millis(FRAME_MS as u64);

/// The voice diagnostics are worth reading in dev builds, where the launcher keeps logs.
const DIAG_LEVEL: tracing::Level = if cfg!(feature = "devtools") { tracing::Level::INFO } else { tracing::Level::DEBUG };

fn create_encoder() -> Result<opus::Encoder, String> {
    let mut encoder = opus::Encoder::new(SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip)
        .map_err(|e| format!("opus encoder: {e}"))?;
    encoder.set_bitrate(opus::Bitrate::Bits(OPUS_BITRATE)).map_err(|e| format!("opus bitrate: {e}"))?;
    encoder.set_vbr(true).map_err(|e| format!("opus vbr: {e}"))?;
    encoder.set_complexity(OPUS_COMPLEXITY).map_err(|e| format!("opus complexity: {e}"))?;
    // The microphone carries voice: whatever the encoder might take for music (laughter,
    // humming) is still coded as voice, and so still protected once loss is reported.
    encoder.set_signal(opus::Signal::Voice).map_err(|e| format!("opus signal: {e}"))?;
    // Used only while the others report loss (`opus_loss_pct`); until then no bits go to it.
    encoder.set_inband_fec(true).map_err(|e| format!("opus fec: {e}"))?;
    encoder.set_packet_loss_perc(0).map_err(|e| format!("opus loss pct: {e}"))?;
    Ok(encoder)
}

/// The loss Opus protects against for the worst loss the others report: the highest
/// step at or below it, none below the first.
fn opus_loss_pct(reported: u8) -> i32 {
    OPUS_LOSS_STEPS.iter().rev().find(|step| reported >= **step).map_or(0, |step| *step as i32)
}

/// Turns captured frames into sent ones: echo cancellation, gain, noise suppression,
/// voice activity, normalization, Opus, and the talk-spurt edges (pre-roll, closing
/// silence).
struct Transmitter {
    sender: FrameSender,
    encoder: opus::Encoder,
    /// The loss the encoder protects against now, percent.
    opus_loss: i32,
    processing: CaptureProcessing,
    /// Runs on every frame, for its speech probability whether or not its denoised
    /// audio is used.
    denoiser: Box<nnnoiseless::DenoiseState<'static>>,
    /// nnnoiseless's first frame after a reset is unreliable and is not sent.
    denoise_primed: bool,
    /// A frame's copy for nnnoiseless when noise suppression is off and the frame goes
    /// out untouched.
    analysis: Vec<f32>,
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
    /// Frames sent over the call, and their encoded size.
    #[cfg(feature = "devtools")]
    sent: (u64, u64),
}

impl Transmitter {
    fn new(sender: FrameSender, processing: CaptureProcessing) -> Result<Self, String> {
        Ok(Self {
            sender,
            encoder: create_encoder()?,
            opus_loss: 0,
            processing,
            denoiser: nnnoiseless::DenoiseState::new(),
            denoise_primed: false,
            analysis: vec![0.0; FRAME_SAMPLES],
            sequence: 0,
            vad_hangover: 0,
            was_speaking: false,
            closing: 0,
            pre_roll: VecDeque::with_capacity(PRE_ROLL_FRAMES),
            encode_buf: vec![0; OPUS_MAX_FRAME_BYTES],
            denoise_in: [0.0; DENOISE_FRAME_SIZE],
            denoise_out: [0.0; DENOISE_FRAME_SIZE],
            frames_sent: 0,
            #[cfg(feature = "devtools")]
            sent: (0, 0),
        })
    }

    fn send(&mut self, sequence: u32, frame: &[u8]) {
        let _ = self.sender.send(sequence, frame);
        self.frames_sent += 1;
        #[cfg(feature = "devtools")]
        {
            self.sent.0 += 1;
            self.sent.1 += frame.len() as u64;
        }
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
        // Echo comes out first, of every frame, muted or not: the canceller keeps up with
        // the room, and nothing ahead of it changes the signal it models.
        self.processing.echo.set_enabled(controls.echo_cancellation.load(Ordering::Relaxed));
        self.processing.echo.process(frame);

        let muted = controls.muted.load(Ordering::Relaxed);
        let mode = InputMode::from(controls.input_mode.load(Ordering::Relaxed));
        let ptt_active = controls.ptt_active.load(Ordering::Relaxed);
        // Mute always wins; push to talk sends only while the key is held.
        if muted || (mode == InputMode::PushToTalk && !ptt_active) {
            self.vad_hangover = 0;
            controls.speaking.store(false, Ordering::Relaxed);
            controls.input_level.store(0.0f32.to_bits(), Ordering::Relaxed);
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
        let level = (frame.iter().map(|s| s * s).sum::<f32>() / frame.len() as f32).sqrt();
        controls.input_level.store(level.to_bits(), Ordering::Relaxed);

        // Speech is told apart by nnnoiseless either way; with noise suppression off it
        // looks at a copy, and the frame goes out as captured.
        let voice_probability = match NoiseSuppressionMode::from(controls.noise_suppression.load(Ordering::Relaxed)) {
            NoiseSuppressionMode::Nnnoiseless => denoise_frame(&mut self.denoiser, frame, &mut self.denoise_in, &mut self.denoise_out),
            NoiseSuppressionMode::Off => {
                self.analysis.copy_from_slice(frame);
                denoise_frame(&mut self.denoiser, &mut self.analysis, &mut self.denoise_in, &mut self.denoise_out)
            }
        };
        if !self.denoise_primed {
            self.denoise_primed = true;
            self.quiet(sequence);
            return;
        }

        let voiced = voice_probability > f32::from_bits(controls.vad_threshold.load(Ordering::Relaxed));
        let speaking = match mode {
            InputMode::PushToTalk => true,
            InputMode::Continuous => level > DIGITAL_SILENCE,
            InputMode::VoiceActivity => {
                // Stay "speaking" briefly after the voice drops, so word ends go out.
                if voiced {
                    self.vad_hangover = VAD_HANGOVER_FRAMES;
                } else if self.vad_hangover > 0 {
                    self.vad_hangover -= 1;
                }
                self.vad_hangover > 0
            }
        };
        controls.speaking.store(speaking, Ordering::Relaxed);

        if AgcMode::from(controls.agc.load(Ordering::Relaxed)) == AgcMode::Auto {
            self.processing.volume.process(frame, voiced);
        }

        let protected = controls.loss_protection.load(Ordering::Relaxed);
        let opus_loss = if protected { opus_loss_pct(controls.expected_loss.load(Ordering::Relaxed)) } else { 0 };
        if opus_loss != self.opus_loss && self.encoder.set_packet_loss_perc(opus_loss).is_ok() {
            self.opus_loss = opus_loss;
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

/// The processing kept from the last call, moved over to `input` if capture now comes
/// from another microphone; fresh processing if none was kept.
fn processing_for(controls: &AudioControls, input: String) -> CaptureProcessing {
    let kept = controls.processing.lock().unwrap().take();
    match kept {
        Some(mut processing) => {
            if processing.input != input {
                switch_input(controls, &mut processing, input);
            }
            processing
        }
        None => CaptureProcessing {
            echo: EchoCanceller::new(controls.echo_cancellation.load(Ordering::Relaxed)),
            volume: VolumeNormalizer::new(controls.start_gain_db(&input)),
            input,
        },
    }
}

/// Keep the gain the normalizer settled on for the microphone it learned on.
fn keep_learned_gain(controls: &AudioControls, processing: &CaptureProcessing) {
    if let Some(gain_db) = processing.volume.learned_gain_db() {
        controls.learned(&processing.input, gain_db);
    }
}

/// Capture moved to `input`: keep what was learned of the last microphone, and start
/// normalizing the new one from what was learned of it.
fn switch_input(controls: &AudioControls, processing: &mut CaptureProcessing, input: String) {
    keep_learned_gain(controls, processing);
    processing.volume = VolumeNormalizer::new(controls.start_gain_db(&input));
    processing.input = input;
}

/// Hand what the session received to each sender's playout. Returns how many frames.
fn route_inbound(received: &mut mpsc::Receiver<Inbound>, link: &mut PlayoutLink) -> u32 {
    let mut frames = 0;
    while let Ok(inbound) = received.try_recv() {
        match inbound {
            Inbound::Frame(frame) => {
                frames += 1;
                link.frame(frame.slot_id, frame.sequence, frame.payload, frame.arrived);
            }
            Inbound::PeerLeft(slot_id) => link.peer_left(slot_id),
        }
    }
    frames
}

/// Read playout quality since the last reading into the controls.
fn read_quality(link: &mut PlayoutLink, controls: &AudioControls) -> String {
    let mut summary = Vec::with_capacity(link.peers.len());
    let mut window = PlayoutStats::default();
    let mut reception = Vec::with_capacity(link.peers.len());
    let (mut max_depth, mut max_target) = (0u32, 0u32);
    for (&slot_id, peer) in link.peers.iter_mut() {
        let playout = peer.stats.playout();
        let since = playout.since(&peer.reported);
        window.add(&since);
        peer.reported = playout;
        let lost = since.recovered + since.concealed + since.dropped_late;
        let heard = since.played + lost;
        if heard >= RECEPTION_MIN_FRAMES {
            reception.push(Reception { slot_id, loss_pct: (lost as f32 * 100.0 / heard as f32).round() as u8 });
        }
        summary.push(format!("d{}t{}", peer.stats.depth(), peer.stats.target()));
        // A silent sender's buffer says nothing about how the call sounds now.
        if !peer.stats.is_idle() {
            max_depth = max_depth.max(peer.stats.depth());
            max_target = max_target.max(peer.stats.target());
        }
    }
    let heard = window.played + window.recovered + window.concealed + window.dropped_late;
    let lost = window.recovered + window.concealed + window.dropped_late;
    let loss_pct = if heard > 0 { lost as f32 / heard as f32 * 100.0 } else { 0.0 };
    controls.packet_loss_pct.store(loss_pct.to_bits(), Ordering::Relaxed);
    *controls.reception.lock().unwrap() = reception;
    controls.jitter_depth.store(max_depth, Ordering::Relaxed);
    controls.jitter_target.store(max_target, Ordering::Relaxed);
    controls.playout_totals.lock().unwrap().add(&window);
    format!("{} {window:?}", summary.join(","))
}

/// Hand each sender's playout to the call figures.
#[cfg(feature = "devtools")]
fn publish_peers(link: &PlayoutLink, controls: &AudioControls) {
    let peers = link
        .peers
        .iter()
        .map(|(&slot_id, peer)| {
            let (received_frames, received_bytes) = peer.stats.received();
            crate::PeerFigures {
                slot_id,
                depth: peer.stats.depth(),
                target: peer.stats.target(),
                playout: peer.stats.playout(),
                received_frames,
                received_bytes,
            }
        })
        .collect();
    controls.figures.set_peers(peers);
}

/// Run a call's audio until `stop` is set, the session ends, or the devices fail.
pub(crate) fn run(
    controls: Arc<AudioControls>,
    devices: Arc<dyn AudioDevices>,
    io: TrackIo,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    let TrackIo { sender, mut received, events } = io;
    let (playback, mut link) = Playback::new(controls.clone());
    let mut streams = devices.open(playback)?;
    let mut transmitter = Transmitter::new(sender.clone(), processing_for(&controls, streams.input_name()))?;
    let mut frame = vec![0.0f32; FRAME_SAMPLES];

    let (mut ticks, mut frames_received, mut capture_empty) = (0u32, 0u32, 0u32);
    let mut result = Ok(());
    'call: while !stop.load(Ordering::Relaxed) && !sender.is_closed() {
        frames_received += route_inbound(&mut received, &mut link);
        link.collect();

        // Capture paces the loop: wait for one frame, then take any that queued up.
        let mut timeout = FRAME_DURATION;
        let mut got_capture = false;
        loop {
            match streams.read_frame(&mut frame, timeout) {
                CaptureRead::Frame => {
                    got_capture = true;
                    #[cfg(feature = "devtools")]
                    let started = std::time::Instant::now();
                    // What played before this frame was captured is what may echo in it.
                    link.played(|samples| transmitter.processing.echo.played(samples));
                    transmitter.process(&mut frame, &controls);
                    #[cfg(feature = "devtools")]
                    {
                        controls.figures.capture.record(started.elapsed(), FRAME_DURATION);
                        controls.figures.set_sent(transmitter.sent.0, transmitter.sent.1);
                    }
                    timeout = Duration::ZERO;
                }
                CaptureRead::Waiting => break,
                CaptureRead::Restarted => {
                    tracing::info!("voice: audio devices reopened");
                    transmitter.denoise_primed = false;
                    switch_input(&controls, &mut transmitter.processing, streams.input_name());
                }
                CaptureRead::Substituted(notice) => {
                    tracing::warn!("voice: {notice}");
                    transmitter.denoise_primed = false;
                    switch_input(&controls, &mut transmitter.processing, streams.input_name());
                    let _ = events.send(TrackEvent::Notice(notice));
                }
                CaptureRead::Failed(e) => {
                    result = Err(e);
                    break 'call;
                }
            }
        }
        if !got_capture {
            capture_empty += 1;
        }

        ticks += 1;
        #[cfg(feature = "devtools")]
        if ticks % FIGURES_TICKS == 0 {
            publish_peers(&link, &controls);
        }
        if ticks >= DIAG_TICKS {
            let playout = read_quality(&mut link, &controls);
            tracing::event!(
                DIAG_LEVEL,
                "voice diag: sent={} protect={}% recv={frames_received} cap_empty={capture_empty}/{ticks} echo=[{}] playout=[{playout}]",
                transmitter.frames_sent,
                transmitter.opus_loss,
                transmitter.processing.echo.summary()
            );
            (ticks, frames_received, capture_empty, transmitter.frames_sent) = (0, 0, 0, 0);
        }
    }
    read_quality(&mut link, &controls);
    controls.speaking.store(false, Ordering::Relaxed);
    // The next call starts from what this one learned.
    keep_learned_gain(&controls, &transmitter.processing);
    *controls.processing.lock().unwrap() = Some(transmitter.processing);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{speech_like, ToneDevices};
    use crate::receiver::PeerStats;
    use crate::{AudioTrack, VoiceAudio};

    /// Opus's coding mode and bandwidth, from a packet's TOC byte.
    fn coding(packet: &[u8]) -> &'static str {
        match packet[0] >> 3 {
            0..=11 => "silk",
            12..=15 => "hybrid",
            _ => "celt",
        }
    }

    #[test]
    fn the_encoder_codes_full_band_until_loss_is_reported_then_protects_against_it() {
        assert_eq!([0, 1, 4, 5, 9, 10, 19, 20, 100].map(opus_loss_pct), [0, 1, 1, 5, 5, 10, 10, 20, 20]);
        // One sentence of the synthetic voice; pauses are left out, as Opus codes silence
        // as it likes, and so are the first frames, while the encoder changes mode.
        let voice = speech_like(1.6, 0.03);
        let mut encoder = create_encoder().unwrap();
        let mut packet = vec![0u8; OPUS_MAX_FRAME_BYTES];
        let mut modes = |encoder: &mut opus::Encoder| -> Vec<&'static str> {
            voice.chunks_exact(FRAME_SAMPLES).map(|frame| {
                let len = encoder.encode_float(frame, &mut packet).unwrap();
                coding(&packet[..len])
            }).skip(5).collect()
        };
        assert!(modes(&mut encoder).iter().all(|m| *m == "celt"), "a clean network gets full-band CELT");
        encoder.set_packet_loss_perc(opus_loss_pct(5)).unwrap();
        assert!(modes(&mut encoder).iter().all(|m| *m != "celt"), "reported loss brings the SILK layer that carries FEC");
    }

    #[test]
    fn protection_carries_speech_through_loss_far_better_than_concealment() {
        let voice = speech_like(6.6, 0.03);
        // Voiced 20 ms frames that come out more than 10 dB below what went in, with one
        // frame in five lost (never two in a row, so each lost frame's copy arrives).
        let dropouts = |reported: u8| -> usize {
            let mut encoder = create_encoder().unwrap();
            encoder.set_packet_loss_perc(opus_loss_pct(reported)).unwrap();
            let packets: Vec<Vec<u8>> = voice.chunks_exact(FRAME_SAMPLES).map(|f| encoder.encode_vec_float(f, OPUS_MAX_FRAME_BYTES).unwrap()).collect();
            let mut decoder = opus::Decoder::new(SAMPLE_RATE, opus::Channels::Mono).unwrap();
            let mut out = vec![0.0f32; FRAME_SAMPLES];
            let mut drops = 0;
            for (i, (packet, input)) in packets.iter().zip(voice.chunks_exact(FRAME_SAMPLES)).enumerate() {
                if i % 5 == 2 {
                    decoder.decode_float(&packets[i + 1], &mut out, true).unwrap();
                } else {
                    decoder.decode_float(packet, &mut out, false).unwrap();
                }
                let level = crate::dsp::rms(input);
                if level > SPEECH * 0.5 && crate::dsp::rms(&out) < level * 0.316 {
                    drops += 1;
                }
            }
            drops
        };
        let (protected, concealed) = (dropouts(20), dropouts(0));
        assert!(concealed >= 5 && protected * 3 <= concealed, "{protected} dropouts with protection, {concealed} with concealment alone");
    }

    #[test]
    fn each_sender_is_told_its_loss_once_enough_of_it_was_heard() {
        let controls = Arc::new(AudioControls::new());
        let (_playback, mut link) = Playback::new(controls.clone());
        for (slot, played, concealed) in [(1, 95, 5), (2, 30, 10)] {
            let stats = Arc::new(PeerStats::default());
            stats.set_playout(PlayoutStats { played, concealed, ..Default::default() });
            link.peers.insert(slot, crate::devices::Peer { stats, reported: PlayoutStats::default() });
        }
        read_quality(&mut link, &controls);
        assert_eq!(*controls.reception.lock().unwrap(), vec![Reception { slot_id: 1, loss_pct: 5 }], "slot 2 was heard too little to tell");
    }

    #[test]
    fn quality_readings_count_each_frame_once() {
        let controls = Arc::new(AudioControls::new());
        let (_playback, mut link) = Playback::new(controls.clone());
        let stats = Arc::new(PeerStats::default());
        stats.set_playout(PlayoutStats { played: 90, concealed: 10, ..Default::default() });
        link.peers.insert(1, crate::devices::Peer { stats: stats.clone(), reported: PlayoutStats::default() });

        read_quality(&mut link, &controls);
        assert_eq!(f32::from_bits(controls.packet_loss_pct.load(Ordering::Relaxed)), 10.0);
        stats.set_playout(PlayoutStats { played: 140, concealed: 10, ..Default::default() });
        read_quality(&mut link, &controls);

        let totals = *controls.playout_totals.lock().unwrap();
        assert_eq!((totals.played, totals.concealed), (140, 10));
        assert_eq!(f32::from_bits(controls.packet_loss_pct.load(Ordering::Relaxed)), 0.0, "nothing was lost since the first reading");
    }

    /// Voiced level of speech, in RMS.
    const SPEECH: f32 = 0.03;
    const SPEECH_SECONDS: f32 = 4.4;
    /// Recorded after the speech ends, for echoes to ring out (or not).
    const TAIL_SECONDS: f32 = 2.0;
    /// Level (RMS, -60 dBFS) under which the last second is silent: no echo rings on.
    const SILENT: f32 = 1e-3;
    /// How strongly the microphone hears the speakers: nearly as loud as they play, as
    /// a laptop's own microphone hears them turned up.
    const LEAK: f32 = 0.9;

    /// Play the default chain's own output back to it, through the sealed loopback a mic
    /// test uses, with the speakers heard by the microphone at `leak`. Returns the
    /// speech and what played.
    fn call_with_speakers(leak: f32, echo_cancellation: bool) -> (Vec<f32>, Vec<f32>) {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let _enter = runtime.enter();
        let devices = ToneDevices::new();
        devices.set_leak(leak);
        let audio = VoiceAudio::new(devices.clone());
        audio.set_echo_cancellation(echo_cancellation);
        let speech = speech_like(SPEECH_SECONDS, SPEECH);
        devices.play(&speech);
        let (events, _events) = mpsc::unbounded_channel();
        audio.start(TrackIo::loopback(events).unwrap()).unwrap();
        std::thread::sleep(Duration::from_secs_f32(SPEECH_SECONDS + TAIL_SECONDS));
        audio.stop();
        (speech, devices.recording())
    }

    /// Level of the last second played, in RMS: after the speech, so only echo.
    fn tail(played: &[f32]) -> f32 {
        crate::dsp::rms(&played[played.len().saturating_sub(SAMPLE_RATE as usize)..])
    }

    /// Share of the speech's voiced frames heard in `played` (at least a tenth of their
    /// level, allowing for the path's delay), and the level of its last second, in RMS.
    fn heard(speech: &[f32], played: &[f32]) -> (f32, f32) {
        let voiced: Vec<usize> = speech.chunks_exact(FRAME_SAMPLES).enumerate().filter(|(_, f)| crate::dsp::rms(f) > SPEECH * 0.3).map(|(i, _)| i).collect();
        let audible = voiced
            .iter()
            .filter(|&&i| (0..10).any(|lag| played.get((i + lag) * FRAME_SAMPLES..(i + lag + 1) * FRAME_SAMPLES).is_some_and(|f| crate::dsp::rms(f) > SPEECH * 0.1)))
            .count();
        (audible as f32 / voiced.len() as f32, tail(played))
    }

    #[test]
    fn speech_comes_through_the_default_chain() {
        let (speech, played) = call_with_speakers(0.0, true);
        let (share, tail) = heard(&speech, &played);
        assert!(share > 0.9, "only {:.0}% of speech heard", share * 100.0);
        assert!(tail < SILENT, "silence after the speech, got RMS {tail}");
    }

    #[test]
    fn speakers_the_microphone_hears_do_not_feed_back() {
        let (speech, played) = call_with_speakers(LEAK, true);
        let (share, tail) = heard(&speech, &played);
        assert!(share > 0.7, "only {:.0}% of speech heard", share * 100.0);
        assert!(tail < SILENT, "the echo rang on after the speech: RMS {tail}");
    }

    #[test]
    fn with_noise_suppression_off_quiet_speech_still_goes_out() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let _enter = runtime.enter();
        let devices = ToneDevices::new();
        let audio = VoiceAudio::new(devices.clone());
        audio.set_noise_suppression(NoiseSuppressionMode::Off);
        // -40 dBFS: a laptop's microphone a little way off.
        let speech = speech_like(SPEECH_SECONDS, 0.01);
        devices.play(&speech);
        let (events, _events) = mpsc::unbounded_channel();
        audio.start(TrackIo::loopback(events).unwrap()).unwrap();
        std::thread::sleep(Duration::from_secs_f32(SPEECH_SECONDS + TAIL_SECONDS));
        audio.stop();
        let played = devices.recording();
        let voiced: Vec<usize> = speech.chunks_exact(FRAME_SAMPLES).enumerate().filter(|(_, f)| crate::dsp::rms(f) > 0.003).map(|(i, _)| i).collect();
        let heard = voiced
            .iter()
            .filter(|&&i| (0..10).any(|lag| played.get((i + lag) * FRAME_SAMPLES..(i + lag + 1) * FRAME_SAMPLES).is_some_and(|f| crate::dsp::rms(f) > 0.001)))
            .count();
        assert!(heard as f32 > voiced.len() as f32 * 0.9, "only {heard} of {} voiced frames went out", voiced.len());
    }

    #[test]
    fn without_echo_cancellation_the_same_speakers_feed_back() {
        // What the test above guards against: the loop sustains itself.
        let (_, played) = call_with_speakers(LEAK, false);
        let level = tail(&played);
        assert!(level > SILENT, "the echo died out on its own: RMS {level}");
    }
}
