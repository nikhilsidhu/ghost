use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{SampleFormat, SampleRate, StreamConfig};
use ghost_core::mls::voice::{decrypt_voice_frame, encrypt_voice_frame};
use ringbuf::{traits::*, HeapRb};
use rubato::Resampler as _;
use tokio::sync::mpsc;

use crate::constants::*;

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

// 0 = voice activity, 1 = push to talk
pub const INPUT_MODE_VA: u8 = 0;
pub const INPUT_MODE_PTT: u8 = 1;

// CELT-only fullband 20ms mono silence — resets the decoder's prediction state cleanly
const OPUS_SILENCE: [u8; 3] = [0xF8, 0xFF, 0xFE];

pub struct AudioControls {
    pub muted: AtomicBool,
    pub deafened: AtomicBool,
    pub speaking: AtomicBool,
    // Shared with voice_task for the quality indicator
    pub packet_loss_pct: AtomicU32,
    pub jitter_depth: AtomicU32,
    pub jitter_target: AtomicU32,
    pub noise_suppression: AtomicU8,
    pub agc: AtomicU8,
    pub vad_threshold: AtomicU32,
    pub input_gain: AtomicU32,
    pub input_mode: AtomicU8,
    pub ptt_active: AtomicBool,
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
            input_mode: AtomicU8::new(INPUT_MODE_VA),
            ptt_active: AtomicBool::new(false),
        }
    }
}

pub struct InboundFrame {
    pub slot_id: u32,
    pub sequence: u32,
    pub encrypted_payload: Vec<u8>,
}

// Per-sender jitter buffer. Buffers N frames before starting playback, then
// keeps playing continuously using loss concealment for missing frames.

struct JitterBuffer {
    buffer: BTreeMap<u32, Vec<u8>>,
    next_seq: u32,
    initialized: bool,
    playing: bool,
    target_depth: u32,
    late_count: u32,
    on_time_count: u32,
    consecutive_misses: u32,
    decoder: opus::Decoder,
    // Reset every 2s when metrics are read
    quality_frames: u32,
    quality_missing: u32,
}

impl JitterBuffer {
    fn new() -> Result<Self, String> {
        let decoder = opus::Decoder::new(OPUS_SAMPLE_RATE, opus::Channels::Mono)
            .map_err(|e| format!("opus decoder: {e}"))?;
        Ok(Self {
            buffer: BTreeMap::new(),
            next_seq: 0,
            initialized: false,
            playing: false,
            target_depth: JITTER_MIN_DEPTH,
            late_count: 0,
            on_time_count: 0,
            consecutive_misses: 0,
            decoder,
            quality_frames: 0,
            quality_missing: 0,
        })
    }

    fn set_next_seq(&mut self, seq: u32) {
        if !self.initialized {
            self.next_seq = seq;
            self.initialized = true;
        }
    }

    fn insert(&mut self, seq: u32, payload: Vec<u8>) {
        if self.initialized && seq < self.next_seq {
            self.late_count += 1;
            return;
        }
        if self.buffer.len() >= JITTER_MAX_ENTRIES {
            return;
        }
        self.buffer.insert(seq, payload);
    }

    fn ready(&self) -> bool {
        if self.playing {
            return true;
        }
        self.buffer.len() >= self.target_depth as usize
    }

    fn pop_frame(&mut self, key: &[u8; 32], out: &mut [f32]) -> bool {
        self.playing = true;
        self.quality_frames += 1;
        let seq = self.next_seq;
        self.next_seq = seq.wrapping_add(1);

        if let Some(encrypted) = self.buffer.remove(&seq) {
            if let Ok(opus_bytes) = decrypt_voice_frame(key, seq, &encrypted) {
                self.on_time_count += 1;
                self.consecutive_misses = 0;
                let _ = self.decoder.decode_float(&opus_bytes, out, false);
                self.adapt_depth();
                return true;
            }
        }

        // Missing or decrypt failed
        self.quality_missing += 1;
        self.late_count += 1;
        self.consecutive_misses += 1;

        // Too many consecutive misses — sender likely paused.
        if self.consecutive_misses > JITTER_MAX_PLC_RUN {
            self.playing = false;
            self.initialized = false;
            self.buffer.clear();
            out.fill(0.0);
            return false;
        }

        // Try forward error correction: if the next packet is available,
        // decode it with fec=true to recover a rough version of this missing frame
        let next_seq = seq.wrapping_add(1);
        if let Some(next_encrypted) = self.buffer.get(&next_seq) {
            if let Ok(next_opus) = decrypt_voice_frame(key, next_seq, next_encrypted) {
                let _ = self.decoder.decode_float(&next_opus, out, true);
                self.adapt_depth();
                return true;
            }
        }

        // No forward error correction available — fall back to loss concealment (empty decode)
        let _ = self.decoder.decode_float(&[], out, false);
        self.adapt_depth();
        true
    }

    fn is_stale(&self) -> bool {
        !self.playing && !self.initialized && self.buffer.is_empty()
    }

    fn adapt_depth(&mut self) {
        let total = self.late_count + self.on_time_count;
        if total < JITTER_ADAPT_WINDOW {
            return;
        }
        if self.late_count > total / JITTER_LATE_THRESHOLD && self.target_depth < JITTER_MAX_DEPTH {
            self.target_depth += 1;
        } else if self.late_count < total / JITTER_EARLY_THRESHOLD && self.target_depth > JITTER_MIN_DEPTH {
            self.target_depth -= 1;
        }
        self.late_count = 0;
        self.on_time_count = 0;
    }
}

// Compensates clock drift between sender and receiver by resampling decoded audio
// at a variable rate. Small drift gets gentle correction, large drift (device
// reconnect, Bluetooth handoff) gets aggressive correction.
struct DriftResampler {
    pos: f64,
    smoothed_error: f64,
}

impl DriftResampler {
    fn new() -> Self {
        Self { pos: 0.0, smoothed_error: 0.0 }
    }

    fn process(&mut self, input: &[f32], output: &mut Vec<f32>, depth: usize, target: usize) {
        let error = depth as f64 - target as f64;

        // Adaptive smoothing: large deviations get fast reaction, small ones stay gentle
        let abs_err = error.abs();
        let alpha = if abs_err > 4.0 { 0.3 } else if abs_err > 2.0 { 0.1 } else { 0.02 };
        self.smoothed_error += alpha * (error - self.smoothed_error);

        // Adaptive clamp: widen range for large corrections
        let max_step = if self.smoothed_error.abs() > 3.0 { 0.05 } else { 0.02 };
        let step = (1.0 + self.smoothed_error * 0.005).clamp(1.0 - max_step, 1.0 + max_step);

        while self.pos < input.len() as f64 {
            let idx = self.pos as usize;
            let frac = (self.pos - idx as f64) as f32;
            let a = input[idx.min(input.len() - 1)];
            let b = input[(idx + 1).min(input.len() - 1)];
            output.push(a + frac * (b - a));
            self.pos += step;
        }
        self.pos -= input.len() as f64;
    }
}

struct Agc {
    current_gain: f32,
}

impl Agc {
    fn new() -> Self {
        Self { current_gain: 1.0 }
    }

    fn process(&mut self, samples: &mut [f32]) {
        let rms = (samples.iter().map(|s| s * s).sum::<f32>() / samples.len() as f32).sqrt();
        if rms < AGC_SILENCE_FLOOR {
            return;
        }

        let desired_gain = (AGC_TARGET_RMS / rms).min(AGC_MAX_GAIN);
        let alpha = if desired_gain < self.current_gain {
            AGC_ATTACK
        } else {
            AGC_RELEASE
        };
        self.current_gain += alpha * (desired_gain - self.current_gain);

        for s in samples.iter_mut() {
            *s = (*s * self.current_gain).clamp(-1.0, 1.0);
        }
    }
}

pub fn build_packet(
    channel_id: &[u8; 32],
    slot_id: u32,
    sequence: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(VOICE_HEADER_SIZE + payload.len());
    pkt.extend_from_slice(&(VOICE_HEADER_SIZE as u16).to_be_bytes());
    pkt.extend_from_slice(channel_id);
    pkt.extend_from_slice(&slot_id.to_be_bytes());
    pkt.push(0x00); // flags
    pkt.extend_from_slice(&sequence.to_be_bytes());
    pkt.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

/// Returns (channel_id, slot_id, sequence, payload_len, header_len).
/// Payload starts at buf[header_len..header_len + payload_len].
pub fn parse_header(buf: &[u8]) -> Option<([u8; 32], u32, u32, usize, usize)> {
    if buf.len() < VOICE_HEADER_SIZE {
        return None;
    }
    let header_len = u16::from_be_bytes(buf[0..2].try_into().ok()?) as usize;
    if header_len < VOICE_HEADER_SIZE || buf.len() < header_len {
        return None;
    }
    let channel_id: [u8; 32] = buf[2..34].try_into().ok()?;
    let slot_id = u32::from_be_bytes(buf[34..38].try_into().ok()?);
    // flags at byte 38
    let sequence = u32::from_be_bytes(buf[39..43].try_into().ok()?);
    let payload_len = u16::from_be_bytes(buf[43..45].try_into().ok()?) as usize;
    if buf.len() < header_len + payload_len {
        return None;
    }
    Some((channel_id, slot_id, sequence, payload_len, header_len))
}

struct SampleRateConverter {
    inner: rubato::FftFixedIn<f32>,
    input_buf: Vec<Vec<f32>>,
    output_buf: Vec<Vec<f32>>,
}

impl SampleRateConverter {
    fn new(from_rate: u32, to_rate: u32, chunk_size: usize) -> Result<Self, String> {
        let resampler = rubato::FftFixedIn::new(
            from_rate as usize,
            to_rate as usize,
            chunk_size,
            RESAMPLE_SUB_CHUNKS,
            1, // mono
        )
        .map_err(|e| format!("resampler: {e}"))?;
        let out_len = resampler.output_frames_max();
        Ok(Self {
            inner: resampler,
            input_buf: vec![vec![0.0; chunk_size]],
            output_buf: vec![vec![0.0; out_len]],
        })
    }

    fn process(&mut self, input: &[f32]) -> &[f32] {
        debug_assert!(
            input.len() <= self.input_buf[0].len(),
            "resampler input {} exceeds buffer {}",
            input.len(),
            self.input_buf[0].len(),
        );
        let len = input.len().min(self.input_buf[0].len());
        self.input_buf[0][..len].copy_from_slice(&input[..len]);
        let (_, out_len) = self
            .inner
            .process_into_buffer(&self.input_buf, &mut self.output_buf, None)
            .unwrap_or((len, len));
        &self.output_buf[0][..out_len]
    }
}

pub struct AudioPipeline {
    pub controls: Arc<AudioControls>,
    pub outbound_rx: Option<mpsc::Receiver<Vec<u8>>>,
    pub inbound_tx: mpsc::Sender<InboundFrame>,
    // slot_id → (fingerprint, voice_key) — single map eliminates double-lock in output callback
    pub peer_keys: Arc<Mutex<HashMap<u32, ([u8; 32], [u8; 32])>>>,
}

impl AudioPipeline {
    pub fn start(
        own_slot_id: u32,
        own_key: [u8; 32],
        channel_id: [u8; 32],
        peer_keys: HashMap<u32, ([u8; 32], [u8; 32])>,
        input_device_name: Option<String>,
        output_device_name: Option<String>,
    ) -> Result<Self, String> {
        let controls = Arc::new(AudioControls::new());
        let peer_keys = Arc::new(Mutex::new(peer_keys));

        let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(VOICE_OUTBOUND_QUEUE);
        let (inbound_tx, inbound_rx) = mpsc::channel::<InboundFrame>(VOICE_INBOUND_QUEUE);

        let controls_clone = controls.clone();
        let peer_keys_clone = peer_keys.clone();

        std::thread::Builder::new()
            .name("voice-audio".into())
            .spawn(move || {
                if let Err(e) = run_audio_thread(
                    controls_clone,
                    outbound_tx,
                    inbound_rx,
                    own_slot_id,
                    own_key,
                    channel_id,
                    peer_keys_clone,
                    input_device_name,
                    output_device_name,
                ) {
                    eprintln!("voice audio thread failed: {e}");
                }
            })
            .map_err(|e| format!("spawn audio thread: {e}"))?;

        Ok(Self {
            controls,
            outbound_rx: Some(outbound_rx),
            inbound_tx,
            peer_keys,
        })
    }
}

fn pick_config(
    configs: impl Iterator<Item = cpal::SupportedStreamConfigRange>,
) -> Result<StreamConfig, String> {
    let mut best: Option<cpal::SupportedStreamConfig> = None;
    for cfg in configs {
        if cfg.sample_format() != SampleFormat::F32 {
            continue;
        }
        let min = cfg.min_sample_rate().0;
        let max = cfg.max_sample_rate().0;

        // Exact 48kHz match — ideal, no resampling needed
        if min <= OPUS_SAMPLE_RATE && OPUS_SAMPLE_RATE <= max {
            best = Some(cfg.with_sample_rate(SampleRate(OPUS_SAMPLE_RATE)));
            break;
        }

        // Prefer the config whose max rate is closest to 48kHz
        let candidate = cfg.with_max_sample_rate();
        if let Some(ref current) = best {
            let cur_diff = (current.sample_rate().0 as i64 - OPUS_SAMPLE_RATE as i64).unsigned_abs();
            let new_diff = (candidate.sample_rate().0 as i64 - OPUS_SAMPLE_RATE as i64).unsigned_abs();
            if new_diff < cur_diff {
                best = Some(candidate);
            }
        } else {
            best = Some(candidate);
        }
    }
    let supported = best.ok_or("no suitable audio config")?;
    Ok(StreamConfig {
        channels: OPUS_CHANNELS,
        sample_rate: supported.sample_rate(),
        buffer_size: cpal::BufferSize::Fixed(DENOISE_FRAME_SIZE as u32),
    })
}

fn find_device_by_name(
    mut devices: impl Iterator<Item = cpal::Device>,
    name: &str,
) -> Option<cpal::Device> {
    devices.find(|d| d.name().ok().as_deref() == Some(name))
}

pub fn resolve_device(
    host: &cpal::Host,
    name: &Option<String>,
    direction: &str,
) -> Result<cpal::Device, String> {
    match name {
        Some(name) => {
            let devices = if direction == "input" {
                host.input_devices().map_err(|e| format!("{direction} devices: {e}"))?
            } else {
                host.output_devices().map_err(|e| format!("{direction} devices: {e}"))?
            };
            find_device_by_name(devices, name)
                .ok_or_else(|| format!("{direction} device '{name}' not found"))
        }
        None => {
            if direction == "input" {
                host.default_input_device()
            } else {
                host.default_output_device()
            }
            .ok_or_else(|| format!("no {direction} device"))
        }
    }
}

struct PlaybackShared {
    jitter_buffers: HashMap<u32, JitterBuffer>,
}

struct AudioStreams {
    _capture: cpal::Stream,
    _playback: cpal::Stream,
    capture_cons: ringbuf::HeapCons<f32>,
    input_rate: u32,
}

fn setup_streams(
    host: &cpal::Host,
    input_device_name: &Option<String>,
    output_device_name: &Option<String>,
    playback_shared: Arc<Mutex<PlaybackShared>>,
    peer_keys: Arc<Mutex<HashMap<u32, ([u8; 32], [u8; 32])>>>,
    controls: Arc<AudioControls>,
) -> Result<AudioStreams, String> {
    let input_device = resolve_device(host, input_device_name, "input")?;
    let input_config = pick_config(
        input_device.supported_input_configs().map_err(|e| format!("input configs: {e}"))?,
    )?;
    let input_rate = input_config.sample_rate.0;

    let (mut capture_prod, capture_cons) = HeapRb::<f32>::new(RING_CAPACITY).split();

    let capture_stream = input_device
        .build_input_stream(
            &input_config,
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                capture_prod.push_slice(data);
            },
            move |err| { eprintln!("voice capture error: {err}"); },
            None,
        )
        .map_err(|e| format!("build input stream: {e}"))?;

    let output_device = resolve_device(host, output_device_name, "output")?;
    let output_config = pick_config(
        output_device.supported_output_configs().map_err(|e| format!("output configs: {e}"))?,
    )?;
    let output_rate = output_config.sample_rate.0;

    // Output callback mixes directly from jitter buffers — no intermediate ring.
    // The output hardware clock drives consumption; a drift resampler adjusts
    // playback speed to keep the jitter buffer centered on its target.
    let mut playback_resampler = if output_rate != OPUS_SAMPLE_RATE {
        Some(SampleRateConverter::new(OPUS_SAMPLE_RATE, output_rate, OPUS_FRAME_SIZE)?)
    } else {
        None
    };
    let mut mix_buf = vec![0.0f32; OPUS_FRAME_SIZE];
    let mut decode_buf = vec![0.0f32; OPUS_FRAME_SIZE];
    let mut residual: Vec<f32> = Vec::with_capacity(OPUS_FRAME_SIZE * 2);
    let mut drift = DriftResampler::new();

    let ps = playback_shared;
    let pk = peer_keys.clone();
    let ctrl = controls;

    let playback_stream = output_device
        .build_output_stream(
            &output_config,
            move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                let deafened = ctrl.deafened.load(Ordering::Relaxed);

                // Fill residual buffer with enough decoded audio for this callback
                while residual.len() < data.len() {
                    let (jb_depth, jb_target) = {
                        let mut shared = ps.lock().unwrap();
                        let dt = shared.jitter_buffers.values()
                            .map(|jb| (jb.buffer.len(), jb.target_depth as usize))
                            .max_by_key(|(d, _)| *d)
                            .unwrap_or((0, JITTER_MIN_DEPTH as usize));
                        if !deafened {
                            mix_playback(
                                &mut shared.jitter_buffers, &pk,
                                &mut mix_buf, &mut decode_buf,
                            );
                        }
                        dt
                    };

                    if deafened {
                        mix_buf.fill(0.0);
                    }

                    let source = if let Some(ref mut rs) = playback_resampler {
                        rs.process(&mix_buf)
                    } else {
                        &mix_buf[..]
                    };

                    drift.process(source, &mut residual, jb_depth, jb_target);
                }

                data.copy_from_slice(&residual[..data.len()]);
                residual.drain(..data.len());
            },
            move |err| { eprintln!("voice playback error: {err}"); },
            None,
        )
        .map_err(|e| format!("build output stream: {e}"))?;

    capture_stream.play().map_err(|e| format!("start capture: {e}"))?;
    playback_stream.play().map_err(|e| format!("start playback: {e}"))?;

    eprintln!(
        "voice: capture \"{}\" @ {}Hz, playback \"{}\" @ {}Hz",
        input_device.name().unwrap_or_default(),
        input_rate,
        output_device.name().unwrap_or_default(),
        output_rate,
    );

    Ok(AudioStreams {
        _capture: capture_stream,
        _playback: playback_stream,
        capture_cons,
        input_rate,
    })
}

fn create_encoder() -> Result<opus::Encoder, String> {
    let mut encoder = opus::Encoder::new(OPUS_SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip)
        .map_err(|e| format!("opus encoder: {e}"))?;
    encoder.set_bitrate(opus::Bitrate::Bits(OPUS_BITRATE)).map_err(|e| format!("opus bitrate: {e}"))?;
    encoder.set_vbr(true).map_err(|e| format!("opus vbr: {e}"))?;
    encoder.set_complexity(OPUS_COMPLEXITY).map_err(|e| format!("opus complexity: {e}"))?;
    encoder.set_inband_fec(true).map_err(|e| format!("opus fec: {e}"))?;
    encoder.set_packet_loss_perc(OPUS_EXPECTED_LOSS_PCT).map_err(|e| format!("opus loss pct: {e}"))?;
    Ok(encoder)
}

// Denoise a 960-sample frame in 480-sample chunks, return max voice-activity probability
fn denoise_frame(
    denoiser: &mut nnnoiseless::DenoiseState,
    frame: &mut [f32],
    denoise_in: &mut [f32; DENOISE_FRAME_SIZE],
    denoise_out: &mut [f32; DENOISE_FRAME_SIZE],
) -> f32 {
    let mut max_vad: f32 = 0.0;
    for chunk_start in (0..OPUS_FRAME_SIZE).step_by(DENOISE_FRAME_SIZE) {
        if chunk_start + DENOISE_FRAME_SIZE > OPUS_FRAME_SIZE {
            break;
        }
        for i in 0..DENOISE_FRAME_SIZE {
            denoise_in[i] = frame[chunk_start + i] * DENOISE_SAMPLE_SCALE;
        }
        let vad = denoiser.process_frame(denoise_out, denoise_in);
        max_vad = max_vad.max(vad);
        for i in 0..DENOISE_FRAME_SIZE {
            frame[chunk_start + i] = denoise_out[i] / DENOISE_SAMPLE_SCALE;
        }
    }
    max_vad
}

// Detect speech by volume when nnnoiseless is off (returns 1.0 if loud enough, else 0.0)
fn energy_vad(samples: &[f32]) -> f32 {
    let rms = (samples.iter().map(|s| s * s).sum::<f32>() / samples.len() as f32).sqrt();
    if rms >= ENERGY_VAD_SPEECH_RMS { 1.0 } else { 0.0 }
}

// Mix all ready jitter buffers into mix_buf, return true if any audio was mixed
fn mix_playback(
    jitter_buffers: &mut HashMap<u32, JitterBuffer>,
    peer_keys: &Mutex<HashMap<u32, ([u8; 32], [u8; 32])>>,
    mix_buf: &mut [f32],
    decode_buf: &mut [f32],
) -> bool {
    mix_buf.fill(0.0);
    let mut any_audio = false;

    let keys = peer_keys.lock().unwrap();
    let slot_ids: Vec<u32> = jitter_buffers.keys().copied().collect();
    for sid in &slot_ids {
        let jb = jitter_buffers.get_mut(sid).unwrap();
        if !jb.ready() {
            continue;
        }
        if let Some((_, key)) = keys.get(sid) {
            if jb.pop_frame(key, decode_buf) {
                any_audio = true;
                for i in 0..OPUS_FRAME_SIZE {
                    mix_buf[i] += decode_buf[i];
                }
            }
        }
    }
    drop(keys);

    if any_audio {
        for s in mix_buf.iter_mut() {
            *s = s.clamp(-1.0, 1.0);
        }
    }

    any_audio
}

fn run_audio_thread(
    controls: Arc<AudioControls>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    mut inbound_rx: mpsc::Receiver<InboundFrame>,
    own_slot_id: u32,
    own_key: [u8; 32],
    channel_id: [u8; 32],
    peer_keys: Arc<Mutex<HashMap<u32, ([u8; 32], [u8; 32])>>>,
    input_device_name: Option<String>,
    output_device_name: Option<String>,
) -> Result<(), String> {
    let host = cpal::default_host();

    let playback_shared = Arc::new(Mutex::new(PlaybackShared {
        jitter_buffers: HashMap::new(),
    }));

    let device_watcher = crate::device_watcher::DeviceWatcher::new()
        .map_err(|e| format!("device watcher: {e}"))?;

    let mut streams = setup_streams(
        &host, &input_device_name, &output_device_name,
        playback_shared.clone(), peer_keys.clone(), controls.clone(),
    )?;

    let mut encoder = create_encoder()?;
    let mut denoiser = nnnoiseless::DenoiseState::new();
    let mut denoise_primed = false;
    let mut agc = Agc::new();
    let mut sequence: u32 = 0;
    let mut vad_hangover: u32 = 0;
    let mut was_speaking = false;
    let mut pre_roll: VecDeque<Vec<u8>> = VecDeque::with_capacity(PRE_ROLL_FRAMES);

    let mut capture_device_frame = if streams.input_rate != OPUS_SAMPLE_RATE {
        (streams.input_rate as usize * OPUS_FRAME_MS as usize) / 1000
    } else {
        OPUS_FRAME_SIZE
    };

    let mut capture_resampler = if streams.input_rate != OPUS_SAMPLE_RATE {
        Some(SampleRateConverter::new(streams.input_rate, OPUS_SAMPLE_RATE, capture_device_frame)?)
    } else {
        None
    };

    let mut capture_buf = vec![0.0f32; capture_device_frame];
    let mut frame_48k = vec![0.0f32; OPUS_FRAME_SIZE];
    let mut encode_buf = [0u8; VOICE_MAX_PACKET];
    let mut denoise_in = [0.0f32; DENOISE_FRAME_SIZE];
    let mut denoise_out = [0.0f32; DENOISE_FRAME_SIZE];
    let mut resample_accum: Vec<f32> = Vec::with_capacity(OPUS_FRAME_SIZE * 2);
    let mut last_ns_mode = NoiseSuppressionMode::Nnnoiseless;
    let frame_timeout = std::time::Duration::from_millis(OPUS_FRAME_MS as u64);

    let mut diag_ticks: u32 = 0;
    let mut diag_frames_sent: u32 = 0;
    let mut diag_frames_recv: u32 = 0;
    let mut diag_capture_empty: u32 = 0;

    loop {
        // Drive the loop from the capture device clock
        {
            let deadline = std::time::Instant::now() + frame_timeout;
            loop {
                if outbound_tx.is_closed() {
                    break;
                }
                if streams.capture_cons.occupied_len() >= capture_device_frame {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            if outbound_tx.is_closed() {
                break;
            }
        }

        // --- Route inbound frames to jitter buffers (owned by output callback) ---
        {
            let mut shared = playback_shared.lock().unwrap();
            while let Ok(frame) = inbound_rx.try_recv() {
                diag_frames_recv += 1;
                let jb = shared.jitter_buffers
                    .entry(frame.slot_id)
                    .or_insert_with(|| JitterBuffer::new().expect("jitter buffer init"));
                jb.set_next_seq(frame.sequence);
                jb.insert(frame.sequence, frame.encrypted_payload);
            }
        }

        // --- Capture: drain device samples, resample, accumulate exact 960-sample frames ---
        let mut got_capture = false;
        loop {
            if streams.capture_cons.occupied_len() < capture_device_frame {
                break;
            }
            got_capture = true;
            streams.capture_cons.pop_slice(&mut capture_buf);

            if let Some(ref mut rs) = capture_resampler {
                let resampled = rs.process(&capture_buf[..capture_device_frame]);
                resample_accum.extend_from_slice(resampled);
            } else {
                resample_accum.extend_from_slice(&capture_buf[..OPUS_FRAME_SIZE]);
            }
        }

        while resample_accum.len() >= OPUS_FRAME_SIZE {
            frame_48k.copy_from_slice(&resample_accum[..OPUS_FRAME_SIZE]);
            resample_accum.drain(..OPUS_FRAME_SIZE);

            let muted = controls.muted.load(Ordering::Relaxed);
            let mode = controls.input_mode.load(Ordering::Relaxed);
            let ptt_active = controls.ptt_active.load(Ordering::Relaxed);
            // User mute always overrides. In PTT mode, only transmit while key held.
            let transmit = !muted && (mode == INPUT_MODE_VA || ptt_active);

            if transmit {
                let gain = f32::from_bits(controls.input_gain.load(Ordering::Relaxed));
                if gain != 1.0 {
                    for s in frame_48k.iter_mut() {
                        *s = (*s * gain).clamp(-1.0, 1.0);
                    }
                }

                let ns_mode = NoiseSuppressionMode::from(controls.noise_suppression.load(Ordering::Relaxed));
                let agc_mode = AgcMode::from(controls.agc.load(Ordering::Relaxed));

                // Reset denoise state when switching back to nnnoiseless
                if ns_mode == NoiseSuppressionMode::Nnnoiseless && last_ns_mode != NoiseSuppressionMode::Nnnoiseless {
                    denoise_primed = false;
                }
                last_ns_mode = ns_mode;

                let max_vad = match ns_mode {
                    NoiseSuppressionMode::Nnnoiseless => {
                        let vad = denoise_frame(
                            &mut denoiser, &mut frame_48k, &mut denoise_in, &mut denoise_out,
                        );
                        if !denoise_primed {
                            denoise_primed = true;
                            continue;
                        }
                        vad
                    }
                    NoiseSuppressionMode::Off => energy_vad(&frame_48k),
                };

                if mode == INPUT_MODE_PTT {
                    // PTT: always speaking while key held
                    controls.speaking.store(true, Ordering::Relaxed);
                } else {
                    // Voice activity mode: keep speaking indicator on briefly after voice drops
                    let vad_thresh = f32::from_bits(controls.vad_threshold.load(Ordering::Relaxed));
                    if max_vad > vad_thresh {
                        vad_hangover = VAD_HANGOVER_FRAMES;
                    } else if vad_hangover > 0 {
                        vad_hangover -= 1;
                    }
                    controls.speaking.store(vad_hangover > 0, Ordering::Relaxed);
                }

                if agc_mode == AgcMode::Auto {
                    agc.process(&mut frame_48k);
                }

                let speaking = mode == INPUT_MODE_PTT || vad_hangover > 0;

                // Always encode to keep Opus encoder state warm
                if let Ok(len) = encoder.encode_float(&frame_48k, &mut encode_buf) {
                    if let Ok(encrypted) = encrypt_voice_frame(&own_key, sequence, &encode_buf[..len]) {
                        let pkt = build_packet(&channel_id, own_slot_id, sequence, &encrypted);
                        sequence = sequence.wrapping_add(1);

                        if speaking {
                            if !was_speaking {
                                // Speech onset: flush pre-roll to capture leading edge
                                for pre_pkt in pre_roll.drain(..) {
                                    let _ = outbound_tx.try_send(pre_pkt);
                                    diag_frames_sent += 1;
                                }
                            }
                            was_speaking = true;
                            let _ = outbound_tx.try_send(pkt);
                            diag_frames_sent += 1;
                        } else {
                            if was_speaking {
                                // Speech end: send silence frames for clean decoder reset
                                for _ in 0..SILENCE_FRAME_COUNT {
                                    if let Ok(enc) = encrypt_voice_frame(&own_key, sequence, &OPUS_SILENCE) {
                                        let spkt = build_packet(&channel_id, own_slot_id, sequence, &enc);
                                        let _ = outbound_tx.try_send(spkt);
                                        sequence = sequence.wrapping_add(1);
                                        diag_frames_sent += 1;
                                    }
                                }
                                was_speaking = false;
                            }
                            // Buffer for pre-roll
                            if pre_roll.len() >= PRE_ROLL_FRAMES {
                                pre_roll.pop_front();
                            }
                            pre_roll.push_back(pkt);
                        }
                    }
                }
            } else {
                vad_hangover = 0;
                controls.speaking.store(false, Ordering::Relaxed);
                // Muted or PTT released: send silence frames if we were speaking
                if was_speaking {
                    for _ in 0..SILENCE_FRAME_COUNT {
                        if let Ok(enc) = encrypt_voice_frame(&own_key, sequence, &OPUS_SILENCE) {
                            let spkt = build_packet(&channel_id, own_slot_id, sequence, &enc);
                            let _ = outbound_tx.try_send(spkt);
                            sequence = sequence.wrapping_add(1);
                            diag_frames_sent += 1;
                        }
                    }
                    was_speaking = false;
                }
                pre_roll.clear();
            }
        }

        // Playback is handled by the output device callback — no mixing here

        if !got_capture {
            diag_capture_empty += 1;
        }

        diag_ticks += 1;
        if diag_ticks >= 100 {
            let cap_fill = streams.capture_cons.occupied_len();
            let mut shared = playback_shared.lock().unwrap();
            let jb_info: Vec<String> = shared.jitter_buffers
                .values()
                .map(|jb| format!("d{}m{}", jb.buffer.len(), jb.consecutive_misses))
                .collect();
            // Aggregate quality metrics across all active jitter buffers
            let mut q_frames: u32 = 0;
            let mut q_missing: u32 = 0;
            let mut max_depth: u32 = 0;
            let mut max_target: u32 = 0;
            for jb in shared.jitter_buffers.values_mut() {
                q_frames += jb.quality_frames;
                q_missing += jb.quality_missing;
                max_depth = max_depth.max(jb.buffer.len() as u32);
                max_target = max_target.max(jb.target_depth);
                jb.quality_frames = 0;
                jb.quality_missing = 0;
            }
            shared.jitter_buffers.retain(|_, jb| !jb.is_stale());
            drop(shared);
            let loss_pct = if q_frames > 0 {
                (q_missing as f32 / q_frames as f32) * 100.0
            } else {
                0.0
            };
            controls.packet_loss_pct.store(loss_pct.to_bits(), Ordering::Relaxed);
            controls.jitter_depth.store(max_depth, Ordering::Relaxed);
            controls.jitter_target.store(max_target, Ordering::Relaxed);
            eprintln!(
                "voice diag: sent={} recv={} cap_empty={}/{} cap_ring={} jb=[{}]",
                diag_frames_sent, diag_frames_recv, diag_capture_empty, diag_ticks,
                cap_fill, jb_info.join(","),
            );

            diag_ticks = 0;
            diag_frames_sent = 0;
            diag_frames_recv = 0;
            diag_capture_empty = 0;
        }

        // OS notified us the default device changed — recreate streams on the new device
        if device_watcher.try_recv().is_some() {
            // Drain any duplicate events (input+output often fire together)
            while device_watcher.try_recv().is_some() {}
            eprintln!("voice: audio device changed, switching...");
            drop(streams);
            resample_accum.clear();

            match setup_streams(
                &host, &input_device_name, &output_device_name,
                playback_shared.clone(), peer_keys.clone(), controls.clone(),
            ) {
                Ok(new_streams) => {
                    capture_device_frame = if new_streams.input_rate != OPUS_SAMPLE_RATE {
                        (new_streams.input_rate as usize * OPUS_FRAME_MS as usize) / 1000
                    } else {
                        OPUS_FRAME_SIZE
                    };
                    capture_resampler = if new_streams.input_rate != OPUS_SAMPLE_RATE {
                        match SampleRateConverter::new(
                            new_streams.input_rate, OPUS_SAMPLE_RATE, capture_device_frame,
                        ) {
                            Ok(r) => Some(r),
                            Err(e) => {
                                eprintln!("voice: resampler init failed on new device: {e}");
                                return Err(e);
                            }
                        }
                    } else {
                        None
                    };
                    capture_buf.resize(capture_device_frame, 0.0);
                    denoise_primed = false;
                    streams = new_streams;
                }
                Err(e) => {
                    eprintln!("voice: failed to open new device: {e}");
                    return Err(e);
                }
            }
        }
    }

    Ok(())
}
