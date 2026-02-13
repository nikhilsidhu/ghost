use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{SampleFormat, SampleRate, StreamConfig};
use ghost_core::mls::voice::{decrypt_voice_frame, encrypt_voice_frame};
use rubato::Resampler as _;
use tokio::sync::mpsc;

use crate::constants::*;

// Shared buffer between audio device callbacks and the processing thread.
// Pre-allocated and lock-free so device callbacks never stall audio output.

struct RingBuffer {
    buf: Box<[f32]>,
    read: AtomicUsize,
    write: AtomicUsize,
}

impl RingBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            buf: vec![0.0; capacity].into_boxed_slice(),
            read: AtomicUsize::new(0),
            write: AtomicUsize::new(0),
        }
    }

    fn push(&self, samples: &[f32]) -> usize {
        let cap = self.buf.len();
        let r = self.read.load(Ordering::Acquire);
        let w = self.write.load(Ordering::Relaxed);
        let available = cap - (w.wrapping_sub(r));
        let count = samples.len().min(available);
        for i in 0..count {
            let idx = (w + i) % cap;
            // Safety: single writer (cpal input callback), idx is valid
            unsafe {
                let ptr = self.buf.as_ptr() as *mut f32;
                *ptr.add(idx) = samples[i];
            }
        }
        self.write.store(w.wrapping_add(count), Ordering::Release);
        count
    }

    fn pop(&self, out: &mut [f32]) -> usize {
        let cap = self.buf.len();
        let w = self.write.load(Ordering::Acquire);
        let r = self.read.load(Ordering::Relaxed);
        let available = w.wrapping_sub(r);
        let count = out.len().min(available);
        for i in 0..count {
            let idx = (r + i) % cap;
            out[i] = self.buf[idx];
        }
        self.read.store(r.wrapping_add(count), Ordering::Release);
        count
    }
}

// Safety: single producer, single consumer — indices use atomic ordering to stay in sync.
unsafe impl Sync for RingBuffer {}

// Shared flags readable from any thread without locking

pub struct AudioControls {
    pub muted: AtomicBool,
    pub deafened: AtomicBool,
    pub speaking: AtomicBool,
}

impl AudioControls {
    fn new() -> Self {
        Self {
            muted: AtomicBool::new(false),
            deafened: AtomicBool::new(false),
            speaking: AtomicBool::new(false),
        }
    }
}

// Received voice frame waiting to be decoded and played

pub struct InboundFrame {
    pub sender_fp: [u8; 32],
    pub sequence: u32,
    pub encrypted_payload: Vec<u8>,
}

// Holds incoming frames per sender, smoothing out network timing

struct JitterBuffer {
    buffer: BTreeMap<u32, Vec<u8>>,
    next_seq: u32,
    target_depth: u32,
    late_count: u32,
    on_time_count: u32,
    decoder: opus::Decoder,
}

impl JitterBuffer {
    fn new() -> Result<Self, String> {
        let decoder = opus::Decoder::new(OPUS_SAMPLE_RATE, opus::Channels::Mono)
            .map_err(|e| format!("opus decoder: {e}"))?;
        Ok(Self {
            buffer: BTreeMap::new(),
            next_seq: 0,
            target_depth: JITTER_MIN_DEPTH,
            late_count: 0,
            on_time_count: 0,
            decoder,
        })
    }

    fn insert(&mut self, seq: u32, payload: Vec<u8>) {
        if self.next_seq > 0 && seq < self.next_seq {
            self.late_count += 1;
            return;
        }
        if self.buffer.len() >= JITTER_MAX_ENTRIES {
            return;
        }
        self.buffer.insert(seq, payload);
    }

    /// Pop the next frame. Decrypts + decodes, or synthesizes audio for gaps.
    fn pop_frame(&mut self, key: &[u8; 32], out: &mut [f32]) -> bool {
        let seq = self.next_seq;
        self.next_seq = seq.wrapping_add(1);

        if let Some(encrypted) = self.buffer.remove(&seq) {
            self.on_time_count += 1;
            if let Ok(opus_bytes) = decrypt_voice_frame(key, seq, &encrypted) {
                let _ = self.decoder.decode_float(&opus_bytes, out, false);
                self.adapt_depth();
                return true;
            }
        }

        // Missing or decrypt failed — synthesize audio to cover the gap
        self.late_count += 1;
        let _ = self.decoder.decode_float(&[], out, false);
        self.adapt_depth();
        true
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

    fn ready(&self) -> bool {
        self.buffer.len() >= self.target_depth as usize
    }

    fn set_next_seq(&mut self, seq: u32) {
        if self.next_seq == 0 {
            self.next_seq = seq;
        }
    }
}

// Normalizes mic volume so quiet speakers sound louder and loud ones don't clip

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

// Build / parse voice packet headers (must match relay format)

pub fn build_packet(
    channel_id: &[u8; 32],
    sender_fp: &[u8; 32],
    sequence: u32,
    epoch: u64,
    payload: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(VOICE_HEADER_SIZE + payload.len());
    pkt.push(VOICE_VERSION);
    pkt.extend_from_slice(channel_id);
    pkt.extend_from_slice(sender_fp);
    pkt.extend_from_slice(&sequence.to_be_bytes());
    pkt.extend_from_slice(&epoch.to_be_bytes());
    pkt.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

pub fn parse_header(buf: &[u8]) -> Option<([u8; 32], [u8; 32], u32, usize)> {
    if buf.len() < VOICE_HEADER_SIZE || buf[0] != VOICE_VERSION {
        return None;
    }
    let channel_id: [u8; 32] = buf[1..33].try_into().ok()?;
    let sender_fp: [u8; 32] = buf[33..65].try_into().ok()?;
    let sequence = u32::from_be_bytes(buf[65..69].try_into().ok()?);
    let payload_len = u16::from_be_bytes(buf[77..79].try_into().ok()?) as usize;
    if buf.len() < VOICE_HEADER_SIZE + payload_len {
        return None;
    }
    Some((channel_id, sender_fp, sequence, payload_len))
}

// Resampler wrapper — converts between device sample rate and 48kHz

struct SampleRateConverter {
    inner: rubato::SincFixedIn<f32>,
    input_buf: Vec<Vec<f32>>,
    output_buf: Vec<Vec<f32>>,
}

impl SampleRateConverter {
    fn new(from_rate: u32, to_rate: u32, chunk_size: usize) -> Result<Self, String> {
        let ratio = to_rate as f64 / from_rate as f64;
        let params = rubato::SincInterpolationParameters {
            sinc_len: RESAMPLE_SINC_LEN,
            f_cutoff: RESAMPLE_CUTOFF as f32,
            oversampling_factor: RESAMPLE_OVERSAMPLING,
            interpolation: rubato::SincInterpolationType::Cubic,
            window: rubato::WindowFunction::Blackman,
        };
        let resampler = rubato::SincFixedIn::new(ratio, RESAMPLE_MAX_RATIO, params, chunk_size, 1)
            .map_err(|e| format!("resampler: {e}"))?;
        let out_len = resampler.output_frames_max();
        Ok(Self {
            inner: resampler,
            input_buf: vec![vec![0.0; chunk_size]],
            output_buf: vec![vec![0.0; out_len]],
        })
    }

    fn process(&mut self, input: &[f32]) -> &[f32] {
        let len = input.len().min(self.input_buf[0].len());
        self.input_buf[0][..len].copy_from_slice(&input[..len]);
        let (_, out_len) = self
            .inner
            .process_into_buffer(&self.input_buf, &mut self.output_buf, None)
            .unwrap_or((len, len));
        &self.output_buf[0][..out_len]
    }
}

// Audio device streams live on the processing thread, so this struct
// only holds channels and flags.

pub struct AudioPipeline {
    pub controls: Arc<AudioControls>,
    pub outbound_rx: Option<mpsc::Receiver<Vec<u8>>>,
    pub inbound_tx: mpsc::Sender<InboundFrame>,
    pub peer_keys: Arc<Mutex<HashMap<[u8; 32], [u8; 32]>>>,
}

impl AudioPipeline {
    pub fn start(
        own_fp: [u8; 32],
        own_key: [u8; 32],
        channel_id: [u8; 32],
        peer_keys: HashMap<[u8; 32], [u8; 32]>,
    ) -> Result<Self, String> {
        let controls = Arc::new(AudioControls::new());
        let peer_keys = Arc::new(Mutex::new(peer_keys));

        let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(VOICE_OUTBOUND_QUEUE);
        let (inbound_tx, inbound_rx) = mpsc::channel::<InboundFrame>(VOICE_INBOUND_QUEUE);

        let controls_clone = controls.clone();
        let peer_keys_clone = peer_keys.clone();

        // Everything that touches cpal::Stream stays on this thread.
        std::thread::Builder::new()
            .name("voice-audio".into())
            .spawn(move || {
                if let Err(e) = run_audio_thread(
                    controls_clone,
                    outbound_tx,
                    inbound_rx,
                    own_fp,
                    own_key,
                    channel_id,
                    peer_keys_clone,
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
    let mut best = None;
    for cfg in configs {
        if cfg.sample_format() != SampleFormat::F32 {
            continue;
        }
        let min = cfg.min_sample_rate().0;
        let max = cfg.max_sample_rate().0;
        if min <= OPUS_SAMPLE_RATE && OPUS_SAMPLE_RATE <= max {
            best = Some(cfg.with_sample_rate(SampleRate(OPUS_SAMPLE_RATE)));
            break;
        }
        if best.is_none() {
            best = Some(cfg.with_max_sample_rate());
        }
    }
    let supported = best.ok_or("no suitable audio config")?;
    Ok(StreamConfig {
        channels: OPUS_CHANNELS,
        sample_rate: supported.sample_rate(),
        buffer_size: cpal::BufferSize::Default,
    })
}

// Audio thread — owns device streams and runs the 20ms processing loop

fn run_audio_thread(
    controls: Arc<AudioControls>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    mut inbound_rx: mpsc::Receiver<InboundFrame>,
    own_fp: [u8; 32],
    own_key: [u8; 32],
    channel_id: [u8; 32],
    peer_keys: Arc<Mutex<HashMap<[u8; 32], [u8; 32]>>>,
) -> Result<(), String> {
    let host = cpal::default_host();

    // --- Capture ---
    let input_device = host.default_input_device().ok_or("no input device")?;
    let input_config = pick_config(
        input_device.supported_input_configs().map_err(|e| format!("input configs: {e}"))?,
    )?;
    let input_rate = input_config.sample_rate.0;

    let capture_ring = Arc::new(RingBuffer::new(RING_CAPACITY));
    let capture_writer = capture_ring.clone();

    let capture_stream = input_device
        .build_input_stream(
            &input_config,
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                capture_writer.push(data);
            },
            |err| eprintln!("voice capture error: {err}"),
            None,
        )
        .map_err(|e| format!("build input stream: {e}"))?;

    // --- Playback ---
    let output_device = host.default_output_device().ok_or("no output device")?;
    let output_config = pick_config(
        output_device.supported_output_configs().map_err(|e| format!("output configs: {e}"))?,
    )?;
    let output_rate = output_config.sample_rate.0;

    let playback_ring = Arc::new(RingBuffer::new(RING_CAPACITY));
    let playback_reader = playback_ring.clone();

    let playback_stream = output_device
        .build_output_stream(
            &output_config,
            move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                let read = playback_reader.pop(data);
                for s in &mut data[read..] {
                    *s = 0.0;
                }
            },
            |err| eprintln!("voice playback error: {err}"),
            None,
        )
        .map_err(|e| format!("build output stream: {e}"))?;

    capture_stream.play().map_err(|e| format!("start capture: {e}"))?;
    playback_stream.play().map_err(|e| format!("start playback: {e}"))?;

    // --- Processing loop ---
    let mut encoder = opus::Encoder::new(OPUS_SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip)
        .map_err(|e| format!("opus encoder: {e}"))?;

    let mut denoiser = nnnoiseless::DenoiseState::new();
    let mut agc = Agc::new();
    let mut sequence: u32 = 0;

    let needs_capture_resample = input_rate != OPUS_SAMPLE_RATE;
    let needs_playback_resample = output_rate != OPUS_SAMPLE_RATE;

    let capture_device_frame = if needs_capture_resample {
        (input_rate as usize * OPUS_FRAME_MS as usize) / 1000
    } else {
        OPUS_FRAME_SIZE
    };

    let mut capture_resampler = if needs_capture_resample {
        Some(SampleRateConverter::new(input_rate, OPUS_SAMPLE_RATE, capture_device_frame)?)
    } else {
        None
    };
    let mut playback_resampler = if needs_playback_resample {
        Some(SampleRateConverter::new(OPUS_SAMPLE_RATE, output_rate, OPUS_FRAME_SIZE)?)
    } else {
        None
    };

    let mut capture_buf = vec![0.0f32; capture_device_frame];
    let mut frame_48k = vec![0.0f32; OPUS_FRAME_SIZE];
    let mut encode_buf = [0u8; VOICE_MAX_PACKET];
    let mut denoise_in = [0.0f32; DENOISE_FRAME_SIZE];
    let mut denoise_out = [0.0f32; DENOISE_FRAME_SIZE];
    let mut jitter_buffers: HashMap<[u8; 32], JitterBuffer> = HashMap::new();
    let mut mix_buf = vec![0.0f32; OPUS_FRAME_SIZE];
    let mut decode_buf = vec![0.0f32; OPUS_FRAME_SIZE];

    let tick = std::time::Duration::from_millis(OPUS_FRAME_MS as u64);

    loop {
        let frame_start = std::time::Instant::now();

        // Check if pipeline was dropped (outbound channel closed)
        if outbound_tx.is_closed() {
            break;
        }

        // --- Drain received frames into per-sender buffers ---
        while let Ok(frame) = inbound_rx.try_recv() {
            let jb = jitter_buffers
                .entry(frame.sender_fp)
                .or_insert_with(|| JitterBuffer::new().expect("jitter buffer init"));
            jb.set_next_seq(frame.sequence);
            jb.insert(frame.sequence, frame.encrypted_payload);
        }

        // --- Capture path ---
        let got = capture_ring.pop(&mut capture_buf);
        if got >= capture_device_frame {
            // Resample to 48kHz if needed, or copy directly
            if let Some(ref mut rs) = capture_resampler {
                let resampled = rs.process(&capture_buf[..capture_device_frame]);
                let n = resampled.len().min(OPUS_FRAME_SIZE);
                frame_48k[..n].copy_from_slice(&resampled[..n]);
            } else {
                let n = got.min(OPUS_FRAME_SIZE);
                frame_48k[..n].copy_from_slice(&capture_buf[..n]);
            }

            let muted = controls.muted.load(Ordering::Relaxed);
            if !muted {
                // Noise suppression (nnnoiseless uses 480-sample chunks scaled to [-32768, 32767])
                let mut max_vad: f32 = 0.0;
                for chunk_start in (0..OPUS_FRAME_SIZE).step_by(DENOISE_FRAME_SIZE) {
                    if chunk_start + DENOISE_FRAME_SIZE > OPUS_FRAME_SIZE {
                        break;
                    }
                    for i in 0..DENOISE_FRAME_SIZE {
                        denoise_in[i] = frame_48k[chunk_start + i] * DENOISE_SAMPLE_SCALE;
                    }
                    let vad = denoiser.process_frame(&mut denoise_out, &denoise_in);
                    max_vad = max_vad.max(vad);
                    for i in 0..DENOISE_FRAME_SIZE {
                        frame_48k[chunk_start + i] = denoise_out[i] / DENOISE_SAMPLE_SCALE;
                    }
                }

                agc.process(&mut frame_48k);

                let speaking = max_vad > VAD_THRESHOLD;
                controls.speaking.store(speaking, Ordering::Relaxed);

                if speaking {
                    if let Ok(len) = encoder.encode_float(&frame_48k, &mut encode_buf) {
                        if let Ok(encrypted) = encrypt_voice_frame(&own_key, sequence, &encode_buf[..len]) {
                            let pkt = build_packet(&channel_id, &own_fp, sequence, 0, &encrypted);
                            let _ = outbound_tx.try_send(pkt);
                            sequence = sequence.wrapping_add(1);
                        }
                    }
                }
            } else {
                controls.speaking.store(false, Ordering::Relaxed);
            }
        }

        // --- Playback path ---
        let deafened = controls.deafened.load(Ordering::Relaxed);
        if !deafened {
            mix_buf.fill(0.0);
            let mut any_audio = false;

            let keys = peer_keys.lock().unwrap();
            let fps: Vec<[u8; 32]> = jitter_buffers.keys().copied().collect();
            for fp in &fps {
                let jb = jitter_buffers.get_mut(fp).unwrap();
                if !jb.ready() {
                    continue;
                }
                if let Some(key) = keys.get(fp) {
                    if jb.pop_frame(key, &mut decode_buf) {
                        any_audio = true;
                        for i in 0..OPUS_FRAME_SIZE {
                            mix_buf[i] = (mix_buf[i] + decode_buf[i]).clamp(-1.0, 1.0);
                        }
                    }
                }
            }
            drop(keys);

            if any_audio {
                if let Some(ref mut rs) = playback_resampler {
                    let resampled = rs.process(&mix_buf);
                    playback_ring.push(resampled);
                } else {
                    playback_ring.push(&mix_buf);
                }
            }
        }

        jitter_buffers.retain(|_, jb| !jb.buffer.is_empty() || jb.next_seq > 0);

        let elapsed = frame_start.elapsed();
        if elapsed < tick {
            std::thread::sleep(tick - elapsed);
        }
    }

    // Streams are dropped here, stopping audio
    Ok(())
}
