use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{SampleFormat, SampleRate, StreamConfig};
use ghost_core::mls::voice::{decrypt_voice_frame, encrypt_voice_frame};
use ringbuf::{traits::*, HeapRb};
use rubato::Resampler as _;
use tokio::sync::mpsc;

use crate::constants::*;

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

pub struct InboundFrame {
    pub sender_fp: [u8; 32],
    pub sequence: u32,
    pub encrypted_payload: Vec<u8>,
}

// Per-sender jitter buffer. Gates initial playback on target_depth, then
// keeps playing continuously using Opus PLC for missing frames.

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
        let seq = self.next_seq;
        self.next_seq = seq.wrapping_add(1);

        if let Some(encrypted) = self.buffer.remove(&seq) {
            self.on_time_count += 1;
            self.consecutive_misses = 0;
            if let Ok(opus_bytes) = decrypt_voice_frame(key, seq, &encrypted) {
                let _ = self.decoder.decode_float(&opus_bytes, out, false);
                self.adapt_depth();
                return true;
            }
        }

        // Missing or decrypt failed
        self.late_count += 1;
        self.consecutive_misses += 1;

        // Too many consecutive misses — sender likely paused (VAD off).
        // Reset so we re-sync to the sender's actual sequence on resume.
        if self.consecutive_misses > JITTER_MAX_PLC_RUN {
            self.playing = false;
            self.initialized = false;
            self.buffer.clear();
            out.fill(0.0);
            return false;
        }

        // Short gap — use PLC to fill
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

    let (mut capture_prod, mut capture_cons) = HeapRb::<f32>::new(RING_CAPACITY).split();

    let capture_stream = input_device
        .build_input_stream(
            &input_config,
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                capture_prod.push_slice(data);
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

    let (mut playback_prod, mut playback_cons) = HeapRb::<f32>::new(RING_CAPACITY).split();

    // Pre-fill with 40ms of silence so the output callback has headroom for timing jitter
    let prefill = 2 * OPUS_FRAME_SIZE * output_rate as usize / OPUS_SAMPLE_RATE as usize;
    playback_prod.push_slice(&vec![0.0f32; prefill]);

    let playback_stream = output_device
        .build_output_stream(
            &output_config,
            move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                let read = playback_cons.pop_slice(data);
                if read < data.len() {
                    // Fade to silence from last real sample instead of hard zero-fill
                    let last = if read > 0 { data[read - 1] } else { 0.0 };
                    let gap = data.len() - read;
                    for (i, s) in data[read..].iter_mut().enumerate() {
                        *s = last * (1.0 - i as f32 / gap as f32);
                    }
                }
            },
            |err| eprintln!("voice playback error: {err}"),
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

    // --- Processing loop ---
    let mut encoder = opus::Encoder::new(OPUS_SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip)
        .map_err(|e| format!("opus encoder: {e}"))?;
    let _ = encoder.set_bitrate(opus::Bitrate::Bits(OPUS_BITRATE));
    let _ = encoder.set_vbr(true);
    let _ = encoder.set_complexity(OPUS_COMPLEXITY);
    let _ = encoder.set_inband_fec(true);
    let _ = encoder.set_packet_loss_perc(OPUS_EXPECTED_LOSS_PCT);

    let mut denoiser = nnnoiseless::DenoiseState::new();
    let mut denoise_primed = false;
    let mut agc = Agc::new();
    let mut sequence: u32 = 0;
    let mut vad_hangover: u32 = 0;

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

        if outbound_tx.is_closed() {
            break;
        }

        // --- Drain received frames into per-sender jitter buffers ---
        while let Ok(frame) = inbound_rx.try_recv() {
            let jb = jitter_buffers
                .entry(frame.sender_fp)
                .or_insert_with(|| JitterBuffer::new().expect("jitter buffer init"));
            jb.set_next_seq(frame.sequence);
            jb.insert(frame.sequence, frame.encrypted_payload);
        }

        // --- Capture: process ALL available frames to stay current ---
        loop {
            if capture_cons.occupied_len() < capture_device_frame {
                break;
            }
            capture_cons.pop_slice(&mut capture_buf);

            frame_48k.fill(0.0);
            if let Some(ref mut rs) = capture_resampler {
                let resampled = rs.process(&capture_buf[..capture_device_frame]);
                let n = resampled.len().min(OPUS_FRAME_SIZE);
                frame_48k[..n].copy_from_slice(&resampled[..n]);
            } else {
                frame_48k.copy_from_slice(&capture_buf[..OPUS_FRAME_SIZE]);
            }

            let muted = controls.muted.load(Ordering::Relaxed);
            if !muted {
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

                // First denoise output has fade-in artifacts — skip it
                if !denoise_primed {
                    denoise_primed = true;
                    continue;
                }

                // VAD with hangover to avoid clipping word endings
                if max_vad > VAD_THRESHOLD {
                    vad_hangover = VAD_HANGOVER_FRAMES;
                } else if vad_hangover > 0 {
                    vad_hangover -= 1;
                }
                let transmit = vad_hangover > 0;
                controls.speaking.store(transmit, Ordering::Relaxed);

                if transmit {
                    // AGC only during speech — prevents gain pumping up during silence
                    agc.process(&mut frame_48k);
                    if let Ok(len) = encoder.encode_float(&frame_48k, &mut encode_buf) {
                        if let Ok(encrypted) = encrypt_voice_frame(&own_key, sequence, &encode_buf[..len]) {
                            let pkt = build_packet(&channel_id, &own_fp, sequence, 0, &encrypted);
                            let _ = outbound_tx.try_send(pkt);
                            sequence = sequence.wrapping_add(1);
                        }
                    }
                }
            } else {
                vad_hangover = 0;
                controls.speaking.store(false, Ordering::Relaxed);
            }
        }

        // --- Playback: always push a frame so output callback never starves ---
        let deafened = controls.deafened.load(Ordering::Relaxed);
        mix_buf.fill(0.0);
        let mut any_audio = false;

        if !deafened {
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
                            mix_buf[i] += decode_buf[i];
                        }
                    }
                }
            }
            drop(keys);

            // Soft-clip the mix
            if any_audio {
                for s in mix_buf.iter_mut() {
                    *s = s.clamp(-1.0, 1.0);
                }
            }
        }

        // Always push to playback ring — silence when no peers, mixed audio otherwise
        if let Some(ref mut rs) = playback_resampler {
            let resampled = rs.process(&mix_buf);
            playback_prod.push_slice(resampled);
        } else {
            playback_prod.push_slice(&mix_buf);
        }

        jitter_buffers.retain(|_, jb| !jb.is_stale());

        let elapsed = frame_start.elapsed();
        if elapsed < tick {
            let remaining = tick - elapsed;
            // Sleep most of the duration, then spin-wait for the last ~1ms for precision
            if remaining > std::time::Duration::from_millis(1) {
                std::thread::sleep(remaining - std::time::Duration::from_millis(1));
            }
            while frame_start.elapsed() < tick {
                std::hint::spin_loop();
            }
        }
    }

    Ok(())
}
