pub const INVITE_EXPIRY_MS: u64 = 7 * 24 * 3600 * 1000;
pub const SEQ_HEADER: &str = "X-Ghost-Seq";
pub const DEFAULT_PAGE_SIZE: u32 = 50;
pub const VOICE_CMD_CHANNEL_SIZE: usize = 16;

// Audio pipeline
pub const OPUS_CHANNELS: u16 = 1; // mono
pub const OPUS_SAMPLE_RATE: u32 = 48_000;
pub const OPUS_FRAME_MS: u32 = 20;
pub const OPUS_FRAME_SIZE: usize = (OPUS_SAMPLE_RATE * OPUS_FRAME_MS / 1000) as usize; // 960
pub const DENOISE_FRAME_SIZE: usize = 480; // nnnoiseless expects this
pub const OPUS_BITRATE: i32 = 64_000;
pub const OPUS_COMPLEXITY: i32 = 10;
pub const OPUS_EXPECTED_LOSS_PCT: i32 = 5;

// Voice packet header — re-exported from ghost-wire
pub use ghost_wire::{VOICE_HEADER_SIZE, VOICE_MAX_PACKET};

// Volume normalizer
pub const AGC_TARGET_RMS: f32 = 0.1;
pub const AGC_MAX_GAIN: f32 = 3.0;
pub const AGC_ATTACK: f32 = 0.3;
pub const AGC_RELEASE: f32 = 0.05;

// Voice activity threshold (nnnoiseless returns 0.0–1.0, community recommends 0.85+)
pub const VAD_THRESHOLD: f32 = 0.85;

// Continue transmitting for this many frames after voice activity drops (prevents clipping word ends)
pub const VAD_HANGOVER_FRAMES: u32 = 15; // ~300ms at 50fps

// Shared buffer holds ~1 second of audio between device callbacks and processing thread
pub const RING_CAPACITY: usize = 48_000;

// Per-sender jitter buffer
pub const JITTER_MIN_DEPTH: u32 = 3;
pub const JITTER_MAX_DEPTH: u32 = 5;
pub const JITTER_MAX_PLC_RUN: u32 = 15; // reset after this many consecutive loss-concealment frames (~300ms)
pub const JITTER_MAX_ENTRIES: usize = 50;
pub const JITTER_ADAPT_WINDOW: u32 = 50; // adapt after this many frames
pub const JITTER_LATE_THRESHOLD: u32 = 4; // increase depth when >1/4 are late
pub const JITTER_EARLY_THRESHOLD: u32 = 20; // decrease depth when <1/20 are late

// Volume normalizer ignores signals below this (silence/noise floor)
pub const AGC_SILENCE_FLOOR: f32 = 1e-6;

// Speech detection threshold when nnnoiseless is off (volume-based fallback)
pub const ENERGY_VAD_SPEECH_RMS: f32 = 0.035;

// nnnoiseless operates on i16-range floats
pub const DENOISE_SAMPLE_SCALE: f32 = i16::MAX as f32;

// Resampler sub-chunks (lower = less latency)
pub const RESAMPLE_SUB_CHUNKS: usize = 2;

// Channel capacities for audio pipeline ↔ UDP transport
pub const VOICE_OUTBOUND_QUEUE: usize = 64;
pub const VOICE_INBOUND_QUEUE: usize = 128;
