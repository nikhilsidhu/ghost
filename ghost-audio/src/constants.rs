/// The engine's rate and frame: devices deliver and take 48 kHz mono in 20 ms frames.
pub const SAMPLE_RATE: u32 = 48_000;
pub const FRAME_MS: u32 = 20;
pub const FRAME_SAMPLES: usize = (SAMPLE_RATE * FRAME_MS / 1000) as usize; // 960
/// Echo cancellation and volume normalization work on 10 ms chunks.
pub const PROCESSING_CHUNK: usize = (SAMPLE_RATE / 100) as usize; // 480

// Opus
pub const OPUS_BITRATE: i32 = 64_000;
pub const OPUS_COMPLEXITY: i32 = 10;
pub const OPUS_EXPECTED_LOSS_PCT: i32 = 5;
/// Room for one encoded frame.
pub const OPUS_MAX_FRAME_BYTES: usize = 1500;

/// nnnoiseless works on 480-sample chunks of i16-range floats.
pub const DENOISE_FRAME_SIZE: usize = 480;
pub const DENOISE_SAMPLE_SCALE: f32 = i16::MAX as f32;

// Volume normalizer
/// Gain for a microphone whose level is not learned yet: none, so a loud one is not
/// pushed into the limiter while the normalizer finds its level.
pub const AGC_START_GAIN_DB: f32 = 0.0;
/// The most it raises speech: enough to bring a -50 dBFS microphone to the target.
pub const AGC_MAX_GAIN_DB: f32 = 30.0;
/// Weight of each speech frame in the estimate of the gain the normalizer settled on.
pub const AGC_LEARN_WEIGHT: f32 = 0.05;
/// Speech frames heard before that estimate is worth keeping (2 s).
pub const AGC_LEARN_MIN_FRAMES: u32 = 100;
/// Frames quieter than this (RMS) are left out of it: their level is mostly noise.
pub const AGC_LEARN_MIN_LEVEL: f32 = 1e-4;

/// Voice activity threshold on nnnoiseless's 0.0–1.0 probability (0.85+ is the usual advice).
pub const VAD_THRESHOLD: f32 = 0.85;
/// Speech threshold when noise suppression is off and loudness decides.
pub const ENERGY_VAD_SPEECH_RMS: f32 = 0.035;
/// Frames still sent after voice activity drops, so word ends are not clipped (~300 ms).
pub const VAD_HANGOVER_FRAMES: u32 = 15;
/// Silence frames sent when a talk spurt ends, so receivers' decoders reset cleanly.
pub const SILENCE_FRAME_COUNT: usize = 3;
/// Frames kept while silent and sent at speech onset, so the first syllable is not clipped.
pub const PRE_ROLL_FRAMES: usize = 3;

// Per-sender playout
/// Target delay bounds, in frames: two frames keep the next one at hand for Opus FEC;
/// ten (200 ms) is past the comfortable mouth-to-ear budget.
pub const PLAYOUT_MIN_TARGET: u32 = 2;
pub const PLAYOUT_MAX_TARGET: u32 = 10;
/// Frames held per sender at most.
pub const PLAYOUT_MAX_BUFFERED: usize = 50;
/// Decoded samples a sender's playout keeps room for: the largest device buffers plus a
/// lengthened frame, so playback does not allocate.
pub const PLAYOUT_OUTPUT_ROOM: usize = FRAME_SAMPLES * 8;
/// Senders playback keeps room for: the relay's default room size.
pub const PLAYOUT_SENDER_ROOM: usize = 25;
/// Commands from the audio thread waiting for playback: more than a full inbound queue.
pub const PLAYOUT_COMMAND_QUEUE: usize = 256;
/// What playback hands back to the audio thread to free, so it never frees memory itself.
pub const PLAYOUT_RETURN_QUEUE: usize = 256;
/// What playback played, kept for the echo canceller: one second.
pub const RENDER_QUEUE: usize = SAMPLE_RATE as usize;
/// Concealed frames in a row after which the sender is taken to have paused (~300 ms).
pub const PLAYOUT_MAX_CONCEALED: u32 = 15;
/// Frames after a stretch before the next may stretch, so changes stay gentle.
pub const STRETCH_COOLDOWN: u32 = 2;
/// Window over which the shallowest and deepest buffered depths are tracked (1 s):
/// delay only goes once it has stood unused that long, and only grows once even the
/// deepest moment fell short that long, so jitter alone moves neither.
pub const DEPTH_WINDOW: u32 = 50;

// Target delay
/// NetEQ's defaults: the quantile of relative arrival delay covered, its 20 ms buckets
/// (100 of them), how fast old samples fade, one sample (the worst) per half second over
/// a two-second history, and the delay one percent of late loss is worth.
pub const QUANTILE_LEVEL: f64 = 0.95;
pub const QUANTILE_BUCKETS: usize = 100;
pub const QUANTILE_FORGET: f64 = 0.983;
pub const QUANTILE_REORDER_FORGET: f64 = 0.9993;
pub const QUANTILE_START_WEIGHT: f64 = 2.0;
pub const QUANTILE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
pub const QUANTILE_HISTORY: std::time::Duration = std::time::Duration::from_secs(2);
pub const QUANTILE_MS_PER_LOSS_PERCENT: f64 = 20.0;

/// Processing ticks between quality readings and diagnostics (2 s).
pub const DIAG_TICKS: u32 = 100;
/// Ticks between updates of the call figures for the dev builds' profiler, which polls
/// once a second.
#[cfg(feature = "devtools")]
pub const FIGURES_TICKS: u32 = 10;
