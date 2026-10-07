pub const INVITE_EXPIRY_MS: u64 = 7 * 24 * 3600 * 1000;
pub const DEFAULT_PAGE_SIZE: u32 = 50;

// Audio devices
pub const AUDIO_CHANNELS: u16 = 1; // mono
/// Device buffer size: 10 ms at 48 kHz, half an engine frame.
pub const DEVICE_BUFFER_SAMPLES: u32 = 480;

// Shared buffer holds ~1 second of audio between device callbacks and processing thread
pub const RING_CAPACITY: usize = 48_000;

// Resampler sub-chunks (lower = less latency)
pub const RESAMPLE_SUB_CHUNKS: usize = 2;
