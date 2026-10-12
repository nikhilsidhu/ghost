pub const DEFAULT_PAGE_SIZE: u32 = 50;
/// The most the microphone gain may amplify.
pub const INPUT_GAIN_MAX: f32 = 2.0;
/// How long quitting waits for the relay connections to close, so relays show this
/// device offline at once rather than after their grace period.
pub const EXIT_CLOSE_WAIT: std::time::Duration = std::time::Duration::from_millis(500);

// Audio devices
/// The voice engine's audio is mono; devices are converted to and from it.
pub const ENGINE_CHANNELS: usize = 1;
/// Device buffer asked for where the device allows it: 10 ms at 48 kHz, half an engine frame.
pub const DEVICE_BUFFER_SAMPLES: u32 = 480;
/// Mono samples a device callback converts without allocating: more than the largest
/// buffers devices use.
pub const CALLBACK_ROOM: usize = 8192;

// Shared buffer holds ~1 second of audio between device callbacks and processing thread
pub const RING_CAPACITY: usize = 48_000;

// Resampler sub-chunks (lower = less latency)
pub const RESAMPLE_SUB_CHUNKS: usize = 2;

/// Times a call's devices may be reopened after losing a device within
/// `DEVICE_LOSS_WINDOW` before they count as failed for good: a device that errors as
/// soon as it opens would otherwise be reopened every frame.
pub const DEVICE_LOSS_LIMIT: usize = 3;
pub const DEVICE_LOSS_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
/// Quiet after a default-device change before a call follows it: such changes come in
/// bursts (a Bluetooth headset changing mode announces several within a second).
pub const DEVICE_SETTLE: std::time::Duration = std::time::Duration::from_secs(1);
/// Capture silent this long counts as its device gone: longer than a Bluetooth
/// microphone takes to start.
pub const CAPTURE_STALL: std::time::Duration = std::time::Duration::from_secs(3);
