//! The real audio devices behind voice calls: cpal capture and playback, converted
//! to and from the engine's 48 kHz mono, and reopened when the default device changes.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{SampleFormat, SampleRate, StreamConfig};
use ghost_audio::constants::{FRAME_MS, FRAME_SAMPLES, SAMPLE_RATE};
use ghost_audio::{AudioDevices, CaptureRead, DeviceStreams, Playback};
use ringbuf::{traits::*, HeapRb};
use rubato::Resampler as _;

use crate::constants::{AUDIO_CHANNELS, DEVICE_BUFFER_SAMPLES, RESAMPLE_SUB_CHUNKS, RING_CAPACITY};
use crate::device_watcher::DeviceWatcher;

/// How often capture is checked while waiting for a frame.
const CAPTURE_POLL: Duration = Duration::from_millis(1);

/// Converts between a device's sample rate and the engine's, in fixed-size chunks.
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
            AUDIO_CHANNELS as usize,
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
        if min <= SAMPLE_RATE && SAMPLE_RATE <= max {
            best = Some(cfg.with_sample_rate(SampleRate(SAMPLE_RATE)));
            break;
        }

        // Prefer the config whose max rate is closest to 48kHz
        let candidate = cfg.with_max_sample_rate();
        if let Some(ref current) = best {
            let cur_diff = (current.sample_rate().0 as i64 - SAMPLE_RATE as i64).unsigned_abs();
            let new_diff = (candidate.sample_rate().0 as i64 - SAMPLE_RATE as i64).unsigned_abs();
            if new_diff < cur_diff {
                best = Some(candidate);
            }
        } else {
            best = Some(candidate);
        }
    }
    let supported = best.ok_or("no suitable audio config")?;
    Ok(StreamConfig {
        channels: AUDIO_CHANNELS,
        sample_rate: supported.sample_rate(),
        buffer_size: cpal::BufferSize::Fixed(DEVICE_BUFFER_SAMPLES),
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

/// Which devices calls use; `None` follows the system default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceChoice {
    pub input: Option<String>,
    pub output: Option<String>,
}

/// The machine's audio devices, as the user chose them.
#[derive(Default)]
pub struct CpalDevices {
    choice: Mutex<DeviceChoice>,
}

impl CpalDevices {
    /// Use these devices from the next call on.
    pub fn choose(&self, choice: DeviceChoice) {
        *self.choice.lock().unwrap() = choice;
    }
}

impl AudioDevices for CpalDevices {
    fn open(&self, playback: Playback) -> Result<Box<dyn DeviceStreams>, String> {
        let choice = self.choice.lock().unwrap().clone();
        let watcher = DeviceWatcher::new().map_err(|e| format!("device watcher: {e}"))?;
        let host = cpal::default_host();
        let streams = OpenStreams::open(&host, &choice, playback.clone())?;
        let capture = Capture::new(streams.input_rate)?;
        Ok(Box::new(CpalStreams { host, choice, playback, watcher, streams, capture }))
    }
}

/// A call's open cpal streams.
struct OpenStreams {
    _capture: cpal::Stream,
    _playback: cpal::Stream,
    capture_cons: ringbuf::HeapCons<f32>,
    input_rate: u32,
}

impl OpenStreams {
    fn open(host: &cpal::Host, choice: &DeviceChoice, playback: Playback) -> Result<Self, String> {
        let input_device = resolve_device(host, &choice.input, "input")?;
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

        let output_device = resolve_device(host, &choice.output, "output")?;
        let output_config = pick_config(
            output_device.supported_output_configs().map_err(|e| format!("output configs: {e}"))?,
        )?;
        let output_rate = output_config.sample_rate.0;

        // The output hardware clock drives the mixer; at other rates than 48 kHz, whole
        // engine frames are converted and the remainder kept for the next callback.
        let mut converter = if output_rate != SAMPLE_RATE {
            Some(SampleRateConverter::new(SAMPLE_RATE, output_rate, FRAME_SAMPLES)?)
        } else {
            None
        };
        let mut mixed = vec![0.0f32; FRAME_SAMPLES];
        let mut residual: Vec<f32> = Vec::with_capacity(FRAME_SAMPLES * 2);
        let playback_stream = output_device
            .build_output_stream(
                &output_config,
                move |data: &mut [f32], _: &cpal::OutputCallbackInfo| match converter {
                    None => playback.fill(data),
                    Some(ref mut converter) => {
                        while residual.len() < data.len() {
                            playback.fill(&mut mixed);
                            residual.extend_from_slice(converter.process(&mixed));
                        }
                        data.copy_from_slice(&residual[..data.len()]);
                        residual.drain(..data.len());
                    }
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

        Ok(Self { _capture: capture_stream, _playback: playback_stream, capture_cons, input_rate })
    }
}

/// Turns device-rate capture into engine frames.
struct Capture {
    /// Device samples per 20 ms.
    device_frame: usize,
    device_buf: Vec<f32>,
    converter: Option<SampleRateConverter>,
    /// Engine-rate samples not yet handed out as a whole frame.
    pending: Vec<f32>,
}

impl Capture {
    fn new(input_rate: u32) -> Result<Self, String> {
        let device_frame = (input_rate as usize * FRAME_MS as usize) / 1000;
        let converter = if input_rate != SAMPLE_RATE {
            Some(SampleRateConverter::new(input_rate, SAMPLE_RATE, device_frame)?)
        } else {
            None
        };
        Ok(Self {
            device_frame,
            device_buf: vec![0.0; device_frame],
            converter,
            pending: Vec::with_capacity(FRAME_SAMPLES * 2),
        })
    }
}

struct CpalStreams {
    host: cpal::Host,
    choice: DeviceChoice,
    playback: Playback,
    watcher: DeviceWatcher,
    streams: OpenStreams,
    capture: Capture,
}

impl DeviceStreams for CpalStreams {
    fn read_frame(&mut self, frame: &mut [f32], timeout: Duration) -> CaptureRead {
        // The OS says the default device changed: reopen on the new one.
        if self.watcher.try_recv().is_some() {
            // Input and output changes often arrive together.
            while self.watcher.try_recv().is_some() {}
            eprintln!("voice: audio device changed, switching...");
            let reopened = OpenStreams::open(&self.host, &self.choice, self.playback.clone())
                .and_then(|streams| Ok((Capture::new(streams.input_rate)?, streams)));
            return match reopened {
                Ok((capture, streams)) => {
                    self.streams = streams;
                    self.capture = capture;
                    CaptureRead::Restarted
                }
                Err(e) => CaptureRead::Failed(format!("failed to open new device: {e}")),
            };
        }

        let deadline = Instant::now() + timeout;
        let capture = &mut self.capture;
        loop {
            if capture.pending.len() >= FRAME_SAMPLES {
                frame.copy_from_slice(&capture.pending[..FRAME_SAMPLES]);
                capture.pending.drain(..FRAME_SAMPLES);
                return CaptureRead::Frame;
            }
            if self.streams.capture_cons.occupied_len() >= capture.device_frame {
                self.streams.capture_cons.pop_slice(&mut capture.device_buf);
                match capture.converter {
                    Some(ref mut converter) => capture.pending.extend_from_slice(converter.process(&capture.device_buf)),
                    None => capture.pending.extend_from_slice(&capture.device_buf),
                }
                continue;
            }
            if Instant::now() >= deadline {
                return CaptureRead::Waiting;
            }
            std::thread::sleep(CAPTURE_POLL);
        }
    }
}
