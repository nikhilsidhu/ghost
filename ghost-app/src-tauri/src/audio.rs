//! The real audio devices behind voice calls: cpal capture and playback, opened in each
//! device's own channel layout and sample format and converted to and from the engine's
//! 48 kHz mono, and reopened when the default device changes, when the user chooses
//! other devices, and when a device goes away. A chosen device that is not there gives
//! way to the system default, and the call is told.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{BufferSize, FromSample, Sample, SampleFormat, SampleRate, SizedSample, StreamConfig, SupportedBufferSize};
use ghost_audio::constants::{FRAME_MS, FRAME_SAMPLES, SAMPLE_RATE};
use ghost_audio::{AudioDevices, CaptureRead, DeviceStreams, Playback};
use ringbuf::{traits::*, HeapRb};
use rubato::Resampler as _;

use crate::constants::{
    CALLBACK_ROOM, CAPTURE_STALL, DEVICE_BUFFER_SAMPLES, DEVICE_LOSS_LIMIT, DEVICE_LOSS_WINDOW, DEVICE_SETTLE, ENGINE_CHANNELS, RESAMPLE_SUB_CHUNKS,
    RING_CAPACITY,
};
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
            ENGINE_CHANNELS,
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

/// Sample formats converted from and to, best first: the formats cpal's hosts offer.
const SAMPLE_FORMATS: [SampleFormat; 7] =
    [SampleFormat::F32, SampleFormat::I32, SampleFormat::I16, SampleFormat::F64, SampleFormat::U16, SampleFormat::I8, SampleFormat::U8];

/// Evaluate `$build` with `$t` naming the Rust type of `$format`, one of `SAMPLE_FORMATS`.
macro_rules! for_sample_format {
    ($format:expr, $t:ident => $build:expr) => {
        match $format {
            SampleFormat::F32 => {
                type $t = f32;
                $build
            }
            SampleFormat::I32 => {
                type $t = i32;
                $build
            }
            SampleFormat::I16 => {
                type $t = i16;
                $build
            }
            SampleFormat::F64 => {
                type $t = f64;
                $build
            }
            SampleFormat::U16 => {
                type $t = u16;
                $build
            }
            SampleFormat::I8 => {
                type $t = i8;
                $build
            }
            SampleFormat::U8 => {
                type $t = u8;
                $build
            }
            other => Err(format!("sample format {other} is not supported")),
        }
    };
}

/// How a device's stream is opened: in its own channel layout and sample format, which
/// it is sure to accept, at 48 kHz when it runs at it (else the nearest rate it does).
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceFormat {
    pub config: StreamConfig,
    pub sample_format: SampleFormat,
}

impl std::fmt::Display for DeviceFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let buffer = match self.config.buffer_size {
            BufferSize::Fixed(frames) => format!("{frames}-frame buffer"),
            BufferSize::Default => "default buffer".into(),
        };
        write!(f, "{} Hz, {} ch, {}, {buffer}", self.config.sample_rate.0, self.config.channels, self.sample_format)
    }
}

/// The format to open a device in, from the configurations it lists: the rate nearest
/// 48 kHz first, then the best sample format, then the fewest channels. A 10 ms buffer
/// where the device allows one, else its own.
pub fn pick_format(configs: impl Iterator<Item = cpal::SupportedStreamConfigRange>) -> Result<DeviceFormat, String> {
    let rate = |range: &cpal::SupportedStreamConfigRange| SAMPLE_RATE.clamp(range.min_sample_rate().0, range.max_sample_rate().0);
    let best = configs
        .filter(|range| range.channels() > 0)
        .filter_map(|range| {
            let format_rank = SAMPLE_FORMATS.iter().position(|format| *format == range.sample_format())?;
            Some(((rate(&range).abs_diff(SAMPLE_RATE), format_rank, range.channels()), range))
        })
        .min_by_key(|(rank, _)| *rank)
        .map(|(_, range)| range)
        .ok_or("the device offers no format Ghost can use")?;
    let supported = best.with_sample_rate(SampleRate(rate(&best)));
    let buffer_size = match supported.buffer_size() {
        SupportedBufferSize::Range { min, max } if (*min..=*max).contains(&DEVICE_BUFFER_SAMPLES) => BufferSize::Fixed(DEVICE_BUFFER_SAMPLES),
        _ => BufferSize::Default,
    };
    Ok(DeviceFormat {
        config: StreamConfig { channels: supported.channels(), sample_rate: supported.sample_rate(), buffer_size },
        sample_format: supported.sample_format(),
    })
}

/// Average each frame of interleaved `samples`, `channels` wide, into `mono`.
fn downmix<T: Sample>(samples: &[T], channels: usize, mono: &mut Vec<f32>)
where
    f32: FromSample<T>,
{
    mono.clear();
    mono.extend(samples.chunks_exact(channels).map(|frame| frame.iter().map(|s| f32::from_sample(*s)).sum::<f32>() / channels as f32));
}

/// Write each sample of `mono` to every channel of its frame in interleaved `out`.
fn upmix<T: Sample + FromSample<f32>>(mono: &[f32], channels: usize, out: &mut [T]) {
    for (frame, sample) in out.chunks_exact_mut(channels).zip(mono) {
        frame.fill(T::from_sample(*sample));
    }
}

fn build_input<T>(
    device: &cpal::Device,
    format: &DeviceFormat,
    mut take: impl FnMut(&[f32]) + Send + 'static,
    on_error: impl FnMut(cpal::StreamError) + Send + 'static,
) -> Result<cpal::Stream, String>
where
    T: SizedSample,
    f32: FromSample<T>,
{
    let channels = format.config.channels as usize;
    let mut mono = Vec::with_capacity(CALLBACK_ROOM);
    device
        .build_input_stream(
            &format.config,
            move |data: &[T], _: &cpal::InputCallbackInfo| {
                downmix(data, channels, &mut mono);
                take(&mono);
            },
            on_error,
            None,
        )
        .map_err(|e| format!("build input stream: {e}"))
}

fn build_output<T: SizedSample + FromSample<f32>>(
    device: &cpal::Device,
    format: &DeviceFormat,
    mut render: impl FnMut(&mut [f32]) + Send + 'static,
    on_error: impl FnMut(cpal::StreamError) + Send + 'static,
) -> Result<cpal::Stream, String> {
    let channels = format.config.channels as usize;
    let mut mono = Vec::with_capacity(CALLBACK_ROOM);
    device
        .build_output_stream(
            &format.config,
            move |data: &mut [T], _: &cpal::OutputCallbackInfo| {
                mono.resize(data.len() / channels, 0.0);
                render(&mut mono);
                upmix(&mono, channels, data);
            },
            on_error,
            None,
        )
        .map_err(|e| format!("build output stream: {e}"))
}

/// Capture from `device` in `format`, handing `take` each callback's audio as mono.
fn open_input(
    device: &cpal::Device,
    format: &DeviceFormat,
    take: impl FnMut(&[f32]) + Send + 'static,
    on_error: impl FnMut(cpal::StreamError) + Send + 'static,
) -> Result<cpal::Stream, String> {
    for_sample_format!(format.sample_format, T => build_input::<T>(device, format, take, on_error))
}

/// Play to `device` in `format` what `render` writes, as mono, at each callback.
pub fn open_output(
    device: &cpal::Device,
    format: &DeviceFormat,
    render: impl FnMut(&mut [f32]) + Send + 'static,
    on_error: impl FnMut(cpal::StreamError) + Send + 'static,
) -> Result<cpal::Stream, String> {
    for_sample_format!(format.sample_format, T => build_output::<T>(device, format, render, on_error))
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

/// A burst of notices, acted on once it stops.
#[derive(Default)]
struct Settle {
    last: Option<Instant>,
}

impl Settle {
    fn notice(&mut self, now: Instant) {
        self.last = Some(now);
    }

    /// Whether a burst ended at least `DEVICE_SETTLE` ago; it counts once.
    fn settled(&mut self, now: Instant) -> bool {
        let settled = self.last.is_some_and(|at| now.duration_since(at) >= DEVICE_SETTLE);
        if settled {
            self.last = None;
        }
        settled
    }
}

/// Which devices calls use; `None` follows the system default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceChoice {
    pub input: Option<String>,
    pub output: Option<String>,
}

/// The machine's audio devices, as the user chose them. A new choice reaches a call
/// already running, whose devices reopen on it.
#[derive(Default)]
pub struct CpalDevices {
    choice: Arc<Mutex<DeviceChoice>>,
    /// Counts the choices made, so open devices notice a new one.
    choices: Arc<AtomicU64>,
}

impl CpalDevices {
    /// Use these devices from now on, in a call already running too.
    pub fn choose(&self, choice: DeviceChoice) {
        let mut current = self.choice.lock().unwrap();
        if *current != choice {
            *current = choice;
            self.choices.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl AudioDevices for CpalDevices {
    fn open(&self, playback: Playback) -> Result<Box<dyn DeviceStreams>, String> {
        let seen_choice = self.choices.load(Ordering::Relaxed);
        let choice = self.choice.lock().unwrap().clone();
        let watcher = DeviceWatcher::new().map_err(|e| format!("device watcher: {e}"))?;
        let host = cpal::default_host();
        let (streams, notice) = open_or_default(&host, &choice, playback.clone())?;
        let capture = Capture::new(streams.input_rate)?;
        Ok(Box::new(CpalStreams {
            host,
            choice: self.choice.clone(),
            choices: self.choices.clone(),
            seen_choice,
            playback,
            watcher,
            streams,
            capture,
            notice,
            losses: VecDeque::new(),
            settle: Settle::default(),
        }))
    }
}

/// Open the chosen devices; when they are not available, the system default's instead,
/// with the notice to give.
fn open_or_default(host: &cpal::Host, choice: &DeviceChoice, playback: Playback) -> Result<(OpenStreams, Option<String>), String> {
    match OpenStreams::open(host, choice, playback.clone()) {
        Ok(streams) => Ok((streams, None)),
        Err(e) if *choice != DeviceChoice::default() => {
            let streams = OpenStreams::open(host, &DeviceChoice::default(), playback)?;
            Ok((streams, Some(format!("{e}; using the system default instead"))))
        }
        Err(e) => Err(e),
    }
}

/// A call's open cpal streams.
struct OpenStreams {
    _capture: cpal::Stream,
    _playback: cpal::Stream,
    capture_cons: ringbuf::HeapCons<f32>,
    input_name: String,
    output_name: String,
    input_rate: u32,
    /// Set by either stream when its device goes away.
    device_lost: Arc<AtomicBool>,
}

impl OpenStreams {
    fn open(host: &cpal::Host, choice: &DeviceChoice, playback: Playback) -> Result<Self, String> {
        let device_lost = Arc::new(AtomicBool::new(false));
        let lost_by = |what: &'static str| {
            let device_lost = device_lost.clone();
            move |err: cpal::StreamError| {
                tracing::warn!("voice {what} error: {err}");
                if matches!(err, cpal::StreamError::DeviceNotAvailable) {
                    device_lost.store(true, Ordering::Relaxed);
                }
            }
        };
        let input_device = resolve_device(host, &choice.input, "input")?;
        let input_format = pick_format(input_device.supported_input_configs().map_err(|e| format!("input configs: {e}"))?)?;
        let input_rate = input_format.config.sample_rate.0;

        let (mut capture_prod, capture_cons) = HeapRb::<f32>::new(RING_CAPACITY).split();
        let capture_stream = open_input(
            &input_device,
            &input_format,
            move |mono| {
                capture_prod.push_slice(mono);
            },
            lost_by("capture"),
        )?;

        let output_device = resolve_device(host, &choice.output, "output")?;
        let output_format = pick_format(output_device.supported_output_configs().map_err(|e| format!("output configs: {e}"))?)?;
        let output_rate = output_format.config.sample_rate.0;

        // The output hardware clock drives the mixer; at other rates than 48 kHz, whole
        // engine frames are converted and the remainder kept for the next callback.
        let mut converter = if output_rate != SAMPLE_RATE {
            Some(SampleRateConverter::new(SAMPLE_RATE, output_rate, FRAME_SAMPLES)?)
        } else {
            None
        };
        let mut mixed = vec![0.0f32; FRAME_SAMPLES];
        let mut residual: Vec<f32> = Vec::with_capacity(CALLBACK_ROOM + FRAME_SAMPLES * 2);
        let playback_stream = open_output(
            &output_device,
            &output_format,
            move |out| match converter {
                None => playback.fill(out),
                Some(ref mut converter) => {
                    while residual.len() < out.len() {
                        playback.fill(&mut mixed);
                        residual.extend_from_slice(converter.process(&mixed));
                    }
                    out.copy_from_slice(&residual[..out.len()]);
                    residual.drain(..out.len());
                }
            },
            lost_by("playback"),
        )?;

        capture_stream.play().map_err(|e| format!("start capture: {e}"))?;
        playback_stream.play().map_err(|e| format!("start playback: {e}"))?;

        let (input_name, output_name) = (input_device.name().unwrap_or_default(), output_device.name().unwrap_or_default());
        tracing::info!("voice: capture \"{input_name}\" ({input_format}), playback \"{output_name}\" ({output_format})");

        Ok(Self { _capture: capture_stream, _playback: playback_stream, capture_cons, input_name, output_name, input_rate, device_lost })
    }

    /// The devices open, by name.
    fn devices(&self) -> (Option<String>, Option<String>) {
        (Some(self.input_name.clone()), Some(self.output_name.clone()))
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
    /// When the device last delivered.
    heard_at: Instant,
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
            heard_at: Instant::now(),
        })
    }
}

/// The devices `choice` resolves to now, by name: what a reopen would open.
fn wanted_devices(host: &cpal::Host, choice: &DeviceChoice) -> (Option<String>, Option<String>) {
    let name = |chosen: &Option<String>, direction| resolve_device(host, chosen, direction).ok().and_then(|device| device.name().ok());
    (name(&choice.input, "input"), name(&choice.output, "output"))
}

struct CpalStreams {
    host: cpal::Host,
    choice: Arc<Mutex<DeviceChoice>>,
    choices: Arc<AtomicU64>,
    /// The choice these streams were opened on.
    seen_choice: u64,
    playback: Playback,
    watcher: DeviceWatcher,
    streams: OpenStreams,
    capture: Capture,
    /// What to tell the call at the next read: the chosen devices gave way to others.
    notice: Option<String>,
    /// When devices were lost lately, oldest first.
    losses: VecDeque<Instant>,
    /// Default-device changes waiting to settle.
    settle: Settle,
}

impl CpalStreams {
    /// Open the devices again, on the choice as it is now.
    fn reopen(&mut self) -> CaptureRead {
        let choice = self.choice.lock().unwrap().clone();
        let reopened = open_or_default(&self.host, &choice, self.playback.clone())
            .and_then(|(streams, notice)| Ok((Capture::new(streams.input_rate)?, streams, notice)));
        match reopened {
            Ok((capture, streams, notice)) => {
                self.streams = streams;
                self.capture = capture;
                notice.map_or(CaptureRead::Restarted, CaptureRead::Substituted)
            }
            Err(e) => CaptureRead::Failed(format!("failed to open audio devices: {e}")),
        }
    }
}

impl DeviceStreams for CpalStreams {
    fn read_frame(&mut self, frame: &mut [f32], timeout: Duration) -> CaptureRead {
        if let Some(notice) = self.notice.take() {
            return CaptureRead::Substituted(notice);
        }
        // A device went away under the streams, or capture stopped coming: reopen, unless
        // devices keep going.
        let stalled = self.capture.heard_at.elapsed() >= CAPTURE_STALL;
        if self.streams.device_lost.load(Ordering::Relaxed) || stalled {
            let now = Instant::now();
            self.losses.retain(|at| now.duration_since(*at) < DEVICE_LOSS_WINDOW);
            if self.losses.len() >= DEVICE_LOSS_LIMIT {
                return CaptureRead::Failed("audio devices keep going away".into());
            }
            self.losses.push_back(now);
            tracing::info!("voice: {}, reopening", if stalled { "capture stopped" } else { "an audio device went away" });
            return self.reopen();
        }
        // The user chose other devices.
        let choices = self.choices.load(Ordering::Relaxed);
        if choices != self.seen_choice {
            self.seen_choice = choices;
            tracing::info!("voice: other audio devices chosen, switching");
            return self.reopen();
        }
        // The OS says a default device changed: once the changes settle, reopen if the
        // devices to use are not the ones open (a headset changing mode keeps its name).
        while self.watcher.try_recv().is_some() {
            self.settle.notice(Instant::now());
        }
        if self.settle.settled(Instant::now()) {
            let choice = self.choice.lock().unwrap().clone();
            if wanted_devices(&self.host, &choice) != self.streams.devices() {
                tracing::info!("voice: audio device changed, switching");
                return self.reopen();
            }
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
                capture.heard_at = Instant::now();
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

    fn input_name(&self) -> String {
        self.streams.input_name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpal::SupportedStreamConfigRange;

    const ANY_BUFFER: SupportedBufferSize = SupportedBufferSize::Range { min: 64, max: 4096 };

    fn range(channels: u16, rates: (u32, u32), sample_format: SampleFormat, buffer: SupportedBufferSize) -> SupportedStreamConfigRange {
        SupportedStreamConfigRange::new(channels, SampleRate(rates.0), SampleRate(rates.1), buffer, sample_format)
    }

    #[test]
    fn a_burst_of_device_changes_is_acted_on_once_after_it_stops() {
        let start = Instant::now();
        let mut settle = Settle::default();
        assert!(!settle.settled(start), "nothing to act on");
        settle.notice(start);
        settle.notice(start + Duration::from_millis(300));
        assert!(!settle.settled(start + DEVICE_SETTLE), "the burst went on");
        assert!(settle.settled(start + Duration::from_millis(300) + DEVICE_SETTLE));
        assert!(!settle.settled(start + DEVICE_SETTLE * 5), "once");
    }

    #[test]
    fn speakers_that_only_play_stereo_open_in_stereo() {
        // A MacBook's speakers list no mono configuration.
        let format = pick_format([range(2, (44_100, 96_000), SampleFormat::F32, ANY_BUFFER)].into_iter()).unwrap();
        assert_eq!(format.config.channels, 2);
        assert_eq!(format.config.sample_rate.0, SAMPLE_RATE);
        assert_eq!(format.config.buffer_size, BufferSize::Fixed(DEVICE_BUFFER_SAMPLES));
    }

    #[test]
    fn the_rate_decides_first_then_the_sample_format_then_fewer_channels() {
        let configs = [
            range(1, (44_100, 44_100), SampleFormat::F32, ANY_BUFFER),
            range(1, (48_000, 48_000), SampleFormat::I16, ANY_BUFFER),
            range(2, (48_000, 48_000), SampleFormat::F32, ANY_BUFFER),
        ];
        let format = pick_format(configs.into_iter()).unwrap();
        assert_eq!((format.config.channels, format.sample_format), (2, SampleFormat::F32));

        let integer_only = [range(2, (48_000, 48_000), SampleFormat::I16, ANY_BUFFER), range(1, (48_000, 48_000), SampleFormat::I16, ANY_BUFFER)];
        let format = pick_format(integer_only.into_iter()).unwrap();
        assert_eq!((format.config.channels, format.sample_format), (1, SampleFormat::I16));
    }

    #[test]
    fn a_device_without_48k_opens_at_its_nearest_rate_and_its_own_buffer() {
        let format = pick_format([range(2, (88_200, 192_000), SampleFormat::I32, SupportedBufferSize::Unknown)].into_iter()).unwrap();
        assert_eq!(format.config.sample_rate.0, 88_200);
        assert_eq!(format.config.buffer_size, BufferSize::Default);
    }

    #[test]
    fn formats_that_cannot_be_converted_are_passed_over() {
        assert!(pick_format([range(2, (48_000, 48_000), SampleFormat::U64, ANY_BUFFER)].into_iter()).is_err());
    }

    #[test]
    fn capture_is_averaged_to_mono_and_playback_fills_every_channel() {
        let mut mono = Vec::new();
        downmix(&[0.5f32, 0.25, -0.75, -0.25], 2, &mut mono);
        assert_eq!(mono, vec![0.375, -0.5]);
        downmix(&[i16::MAX, i16::MAX], 2, &mut mono);
        assert!((mono[0] - 1.0).abs() < 1e-3, "integer samples come in at full scale");

        let mut out = [0.0f32; 4];
        upmix(&[0.25, -0.5], 2, &mut out);
        assert_eq!(out, [0.25, 0.25, -0.5, -0.5]);
        let mut out = [0i16; 2];
        upmix(&[0.5], 2, &mut out);
        assert_eq!(out[0], out[1]);
        assert!(out[0] > 16_000, "half scale goes out as half of i16");
    }
}
