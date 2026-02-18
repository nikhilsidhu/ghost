use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cpal::traits::{DeviceTrait, StreamTrait};
use cpal::SampleFormat;
use ringbuf::{traits::*, HeapRb};
use tauri::{AppHandle, Emitter};

use crate::audio::resolve_device;

// Pick an F32 config targeting the given sample rate, preserving native channel count.
fn pick_test_config(
    configs: impl Iterator<Item = cpal::SupportedStreamConfigRange>,
    target_rate: u32,
) -> Result<cpal::StreamConfig, String> {
    let mut best: Option<cpal::SupportedStreamConfig> = None;
    for cfg in configs {
        if cfg.sample_format() != SampleFormat::F32 {
            continue;
        }
        let min = cfg.min_sample_rate().0;
        let max = cfg.max_sample_rate().0;
        if min <= target_rate && target_rate <= max {
            best = Some(cfg.with_sample_rate(cpal::SampleRate(target_rate)));
            break;
        }
        let candidate = cfg.with_max_sample_rate();
        if let Some(ref b) = best {
            if (candidate.sample_rate().0 as i64 - target_rate as i64).unsigned_abs()
                < (b.sample_rate().0 as i64 - target_rate as i64).unsigned_abs()
            {
                best = Some(candidate);
            }
        } else {
            best = Some(candidate);
        }
    }
    best.map(|c| c.config()).ok_or_else(|| "no f32 audio config".into())
}

static MIC_TESTING: AtomicBool = AtomicBool::new(false);
static TONE_PLAYING: AtomicBool = AtomicBool::new(false);

const MIC_POLL_MS: u64 = 50;
const TONE_DURATION: Duration = Duration::from_secs(2);
const TONE_FREQ: f32 = 440.0;
const TONE_VOLUME: f32 = 0.3;
const LOOPBACK_BUF_SIZE: usize = 12_000;
const LOOPBACK_PREFILL_MS: u64 = 150;

pub fn start_mic_test(
    app: AppHandle,
    input_device_name: Option<String>,
    output_device_name: Option<String>,
) -> Result<(), String> {
    if MIC_TESTING.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    std::thread::Builder::new()
        .name("mic-test".into())
        .spawn(move || {
            if let Err(e) = run_mic_test(&app, input_device_name, output_device_name) {
                eprintln!("mic test error: {e}");
            }
            MIC_TESTING.store(false, Ordering::SeqCst);
        })
        .map_err(|e| format!("spawn mic test: {e}"))?;

    Ok(())
}

pub fn stop_mic_test() {
    MIC_TESTING.store(false, Ordering::SeqCst);
}

fn run_mic_test(
    app: &AppHandle,
    input_device_name: Option<String>,
    output_device_name: Option<String>,
) -> Result<(), String> {
    let host = cpal::default_host();

    let input_device = resolve_device(&host, &input_device_name, "input")?;
    let in_config = pick_test_config(
        input_device.supported_input_configs().map_err(|e| format!("input configs: {e}"))?,
        48_000,
    )?;
    let in_channels = in_config.channels as usize;
    let in_rate = in_config.sample_rate.0;

    let output_device = resolve_device(&host, &output_device_name, "output")?;
    let out_config = pick_test_config(
        output_device.supported_output_configs().map_err(|e| format!("output configs: {e}"))?,
        in_rate,
    )?;
    let out_channels = out_config.channels as usize;
    let out_rate = out_config.sample_rate.0;

    eprintln!(
        "mic test: capture \"{}\" @ {}Hz {}ch, playback \"{}\" @ {}Hz {}ch",
        input_device.name().unwrap_or_default(), in_rate, in_channels,
        output_device.name().unwrap_or_default(), out_rate, out_channels,
    );

    let level = Arc::new(std::sync::Mutex::new(0.0f32));
    let level_w = level.clone();

    // Diagnostics: track underruns and overruns in the ring buffer
    let overruns = Arc::new(AtomicU64::new(0));
    let underruns = Arc::new(AtomicU64::new(0));
    let overruns_w = overruns.clone();
    let underruns_r = underruns.clone();

    let ring = HeapRb::<f32>::new(LOOPBACK_BUF_SIZE);
    let (mut loopback_prod, mut loopback_cons) = ring.split();

    let input_stream = input_device
        .build_input_stream(
            &in_config,
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                let rms = (data.iter().map(|s| s * s).sum::<f32>() / data.len() as f32).sqrt();
                *level_w.lock().unwrap() = rms;
                for frame in data.chunks(in_channels) {
                    let mono = frame.iter().sum::<f32>() / in_channels as f32;
                    if loopback_prod.try_push(mono).is_err() {
                        overruns_w.fetch_add(1, Ordering::Relaxed);
                    }
                }
            },
            |err| eprintln!("mic test capture error: {err}"),
            None,
        )
        .map_err(|e| format!("build input: {e}"))?;

    // Base consumption ratio. Adjusted at runtime by drift compensation below.
    let base_step = in_rate as f32 / out_rate as f32;
    let buf_cap = LOOPBACK_BUF_SIZE;
    let target_fill = buf_cap / 2;
    let mut accum = 0.0f32;
    let mut last_sample = 0.0f32;

    let output_stream = output_device
        .build_output_stream(
            &out_config,
            move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                // Drift compensation: speed up/slow down consumption based on buffer fill.
                // Bluetooth input (AirPods HFP) delivers data in bursts — this keeps
                // the buffer centered at 50% so neither underruns nor overruns accumulate.
                let fill = loopback_cons.occupied_len();
                let drift = (fill as f32 - target_fill as f32) / buf_cap as f32;
                let step = base_step * (1.0 + drift);

                for frame in data.chunks_mut(out_channels) {
                    accum += step;
                    while accum >= 1.0 {
                        accum -= 1.0;
                        match loopback_cons.try_pop() {
                            Some(s) => last_sample = s,
                            None => { underruns_r.fetch_add(1, Ordering::Relaxed); }
                        }
                    }
                    for s in frame.iter_mut() {
                        *s = last_sample;
                    }
                }
            },
            |err| eprintln!("mic test playback error: {err}"),
            None,
        )
        .map_err(|e| format!("build output: {e}"))?;

    // Pre-fill the ring before starting output — absorbs Bluetooth callback jitter
    input_stream
        .play()
        .map_err(|e| format!("start capture: {e}"))?;
    std::thread::sleep(Duration::from_millis(LOOPBACK_PREFILL_MS));
    output_stream
        .play()
        .map_err(|e| format!("start playback: {e}"))?;

    let mut ticks = 0u32;
    while MIC_TESTING.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(MIC_POLL_MS));
        let rms = *level.lock().unwrap();
        let normalized = (rms * 10.0).min(1.0);
        let _ = app.emit("mic-level", normalized);

        ticks += 1;
        if ticks % 40 == 0 {
            let over = overruns.swap(0, Ordering::Relaxed);
            let under = underruns.swap(0, Ordering::Relaxed);
            if over > 0 || under > 0 {
                eprintln!("mic test: overruns={over} underruns={under} (last 2s)");
            }
        }
    }

    let _ = app.emit("mic-level", 0.0f32);
    Ok(())
}

pub fn play_test_tone(output_device_name: Option<String>) -> Result<(), String> {
    if TONE_PLAYING.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    std::thread::Builder::new()
        .name("test-tone".into())
        .spawn(move || {
            if let Err(e) = run_test_tone(output_device_name) {
                eprintln!("test tone error: {e}");
            }
            TONE_PLAYING.store(false, Ordering::SeqCst);
        })
        .map_err(|e| format!("spawn test tone: {e}"))?;

    Ok(())
}

fn run_test_tone(output_device_name: Option<String>) -> Result<(), String> {
    let host = cpal::default_host();

    let device = resolve_device(&host, &output_device_name, "output")?;
    let config = pick_test_config(
        device.supported_output_configs().map_err(|e| format!("output configs: {e}"))?,
        48_000,
    )?;

    let sample_rate = config.sample_rate.0 as f32;
    let channels = config.channels as usize;
    let phase_inc = TONE_FREQ / sample_rate;
    let mut phase = 0.0f32;

    let stream = device
        .build_output_stream(
            &config,
            move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                for frame in data.chunks_mut(channels) {
                    let sample = (phase * 2.0 * std::f32::consts::PI).sin() * TONE_VOLUME;
                    for s in frame.iter_mut() {
                        *s = sample;
                    }
                    phase = (phase + phase_inc) % 1.0;
                }
            },
            |err| eprintln!("test tone error: {err}"),
            None,
        )
        .map_err(|e| format!("build output: {e}"))?;

    stream.play().map_err(|e| format!("start playback: {e}"))?;
    std::thread::sleep(TONE_DURATION);
    Ok(())
}
