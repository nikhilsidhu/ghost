use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::SampleFormat;
use tauri::{AppHandle, Emitter};

static MIC_TESTING: AtomicBool = AtomicBool::new(false);
static TONE_PLAYING: AtomicBool = AtomicBool::new(false);

const MIC_POLL_MS: u64 = 50;
const TONE_DURATION: Duration = Duration::from_secs(2);
const TONE_FREQ: f32 = 440.0;
const TONE_VOLUME: f32 = 0.3;

pub fn start_mic_test(app: AppHandle) -> Result<(), String> {
    if MIC_TESTING.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    std::thread::Builder::new()
        .name("mic-test".into())
        .spawn(move || {
            if let Err(e) = run_mic_test(&app) {
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

fn run_mic_test(app: &AppHandle) -> Result<(), String> {
    let host = cpal::default_host();
    let device = host.default_input_device().ok_or("no input device")?;

    let supported = device
        .supported_input_configs()
        .map_err(|e| format!("input configs: {e}"))?
        .find(|c| c.sample_format() == SampleFormat::F32)
        .ok_or("no f32 input config")?;
    let config = supported.with_max_sample_rate().config();

    let level = Arc::new(std::sync::Mutex::new(0.0f32));
    let level_w = level.clone();

    let stream = device
        .build_input_stream(
            &config,
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                let rms = (data.iter().map(|s| s * s).sum::<f32>() / data.len() as f32).sqrt();
                *level_w.lock().unwrap() = rms;
            },
            |err| eprintln!("mic test capture error: {err}"),
            None,
        )
        .map_err(|e| format!("build input: {e}"))?;

    stream.play().map_err(|e| format!("start capture: {e}"))?;

    while MIC_TESTING.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(MIC_POLL_MS));
        let rms = *level.lock().unwrap();
        let normalized = (rms * 10.0).min(1.0);
        let _ = app.emit("mic-level", normalized);
    }

    let _ = app.emit("mic-level", 0.0f32);
    Ok(())
}

pub fn play_test_tone() -> Result<(), String> {
    if TONE_PLAYING.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    std::thread::Builder::new()
        .name("test-tone".into())
        .spawn(move || {
            if let Err(e) = run_test_tone() {
                eprintln!("test tone error: {e}");
            }
            TONE_PLAYING.store(false, Ordering::SeqCst);
        })
        .map_err(|e| format!("spawn test tone: {e}"))?;

    Ok(())
}

fn run_test_tone() -> Result<(), String> {
    let host = cpal::default_host();
    let device = host.default_output_device().ok_or("no output device")?;

    let supported = device
        .supported_output_configs()
        .map_err(|e| format!("output configs: {e}"))?
        .find(|c| c.sample_format() == SampleFormat::F32)
        .ok_or("no f32 output config")?;
    let config = supported.with_max_sample_rate().config();

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
