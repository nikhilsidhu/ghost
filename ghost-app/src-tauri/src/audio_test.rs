use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cpal::traits::{DeviceTrait, StreamTrait};
use ghost_audio::{TrackEvent, TrackIo, VoiceAudio};
use tauri::{AppHandle, Emitter};

use crate::audio::{open_output, pick_format, resolve_device, ChosenDevice, Direction};

/// The mic test running now, by its number; 0 when none runs. A test stopped and one
/// started right after never mix: the first's thread sees it is no longer current.
static MIC_TEST: AtomicU64 = AtomicU64::new(0);
/// Numbers the mic tests.
static MIC_TESTS: AtomicU64 = AtomicU64::new(0);
static TONE_PLAYING: AtomicBool = AtomicBool::new(false);

const MIC_POLL_MS: u64 = 50;
/// Speech sits well under full scale; this makes normal speech nearly fill the meter.
const METER_GAIN: f32 = 10.0;
const TONE_DURATION: Duration = Duration::from_secs(2);
const TONE_FREQ: f32 = 440.0;
const TONE_VOLUME: f32 = 0.3;

/// Hear the microphone through the call's own audio path, with its processing and the
/// chosen devices, and see its level: the voice audio runs a track whose frames come
/// straight back. Ends with `stop_mic_test` (a call joining calls it too), or when its
/// devices fail; `mic-test-ended` says so, with the failure if there was one. Only the
/// test's own track is stopped, so a call that took the microphone keeps it.
pub fn start_mic_test(app: AppHandle, audio: Arc<VoiceAudio>) -> Result<(), String> {
    let test = MIC_TESTS.fetch_add(1, Ordering::SeqCst) + 1;
    if MIC_TEST.compare_exchange(0, test, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return Ok(());
    }
    let (events, mut reports) = tokio::sync::mpsc::unbounded_channel();
    let started = TrackIo::loopback(events).map_err(|e| format!("loopback track: {e}")).and_then(|io| audio.start_run(io));
    let run = match started {
        Ok(run) => run,
        Err(e) => {
            let _ = MIC_TEST.compare_exchange(test, 0, Ordering::SeqCst, Ordering::SeqCst);
            return Err(e);
        }
    };
    let spawned = std::thread::Builder::new().name("mic-test".into()).spawn({
        let audio = audio.clone();
        move || {
            let mut failure = None;
            while MIC_TEST.load(Ordering::SeqCst) == test {
                std::thread::sleep(Duration::from_millis(MIC_POLL_MS));
                match reports.try_recv() {
                    Ok(TrackEvent::Failed(e)) => {
                        failure = Some(e);
                        break;
                    }
                    Ok(TrackEvent::Notice(notice)) => tracing::warn!("mic test: {notice}"),
                    Err(_) => {}
                }
                let _ = app.emit("mic-level", (audio.input_level() * METER_GAIN).min(1.0));
            }
            // Still this test's to report, unless a newer test already took over.
            let current = MIC_TEST.compare_exchange(test, 0, Ordering::SeqCst, Ordering::SeqCst).is_ok() || MIC_TEST.load(Ordering::SeqCst) == 0;
            audio.stop_run(run);
            if current {
                let _ = app.emit("mic-level", 0.0f32);
                let _ = app.emit("mic-test-ended", failure);
            }
        }
    });
    if let Err(e) = spawned {
        audio.stop_run(run);
        let _ = MIC_TEST.compare_exchange(test, 0, Ordering::SeqCst, Ordering::SeqCst);
        return Err(format!("spawn mic test: {e}"));
    }
    Ok(())
}

pub fn stop_mic_test() {
    MIC_TEST.store(0, Ordering::SeqCst);
}

pub fn play_test_tone(output: Option<ChosenDevice>) -> Result<(), String> {
    if TONE_PLAYING.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    std::thread::Builder::new()
        .name("test-tone".into())
        .spawn(move || {
            if let Err(e) = run_test_tone(output) {
                tracing::warn!("test tone error: {e}");
            }
            TONE_PLAYING.store(false, Ordering::SeqCst);
        })
        .map_err(|e| format!("spawn test tone: {e}"))?;

    Ok(())
}

fn run_test_tone(output: Option<ChosenDevice>) -> Result<(), String> {
    let host = cpal::default_host();

    let device = resolve_device(&host, output.as_ref(), Direction::Output)?;
    let format = pick_format(device.supported_output_configs().map_err(|e| format!("output configs: {e}"))?)?;

    let phase_inc = TONE_FREQ / format.config.sample_rate as f32;
    let mut phase = 0.0f32;
    let stream = open_output(
        &device,
        &format,
        move |out| {
            for sample in out.iter_mut() {
                *sample = (phase * std::f32::consts::TAU).sin() * TONE_VOLUME;
                phase = (phase + phase_inc) % 1.0;
            }
        },
        |err| tracing::warn!("test tone error: {err}"),
    )?;

    stream.play().map_err(|e| format!("start playback: {e}"))?;
    std::thread::sleep(TONE_DURATION);
    Ok(())
}
