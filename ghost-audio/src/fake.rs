//! Synthetic devices for tests: capture plays a sine tone that can be changed or
//! silenced at any time, playback records what the mixer produced, both paced in real
//! time like hardware. `tone_windows` tells which stretches of a recording carry a tone.

use std::f32::consts::TAU;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::constants::{FRAME_MS, FRAME_SAMPLES, SAMPLE_RATE};
use crate::devices::{AudioDevices, CaptureRead, DeviceStreams, Playback};

const FRAME_DURATION: Duration = Duration::from_millis(FRAME_MS as u64);

/// What the microphone hears, shared with the open capture.
#[derive(Default)]
struct Tone {
    frequency: AtomicU32,
    /// 0 is silence.
    amplitude: AtomicU32,
}

/// A tone source and a recorder standing in for a microphone and speakers. The
/// microphone starts silent.
#[derive(Default)]
pub struct ToneDevices {
    tone: Arc<Tone>,
    recording: Arc<Mutex<Vec<f32>>>,
    /// Set to make open devices fail with this reason at their next read.
    failure: Arc<Mutex<Option<String>>>,
}

impl ToneDevices {
    pub fn new() -> Arc<Self> {
        Arc::default()
    }

    /// Make the microphone hear `frequency` Hz at `amplitude` (0 for silence).
    pub fn set_tone(&self, frequency: f32, amplitude: f32) {
        self.tone.frequency.store(frequency.to_bits(), Ordering::Relaxed);
        self.tone.amplitude.store(amplitude.to_bits(), Ordering::Relaxed);
    }

    /// Everything played so far.
    pub fn recording(&self) -> Vec<f32> {
        self.recording.lock().unwrap().clone()
    }

    /// Samples played so far, for marking where a test phase begins.
    pub fn recorded_len(&self) -> usize {
        self.recording.lock().unwrap().len()
    }

    /// Make the open devices fail for good, as unplugged hardware does.
    pub fn fail(&self, reason: &str) {
        *self.failure.lock().unwrap() = Some(reason.to_string());
    }
}

impl AudioDevices for ToneDevices {
    fn open(&self, playback: Playback) -> Result<Box<dyn DeviceStreams>, String> {
        let playing = Arc::new(AtomicBool::new(true));
        let (still_playing, recording) = (playing.clone(), self.recording.clone());
        std::thread::Builder::new()
            .name("fake-playback".into())
            .spawn(move || {
                let mut frame = vec![0.0f32; FRAME_SAMPLES];
                let mut deadline = Instant::now();
                while still_playing.load(Ordering::Relaxed) {
                    deadline += FRAME_DURATION;
                    std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
                    playback.fill(&mut frame);
                    recording.lock().unwrap().extend_from_slice(&frame);
                }
            })
            .map_err(|e| format!("spawn fake playback: {e}"))?;
        Ok(Box::new(ToneStreams {
            tone: self.tone.clone(),
            failure: self.failure.clone(),
            phase: 0.0,
            next_frame: Instant::now() + FRAME_DURATION,
            playing,
        }))
    }
}

struct ToneStreams {
    tone: Arc<Tone>,
    failure: Arc<Mutex<Option<String>>>,
    phase: f32,
    next_frame: Instant,
    playing: Arc<AtomicBool>,
}

impl Drop for ToneStreams {
    fn drop(&mut self) {
        self.playing.store(false, Ordering::Relaxed);
    }
}

impl DeviceStreams for ToneStreams {
    fn read_frame(&mut self, frame: &mut [f32], timeout: Duration) -> CaptureRead {
        if let Some(reason) = self.failure.lock().unwrap().clone() {
            return CaptureRead::Failed(reason);
        }
        let now = Instant::now();
        if self.next_frame > now + timeout {
            std::thread::sleep(timeout);
            return CaptureRead::Waiting;
        }
        std::thread::sleep(self.next_frame.saturating_duration_since(now));
        self.next_frame += FRAME_DURATION;
        let amplitude = f32::from_bits(self.tone.amplitude.load(Ordering::Relaxed));
        let step = TAU * f32::from_bits(self.tone.frequency.load(Ordering::Relaxed)) / SAMPLE_RATE as f32;
        for sample in frame.iter_mut() {
            *sample = amplitude * self.phase.sin();
            self.phase = (self.phase + step) % TAU;
        }
        CaptureRead::Frame
    }
}

/// For each 20 ms window of `samples`, whether `frequency` dominates it: its share of
/// the window's energy (by the Goertzel algorithm) is above `min_share`.
pub fn tone_windows(samples: &[f32], frequency: f32, min_share: f32) -> Vec<bool> {
    let coefficient = 2.0 * (TAU * frequency / SAMPLE_RATE as f32).cos();
    samples
        .chunks_exact(FRAME_SAMPLES)
        .map(|window| {
            let (mut s1, mut s2) = (0.0f32, 0.0f32);
            for sample in window {
                let s0 = sample + coefficient * s1 - s2;
                s2 = s1;
                s1 = s0;
            }
            let tone_power = s1 * s1 + s2 * s2 - coefficient * s1 * s2;
            let total_power: f32 = window.iter().map(|s| s * s).sum::<f32>() * window.len() as f32 / 2.0;
            total_power > 1e-6 && tone_power / total_power > min_share
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tone_windows_find_the_tone_and_only_it() {
        let step = TAU * 440.0 / SAMPLE_RATE as f32;
        let tone: Vec<f32> = (0..FRAME_SAMPLES * 2).map(|i| 0.3 * (step * i as f32).sin()).collect();
        let mut samples = tone.clone();
        samples.extend(std::iter::repeat(0.0).take(FRAME_SAMPLES));
        assert_eq!(tone_windows(&samples, 440.0, 0.5), vec![true, true, false]);
        assert_eq!(tone_windows(&tone, 1000.0, 0.5), vec![false, false]);
    }
}
