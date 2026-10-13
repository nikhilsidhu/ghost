//! Synthetic devices for tests: capture plays a sine tone that can be changed or
//! silenced at any time, plus any samples queued to play once, and can hear the
//! speakers as a laptop's microphone does; playback records what the mixer produced.
//! Both are paced in real time on one clock, as duplex hardware is, so a busy machine
//! that wakes them late stretches time for both alike. `tone_windows` tells which
//! stretches of a recording carry a tone, and `speech_like` makes a voice that voice
//! activity detection takes for speech.

use std::collections::VecDeque;
use std::f32::consts::TAU;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::constants::{FRAME_MS, FRAME_SAMPLES, SAMPLE_RATE};
use crate::devices::{AudioDevices, CaptureRead, DeviceStreams, Playback};

const FRAME_DURATION: Duration = Duration::from_millis(FRAME_MS as u64);

/// How late the microphone hears the speakers: the devices' latency and the air.
const LEAK_DELAY: usize = FRAME_SAMPLES;

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
    /// Samples the microphone hears once, on top of the tone.
    queued: Arc<Mutex<VecDeque<f32>>>,
    /// How strongly the microphone hears the speakers; 0 is not at all.
    leak: Arc<AtomicU32>,
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

    /// Make the microphone hear `samples` once, from the next frame on.
    pub fn play(&self, samples: &[f32]) {
        self.queued.lock().unwrap().extend(samples.iter().copied());
    }

    /// Make the microphone hear the speakers at `gain`, a frame late, as a laptop's
    /// microphone hears its own speakers.
    pub fn set_leak(&self, gain: f32) {
        self.leak.store(gain.to_bits(), Ordering::Relaxed);
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
        Ok(Box::new(ToneStreams {
            tone: self.tone.clone(),
            queued: self.queued.clone(),
            leak: self.leak.clone(),
            recording: self.recording.clone(),
            recorded_before: self.recorded_len(),
            captured: 0,
            failure: self.failure.clone(),
            phase: 0.0,
            next_frame: Instant::now() + FRAME_DURATION,
            playback,
            played: vec![0.0; FRAME_SAMPLES],
        }))
    }
}

struct ToneStreams {
    tone: Arc<Tone>,
    queued: Arc<Mutex<VecDeque<f32>>>,
    leak: Arc<AtomicU32>,
    recording: Arc<Mutex<Vec<f32>>>,
    /// Where these devices' playback starts in the recording; capture runs on the same
    /// clock, so captured sample `n` is heard while recorded sample `recorded_before + n`
    /// plays.
    recorded_before: usize,
    captured: usize,
    failure: Arc<Mutex<Option<String>>>,
    phase: f32,
    next_frame: Instant,
    /// Played on each capture tick.
    playback: Playback,
    played: Vec<f32>,
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
        let mut queued = self.queued.lock().unwrap();
        for sample in frame.iter_mut() {
            *sample = amplitude * self.phase.sin() + queued.pop_front().unwrap_or(0.0);
            self.phase = (self.phase + step) % TAU;
        }
        drop(queued);
        let leak = f32::from_bits(self.leak.load(Ordering::Relaxed));
        if leak > 0.0 {
            let recording = self.recording.lock().unwrap();
            for (i, sample) in frame.iter_mut().enumerate() {
                let heard = (self.recorded_before + self.captured + i).checked_sub(LEAK_DELAY).and_then(|at| recording.get(at));
                *sample += leak * heard.copied().unwrap_or(0.0);
            }
        }
        for sample in frame.iter_mut() {
            *sample = sample.clamp(-1.0, 1.0);
        }
        self.captured += frame.len();
        // The speakers play the tick's frame, which the microphone hears on the next.
        self.playback.fill(&mut self.played);
        self.recording.lock().unwrap().extend_from_slice(&self.played);
        CaptureRead::Frame
    }

    fn input_name(&self) -> String {
        "tone".into()
    }
}

/// The power of `frequency` in a 20 ms window, by the Goertzel algorithm.
fn tone_power(window: &[f32], frequency: f32) -> f32 {
    let coefficient = 2.0 * (TAU * frequency / SAMPLE_RATE as f32).cos();
    let (mut s1, mut s2) = (0.0f32, 0.0f32);
    for sample in window {
        let s0 = sample + coefficient * s1 - s2;
        s2 = s1;
        s1 = s0;
    }
    s1 * s1 + s2 * s2 - coefficient * s1 * s2
}

/// For each 20 ms window of `samples`, whether `frequency` dominates it: its share of
/// the window's energy is above `min_share`.
pub fn tone_windows(samples: &[f32], frequency: f32, min_share: f32) -> Vec<bool> {
    samples
        .chunks_exact(FRAME_SAMPLES)
        .map(|window| {
            let total_power: f32 = window.iter().map(|s| s * s).sum::<f32>() * window.len() as f32 / 2.0;
            total_power > 1e-6 && tone_power(window, frequency) / total_power > min_share
        })
        .collect()
}

/// For each 20 ms window of `samples`, whether `frequency` is there at all: within
/// `within_db` of its usual (median) power across the windows, whatever else plays.
/// What tells a tone rebuilt or concealed after a loss, perhaps less pure, from a
/// dropout.
pub fn tone_present(samples: &[f32], frequency: f32, within_db: f32) -> Vec<bool> {
    let powers: Vec<f32> = samples.chunks_exact(FRAME_SAMPLES).map(|window| tone_power(window, frequency)).collect();
    let mut sorted = powers.clone();
    sorted.sort_by(f32::total_cmp);
    let Some(median) = sorted.get(sorted.len() / 2) else { return Vec::new() };
    let floor = median * 10f32.powf(-within_db / 10.0);
    powers.iter().map(|power| *median > 1e-6 && *power >= floor).collect()
}

/// A two-pole resonator: one formant of the vocal tract.
struct Formant {
    a1: f32,
    a2: f32,
    gain: f32,
    y1: f32,
    y2: f32,
}

impl Formant {
    fn tune(&mut self, frequency: f32, bandwidth: f32) {
        let r = (-std::f32::consts::PI * bandwidth / SAMPLE_RATE as f32).exp();
        self.a1 = 2.0 * r * (TAU * frequency / SAMPLE_RATE as f32).cos();
        self.a2 = -r * r;
        self.gain = 1.0 - r;
    }

    fn step(&mut self, x: f32) -> f32 {
        let y = self.gain * x + self.a1 * self.y1 + self.a2 * self.y2;
        self.y2 = self.y1;
        self.y1 = y;
        y
    }
}

/// A synthetic voice that nnnoiseless takes for speech: glottal pulses at a wandering
/// pitch, shaped by vowel formants, in 200 ms syllables, sentences of 1.6 s and pauses
/// of 0.6 s. `level` is the RMS of its sentences.
pub fn speech_like(seconds: f32, level: f32) -> Vec<f32> {
    /// F1-F3 of a few vowels, and their bandwidths.
    const VOWELS: [[f32; 3]; 5] = [[730.0, 1090.0, 2440.0], [270.0, 2290.0, 3010.0], [300.0, 870.0, 2240.0], [530.0, 1840.0, 2480.0], [570.0, 840.0, 2410.0]];
    const BANDWIDTHS: [f32; 3] = [90.0, 110.0, 170.0];
    const SENTENCE: f32 = 1.6;
    const CYCLE: f32 = 2.2;
    const SYLLABLE: f32 = 0.2;
    let rate = SAMPLE_RATE as f32;
    let mut formants: Vec<Formant> = (0..3).map(|_| Formant { a1: 0.0, a2: 0.0, gain: 0.0, y1: 0.0, y2: 0.0 }).collect();
    let (mut phase, mut noise) = (0.0f32, 7u32);
    let samples: Vec<f32> = (0..(seconds * rate) as usize)
        .map(|i| {
            let t = i as f32 / rate;
            let into_cycle = t % CYCLE;
            let within = into_cycle % SYLLABLE;
            let envelope = if into_cycle < SENTENCE { (within / 0.03).min(1.0) * ((SYLLABLE - within) / 0.06).min(1.0) } else { 0.0 };
            let vowel = VOWELS[((into_cycle / SYLLABLE) as usize + (t / CYCLE) as usize * 3) % VOWELS.len()];
            for (formant, (frequency, bandwidth)) in formants.iter_mut().zip(vowel.iter().zip(BANDWIDTHS)) {
                formant.tune(*frequency, bandwidth);
            }
            let pitch = 120.0 + 15.0 * (TAU * 0.7 * t).sin() + 10.0 * (TAU * 3.0 * into_cycle / SENTENCE).sin();
            phase += pitch / rate;
            let pulse = if phase >= 1.0 {
                phase -= 1.0;
                1.0
            } else {
                0.0
            };
            noise = noise.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let breath = ((noise >> 8) as f32 / (1u32 << 24) as f32 - 0.5) * 0.02;
            let source = pulse + breath;
            formants.iter_mut().fold(0.0, |sum, formant| sum + formant.step(source)) * envelope
        })
        .collect();
    let voiced: Vec<f32> = samples.iter().enumerate().filter(|(i, _)| (*i as f32 / rate) % CYCLE < SENTENCE).map(|(_, s)| *s).collect();
    let scale = level / crate::dsp::rms(&voiced);
    samples.iter().map(|s| s * scale).collect()
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

    #[test]
    fn a_tone_is_present_until_it_drops_out_whatever_plays_beside_it() {
        let tone = |frequency: f32, amplitude: f32| -> Vec<f32> {
            (0..FRAME_SAMPLES).map(|i| amplitude * (TAU * frequency * i as f32 / SAMPLE_RATE as f32).sin()).collect::<Vec<f32>>()
        };
        let mix = |a: Vec<f32>, b: Vec<f32>| -> Vec<f32> { a.iter().zip(&b).map(|(x, y)| x + y).collect() };
        let mut samples = Vec::new();
        samples.extend(mix(tone(440.0, 0.3), tone(880.0, 0.3)));
        samples.extend(mix(tone(440.0, 0.1), tone(880.0, 0.3)));
        samples.extend(mix(tone(440.0, 0.3), tone(880.0, 0.3)));
        samples.extend(mix(tone(440.0, 0.03), tone(880.0, 0.3)));
        assert_eq!(tone_present(&samples, 440.0, 10.0), vec![true, true, true, false], "-9.5 dB is there, -20 dB dropped out");
    }

    #[test]
    fn the_synthetic_voice_counts_as_speech() {
        let voice = speech_like(4.4, 0.03);
        let mut denoiser = nnnoiseless::DenoiseState::new();
        let (mut input, mut output) = ([0.0f32; 480], [0.0f32; 480]);
        let (mut voiced, mut detected) = (0, 0);
        for (i, frame) in voice.chunks_exact(FRAME_SAMPLES).enumerate() {
            let mut probability: f32 = 0.0;
            for half in frame.chunks_exact(480) {
                for (scaled, sample) in input.iter_mut().zip(half) {
                    *scaled = sample * i16::MAX as f32;
                }
                probability = probability.max(denoiser.process_frame(&mut output, &input));
            }
            // Skip each sentence's first frames, while the detector warms up.
            let t = i as f32 * FRAME_MS as f32 / 1000.0;
            if t % 2.2 > 0.1 && t % 2.2 < 1.6 {
                voiced += 1;
                detected += (probability > crate::constants::VAD_THRESHOLD) as u32;
            }
        }
        assert!(detected as f32 > voiced as f32 * 0.9, "{detected} of {voiced} voiced frames detected");
    }
}
