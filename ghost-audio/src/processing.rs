//! WebRTC's capture processing, as sonora ports it: echo cancellation on the raw
//! microphone, before anything nonlinear touches it, and volume normalization after
//! noise suppression. The echo canceller learns from what playback played, which the
//! device's playback thread hands over through a queue, so neither waits on the other.

use sonora::config::{AdaptiveDigital, EchoCanceller as EchoCancellerConfig, GainController2, MaxProcessingRate, Pipeline};
use sonora::{AudioProcessing, Config, StreamConfig};

use crate::constants::*;
use crate::dsp::rms;

fn mono() -> StreamConfig {
    StreamConfig::new(SAMPLE_RATE, 1)
}

/// Takes out of the microphone what the speakers played into it, so the others do not
/// hear themselves come back.
pub(crate) struct EchoCanceller {
    apm: AudioProcessing,
    enabled: bool,
    /// Playback not yet a whole chunk.
    pending: Vec<f32>,
    scratch: [f32; PROCESSING_CHUNK],
}

impl EchoCanceller {
    pub fn new(enabled: bool) -> Self {
        let apm = AudioProcessing::builder().config(Self::config(enabled)).capture_config(mono()).render_config(mono()).build();
        Self { apm, enabled, pending: Vec::with_capacity(RENDER_QUEUE), scratch: [0.0; PROCESSING_CHUNK] }
    }

    fn config(enabled: bool) -> Config {
        // At the pipeline's default 32 kHz everything above 16 kHz is lost.
        let pipeline = Pipeline { maximum_internal_processing_rate: MaxProcessingRate::Rate48kHz, ..Default::default() };
        Config { pipeline, echo_canceller: enabled.then(EchoCancellerConfig::default), ..Default::default() }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        if enabled != self.enabled {
            self.enabled = enabled;
            self.pending.clear();
            self.apm.apply_config(Self::config(enabled));
        }
    }

    /// Learn from what playback played since the last call, in order.
    pub fn played(&mut self, samples: &[f32]) {
        if !self.enabled {
            return;
        }
        self.pending.extend_from_slice(samples);
        let whole = self.pending.len() / PROCESSING_CHUNK * PROCESSING_CHUNK;
        for chunk in self.pending[..whole].chunks_exact(PROCESSING_CHUNK) {
            // Playback is only analyzed; what it plays stays as it is.
            let _ = self.apm.process_render_f32(&[chunk], &mut [&mut self.scratch]);
        }
        self.pending.drain(..whole);
    }

    /// Cancel the echo in one engine frame, in place.
    pub fn process(&mut self, frame: &mut [f32]) {
        if !self.enabled {
            return;
        }
        for chunk in frame.chunks_exact_mut(PROCESSING_CHUNK) {
            self.scratch.copy_from_slice(chunk);
            if self.apm.process_capture_f32(&[&self.scratch], &mut [chunk]).is_err() {
                chunk.copy_from_slice(&self.scratch);
            }
        }
    }

    /// How much echo it removes and the speaker-to-microphone delay it found, for the
    /// diagnostics.
    pub fn summary(&self) -> String {
        if !self.enabled {
            return "off".into();
        }
        let stats = self.apm.statistics();
        let erle = stats.echo_return_loss_enhancement.map_or("-".into(), |db| format!("{db:.0}dB"));
        let delay = stats.delay_ms.map_or("-".into(), |ms| format!("{ms}ms"));
        format!("erle={erle} delay={delay}")
    }
}

/// Brings speech to a steady loudness: WebRTC's AGC2, which adapts only on speech, never
/// faster than a few dB a second, and limits instead of clipping. It starts from the gain
/// learned for the microphone, and keeps learning it.
pub(crate) struct VolumeNormalizer {
    apm: AudioProcessing,
    /// The gain applied to speech, in dB, as measured from levels in and out.
    gain_db: f32,
    /// Speech frames that went into `gain_db`.
    heard: u32,
    scratch: [f32; PROCESSING_CHUNK],
}

impl VolumeNormalizer {
    /// A normalizer starting at `start_gain_db`, the gain it settled on for this
    /// microphone before, or `AGC_START_GAIN_DB` when nothing is learned.
    pub fn new(start_gain_db: f32) -> Self {
        let start_gain_db = start_gain_db.clamp(0.0, AGC_MAX_GAIN_DB);
        let adaptive = AdaptiveDigital { initial_gain_db: start_gain_db, max_gain_db: AGC_MAX_GAIN_DB, ..Default::default() };
        let config = Config {
            gain_controller2: Some(GainController2 { adaptive_digital: Some(adaptive), ..Default::default() }),
            ..Default::default()
        };
        let apm = AudioProcessing::builder().config(config).capture_config(mono()).build();
        Self { apm, gain_db: start_gain_db, heard: 0, scratch: [0.0; PROCESSING_CHUNK] }
    }

    /// Normalize one engine frame in place; `speech` says whether it holds speech, whose
    /// gain is the one worth learning.
    pub fn process(&mut self, frame: &mut [f32], speech: bool) {
        let before = rms(frame);
        for chunk in frame.chunks_exact_mut(PROCESSING_CHUNK) {
            self.scratch.copy_from_slice(chunk);
            if self.apm.process_capture_f32(&[&self.scratch], &mut [chunk]).is_err() {
                chunk.copy_from_slice(&self.scratch);
            }
        }
        if speech && before > AGC_LEARN_MIN_LEVEL {
            let gain_db = 20.0 * (rms(frame) / before).max(f32::MIN_POSITIVE).log10();
            self.gain_db += AGC_LEARN_WEIGHT * (gain_db - self.gain_db);
            self.heard += 1;
        }
    }

    /// The gain it settled on, once it heard enough speech to tell.
    pub fn learned_gain_db(&self) -> Option<f32> {
        (self.heard >= AGC_LEARN_MIN_FRAMES).then(|| self.gain_db.clamp(0.0, AGC_MAX_GAIN_DB))
    }
}

/// The capture processing of one microphone, kept from call to call so the echo
/// canceller and the normalizer start each call where the last left off.
pub(crate) struct CaptureProcessing {
    pub echo: EchoCanceller,
    pub volume: VolumeNormalizer,
    /// The microphone the normalizer learned on.
    pub input: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::speech_like;

    fn noise(len: usize, seed: u32) -> Vec<f32> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                ((state >> 8) as f32 / (1 << 24) as f32 - 0.5) * 0.4
            })
            .collect()
    }

    /// Mic input that hears `played` at half strength one frame later.
    fn echoed(played: &[f32]) -> Vec<f32> {
        (0..played.len()).map(|i| i.checked_sub(FRAME_SAMPLES).map_or(0.0, |at| played[at] * 0.5)).collect()
    }

    #[test]
    fn the_echo_canceller_removes_what_the_speakers_played() {
        let played = noise(SAMPLE_RATE as usize * 4, 1);
        let mic = echoed(&played);
        let mut canceller = EchoCanceller::new(true);
        let mut out = Vec::new();
        for (heard, frame) in played.chunks_exact(FRAME_SAMPLES).zip(mic.chunks_exact(FRAME_SAMPLES)) {
            canceller.played(heard);
            let mut frame = frame.to_vec();
            canceller.process(&mut frame);
            out.extend_from_slice(&frame);
        }
        // After two seconds to converge, the echo is at least 20 dB down.
        let tail = mic.len() / 2..;
        let removed_db = 20.0 * (rms(&mic[tail.clone()]) / rms(&out[tail]).max(1e-9)).log10();
        assert!(removed_db > 20.0, "only {removed_db:.1} dB of echo removed");
    }

    #[test]
    fn a_disabled_echo_canceller_leaves_the_microphone_alone() {
        let played = noise(FRAME_SAMPLES * 10, 2);
        let mic = echoed(&played);
        let mut canceller = EchoCanceller::new(false);
        for (heard, frame) in played.chunks_exact(FRAME_SAMPLES).zip(mic.chunks_exact(FRAME_SAMPLES)) {
            canceller.played(heard);
            let mut processed = frame.to_vec();
            canceller.process(&mut processed);
            assert_eq!(processed, frame);
        }
    }

    /// Speech at `level` (RMS of its voiced parts) through `normalizer`: the output's
    /// voiced level in dBFS over the first and the last second.
    fn normalize(normalizer: &mut VolumeNormalizer, level: f32) -> (f32, f32) {
        let voice = speech_like(6.6, level);
        let mut out = Vec::new();
        for frame in voice.chunks_exact(FRAME_SAMPLES) {
            let mut frame = frame.to_vec();
            let speech = rms(&frame) > level * 0.3;
            normalizer.process(&mut frame, speech);
            out.extend_from_slice(&frame);
        }
        let voiced_db = |samples: &[f32]| {
            let frames: Vec<f32> = samples.chunks_exact(FRAME_SAMPLES).map(rms).filter(|r| *r > 1e-3).collect();
            20.0 * (frames.iter().map(|r| r * r).sum::<f32>() / frames.len() as f32).sqrt().log10()
        };
        let second = SAMPLE_RATE as usize;
        (voiced_db(&out[..second]), voiced_db(&out[out.len() - second * 3..]))
    }

    #[test]
    fn the_normalizer_lifts_a_quiet_microphone_and_starts_where_it_left_off() {
        let quiet = 0.01; // -40 dBFS
        let mut first = VolumeNormalizer::new(AGC_START_GAIN_DB);
        let (cold_start, settled) = normalize(&mut first, quiet);
        assert!(settled > -30.0, "settled at {settled:.1} dBFS");
        assert!(cold_start < settled - 3.0, "a quiet microphone starts low without a learned gain");
        let learned = first.learned_gain_db().expect("enough speech was heard");
        assert!((5.0..=AGC_MAX_GAIN_DB).contains(&learned), "learned {learned:.1} dB");

        let mut next = VolumeNormalizer::new(learned);
        let (warm_start, _) = normalize(&mut next, quiet);
        assert!((warm_start - settled).abs() < 4.0, "the next call starts at {warm_start:.1} dBFS, near {settled:.1}");
    }

    #[test]
    fn the_normalizer_never_clips_a_loud_microphone() {
        let mut normalizer = VolumeNormalizer::new(AGC_START_GAIN_DB);
        // -16.5 dBFS: the level at which the old normalizer clipped hundreds of samples.
        let voice = speech_like(4.4, 0.15);
        for frame in voice.chunks_exact(FRAME_SAMPLES) {
            let mut frame = frame.to_vec();
            normalizer.process(&mut frame, true);
            assert!(frame.iter().all(|s| s.abs() < 1.0), "a sample clipped");
        }
    }
}
