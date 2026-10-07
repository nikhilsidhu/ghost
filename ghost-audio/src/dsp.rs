//! Signal processing on 48 kHz mono frames: noise suppression, voice activity and
//! volume normalization.

use crate::constants::*;

/// Denoise a frame in nnnoiseless-sized chunks; returns the highest voice-activity
/// probability among them.
pub fn denoise_frame(
    denoiser: &mut nnnoiseless::DenoiseState,
    frame: &mut [f32],
    denoise_in: &mut [f32; DENOISE_FRAME_SIZE],
    denoise_out: &mut [f32; DENOISE_FRAME_SIZE],
) -> f32 {
    let mut max_vad: f32 = 0.0;
    for chunk_start in (0..FRAME_SAMPLES).step_by(DENOISE_FRAME_SIZE) {
        if chunk_start + DENOISE_FRAME_SIZE > FRAME_SAMPLES {
            break;
        }
        for i in 0..DENOISE_FRAME_SIZE {
            denoise_in[i] = frame[chunk_start + i] * DENOISE_SAMPLE_SCALE;
        }
        let vad = denoiser.process_frame(denoise_out, denoise_in);
        max_vad = max_vad.max(vad);
        for i in 0..DENOISE_FRAME_SIZE {
            frame[chunk_start + i] = denoise_out[i] / DENOISE_SAMPLE_SCALE;
        }
    }
    max_vad
}

/// Speech by loudness, for when noise suppression is off: 1.0 if loud enough, else 0.0.
pub fn energy_vad(samples: &[f32]) -> f32 {
    if rms(samples) >= ENERGY_VAD_SPEECH_RMS { 1.0 } else { 0.0 }
}

pub fn rms(samples: &[f32]) -> f32 {
    (samples.iter().map(|s| s * s).sum::<f32>() / samples.len() as f32).sqrt()
}

/// Volume normalizer: steers speech toward a target loudness, cutting gain quickly and
/// raising it slowly.
pub struct Agc {
    current_gain: f32,
}

impl Agc {
    pub fn new() -> Self {
        Self { current_gain: 1.0 }
    }

    pub fn process(&mut self, samples: &mut [f32]) {
        let rms = rms(samples);
        if rms < AGC_SILENCE_FLOOR {
            return;
        }
        let desired_gain = (AGC_TARGET_RMS / rms).min(AGC_MAX_GAIN);
        let alpha = if desired_gain < self.current_gain { AGC_ATTACK } else { AGC_RELEASE };
        self.current_gain += alpha * (desired_gain - self.current_gain);
        for s in samples.iter_mut() {
            *s = (*s * self.current_gain).clamp(-1.0, 1.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agc_raises_quiet_speech_and_ignores_silence() {
        let mut agc = Agc::new();
        let mut quiet = vec![0.01f32; FRAME_SAMPLES];
        for _ in 0..50 {
            quiet.fill(0.01);
            agc.process(&mut quiet);
        }
        assert!(quiet[0] > 0.02, "gain rose toward the target");
        let mut silence = vec![0.0f32; FRAME_SAMPLES];
        agc.process(&mut silence);
        assert!(silence.iter().all(|s| *s == 0.0));
    }
}
