//! Signal processing on 48 kHz mono frames: noise suppression and voice activity.

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

pub fn rms(samples: &[f32]) -> f32 {
    (samples.iter().map(|s| s * s).sum::<f32>() / samples.len() as f32).sqrt()
}
