//! Changing playout delay without changing pitch: remove or insert one pitch period of
//! a decoded frame, crossfaded at its seams, as WebRTC's NetEQ does with its accelerate
//! and preemptive expand. A period repeats the signal, so taking one out or putting one
//! in shortens or lengthens the frame without shifting its frequencies.

use crate::constants::*;

/// Lags searched, in samples: 2.5–10 ms, voice fundamentals of 100–400 Hz. Two periods
/// must fit in one frame.
const MIN_LAG: usize = SAMPLE_RATE as usize / 400;
const MAX_LAG: usize = FRAME_SAMPLES / 2;
/// The coarse search runs on every `DECIMATION`th sample, then refines at full rate.
const DECIMATION: usize = 4;

/// Below this level a frame is quiet: any lag works, since nothing audible repeats.
pub const QUIET_RMS: f32 = 0.01;
/// How alike two consecutive periods must be (normalized correlation) for one to be
/// taken out or doubled unnoticed.
pub const MIN_CORRELATION: f32 = 0.9;

/// Normalized correlation between `x[..len]` and `x[lag..lag + len]`, every `step`th sample.
fn correlation(x: &[f32], lag: usize, len: usize, step: usize) -> f32 {
    let (mut cross, mut energy_a, mut energy_b) = (0.0f32, 0.0f32, 0.0f32);
    for i in (0..len).step_by(step) {
        let (a, b) = (x[i], x[i + lag]);
        cross += a * b;
        energy_a += a * a;
        energy_b += b * b;
    }
    if energy_a <= f32::EPSILON || energy_b <= f32::EPSILON {
        return 0.0;
    }
    cross / (energy_a * energy_b).sqrt()
}

/// The period to cut or repeat in `frame`, if one can be changed unnoticed.
fn period(frame: &[f32]) -> Option<usize> {
    if crate::dsp::rms(frame) < QUIET_RMS {
        return Some(MAX_LAG);
    }
    let coarse = (MIN_LAG..=MAX_LAG)
        .step_by(DECIMATION)
        .max_by(|&a, &b| correlation(frame, a, a, DECIMATION).total_cmp(&correlation(frame, b, b, DECIMATION)))?;
    let fine = (coarse.saturating_sub(DECIMATION).max(MIN_LAG)..=(coarse + DECIMATION).min(MAX_LAG))
        .max_by(|&a, &b| correlation(frame, a, a, 1).total_cmp(&correlation(frame, b, b, 1)))?;
    (correlation(frame, fine, fine, 1) >= MIN_CORRELATION).then_some(fine)
}

/// Mix `from` fading out into `to` fading in, linearly over their length.
fn crossfade(from: &[f32], to: &[f32], out: &mut Vec<f32>) {
    let len = from.len() as f32;
    for (i, (a, b)) in from.iter().zip(to).enumerate() {
        let w = (i as f32 + 0.5) / len;
        out.push(a * (1.0 - w) + b * w);
    }
}

/// Append `frame` to `out` one period shorter: its first two periods become one. False
/// (and nothing appended) when no period can be cut unnoticed.
pub fn shorten(frame: &[f32], out: &mut Vec<f32>) -> bool {
    let Some(lag) = period(frame) else { return false };
    crossfade(&frame[..lag], &frame[lag..2 * lag], out);
    out.extend_from_slice(&frame[2 * lag..]);
    true
}

/// Append `frame` to `out` one period longer: its first period plays, then fades back
/// into itself. False (and nothing appended) when no period can be repeated unnoticed.
pub fn lengthen(frame: &[f32], out: &mut Vec<f32>) -> bool {
    let Some(lag) = period(frame) else { return false };
    out.extend_from_slice(&frame[..lag]);
    crossfade(&frame[lag..2 * lag], &frame[..lag], out);
    out.extend_from_slice(&frame[lag..]);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::f32::consts::TAU;

    fn tone(frequency: f32, start: usize, len: usize) -> Vec<f32> {
        (start..start + len).map(|i| 0.3 * (TAU * frequency * i as f32 / SAMPLE_RATE as f32).sin()).collect()
    }

    /// Frequency estimated from rising zero crossings.
    fn frequency(samples: &[f32]) -> f32 {
        let crossings: Vec<usize> = (1..samples.len()).filter(|&i| samples[i - 1] < 0.0 && samples[i] >= 0.0).collect();
        let spans = (crossings.len() - 1) as f32;
        spans * SAMPLE_RATE as f32 / (crossings[crossings.len() - 1] - crossings[0]) as f32
    }

    #[test]
    fn shortening_and_lengthening_keep_the_pitch() {
        let frame = tone(220.0, 0, FRAME_SAMPLES);
        let mut shorter = Vec::new();
        assert!(shorten(&frame, &mut shorter));
        assert!(shorter.len() < FRAME_SAMPLES);
        let mut longer = Vec::new();
        assert!(lengthen(&frame, &mut longer));
        assert!(longer.len() > FRAME_SAMPLES);
        for stretched in [&shorter, &longer] {
            let f = frequency(stretched);
            assert!((f - 220.0).abs() / 220.0 < 0.005, "pitch moved to {f} Hz");
        }
    }

    #[test]
    fn stretched_frames_join_their_neighbours_smoothly() {
        let (previous, frame, next) = (tone(220.0, 0, FRAME_SAMPLES), tone(220.0, FRAME_SAMPLES, FRAME_SAMPLES), tone(220.0, 2 * FRAME_SAMPLES, FRAME_SAMPLES));
        // Largest step between samples of a 220 Hz tone at amplitude 0.3.
        let max_step = 0.3 * TAU * 220.0 / SAMPLE_RATE as f32 * 1.5;
        for change in [shorten as fn(&[f32], &mut Vec<f32>) -> bool, lengthen] {
            let mut out = previous.clone();
            assert!(change(&frame, &mut out));
            out.extend_from_slice(&next);
            let worst = out.windows(2).map(|w| (w[1] - w[0]).abs()).fold(0.0, f32::max);
            assert!(worst < max_step, "a seam jumps by {worst}");
        }
    }

    #[test]
    fn noise_is_left_alone_and_quiet_frames_always_change() {
        let mut state = 1u32;
        let noise: Vec<f32> = (0..FRAME_SAMPLES)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 8) as f32 / (1 << 24) as f32 - 0.5
            })
            .collect();
        assert!(!shorten(&noise, &mut Vec::new()), "loud noise has no period to cut");
        let quiet: Vec<f32> = noise.iter().map(|s| s * 0.001).collect();
        let mut out = Vec::new();
        assert!(shorten(&quiet, &mut out));
        assert_eq!(out.len(), FRAME_SAMPLES - MAX_LAG);
    }
}
