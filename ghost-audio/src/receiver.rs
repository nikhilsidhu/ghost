//! One sender's playout: its frames buffered by sequence, decoded in turn into audio
//! for the mixer, with losses covered by Opus FEC or concealment, late frames waited
//! for, and the delay steered toward what its delay policy asks by stretching frames.

use std::collections::{BTreeMap, VecDeque};
use std::time::Instant;

use crate::constants::*;
use crate::policy::TargetDelay;
use crate::stretch;

/// What playout has done, for call quality and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlayoutStats {
    /// Frames played as sent.
    pub played: u64,
    /// Lost frames rebuilt from the next frame's FEC.
    pub recovered: u64,
    /// Lost frames concealed.
    pub concealed: u64,
    /// Frames of concealment while waiting for a late frame.
    pub waited: u64,
    /// Frames that came after their turn had passed, dropped.
    pub dropped_late: u64,
    /// Frames shortened or lengthened by a pitch period to steer delay.
    pub shortened: u64,
    pub lengthened: u64,
}

impl PlayoutStats {
    pub fn add(&mut self, other: &PlayoutStats) {
        self.played += other.played;
        self.recovered += other.recovered;
        self.concealed += other.concealed;
        self.waited += other.waited;
        self.dropped_late += other.dropped_late;
        self.shortened += other.shortened;
        self.lengthened += other.lengthened;
    }
}

/// Whether sequence `a` comes before `b`, across wraparound.
fn before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

pub(crate) struct Receiver {
    /// Opus frames by sequence. Ordered as plain integers: sequences wrap only after
    /// about 2.7 years of one call.
    frames: BTreeMap<u32, Vec<u8>>,
    decoder: opus::Decoder,
    /// The next sequence to play; `None` until playout starts, and again once the
    /// sender has paused.
    next: Option<u32>,
    /// Frames concealed in a row, and how many of those waited for `next`.
    concealed_run: u32,
    waited_run: u32,
    policy: TargetDelay,
    /// Decoded audio not yet mixed.
    pub(crate) output: VecDeque<f32>,
    /// The shallowest and deepest buffered depths this window and last.
    low_water: u32,
    last_low_water: u32,
    high_water: u32,
    last_high_water: u32,
    window_ticks: u32,
    cooldown: u32,
    pub(crate) stats: PlayoutStats,
    decoded: Vec<f32>,
    stretched: Vec<f32>,
}

impl Receiver {
    pub fn new() -> Result<Self, String> {
        let decoder = opus::Decoder::new(SAMPLE_RATE, opus::Channels::Mono).map_err(|e| format!("opus decoder: {e}"))?;
        Ok(Self {
            frames: BTreeMap::new(),
            decoder,
            next: None,
            concealed_run: 0,
            waited_run: 0,
            policy: TargetDelay::new(),
            output: VecDeque::with_capacity(FRAME_SAMPLES * 4),
            low_water: u32::MAX,
            last_low_water: u32::MAX,
            high_water: 0,
            last_high_water: 0,
            window_ticks: 0,
            cooldown: 0,
            stats: PlayoutStats::default(),
            decoded: vec![0.0; FRAME_SAMPLES],
            stretched: Vec::with_capacity(FRAME_SAMPLES * 2),
        })
    }

    pub fn insert(&mut self, sequence: u32, frame: Vec<u8>, arrived: Instant) {
        self.policy.arrived(sequence, arrived);
        if self.next.is_some_and(|next| before(sequence, next)) {
            self.stats.dropped_late += 1;
            return;
        }
        if self.frames.len() < PLAYOUT_MAX_BUFFERED {
            self.frames.insert(sequence, frame);
        }
    }

    /// Frames buffered from the next to play through the newest, gaps included.
    fn depth(&self) -> u32 {
        let (Some((&first, _)), Some((&last, _))) = (self.frames.first_key_value(), self.frames.last_key_value()) else {
            return 0;
        };
        last.wrapping_sub(self.next.unwrap_or(first)).wrapping_add(1)
    }

    pub fn target(&self) -> u32 {
        self.policy.target()
    }

    pub fn buffered(&self) -> u32 {
        self.depth()
    }

    /// Nothing to play and nothing coming: the sender is gone or long paused.
    pub fn is_idle(&self) -> bool {
        self.next.is_none() && self.frames.is_empty() && self.output.is_empty()
    }

    fn silence(&mut self) {
        self.output.extend(std::iter::repeat(0.0).take(FRAME_SAMPLES));
    }

    /// Decode the next frame's worth of audio onto `output`.
    pub fn produce(&mut self) {
        let next = match self.next {
            Some(next) => next,
            // Not playing: start once the target depth has gathered.
            None => match self.frames.first_key_value() {
                Some((&first, _)) if self.depth() >= self.policy.target() => first,
                _ => return self.silence(),
            },
        };
        let decoded = if let Some(frame) = self.frames.remove(&next) {
            self.next = Some(next.wrapping_add(1));
            self.concealed_run = 0;
            self.waited_run = 0;
            self.stats.played += 1;
            self.decoder.decode_float(&frame, &mut self.decoded, false)
        } else if self.frames.is_empty() {
            // Nothing buffered: the frame is late, or the sender went quiet. Conceal
            // and keep waiting for it, so a late frame still plays.
            self.next = Some(next);
            self.concealed_run += 1;
            self.waited_run += 1;
            self.stats.waited += 1;
            self.decoder.decode_float(&[], &mut self.decoded, false)
        } else if self.waited_run > 0 {
            // Frames came while waiting, but not the awaited one: it was lost, or never
            // sent because the sender paused. Its time is already concealed; resume
            // from the earliest frame.
            let (&first, _) = self.frames.first_key_value().expect("frames buffered");
            self.next = Some(first);
            self.waited_run = 0;
            return self.produce();
        } else {
            // A gap: this frame is lost. The next frame's FEC carries a rough copy.
            self.next = Some(next.wrapping_add(1));
            self.concealed_run += 1;
            match self.frames.get(&next.wrapping_add(1)) {
                Some(following) => {
                    self.stats.recovered += 1;
                    self.decoder.decode_float(following, &mut self.decoded, true)
                }
                None => {
                    self.stats.concealed += 1;
                    self.decoder.decode_float(&[], &mut self.decoded, false)
                }
            }
        };
        if decoded.is_err() {
            self.decoded.fill(0.0);
        }

        if self.concealed_run > PLAYOUT_MAX_CONCEALED {
            // Long silence from the sender: stop, and start afresh when it speaks again.
            self.next = None;
            self.concealed_run = 0;
            self.waited_run = 0;
            self.frames.clear();
            return self.silence();
        }
        self.steer();
    }

    /// Append the decoded frame, stretched when the delay strays from the target.
    fn steer(&mut self) {
        let depth = self.depth();
        self.low_water = self.low_water.min(depth);
        self.high_water = self.high_water.max(depth);
        self.window_ticks += 1;
        if self.window_ticks >= DEPTH_WINDOW {
            (self.last_low_water, self.last_high_water) = (self.low_water, self.high_water);
            (self.low_water, self.high_water) = (u32::MAX, 0);
            self.window_ticks = 0;
        }
        let target = self.policy.target();
        // Depths count frames after this one; this one plays now, so delay is one more.
        let least = self.low_water.min(self.last_low_water).saturating_add(1);
        let most = self.high_water.max(self.last_high_water) + 1;

        self.stretched.clear();
        let stretched = if self.cooldown > 0 || self.waited_run > 0 {
            false
        } else if least > target && least != u32::MAX {
            // Delay above the target has gone unused for a second: give it back.
            let shortened = stretch::shorten(&self.decoded, &mut self.stretched);
            self.stats.shortened += shortened as u64;
            shortened
        } else if most < target {
            // Even the deepest moment fell short: build delay up.
            let lengthened = stretch::lengthen(&self.decoded, &mut self.stretched);
            self.stats.lengthened += lengthened as u64;
            lengthened
        } else {
            false
        };
        if stretched {
            self.cooldown = STRETCH_COOLDOWN;
            self.output.extend(self.stretched.iter());
        } else {
            self.cooldown = self.cooldown.saturating_sub(1);
            self.output.extend(self.decoded.iter());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn frames(count: usize) -> Vec<Vec<u8>> {
        let mut encoder = opus::Encoder::new(SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip).unwrap();
        let tone: Vec<f32> = (0..FRAME_SAMPLES).map(|i| (i as f32 * 0.05).sin() * 0.3).collect();
        (0..count).map(|_| encoder.encode_vec_float(&tone, OPUS_MAX_FRAME_BYTES).unwrap()).collect()
    }

    fn receiver() -> Receiver {
        Receiver::new().unwrap()
    }

    #[test]
    fn starts_once_the_target_gathers_then_plays_in_order() {
        let mut receiver = receiver();
        let encoded = frames(3);
        let now = Instant::now();
        receiver.insert(10, encoded[0].clone(), now);
        receiver.produce();
        assert_eq!(receiver.stats.played, 0, "one frame is short of the target");
        receiver.insert(11, encoded[1].clone(), now);
        receiver.produce();
        assert_eq!(receiver.stats.played, 1);
        assert_eq!(receiver.frames.keys().copied().collect::<Vec<_>>(), vec![11]);
    }

    #[test]
    fn waits_for_a_late_frame_and_plays_it() {
        let mut receiver = receiver();
        let encoded = frames(4);
        let now = Instant::now();
        receiver.insert(0, encoded[0].clone(), now);
        receiver.insert(1, encoded[1].clone(), now);
        receiver.produce();
        receiver.produce();
        receiver.produce();
        assert_eq!(receiver.stats.waited, 1, "frame 2 is late");
        receiver.insert(2, encoded[2].clone(), now + Duration::from_millis(60));
        receiver.produce();
        assert_eq!((receiver.stats.played, receiver.stats.dropped_late), (3, 0), "the late frame still plays");
    }

    #[test]
    fn recovers_a_lost_frame_from_the_next_ones_fec() {
        let mut receiver = receiver();
        let encoded = frames(4);
        let now = Instant::now();
        for seq in [0, 2, 3] {
            receiver.insert(seq, encoded[seq as usize].clone(), now);
        }
        for _ in 0..4 {
            receiver.produce();
        }
        assert_eq!((receiver.stats.played, receiver.stats.recovered), (3, 1));
    }

    #[test]
    fn resumes_at_the_new_talk_spurt_after_a_pause() {
        let mut receiver = receiver();
        let encoded = frames(4);
        let now = Instant::now();
        receiver.insert(0, encoded[0].clone(), now);
        receiver.insert(1, encoded[1].clone(), now);
        for _ in 0..5 {
            receiver.produce();
        }
        // The sender's clock ran on through the pause; nothing between was sent.
        receiver.insert(40, encoded[2].clone(), now);
        receiver.insert(41, encoded[3].clone(), now);
        receiver.produce();
        assert_eq!(receiver.stats.played, 3, "playout jumped to the new spurt");
        assert_eq!(receiver.stats.concealed, 0, "without concealing the unsent frames");
    }

    #[test]
    fn stops_after_a_long_silence() {
        let mut receiver = receiver();
        let encoded = frames(2);
        receiver.insert(0, encoded[0].clone(), Instant::now());
        receiver.insert(1, encoded[1].clone(), Instant::now());
        for _ in 0..(2 + PLAYOUT_MAX_CONCEALED + 1) {
            receiver.produce();
        }
        assert!(receiver.next.is_none());
    }
}
