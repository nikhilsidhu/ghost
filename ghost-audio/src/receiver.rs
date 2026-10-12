//! One sender's playout: its frames buffered by sequence, decoded in turn into audio
//! for the mixer, with losses covered by Opus FEC or concealment, late frames waited
//! for, and the delay steered toward what its delay policy asks by stretching frames.
//! It runs on the device's playback thread, so it never allocates or frees: room is
//! reserved up front, and frames it is done with are handed back to be freed elsewhere.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::constants::*;
use crate::policy::TargetDelay;
use crate::stretch;

/// What playout has done, for call quality and tests. Every count only grows, so an
/// earlier reading can be taken from a later one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlayoutStats {
    /// Frames played as sent.
    pub played: u64,
    /// Lost frames rebuilt from the next frame's FEC.
    pub recovered: u64,
    /// Lost frames concealed.
    pub concealed: u64,
    /// Frames concealed while waiting for a frame that came late or was never sent.
    pub waited: u64,
    /// Frames that came after their turn had passed, dropped.
    pub dropped_late: u64,
    /// Frames shortened or lengthened by a pitch period to steer delay.
    pub shortened: u64,
    pub lengthened: u64,
}

impl PlayoutStats {
    /// What was counted since `earlier`, an earlier copy of these counts.
    pub fn since(&self, earlier: &PlayoutStats) -> PlayoutStats {
        PlayoutStats {
            played: self.played - earlier.played,
            recovered: self.recovered - earlier.recovered,
            concealed: self.concealed - earlier.concealed,
            waited: self.waited - earlier.waited,
            dropped_late: self.dropped_late - earlier.dropped_late,
            shortened: self.shortened - earlier.shortened,
            lengthened: self.lengthened - earlier.lengthened,
        }
    }

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

/// A sender's playout as playback last published it, read by the audio thread without
/// either waiting on the other.
#[derive(Default)]
pub(crate) struct PeerStats {
    played: AtomicU64,
    recovered: AtomicU64,
    concealed: AtomicU64,
    waited: AtomicU64,
    dropped_late: AtomicU64,
    shortened: AtomicU64,
    lengthened: AtomicU64,
    depth: AtomicU32,
    target: AtomicU32,
    idle: AtomicBool,
    #[cfg(feature = "devtools")]
    received_frames: AtomicU64,
    #[cfg(feature = "devtools")]
    received_bytes: AtomicU64,
}

impl PeerStats {
    pub fn playout(&self) -> PlayoutStats {
        PlayoutStats {
            played: self.played.load(Ordering::Relaxed),
            recovered: self.recovered.load(Ordering::Relaxed),
            concealed: self.concealed.load(Ordering::Relaxed),
            waited: self.waited.load(Ordering::Relaxed),
            dropped_late: self.dropped_late.load(Ordering::Relaxed),
            shortened: self.shortened.load(Ordering::Relaxed),
            lengthened: self.lengthened.load(Ordering::Relaxed),
        }
    }

    pub fn depth(&self) -> u32 {
        self.depth.load(Ordering::Relaxed)
    }

    pub fn target(&self) -> u32 {
        self.target.load(Ordering::Relaxed)
    }

    /// Nothing to play and nothing coming: the sender is silent.
    pub fn is_idle(&self) -> bool {
        self.idle.load(Ordering::Relaxed)
    }

    /// Frames that arrived, late ones included, and their encoded size.
    #[cfg(feature = "devtools")]
    pub fn received(&self) -> (u64, u64) {
        (self.received_frames.load(Ordering::Relaxed), self.received_bytes.load(Ordering::Relaxed))
    }

    #[cfg(test)]
    pub fn set_playout(&self, stats: PlayoutStats) {
        self.played.store(stats.played, Ordering::Relaxed);
        self.recovered.store(stats.recovered, Ordering::Relaxed);
        self.concealed.store(stats.concealed, Ordering::Relaxed);
        self.waited.store(stats.waited, Ordering::Relaxed);
        self.dropped_late.store(stats.dropped_late, Ordering::Relaxed);
        self.shortened.store(stats.shortened, Ordering::Relaxed);
        self.lengthened.store(stats.lengthened, Ordering::Relaxed);
    }
}

/// Whether sequence `a` comes before `b`, across wraparound.
fn before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

pub(crate) struct Receiver {
    /// Opus frames, sorted by sequence. Ordered as plain integers: sequences wrap only
    /// after about 2.7 years of one call.
    frames: Vec<(u32, Vec<u8>)>,
    decoder: opus::Decoder,
    /// The next sequence to play; `None` until playout starts, and again once the
    /// sender has paused.
    next: Option<u32>,
    /// Frames concealed in a row, and how many of those waited for `next`; the waited
    /// ones are counted when the wait ends, as waiting or as loss.
    concealed_run: u32,
    waited_run: u32,
    policy: TargetDelay,
    /// Decoded audio not yet mixed.
    pub(crate) output: VecDeque<f32>,
    /// Frames played or dropped, for playback to hand back to be freed.
    pub(crate) spent: Vec<Vec<u8>>,
    /// The shallowest and deepest buffered depths this window and last.
    low_water: u32,
    last_low_water: u32,
    high_water: u32,
    last_high_water: u32,
    window_ticks: u32,
    cooldown: u32,
    /// Samples still to take out quickly: playout started (or resumed) with more
    /// buffered than its target, as when a talk spurt's pre-roll arrives all at once.
    catch_up: usize,
    /// The share of frames lost lately, by a moving average over frames.
    loss_rate: f32,
    /// Over the receiver's life.
    stats: PlayoutStats,
    /// Frames that arrived, late ones included, and their encoded size.
    #[cfg(feature = "devtools")]
    received: (u64, u64),
    shared: Arc<PeerStats>,
    decoded: Vec<f32>,
    stretched: Vec<f32>,
}

impl Receiver {
    /// A playout publishing its figures to `shared`.
    pub fn new(shared: Arc<PeerStats>) -> Result<Self, String> {
        let decoder = opus::Decoder::new(SAMPLE_RATE, opus::Channels::Mono).map_err(|e| format!("opus decoder: {e}"))?;
        Ok(Self {
            frames: Vec::with_capacity(PLAYOUT_MAX_BUFFERED),
            decoder,
            next: None,
            concealed_run: 0,
            waited_run: 0,
            policy: TargetDelay::new(),
            output: VecDeque::with_capacity(PLAYOUT_OUTPUT_ROOM),
            // Each frame is spent once; room for a full buffer cleared plus a few played.
            spent: Vec::with_capacity(PLAYOUT_MAX_BUFFERED * 2),
            low_water: u32::MAX,
            last_low_water: u32::MAX,
            high_water: 0,
            last_high_water: 0,
            window_ticks: 0,
            cooldown: 0,
            catch_up: 0,
            loss_rate: 0.0,
            stats: PlayoutStats::default(),
            #[cfg(feature = "devtools")]
            received: (0, 0),
            shared,
            decoded: vec![0.0; FRAME_SAMPLES],
            stretched: Vec::with_capacity(FRAME_SAMPLES * 2),
        })
    }

    /// Buffer a frame. Returns it when it is not kept (late, a duplicate's older copy,
    /// or the buffer is full), for the caller to hand back.
    pub fn insert(&mut self, sequence: u32, frame: Vec<u8>, arrived: Instant) -> Option<Vec<u8>> {
        #[cfg(feature = "devtools")]
        {
            self.received.0 += 1;
            self.received.1 += frame.len() as u64;
        }
        self.policy.arrived(sequence, arrived);
        if self.next.is_some_and(|next| before(sequence, next)) {
            self.stats.dropped_late += 1;
            self.note_lost(1);
            return Some(frame);
        }
        if self.frames.len() >= PLAYOUT_MAX_BUFFERED {
            return Some(frame);
        }
        match self.frames.binary_search_by_key(&sequence, |(seq, _)| *seq) {
            Ok(at) => Some(std::mem::replace(&mut self.frames[at].1, frame)),
            Err(at) => {
                self.frames.insert(at, (sequence, frame));
                None
            }
        }
    }

    fn first(&self) -> Option<u32> {
        self.frames.first().map(|(seq, _)| *seq)
    }

    fn position(&self, sequence: u32) -> Option<usize> {
        self.frames.binary_search_by_key(&sequence, |(seq, _)| *seq).ok()
    }

    fn take(&mut self, sequence: u32) -> Option<Vec<u8>> {
        let at = self.position(sequence)?;
        Some(self.frames.remove(at).1)
    }

    /// Frames buffered from the next to play through the newest, gaps included.
    fn depth(&self) -> u32 {
        let (Some((first, _)), Some((last, _))) = (self.frames.first(), self.frames.last()) else {
            return 0;
        };
        last.wrapping_sub(self.next.unwrap_or(*first)).wrapping_add(1)
    }

    /// The delay playout aims for, in frames: what the delay policy asks, and a frame
    /// more while frames are being lost, so the next one's FEC is at hand.
    pub fn target(&self) -> u32 {
        let target = self.policy.target();
        if self.loss_rate >= FEC_LOSS_RATE { target.max(PLAYOUT_MIN_TARGET + 1) } else { target }
    }

    fn note_played(&mut self) {
        self.loss_rate *= 1.0 - LOSS_RATE_WEIGHT;
    }

    fn note_lost(&mut self, frames: u64) {
        for _ in 0..frames {
            self.loss_rate += LOSS_RATE_WEIGHT * (1.0 - self.loss_rate);
        }
    }

    /// Nothing to play and nothing coming: the sender is gone or long paused.
    pub fn is_idle(&self) -> bool {
        self.next.is_none() && self.frames.is_empty() && self.output.is_empty()
    }

    /// Make the figures current for the audio thread.
    pub fn publish(&self) {
        let shared = &self.shared;
        shared.played.store(self.stats.played, Ordering::Relaxed);
        shared.recovered.store(self.stats.recovered, Ordering::Relaxed);
        shared.concealed.store(self.stats.concealed, Ordering::Relaxed);
        shared.waited.store(self.stats.waited, Ordering::Relaxed);
        shared.dropped_late.store(self.stats.dropped_late, Ordering::Relaxed);
        shared.shortened.store(self.stats.shortened, Ordering::Relaxed);
        shared.lengthened.store(self.stats.lengthened, Ordering::Relaxed);
        shared.depth.store(self.depth(), Ordering::Relaxed);
        shared.target.store(self.target(), Ordering::Relaxed);
        shared.idle.store(self.is_idle(), Ordering::Relaxed);
        #[cfg(feature = "devtools")]
        {
            shared.received_frames.store(self.received.0, Ordering::Relaxed);
            shared.received_bytes.store(self.received.1, Ordering::Relaxed);
        }
    }

    fn silence(&mut self) {
        self.output.extend(std::iter::repeat(0.0).take(FRAME_SAMPLES));
    }

    /// Playout (re)starts at `next` with more buffered than its target: the surplus is
    /// played off quickly instead of carried as delay.
    fn catch_up_from(&mut self, target: u32) {
        self.catch_up = self.depth().saturating_sub(target) as usize * FRAME_SAMPLES;
    }

    /// Decode the next frame's worth of audio onto `output`.
    pub fn produce(&mut self) {
        let next = match self.next {
            Some(next) => next,
            // Not playing: start once the target depth has gathered.
            None => {
                let target = self.target();
                match self.first() {
                    Some(first) if self.depth() >= target => {
                        self.catch_up_from(target);
                        first
                    }
                    _ => return self.silence(),
                }
            }
        };
        let decoded = if let Some(frame) = self.take(next) {
            self.next = Some(next.wrapping_add(1));
            self.concealed_run = 0;
            self.stats.waited += u64::from(self.waited_run);
            self.waited_run = 0;
            self.stats.played += 1;
            self.note_played();
            let decoded = self.decoder.decode_float(&frame, &mut self.decoded, false);
            self.spent.push(frame);
            decoded
        } else if self.frames.is_empty() {
            // Nothing buffered: the frame is late, or the sender went quiet. Conceal
            // and keep waiting for it, so a late frame still plays.
            self.next = Some(next);
            self.concealed_run += 1;
            self.waited_run += 1;
            self.catch_up = 0;
            self.decoder.decode_float(&[], &mut self.decoded, false)
        } else if self.waited_run > 0 {
            // Frames came while waiting, but not the awaited one: it was lost, or never
            // sent because the sender paused. Its time is already concealed; resume
            // from the earliest frame.
            let first = self.first().expect("frames buffered");
            // A pause leaves a gap longer than the pre-roll, which fills any shorter
            // one: a shorter gap is frames lost, concealed while they were waited for.
            let skipped = first.wrapping_sub(next);
            let mut waited = u64::from(self.waited_run);
            if skipped as usize <= PRE_ROLL_FRAMES {
                let lost = skipped.min(self.waited_run) as u64;
                waited -= lost;
                self.stats.concealed += lost;
                self.note_lost(lost);
            }
            self.stats.waited += waited;
            self.next = Some(first);
            self.waited_run = 0;
            self.catch_up_from(self.target());
            return self.produce();
        } else {
            // A gap: this frame is lost. The next frame's FEC carries a rough copy.
            self.next = Some(next.wrapping_add(1));
            self.concealed_run += 1;
            self.note_lost(1);
            match self.position(next.wrapping_add(1)) {
                Some(following) => {
                    self.stats.recovered += 1;
                    self.decoder.decode_float(&self.frames[following].1, &mut self.decoded, true)
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
            self.stats.waited += u64::from(self.waited_run);
            self.waited_run = 0;
            self.spent.extend(self.frames.drain(..).map(|(_, frame)| frame));
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
        let target = self.target();
        // Depths count frames after this one; this one plays now, so delay is one more.
        let least = self.low_water.min(self.last_low_water).saturating_add(1);
        let most = self.high_water.max(self.last_high_water) + 1;

        self.stretched.clear();
        let stretched = if self.catch_up > 0 {
            // A surplus known to be no cushion against jitter: shorten every frame that
            // allows it, without waiting out a window or a cooldown.
            let shortened = stretch::shorten(&self.decoded, &mut self.stretched);
            if shortened {
                self.catch_up = self.catch_up.saturating_sub(self.decoded.len() - self.stretched.len());
                self.stats.shortened += 1;
            }
            shortened
        } else if self.cooldown > 0 || self.waited_run > 0 {
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

    fn encode(count: usize, amplitude: f32) -> Vec<Vec<u8>> {
        let mut encoder = opus::Encoder::new(SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip).unwrap();
        let tone: Vec<f32> = (0..FRAME_SAMPLES).map(|i| (i as f32 * 0.05).sin() * amplitude).collect();
        (0..count).map(|_| encoder.encode_vec_float(&tone, OPUS_MAX_FRAME_BYTES).unwrap()).collect()
    }

    fn frames(count: usize) -> Vec<Vec<u8>> {
        encode(count, 0.3)
    }

    fn receiver() -> Receiver {
        Receiver::new(Arc::default()).unwrap()
    }

    fn buffered(receiver: &Receiver) -> Vec<u32> {
        receiver.frames.iter().map(|(seq, _)| *seq).collect()
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
        assert_eq!(buffered(&receiver), vec![11]);
    }

    #[test]
    fn frames_are_kept_in_sequence_and_handed_back_when_not_kept() {
        let mut receiver = receiver();
        let encoded = frames(4);
        let now = Instant::now();
        for seq in [12, 10, 11] {
            assert!(receiver.insert(seq, encoded[0].clone(), now).is_none());
        }
        assert_eq!(buffered(&receiver), vec![10, 11, 12]);
        assert_eq!(receiver.insert(11, encoded[1].clone(), now), Some(encoded[0].clone()), "a duplicate replaces the older copy");
        receiver.produce();
        assert_eq!(receiver.spent.len(), 1, "the played frame waits to be freed elsewhere");
        assert!(receiver.insert(5, encoded[2].clone(), now).is_some(), "a frame past its turn comes back");
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
        assert_eq!(receiver.waited_run, 1, "frame 2 is late");
        receiver.insert(2, encoded[2].clone(), now + Duration::from_millis(60));
        receiver.produce();
        assert_eq!((receiver.stats.played, receiver.stats.dropped_late), (3, 0), "the late frame still plays");
        assert_eq!(receiver.stats.waited, 1, "a wait for a late frame");
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
    fn while_frames_are_lost_playout_keeps_one_more_for_their_fec() {
        let mut receiver = receiver();
        let encoded = frames(1).remove(0);
        let now = Instant::now();
        let mut sequence = 0u32;
        let mut feed = |receiver: &mut Receiver, count: u32, lose_every: u32| {
            for _ in 0..count {
                if lose_every == 0 || sequence % lose_every != 0 {
                    receiver.insert(sequence, encoded.clone(), now);
                }
                sequence += 1;
                // Two buffered, so a lost frame has the next one at hand.
                if receiver.frames.len() >= 2 {
                    receiver.produce();
                }
            }
        };
        feed(&mut receiver, 200, 0);
        assert_eq!(receiver.target(), PLAYOUT_MIN_TARGET, "a clean stream keeps the least delay");
        feed(&mut receiver, 200, 10);
        assert_eq!(receiver.target(), PLAYOUT_MIN_TARGET + 1, "one frame in ten lost");
        feed(&mut receiver, 600, 0);
        assert_eq!(receiver.target(), PLAYOUT_MIN_TARGET, "the extra frame goes once the loss stops");
    }

    #[test]
    fn a_frame_lost_while_playout_waited_for_it_counts_as_lost() {
        let mut receiver = receiver();
        let encoded = frames(5);
        let now = Instant::now();
        receiver.insert(0, encoded[0].clone(), now);
        receiver.insert(1, encoded[1].clone(), now);
        for _ in 0..3 {
            receiver.produce();
        }
        assert_eq!(receiver.waited_run, 1, "frame 2 is waited for");
        // A quality reading falls mid-wait.
        let read = receiver.stats;
        // Frame 2 never comes; 3 does.
        receiver.insert(3, encoded[3].clone(), now);
        receiver.produce();
        assert_eq!((receiver.stats.waited, receiver.stats.concealed), (0, 1), "the wait was a loss");
        let since = receiver.stats.since(&read);
        assert_eq!((since.played, since.concealed, since.waited), (1, 1, 0), "the next reading counts on from it");
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

    #[test]
    fn a_talk_spurt_that_starts_in_a_burst_catches_up_to_its_target() {
        // The pre-roll arrives with the frame that set it off: four frames where the
        // target is two. They are quiet (the speaker had not yet been heard).
        let mut receiver = receiver();
        let now = Instant::now();
        for (seq, frame) in encode(4, 0.001).into_iter().enumerate() {
            receiver.insert(seq as u32, frame, now);
        }
        for _ in 0..4 {
            receiver.produce();
        }
        assert_eq!(receiver.output.len(), 2 * FRAME_SAMPLES, "two frames of surplus taken out over the four");
        assert_eq!(receiver.catch_up, 0);
    }

    #[test]
    fn a_spurt_that_gathers_at_its_pace_plays_unshortened() {
        let mut receiver = receiver();
        let now = Instant::now();
        let encoded = encode(4, 0.001);
        receiver.insert(0, encoded[0].clone(), now);
        receiver.insert(1, encoded[1].clone(), now);
        receiver.produce();
        receiver.insert(2, encoded[2].clone(), now);
        receiver.produce();
        assert_eq!(receiver.output.len(), 2 * FRAME_SAMPLES);
        assert_eq!(receiver.stats.shortened, 0);
    }
}
