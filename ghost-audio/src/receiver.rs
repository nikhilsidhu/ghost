//! One sender's playout: its frames buffered by sequence, decoded in turn into audio
//! for the mixer, with losses rebuilt from Opus FEC or DRED or else concealed, late frames
//! waited for, and the delay steered toward what its delay policy asks by stretching frames.
//! It runs on the device's playback thread, so it never allocates or frees: room is
//! reserved up front, and frames it is done with are handed back to be freed elsewhere.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::codec::{self, Decoder, Dred, DredReach, OpusError};
use crate::constants::*;
use crate::policy::TargetDelay;
use crate::stretch;

/// What playout has done, for call quality and tests. Every count only grows, so an
/// earlier reading can be taken from a later one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlayoutStats {
    /// Frames played as sent.
    pub played: u64,
    /// Lost frames rebuilt from the next frame's FEC or a later frame's DRED.
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

/// How far back, up to `limit` frames before `packet`, it can rebuild a frame: the one
/// just before from its FEC copy or its DRED, older ones from its DRED, which this parses
/// into `dred` (only finding its reach if `defer`). DRED can leave out the last moments
/// before its packet, so a nearer frame it misses, with no FEC copy, is concealed.
fn rebuildable(dred: &mut Dred, packet: &[u8], limit: u32, defer: bool) -> (u32, Option<DredReach>) {
    if limit == 0 {
        return (0, None);
    }
    let reach = dred.parse(packet, limit as usize * FRAME_SAMPLES + DRED_PARSE_MARGIN, defer).ok();
    let fec = codec::has_fec(packet);
    let furthest = (1..=limit)
        .rev()
        .find(|&back| (back == 1 && fec) || reach.is_some_and(|reach| reach.covers(back as usize * FRAME_SAMPLES, FRAME_SAMPLES)))
        .unwrap_or(0);
    (furthest, reach)
}

pub(crate) struct Receiver {
    /// Opus frames, sorted by sequence. Ordered as plain integers: sequences wrap only
    /// after about 2.7 years of one call.
    frames: Vec<(u32, Vec<u8>)>,
    decoder: Decoder,
    /// The DRED of the first frame after a gap, parsed for rebuilding the frames lost
    /// before it, and which frame that is and how far back it reaches.
    dred: Dred,
    dred_from: Option<(u32, DredReach)>,
    /// For finding, as a frame arrives, how much of a gap before it its DRED reaches;
    /// apart from `dred`, which playout may be part way through.
    probe: Dred,
    /// Whether concealment runs Deep PLC now.
    deep_plc: bool,
    /// The newest frame that arrived, and whether it closed a talk spurt.
    newest: Option<(u32, bool)>,
    /// Whether the frame played last closed a talk spurt.
    played_closed: bool,
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
        let decoder = Decoder::new().map_err(|e| format!("opus decoder: {e}"))?;
        Ok(Self {
            frames: Vec::with_capacity(PLAYOUT_MAX_BUFFERED),
            decoder,
            dred: Dred::new().map_err(|e| format!("opus dred: {e}"))?,
            dred_from: None,
            probe: Dred::new().map_err(|e| format!("opus dred: {e}"))?,
            deep_plc: false,
            newest: None,
            played_closed: false,
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
        // Frames lost just before this one that it can rebuild count as arriving with it,
        // so a burst it covers deepens the target as late frames would (NetEQ adapts its
        // delay to recovered frames the same way).
        for back in (1..=self.rebuildable_on_arrival(sequence, &frame)).rev() {
            self.policy.arrived(sequence.wrapping_sub(back), arrived);
        }
        self.policy.arrived(sequence, arrived);
        if self.newest.is_none_or(|(newest, _)| before(newest, sequence)) {
            self.newest = Some((sequence, frame == OPUS_SILENCE));
        }
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

    /// How far back into the frames lost just before `sequence`, newer than any that
    /// arrived, `frame` can rebuild. None after a pause, which the sender closes with
    /// silence: its DRED would only bring back that silence.
    fn rebuildable_on_arrival(&mut self, sequence: u32, frame: &[u8]) -> u32 {
        let Some((newest, false)) = self.newest else { return 0 };
        if !before(newest, sequence) {
            return 0;
        }
        let lost = sequence.wrapping_sub(newest) - 1;
        rebuildable(&mut self.probe, frame, lost.min(PLAYOUT_MAX_TARGET), true).0
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

    /// Rebuild lost frame `sequence` from the first frame buffered after it: from its FEC
    /// copy if it is the next frame and carries one (Opus's own copy beats DRED's), else
    /// from its DRED if that reaches back far enough.
    fn rebuild(&mut self, sequence: u32) -> Option<Result<usize, OpusError>> {
        let (carrier, packet) = self.frames.iter().find(|(seq, _)| before(sequence, *seq))?;
        let back = carrier.wrapping_sub(sequence) as usize;
        if back == 1 && codec::has_fec(packet) {
            return Some(self.decoder.decode_float(packet, &mut self.decoded, true));
        }
        if self.dred_from.is_none_or(|(from, _)| from != *carrier) {
            let reach = self.dred.parse(packet, back * FRAME_SAMPLES + DRED_PARSE_MARGIN, false).ok()?;
            self.dred_from = Some((*carrier, reach));
        }
        let (_, reach) = self.dred_from?;
        let offset = back * FRAME_SAMPLES;
        reach.covers(offset, FRAME_SAMPLES).then(|| self.decoder.decode_dred(&self.dred, offset, &mut self.decoded))
    }

    /// Conceal a lost frame: with Deep PLC under heavy loss, else libopus's own way.
    fn conceal(&mut self) -> Result<usize, OpusError> {
        let deep = self.loss_rate >= DEEP_PLC_LOSS_RATE;
        if deep != self.deep_plc && self.decoder.set_complexity(if deep { DEEP_PLC_COMPLEXITY } else { 0 }).is_ok() {
            self.deep_plc = deep;
        }
        self.decoder.decode_float(&[], &mut self.decoded, false)
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
            self.played_closed = frame == OPUS_SILENCE;
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
            self.conceal()
        } else if self.waited_run > 0 {
            // Frames came while waiting, but not the awaited one: it was lost, or never
            // sent because the sender paused, which it does only after closing the talk
            // spurt with silence. Its time is already concealed. Lost frames the first
            // to arrive can rebuild play now, late, as NetEQ plays DRED, rather than be
            // passed over: the delay grows by what was concealed. The rest are passed over.
            let first = self.first().expect("frames buffered");
            let skipped = first.wrapping_sub(next);
            let mut waited = u64::from(self.waited_run);
            let mut replay = 0;
            if !self.played_closed {
                let buffered = self.frames.last().map_or(0, |(last, _)| last.wrapping_sub(first) + 1);
                let room = PLAYOUT_MAX_TARGET.saturating_sub(buffered);
                let (rebuilt, reach) = rebuildable(&mut self.dred, &self.frames[0].1, skipped.min(room), false);
                self.dred_from = reach.map(|reach| (first, reach));
                replay = rebuilt;
                let lost = (skipped - replay).min(self.waited_run) as u64;
                waited -= lost;
                self.stats.concealed += lost;
                self.note_lost(lost);
            }
            self.stats.waited += waited;
            self.next = Some(first.wrapping_sub(replay));
            self.waited_run = 0;
            self.catch_up_from(self.target());
            return self.produce();
        } else {
            // A gap: this frame is lost. Rebuild it from the next frame's FEC copy or from
            // the DRED of the first frame after the gap; failing both, conceal it.
            self.next = Some(next.wrapping_add(1));
            self.note_lost(1);
            match self.rebuild(next) {
                // The sender's own audio, so not a sign it went quiet.
                Some(rebuilt) => {
                    self.stats.recovered += 1;
                    self.concealed_run = 0;
                    rebuilt
                }
                None => {
                    self.stats.concealed += 1;
                    self.concealed_run += 1;
                    self.conceal()
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
        let mut encoder = crate::codec::Encoder::voip().unwrap();
        let tone: Vec<f32> = (0..FRAME_SAMPLES).map(|i| (i as f32 * 0.05).sin() * amplitude).collect();
        (0..count).map(|_| encoder.encode_vec_float(&tone)).collect()
    }

    fn frames(count: usize) -> Vec<Vec<u8>> {
        encode(count, 0.3)
    }

    /// The synthetic voice as a sender protecting against `loss` percent codes it, with
    /// DRED when `dred`. Opus codes FEC copies only for frames it takes for speech.
    fn speech(seconds: f32, loss: i32, dred: bool) -> Vec<Vec<u8>> {
        let mut encoder = crate::codec::Encoder::voip().unwrap();
        encoder.set_bitrate(OPUS_BITRATE).unwrap();
        encoder.set_voice_signal().unwrap();
        encoder.set_inband_fec(true).unwrap();
        encoder.set_packet_loss_perc(loss).unwrap();
        encoder.set_dred_duration(if dred { DRED_DURATION } else { 0 }).unwrap();
        crate::fake::speech_like(seconds, 0.03).chunks_exact(FRAME_SAMPLES).map(|frame| encoder.encode_vec_float(frame)).collect()
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
        let encoded = speech(1.0, 20, false);
        let lost = (10..encoded.len() - 2).find(|&n| codec::has_fec(&encoded[n + 1])).expect("a frame with an FEC copy");
        let now = Instant::now();
        for seq in [lost - 2, lost - 1, lost + 1, lost + 2] {
            receiver.insert(seq as u32, encoded[seq].clone(), now);
        }
        for _ in 0..4 {
            receiver.produce();
        }
        assert_eq!((receiver.stats.played, receiver.stats.recovered, receiver.stats.concealed), (3, 1, 0));
    }

    #[test]
    fn a_lost_frame_with_no_fec_copy_in_reach_is_rebuilt_from_dred() {
        let mut receiver = receiver();
        let encoded = speech(1.0, 20, true);
        // Two lost in a row: the second's FEC copy arrives, the first has none in reach.
        let lost = (20..encoded.len() - 3).find(|&n| codec::has_fec(&encoded[n + 2])).expect("a frame with an FEC copy");
        let now = Instant::now();
        for seq in [lost - 2, lost - 1, lost + 2, lost + 3] {
            receiver.insert(seq as u32, encoded[seq].clone(), now);
        }
        for _ in 0..5 {
            receiver.produce();
        }
        assert_eq!((receiver.stats.played, receiver.stats.recovered, receiver.stats.concealed), (3, 2, 0));
    }

    #[test]
    fn a_burst_concealed_while_waiting_plays_late_from_dred() {
        let mut receiver = receiver();
        let encoded = speech(1.0, 20, true);
        let burst = (20..encoded.len() - 4).find(|&n| codec::has_fec(&encoded[n + 3])).expect("a frame with an FEC copy");
        let now = Instant::now();
        receiver.insert(burst as u32 - 2, encoded[burst - 2].clone(), now);
        receiver.insert(burst as u32 - 1, encoded[burst - 1].clone(), now);
        for _ in 0..4 {
            receiver.produce();
        }
        assert_eq!(receiver.waited_run, 2, "the burst's first frame is waited for");
        // Its three frames never come; the next does, and its DRED reaches back over them.
        receiver.insert(burst as u32 + 3, encoded[burst + 3].clone(), now);
        for _ in 0..4 {
            receiver.produce();
        }
        assert_eq!(receiver.stats.recovered, 3, "the burst plays, late, rather than being passed over");
        assert_eq!((receiver.stats.played, receiver.stats.waited, receiver.stats.concealed), (3, 2, 0));
    }

    #[test]
    fn bursts_dred_covers_deepen_the_target() {
        // Three lost in every 25 (a half second): with DRED the burst's frames count as
        // arriving with the frame after it, up to three frames late; with FEC alone only
        // the last of them does, one frame late.
        let target = |dred: bool| {
            let mut receiver = receiver();
            let encoded = speech(8.0, 20, dred);
            let start = Instant::now();
            for (seq, frame) in encoded.into_iter().enumerate() {
                if seq % 25 < 22 {
                    receiver.insert(seq as u32, frame, start + Duration::from_millis(seq as u64 * FRAME_MS as u64));
                }
                receiver.produce();
            }
            receiver.target()
        };
        let (with_fec, with_dred) = (target(false), target(true));
        assert_eq!(with_fec, PLAYOUT_MIN_TARGET + 1, "FEC alone: the extra frame kept while losing");
        assert!(with_dred > with_fec, "DRED-covered bursts deepen the target: {with_dred} frames, {with_fec} with FEC alone");
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
        let encoded = speech(1.0, 20, true);
        let now = Instant::now();
        receiver.insert(0, encoded[0].clone(), now);
        receiver.insert(1, encoded[1].clone(), now);
        // The talk spurt closes with silence before the pause.
        for seq in 2..2 + SILENCE_FRAME_COUNT as u32 {
            receiver.insert(seq, OPUS_SILENCE.to_vec(), now);
        }
        for _ in 0..7 {
            receiver.produce();
        }
        // The sender's clock ran on through the pause; nothing between was sent. The new
        // spurt's DRED reaches back into the pause, which is not played.
        receiver.insert(40, encoded[40].clone(), now);
        receiver.insert(41, encoded[41].clone(), now);
        receiver.produce();
        assert_eq!(receiver.stats.played, 6, "playout jumped to the new spurt");
        assert_eq!((receiver.stats.recovered, receiver.stats.concealed), (0, 0), "without rebuilding or concealing the unsent frames");
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
