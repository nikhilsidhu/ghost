//! How much delay each sender's playout aims for. Too little and frames that arrive
//! late are lost; too much and the conversation lags. Measured against the alternative
//! of deepening at once on every late frame, this held equal or better audibility
//! under jitter, loss and spikes with up to 100 ms less delay.

use std::collections::VecDeque;
use std::time::Instant;

use crate::constants::*;

/// Arrivals the history keeps room for: twice what it holds on a steady network, so it
/// does not allocate on the playback thread it runs on.
const HISTORY_ROOM: usize = 2 * (QUANTILE_HISTORY.as_millis() as usize / FRAME_MS as usize);

/// A histogram that forgets: each new sample weighs `1 - forget` and every older one
/// fades by `forget`, starting fast so the first samples count fully.
struct ForgetfulHistogram {
    buckets: Vec<f64>,
    forget: f64,
    added: u32,
}

impl ForgetfulHistogram {
    fn new(buckets: usize, forget: f64) -> Self {
        Self { buckets: vec![0.0; buckets], forget, added: 0 }
    }

    fn add(&mut self, bucket: usize) {
        let forget = (1.0 - QUANTILE_START_WEIGHT / (self.added as f64 + 1.0)).clamp(0.0, self.forget);
        self.added += 1;
        for weight in &mut self.buckets {
            *weight *= forget;
        }
        let last = self.buckets.len() - 1;
        self.buckets[bucket.min(last)] += 1.0 - forget;
    }

    /// Smallest bucket at or below which `quantile` of the weight lies.
    fn quantile(&self, quantile: f64) -> usize {
        let total: f64 = self.buckets.iter().sum();
        let mut cumulative = 0.0;
        for (bucket, weight) in self.buckets.iter().enumerate() {
            cumulative += weight;
            if cumulative >= quantile * total {
                return bucket;
            }
        }
        self.buckets.len() - 1
    }

    /// Share of the weight above `bucket`.
    fn above(&self, bucket: usize) -> f64 {
        let total: f64 = self.buckets.iter().sum();
        if total <= 0.0 {
            return 0.0;
        }
        self.buckets.iter().skip(bucket + 1).sum::<f64>() / total
    }
}

/// WebRTC NetEQ's approach: the target covers the 95th percentile of how much later
/// than the earliest-arriving recent frame each frame arrived (measured per half
/// second, keeping the worst), and enough reordering that the delay saved is worth
/// the frames lost. Frames that come later still are waited for by playout.
pub(crate) struct TargetDelay {
    started: Instant,
    /// (media time, arrival time) of recent frames, in ms since `started`.
    history: VecDeque<(f64, f64)>,
    /// Highest sequence seen and its unwrapped value, for media time and reordering.
    highest: Option<(u32, i64)>,
    interval_start: f64,
    interval_worst: f64,
    underrun: ForgetfulHistogram,
    reorder: ForgetfulHistogram,
}

impl TargetDelay {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            history: VecDeque::with_capacity(HISTORY_ROOM),
            highest: None,
            interval_start: 0.0,
            interval_worst: 0.0,
            underrun: ForgetfulHistogram::new(QUANTILE_BUCKETS, QUANTILE_FORGET),
            reorder: ForgetfulHistogram::new(PLAYOUT_MAX_TARGET as usize + 1, QUANTILE_REORDER_FORGET),
        }
    }

    fn ms(&self, at: Instant) -> f64 {
        at.duration_since(self.started).as_secs_f64() * 1000.0
    }

    /// The target that keeps late-loss from reordering worth its delay.
    fn reorder_target(&self) -> u32 {
        (PLAYOUT_MIN_TARGET..=PLAYOUT_MAX_TARGET)
            .min_by(|&a, &b| {
                let cost = |frames: u32| {
                    frames as f64 * FRAME_MS as f64
                        + QUANTILE_MS_PER_LOSS_PERCENT * 100.0 * self.reorder.above(frames as usize - 1)
                };
                cost(a).total_cmp(&cost(b))
            })
            .unwrap_or(PLAYOUT_MIN_TARGET)
    }

    /// Take a frame's arrival into account.
    pub fn arrived(&mut self, sequence: u32, arrived: Instant) {
        let now = self.ms(arrived);
        let unwrapped = match self.highest {
            None => sequence as i64,
            Some((last, last_unwrapped)) => last_unwrapped + sequence.wrapping_sub(last) as i32 as i64,
        };
        let reordered_by = match self.highest {
            Some((_, highest)) if unwrapped < highest => (highest - unwrapped) as usize,
            _ => 0,
        };
        // The sender's clock runs on while it is silent, so frames it skipped mean a new
        // talk spurt: arrival delay is measured afresh from it. (A delay spike holds
        // frames back without skipping any, and is measured.)
        if self.highest.is_none_or(|(_, highest)| unwrapped - highest > PRE_ROLL_FRAMES as i64 + 1) {
            self.history.clear();
            self.interval_start = now;
            self.interval_worst = 0.0;
        }
        if self.highest.is_none_or(|(_, highest)| unwrapped > highest) {
            self.highest = Some((sequence, unwrapped));
        }
        self.reorder.add(reordered_by);

        let media = unwrapped as f64 * FRAME_MS as f64;
        self.history.push_back((media, now));
        while self.history.front().is_some_and(|&(_, at)| now - at > QUANTILE_HISTORY.as_secs_f64() * 1000.0) {
            self.history.pop_front();
        }
        let earliest = self.history.iter().map(|&(m, at)| at - m).fold(f64::INFINITY, f64::min);
        let relative_delay = (now - media - earliest).max(0.0);
        self.interval_worst = self.interval_worst.max(relative_delay);
        if now - self.interval_start >= QUANTILE_INTERVAL.as_secs_f64() * 1000.0 {
            self.underrun.add((self.interval_worst / FRAME_MS as f64) as usize);
            self.interval_start = now;
            self.interval_worst = 0.0;
        }
    }

    /// Target delay, in frames.
    pub fn target(&self) -> u32 {
        let underrun = if self.underrun.added == 0 {
            PLAYOUT_MIN_TARGET
        } else {
            1 + self.underrun.quantile(QUANTILE_LEVEL) as u32
        };
        underrun.max(self.reorder_target()).clamp(PLAYOUT_MIN_TARGET, PLAYOUT_MAX_TARGET)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Feed `count` frames at 20 ms spacing, each delayed by `delay(seq)` ms.
    fn feed(policy: &mut TargetDelay, start: Instant, count: u32, delay: impl Fn(u32) -> u64) {
        let mut arrivals: Vec<(Instant, u32)> =
            (0..count).map(|seq| (start + Duration::from_millis(seq as u64 * 20 + delay(seq)), seq)).collect();
        arrivals.sort();
        for (at, seq) in arrivals {
            policy.arrived(seq, at);
        }
    }

    #[test]
    fn stays_low_on_a_steady_network_and_covers_jitter() {
        let start = Instant::now();
        let mut steady = TargetDelay::new();
        feed(&mut steady, start, 500, |_| 5);
        assert_eq!(steady.target(), PLAYOUT_MIN_TARGET);

        let mut jittery = TargetDelay::new();
        feed(&mut jittery, start, 1500, |seq| (seq as u64 * 7919) % 61);
        let target = jittery.target();
        assert!((3..=5).contains(&target), "60 ms of jitter wants about 3-4 frames, got {target}");
    }

    #[test]
    fn a_pause_does_not_count_as_delay() {
        let start = Instant::now();
        let mut policy = TargetDelay::new();
        feed(&mut policy, start, 100, |_| 5);
        // Silent for 3 s (the sender's clock ran on), then speaking again on time.
        let resumed = start + Duration::from_secs(5);
        for seq in 250..400u32 {
            policy.arrived(seq, resumed + Duration::from_millis((seq - 250) as u64 * 20));
        }
        assert_eq!(policy.target(), PLAYOUT_MIN_TARGET);
    }

    #[test]
    fn frequent_spikes_are_covered() {
        let start = Instant::now();
        let mut policy = TargetDelay::new();
        // Every 2 s the network holds frames back for 200 ms.
        feed(&mut policy, start, 1000, |seq| {
            let into_cycle = (seq % 100) * 20;
            if into_cycle < 200 { (200 - into_cycle) as u64 } else { 0 }
        });
        assert!(policy.target() >= 8, "200 ms spikes in a quarter of intervals, target {}", policy.target());
    }
}
