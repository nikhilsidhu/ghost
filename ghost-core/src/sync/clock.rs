//! A hybrid logical clock for sync writes: physical milliseconds in the high 48 bits, a
//! counter in the low 16. Every write is stamped past everything the device has seen,
//! so a device with a slow clock cannot have its writes lost to older ones, and a fast
//! clock is clamped so it cannot freeze the map for everyone.

/// How far ahead of this device's wall clock another device's clock may read.
pub const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;

const COUNTER_BITS: u32 = 16;

/// Physical milliseconds of a clock value.
pub fn millis_of(clock: u64) -> u64 {
    clock >> COUNTER_BITS
}

/// A clock value whose physical part is `millis`, at the lowest counter.
pub fn from_millis(millis: u64) -> u64 {
    millis << COUNTER_BITS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HybridClock {
    last: u64,
}

impl HybridClock {
    /// Resume from the last value this device issued or observed.
    pub fn new(last: u64) -> Self {
        Self { last }
    }

    pub fn last(&self) -> u64 {
        self.last
    }

    /// A value for a write this device makes now: past its wall clock and past anything
    /// it has seen.
    pub fn tick(&mut self, now_ms: u64) -> u64 {
        self.last = from_millis(now_ms).max(self.last + 1);
        self.last
    }

    /// Take in a clock another device wrote, so later writes here are ordered after it.
    /// Returns the value as stored, clamped to this device's time plus the allowed skew.
    pub fn observe(&mut self, clock: u64, now_ms: u64) -> u64 {
        let clock = clamp(clock, now_ms);
        self.last = self.last.max(clock);
        clock
    }
}

/// `clock`, or the greatest value this device accepts from another, whichever is less.
pub fn clamp(clock: u64, now_ms: u64) -> u64 {
    clock.min(from_millis(now_ms + MAX_CLOCK_SKEW_MS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_are_strictly_increasing_whatever_the_wall_clock_does() {
        let mut clock = HybridClock::new(0);
        let first = clock.tick(1_000);
        let same_ms = clock.tick(1_000);
        let backwards = clock.tick(500);
        assert!(first < same_ms && same_ms < backwards);
        assert_eq!(millis_of(backwards), 1_000, "the physical part never goes back");
    }

    #[test]
    fn a_write_after_observing_a_later_clock_orders_after_it() {
        let mut clock = HybridClock::new(0);
        let seen = from_millis(10_000);
        clock.observe(seen, 2_000);
        assert!(clock.tick(2_000) > seen);
    }

    #[test]
    fn clocks_too_far_ahead_are_clamped_before_they_are_kept() {
        let mut clock = HybridClock::new(0);
        let poison = from_millis(1_000 + MAX_CLOCK_SKEW_MS + 60_000);
        let stored = clock.observe(poison, 1_000);
        assert_eq!(millis_of(stored), 1_000 + MAX_CLOCK_SKEW_MS);
        assert!(stored < poison);
        let next = clock.tick(1_000);
        assert!(next > stored && millis_of(next) == 1_000 + MAX_CLOCK_SKEW_MS, "the device moves past the clamp, not the poison");
    }

    #[test]
    fn wall_clock_values_from_before_hybrid_clocks_lose_to_any_new_write() {
        // Milliseconds since the epoch, as the old entries were stamped; shifted into the
        // hybrid clock's physical part, any write today is far above them.
        let legacy_ms = 1_800_000_000_000u64;
        let mut clock = HybridClock::new(0);
        assert!(clock.tick(legacy_ms) > legacy_ms);
    }
}
