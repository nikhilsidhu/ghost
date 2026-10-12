//! Which of a device's messages were seen already: the highest sequence number and a
//! window of 64 below it, as an IPsec replay window. A copy from a second relay, or a
//! replay, is told apart from a new message without keeping every hash ever seen.

/// Messages below the highest by more than this are treated as seen: a copy that
/// arrives this late is a replay or a relay far behind, and the snapshot covers it.
pub const WINDOW: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReplayWindow {
    /// The highest sequence number seen; 0 before any.
    high: u64,
    /// Bit `i` set: `high - i` was seen.
    bits: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrival {
    /// Not seen before. `gap` is how many sequence numbers below it are still unseen
    /// since the previous highest.
    New { gap: u64 },
    /// A copy or a replay.
    Seen,
}

impl ReplayWindow {
    pub fn new(high: u64, bits: u64) -> Self {
        Self { high, bits }
    }

    pub fn high(&self) -> u64 {
        self.high
    }

    pub fn bits(&self) -> u64 {
        self.bits
    }

    /// Record `seq` and say whether it was new.
    pub fn accept(&mut self, seq: u64) -> Arrival {
        if seq == 0 {
            return Arrival::Seen;
        }
        if seq > self.high {
            let gap = seq - self.high - 1;
            let shift = seq - self.high;
            self.bits = if shift >= WINDOW { 0 } else { self.bits << shift };
            self.bits |= 1;
            self.high = seq;
            return Arrival::New { gap };
        }
        let behind = self.high - seq;
        if behind >= WINDOW {
            return Arrival::Seen;
        }
        let bit = 1u64 << behind;
        if self.bits & bit != 0 {
            return Arrival::Seen;
        }
        self.bits |= bit;
        Arrival::New { gap: 0 }
    }

    /// A snapshot covered everything up to `seq`: nothing at or below it is new any more.
    pub fn cover_up_to(&mut self, seq: u64) {
        if seq > self.high {
            self.high = seq;
            self.bits = u64::MAX;
        } else {
            let behind = self.high - seq;
            if behind < WINDOW {
                // Every position at `behind` and beyond is covered.
                self.bits |= u64::MAX << behind;
            }
        }
    }

    /// Sequence numbers below the highest that were never seen, within the window.
    pub fn missing(&self) -> Vec<u64> {
        (1..WINDOW)
            .filter(|i| *i < self.high && self.bits & (1u64 << i) == 0)
            .map(|i| self.high - i)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_of_a_message_are_seen_from_the_second_on() {
        let mut window = ReplayWindow::default();
        assert_eq!(window.accept(1), Arrival::New { gap: 0 });
        assert_eq!(window.accept(1), Arrival::Seen);
        assert_eq!(window.accept(2), Arrival::New { gap: 0 });
        assert_eq!(window.accept(1), Arrival::Seen);
        assert_eq!(window.accept(2), Arrival::Seen);
    }

    #[test]
    fn out_of_order_arrivals_are_new_once_and_gaps_are_reported() {
        let mut window = ReplayWindow::default();
        assert_eq!(window.accept(3), Arrival::New { gap: 2 });
        assert_eq!(window.missing(), vec![2, 1]);
        assert_eq!(window.accept(1), Arrival::New { gap: 0 });
        assert_eq!(window.accept(2), Arrival::New { gap: 0 });
        assert!(window.missing().is_empty());
        assert_eq!(window.accept(2), Arrival::Seen);
    }

    #[test]
    fn messages_older_than_the_window_count_as_seen() {
        let mut window = ReplayWindow::default();
        window.accept(100);
        assert_eq!(window.accept(100 - WINDOW), Arrival::Seen);
        assert_eq!(window.accept(100 - WINDOW + 1), Arrival::New { gap: 0 });
    }

    #[test]
    fn a_jump_past_the_window_forgets_the_old_bits() {
        let mut window = ReplayWindow::default();
        window.accept(1);
        window.accept(1 + WINDOW + 5);
        assert_eq!(window.accept(1), Arrival::Seen, "too old to matter");
        assert_eq!(window.missing().len() as u64, WINDOW - 1, "everything in the window below the jump is unseen");
    }

    #[test]
    fn a_snapshot_covers_the_gaps_below_what_it_includes() {
        let mut window = ReplayWindow::default();
        window.accept(5);
        window.cover_up_to(5);
        assert!(window.missing().is_empty());
        assert_eq!(window.accept(3), Arrival::Seen);
        window.cover_up_to(40);
        assert_eq!(window.high(), 40);
        assert_eq!(window.accept(39), Arrival::Seen);
        assert_eq!(window.accept(41), Arrival::New { gap: 0 });
    }

    #[test]
    fn sequence_zero_is_never_a_message() {
        assert_eq!(ReplayWindow::default().accept(0), Arrival::Seen);
    }
}
