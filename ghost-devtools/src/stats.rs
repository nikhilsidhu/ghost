//! Timing statistics per kind of span (target and name) since the last reset: how many
//! closed, how long they were open (wall time, awaits included), how long their own code
//! ran (busy time), the slowest, and the longest one went without yielding.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use serde::Serialize;

use crate::layer::ClosedSpan;

/// Aggregate timings of one kind of span.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct SpanSummary {
    pub target: String,
    pub name: String,
    pub count: u64,
    pub wall_ms: f64,
    /// Time its own code ran, not counting spans nested inside it.
    pub busy_ms: f64,
    pub max_wall_ms: f64,
    /// The longest any of them ran its own code without yielding.
    pub longest_poll_ms: f64,
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

impl SpanSummary {
    fn new(target: &str, name: &str) -> Self {
        Self { target: target.to_string(), name: name.to_string(), ..Self::default() }
    }

    fn record(&mut self, wall_ms: f64, busy_ms: f64, longest_poll_ms: f64) {
        self.count += 1;
        self.wall_ms += wall_ms;
        self.busy_ms += busy_ms;
        self.max_wall_ms = self.max_wall_ms.max(wall_ms);
        self.longest_poll_ms = self.longest_poll_ms.max(longest_poll_ms);
    }
}

/// The collected statistics, shared between the layer and whoever reads them.
#[derive(Default)]
pub struct Stats {
    by_span: Mutex<HashMap<(&'static str, &'static str), SpanSummary>>,
}

impl Stats {
    /// Every kind of span seen since the last reset, busiest first.
    pub fn snapshot(&self) -> Vec<SpanSummary> {
        let mut all: Vec<SpanSummary> = self.by_span.lock().unwrap().values().cloned().collect();
        all.sort_by(|a, b| b.busy_ms.total_cmp(&a.busy_ms));
        all
    }

    pub fn reset(&self) {
        self.by_span.lock().unwrap().clear();
    }

    pub(crate) fn record(&self, span: &ClosedSpan) {
        self.by_span
            .lock()
            .unwrap()
            .entry((span.target, span.name))
            .or_insert_with(|| SpanSummary::new(span.target, span.name))
            .record(millis(span.wall()), millis(span.own_busy), millis(span.longest_poll));
    }
}

#[cfg(test)]
mod tests {
    use crate::Devtools;
    use std::time::Duration;

    #[test]
    fn spans_are_counted_and_timed_by_kind() {
        let devtools = Devtools::default();
        tracing::subscriber::with_default(devtools.subscriber(), || {
            for _ in 0..3 {
                let _span = tracing::info_span!(target: "ghost_test", "work").entered();
                std::thread::sleep(Duration::from_millis(2));
            }
            let _other = tracing::info_span!(target: "ghost_test", "other").entered();
        });
        let snapshot = devtools.stats.snapshot();
        let work = snapshot.iter().find(|s| s.name == "work").unwrap();
        assert_eq!(work.count, 3);
        assert!(work.wall_ms >= 6.0 && work.busy_ms >= 6.0, "{work:?}");
        assert!(work.max_wall_ms >= 2.0 && work.longest_poll_ms >= 2.0, "{work:?}");
        assert_eq!(snapshot[0].name, "work", "busiest first");
        devtools.stats.reset();
        assert!(devtools.stats.snapshot().is_empty());
    }
}
