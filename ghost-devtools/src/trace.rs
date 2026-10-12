//! The flight recorder: every span of the last minute, kept so a capture shows what just
//! happened, spans still running included. Only span names are kept, never their fields,
//! so no message content can end up in a capture.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::layer::ClosedSpan;

/// How far back the recorder keeps spans.
pub const WINDOW: Duration = Duration::from_secs(60);
/// Spans kept at most, so a burst cannot eat the machine's memory; past it the oldest go
/// and captures start where the record is still complete.
pub const CAPACITY: usize = 100_000;
/// Own code running this long without yielding held up its thread: on the async runtime,
/// every task waiting for that worker waited as long. A browser's long task is the same
/// 50 ms.
pub const BLOCKING: Duration = Duration::from_millis(50);

const WINDOW_US: f64 = WINDOW.as_micros() as f64;
const BLOCKING_US: f64 = BLOCKING.as_micros() as f64;

/// One span. In a capture, times are microseconds from the capture's start, and a span
/// that began before it starts below zero.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SpanRecord {
    pub id: u64,
    /// The enclosing span, which may have closed before the capture's start.
    pub parent: Option<u64>,
    pub target: &'static str,
    pub name: &'static str,
    pub start_us: f64,
    pub duration_us: f64,
    /// Time running, spans nested inside it included.
    pub busy_us: f64,
    /// Time running its own code.
    pub own_busy_us: f64,
    pub longest_poll_us: f64,
    /// Still running when captured: the duration is so far, and the busy figures are
    /// unknown until it closes.
    pub open: bool,
}

impl SpanRecord {
    fn end_us(&self) -> f64 {
        self.start_us + self.duration_us
    }
}

/// What the recorder held when captured.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Capture {
    pub spans: Vec<SpanRecord>,
    pub duration_us: f64,
    /// When the capture starts, in milliseconds since the Unix epoch, to line other
    /// timelines up with it.
    pub start_unix_ms: f64,
    /// Spans were dropped for room, so the capture covers less than `WINDOW`.
    pub truncated: bool,
}

/// A span whose own code ran at least `BLOCKING` without yielding.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Blocking {
    pub id: u64,
    pub target: &'static str,
    pub name: &'static str,
    /// When it closed, in milliseconds since the Unix epoch.
    pub ended_unix_ms: f64,
    pub longest_poll_us: f64,
}

struct Open {
    parent: Option<u64>,
    target: &'static str,
    name: &'static str,
    start_us: f64,
}

/// Spans with times in microseconds since the recorder started.
#[derive(Default)]
struct Ring {
    /// In the order they closed, so the oldest end comes first.
    closed: VecDeque<SpanRecord>,
    open: HashMap<u64, Open>,
    /// Spans that ended before this were dropped for room.
    complete_since_us: Option<f64>,
}

impl Ring {
    fn push(&mut self, span: SpanRecord, now_us: f64, capacity: usize) {
        let horizon = now_us - WINDOW_US;
        while self.closed.front().is_some_and(|oldest| oldest.end_us() < horizon) {
            self.closed.pop_front();
        }
        if self.closed.len() >= capacity {
            if let Some(dropped) = self.closed.pop_front() {
                self.complete_since_us = Some(self.complete_since_us.unwrap_or(0.0).max(dropped.end_us()));
            }
        }
        self.closed.push_back(span);
    }

    /// Where a capture taken now starts: a window back, or less where the record is
    /// incomplete or the recorder younger.
    fn start_us(&self, now_us: f64) -> f64 {
        (now_us - WINDOW_US).max(self.complete_since_us.unwrap_or(0.0)).max(0.0)
    }

    /// Whether spans dropped for room leave a capture taken now short of a window.
    fn truncated(&self, now_us: f64) -> bool {
        self.complete_since_us.is_some_and(|since| since > now_us - WINDOW_US)
    }

    /// Closed spans that ended at or after `since_us`, newest first.
    fn closed_since(&self, since_us: f64) -> impl Iterator<Item = &SpanRecord> {
        self.closed.iter().rev().take_while(move |span| span.end_us() >= since_us)
    }
}

/// Keeps the last `WINDOW` of spans.
pub struct Recorder {
    epoch: Instant,
    capacity: usize,
    ring: Mutex<Ring>,
}

impl Default for Recorder {
    fn default() -> Self {
        Self { epoch: Instant::now(), capacity: CAPACITY, ring: Mutex::default() }
    }
}

fn micros(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000_000.0
}

fn unix_ms() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |since| since.as_secs_f64() * 1000.0)
}

impl Recorder {
    fn us(&self, at: Instant) -> f64 {
        micros(at.saturating_duration_since(self.epoch))
    }

    pub(crate) fn opened(&self, id: u64, parent: Option<u64>, target: &'static str, name: &'static str, at: Instant) {
        let start_us = self.us(at);
        self.ring.lock().unwrap().open.insert(id, Open { parent, target, name, start_us });
    }

    pub(crate) fn closed(&self, span: &ClosedSpan) {
        let record = SpanRecord {
            id: span.id,
            parent: span.parent,
            target: span.target,
            name: span.name,
            start_us: self.us(span.opened),
            duration_us: micros(span.wall()),
            busy_us: micros(span.busy),
            own_busy_us: micros(span.own_busy),
            longest_poll_us: micros(span.longest_poll),
            open: false,
        };
        let now_us = self.us(span.closed);
        let mut ring = self.ring.lock().unwrap();
        ring.open.remove(&span.id);
        ring.push(record, now_us, self.capacity);
    }

    /// Everything of the last `WINDOW`, closed or still running.
    pub fn capture(&self) -> Capture {
        let (now_us, now_unix_ms) = (self.us(Instant::now()), unix_ms());
        let ring = self.ring.lock().unwrap();
        let start_us = ring.start_us(now_us);
        let mut spans: Vec<SpanRecord> = ring
            .closed_since(start_us)
            .map(|span| SpanRecord { start_us: span.start_us - start_us, ..span.clone() })
            .collect();
        spans.reverse();
        spans.extend(ring.open.iter().map(|(id, open)| SpanRecord {
            id: *id,
            parent: open.parent,
            target: open.target,
            name: open.name,
            start_us: open.start_us - start_us,
            duration_us: now_us - open.start_us,
            busy_us: 0.0,
            own_busy_us: 0.0,
            longest_poll_us: 0.0,
            open: true,
        }));
        Capture {
            spans,
            duration_us: now_us - start_us,
            start_unix_ms: now_unix_ms - (now_us - start_us) / 1000.0,
            truncated: ring.truncated(now_us),
        }
    }

    /// Spans of the last `WINDOW` that held their thread for `BLOCKING` or longer.
    pub fn blocking(&self) -> Vec<Blocking> {
        let (now_us, now_unix_ms) = (self.us(Instant::now()), unix_ms());
        let ring = self.ring.lock().unwrap();
        ring.closed_since(now_us - WINDOW_US)
            .filter(|span| span.longest_poll_us >= BLOCKING_US)
            .map(|span| Blocking {
                id: span.id,
                target: span.target,
                name: span.name,
                ended_unix_ms: now_unix_ms - (now_us - span.end_us()) / 1000.0,
                longest_poll_us: span.longest_poll_us,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Devtools;

    fn record(id: u64, start_us: f64, duration_us: f64) -> SpanRecord {
        SpanRecord {
            id,
            parent: None,
            target: "ghost_test",
            name: "work",
            start_us,
            duration_us,
            busy_us: 0.0,
            own_busy_us: 0.0,
            longest_poll_us: 0.0,
            open: false,
        }
    }

    #[test]
    fn the_ring_keeps_one_window_and_drops_the_oldest_when_full() {
        let mut ring = Ring::default();
        ring.push(record(1, 0.0, 10.0), 10.0, 3);
        ring.push(record(2, 20.0, 10.0), WINDOW_US + 20.0, 3);
        let ids: Vec<u64> = ring.closed.iter().map(|span| span.id).collect();
        assert_eq!(ids, [2], "span 1 ended a window before now");
        assert_eq!(ring.start_us(WINDOW_US + 20.0), 20.0);

        let now = WINDOW_US + 25.0;
        for id in 3..=5 {
            ring.push(record(id, now - 10.0, 5.0), now, 3);
        }
        let ids: Vec<u64> = ring.closed.iter().map(|span| span.id).collect();
        assert_eq!(ids, [3, 4, 5], "full: the oldest went for room");
        assert_eq!(ring.complete_since_us, Some(30.0), "span 2 ended at 30 µs");
        assert_eq!(ring.start_us(now), 30.0, "a capture starts where the record is complete");
        assert!(ring.truncated(now));
        assert!(!ring.truncated(WINDOW_US + 30.0), "a window later, nothing dropped is missed");
    }

    #[test]
    fn a_capture_holds_closed_and_running_spans_with_their_parents() {
        let devtools = Devtools::default();
        let outer = tracing::subscriber::with_default(devtools.subscriber(), || {
            let outer = tracing::info_span!(target: "ghost_test", "outer").entered();
            let inner = tracing::info_span!(target: "ghost_test", "inner").entered();
            std::thread::sleep(Duration::from_millis(2));
            drop(inner);
            let capture = devtools.recorder.capture();
            let names: Vec<(&str, bool)> = capture.spans.iter().map(|span| (span.name, span.open)).collect();
            assert_eq!(names, [("inner", false), ("outer", true)]);
            let (inner, running) = (&capture.spans[0], &capture.spans[1]);
            assert_eq!(inner.parent, Some(running.id));
            assert!(running.start_us >= 0.0 && running.start_us <= inner.start_us);
            assert!(inner.duration_us >= 2000.0 && inner.busy_us >= 2000.0);
            assert!(running.duration_us >= inner.duration_us, "a running span lasts until the capture");
            assert!(capture.duration_us >= running.start_us + running.duration_us);
            assert!(!capture.truncated);
            outer
        });
        drop(outer);
        let capture = devtools.recorder.capture();
        assert!(capture.spans.iter().all(|span| !span.open), "outer closed since");
    }

    #[test]
    fn spans_that_held_their_thread_are_listed() {
        let recorder = Recorder::default();
        let closed = |id: u64, longest_poll: Duration| ClosedSpan {
            id,
            parent: None,
            target: "ghost_test",
            name: "work",
            opened: recorder.epoch,
            closed: recorder.epoch + longest_poll,
            busy: longest_poll,
            own_busy: longest_poll,
            longest_poll,
        };
        recorder.closed(&closed(1, BLOCKING - Duration::from_millis(1)));
        recorder.closed(&closed(2, BLOCKING));
        let blocking = recorder.blocking();
        assert_eq!(blocking.iter().map(|span| span.id).collect::<Vec<_>>(), [2]);
        assert_eq!(blocking[0].longest_poll_us, BLOCKING.as_micros() as f64);
    }
}
