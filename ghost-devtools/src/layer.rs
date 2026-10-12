//! Measures each span of Ghost's crates as it runs: how long it was open, how long it
//! ran, how much of that was its own code rather than spans nested inside it, and the
//! longest its own code ran without yielding. Closed spans go to the statistics and the
//! flight recorder.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::span::{Attributes, Id};
use tracing::Subscriber;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

use crate::stats::Stats;
use crate::trace::Recorder;

/// A span as measured, once closed.
#[derive(Debug, Clone)]
pub struct ClosedSpan {
    pub id: u64,
    pub parent: Option<u64>,
    pub target: &'static str,
    pub name: &'static str,
    pub opened: Instant,
    pub closed: Instant,
    /// Time entered (running), spans nested inside it included.
    pub busy: Duration,
    /// Busy time spent in its own code, not in spans entered inside it.
    pub own_busy: Duration,
    /// The longest its own code ran in one go: how long it held its thread without
    /// yielding.
    pub longest_poll: Duration,
}

impl ClosedSpan {
    pub fn wall(&self) -> Duration {
        self.closed.duration_since(self.opened)
    }
}

/// Kept on each open span.
struct Timing {
    opened: Instant,
    busy: Duration,
    /// Busy time of spans entered while this one was.
    nested: Duration,
    longest_poll: Duration,
    entered: Option<Entered>,
}

struct Entered {
    at: Instant,
    /// `nested` when entered, so exiting knows how much of the stretch was nested.
    nested_before: Duration,
    /// Whether the parent was entered too, so this stretch ran inside its stretch.
    inside_parent: bool,
}

/// Feeds `Stats` and a `Recorder` from span lifetimes.
pub struct DevtoolsLayer {
    stats: Arc<Stats>,
    recorder: Arc<Recorder>,
}

impl DevtoolsLayer {
    pub fn new(stats: Arc<Stats>, recorder: Arc<Recorder>) -> Self {
        Self { stats, recorder }
    }
}

impl<S> Layer<S> for DevtoolsLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, _attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let opened = Instant::now();
        let metadata = span.metadata();
        let parent = span.parent().map(|parent| parent.id().into_u64());
        self.recorder.opened(id.into_u64(), parent, metadata.target(), metadata.name(), opened);
        span.extensions_mut().insert(Timing {
            opened,
            busy: Duration::ZERO,
            nested: Duration::ZERO,
            longest_poll: Duration::ZERO,
            entered: None,
        });
    }

    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        // A parent entered at the same time on another thread would count too; spans
        // of one future are polled by one thread at a time, so that stays rare.
        let inside_parent = span
            .parent()
            .is_some_and(|parent| parent.extensions().get::<Timing>().is_some_and(|timing| timing.entered.is_some()));
        if let Some(timing) = span.extensions_mut().get_mut::<Timing>() {
            timing.entered = Some(Entered { at: Instant::now(), nested_before: timing.nested, inside_parent });
        };
    }

    fn on_exit(&self, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let (stretch, inside_parent) = {
            let mut extensions = span.extensions_mut();
            let Some(timing) = extensions.get_mut::<Timing>() else { return };
            let Some(entered) = timing.entered.take() else { return };
            let stretch = entered.at.elapsed();
            timing.busy += stretch;
            let own = stretch.saturating_sub(timing.nested - entered.nested_before);
            timing.longest_poll = timing.longest_poll.max(own);
            (stretch, entered.inside_parent)
        };
        if !inside_parent {
            return;
        }
        if let Some(parent) = span.parent() {
            if let Some(timing) = parent.extensions_mut().get_mut::<Timing>() {
                timing.nested += stretch;
            };
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        let Some(timing) = span.extensions_mut().remove::<Timing>() else { return };
        let metadata = span.metadata();
        let closed = ClosedSpan {
            id: id.into_u64(),
            parent: span.parent().map(|parent| parent.id().into_u64()),
            target: metadata.target(),
            name: metadata.name(),
            opened: timing.opened,
            closed: Instant::now(),
            busy: timing.busy,
            own_busy: timing.busy.saturating_sub(timing.nested),
            longest_poll: timing.longest_poll,
        };
        self.stats.record(&closed);
        self.recorder.closed(&closed);
    }
}

#[cfg(test)]
mod tests {
    use crate::Devtools;
    use std::time::Duration;

    #[test]
    fn time_spent_awaiting_counts_as_wall_but_not_busy() {
        let devtools = Devtools::default();
        tracing::subscriber::with_default(devtools.subscriber(), || {
            let span = tracing::info_span!(target: "ghost_test", "waits");
            {
                let _entered = span.enter();
                std::thread::sleep(Duration::from_millis(1));
            }
            // Open but not entered: like a future parked at an await.
            std::thread::sleep(Duration::from_millis(5));
            drop(span);
        });
        let waits = &devtools.stats.snapshot()[0];
        assert!(waits.wall_ms >= 6.0, "{waits:?}");
        assert!(waits.busy_ms < waits.wall_ms - 4.0, "{waits:?}");
    }

    #[test]
    fn spans_entered_inside_a_span_are_not_its_own_time() {
        let devtools = Devtools::default();
        tracing::subscriber::with_default(devtools.subscriber(), || {
            let _outer = tracing::info_span!(target: "ghost_test", "outer").entered();
            std::thread::sleep(Duration::from_millis(1));
            {
                let _inner = tracing::info_span!(target: "ghost_test", "inner").entered();
                std::thread::sleep(Duration::from_millis(3));
            }
            std::thread::sleep(Duration::from_millis(1));
        });
        let capture = devtools.recorder.capture();
        let span = |name: &str| capture.spans.iter().find(|span| span.name == name).unwrap();
        let (outer, inner) = (span("outer"), span("inner"));
        assert!(inner.own_busy_us >= 3000.0 && inner.own_busy_us == inner.busy_us, "{inner:?}");
        assert!(outer.busy_us >= 5000.0, "{outer:?}");
        assert!((outer.busy_us - outer.own_busy_us - inner.busy_us).abs() < 1.0, "inner's time is not outer's own: {outer:?}");
        assert_eq!(outer.longest_poll_us, outer.own_busy_us, "one stretch, less what ran inside it");
        assert_eq!(inner.longest_poll_us, inner.own_busy_us);
    }
}
