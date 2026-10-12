//! How hard a media thread works, for the dev builds' profiler: the time taken to
//! process each stretch of media as a share of how long that stretch plays, so audio
//! frames and video frames are judged against their own deadlines alike. Near 100% a
//! thread cannot keep up. Lock-free, so real-time threads never wait on whoever reads it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const PPM: u64 = 1_000_000;

fn nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

/// Loads recorded since the last read.
#[derive(Default)]
pub struct LoadTimer {
    took_ns: AtomicU64,
    media_ns: AtomicU64,
    count: AtomicU64,
    /// The highest load of one stretch, in parts per million.
    peak_ppm: AtomicU64,
}

impl LoadTimer {
    /// Processing `media` worth of audio or video took `took`.
    pub fn record(&self, took: Duration, media: Duration) {
        let (took_ns, media_ns) = (nanos(took), nanos(media).max(1));
        self.took_ns.fetch_add(took_ns, Ordering::Relaxed);
        self.media_ns.fetch_add(media_ns, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.peak_ppm.fetch_max(took_ns.saturating_mul(PPM) / media_ns, Ordering::Relaxed);
    }

    /// What was recorded since the last call, which starts afresh.
    pub fn take(&self) -> Load {
        let took_ns = self.took_ns.swap(0, Ordering::Relaxed);
        let media_ns = self.media_ns.swap(0, Ordering::Relaxed);
        let count = self.count.swap(0, Ordering::Relaxed);
        let peak_ppm = self.peak_ppm.swap(0, Ordering::Relaxed);
        Load {
            frames: count,
            load: if media_ns > 0 { took_ns as f64 / media_ns as f64 } else { 0.0 },
            peak: peak_ppm as f64 / PPM as f64,
        }
    }
}

/// Processing load over a run of frames, as a share of real time.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Load {
    pub frames: u64,
    /// Time taken over the media's playing time, across all the frames.
    pub load: f64,
    /// The highest of any one frame.
    pub peak: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_are_shares_of_real_time_and_reset_on_read() {
        let timer = LoadTimer::default();
        timer.record(Duration::from_millis(1), Duration::from_millis(20));
        timer.record(Duration::from_millis(5), Duration::from_millis(10));
        assert_eq!(timer.take(), Load { frames: 2, load: 0.2, peak: 0.5 });
        assert_eq!(timer.take(), Load::default());
    }
}
