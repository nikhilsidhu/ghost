use std::collections::VecDeque;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Per-key sliding window rate limiter.
pub struct RateLimiter {
    windows: DashMap<[u8; 32], VecDeque<Instant>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            windows: DashMap::new(),
            max_requests,
            window,
        }
    }

    /// Returns `true` if the request is allowed, `false` if rate-limited.
    pub fn check(&self, key: &[u8; 32]) -> bool {
        let now = Instant::now();
        let cutoff = now - self.window;

        let mut entry = self.windows.entry(*key).or_default();
        let deque = entry.value_mut();

        // Remove expired entries
        while deque.front().is_some_and(|t| *t < cutoff) {
            deque.pop_front();
        }

        if deque.len() >= self.max_requests {
            return false;
        }

        deque.push_back(now);
        true
    }

    /// Remove entries older than the window. Call periodically from the worker.
    pub fn sweep(&self) {
        let cutoff = Instant::now() - self.window;
        self.windows.retain(|_, deque| {
            while deque.front().is_some_and(|t| *t < cutoff) {
                deque.pop_front();
            }
            !deque.is_empty()
        });
    }
}
