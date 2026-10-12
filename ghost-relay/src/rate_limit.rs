use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::constants::{AUTH_FAILURES_PER_MINUTE, UNAUTHENTICATED_PER_MINUTE};
use crate::error::RelayError;

/// Maximum tracked keys to prevent memory exhaustion from key spraying.
const MAX_TRACKED_KEYS: usize = 100_000;

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
        // Reject new keys when the map is full to prevent memory exhaustion
        if self.windows.len() >= MAX_TRACKED_KEYS && !self.windows.contains_key(key) {
            return false;
        }

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

    /// Whether a request would be allowed now, without counting it. With
    /// [`record`](Self::record) after the request succeeds, only requests that pass
    /// validation spend the budget, so junk cannot use up an owner's attempts.
    pub fn allows(&self, key: &[u8; 32]) -> bool {
        let cutoff = Instant::now() - self.window;
        match self.windows.get(key) {
            Some(deque) => deque.iter().filter(|t| **t >= cutoff).count() < self.max_requests,
            None => self.windows.len() < MAX_TRACKED_KEYS,
        }
    }

    /// How long until the key may make a request again: none while it may now, the
    /// whole window when the limiter tracks too many keys to take a new one.
    pub fn wait(&self, key: &[u8; 32]) -> Duration {
        let now = Instant::now();
        let cutoff = now - self.window;
        match self.windows.get(key) {
            Some(deque) => {
                let recent: Vec<&Instant> = deque.iter().filter(|t| **t >= cutoff).collect();
                if recent.len() < self.max_requests {
                    return Duration::ZERO;
                }
                // A slot frees when the oldest request still counted leaves the window.
                let freed = recent.len() - self.max_requests;
                (*recent[freed] + self.window).saturating_duration_since(now)
            }
            None if self.windows.len() < MAX_TRACKED_KEYS => Duration::ZERO,
            None => self.window,
        }
    }

    /// The refusal for a key past its allowance, saying how long to wait.
    pub fn refusal(&self, key: &[u8; 32]) -> RelayError {
        RelayError::RateLimited(self.wait(key))
    }

    /// Count a request that [`allows`](Self::allows) let through and that succeeded.
    pub fn record(&self, key: &[u8; 32]) {
        if self.windows.len() >= MAX_TRACKED_KEYS && !self.windows.contains_key(key) {
            return;
        }
        let cutoff = Instant::now() - self.window;
        let mut entry = self.windows.entry(*key).or_default();
        let deque = entry.value_mut();
        while deque.front().is_some_and(|t| *t < cutoff) {
            deque.pop_front();
        }
        deque.push_back(Instant::now());
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

/// Limits per client address, for what happens before anyone has authenticated: the
/// requests that need no credentials and the attempts that fail to present valid ones.
pub struct IpLimits {
    /// Signatures that did not verify; an address past its allowance is refused outright.
    failures: RateLimiter,
    /// Requests that need no credentials but cost validation work or storage.
    unauthenticated: RateLimiter,
}

fn ip_key(ip: IpAddr) -> [u8; 32] {
    match ip {
        IpAddr::V4(v4) => blake3::hash(&v4.octets()).into(),
        IpAddr::V6(v6) => blake3::hash(&v6.octets()).into(),
    }
}

impl Default for IpLimits {
    fn default() -> Self {
        let minute = Duration::from_secs(60);
        Self {
            failures: RateLimiter::new(AUTH_FAILURES_PER_MINUTE, minute),
            unauthenticated: RateLimiter::new(UNAUTHENTICATED_PER_MINUTE, minute),
        }
    }
}

impl IpLimits {
    /// Whether the address has failed authentication too often to be served at all.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        !self.failures.allows(&ip_key(ip))
    }

    pub fn auth_failed(&self, ip: IpAddr) {
        self.failures.record(&ip_key(ip));
    }

    /// Count a request made without credentials; refused past the allowance.
    pub fn check_unauthenticated(&self, ip: IpAddr) -> Result<(), RelayError> {
        let key = ip_key(ip);
        if self.unauthenticated.check(&key) {
            Ok(())
        } else {
            Err(self.unauthenticated.refusal(&key))
        }
    }

    /// The refusal for an address that failed authentication too often.
    pub fn blocked(&self, ip: IpAddr) -> RelayError {
        self.failures.refusal(&ip_key(ip))
    }

    pub fn sweep(&self) {
        self.failures.sweep();
        self.unauthenticated.sweep();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wait_runs_until_the_oldest_counted_request_leaves_the_window() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        let key = [7; 32];
        assert_eq!(limiter.wait(&key), Duration::ZERO);
        limiter.record(&key);
        assert_eq!(limiter.wait(&key), Duration::ZERO, "one request left");
        limiter.record(&key);
        let wait = limiter.wait(&key);
        assert!(wait > Duration::from_secs(59) && wait <= Duration::from_secs(60), "{wait:?}");
    }
}
