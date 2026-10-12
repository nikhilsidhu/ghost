//! Periodic housekeeping: expired invites, pairing sessions, lapsed mirror grants and
//! rate-limiter entries go, and the log is trimmed to its retention.

use std::time::Duration;

use crate::constants::WORKER_INTERVAL_SECS;
use crate::state::AppState;
use crate::util::now_millis;

pub async fn run(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(WORKER_INTERVAL_SECS));
    let retention_ms = state.config.log_retention_hours * 3600 * 1000;
    let min_entries = state.config.log_min_entries;

    loop {
        interval.tick().await;
        let now = now_millis();

        match state.storage.invite_sweep(now).await {
            Ok(gone) => {
                if !gone.is_empty() {
                    state.forget_invite_waiters(|token| !gone.iter().any(|t| t == token));
                }
            }
            Err(e) => tracing::warn!("invite sweep failed: {e}"),
        }

        crate::routes::pair::reap_expired(&state).await;
        match state.storage.sweep_mirror_grants(now).await {
            Ok(n) if n > 0 => tracing::debug!("{n} mirror grants lapsed"),
            Err(e) => tracing::warn!("mirror grant sweep failed: {e}"),
            _ => {}
        }

        state.idlog_recovery_limiter.sweep();
        state.idlog_anchored_limiter.sweep();
        state.idlog_import_limiter.sweep();
        state.idlog_batch_limiter.sweep();
        state.ip_limits.sweep();
        state.replay_cache.sweep();

        if retention_ms > 0 {
            let cutoff = now.saturating_sub(retention_ms);
            match state.storage.sweep_log(cutoff, min_entries).await {
                Ok(n) if n > 0 => tracing::info!("swept {n} expired log entries"),
                Err(e) => tracing::warn!("log sweep error: {e}"),
                _ => {}
            }
        }
    }
}
