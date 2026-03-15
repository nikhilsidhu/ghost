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

        // Sweep expired invites
        {
            let mut invites = state.invites.write().await;
            invites.retain(|_, inv| inv.expires_at > now);
        }

        // Sweep expired pairing sessions
        crate::routes::pair::reap_expired(&state).await;

        // Sweep expired rate limiter entries
        state.recovery_limiter.sweep();
        state.idlog_recovery_limiter.sweep();

        // Sweep old log entries (retain at least min_entries per mailbox)
        if retention_ms > 0 {
            let cutoff = now.saturating_sub(retention_ms);
            match state.storage.sweep_log(cutoff, min_entries) {
                Ok(n) if n > 0 => tracing::info!("swept {n} expired log entries"),
                Err(e) => tracing::warn!("log sweep error: {e}"),
                _ => {}
            }
        }
    }
}
