use std::time::Duration;

use crate::constants::WORKER_INTERVAL_SECS;
use crate::state::AppState;
use crate::util::now_millis;

pub async fn run(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(WORKER_INTERVAL_SECS));

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
    }
}
