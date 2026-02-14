use std::time::Duration;

use crate::constants::WORKER_INTERVAL_SECS;
use crate::state::AppState;
use crate::util::now_millis;

pub async fn run(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(WORKER_INTERVAL_SECS));

    loop {
        interval.tick().await;

        let now = now_millis();
        let ttl_ms = state.config.ttl.as_millis() as u64;
        let cutoff = now.saturating_sub(ttl_ms);

        let _ = state.storage.sweep_expired(cutoff);

        // Sweep expired invites
        {
            let mut invites = state.invites.write().await;
            invites.retain(|_, inv| inv.expires_at > now);
        }
    }
}
