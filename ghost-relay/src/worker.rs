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

        // Sweep expired blobs
        let mut freed = 0usize;
        let mut empty_keys = Vec::new();
        {
            let mut map = state.mailboxes.write().await;
            for (key, mailbox) in map.iter_mut() {
                mailbox.blobs.retain(|blob| {
                    if blob.received_at < cutoff {
                        freed += blob.payload.len();
                        false
                    } else {
                        true
                    }
                });
                if mailbox.blobs.is_empty() && mailbox.tx.receiver_count() == 0 {
                    empty_keys.push(*key);
                }
            }
            for key in &empty_keys {
                map.remove(key);
            }
        }

        if freed > 0 {
            state.release(freed);
        }

        // Sweep expired invites
        let mut invite_freed = 0usize;
        {
            let mut invites = state.invites.write().await;
            invites.retain(|_, inv| {
                if inv.expires_at > now {
                    return true;
                }
                if let Some(ref j) = inv.join {
                    invite_freed += j.len();
                }
                if let Some(ref a) = inv.accept {
                    invite_freed += a.len();
                }
                false
            });
        }
        if invite_freed > 0 {
            state.release(invite_freed);
        }
    }
}
