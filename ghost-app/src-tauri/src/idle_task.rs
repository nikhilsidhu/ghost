//! Follows the user's presence over time: clears an expired status message, here and on
//! the account's other devices, and goes idle (muting a call) after a stretch without
//! input, back online at the next input, which the system's idle clock shows at the next
//! poll and this window reports at once. The return lifts only the mute idle applied.

use std::sync::atomic::Ordering;
use std::time::Duration;

use ghost_core::flows::{self, now_millis, presence};
use ghost_core::mls::presence::OnlineStatus;
use ghost_core::wire::SYNC_KEY_STATUS_MESSAGE;
use tauri::{AppHandle, Emitter};

use crate::dto::OnlineStatusDto;
use crate::state::SessionHandles;

const POLL_INTERVAL: Duration = Duration::from_secs(1);
const IDLE_THRESHOLD_SECS: u64 = 600;

pub async fn run(app: AppHandle, handles: SessionHandles) {
    let SessionHandles { client, relay, presence, config, config_path, .. } = handles.clone();
    // The system's idle time at the last poll; it only goes down when input happened.
    let mut last_idle_secs = 0;
    let mut idle_clock_missing_told = false;

    loop {
        tokio::time::sleep(POLL_INTERVAL).await;

        // A status message past its expiry goes, here and for everyone else.
        {
            let mut p = presence.lock().await;
            if p.status_expiry.is_some_and(|expiry| now_millis() >= expiry) {
                p.status_message = None;
                p.status_expiry = None;
                let info = p.clone();
                drop(p);
                presence::broadcast(&client, &relay, &info).await;
                {
                    let mut cfg = config.lock().await;
                    cfg.status_message = None;
                    cfg.status_expiry = None;
                    if let Err(e) = cfg.save(&config_path) {
                        tracing::warn!("expired status message not cleared from the config: {e}");
                    }
                }
                // The other devices clear it at the same moment by the synced expiry; this
                // also clears it from the snapshots a device linked later restores.
                flows::sync::remove_and_push(&client, &relay, SYNC_KEY_STATUS_MESSAGE).await;
                let _ = app.emit("status-message-cleared", ());
                continue;
            }
        }

        let idle_secs = match user_idle::UserIdle::get_time() {
            Ok(time) => time.as_seconds(),
            Err(e) => {
                if !std::mem::replace(&mut idle_clock_missing_told, true) {
                    tracing::warn!("this system gives no idle time ({e}); the device will not go idle on its own");
                }
                continue;
            }
        };
        let input_since_last_poll = idle_secs < last_idle_secs;
        last_idle_secs = idle_secs;

        if idle_secs >= IDLE_THRESHOLD_SECS {
            go_idle(&app, &handles).await;
        } else if input_since_last_poll {
            back_from_idle(&app, &handles).await;
        }
    }
}

/// Announce idle, if the device is online: the user has been away from the keyboard.
/// A call that is not muted mutes too, unless the user turned that off; the mute is
/// idle's until the user mutes or deafens themselves.
async fn go_idle(app: &AppHandle, handles: &SessionHandles) {
    let info = {
        let mut p = handles.presence.lock().await;
        if p.status != OnlineStatus::Online {
            return;
        }
        p.status = OnlineStatus::Idle;
        p.clone()
    };
    presence::broadcast(&handles.client, &handles.relay, &info).await;
    let _ = app.emit("idle-transition", OnlineStatusDto::Idle);
    let mutes = handles.voice.in_call() && !handles.voice.muted() && handles.config.lock().await.auto_mute_on_idle();
    if mutes && handles.voice.set_muted(true).await.is_ok() {
        handles.idle_mute.store(true, Ordering::SeqCst);
        let _ = app.emit("auto-muted", true);
    }
}

/// Announce online again, if idle is what the device announced: the user is back, by the
/// system's idle clock or by acting in this window. A mute idle applied, and the user
/// has not taken over, is lifted.
pub async fn back_from_idle(app: &AppHandle, handles: &SessionHandles) {
    let info = {
        let mut p = handles.presence.lock().await;
        if p.status != OnlineStatus::Idle {
            return;
        }
        p.status = OnlineStatus::Online;
        p.clone()
    };
    presence::broadcast(&handles.client, &handles.relay, &info).await;
    let _ = app.emit("idle-transition", OnlineStatusDto::Online);
    if handles.idle_mute.swap(false, Ordering::SeqCst) && handles.voice.set_muted(false).await.is_ok() {
        let _ = app.emit("auto-muted", false);
    }
}
