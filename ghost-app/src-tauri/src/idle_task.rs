use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ghost_core::client::GhostClient;
use ghost_core::mls::presence::OnlineStatus;
use ghost_core::relay::RelayClient;
use tauri::{AppHandle, Emitter};
use tokio::sync::Mutex;

use crate::config::GhostConfig;
use crate::presence::{self, PresenceInfo};
use crate::voice_task::VoiceCommand;

const POLL_INTERVAL: Duration = Duration::from_secs(15);
const IDLE_THRESHOLD_SECS: u64 = 600; // 10 minutes
const HYSTERESIS_SECS: u64 = 2;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub async fn run(
    app: AppHandle,
    client: Arc<Mutex<GhostClient>>,
    relay: Arc<Mutex<RelayClient>>,
    presence: Arc<Mutex<PresenceInfo>>,
    voice_cmd: tokio::sync::mpsc::Sender<VoiceCommand>,
    config: Arc<Mutex<GhostConfig>>,
    config_path: PathBuf,
) {
    let mut was_idle = false;

    loop {
        tokio::time::sleep(POLL_INTERVAL).await;

        // Check status message expiry
        {
            let mut p = presence.lock().await;
            if let Some(exp) = p.status_expiry {
                if now_ms() >= exp {
                    p.status_message = None;
                    p.status_expiry = None;
                    let info = p.clone();
                    drop(p);
                    presence::broadcast_presence(&client, &relay, &info).await;
                    let mut cfg = config.lock().await;
                    cfg.status_message = None;
                    cfg.status_expiry = None;
                    let _ = cfg.save(&config_path);
                    let _ = app.emit("status-message-cleared", ());
                    continue;
                }
            }
        }

        let idle_secs = match user_idle::UserIdle::get_time() {
            Ok(t) => t.as_seconds(),
            Err(_) => continue,
        };

        let current = presence.lock().await.status;

        if idle_secs >= IDLE_THRESHOLD_SECS && !was_idle {
            if current != OnlineStatus::Online {
                continue;
            }
            was_idle = true;

            let info = {
                let mut p = presence.lock().await;
                p.status = OnlineStatus::Idle;
                p.clone()
            };
            presence::broadcast_presence(&client, &relay, &info).await;
            let _ = app.emit("idle-transition", "idle");

            let _ = voice_cmd.send(VoiceCommand::SetMuted(true)).await;
            let _ = app.emit("auto-muted", true);
        } else if idle_secs < HYSTERESIS_SECS && was_idle {
            was_idle = false;

            if presence.lock().await.status != OnlineStatus::Idle {
                continue;
            }

            let info = {
                let mut p = presence.lock().await;
                p.status = OnlineStatus::Online;
                p.clone()
            };
            presence::broadcast_presence(&client, &relay, &info).await;
            let _ = app.emit("idle-transition", "online");
        }
    }
}
