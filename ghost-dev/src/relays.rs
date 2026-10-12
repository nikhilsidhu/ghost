//! The local relays: the real relay binary with its own database, its voice port behind
//! a forwarder the launcher holds, so any caller's network can be made worse mid-call.

use std::sync::Arc;
use std::time::Duration;

use ghost_media::netem::{Forwarder, Impairment};
use tokio::process::Command;

use crate::launcher::{launcher, relay_process};
use crate::paths;
use crate::process::Status;
use crate::workspace::{build, wait_for_port};

const READY_WAIT: Duration = Duration::from_secs(15);

/// Start relay `name` if it is not running.
pub async fn start(name: &str) -> Result<(), String> {
    let launcher = launcher();
    let relay = launcher.settings.lock().unwrap().relay(name)?.clone();
    let process = relay_process(name);
    if launcher.processes.status(&process) == Status::Running {
        return Ok(());
    }
    build().await?;
    let forwarder = Arc::new(Forwarder::bind(u64::from(relay.port)).await.map_err(|e| format!("forwarder: {e}"))?);
    let dir = paths::relay(name);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut command = Command::new(paths::binary("ghost-relay"));
    command
        .env("GHOST_PORT", relay.port.to_string())
        .env("GHOST_VOICE_PORT", relay.voice_port.to_string())
        .env("GHOST_VOICE_PUBLIC_PORT", forwarder.port().to_string())
        .env("GHOST_DB_PATH", dir.join("relay.db"))
        .env("GHOST_PUBLIC_URL", relay.url())
        .current_dir(&dir);
    launcher.processes.spawn(&process, command, false, None)?;
    forwarder.forward_to(([127, 0, 0, 1], relay.voice_port).into());
    launcher.forwarders.lock().unwrap().insert(name.to_string(), forwarder);
    wait_for_port(relay.port, &process, READY_WAIT).await
}

pub async fn stop(name: &str) {
    let launcher = launcher();
    launcher.processes.stop(&relay_process(name)).await;
    launcher.forwarders.lock().unwrap().remove(name);
}

/// Stop relay `name` and delete its database, for a clean start.
pub async fn reset(name: &str) -> Result<(), String> {
    stop(name).await;
    match std::fs::remove_dir_all(paths::relay(name)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
        _ => Ok(()),
    }
}

/// Impair everything to and from whoever holds `slot` in calls on relay `name`.
pub fn impair(name: &str, slot: u32, impairment: Impairment) -> Result<(), String> {
    let forwarders = launcher().forwarders.lock().unwrap();
    let forwarder = forwarders.get(name).ok_or_else(|| format!("relay {name} is not running"))?;
    forwarder.set_slot_impairment(slot, impairment);
    Ok(())
}

/// The impairment set for `slot` on relay `name`.
pub fn impairment(name: &str, slot: u32) -> Impairment {
    launcher().forwarders.lock().unwrap().get(name).and_then(|forwarder| {
        forwarder.slots().into_iter().find(|(seen, _)| *seen == slot).map(|(_, impairment)| impairment)
    }).unwrap_or_default()
}
