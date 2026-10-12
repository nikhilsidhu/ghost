//! Profiles: named accounts that persist between runs, each run as an app instance from
//! the one build, with its own data folder (and so its own webview storage) and home relay.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::process::Command;
use tokio::task::JoinSet;

use crate::control;
use crate::launcher::{launcher, profile_process};
use crate::paths;
use crate::process::Status;
use crate::relays;
use crate::settings::ProfileSettings;
use crate::view::CallPlace;
use crate::windows::{self, Bounds};
use crate::workspace::{build, ensure_dev_server};

/// How long a new instance may take to answer its first request.
const STARTUP_WAIT: Duration = Duration::from_secs(30);
const STARTUP_POLL: Duration = Duration::from_millis(500);
/// Between asks of the running instances for their calls.
const CALL_POLL: Duration = Duration::from_secs(2);
const MAX_NAME: usize = 24;

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_NAME && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

pub fn add(name: &str, relay: &str) -> Result<(), String> {
    if !valid_name(name) {
        return Err(format!("a profile name is up to {MAX_NAME} lowercase letters, digits and dashes"));
    }
    let mut settings = launcher().settings.lock().unwrap();
    settings.relay(relay)?;
    if settings.profile(name).is_ok() {
        return Err(format!("there is already a profile {name}"));
    }
    settings.profiles.push(ProfileSettings { name: name.into(), relay: relay.into() });
    settings.save()
}

/// Stop profile `name`, delete its account and forget it.
pub async fn remove(name: &str) -> Result<(), String> {
    reset(name).await?;
    launcher().processes.forget(&profile_process(name));
    let mut settings = launcher().settings.lock().unwrap();
    settings.profiles.retain(|profile| profile.name != name);
    settings.save()
}

/// Where a starting profile's window opens.
enum Place {
    /// Where the windows already open cover least.
    Freest,
    At(Bounds),
    /// Where the app puts it, when there is no display to measure.
    AppDefault,
}

/// Run profile `name`, starting its home relay first if needed. Its window opens where
/// the windows already open cover least.
pub async fn start(name: &str) -> Result<(), String> {
    launch(name, Place::Freest).await
}

/// Run profile `name` with its window at `bounds`, or where the app puts it.
pub async fn start_at(name: &str, bounds: Option<Bounds>) -> Result<(), String> {
    launch(name, bounds.map_or(Place::AppDefault, Place::At)).await
}

/// Run `names` together, their windows taking a grid in order.
pub async fn start_all(names: &[String]) -> Result<(), String> {
    let places = windows::places(names.len()).unwrap_or_default();
    for (index, name) in names.iter().enumerate() {
        launch(name, places.get(index).map_or(Place::AppDefault, |place| Place::At(*place))).await?;
    }
    Ok(())
}

async fn launch(name: &str, place: Place) -> Result<(), String> {
    let launcher = launcher();
    let profile = launcher.settings.lock().unwrap().profile(name)?.clone();
    let relay = launcher.settings.lock().unwrap().relay(&profile.relay)?.clone();
    let process = profile_process(name);
    if launcher.processes.status(&process) == Status::Running {
        return Ok(());
    }
    build().await?;
    ensure_dev_server().await?;
    relays::start(&relay.name).await?;
    let port = control::free_port()?;
    let dir = paths::profile(name);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut command = Command::new(paths::binary("ghost-app"));
    command
        .env("GHOST_DATA_DIR", &dir)
        .env("GHOST_RELAY_URL", relay.url())
        .env("GHOST_PROFILE", name)
        .env("GHOST_DEV_CONTROL_PORT", port.to_string())
        .current_dir(paths::repo());
    let bounds = match place {
        Place::Freest => windows::next_place(name).await.ok(),
        Place::At(bounds) => Some(bounds),
        Place::AppDefault => None,
    };
    if let Some(bounds) = bounds {
        command.env("GHOST_WINDOW_BOUNDS", bounds.env_value());
    }
    launcher.processes.spawn(&process, command, false, None)?;
    launcher.control_ports.lock().unwrap().insert(name.to_string(), port);
    tokio::spawn(learn_fingerprint(name.to_string()));
    Ok(())
}

/// Ask the new instance for its account until it answers, so callers can be told apart
/// from it in a call.
async fn learn_fingerprint(name: String) {
    let deadline = tokio::time::Instant::now() + STARTUP_WAIT;
    while tokio::time::Instant::now() < deadline {
        if let Ok(identity) = request(&name, json!({ "cmd": "identity" })).await {
            if let Some(fingerprint) = identity["fingerprint"].as_str() {
                launcher().fingerprints.lock().unwrap().insert(name.clone(), fingerprint.to_string());
                return;
            }
        }
        tokio::time::sleep(STARTUP_POLL).await;
    }
}

pub async fn stop(name: &str) {
    let launcher = launcher();
    launcher.processes.stop(&profile_process(name)).await;
    launcher.control_ports.lock().unwrap().remove(name);
    launcher.calls.lock().unwrap().remove(name);
}

/// Stop profile `name` and delete its account and data, keeping the profile.
pub async fn reset(name: &str) -> Result<(), String> {
    stop(name).await;
    launcher().fingerprints.lock().unwrap().remove(name);
    match std::fs::remove_dir_all(paths::profile(name)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
        _ => Ok(()),
    }
}

/// Keep each running profile's call current, asking every instance in turn, so the page
/// shows who is in a call without asking itself. Runs for the launcher's life.
pub async fn watch_calls() {
    let launcher = launcher();
    loop {
        tokio::time::sleep(CALL_POLL).await;
        let names: Vec<String> = launcher.control_ports.lock().unwrap().keys().cloned().collect();
        let mut asks = JoinSet::new();
        for name in names {
            asks.spawn(async move { (request(&name, json!({ "cmd": "call" })).await, name) });
        }
        let mut calls = HashMap::new();
        while let Some(Ok((answer, name))) = asks.join_next().await {
            // An error is mostly "not in a call"; an instance not answering is in none either.
            if let Ok(call) = answer {
                calls.insert(name, CallPlace::from_call(&call));
            }
        }
        let changed = {
            let mut known = launcher.calls.lock().unwrap();
            let changed = *known != calls;
            *known = calls;
            changed
        };
        if changed {
            launcher.processes.changed();
        }
    }
}

/// Send `request` to profile `name`'s running instance.
pub async fn request(name: &str, request: Value) -> Result<Value, String> {
    let port = launcher().control_ports.lock().unwrap().get(name).copied().ok_or_else(|| format!("{name} is not running"))?;
    control::request(port, request).await
}
