//! What the launcher page shows: every process with its state, where each profile is in a
//! call, what ended badly, the blueprints, and a call's participants with the network each
//! one has.

use std::collections::HashMap;
use std::time::Duration;

use ghost_media::netem::Impairment;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::callers::Voice;
use crate::launcher::{caller_process, launcher, profile_process, relay_process, BUILD, DEV_SERVER};
use crate::paths;
use crate::process::Status;
use crate::profiles;
use crate::relays;
use crate::blueprints::{self, BlueprintView, BLUEPRINT_PROCESS};

/// Characters of a fingerprint shown for someone the launcher cannot name.
const FINGERPRINT_CHARS: usize = 8;

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct RelayView {
    name: String,
    url: String,
    port: u16,
    voice_port: u16,
    process: String,
    status: Status,
}

/// The server and channel of a call, by name.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct CallPlace {
    server: String,
    channel: String,
}

impl CallPlace {
    /// From an instance's answer to `call`.
    pub fn from_call(call: &Value) -> Self {
        let name = |key: &str| call[key].as_str().unwrap_or_default().to_string();
        Self { server: name("server_name"), channel: name("channel_name") }
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct ProfileView {
    name: String,
    relay: String,
    process: String,
    status: Status,
    data_dir: String,
    /// Where it is in a call, when it is.
    call: Option<CallPlace>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct CallerView {
    id: u32,
    name: String,
    relay: String,
    /// Whose call it joined.
    profile: String,
    voice: Voice,
    process: String,
    status: Status,
}

/// A process the launcher runs for itself: the dev server, the build, using or saving a
/// blueprint.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct ProcessView {
    process: String,
    status: Status,
}

impl ProcessView {
    fn of(process: &str) -> Self {
        Self { process: process.to_string(), status: launcher().processes.status(process) }
    }
}

/// A process that ended badly.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct FailureView {
    process: String,
    status: Status,
    last_line: Option<String>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct LauncherView {
    dev_server: ProcessView,
    build: ProcessView,
    blueprint: ProcessView,
    relays: Vec<RelayView>,
    profiles: Vec<ProfileView>,
    callers: Vec<CallerView>,
    failures: Vec<FailureView>,
    blueprints: Vec<BlueprintView>,
}

pub fn launcher_view() -> LauncherView {
    let launcher = launcher();
    let settings = launcher.settings.lock().unwrap().clone();
    let relays = settings
        .relays
        .iter()
        .map(|relay| RelayView {
            name: relay.name.clone(),
            url: relay.url(),
            port: relay.port,
            voice_port: relay.voice_port,
            process: relay_process(&relay.name),
            status: launcher.processes.status(&relay_process(&relay.name)),
        })
        .collect();
    let calls = launcher.calls.lock().unwrap().clone();
    let profiles = settings
        .profiles
        .iter()
        .map(|profile| ProfileView {
            name: profile.name.clone(),
            relay: profile.relay.clone(),
            process: profile_process(&profile.name),
            status: launcher.processes.status(&profile_process(&profile.name)),
            data_dir: paths::profile(&profile.name).display().to_string(),
            call: calls.get(&profile.name).cloned(),
        })
        .collect();
    let mut callers: Vec<CallerView> = launcher
        .callers
        .lock()
        .unwrap()
        .values()
        .map(|caller| CallerView {
            id: caller.id,
            name: caller.name.clone(),
            relay: caller.relay.clone(),
            profile: caller.profile.clone(),
            voice: caller.voice(),
            process: caller_process(caller.id),
            status: launcher.processes.status(&caller_process(caller.id)),
        })
        .collect();
    callers.sort_by_key(|caller| caller.id);
    let failures = launcher.processes.failures().into_iter().map(|(process, status, last_line)| FailureView { process, status, last_line }).collect();
    LauncherView {
        dev_server: ProcessView::of(DEV_SERVER),
        build: ProcessView::of(BUILD),
        blueprint: ProcessView::of(BLUEPRINT_PROCESS),
        relays,
        profiles,
        callers,
        failures,
        blueprints: blueprints::views(),
    }
}

/// A network setting as the page edits it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct NetworkView {
    loss_percent: f64,
    delay_ms: u32,
    jitter_ms: u32,
}

impl From<Impairment> for NetworkView {
    fn from(i: Impairment) -> Self {
        Self { loss_percent: i.loss * 100.0, delay_ms: i.delay.as_millis() as u32, jitter_ms: i.jitter.as_millis() as u32 }
    }
}

impl From<NetworkView> for Impairment {
    fn from(n: NetworkView) -> Self {
        Self {
            loss: (n.loss_percent / 100.0).clamp(0.0, 1.0),
            delay: Duration::from_millis(n.delay_ms.into()),
            jitter: Duration::from_millis(n.jitter_ms.into()),
        }
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum ParticipantKind {
    /// The profile whose call this is.
    Own,
    Profile,
    Caller,
    /// Someone the launcher did not start.
    Other,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct ParticipantView {
    slot: u32,
    name: String,
    kind: ParticipantKind,
    /// The test caller it is, when it is one.
    caller: Option<u32>,
    network: NetworkView,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
pub struct CallView {
    /// The launcher relay hosting the call; none when it is a relay the launcher does not run.
    relay: Option<String>,
    participants: Vec<ParticipantView>,
}

/// Profile `profile`'s call: everyone in it by slot, named where the launcher started
/// them, with the network each one has on the hosting relay.
pub async fn call_view(profile: &str) -> Result<CallView, String> {
    let call = profiles::request(profile, json!({ "cmd": "call" })).await?;
    let launcher = launcher();
    let relay = call["relay"].as_str().and_then(|url| launcher.settings.lock().unwrap().relay_at(url).map(|relay| relay.name.clone()));
    // Who each account is: a profile, or a test caller by id.
    let mut names: HashMap<String, (String, Option<u32>)> = HashMap::new();
    for (name, fingerprint) in launcher.fingerprints.lock().unwrap().iter() {
        names.insert(fingerprint.clone(), (name.clone(), None));
    }
    for caller in launcher.callers.lock().unwrap().values() {
        if let Some(fingerprint) = caller.fingerprint() {
            names.insert(fingerprint, (caller.name.clone(), Some(caller.id)));
        }
    }
    let network = |slot: u32| relay.as_deref().map(|relay| relays::impairment(relay, slot)).unwrap_or_default().into();
    let mut participants = Vec::new();
    if let Some(slot) = call["own_slot"].as_u64() {
        let slot = slot as u32;
        participants.push(ParticipantView { slot, name: profile.to_string(), kind: ParticipantKind::Own, caller: None, network: network(slot) });
    }
    for peer in call["peers"].as_array().into_iter().flatten() {
        let (Some(slot), Some(fingerprint)) = (peer["slot"].as_u64(), peer["fingerprint"].as_str()) else { continue };
        let slot = slot as u32;
        let (name, kind, caller) = match names.get(fingerprint) {
            Some((name, Some(id))) => (name.clone(), ParticipantKind::Caller, Some(*id)),
            Some((name, None)) => (name.clone(), ParticipantKind::Profile, None),
            None => (fingerprint.chars().take(FINGERPRINT_CHARS).collect(), ParticipantKind::Other, None),
        };
        participants.push(ParticipantView { slot, name, kind, caller, network: network(slot) });
    }
    participants.sort_by_key(|participant| participant.slot);
    Ok(CallView { relay, participants })
}

/// The output of process `process`, for the logs view.
pub fn log(process: &str) -> Vec<String> {
    launcher().processes.log(process)
}
