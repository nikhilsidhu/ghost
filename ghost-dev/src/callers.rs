//! Test callers: headless devices (ghost-node) that join a profile's call from an invite
//! its instance makes, at home on either relay, each playing its own tone as a voice:
//! steadily, in talk spurts, or not at all. They come and go with the launcher.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::process::{ChildStdin, Command};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::launcher::{caller_process, launcher};
use crate::paths;
use crate::profiles;
use crate::relays;
use crate::workspace::build;

/// How long a caller may take to answer one of its commands (joining a server included).
const REPLY_WAIT: Duration = Duration::from_secs(30);
/// Loud enough to send through voice activity, quiet enough to talk over.
const AMPLITUDE: f32 = 0.2;
const BASE_TONE_HZ: f32 = 300.0;
const TONE_STEP_HZ: f32 = 70.0;
/// Tones before they repeat, kept apart so callers can be told apart by ear.
const DISTINCT_TONES: u32 = 8;
/// A talk spurt and the pause after it.
const SPURT: Duration = Duration::from_millis(2000);
const PAUSE: Duration = Duration::from_millis(1500);

/// How a test caller's synthetic microphone sounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Voice {
    Steady,
    Spurts,
    Silent,
}

pub struct Caller {
    pub id: u32,
    pub name: String,
    pub relay: String,
    pub profile: String,
    voice: Mutex<Voice>,
    fingerprint: Mutex<Option<String>>,
    tone_hz: f32,
    stdin: tokio::sync::Mutex<Option<ChildStdin>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>,
    next_request: AtomicU64,
    spurts: Mutex<Option<JoinHandle<()>>>,
}

impl Caller {
    pub fn voice(&self) -> Voice {
        *self.voice.lock().unwrap()
    }

    pub fn fingerprint(&self) -> Option<String> {
        self.fingerprint.lock().unwrap().clone()
    }

    /// A reply to one of our commands, among the device's output lines.
    fn on_line(&self, line: &str) {
        let Ok(reply) = serde_json::from_str::<Value>(line) else { return };
        let Some(id) = reply["id"].as_u64() else { return };
        let Some(waiting) = self.pending.lock().unwrap().remove(&id) else { return };
        let _ = waiting.send(match reply.get("error") {
            Some(error) => Err(error.as_str().unwrap_or("failed").to_string()),
            None => Ok(reply["ok"].clone()),
        });
    }

    async fn send(&self, mut request: Value) -> Result<Value, String> {
        let id = self.next_request.fetch_add(1, Ordering::Relaxed);
        request["id"] = json!(id);
        let (reply, answered) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, reply);
        let mut line = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
        line.push(b'\n');
        {
            let mut stdin = self.stdin.lock().await;
            let stdin = stdin.as_mut().ok_or("the caller has no input")?;
            stdin.write_all(&line).await.map_err(|e| format!("talk to the caller: {e}"))?;
        }
        tokio::time::timeout(REPLY_WAIT, answered).await.map_err(|_| "the caller did not answer".to_string())?.map_err(|_| "the caller stopped".to_string())?
    }

    async fn tone(&self, amplitude: f32) -> Result<(), String> {
        self.send(json!({ "cmd": "tone", "frequency": self.tone_hz, "amplitude": amplitude })).await.map(|_| ())
    }

    /// Make the microphone sound like `voice` from now on.
    async fn speak(self: &Arc<Self>, voice: Voice) -> Result<(), String> {
        if let Some(spurts) = self.spurts.lock().unwrap().take() {
            spurts.abort();
        }
        *self.voice.lock().unwrap() = voice;
        match voice {
            Voice::Steady => self.tone(AMPLITUDE).await,
            Voice::Silent => self.tone(0.0).await,
            Voice::Spurts => {
                let caller = self.clone();
                *self.spurts.lock().unwrap() = Some(tokio::spawn(async move {
                    loop {
                        let _ = caller.tone(AMPLITUDE).await;
                        tokio::time::sleep(SPURT).await;
                        let _ = caller.tone(0.0).await;
                        tokio::time::sleep(PAUSE).await;
                    }
                }));
                Ok(())
            }
        }
    }
}

/// Start a test caller at home on relay `relay` and bring it into profile `profile`'s call.
pub async fn add(profile: &str, relay: &str, voice: Voice) -> Result<u32, String> {
    let launcher = launcher();
    let home = launcher.settings.lock().unwrap().relay(relay)?.url();
    build().await?;
    relays::start(relay).await?;
    let invite = profiles::request(profile, json!({ "cmd": "test_call_invite" })).await?;

    let id = launcher.next_caller.fetch_add(1, Ordering::Relaxed);
    let caller = Arc::new(Caller {
        id,
        name: format!("test caller {id}"),
        relay: relay.to_string(),
        profile: profile.to_string(),
        voice: Mutex::new(voice),
        fingerprint: Mutex::new(None),
        tone_hz: BASE_TONE_HZ + TONE_STEP_HZ * (id % DISTINCT_TONES) as f32,
        stdin: tokio::sync::Mutex::new(None),
        pending: Mutex::default(),
        next_request: AtomicU64::new(1),
        spurts: Mutex::new(None),
    });
    let dir = paths::caller(id);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut command = Command::new(paths::binary("ghost-node"));
    command.arg("--data-dir").arg(&dir).args(["--relay", &home, "--create", &caller.name]);
    let listener = caller.clone();
    let stdin = launcher.processes.spawn(&caller_process(id), command, true, Some(Box::new(move |line| listener.on_line(line))))?;
    *caller.stdin.lock().await = stdin;

    let joined = async {
        let identity = caller.send(json!({ "cmd": "identity" })).await?;
        *caller.fingerprint.lock().unwrap() = identity["fingerprint"].as_str().map(str::to_string);
        // Through the relay hosting the server when that is not the caller's home.
        let hosting = invite["relay"].as_str().filter(|url| url.trim_end_matches('/') != home);
        caller.send(json!({ "cmd": "join", "token": invite["token"], "key": invite["key"], "relay": hosting })).await?;
        caller.send(json!({ "cmd": "join_voice", "server": invite["server"], "channel": invite["channel"] })).await?;
        caller.speak(voice).await
    };
    if let Err(e) = joined.await {
        launcher.processes.stop(&caller_process(id)).await;
        let _ = std::fs::remove_dir_all(&dir);
        return Err(e);
    }
    launcher.callers.lock().unwrap().insert(id, caller);
    Ok(id)
}

pub async fn set_voice(id: u32, voice: Voice) -> Result<(), String> {
    let caller = launcher().callers.lock().unwrap().get(&id).cloned().ok_or("no such caller")?;
    caller.speak(voice).await
}

/// Take caller `id` out of its call and delete it.
pub async fn remove(id: u32) {
    let launcher = launcher();
    let Some(caller) = launcher.callers.lock().unwrap().remove(&id) else { return };
    if let Some(spurts) = caller.spurts.lock().unwrap().take() {
        spurts.abort();
    }
    let _ = caller.send(json!({ "cmd": "leave_voice" })).await;
    launcher.processes.stop(&caller_process(id)).await;
    launcher.processes.forget(&caller_process(id));
    let _ = std::fs::remove_dir_all(paths::caller(id));
}
