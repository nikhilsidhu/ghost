//! The processes the launcher runs (the dev server, builds, relays, app instances, test
//! callers): each one's state, its recent output for the logs view, and stopping it. Every
//! child dies with the launcher.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{ChildStdin, Command};
use tokio::sync::{oneshot, watch};

/// Lines of output kept per process.
const LOG_LINES: usize = 5000;
/// Sent with each line of output, for the logs view.
pub const LOG_EVENT: &str = "launcher-log";
/// Sent whenever a process starts or stops, or anything else the page shows changes, so
/// it reloads what it shows.
pub const CHANGED_EVENT: &str = "launcher-changed";
/// Between one run's output and the next's in a log.
const RESTART_MARK: &str = "──── started again ────";

/// Told each line a process writes to its standard output.
pub type LineHandler = Box<dyn Fn(&str) + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Status {
    Stopped,
    Running,
    Exited { code: Option<i32> },
    Failed { message: String },
}

impl Status {
    /// Whether it ended badly: failing to start or run, or exiting with an error or by a
    /// signal. A clean exit is someone closing the app, and stopping is the launcher's.
    pub fn is_failure(&self) -> bool {
        matches!(self, Status::Failed { .. }) || matches!(self, Status::Exited { code } if *code != Some(0))
    }
}

#[derive(Clone, Serialize)]
struct LogLine<'a> {
    process: &'a str,
    line: &'a str,
}

struct Entry {
    status: Status,
    log: VecDeque<String>,
    stop: Option<oneshot::Sender<()>>,
    /// True once the process has exited.
    exited: watch::Receiver<bool>,
}

pub struct Processes {
    app: AppHandle,
    entries: Mutex<HashMap<String, Entry>>,
}

impl Processes {
    pub fn new(app: AppHandle) -> Self {
        Self { app, entries: Mutex::default() }
    }

    pub fn changed(&self) {
        let _ = self.app.emit(CHANGED_EVENT, ());
    }

    fn record(&self, id: &str, line: String) {
        let _ = self.app.emit(LOG_EVENT, LogLine { process: id, line: &line });
        let mut entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.get_mut(id) {
            if entry.log.len() == LOG_LINES {
                entry.log.pop_front();
            }
            entry.log.push_back(line);
        }
    }

    /// Run `command` as process `id`, replacing a finished one of that name. Each line it
    /// writes goes to its log, and its standard output to `on_line` as well. With
    /// `stdin`, the caller gets the process's input to write to.
    pub fn spawn(
        &'static self,
        id: &str,
        mut command: Command,
        stdin: bool,
        on_line: Option<LineHandler>,
    ) -> Result<Option<ChildStdin>, String> {
        if self.status(id) == Status::Running {
            return Err(format!("{id} is already running"));
        }
        command.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).kill_on_drop(true);
        command.stdin(if stdin { std::process::Stdio::piped() } else { std::process::Stdio::null() });
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                let message = format!("start: {e}");
                self.set_status(id, Status::Failed { message: message.clone() });
                return Err(message);
            }
        };
        let (stop, stopped) = oneshot::channel();
        let (exited_tx, exited) = watch::channel(false);
        {
            let mut entries = self.entries.lock().unwrap();
            // A restarted process keeps its earlier output, marked off.
            let mut log = entries.remove(id).map(|entry| entry.log).unwrap_or_default();
            if !log.is_empty() {
                log.push_back(RESTART_MARK.to_string());
            }
            entries.insert(id.to_string(), Entry { status: Status::Running, log, stop: Some(stop), exited });
        }
        self.changed();

        let on_line = Arc::new(on_line);
        if let Some(stdout) = child.stdout.take() {
            self.read(id, stdout, on_line.clone());
        }
        if let Some(stderr) = child.stderr.take() {
            self.read(id, stderr, Arc::new(None));
        }
        let input = child.stdin.take();
        let id = id.to_string();
        tokio::spawn(async move {
            let status = tokio::select! {
                result = child.wait() => match result {
                    Ok(status) => Status::Exited { code: status.code() },
                    Err(e) => Status::Failed { message: e.to_string() },
                },
                _ = stopped => {
                    let _ = child.kill().await;
                    Status::Stopped
                }
            };
            self.set_status(&id, status);
            let _ = exited_tx.send(true);
        });
        Ok(input)
    }

    fn read(&'static self, id: &str, stream: impl AsyncRead + Unpin + Send + 'static, on_line: Arc<Option<LineHandler>>) {
        let id = id.to_string();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stream).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if let Some(on_line) = on_line.as_ref() {
                    on_line(&line);
                }
                self.record(&id, line);
            }
        });
    }

    fn set_status(&self, id: &str, status: Status) {
        {
            let mut entries = self.entries.lock().unwrap();
            match entries.get_mut(id) {
                Some(entry) => entry.status = status,
                None => {
                    let (_, exited) = watch::channel(true);
                    entries.insert(id.to_string(), Entry { status, log: VecDeque::new(), stop: None, exited });
                }
            }
        }
        self.changed();
    }

    /// Show work the launcher does itself (using a blueprint) as process `id`, with
    /// `line` for its log and `end` when it is done.
    pub fn begin_task(&self, id: &str) {
        let (_, exited) = watch::channel(false);
        {
            let mut entries = self.entries.lock().unwrap();
            let mut log = entries.remove(id).map(|entry| entry.log).unwrap_or_default();
            if !log.is_empty() {
                log.push_back(RESTART_MARK.to_string());
            }
            entries.insert(id.to_string(), Entry { status: Status::Running, log, stop: None, exited });
        }
        self.changed();
    }

    pub fn line(&self, id: &str, line: impl Into<String>) {
        self.record(id, line.into());
    }

    pub fn end_task(&self, id: &str, result: &Result<(), String>) {
        let status = match result {
            Ok(()) => Status::Exited { code: Some(0) },
            Err(e) => {
                self.record(id, format!("failed: {e}"));
                Status::Failed { message: e.clone() }
            }
        };
        self.set_status(id, status);
    }

    pub fn status(&self, id: &str) -> Status {
        self.entries.lock().unwrap().get(id).map_or(Status::Stopped, |entry| entry.status.clone())
    }

    pub fn log(&self, id: &str) -> Vec<String> {
        self.entries.lock().unwrap().get(id).map_or_else(Vec::new, |entry| entry.log.iter().cloned().collect())
    }

    /// Every process that ended badly, with its last line of output.
    pub fn failures(&self) -> Vec<(String, Status, Option<String>)> {
        let entries = self.entries.lock().unwrap();
        let mut failures: Vec<_> = entries
            .iter()
            .filter(|(_, entry)| entry.status.is_failure())
            .map(|(id, entry)| (id.clone(), entry.status.clone(), entry.log.back().cloned()))
            .collect();
        failures.sort_by(|a, b| a.0.cmp(&b.0));
        failures
    }

    /// Drop stopped process `id` and its log, as what it ran for goes away.
    pub fn forget(&self, id: &str) {
        let removed = {
            let mut entries = self.entries.lock().unwrap();
            let stopped = entries.get(id).is_some_and(|entry| entry.status != Status::Running);
            stopped && entries.remove(id).is_some()
        };
        if removed {
            self.changed();
        }
    }

    /// Wait for process `id` to exit by itself, returning how it ended.
    pub async fn wait(&self, id: &str) -> Status {
        let exited = self.entries.lock().unwrap().get(id).map(|entry| entry.exited.clone());
        if let Some(mut exited) = exited {
            let _ = exited.wait_for(|done| *done).await;
        }
        self.status(id)
    }

    /// Stop process `id` and wait until it is gone.
    pub async fn stop(&self, id: &str) {
        let stop = self.entries.lock().unwrap().get_mut(id).and_then(|entry| entry.stop.take());
        if let Some(stop) = stop {
            let _ = stop.send(());
            self.wait(id).await;
        }
    }

    /// Stop everything, as the launcher quits.
    pub async fn stop_all(&self) {
        let ids: Vec<String> = self.entries.lock().unwrap().keys().cloned().collect();
        for id in ids {
            self.stop(&id).await;
        }
    }
}
