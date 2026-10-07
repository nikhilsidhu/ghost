//! The shipped binaries as separate processes: a relay on its SQLite file and headless
//! devices on their data directories, killed with SIGKILL and restarted on the same
//! state. Catches what in-process tests cannot: the binaries' start-up wiring and
//! durability across a hard kill.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc;

/// How long to wait for a reply, an event or a relay to come up.
const WAIT: Duration = Duration::from_secs(20);

/// The relay binary, built on first use (integration tests only get their own
/// package's binaries built for them).
fn relay_binary() -> PathBuf {
    static BUILT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
            let status = std::process::Command::new(cargo)
                .args(["build", "-p", "ghost-relay", "--bin", "ghost-relay"])
                .status()
                .expect("run cargo build for ghost-relay");
            assert!(status.success(), "building ghost-relay failed");
            // target/<profile>/deps/<this test> → target/<profile>/ghost-relay
            let exe = std::env::current_exe().unwrap();
            exe.parent().and_then(Path::parent).unwrap().join("ghost-relay")
        })
        .clone()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A relay process serving on a fixed port from a database file.
struct RelayProcess {
    child: Child,
    port: u16,
    db_path: PathBuf,
}

impl RelayProcess {
    async fn start(db_path: &Path, port: u16) -> Self {
        let child = Command::new(relay_binary())
            .env("GHOST_PORT", port.to_string())
            .env("GHOST_VOICE_PORT", "0")
            .env("GHOST_DB_PATH", db_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn ghost-relay");
        let deadline = tokio::time::Instant::now() + WAIT;
        while tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err() {
            assert!(tokio::time::Instant::now() < deadline, "relay never started listening");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Self { child, port, db_path: db_path.to_path_buf() }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// SIGKILL, then start again on the same port and database.
    async fn crash_and_restart(&mut self) {
        self.child.kill().await.unwrap();
        *self = Self::start(&self.db_path, self.port).await;
    }
}

/// A `ghost-node` process and what it has said so far.
struct NodeProcess {
    name: &'static str,
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::UnboundedReceiver<Value>,
    seen: Vec<Value>,
    next_id: u64,
    data_dir: PathBuf,
    relay_url: String,
}

impl NodeProcess {
    async fn spawn(name: &'static str, data_dir: &Path, relay_url: &str, create: bool) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ghost-node"));
        command.arg("--data-dir").arg(data_dir).arg("--relay").arg(relay_url);
        if create {
            command.arg("--create").arg(name);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn ghost-node");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                if let Ok(value) = serde_json::from_str::<Value>(&line) {
                    let _ = tx.send(value);
                }
            }
        });
        let mut node = Self {
            name,
            child,
            stdin,
            lines,
            seen: Vec::new(),
            next_id: 1,
            data_dir: data_dir.to_path_buf(),
            relay_url: relay_url.to_string(),
        };
        node.expect_event("ready", |v| v["event"] == "ready").await;
        node
    }

    /// SIGKILL the process; `restart` brings it back from its data directory.
    async fn kill(&mut self) {
        self.child.kill().await.unwrap();
    }

    async fn restart(&mut self) {
        let (dir, url) = (self.data_dir.clone(), self.relay_url.clone());
        *self = Self::spawn(self.name, &dir, &url, false).await;
    }

    async fn next_line(&mut self, what: &str) -> Value {
        match tokio::time::timeout(WAIT, self.lines.recv()).await {
            Ok(Some(line)) => line,
            Ok(None) => panic!("{} exited while waiting for {what}", self.name),
            Err(_) => panic!("{} never sent {what}; it sent: {:#?}", self.name, self.seen),
        }
    }

    /// Send a command and return its `ok` reply, keeping events that arrive meanwhile.
    async fn request(&mut self, mut command: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        command["id"] = json!(id);
        let mut line = command.to_string().into_bytes();
        line.push(b'\n');
        self.stdin.write_all(&line).await.unwrap();
        loop {
            let value = self.next_line(&format!("a reply to {command}")).await;
            if value["id"] == json!(id) {
                if let Some(error) = value.get("error") {
                    panic!("{} refused {command}: {error}", self.name);
                }
                return value["ok"].clone();
            }
            self.seen.push(value);
        }
    }

    /// Wait for an event (already seen, or arriving) that `matches` accepts, and use it up.
    async fn expect_event(&mut self, what: &str, matches: impl Fn(&Value) -> bool) -> Value {
        if let Some(pos) = self.seen.iter().position(&matches) {
            return self.seen.remove(pos);
        }
        loop {
            let value = self.next_line(what).await;
            if matches(&value) {
                return value;
            }
            self.seen.push(value);
        }
    }

    async fn expect_message(&mut self, text: &str) {
        self.expect_event(&format!("the message {text:?}"), |v| v["event"] == "message" && v["text"] == text).await;
    }
}

/// Alice's server with Bob in it, both as processes. Returns (server, general channel).
async fn server_with_two(alice: &mut NodeProcess, bob: &mut NodeProcess) -> (String, String) {
    let created = alice.request(json!({ "cmd": "create_server", "name": "club" })).await;
    let (server, general) = (created["server"].as_str().unwrap().to_string(), created["general"].as_str().unwrap().to_string());
    let invite = alice.request(json!({ "cmd": "invite", "server": server })).await;
    bob.request(json!({ "cmd": "join", "token": invite["token"], "key": invite["key"] })).await;
    let s = server.clone();
    alice.expect_event("Bob's join", move |v| v["event"] == "server_changed" && v["server"] == s.as_str()).await;
    (server, general)
}

#[tokio::test]
async fn messages_survive_the_relay_being_killed_and_restarted() {
    let dir = tempfile::tempdir().unwrap();
    let mut relay = RelayProcess::start(&dir.path().join("relay.db"), free_port()).await;
    let mut alice = NodeProcess::spawn("alice", &dir.path().join("alice"), &relay.url(), true).await;
    let mut bob = NodeProcess::spawn("bob", &dir.path().join("bob"), &relay.url(), true).await;
    let (server, general) = server_with_two(&mut alice, &mut bob).await;

    alice.request(json!({ "cmd": "say", "server": server, "channel": general, "text": "before the crash" })).await;
    bob.expect_message("before the crash").await;

    // The relay dies mid-session and comes back on the same database; the devices
    // reconnect by themselves and the group carries on.
    relay.crash_and_restart().await;
    bob.expect_event("reconnecting", |v| v["event"] == "relay_connectivity" && v["connected"] == true).await;
    alice.expect_event("reconnecting", |v| v["event"] == "relay_connectivity" && v["connected"] == true).await;
    alice.request(json!({ "cmd": "say", "server": server, "channel": general, "text": "after the crash" })).await;
    bob.expect_message("after the crash").await;
}

#[tokio::test]
async fn a_device_killed_mid_session_resumes_from_its_data_directory() {
    let dir = tempfile::tempdir().unwrap();
    let relay = RelayProcess::start(&dir.path().join("relay.db"), free_port()).await;
    let mut alice = NodeProcess::spawn("alice", &dir.path().join("alice"), &relay.url(), true).await;
    let mut bob = NodeProcess::spawn("bob", &dir.path().join("bob"), &relay.url(), true).await;
    let (server, general) = server_with_two(&mut alice, &mut bob).await;

    // Bob's process is killed; what Alice says meanwhile waits on the relay.
    bob.kill().await;
    alice.request(json!({ "cmd": "say", "server": server, "channel": general, "text": "while bob was down" })).await;
    bob.restart().await;
    bob.expect_message("while bob was down").await;
    bob.request(json!({ "cmd": "say", "server": server, "channel": general, "text": "bob is back" })).await;
    alice.expect_message("bob is back").await;
}
