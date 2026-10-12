//! The workspace's moving parts the rest needs: the front-end dev server that serves the
//! launcher, every instance and every profiler, and the build of the app (with the
//! profiler), the relay and the headless device.

use std::time::Duration;

use tokio::net::TcpStream;
use tokio::process::Command;

use crate::launcher::{launcher, BUILD, DEV_SERVER};
use crate::paths;
use crate::process::Status;

/// Where the app's config expects its dev server.
pub const DEV_SERVER_PORT: u16 = 1420;
const READY_POLL: Duration = Duration::from_millis(250);
const DEV_SERVER_WAIT: Duration = Duration::from_secs(60);

/// Whether something answers on loopback `port`.
pub async fn listening(port: u16) -> bool {
    TcpStream::connect(("127.0.0.1", port)).await.is_ok()
}

/// Wait until loopback `port` answers or `process` ends, for up to `wait`.
pub async fn wait_for_port(port: u16, process: &str, wait: Duration) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + wait;
    while tokio::time::Instant::now() < deadline {
        if listening(port).await {
            return Ok(());
        }
        if launcher().processes.status(process) != Status::Running {
            return Err(format!("{process} stopped before it was ready; see its log"));
        }
        tokio::time::sleep(READY_POLL).await;
    }
    Err(format!("{process} was not ready within {} s", wait.as_secs()))
}

/// Start the dev server in devtools mode, unless one already runs on its port.
pub async fn ensure_dev_server() -> Result<(), String> {
    if listening(DEV_SERVER_PORT).await {
        return Ok(());
    }
    let mut command = Command::new("node");
    command
        .args(["node_modules/vite/bin/vite.js", "--mode", "devtools", "--strictPort", "--port", &DEV_SERVER_PORT.to_string()])
        .current_dir(paths::app());
    launcher().processes.spawn(DEV_SERVER, command, false, None)?;
    wait_for_port(DEV_SERVER_PORT, DEV_SERVER, DEV_SERVER_WAIT).await
}

/// Build what the launcher runs. Quick when nothing changed; one build at a time.
pub async fn build() -> Result<(), String> {
    let launcher = launcher();
    let _building = launcher.building.lock().await;
    let mut command = Command::new("cargo");
    command
        .args(["build", "-p", "ghost-app", "-p", "ghost-relay", "-p", "ghost-node", "--features", "ghost-app/devtools"])
        .current_dir(paths::repo());
    launcher.processes.spawn(BUILD, command, false, None)?;
    match launcher.processes.wait(BUILD).await {
        Status::Exited { code: Some(0) } => Ok(()),
        _ => Err("the build failed; see its log".into()),
    }
}
