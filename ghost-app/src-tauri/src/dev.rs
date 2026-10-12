//! How the Ghost Dev launcher reaches an app instance it started, in debug builds. The
//! launcher names the instance's profile, where its window opens, and a loopback port in
//! its environment; the instance listens there and answers one JSON request per connection
//! with one JSON reply: who it is, where its window is, move or focus its window, open its
//! profiler, describe its call, or make an invite into its call for a test caller.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, LogicalPosition, LogicalSize, Manager};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use crate::state::AppState;

/// The launcher profile this instance runs as.
pub const PROFILE_ENV: &str = "GHOST_PROFILE";
/// The loopback port the launcher reaches this instance on.
pub const CONTROL_PORT_ENV: &str = "GHOST_DEV_CONTROL_PORT";
/// Where the main window opens, as `x,y,width,height` in logical pixels.
pub const WINDOW_BOUNDS_ENV: &str = "GHOST_WINDOW_BOUNDS";
const MAIN_WINDOW: &str = "main";

/// What the launcher can ask.
#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Request {
    /// This instance's account fingerprint.
    Identity,
    /// Where the main window is.
    Window,
    /// Move the main window.
    Place(Bounds),
    Focus,
    OpenProfiler,
    /// Who is in this instance's call, by media slot, and the relay hosting it.
    Call,
    /// An invite into the server of this instance's call, and the call's channel.
    TestCallInvite,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Reply {
    Ok(Value),
    Error(String),
}

/// A window's place on its display, in logical pixels.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Bounds {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// The profile this instance runs as, when the launcher started it.
pub fn profile() -> Option<String> {
    std::env::var(PROFILE_ENV).ok().filter(|name| !name.is_empty())
}

/// Where the launcher wants the main window to open.
pub fn window_bounds() -> Option<Bounds> {
    let value = std::env::var(WINDOW_BOUNDS_ENV).ok()?;
    let numbers: Vec<f64> = value.split(',').map(|part| part.trim().parse().ok()).collect::<Option<_>>()?;
    match numbers[..] {
        [x, y, width, height] => Some(Bounds { x, y, width, height }),
        _ => None,
    }
}

async fn handle(app: &AppHandle, request: Request) -> Result<Value, String> {
    let state = app.state::<AppState>();
    let main_window = || app.get_webview_window(MAIN_WINDOW).ok_or("no main window");
    match request {
        Request::Identity => Ok(json!({ "fingerprint": hex::encode(state.client.lock().await.identity().fingerprint) })),
        Request::Window => {
            let window = main_window()?;
            let scale = window.scale_factor().map_err(|e| e.to_string())?;
            let position = window.outer_position().map_err(|e| e.to_string())?.to_logical::<f64>(scale);
            let size = window.outer_size().map_err(|e| e.to_string())?.to_logical::<f64>(scale);
            Ok(json!(Bounds { x: position.x, y: position.y, width: size.width, height: size.height }))
        }
        Request::Place(bounds) => {
            let window = main_window()?;
            let _ = window.unminimize();
            window.set_size(LogicalSize::new(bounds.width, bounds.height)).map_err(|e| e.to_string())?;
            window.set_position(LogicalPosition::new(bounds.x, bounds.y)).map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        Request::Focus => {
            let window = main_window()?;
            let _ = window.unminimize();
            window.show().map_err(|e| e.to_string())?;
            window.set_focus().map_err(|e| e.to_string())?;
            Ok(Value::Null)
        }
        #[cfg(feature = "devtools")]
        Request::OpenProfiler => crate::devtools::open_profiler(app, false).map(|()| Value::Null),
        #[cfg(not(feature = "devtools"))]
        Request::OpenProfiler => Err("this instance was built without the profiler".into()),
        #[cfg(feature = "devtools")]
        Request::Call => {
            let slots = state.voice.call_slots().ok_or("not in a call")?;
            let (own, hosting, server_name, channel_name) = {
                let client = state.client.lock().await;
                let store = client.store();
                (
                    client.identity().fingerprint,
                    ghost_core::flows::server_relay_url(&client, &slots.server_id),
                    store.get_server(&slots.server_id).map(|server| server.name).unwrap_or_default(),
                    store.get_channel(&slots.channel_id).map(|channel| channel.name).unwrap_or_default(),
                )
            };
            let relay = match hosting {
                Some(url) => url,
                None => state.relay_url(),
            };
            let peers: Vec<Value> = slots.peers.iter().map(|(slot, fp)| json!({ "slot": slot, "fingerprint": hex::encode(fp) })).collect();
            Ok(json!({
                "relay": relay,
                "server": hex::encode(slots.server_id),
                "channel": hex::encode(slots.channel_id),
                "server_name": server_name,
                "channel_name": channel_name,
                "own_slot": slots.own_slot,
                "own_fingerprint": hex::encode(own),
                "peers": peers,
            }))
        }
        #[cfg(feature = "devtools")]
        Request::TestCallInvite => {
            let slots = state.voice.call_slots().ok_or("not in a call")?;
            let invite = crate::commands::issue_invite(&state, &slots.server_id).await.map_err(|e| e.to_string())?;
            Ok(json!({
                "relay": invite.relay_url,
                "token": invite.token,
                "key": hex::encode(invite.key),
                "server": hex::encode(slots.server_id),
                "channel": hex::encode(slots.channel_id),
            }))
        }
        #[cfg(not(feature = "devtools"))]
        Request::Call | Request::TestCallInvite => Err("calls are described only in builds with the profiler".into()),
    }
}

/// Listen for the launcher, when it started this instance. Called once at startup.
pub fn serve(app: &AppHandle) {
    let Some(port) = std::env::var(CONTROL_PORT_ENV).ok().and_then(|port| port.parse::<u16>().ok()) else { return };
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let listener = match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => listener,
            Err(e) => {
                tracing::warn!("dev: listen for the launcher on {port}: {e}");
                return;
            }
        };
        while let Ok((stream, _)) = listener.accept().await {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let (read, mut write) = stream.into_split();
                let mut line = String::new();
                if BufReader::new(read).read_line(&mut line).await.is_err() || line.is_empty() {
                    return;
                }
                let reply = match serde_json::from_str::<Request>(&line) {
                    Ok(request) => handle(&app, request).await,
                    Err(e) => Err(format!("bad request: {e}")),
                };
                let reply = match reply {
                    Ok(value) => Reply::Ok(value),
                    Err(e) => Reply::Error(e),
                };
                let mut out = serde_json::to_vec(&reply).unwrap_or_default();
                out.push(b'\n');
                let _ = write.write_all(&out).await;
            });
        }
    });
}

/// The launcher profile this instance runs as, for labelling its windows.
#[tauri::command]
#[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
pub fn dev_profile() -> Option<String> {
    profile()
}
