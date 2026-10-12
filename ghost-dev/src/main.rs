//! Ghost Dev: the launcher for developing Ghost. It runs the local relays, the app as
//! named profiles with their windows tiled, and test callers, and shows their logs; it
//! starts everything from blueprints, built in or saved from what was set up by hand. Run
//! with `cargo run -p ghost-dev`; it starts the front-end dev server itself when none runs.

mod blueprints;
mod callers;
mod control;
mod launcher;
mod paths;
mod process;
mod profiles;
mod relays;
mod settings;
mod view;
mod windows;
mod workspace;
#[cfg(test)]
mod bindings;

use blueprints::{Preview, Sizes};
use callers::Voice;
use view::{CallView, LauncherView, NetworkView};

#[tauri::command]
fn launcher_view() -> LauncherView {
    view::launcher_view()
}

#[tauri::command]
fn process_log(process: String) -> Vec<String> {
    view::log(&process)
}

#[tauri::command]
async fn rebuild() -> Result<(), String> {
    workspace::build().await
}

#[tauri::command]
async fn relay_start(name: String) -> Result<(), String> {
    relays::start(&name).await
}

#[tauri::command]
async fn relay_stop(name: String) {
    relays::stop(&name).await;
}

#[tauri::command]
async fn relay_reset(name: String) -> Result<(), String> {
    relays::reset(&name).await
}

#[tauri::command]
fn profile_add(name: String, relay: String) -> Result<(), String> {
    profiles::add(&name, &relay)
}

#[tauri::command]
async fn profile_remove(name: String) -> Result<(), String> {
    profiles::remove(&name).await
}

#[tauri::command]
async fn profile_start(name: String) -> Result<(), String> {
    profiles::start(&name).await
}

#[tauri::command]
async fn profile_stop(name: String) {
    profiles::stop(&name).await;
}

#[tauri::command]
async fn profile_reset(name: String) -> Result<(), String> {
    profiles::reset(&name).await
}

/// Ask profile `name`'s instance to `cmd`: focus its window or open its profiler.
#[tauri::command]
async fn profile_window(name: String, cmd: String) -> Result<(), String> {
    match cmd.as_str() {
        "focus" | "open_profiler" => profiles::request(&name, serde_json::json!({ "cmd": cmd })).await.map(|_| ()),
        other => Err(format!("no window command {other}")),
    }
}

#[tauri::command]
async fn call_view(profile: String) -> Result<CallView, String> {
    view::call_view(&profile).await
}

#[tauri::command]
fn set_network(relay: String, slot: u32, network: NetworkView) -> Result<(), String> {
    relays::impair(&relay, slot, network.into())
}

#[tauri::command]
async fn caller_add(profile: String, relay: String, voice: Voice) -> Result<u32, String> {
    callers::add(&profile, &relay, voice).await
}

#[tauri::command]
async fn caller_voice(id: u32, voice: Voice) -> Result<(), String> {
    callers::set_voice(id, voice).await
}

#[tauri::command]
async fn caller_remove(id: u32) {
    callers::remove(id).await;
}

/// Arrange every running profile's window afresh.
#[tauri::command]
async fn windows_tile() -> Result<(), String> {
    windows::tile().await
}

/// Use blueprint `id`, with `sizes` for a built-in one that takes them.
#[tauri::command]
async fn blueprint_use(id: String, sizes: Option<Sizes>) -> Result<(), String> {
    blueprints::apply(&id, sizes.unwrap_or_default()).await
}

/// What built-in blueprint `id` opens at `sizes`, as the page's size inputs change.
#[tauri::command]
fn blueprint_preview(id: String, sizes: Sizes) -> Result<Preview, String> {
    blueprints::preview_at(&id, sizes)
}

#[tauri::command]
async fn blueprint_save(name: String) -> Result<(), String> {
    blueprints::save(&name).await
}

#[tauri::command]
fn blueprint_delete(id: String) -> Result<(), String> {
    blueprints::delete(&id)
}

/// The launcher window, once the dev server serving its page answers.
async fn open_window(app: tauri::AppHandle) {
    if let Err(e) = workspace::ensure_dev_server().await {
        tracing::error!("the dev server did not start: {e}");
        app.exit(1);
        return;
    }
    let config = app.config().app.windows.first().expect("a launcher window in the config").clone();
    if let Err(e) = tauri::WebviewWindowBuilder::from_config(&app, &config).and_then(|builder| builder.build()) {
        tracing::error!("the launcher window did not open: {e}");
        app.exit(1);
        return;
    }
    // Get the build going, so the first start is quick.
    let _ = workspace::build().await;
}

fn main() {
    let _log = ghost_log::init(None);
    tauri::Builder::default()
        .setup(|app| {
            launcher::init(app.handle().clone());
            tauri::async_runtime::spawn(open_window(app.handle().clone()));
            tauri::async_runtime::spawn(profiles::watch_calls());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            launcher_view,
            process_log,
            rebuild,
            relay_start,
            relay_stop,
            relay_reset,
            profile_add,
            profile_remove,
            profile_start,
            profile_stop,
            profile_reset,
            profile_window,
            call_view,
            set_network,
            caller_add,
            caller_voice,
            caller_remove,
            windows_tile,
            blueprint_use,
            blueprint_preview,
            blueprint_save,
            blueprint_delete,
        ])
        .build(tauri::generate_context!())
        .expect("error while building the launcher")
        .run(|_app, event| {
            if let tauri::RunEvent::Exit = event {
                tauri::async_runtime::block_on(launcher::launcher().processes.stop_all());
            }
        });
}
