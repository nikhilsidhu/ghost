use tauri::Manager;

mod audio;
mod commands;
mod config;
mod constants;
mod dto;
mod relay_task;
mod setup;
mod state;
mod udp_transport;
mod voice_task;

#[cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
fn main() {
    let setup::SetupResult {
        state: app_state,
        inbox_rx,
        voice_cmd_rx,
        voice_state_tx,
    } = setup::initialize();
    let client = app_state.client.clone();
    let voice_client = app_state.client.clone();
    let relay = app_state.relay.clone();

    tauri::Builder::default()
        .manage(app_state)
        .setup(move |app| {
            #[cfg(target_os = "macos")]
            {
                use objc2_app_kit::{NSColor, NSWindow};

                let window = app.get_webview_window("main").unwrap();
                let ns_window = unsafe { &*(window.ns_window().unwrap() as *mut NSWindow) };
                // pure black — matches --neutral-950
                let color = NSColor::colorWithSRGBRed_green_blue_alpha(0.0, 0.0, 0.0, 1.0);
                ns_window.setBackgroundColor(Some(&color));
            }

            let handle = app.handle().clone();
            tauri::async_runtime::spawn(relay_task::run(
                handle.clone(),
                client,
                relay,
                inbox_rx,
            ));
            tauri::async_runtime::spawn(voice_task::run(
                handle,
                voice_client,
                voice_cmd_rx,
                voice_state_tx,
            ));

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_identity,
            commands::list_groups,
            commands::create_group,
            commands::list_channels,
            commands::list_members,
            commands::pin_group,
            commands::unpin_group,
            commands::list_pinned_groups,
            commands::list_messages,
            commands::send_message,
            commands::create_channel,
            commands::rename_channel,
            commands::delete_channel,
            commands::mark_channel_read,
            commands::create_invite,
            commands::join_by_invite,
            commands::get_config,
            commands::set_display_name,
            commands::set_relay_url,
            commands::join_voice,
            commands::leave_voice,
            commands::set_muted,
            commands::set_deafened,
            commands::seed_test_data,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ghost");
}
