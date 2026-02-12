use tauri::Manager;

mod commands;
mod constants;
mod dto;
mod setup;
mod state;

#[cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
fn main() {
    let app_state = setup::initialize();

    tauri::Builder::default()
        .manage(app_state)
        .setup(|app| {
            // Set native window background to black so macOS doesn't flash white
            #[cfg(target_os = "macos")]
            {
                use objc2_app_kit::{NSColor, NSWindow};

                let window = app.get_webview_window("main").unwrap();
                let ns_window = unsafe { &*(window.ns_window().unwrap() as *mut NSWindow) };
                let color = NSColor::colorWithSRGBRed_green_blue_alpha(0.0, 0.0, 0.0, 1.0);
                ns_window.setBackgroundColor(Some(&color));
            }
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
            commands::create_invite,
            commands::join_by_invite,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ghost");
}
