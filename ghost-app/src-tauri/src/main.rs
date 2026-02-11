mod commands;
mod dto;
mod setup;
mod state;

#[cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
fn main() {
    let app_state = setup::initialize();

    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            commands::get_identity,
            commands::list_groups,
            commands::create_group,
            commands::list_channels,
            commands::list_members,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ghost");
}
