use axum::extract::State;

use crate::state::AppState;

pub async fn get(State(state): State<AppState>) -> String {
    hex::encode(state.relay_vk)
}
