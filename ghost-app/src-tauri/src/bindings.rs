//! Writes the TypeScript types the front end uses for command results and events,
//! from the Rust types the backend actually sends, into `src/lib/generated/`.
//! `cargo test -p ghost-app bindings` regenerates them; CI fails if the committed
//! files differ, so the two sides cannot drift apart.

use std::path::PathBuf;

use ts_rs::{Config, TS};

use crate::dto::*;
use crate::relay_task::{
    OnlinePresenceEvent, OnlinePresenceMemberDto, VoiceChannelMember, VoiceChannelMembersEvent, VoiceMuteStateEvent,
    VoiceParticipantsEvent, VoiceQualityEvent, VoiceSpeakingEvent, VoiceStateEvent,
};

fn config() -> Config {
    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../src/lib/generated");
    // Serde writes 64-bit integers as JSON numbers; every one Ghost sends fits exactly.
    Config::new().with_large_int("number").with_out_dir(out_dir)
}

#[test]
fn export_typescript_bindings() {
    let cfg = config();
    IdentityDto::export_all(&cfg).unwrap();
    ServerDto::export_all(&cfg).unwrap();
    ChannelDto::export_all(&cfg).unwrap();
    MemberDto::export_all(&cfg).unwrap();
    RoleDto::export_all(&cfg).unwrap();
    AssignmentDto::export_all(&cfg).unwrap();
    PolicyDto::export_all(&cfg).unwrap();
    ServerRolesDto::export_all(&cfg).unwrap();
    ChannelAccessDto::export_all(&cfg).unwrap();
    MessageDto::export_all(&cfg).unwrap();
    InviteDto::export_all(&cfg).unwrap();
    ConfigDto::export_all(&cfg).unwrap();
    KeybindConfigDto::export_all(&cfg).unwrap();
    DeviceDto::export_all(&cfg).unwrap();
    crate::commands::AudioDevicesDto::export_all(&cfg).unwrap();
    VoiceStateEvent::export_all(&cfg).unwrap();
    VoiceParticipantsEvent::export_all(&cfg).unwrap();
    VoiceSpeakingEvent::export_all(&cfg).unwrap();
    VoiceMuteStateEvent::export_all(&cfg).unwrap();
    VoiceQualityEvent::export_all(&cfg).unwrap();
    VoiceChannelMembersEvent::export_all(&cfg).unwrap();
    VoiceChannelMember::export_all(&cfg).unwrap();
    OnlinePresenceEvent::export_all(&cfg).unwrap();
    OnlinePresenceMemberDto::export_all(&cfg).unwrap();
}
