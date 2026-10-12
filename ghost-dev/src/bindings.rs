//! Writes the launcher page's TypeScript types from the Rust types the launcher sends, into
//! `ghost-app/src/launcher/generated/`. `cargo test -p ghost-dev bindings` regenerates them.

use std::path::PathBuf;

use ts_rs::{Config, TS};

use crate::blueprints::preview::{ChannelPreview, Counts, DmPreview, MemberPreview, Note, Preview, ServerPreview, Tone, WindowPreview};
use crate::blueprints::{BlueprintSource, BlueprintView, SizeLimits, Sizes};
use crate::callers::Voice;
use crate::process::Status;
use crate::view::*;

#[test]
fn export_typescript_bindings() {
    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ghost-app/src/launcher/generated");
    let cfg = Config::new().with_large_int("number").with_out_dir(out_dir);
    Status::export_all(&cfg).unwrap();
    Voice::export_all(&cfg).unwrap();
    RelayView::export_all(&cfg).unwrap();
    CallPlace::export_all(&cfg).unwrap();
    ProfileView::export_all(&cfg).unwrap();
    CallerView::export_all(&cfg).unwrap();
    ProcessView::export_all(&cfg).unwrap();
    FailureView::export_all(&cfg).unwrap();
    LauncherView::export_all(&cfg).unwrap();
    NetworkView::export_all(&cfg).unwrap();
    ParticipantKind::export_all(&cfg).unwrap();
    ParticipantView::export_all(&cfg).unwrap();
    CallView::export_all(&cfg).unwrap();
    Sizes::export_all(&cfg).unwrap();
    SizeLimits::export_all(&cfg).unwrap();
    Tone::export_all(&cfg).unwrap();
    Note::export_all(&cfg).unwrap();
    ChannelPreview::export_all(&cfg).unwrap();
    MemberPreview::export_all(&cfg).unwrap();
    ServerPreview::export_all(&cfg).unwrap();
    DmPreview::export_all(&cfg).unwrap();
    WindowPreview::export_all(&cfg).unwrap();
    Counts::export_all(&cfg).unwrap();
    Preview::export_all(&cfg).unwrap();
    BlueprintSource::export_all(&cfg).unwrap();
    BlueprintView::export_all(&cfg).unwrap();
}
