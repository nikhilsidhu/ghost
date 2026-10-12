//! The profiler of dev builds: span statistics, spans that held their thread, the
//! current call's per-stream figures, and captures of the flight recorder. Built only
//! with the `devtools` feature; nothing here leaves the app.

use std::collections::HashMap;

use ghost_audio::constants::FRAME_MS;
use ghost_audio::{Load, PeerFigures};
use ghost_devtools::stats::SpanSummary;
use ghost_devtools::trace::{BLOCKING, WINDOW};
use ghost_devtools::Devtools;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State, WebviewUrl, WebviewWindowBuilder};

use crate::state::AppState;

/// Label of the profiler window, which its capability file names too.
pub const PROFILER_WINDOW: &str = "profiler";
/// The profiler's page, an entry of the devtools front-end build.
const PROFILER_PAGE: &str = "profiler.html";
/// Sent to an open profiler to capture now; a new one gets it as its URL's fragment.
const CAPTURE_EVENT: &str = "devtools-capture";
const CAPTURE_FRAGMENT: &str = "#capture";
const PROFILER_SIZE: (f64, f64) = (1040.0, 800.0);
const PROFILER_MIN_SIZE: (f64, f64) = (760.0, 600.0);

/// Shared with the commands below.
pub struct DevtoolsState {
    tools: Devtools,
}

/// The profiler's handles, and the layer for the process's logging setup that feeds them.
pub fn prepare() -> (DevtoolsState, impl ghost_log::ExtraLayer) {
    let tools = Devtools::default();
    let layer = tools.layer();
    (DevtoolsState { tools }, layer)
}

fn millis(duration: std::time::Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "SpanTiming"))]
pub struct SpanTimingDto {
    target: String,
    name: String,
    count: u64,
    wall_ms: f64,
    /// Time its own code ran, not counting spans nested inside it.
    busy_ms: f64,
    max_wall_ms: f64,
    /// The longest any of them ran its own code without yielding.
    longest_poll_ms: f64,
}

impl From<SpanSummary> for SpanTimingDto {
    fn from(s: SpanSummary) -> Self {
        Self {
            target: s.target,
            name: s.name,
            count: s.count,
            wall_ms: s.wall_ms,
            busy_ms: s.busy_ms,
            max_wall_ms: s.max_wall_ms,
            longest_poll_ms: s.longest_poll_ms,
        }
    }
}

/// A span that ran its own code for the blocking threshold or longer without yielding.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "BlockingSpan"))]
pub struct BlockingSpanDto {
    id: String,
    target: String,
    name: String,
    ended_unix_ms: f64,
    longest_poll_ms: f64,
}

/// A media thread's processing load since the last snapshot, as a share of real time.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "LoadFigure"))]
pub struct LoadFigureDto {
    frames: u64,
    load: f64,
    peak: f64,
}

impl From<Load> for LoadFigureDto {
    fn from(l: Load) -> Self {
        Self { frames: l.frames, load: l.load, peak: l.peak }
    }
}

/// Another caller's stream, with counts over the call so far.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "PeerFigure"))]
pub struct PeerFigureDto {
    slot_id: u32,
    fingerprint: String,
    /// Their display name, where this device knows it.
    name: Option<String>,
    /// Frames in their jitter buffer, and what its delay policy aims for.
    depth_frames: u32,
    target_frames: u32,
    played: u64,
    /// Lost frames rebuilt from the next frame's error correction.
    recovered: u64,
    /// Lost frames covered by concealment: what a listener hears as breakup.
    concealed: u64,
    dropped_late: u64,
    received_frames: u64,
    received_bytes: u64,
}

impl PeerFigureDto {
    fn new(slot_id: u32, fingerprint: &[u8; 32], name: Option<String>, figures: PeerFigures) -> Self {
        Self {
            slot_id,
            fingerprint: hex::encode(fingerprint),
            name,
            depth_frames: figures.depth,
            target_frames: figures.target,
            played: figures.playout.played,
            recovered: figures.playout.recovered,
            concealed: figures.playout.concealed,
            dropped_late: figures.playout.dropped_late,
            received_frames: figures.received_frames,
            received_bytes: figures.received_bytes,
        }
    }
}

/// The current call, stream by stream.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "CallFigure"))]
pub struct CallFigureDto {
    /// The voice server's round trip over the signalling connection.
    ping_ms: Option<u32>,
    /// Audio per frame, to turn frame counts into time.
    frame_ms: u32,
    capture: LoadFigureDto,
    playback: LoadFigureDto,
    /// What this device sent over the call so far.
    sent_frames: u64,
    sent_bytes: u64,
    peers: Vec<PeerFigureDto>,
}

/// The thresholds and windows behind the figures, so both windows use the same values.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "DevtoolsLimits"))]
pub struct DevtoolsLimitsDto {
    capture_window_ms: f64,
    blocking_ms: f64,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "DevtoolsSnapshot"))]
pub struct DevtoolsSnapshotDto {
    /// Per kind of span since the last reset.
    spans: Vec<SpanTimingDto>,
    /// Spans in the flight recorder that held their thread.
    blocking: Vec<BlockingSpanDto>,
    /// Null outside a call.
    call: Option<CallFigureDto>,
}

/// One span of a capture. Ids are strings: tracing packs a generation into the high
/// bits, past what a JavaScript number holds exactly.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "TraceSpan"))]
pub struct TraceSpanDto {
    id: String,
    parent: Option<String>,
    target: String,
    name: String,
    /// From the capture's start; below zero for a span that began before it.
    start_us: f64,
    duration_us: f64,
    busy_us: f64,
    own_busy_us: f64,
    longest_poll_us: f64,
    /// Still running when captured: the busy figures are unknown.
    open: bool,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(rename = "TraceCapture"))]
pub struct TraceCaptureDto {
    spans: Vec<TraceSpanDto>,
    duration_us: f64,
    start_unix_ms: f64,
    /// The flight recorder was full, so the capture covers less than its window.
    truncated: bool,
}

/// The call's streams, with each caller's name from this device's member list.
async fn call_figure(state: &AppState) -> Option<CallFigureDto> {
    let slots = state.voice.call_slots()?;
    let figures = state.audio.call_figures();
    let names: HashMap<[u8; 32], String> = state
        .client
        .lock()
        .await
        .store()
        .list_members(&slots.server_id)
        .map(|members| members.into_iter().filter(|m| !m.display_name.is_empty()).map(|m| (m.fingerprint, m.display_name)).collect())
        .unwrap_or_default();
    let by_slot: HashMap<u32, PeerFigures> = figures.peers.iter().map(|peer| (peer.slot_id, *peer)).collect();
    let mut peers: Vec<PeerFigureDto> = slots
        .peers
        .iter()
        .map(|(slot, fingerprint)| {
            // A caller who has not spoken yet has no playout.
            let playout = by_slot.get(slot).copied().unwrap_or_default();
            PeerFigureDto::new(*slot, fingerprint, names.get(fingerprint).cloned(), playout)
        })
        .collect();
    peers.sort_by_key(|peer| peer.slot_id);
    Some(CallFigureDto {
        ping_ms: slots.ping_ms,
        frame_ms: FRAME_MS,
        capture: figures.capture.into(),
        playback: figures.playback.into(),
        sent_frames: figures.sent_frames,
        sent_bytes: figures.sent_bytes,
        peers,
    })
}

#[tauri::command]
pub fn devtools_limits() -> DevtoolsLimitsDto {
    DevtoolsLimitsDto { capture_window_ms: millis(WINDOW), blocking_ms: millis(BLOCKING) }
}

/// What the profiler polls: statistics accumulate until reset, blocking spans come from
/// the flight recorder, and the call's loads cover the time since the last snapshot.
#[tauri::command]
pub async fn devtools_snapshot(devtools: State<'_, DevtoolsState>, state: State<'_, AppState>) -> Result<DevtoolsSnapshotDto, String> {
    let blocking = devtools
        .tools
        .recorder
        .blocking()
        .into_iter()
        .map(|b| BlockingSpanDto {
            id: b.id.to_string(),
            target: b.target.to_string(),
            name: b.name.to_string(),
            ended_unix_ms: b.ended_unix_ms,
            longest_poll_ms: b.longest_poll_us / 1000.0,
        })
        .collect();
    Ok(DevtoolsSnapshotDto {
        spans: devtools.tools.stats.snapshot().into_iter().map(SpanTimingDto::from).collect(),
        blocking,
        call: call_figure(&state).await,
    })
}

/// Start the span statistics afresh.
#[tauri::command]
pub fn devtools_reset(devtools: State<'_, DevtoolsState>) {
    devtools.tools.stats.reset();
}

/// What the flight recorder holds: the last minute of spans, running ones included.
#[tauri::command]
pub fn devtools_capture(devtools: State<'_, DevtoolsState>) -> TraceCaptureDto {
    let capture = devtools.tools.recorder.capture();
    let spans = capture
        .spans
        .into_iter()
        .map(|s| TraceSpanDto {
            id: s.id.to_string(),
            parent: s.parent.map(|p| p.to_string()),
            target: s.target.to_string(),
            name: s.name.to_string(),
            start_us: s.start_us,
            duration_us: s.duration_us,
            busy_us: s.busy_us,
            own_busy_us: s.own_busy_us,
            longest_poll_us: s.longest_poll_us,
            open: s.open,
        })
        .collect();
    TraceCaptureDto { spans, duration_us: capture.duration_us, start_unix_ms: capture.start_unix_ms, truncated: capture.truncated }
}

/// Open the profiler window, or bring it forward if it is open; with `capture`, it
/// captures the flight recorder and shows the trace.
pub fn open_profiler(app: &AppHandle, capture: bool) -> Result<(), String> {
    if let Some(window) = app.get_webview_window(PROFILER_WINDOW) {
        if capture {
            window.emit_to(PROFILER_WINDOW, CAPTURE_EVENT, ()).map_err(|e| e.to_string())?;
        }
        return window.set_focus().map_err(|e| e.to_string());
    }
    let page = if capture { format!("{PROFILER_PAGE}{CAPTURE_FRAGMENT}") } else { PROFILER_PAGE.to_string() };
    let builder = WebviewWindowBuilder::new(app, PROFILER_WINDOW, WebviewUrl::App(page.into()))
        .title("Ghost profiler")
        .inner_size(PROFILER_SIZE.0, PROFILER_SIZE.1)
        .min_inner_size(PROFILER_MIN_SIZE.0, PROFILER_MIN_SIZE.1)
        .theme(Some(tauri::Theme::Dark))
        .background_color(tauri::window::Color(0, 0, 0, 255));
    // The same overlaid title bar as the main window.
    #[cfg(target_os = "macos")]
    let builder = builder.title_bar_style(tauri::TitleBarStyle::Overlay).hidden_title(true);
    builder.build().map(|_| ()).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn devtools_open_profiler(app: AppHandle, capture: bool) -> Result<(), String> {
    open_profiler(&app, capture)
}
