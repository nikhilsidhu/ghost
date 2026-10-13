use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

use ghost_wire::presence::{OnlineStateMsg, PresenceSender, VoiceStateMsg};
use ghost_wire::{short_id, WS_ERROR_PREFIX, WS_SIGNAL_CHANNELS, WS_SIGNAL_GAP};

use crate::auth::DeviceAuth;
use crate::constants::{MAX_PRESENCE_BLOB_SIZE, WS_CATCHUP_PAGE, WS_CLOSE_WAIT_SECS, WS_MISSED_PONGS};
use crate::mailbox::{Frame, Mailbox, OnlinePresence, VoicePresence};
use crate::state::AppState;
use crate::util::{decode_mailbox_id, now_millis};

const HANDSHAKE_TIMEOUT_SECS: u64 = 5;

type Sink = SplitSink<WebSocket, Message>;
type Stream = SplitStream<WebSocket>;

/// A voice state announcement as a client sends it; the relay adds who sent it.
#[derive(Deserialize)]
struct VsMsg {
    vs: VsInner,
}

#[derive(Deserialize)]
struct VsInner {
    ch: String,
    p: Option<String>,
    leave: Option<bool>,
}

/// An online presence announcement as a client sends it; the relay adds who sent it.
#[derive(Deserialize)]
struct PsMsg {
    ps: PsInner,
}

#[derive(Deserialize)]
struct PsInner {
    p: Option<String>,
    leave: Option<bool>,
}

pub async fn ws_upgrade(
    auth: DeviceAuth,
    State(state): State<AppState>,
    Path(mailbox_id): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    let id = match decode_mailbox_id(&mailbox_id) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let read_limit = match state.read_limit(id, auth.account_fp).await {
        Ok(limit) => limit,
        Err(e) => return e.into_response(),
    };
    ws.on_upgrade(move |socket| ws_connection(socket, id, state, auth, read_limit))
}

/// The receiving ends of a mailbox's live state, taken before the handshake so nothing
/// committed during catch-up is missed.
struct Subscriptions {
    frames: broadcast::Receiver<Arc<Frame>>,
    voice: broadcast::Receiver<(u64, String)>,
    presence: broadcast::Receiver<(u64, String)>,
    channels: broadcast::Receiver<[u8; 32]>,
}

impl Subscriptions {
    fn to(mailbox: &Mailbox) -> Self {
        Self {
            frames: mailbox.frames.subscribe(),
            voice: mailbox.voice_tx.subscribe(),
            presence: mailbox.presence_tx.subscribe(),
            channels: mailbox.channels_tx.subscribe(),
        }
    }
}

/// Where the connection stands in the mailbox's log.
struct Cursor {
    last_seen: u64,
    /// For an account removed from the group: the last entry it may read, after which
    /// the connection closes. Set at connect, or by a removal while connected.
    read_limit: Option<u64>,
    /// Entries this connection posted itself and was acked for, not to be echoed.
    own_seqs: Vec<u64>,
}

/// Why the connection's delivery ended.
enum Stop {
    /// The account's read limit was reached; close as removed.
    Removed,
    /// The socket or the store failed; just end.
    Lost,
}

/// `read_limit` is set for an account removed from the group: it gets the entries up
/// to its removal and the connection ends. A removal while connected sets it too.
async fn ws_connection(socket: WebSocket, mailbox_id: [u8; 32], state: AppState, auth: DeviceAuth, read_limit: Option<u64>) {
    let (mut sink, mut stream) = socket.split();
    let conn_id = state.next_conn_id.fetch_add(1, Relaxed);
    let from = PresenceSender { account_fp: auth.account_fp, device_vk: auth.device_vk };
    let mut subs = state.subscribe(mailbox_id, Subscriptions::to);

    // Handshake: first binary frame is 8-byte BE last_seen_seq. Without it the
    // connection is closed with a frame, so the client reconnects at once rather than
    // waiting out its silence limit.
    let timeout = Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
    let last_seen: u64 = match tokio::time::timeout(timeout, stream.next()).await {
        Ok(Some(Ok(Message::Binary(data)))) if data.len() == 8 => u64::from_be_bytes(data[..8].try_into().unwrap()),
        _ => {
            let close = axum::extract::ws::CloseFrame { code: axum::extract::ws::close_code::PROTOCOL, reason: "no resume point sent".into() };
            close_with(&mut sink, &mut stream, close).await;
            return;
        }
    };
    let mut cursor = Cursor { last_seen, read_limit, own_seqs: Vec::new() };

    // A client asking for entries already swept has a gap: it must rebuild its group
    // state, and the entries it missed are unprocessable after that. The cursor moves to
    // the head and the client is told where, so it resumes there; only new entries are
    // delivered. A client past the end of the log saw a log that started over since (the
    // relay was reset): everything held now is newer, and it is served from the start.
    // A store that cannot say serves from the cursor, as if neither.
    let (past_end, has_gap) = match state.storage.log_position(mailbox_id).await {
        Ok(log) => {
            let past_end = cursor.last_seen > log.head;
            let missed_swept = cursor.last_seen < log.head && log.first.is_none_or(|first| cursor.last_seen + 1 < first);
            (past_end, missed_swept)
        }
        Err(_) => (false, false),
    };
    tracing::debug!(
        "ws {}: device {} of {} subscribed after seq {last_seen}{}",
        short_id(&mailbox_id),
        short_id(&auth.device_vk),
        short_id(&auth.account_fp),
        if has_gap { ", past a gap" } else if past_end { ", past the log's end" } else { "" }
    );
    if past_end {
        cursor.last_seen = 0;
    }
    if has_gap {
        if skip_to_head(&state, mailbox_id, &mut cursor).await.is_err() {
            return;
        }
        if sink.send(Message::text(format!("{WS_SIGNAL_GAP}{}", cursor.last_seen))).await.is_err() {
            return;
        }
    } else if let Err(stop) = catch_up(&state, mailbox_id, &mut cursor, &mut sink).await {
        if matches!(stop, Stop::Removed) {
            close_with(&mut sink, &mut stream, removed_close()).await;
        }
        return;
    }
    if cursor.read_limit.is_some() {
        close_with(&mut sink, &mut stream, removed_close()).await;
        return;
    }
    if sink.send(Message::text(ghost_wire::WS_SIGNAL_CAUGHT_UP)).await.is_err() {
        return;
    }

    let (voice, online) = state.subscribe(mailbox_id, |mailbox| (voice_snapshot(mailbox, &mut subs.voice), online_snapshot(mailbox, &mut subs.presence)));
    if sink.send(Message::text(voice)).await.is_err() || sink.send(Message::text(online)).await.is_err() {
        return;
    }

    let ping_every = Duration::from_secs(state.config.ws_ping_secs.max(1));
    let mut ping_interval = tokio::time::interval(ping_every);
    let mut last_pong = tokio::time::Instant::now();
    // The device said goodbye, or the relay closed the connection because the device may
    // not come back to this mailbox: its presence goes at once. Anything else may be a
    // blip, which the grace rides out.
    let mut withdraw_at_once = false;
    // The close the relay ends the connection with, if it does: sent once the presence is
    // withdrawn.
    let mut closing: Option<axum::extract::ws::CloseFrame> = None;
    let mut revoke_rx = state.revocation_tx.subscribe();
    let mut departure_rx = state.departure_tx.subscribe();
    let mut readmission_rx = state.readmission_tx.subscribe();

    loop {
        tokio::select! {
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        // Answered in order, so the sender can tell which post each reply is for.
                        let reply = match state.accept_post(mailbox_id, auth.account_fp, data.to_vec()).await {
                            Ok(stored) => {
                                cursor.own_seqs.push(stored.seq);
                                Message::text(stored.seq.to_string())
                            }
                            Err(e) => Message::text(format!("{WS_ERROR_PREFIX}{} {e}", e.status().as_u16())),
                        };
                        if sink.send(reply).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        let s = text.as_str();
                        if let Ok(vs) = serde_json::from_str::<VsMsg>(s) {
                            handle_voice_state(&state, &mailbox_id, conn_id, &from, vs.vs);
                        } else if let Ok(ps) = serde_json::from_str::<PsMsg>(s) {
                            handle_online_presence(&state, &mailbox_id, conn_id, &from, ps.ps);
                        }
                    }
                    Some(Ok(Message::Pong(_))) => last_pong = tokio::time::Instant::now(),
                    Some(Ok(Message::Close(_))) => {
                        withdraw_at_once = true;
                        break;
                    }
                    None => break,
                    _ => {}
                }
            }
            frame = subs.frames.recv() => {
                let delivered = match frame {
                    Ok(frame) => deliver_frame(&state, mailbox_id, &mut cursor, &frame, &mut sink).await,
                    // Behind the fan-out: the log has everything that was missed.
                    Err(RecvError::Lagged(_)) => catch_up(&state, mailbox_id, &mut cursor, &mut sink).await,
                    Err(RecvError::Closed) => break,
                };
                match delivered {
                    Ok(()) => {}
                    Err(Stop::Removed) => {
                        closing = Some(removed_close());
                        withdraw_at_once = true;
                        break;
                    }
                    Err(Stop::Lost) => break,
                }
            }
            departure = departure_rx.recv() => {
                match departure {
                    Ok(d) if d.mailbox_id == mailbox_id && d.account_fp == auth.account_fp => {
                        // Deliver up to the removing commit, which the frame branch may
                        // not have reached yet, then close.
                        cursor.read_limit = Some(d.seq);
                        if cursor.last_seen >= d.seq {
                            closing = Some(removed_close());
                            withdraw_at_once = true;
                            break;
                        }
                    }
                    Err(RecvError::Lagged(_)) => {
                        if let Ok(limit) = state.read_limit(mailbox_id, auth.account_fp).await {
                            cursor.read_limit = limit;
                        }
                    }
                    Err(RecvError::Closed) => break,
                    _ => {}
                }
            }
            voice_event = subs.voice.recv() => {
                let forward = match voice_event {
                    Ok((sender_conn_id, json)) => (sender_conn_id != conn_id).then_some(json),
                    // Behind the fan-out: the snapshot says who is in which channel now.
                    Err(RecvError::Lagged(_)) => Some(state.subscribe(mailbox_id, |mailbox| voice_snapshot(mailbox, &mut subs.voice))),
                    Err(RecvError::Closed) => break,
                };
                if let Some(json) = forward {
                    if sink.send(Message::text(json)).await.is_err() {
                        break;
                    }
                }
            }
            admitted = subs.channels.recv() => {
                match admitted {
                    Ok(account_fp) if account_fp == auth.account_fp => {
                        if sink.send(Message::text(WS_SIGNAL_CHANNELS)).await.is_err() {
                            break;
                        }
                    }
                    Err(RecvError::Closed) => break,
                    _ => {}
                }
            }
            presence_event = subs.presence.recv() => {
                let forward = match presence_event {
                    Ok((sender_conn_id, json)) => (sender_conn_id != conn_id).then_some(json),
                    // Behind the fan-out: the snapshot says who is online now.
                    Err(RecvError::Lagged(_)) => Some(state.subscribe(mailbox_id, |mailbox| online_snapshot(mailbox, &mut subs.presence))),
                    Err(RecvError::Closed) => break,
                };
                if let Some(json) = forward {
                    if sink.send(Message::text(json)).await.is_err() {
                        break;
                    }
                }
            }
            revoke_event = revoke_rx.recv() => {
                let revoked = match revoke_event {
                    Ok((afp, dvk)) => afp == auth.account_fp && dvk == auth.device_vk,
                    // Missed events: ask the store whether this device still stands.
                    Err(RecvError::Lagged(_)) => {
                        !state.storage.is_active_device(auth.account_fp, auth.device_vk).await.unwrap_or(false)
                    }
                    Err(RecvError::Closed) => break,
                };
                if revoked {
                    closing = Some(revoked_close(&state, &auth).await);
                    withdraw_at_once = true;
                    break;
                }
            }
            readmission = readmission_rx.recv() => {
                let recheck = match readmission {
                    Ok(account_fp) => account_fp == auth.account_fp,
                    Err(RecvError::Lagged(_)) => true,
                    Err(RecvError::Closed) => break,
                };
                // Admitted when it connected is not admitted now: the device learns why
                // from the refusal its reconnect gets.
                if recheck && !still_admitted(&state, &auth).await {
                    closing = Some(axum::extract::ws::CloseFrame { code: ghost_wire::WS_CLOSE_ADMISSION_CHANGED, reason: "no longer admitted".into() });
                    withdraw_at_once = true;
                    break;
                }
            }
            _ = ping_interval.tick() => {
                if last_pong.elapsed() > ping_every * WS_MISSED_PONGS {
                    tracing::debug!(
                        "ws {}: device {} answered no ping for {:?}; dropping the connection",
                        short_id(&mailbox_id),
                        short_id(&auth.device_vk),
                        last_pong.elapsed()
                    );
                    break;
                }
                if sink.send(Message::Ping(bytes::Bytes::new())).await.is_err() {
                    break;
                }
            }
        }
    }

    withdraw_presence(&state, mailbox_id, conn_id, withdraw_at_once);
    if let Some(frame) = closing {
        close_with(&mut sink, &mut stream, frame).await;
    }
}

/// Send `frame`, then wait for the device's own close before the socket goes, so none
/// of the device's data is left unread: a socket closed with data unread is reset, and
/// the device sees the reset in place of the reason (on Windows, every time). A device
/// that does not answer within `WS_CLOSE_WAIT_SECS` is not waited for longer.
pub(crate) async fn close_with(sink: &mut Sink, stream: &mut Stream, frame: axum::extract::ws::CloseFrame) {
    if sink.send(Message::Close(Some(frame))).await.is_err() {
        return;
    }
    let answered = async {
        while let Some(Ok(message)) = stream.next().await {
            if matches!(message, Message::Close(_)) {
                break;
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(WS_CLOSE_WAIT_SECS), answered).await;
}

/// The close for an account removed from the group.
pub(crate) fn removed_close() -> axum::extract::ws::CloseFrame {
    axum::extract::ws::CloseFrame { code: ghost_wire::WS_CLOSE_REMOVED, reason: "removed from the group".into() }
}

/// The close for a device the account's log revoked; its reason says what revoked it,
/// when the log tells.
pub(crate) async fn revoked_close(state: &AppState, auth: &DeviceAuth) -> axum::extract::ws::CloseFrame {
    let cause = state.storage.revocation_cause(auth.account_fp, auth.device_vk).await.ok().flatten();
    axum::extract::ws::CloseFrame {
        code: ghost_wire::WS_CLOSE_DEVICE_REVOKED,
        reason: cause.map_or_else(|| "device revoked".to_string(), |c| c.encode()).into(),
    }
}

/// Whether the relay would still admit the connection's device. A store that cannot
/// answer keeps the connection: a reconnect would be judged by the same store.
async fn still_admitted(state: &AppState, auth: &DeviceAuth) -> bool {
    state.storage.may_authenticate(auth.account_fp, auth.device_vk, now_millis()).await.map_or(true, |admission| admission.is_some())
}

/// Deliver one frame from the fan-out. A frame already delivered is skipped; one that
/// is not the next in the log means the fan-out skipped ahead, and the log fills in.
async fn deliver_frame(state: &AppState, mailbox_id: [u8; 32], cursor: &mut Cursor, frame: &Frame, sink: &mut Sink) -> Result<(), Stop> {
    if frame.seq <= cursor.last_seen {
        return Ok(());
    }
    if frame.seq != cursor.last_seen + 1 {
        return catch_up(state, mailbox_id, cursor, sink).await;
    }
    send_entry(cursor, frame.seq, &frame.encoded, sink).await
}

/// Send everything in the log after the cursor, a page at a time.
async fn catch_up(state: &AppState, mailbox_id: [u8; 32], cursor: &mut Cursor, sink: &mut Sink) -> Result<(), Stop> {
    loop {
        let entries = state.storage.read_from(mailbox_id, cursor.last_seen, WS_CATCHUP_PAGE).await.map_err(|_| Stop::Lost)?;
        if entries.is_empty() {
            return Ok(());
        }
        for entry in &entries {
            let frame = Frame::new(entry.seq, entry.received_at, &entry.payload);
            send_entry(cursor, entry.seq, &frame.encoded, sink).await?;
        }
    }
}

/// Send one entry, unless it is past the read limit or the connection's own.
async fn send_entry(cursor: &mut Cursor, seq: u64, encoded: &[u8], sink: &mut Sink) -> Result<(), Stop> {
    if cursor.read_limit.is_some_and(|last| seq > last) {
        return Err(Stop::Removed);
    }
    cursor.last_seen = seq;
    if let Some(pos) = cursor.own_seqs.iter().position(|&s| s == seq) {
        cursor.own_seqs.swap_remove(pos);
        return Ok(());
    }
    sink.send(Message::binary(encoded.to_vec())).await.map_err(|_| Stop::Lost)?;
    tracing::debug!("ws: sent seq={seq} ({} bytes)", encoded.len());
    if cursor.read_limit.is_some_and(|last| seq >= last) {
        return Err(Stop::Removed);
    }
    Ok(())
}

/// Move the cursor past everything in the log without delivering it.
async fn skip_to_head(state: &AppState, mailbox_id: [u8; 32], cursor: &mut Cursor) -> Result<(), Stop> {
    loop {
        let entries = state.storage.read_from(mailbox_id, cursor.last_seen, WS_CATCHUP_PAGE).await.map_err(|_| Stop::Lost)?;
        let Some(last) = entries.last() else { return Ok(()) };
        cursor.last_seen = last.seq;
    }
}

/// Who is in which voice channel of the mailbox, each stamped with the device that said
/// so, as `vs_snap`; sent even when empty, so the client clears what it remembered. The
/// connection's voice fan-out restarts under the same lock, so it carries exactly the
/// announcements that came after.
fn voice_snapshot(mailbox: &Mailbox, fanout: &mut broadcast::Receiver<(u64, String)>) -> String {
    let voice_presence = mailbox.voice_presence.lock().unwrap();
    *fanout = mailbox.voice_tx.subscribe();
    let entries: Vec<VoiceStateMsg> = voice_presence
        .iter()
        .map(|e| VoiceStateMsg { ch: B64.encode(e.channel_id), p: Some(B64.encode(&e.blob)), leave: None, from: e.from })
        .collect();
    serde_json::json!({ "vs_snap": entries }).to_string()
}

/// Who is online on the mailbox, as `ps_snap`, restarting the connection's online
/// fan-out the same way.
fn online_snapshot(mailbox: &Mailbox, fanout: &mut broadcast::Receiver<(u64, String)>) -> String {
    let online_presence = mailbox.online_presence.lock().unwrap();
    *fanout = mailbox.presence_tx.subscribe();
    let entries: Vec<OnlineStateMsg> =
        online_presence.iter().map(|e| OnlineStateMsg { p: Some(B64.encode(&e.blob)), leave: None, from: e.from }).collect();
    serde_json::json!({ "ps_snap": entries }).to_string()
}

/// A presence blob as announced: base64, non-empty, within the size cap.
fn decode_presence(encoded: &str) -> Option<Vec<u8>> {
    match B64.decode(encoded) {
        Ok(blob) if !blob.is_empty() && blob.len() <= MAX_PRESENCE_BLOB_SIZE => Some(blob),
        _ => None,
    }
}

/// A voice state announcement for the mailbox's other connections, from `from`.
fn voice_announcement(channel_id: &[u8; 32], presence: Option<String>, from: PresenceSender) -> String {
    let leave = presence.is_none().then_some(true);
    serde_json::json!({ "vs": VoiceStateMsg { ch: B64.encode(channel_id), p: presence, leave, from } }).to_string()
}

/// An online presence announcement for the mailbox's other connections, from `from`.
fn online_announcement(presence: Option<String>, from: PresenceSender) -> String {
    let leave = presence.is_none().then_some(true);
    serde_json::json!({ "ps": OnlineStateMsg { p: presence, leave, from } }).to_string()
}

/// A device announcing a voice channel is in that call and no other: its entries for
/// other channels go, with a leave for each. Its entry for the channel moves to this
/// connection, so a device back after a blip takes over what its earlier connection held.
fn handle_voice_state(state: &AppState, mailbox_id: &[u8; 32], conn_id: u64, from: &PresenceSender, vs: VsInner) {
    let channel_id: [u8; 32] = match B64.decode(&vs.ch) {
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        _ => return,
    };
    let mailboxes = state.mailboxes.read().unwrap();
    let Some(mailbox) = mailboxes.get(mailbox_id) else { return };
    let mut voice_presence = mailbox.voice_presence.lock().unwrap();

    if vs.leave == Some(true) {
        if let Some(pos) = voice_presence.iter().position(|e| e.from == *from && e.channel_id == channel_id) {
            voice_presence.remove(pos);
            let _ = mailbox.voice_tx.send((conn_id, voice_announcement(&channel_id, None, *from)));
        }
    } else if let Some(p_b64) = vs.p {
        let Some(blob) = decode_presence(&p_b64) else { return };
        let (elsewhere, kept): (Vec<_>, Vec<_>) =
            voice_presence.drain(..).partition(|e| e.from == *from && e.channel_id != channel_id);
        *voice_presence = kept;
        for entry in elsewhere {
            let _ = mailbox.voice_tx.send((conn_id, voice_announcement(&entry.channel_id, None, *from)));
        }
        match voice_presence.iter_mut().find(|e| e.from == *from) {
            Some(entry) => {
                entry.conn_id = conn_id;
                entry.blob = blob;
            }
            None => voice_presence.push(VoicePresence { channel_id, conn_id, from: *from, blob }),
        }
        let _ = mailbox.voice_tx.send((conn_id, voice_announcement(&channel_id, Some(p_b64), *from)));
    }
}

/// One entry per device: an announcement replaces the device's entry and moves it to
/// this connection, and a leave (the device went invisible) removes it whichever
/// connection announced it.
fn handle_online_presence(state: &AppState, mailbox_id: &[u8; 32], conn_id: u64, from: &PresenceSender, ps: PsInner) {
    let mailboxes = state.mailboxes.read().unwrap();
    let Some(mailbox) = mailboxes.get(mailbox_id) else { return };
    let mut online_presence = mailbox.online_presence.lock().unwrap();

    if ps.leave == Some(true) {
        if let Some(pos) = online_presence.iter().position(|e| e.from == *from) {
            online_presence.remove(pos);
            let _ = mailbox.presence_tx.send((conn_id, online_announcement(None, *from)));
        }
    } else if let Some(p_b64) = ps.p {
        let Some(blob) = decode_presence(&p_b64) else { return };
        match online_presence.iter_mut().find(|e| e.from == *from) {
            Some(entry) => {
                entry.conn_id = conn_id;
                entry.blob = blob;
            }
            None => online_presence.push(OnlinePresence { conn_id, from: *from, blob }),
        }
        let _ = mailbox.presence_tx.send((conn_id, online_announcement(Some(p_b64), *from)));
    }
}

/// A connection that ended takes the presence it holds with it: at once, or once the
/// grace period passes. A device back meanwhile has moved its entries to its new
/// connection by announcing again, so nothing is withdrawn and the others hear nothing.
fn withdraw_presence(state: &AppState, mailbox_id: [u8; 32], conn_id: u64, at_once: bool) {
    if at_once {
        withdraw_now(state, &mailbox_id, conn_id);
        return;
    }
    let state = state.clone();
    let grace = Duration::from_secs(state.config.presence_grace_secs);
    tokio::spawn(async move {
        tokio::time::sleep(grace).await;
        withdraw_now(&state, &mailbox_id, conn_id);
    });
}

/// Drop the entries the connection still holds, with a leave for each.
fn withdraw_now(state: &AppState, mailbox_id: &[u8; 32], conn_id: u64) {
    let mailboxes = state.mailboxes.read().unwrap();
    let Some(mailbox) = mailboxes.get(mailbox_id) else { return };
    {
        let mut voice_presence = mailbox.voice_presence.lock().unwrap();
        let (gone, kept): (Vec<_>, Vec<_>) = voice_presence.drain(..).partition(|e| e.conn_id == conn_id);
        *voice_presence = kept;
        for entry in gone {
            let _ = mailbox.voice_tx.send((conn_id, voice_announcement(&entry.channel_id, None, entry.from)));
        }
    }
    let mut online_presence = mailbox.online_presence.lock().unwrap();
    let (gone, kept): (Vec<_>, Vec<_>) = online_presence.drain(..).partition(|e| e.conn_id == conn_id);
    *online_presence = kept;
    for entry in gone {
        let _ = mailbox.presence_tx.send((conn_id, online_announcement(None, entry.from)));
    }
}
