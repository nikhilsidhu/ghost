//! `ghost-node --data-dir DIR --relay URL [--create LABEL]`
//!
//! Runs a headless device. Commands arrive as JSON lines on stdin, each with an `id`;
//! replies (`{"id":..,"ok":{..}}` or `{"id":..,"error":".."}`) and the device's events
//! (`{"event":..}`) leave as JSON lines on stdout. The process ends when stdin closes.

use std::path::PathBuf;

use ghost_core::session::{ClientEvent, ServerScope};
use ghost_core::voice::VoiceEvent;
use ghost_node::Device;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

#[derive(Deserialize)]
struct Request {
    id: u64,
    #[serde(flatten)]
    command: Command,
}

#[derive(Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Command {
    CreateServer { name: String },
    Invite { server: String },
    Join { token: String, key: String },
    Say { server: String, channel: String, text: String },
    Kick { server: String, member: String },
    JoinVoice { server: String, channel: String },
    LeaveVoice,
    SetMuted { muted: bool },
    /// What the synthetic microphone hears: a tone, or silence at amplitude 0.
    Tone { frequency: f32, amplitude: f32 },
}

struct Args {
    data_dir: PathBuf,
    relay: String,
    create: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let (mut data_dir, mut relay, mut create) = (None, None, None);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--data-dir" => data_dir = Some(PathBuf::from(value)),
            "--relay" => relay = Some(value),
            "--create" => create = Some(value),
            other => return Err(format!("unknown flag {other}")),
        }
    }
    Ok(Args {
        data_dir: data_dir.ok_or("--data-dir is required")?,
        relay: relay.ok_or("--relay is required")?,
        create,
    })
}

fn id32(hex_str: &str) -> Result<[u8; 32], String> {
    hex::decode(hex_str).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| format!("not a 32-byte hex id: {hex_str}"))
}

fn event_json(event: &ClientEvent) -> Value {
    match event {
        ClientEvent::Message { message, received_at } => json!({
            "event": "message",
            "channel": hex::encode(message.channel_id),
            "sender": hex::encode(message.sender_fp),
            "text": String::from_utf8_lossy(&message.content),
            "received_at": received_at,
        }),
        ClientEvent::ServerChanged(ServerScope::One(id)) => json!({ "event": "server_changed", "server": hex::encode(id) }),
        ClientEvent::ServerChanged(ServerScope::All) => json!({ "event": "server_changed", "server": "all" }),
        ClientEvent::Kicked(id) => json!({ "event": "kicked", "server": hex::encode(id) }),
        ClientEvent::RelayConnectivity(connected) => json!({ "event": "relay_connectivity", "connected": connected }),
        ClientEvent::Voice(VoiceEvent::State(state)) => json!({
            "event": "voice_state",
            "connected": state.connected,
            "channel": state.channel_id.map(hex::encode),
            "muted": state.muted,
            "deafened": state.deafened,
        }),
        ClientEvent::Voice(VoiceEvent::Participants(everyone)) => {
            json!({ "event": "voice_participants", "participants": everyone.iter().map(hex::encode).collect::<Vec<_>>() })
        }
        ClientEvent::Voice(VoiceEvent::Error(message)) => json!({ "event": "voice_error", "message": message }),
        other => json!({ "event": "other", "debug": format!("{other:?}") }),
    }
}

async fn run(device: &Device, command: Command) -> Result<Value, String> {
    let fail = |e: ghost_core::error::GhostError| e.to_string();
    match command {
        Command::CreateServer { name } => {
            let server_id = device.create_server(&name).await.map_err(fail)?;
            let general = ghost_core::wire::derive_default_channel_id(&server_id);
            Ok(json!({ "server": hex::encode(server_id), "general": hex::encode(general) }))
        }
        Command::Invite { server } => {
            let (token, key) = device.invite(&id32(&server)?).await.map_err(fail)?;
            Ok(json!({ "token": token, "key": hex::encode(key) }))
        }
        Command::Join { token, key } => {
            let server_id = device.join(&token, &id32(&key)?).await.map_err(fail)?;
            Ok(json!({ "server": hex::encode(server_id) }))
        }
        Command::Say { server, channel, text } => {
            device.say(&id32(&server)?, &id32(&channel)?, &text).await.map_err(fail)?;
            Ok(json!({}))
        }
        Command::Kick { server, member } => {
            let accepted = device.kick(&id32(&server)?, &id32(&member)?).await.map_err(fail)?;
            Ok(json!({ "accepted": accepted }))
        }
        Command::JoinVoice { server, channel } => {
            device.voice().join(id32(&server)?, id32(&channel)?, false, false).await.map_err(fail)?;
            Ok(json!({}))
        }
        Command::LeaveVoice => {
            device.voice().leave().await.map_err(fail)?;
            Ok(json!({}))
        }
        Command::SetMuted { muted } => {
            device.voice().set_muted(muted).await.map_err(fail)?;
            Ok(json!({}))
        }
        Command::Tone { frequency, amplitude } => {
            device.tone.set_tone(frequency, amplitude);
            Ok(json!({}))
        }
    }
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("ghost-node: {e}");
            std::process::exit(2);
        }
    };
    let device = match &args.create {
        Some(label) => Device::create(&args.data_dir, &args.relay, label).await,
        None => Device::open(&args.data_dir, &args.relay),
    };
    let mut device = match device {
        Ok(device) => device,
        Err(e) => {
            eprintln!("ghost-node: {e}");
            std::process::exit(1);
        }
    };

    // One writer for stdout, fed by replies and events.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Value>();
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(line) = out_rx.recv().await {
            let mut bytes = line.to_string().into_bytes();
            bytes.push(b'\n');
            if stdout.write_all(&bytes).await.is_err() || stdout.flush().await.is_err() {
                break;
            }
        }
    });
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<ClientEvent>();
    device.forward_events(event_tx);
    let events_out = out_tx.clone();
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            let _ = events_out.send(event_json(&event));
        }
    });

    device.start();
    let _ = out_tx.send(json!({ "event": "ready", "fingerprint": hex::encode(device.fingerprint().await) }));

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let reply = match serde_json::from_str::<Request>(&line) {
            Ok(request) => match run(&device, request.command).await {
                Ok(ok) => json!({ "id": request.id, "ok": ok }),
                Err(error) => json!({ "id": request.id, "error": error }),
            },
            Err(e) => json!({ "id": null, "error": format!("bad request: {e}") }),
        };
        let _ = out_tx.send(reply);
    }
    drop(out_tx);
    device.stop().await;
    let _ = writer.await;
}
