use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

use crate::error::{GhostError, Result};

const SEQ_SIZE: usize = 8;
const TIMESTAMP_SIZE: usize = 8;
const FRAME_HEADER_SIZE: usize = SEQ_SIZE + TIMESTAMP_SIZE;

pub struct IncomingBlob {
    pub mailbox_id: [u8; 32],
    pub seq: u64,
    pub received_at: u64,
    pub payload: Vec<u8>,
}

pub struct Ack {
    pub seq: u64,
    pub epoch_mismatch: bool,
}

pub enum RelayEvent {
    Blob(IncomingBlob),
    Ack(Ack),
}

struct WsHandle {
    outbox: mpsc::Sender<Vec<u8>>,
    task: JoinHandle<()>,
}

pub struct RelayClient {
    base_url: String,
    ws_base_url: String,
    http: reqwest::Client,
    event_tx: mpsc::Sender<RelayEvent>,
    connections: HashMap<[u8; 32], WsHandle>,
}

impl RelayClient {
    pub fn new(base_url: &str) -> (Self, mpsc::Receiver<RelayEvent>) {
        let base = base_url.trim_end_matches('/').to_string();
        let ws_base = base
            .replace("http://", "ws://")
            .replace("https://", "wss://");
        let (event_tx, event_rx) = mpsc::channel(256);
        let client = Self {
            base_url: base,
            ws_base_url: ws_base,
            http: reqwest::Client::new(),
            event_tx,
            connections: HashMap::new(),
        };
        (client, event_rx)
    }

    pub async fn subscribe(&mut self, mailbox_id: [u8; 32], last_seen_seq: u64) -> Result<()> {
        let url = format!(
            "{}/ws/{}",
            self.ws_base_url,
            URL_SAFE_NO_PAD.encode(mailbox_id)
        );
        let (ws, _) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;

        if let Some(old) = self.connections.remove(&mailbox_id) {
            old.task.abort();
        }

        let (outbox_tx, outbox_rx) = mpsc::channel(64);
        let event_tx = self.event_tx.clone();
        let task = tokio::spawn(ws_loop(ws, mailbox_id, last_seen_seq, event_tx, outbox_rx));
        self.connections
            .insert(mailbox_id, WsHandle { outbox: outbox_tx, task });
        Ok(())
    }

    pub fn unsubscribe(&mut self, mailbox_id: &[u8; 32]) {
        if let Some(handle) = self.connections.remove(mailbox_id) {
            handle.task.abort();
        }
    }

    pub async fn send(&self, mailbox_id: &[u8; 32], blob: Vec<u8>) -> Result<()> {
        let handle = self
            .connections
            .get(mailbox_id)
            .ok_or_else(|| GhostError::Network("not subscribed to mailbox".into()))?;
        handle
            .outbox
            .send(blob)
            .await
            .map_err(|_| GhostError::Network("ws connection closed".into()))
    }

    pub async fn register_invite(&self, token: &str, expires_at: u64) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/invite", self.base_url))
            .json(&serde_json::json!({ "token": token, "expires_at": expires_at }))
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!(
                "register invite: {}",
                resp.status()
            )));
        }
        Ok(())
    }

    pub async fn post_join(&self, token: &str, payload: Vec<u8>) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/invite/{}/join", self.base_url, token))
            .body(payload)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!(
                "post join: {}",
                resp.status()
            )));
        }
        Ok(())
    }

    pub async fn get_join(&self, token: &str) -> Result<Vec<u8>> {
        let resp = self
            .http
            .get(format!("{}/invite/{}/join", self.base_url, token))
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NO_CONTENT {
            return Err(GhostError::Network("join not yet submitted".into()));
        }
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!(
                "get join: {}",
                resp.status()
            )));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| GhostError::Network(e.to_string()))
    }

    pub async fn post_accept(&self, token: &str, payload: Vec<u8>) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/invite/{}/accept", self.base_url, token))
            .body(payload)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!(
                "post accept: {}",
                resp.status()
            )));
        }
        Ok(())
    }

    pub async fn get_accept(&self, token: &str) -> Result<Vec<u8>> {
        let resp = self
            .http
            .get(format!("{}/invite/{}/accept", self.base_url, token))
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NO_CONTENT {
            return Err(GhostError::Network("accept not yet submitted".into()));
        }
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!(
                "get accept: {}",
                resp.status()
            )));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| GhostError::Network(e.to_string()))
    }
}

impl Drop for RelayClient {
    fn drop(&mut self) {
        for (_, handle) in self.connections.drain() {
            handle.task.abort();
        }
    }
}

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn ws_loop(
    ws: WsStream,
    mailbox_id: [u8; 32],
    last_seen_seq: u64,
    event_tx: mpsc::Sender<RelayEvent>,
    mut outbox_rx: mpsc::Receiver<Vec<u8>>,
) {
    let (mut sink, mut stream) = ws.split();

    // Handshake: send last_seen_seq so the relay replays missed entries
    let handshake = last_seen_seq.to_be_bytes().to_vec();
    if sink.send(Message::Binary(handshake.into())).await.is_err() {
        return;
    }

    loop {
        tokio::select! {
            blob = outbox_rx.recv() => {
                match blob {
                    Some(data) => {
                        if sink.send(Message::Binary(data.into())).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Binary(data))) => {
                        if data.len() < FRAME_HEADER_SIZE {
                            continue;
                        }
                        let seq = u64::from_be_bytes(data[..SEQ_SIZE].try_into().unwrap());
                        let received_at = u64::from_be_bytes(
                            data[SEQ_SIZE..FRAME_HEADER_SIZE].try_into().unwrap(),
                        );
                        let payload = data[FRAME_HEADER_SIZE..].to_vec();
                        let _ = event_tx.send(RelayEvent::Blob(IncomingBlob {
                            mailbox_id,
                            seq,
                            received_at,
                            payload,
                        })).await;
                    }
                    Some(Ok(Message::Text(text))) => {
                        if let Some(ack) = parse_ack(&text) {
                            let _ = event_tx.send(RelayEvent::Ack(ack)).await;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
}

fn parse_ack(text: &str) -> Option<Ack> {
    let mut parts = text.splitn(2, ' ');
    let seq: u64 = parts.next()?.parse().ok()?;
    let epoch_mismatch = parts.next() == Some("epoch_mismatch");
    Some(Ack { seq, epoch_mismatch })
}
