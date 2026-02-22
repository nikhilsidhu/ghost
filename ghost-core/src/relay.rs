use std::collections::HashMap;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

use ghost_wire::{WS_FRAME_HEADER_SIZE, WS_SEQ_SIZE, WS_SIGNAL_EPOCH_MISMATCH, WS_SIGNAL_GAP};

use crate::error::{GhostError, Result};

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

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
    Gap { mailbox_id: [u8; 32] },
    VoiceState { mailbox_id: [u8; 32], json: String },
    Presence { mailbox_id: [u8; 32], json: String },
    ConnectionState { mailbox_id: [u8; 32], connected: bool },
}

pub enum WsOutgoing {
    Binary(Vec<u8>),
    Text(String),
}

struct WsHandle {
    outbox: mpsc::Sender<WsOutgoing>,
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

    /// Subscribe to a mailbox. The connection is established in the background
    /// with automatic reconnection on failure.
    pub fn subscribe(&mut self, mailbox_id: [u8; 32], last_seen_seq: u64) {
        let url = format!(
            "{}/ws/{}",
            self.ws_base_url,
            URL_SAFE_NO_PAD.encode(mailbox_id)
        );

        if let Some(old) = self.connections.remove(&mailbox_id) {
            old.task.abort();
        }

        let (outbox_tx, outbox_rx) = mpsc::channel(64);
        let event_tx = self.event_tx.clone();
        let task = tokio::spawn(ws_task(url, mailbox_id, last_seen_seq, event_tx, outbox_rx));
        self.connections
            .insert(mailbox_id, WsHandle { outbox: outbox_tx, task });
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
            .send(WsOutgoing::Binary(blob))
            .await
            .map_err(|_| GhostError::Network("ws connection closed".into()))
    }

    pub async fn send_text(&self, mailbox_id: &[u8; 32], text: String) -> Result<()> {
        let handle = self
            .connections
            .get(mailbox_id)
            .ok_or_else(|| GhostError::Network("not subscribed to mailbox".into()))?;
        handle
            .outbox
            .send(WsOutgoing::Text(text))
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

    pub async fn put_server_info(&self, mailbox_id: &[u8; 32], data: Vec<u8>) -> Result<()> {
        let resp = self
            .http
            .put(format!(
                "{}/box/{}/server_info",
                self.base_url,
                URL_SAFE_NO_PAD.encode(mailbox_id)
            ))
            .body(data)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!(
                "put server_info: {}",
                resp.status()
            )));
        }
        Ok(())
    }

    pub async fn get_server_info(&self, mailbox_id: &[u8; 32]) -> Result<Vec<u8>> {
        let resp = self
            .http
            .get(format!(
                "{}/box/{}/server_info",
                self.base_url,
                URL_SAFE_NO_PAD.encode(mailbox_id)
            ))
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!(
                "get server_info: {}",
                resp.status()
            )));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| GhostError::Network(e.to_string()))
    }

    pub async fn put_avatar(
        &self,
        mailbox_id: &[u8; 32],
        fingerprint: &[u8; 32],
        data: Vec<u8>,
    ) -> Result<()> {
        let resp = self
            .http
            .put(format!(
                "{}/box/{}/avatar/{}",
                self.base_url,
                URL_SAFE_NO_PAD.encode(mailbox_id),
                hex::encode(fingerprint),
            ))
            .body(data)
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!("put avatar: {}", resp.status())));
        }
        Ok(())
    }

    pub async fn get_avatar(
        &self,
        mailbox_id: &[u8; 32],
        fingerprint: &[u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        let resp = self
            .http
            .get(format!(
                "{}/box/{}/avatar/{}",
                self.base_url,
                URL_SAFE_NO_PAD.encode(mailbox_id),
                hex::encode(fingerprint),
            ))
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!("get avatar: {}", resp.status())));
        }
        resp.bytes()
            .await
            .map(|b| Some(b.to_vec()))
            .map_err(|e| GhostError::Network(e.to_string()))
    }

    pub async fn delete_avatar(
        &self,
        mailbox_id: &[u8; 32],
        fingerprint: &[u8; 32],
    ) -> Result<()> {
        let resp = self
            .http
            .delete(format!(
                "{}/box/{}/avatar/{}",
                self.base_url,
                URL_SAFE_NO_PAD.encode(mailbox_id),
                hex::encode(fingerprint),
            ))
            .send()
            .await
            .map_err(|e| GhostError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(GhostError::Network(format!("delete avatar: {}", resp.status())));
        }
        Ok(())
    }
}

impl Drop for RelayClient {
    fn drop(&mut self) {
        for (_, handle) in self.connections.drain() {
            handle.task.abort();
        }
    }
}

/// Persistent task that maintains a WebSocket connection with automatic reconnection.
async fn ws_task(
    url: String,
    mailbox_id: [u8; 32],
    initial_last_seen: u64,
    event_tx: mpsc::Sender<RelayEvent>,
    mut outbox_rx: mpsc::Receiver<WsOutgoing>,
) {
    let mut last_seen = initial_last_seen;
    let mut backoff = INITIAL_BACKOFF;
    let mut first_attempt = true;

    loop {
        if !first_attempt {
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
        first_attempt = false;

        let ws = match tokio_tungstenite::connect_async(&url).await {
            Ok((ws, _)) => ws,
            Err(_) => continue,
        };

        let (mut sink, mut stream) = ws.split();

        // Handshake: send last_seen_seq so the relay replays missed entries
        if sink
            .send(Message::Binary(last_seen.to_be_bytes().to_vec().into()))
            .await
            .is_err()
        {
            continue;
        }

        let _ = event_tx.send(RelayEvent::ConnectionState { mailbox_id, connected: true }).await;
        let mut got_message = false;

        loop {
            tokio::select! {
                outgoing = outbox_rx.recv() => {
                    match outgoing {
                        Some(WsOutgoing::Binary(data)) => {
                            if sink.send(Message::Binary(data.into())).await.is_err() {
                                break;
                            }
                        }
                        Some(WsOutgoing::Text(text)) => {
                            if sink.send(Message::Text(text.into())).await.is_err() {
                                break;
                            }
                        }
                        None => return,
                    }
                }
                msg = stream.next() => {
                    match msg {
                        Some(Ok(Message::Binary(data))) => {
                            if data.len() < WS_FRAME_HEADER_SIZE {
                                continue;
                            }
                            let seq = u64::from_be_bytes(data[..WS_SEQ_SIZE].try_into().unwrap());
                            let received_at = u64::from_be_bytes(
                                data[WS_SEQ_SIZE..WS_FRAME_HEADER_SIZE].try_into().unwrap(),
                            );
                            let payload = data[WS_FRAME_HEADER_SIZE..].to_vec();
                            last_seen = seq;
                            if !got_message {
                                got_message = true;
                                backoff = INITIAL_BACKOFF;
                            }
                            let _ = event_tx.send(RelayEvent::Blob(IncomingBlob {
                                mailbox_id,
                                seq,
                                received_at,
                                payload,
                            })).await;
                        }
                        Some(Ok(Message::Text(text))) => {
                            if !got_message {
                                got_message = true;
                                backoff = INITIAL_BACKOFF;
                            }
                            let s = text.as_str();
                            if s == WS_SIGNAL_GAP {
                                let _ = event_tx.send(RelayEvent::Gap { mailbox_id }).await;
                            } else if s.starts_with("{\"vs") {
                                let _ = event_tx.send(RelayEvent::VoiceState {
                                    mailbox_id,
                                    json: s.to_string(),
                                }).await;
                            } else if s.starts_with("{\"ps") {
                                let _ = event_tx.send(RelayEvent::Presence {
                                    mailbox_id,
                                    json: s.to_string(),
                                }).await;
                            } else if let Some(ack) = parse_ack(s) {
                                let _ = event_tx.send(RelayEvent::Ack(ack)).await;
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => break, // reconnect
                        _ => {}
                    }
                }
            }
        }

        let _ = event_tx.send(RelayEvent::ConnectionState { mailbox_id, connected: false }).await;
    }
}

fn parse_ack(text: &str) -> Option<Ack> {
    let mut parts = text.splitn(2, ' ');
    let seq: u64 = parts.next()?.parse().ok()?;
    let epoch_mismatch = parts.next() == Some(WS_SIGNAL_EPOCH_MISMATCH);
    Some(Ack { seq, epoch_mismatch })
}
