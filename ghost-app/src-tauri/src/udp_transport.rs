use std::net::SocketAddr;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::audio::{parse_header, InboundFrame};
use crate::constants::{VOICE_HEADER_SIZE, VOICE_MAX_PACKET};

pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    pub async fn connect(relay_host: &str, port: u16) -> Result<Self, String> {
        let addr: SocketAddr = format!("{relay_host}:{port}")
            .parse()
            .map_err(|e| format!("parse relay addr: {e}"))?;

        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("bind UDP: {e}"))?;
        socket
            .connect(addr)
            .await
            .map_err(|e| format!("connect UDP: {e}"))?;

        Ok(Self { socket })
    }

    /// Sends encoded packets from the audio pipeline to the relay.
    pub async fn send_loop(&self, mut outbound_rx: mpsc::Receiver<Vec<u8>>) {
        while let Some(pkt) = outbound_rx.recv().await {
            if let Err(e) = self.socket.send(&pkt).await {
                eprintln!("voice udp send: {e}");
            }
        }
    }

    /// Receives packets from the relay and forwards them to the audio pipeline,
    /// skipping our own packets.
    pub async fn recv_loop(&self, inbound_tx: mpsc::Sender<InboundFrame>, own_fp: [u8; 32]) {
        let mut buf = [0u8; VOICE_MAX_PACKET];
        loop {
            let len = match self.socket.recv(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("voice udp recv: {e}");
                    continue;
                }
            };

            let (_channel_id, sender_fp, sequence, payload_len) =
                match parse_header(&buf[..len]) {
                    Some(h) => h,
                    None => continue,
                };

            if sender_fp == own_fp {
                continue;
            }

            let payload = buf[VOICE_HEADER_SIZE..VOICE_HEADER_SIZE + payload_len].to_vec();
            let _ = inbound_tx
                .try_send(InboundFrame {
                    sender_fp,
                    sequence,
                    encrypted_payload: payload,
                })
                .ok();
        }
    }
}
