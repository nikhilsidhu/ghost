use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::constants::{VOICE_HEADER_SIZE, VOICE_MAX_PACKET, VOICE_VERSION};
use crate::state::AppState;

fn parse_header(buf: &[u8]) -> Option<([u8; 32], [u8; 32], usize)> {
    if buf.len() < VOICE_HEADER_SIZE {
        return None;
    }
    if buf[0] != VOICE_VERSION {
        return None;
    }

    let channel_id: [u8; 32] = buf[1..33].try_into().ok()?;
    let sender_fp: [u8; 32] = buf[33..65].try_into().ok()?;
    let payload_length = u16::from_be_bytes(buf[77..79].try_into().ok()?) as usize;

    let total = VOICE_HEADER_SIZE + payload_length;
    if buf.len() < total {
        return None;
    }

    Some((channel_id, sender_fp, total))
}

pub async fn run(state: AppState) {
    let port = state.config.voice_port;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let socket = match UdpSocket::bind(addr).await {
        Ok(s) => {
            let actual = s.local_addr().unwrap();
            tracing::info!("voice UDP listening on {actual}");
            let _ = state.voice_udp_port.send(actual.port());
            s
        }
        Err(e) => {
            tracing::error!("failed to bind voice UDP on {addr}: {e}");
            return;
        }
    };

    let mut buf = [0u8; VOICE_MAX_PACKET];

    loop {
        let (len, sender_addr) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("UDP recv error: {e}");
                continue;
            }
        };

        let (channel_id, sender_fp, valid_len) = match parse_header(&buf[..len]) {
            Some(h) => h,
            None => continue,
        };

        // First packet from this sender registers their real address
        if !state.routing.contains(&channel_id, &sender_fp) {
            state.routing.insert(channel_id, sender_fp, sender_addr);
        }

        let peers = state.routing.peers(&channel_id, &sender_addr);
        let packet = &buf[..valid_len];
        for peer in &peers {
            let _ = socket.try_send_to(packet, *peer);
        }
    }
}
