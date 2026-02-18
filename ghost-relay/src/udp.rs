use std::net::SocketAddr;

use tokio::net::UdpSocket;

use ghost_wire::{VOICE_MAX_PACKET, VOICE_RELAY_PREFIX};
use crate::state::AppState;

// Relay only reads header_len + channel_id + sender_fp. It forwards the
// entire datagram without understanding flags, sequence, or payload.
fn parse_header(buf: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if buf.len() < VOICE_RELAY_PREFIX {
        return None;
    }
    let header_len = u16::from_be_bytes(buf[0..2].try_into().ok()?) as usize;
    if header_len < VOICE_RELAY_PREFIX || buf.len() < header_len {
        return None;
    }
    let channel_id: [u8; 32] = buf[2..34].try_into().ok()?;
    let sender_fp: [u8; 32] = buf[34..66].try_into().ok()?;
    Some((channel_id, sender_fp))
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

        let (channel_id, sender_fp) = match parse_header(&buf[..len]) {
            Some(h) => h,
            None => continue,
        };

        // First packet from this sender registers their real address
        if !state.routing.contains(&channel_id, &sender_fp) {
            state.routing.insert(channel_id, sender_fp, sender_addr);
        }

        let peers = state.routing.peers(&channel_id, &sender_addr);
        let packet = &buf[..len];
        for peer in &peers {
            let _ = socket.try_send_to(packet, *peer);
        }
    }
}
