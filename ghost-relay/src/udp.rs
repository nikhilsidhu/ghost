use std::net::SocketAddr;

use tokio::net::UdpSocket;

use ghost_wire::VOICE_MAX_PACKET;
use crate::state::AppState;

// Relay reads header_len + channel_id + slot_id for routing.
// Dispatches on header_len to reject old 73-byte format packets.
fn parse_header(buf: &[u8]) -> Option<([u8; 32], u32)> {
    if buf.len() < 38 {
        return None;
    }
    let header_len = u16::from_be_bytes(buf[0..2].try_into().ok()?) as usize;
    if buf.len() < header_len {
        return None;
    }
    let channel_id: [u8; 32] = buf[2..34].try_into().ok()?;
    match header_len {
        // [header_len:2][channel_id:32][slot_id:4]...
        45 => {
            let slot_id = u32::from_be_bytes(buf[34..38].try_into().ok()?);
            Some((channel_id, slot_id))
        }
        // [header_len:2][channel_id:32][fingerprint:32]... — reject, old clients must upgrade
        73 => None,
        _ => None,
    }
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

        let (channel_id, slot_id) = match parse_header(&buf[..len]) {
            Some(h) => h,
            None => continue,
        };

        // Register or update the slot's address (handles NAT rebinding)
        if !state.routing.contains(&channel_id, &slot_id) {
            state.routing.insert(channel_id, slot_id, sender_addr);
        } else {
            state.routing.update_addr(&channel_id, &slot_id, sender_addr);
        }

        let peers = state.routing.peers(&channel_id, &sender_addr);
        let packet = &buf[..len];
        for peer in &peers {
            let _ = socket.try_send_to(packet, *peer);
        }
    }
}
