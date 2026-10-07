use std::net::SocketAddr;

use tokio::net::UdpSocket;

use ghost_wire::voice::VoiceBind;
use ghost_wire::{VOICE_HEADER_SIZE, VOICE_MAX_PACKET, VOICE_RELAY_PREFIX};
use crate::state::AppState;

/// Room and slot of a media packet: `[header_len:2][room_id:32][slot_id:4]...`. Older
/// header formats and anything shorter are dropped.
fn parse_media_header(buf: &[u8]) -> Option<([u8; 32], u32)> {
    if buf.len() < VOICE_RELAY_PREFIX {
        return None;
    }
    let header_len = u16::from_be_bytes(buf[0..2].try_into().ok()?) as usize;
    if header_len != VOICE_HEADER_SIZE || buf.len() < header_len {
        return None;
    }
    let room_id: [u8; 32] = buf[2..34].try_into().ok()?;
    let slot_id = u32::from_be_bytes(buf[34..38].try_into().ok()?);
    Some((room_id, slot_id))
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

        let packet = &buf[..len];
        if let Some(bind) = VoiceBind::from_bytes(packet) {
            if !state.routing.bind(&bind, sender_addr) {
                tracing::debug!("voice bind refused from {sender_addr}");
            }
            continue;
        }

        let Some((room_id, slot_id)) = parse_media_header(packet) else { continue };
        // Only a bound address speaks for its slot; anything else is dropped unread.
        let Some(peers) = state.routing.forward_targets(&room_id, slot_id, &sender_addr) else { continue };
        for peer in &peers {
            let _ = socket.try_send_to(packet, *peer);
        }
    }
}
