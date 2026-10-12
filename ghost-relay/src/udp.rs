use std::net::SocketAddr;

use tokio::net::UdpSocket;

use ghost_wire::voice::{MediaHeader, VoiceBind};
use ghost_wire::VOICE_MAX_PACKET;
use crate::state::AppState;

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
            match state.routing.bind(&bind, sender_addr) {
                Some(answer) => {
                    let _ = socket.try_send_to(&answer.to_bytes(), sender_addr);
                }
                None => tracing::debug!("voice bind refused from {sender_addr}"),
            }
            continue;
        }

        // Other header formats and truncated packets are dropped.
        let Some((header, _)) = MediaHeader::parse(packet) else { continue };
        // Only a bound address speaks for its slot; anything else is dropped unread.
        let Some(peers) = state.routing.forward_targets(&header.room_id, header.slot_id, &sender_addr) else { continue };
        for peer in &peers {
            let _ = socket.try_send_to(packet, *peer);
        }
    }
}
