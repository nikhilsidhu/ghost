use std::net::SocketAddr;
use std::time::Instant;

use dashmap::DashMap;
use smallvec::SmallVec;
use tokio::sync::broadcast;

use crate::constants::{DEFAULT_MAX_VOICE_PARTICIPANTS, VOICE_EVENT_CAPACITY};

#[derive(Clone, Debug)]
pub enum VoiceEvent {
    Joined { fingerprint: [u8; 32] },
    Left { fingerprint: [u8; 32] },
    Speaking { fingerprint: [u8; 32], speaking: bool },
}

pub struct Participant {
    pub fingerprint: [u8; 32],
    pub udp_addr: Option<SocketAddr>,
    pub last_udp: Instant,
    pub speaking: bool,
}

pub struct VoiceChannel {
    pub participants: Vec<Participant>,
    pub notify: broadcast::Sender<VoiceEvent>,
}

impl VoiceChannel {
    pub fn new() -> Self {
        let (notify, _) = broadcast::channel(VOICE_EVENT_CAPACITY);
        Self {
            participants: Vec::new(),
            notify,
        }
    }
}

/// Maps channel → participant addresses for UDP packet forwarding.
pub struct RoutingTable {
    channels: DashMap<[u8; 32], Vec<([u8; 32], SocketAddr)>>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            channels: DashMap::new(),
        }
    }

    pub fn insert(&self, channel_id: [u8; 32], fingerprint: [u8; 32], addr: SocketAddr) {
        self.channels
            .entry(channel_id)
            .or_default()
            .push((fingerprint, addr));
    }

    pub fn remove(&self, channel_id: &[u8; 32], fingerprint: &[u8; 32]) {
        let mut remove_channel = false;
        if let Some(mut entries) = self.channels.get_mut(channel_id) {
            entries.retain(|(fp, _)| fp != fingerprint);
            remove_channel = entries.is_empty();
        }
        if remove_channel {
            self.channels.remove(channel_id);
        }
    }

    /// Returns addresses to forward a packet to (everyone except who sent it).
    pub fn peers(
        &self,
        channel_id: &[u8; 32],
        sender: &SocketAddr,
    ) -> SmallVec<[SocketAddr; DEFAULT_MAX_VOICE_PARTICIPANTS]> {
        self.channels
            .get(channel_id)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(_, addr)| addr != sender)
                    .map(|(_, addr)| *addr)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn update_addr(
        &self,
        channel_id: &[u8; 32],
        fingerprint: &[u8; 32],
        new_addr: SocketAddr,
    ) {
        if let Some(mut entries) = self.channels.get_mut(channel_id) {
            if let Some((_, addr)) = entries.iter_mut().find(|(fp, _)| fp == fingerprint) {
                *addr = new_addr;
            }
        }
    }

    pub fn contains(&self, channel_id: &[u8; 32], fingerprint: &[u8; 32]) -> bool {
        self.channels
            .get(channel_id)
            .map(|entries| entries.iter().any(|(fp, _)| fp == fingerprint))
            .unwrap_or(false)
    }
}
