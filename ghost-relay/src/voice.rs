use std::net::SocketAddr;
use std::time::Instant;

use dashmap::DashMap;
use smallvec::SmallVec;
use tokio::sync::broadcast;

use crate::constants::{DEFAULT_MAX_VOICE_PARTICIPANTS, VOICE_EVENT_CAPACITY};

#[derive(Clone, Debug)]
pub enum VoiceEvent {
    Joined { slot_id: u32 },
    Left { slot_id: u32 },
    Presence { slot_id: u32, blob: Vec<u8> },
    Speaking { slot_id: u32, speaking: bool },
}

pub struct Participant {
    pub slot_id: u32,
    pub udp_addr: Option<SocketAddr>,
    pub last_udp: Instant,
    pub latest_presence: Option<Vec<u8>>,
}

pub struct VoiceChannel {
    pub participants: Vec<Participant>,
    pub notify: broadcast::Sender<VoiceEvent>,
    next_slot: u32,
}

impl VoiceChannel {
    pub fn new() -> Self {
        let (notify, _) = broadcast::channel(VOICE_EVENT_CAPACITY);
        Self {
            participants: Vec::new(),
            notify,
            next_slot: 1,
        }
    }

    pub fn alloc_slot(&mut self) -> u32 {
        let id = self.next_slot;
        self.next_slot = self.next_slot.wrapping_add(1);
        id
    }
}

/// Maps channel → participant addresses for UDP packet forwarding.
pub struct RoutingTable {
    channels: DashMap<[u8; 32], Vec<(u32, SocketAddr)>>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            channels: DashMap::new(),
        }
    }

    pub fn insert(&self, channel_id: [u8; 32], slot_id: u32, addr: SocketAddr) {
        self.channels
            .entry(channel_id)
            .or_default()
            .push((slot_id, addr));
    }

    pub fn remove(&self, channel_id: &[u8; 32], slot_id: &u32) {
        let mut remove_channel = false;
        if let Some(mut entries) = self.channels.get_mut(channel_id) {
            entries.retain(|(s, _)| s != slot_id);
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
        slot_id: &u32,
        new_addr: SocketAddr,
    ) {
        if let Some(mut entries) = self.channels.get_mut(channel_id) {
            if let Some((_, addr)) = entries.iter_mut().find(|(s, _)| s == slot_id) {
                *addr = new_addr;
            }
        }
    }

    pub fn contains(&self, channel_id: &[u8; 32], slot_id: &u32) -> bool {
        self.channels
            .get(channel_id)
            .map(|entries| entries.iter().any(|(s, _)| s == slot_id))
            .unwrap_or(false)
    }
}
