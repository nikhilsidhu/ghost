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

/// Minimum time before a slot's address can be updated by a different sender.
const SLOT_REBIND_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(5);

struct SlotEntry {
    slot_id: u32,
    addr: SocketAddr,
    last_seen: Instant,
}

/// Maps channel → participant addresses for UDP packet forwarding.
pub struct RoutingTable {
    channels: DashMap<[u8; 32], Vec<SlotEntry>>,
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
            .push(SlotEntry { slot_id, addr, last_seen: Instant::now() });
    }

    pub fn remove(&self, channel_id: &[u8; 32], slot_id: &u32) {
        let mut remove_channel = false;
        if let Some(mut entries) = self.channels.get_mut(channel_id) {
            entries.retain(|e| e.slot_id != *slot_id);
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
                    .filter(|e| e.addr != *sender)
                    .map(|e| e.addr)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Update slot address. Only allows rebinding from a different sender
    /// if the current owner hasn't sent anything for SLOT_REBIND_COOLDOWN.
    pub fn update_addr(
        &self,
        channel_id: &[u8; 32],
        slot_id: &u32,
        new_addr: SocketAddr,
    ) -> bool {
        if let Some(mut entries) = self.channels.get_mut(channel_id) {
            if let Some(entry) = entries.iter_mut().find(|e| e.slot_id == *slot_id) {
                if entry.addr == new_addr {
                    // Same sender — just refresh timestamp
                    entry.last_seen = Instant::now();
                    return true;
                }
                // Different sender — only allow if cooldown elapsed
                if entry.last_seen.elapsed() >= SLOT_REBIND_COOLDOWN {
                    entry.addr = new_addr;
                    entry.last_seen = Instant::now();
                    return true;
                }
                return false; // Rejected: slot still active
            }
        }
        false
    }

    pub fn contains(&self, channel_id: &[u8; 32], slot_id: &u32) -> bool {
        self.channels
            .get(channel_id)
            .map(|entries| entries.iter().any(|e| e.slot_id == *slot_id))
            .unwrap_or(false)
    }
}
