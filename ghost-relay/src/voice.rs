use std::net::SocketAddr;

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

struct SlotEntry {
    slot_id: u32,
    /// Handed to the participant at its authenticated join; keys its bind packets.
    token: [u8; 32],
    /// Where its media comes from and is sent to, once a bind has verified.
    addr: Option<SocketAddr>,
    /// Highest bind counter accepted, so a captured bind cannot be replayed.
    last_counter: u64,
}

/// Each room's admitted slots and their bound UDP addresses, for forwarding media.
pub struct RoutingTable {
    rooms: DashMap<[u8; 32], Vec<SlotEntry>>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            rooms: DashMap::new(),
        }
    }

    /// Admit a slot given out by an authenticated voice join; it carries no media until
    /// a bind with its token arrives.
    pub fn admit(&self, room_id: [u8; 32], slot_id: u32, token: [u8; 32]) {
        self.rooms
            .entry(room_id)
            .or_default()
            .push(SlotEntry { slot_id, token, addr: None, last_counter: 0 });
    }

    pub fn remove(&self, room_id: &[u8; 32], slot_id: &u32) {
        let mut remove_room = false;
        if let Some(mut entries) = self.rooms.get_mut(room_id) {
            entries.retain(|e| e.slot_id != *slot_id);
            remove_room = entries.is_empty();
        }
        if remove_room {
            self.rooms.remove(room_id);
        }
    }

    /// Bind the sender's address to the slot a bind packet names. Its MAC must verify
    /// under the slot's token and its counter must exceed every earlier one, which also
    /// lets a participant move to a new address (a changed network) at any time.
    pub fn bind(&self, bind: &ghost_wire::voice::VoiceBind, addr: SocketAddr) -> bool {
        let Some(mut entries) = self.rooms.get_mut(&bind.room_id) else { return false };
        let Some(entry) = entries.iter_mut().find(|e| e.slot_id == bind.slot_id) else { return false };
        if bind.counter <= entry.last_counter || !bind.verify(&entry.token) {
            return false;
        }
        entry.last_counter = bind.counter;
        entry.addr = Some(addr);
        true
    }

    /// Where to forward a media packet: every other bound address in the room, provided
    /// the packet comes from the address bound to the slot it names. `None` otherwise.
    pub fn forward_targets(
        &self,
        room_id: &[u8; 32],
        slot_id: u32,
        sender: &SocketAddr,
    ) -> Option<SmallVec<[SocketAddr; DEFAULT_MAX_VOICE_PARTICIPANTS]>> {
        let entries = self.rooms.get(room_id)?;
        let bound_sender = entries.iter().any(|e| e.slot_id == slot_id && e.addr.as_ref() == Some(sender));
        if !bound_sender {
            return None;
        }
        Some(entries.iter().filter_map(|e| e.addr).filter(|addr| addr != sender).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_wire::voice::VoiceBind;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn media_flows_only_between_bound_slots() {
        let table = RoutingTable::new();
        let room = [1; 32];
        table.admit(room, 1, [11; 32]);
        table.admit(room, 2, [22; 32]);

        // Unbound slots carry nothing, whatever address claims them.
        assert!(table.forward_targets(&room, 1, &addr(1000)).is_none());

        assert!(table.bind(&VoiceBind::sign(&[11; 32], room, 1, 1), addr(1000)));
        assert!(table.bind(&VoiceBind::sign(&[22; 32], room, 2, 1), addr(2000)));
        assert_eq!(table.forward_targets(&room, 1, &addr(1000)).unwrap().as_slice(), &[addr(2000)]);

        // Another address cannot speak for a bound slot.
        assert!(table.forward_targets(&room, 1, &addr(3000)).is_none());
    }

    #[test]
    fn binds_need_the_slot_token_and_a_fresh_counter() {
        let table = RoutingTable::new();
        let room = [1; 32];
        table.admit(room, 1, [11; 32]);

        assert!(!table.bind(&VoiceBind::sign(&[99; 32], room, 1, 1), addr(1000)), "wrong token");
        assert!(!table.bind(&VoiceBind::sign(&[11; 32], room, 2, 1), addr(1000)), "slot never admitted");

        let first = VoiceBind::sign(&[11; 32], room, 1, 5);
        assert!(table.bind(&first, addr(1000)));
        assert!(!table.bind(&first, addr(6666)), "a replayed bind cannot move the slot");

        // The participant itself moves to a new address with a newer bind.
        assert!(table.bind(&VoiceBind::sign(&[11; 32], room, 1, 6), addr(1001)));
        table.admit(room, 2, [22; 32]);
        table.bind(&VoiceBind::sign(&[22; 32], room, 2, 1), addr(2000));
        assert_eq!(table.forward_targets(&room, 2, &addr(2000)).unwrap().as_slice(), &[addr(1001)]);
    }
}
