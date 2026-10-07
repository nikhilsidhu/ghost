//! Binding a voice participant's UDP address to the slot its authenticated voice join
//! was given. The join, over a device-authenticated WebSocket, hands the participant a
//! room id, a slot and a secret token. The participant then sends bind packets from its
//! UDP socket, keyed with the token and carrying an increasing counter; the relay
//! forwards media only between bound addresses. As with ICE binding after signaling,
//! knowing a room or slot id is not enough to receive a room's packets, and a bind seen
//! on the wire cannot be replayed to steal a slot.

/// `[header_len:2 = 78][room_id:32][slot_id:4][counter:8][mac:32]`; the length field
/// tells binds apart from media packets.
pub const VOICE_BIND_SIZE: usize = 2 + 32 + 4 + 8 + 32;

const ROOM_DOMAIN: &str = "ghost voice room v1";
const BIND_DOMAIN: &[u8] = b"ghost-voice-bind-v1";

/// The relay's id for the voice room of `channel_id` within the group whose mailbox
/// is `mailbox_id`, so rooms of different groups never meet.
pub fn voice_room_id(mailbox_id: &[u8; 32], channel_id: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ROOM_DOMAIN);
    hasher.update(mailbox_id);
    hasher.update(channel_id);
    hasher.finalize().into()
}

/// A request to bind the sending address to a slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceBind {
    pub room_id: [u8; 32],
    pub slot_id: u32,
    /// Strictly increasing per slot, so a captured bind is useless.
    pub counter: u64,
    pub mac: [u8; 32],
}

fn mac(token: &[u8; 32], room_id: &[u8; 32], slot_id: u32, counter: u64) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new_keyed(token);
    hasher.update(BIND_DOMAIN);
    hasher.update(room_id);
    hasher.update(&slot_id.to_be_bytes());
    hasher.update(&counter.to_be_bytes());
    hasher.finalize()
}

impl VoiceBind {
    pub fn sign(token: &[u8; 32], room_id: [u8; 32], slot_id: u32, counter: u64) -> Self {
        Self { room_id, slot_id, counter, mac: mac(token, &room_id, slot_id, counter).into() }
    }

    /// Whether the MAC was made with `token` (compared in constant time).
    pub fn verify(&self, token: &[u8; 32]) -> bool {
        mac(token, &self.room_id, self.slot_id, self.counter) == blake3::Hash::from(self.mac)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(VOICE_BIND_SIZE);
        buf.extend_from_slice(&(VOICE_BIND_SIZE as u16).to_be_bytes());
        buf.extend_from_slice(&self.room_id);
        buf.extend_from_slice(&self.slot_id.to_be_bytes());
        buf.extend_from_slice(&self.counter.to_be_bytes());
        buf.extend_from_slice(&self.mac);
        buf
    }

    /// Parse a bind packet; `None` for anything else, media packets included.
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() != VOICE_BIND_SIZE || u16::from_be_bytes([buf[0], buf[1]]) as usize != VOICE_BIND_SIZE {
            return None;
        }
        Some(Self {
            room_id: buf[2..34].try_into().ok()?,
            slot_id: u32::from_be_bytes(buf[34..38].try_into().ok()?),
            counter: u64::from_be_bytes(buf[38..46].try_into().ok()?),
            mac: buf[46..78].try_into().ok()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_roundtrip_and_verification() {
        let token = [7; 32];
        let room = voice_room_id(&[1; 32], &[2; 32]);
        let bind = VoiceBind::sign(&token, room, 9, 3);
        let parsed = VoiceBind::from_bytes(&bind.to_bytes()).unwrap();
        assert_eq!(parsed, bind);
        assert!(parsed.verify(&token));
        assert!(!parsed.verify(&[8; 32]), "another slot's token");
        let tampered = VoiceBind { counter: 4, ..parsed };
        assert!(!tampered.verify(&token), "counter is covered by the MAC");
    }

    #[test]
    fn rooms_differ_by_group_and_channel() {
        let a = voice_room_id(&[1; 32], &[2; 32]);
        assert_ne!(a, voice_room_id(&[3; 32], &[2; 32]));
        assert_ne!(a, voice_room_id(&[1; 32], &[4; 32]));
    }

    #[test]
    fn media_packets_are_not_binds() {
        let mut media = vec![0u8; crate::VOICE_HEADER_SIZE];
        media[..2].copy_from_slice(&(crate::VOICE_HEADER_SIZE as u16).to_be_bytes());
        assert!(VoiceBind::from_bytes(&media).is_none());
    }
}
