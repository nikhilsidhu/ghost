//! What voice clients and the relay exchange: the signaling messages of the voice
//! WebSocket, the media packet header, and the binds that tie a participant's UDP
//! address to its slot.
//!
//! The join, over a device-authenticated WebSocket, hands the participant a room id, a
//! slot and a secret token. The participant then sends bind packets from its UDP
//! socket, keyed with the token and carrying an increasing counter; the relay forwards
//! media only between bound addresses and answers each bind it accepts, so the
//! participant knows its media gets through. As with ICE binding after signaling,
//! knowing a room or slot id is not enough to receive a room's packets, and a bind seen
//! on the wire cannot be replayed to steal a slot.
//!
//! The token also lets a participant whose WebSocket dropped claim its slot back on a
//! new one, so the call and its media carry on through a signaling blip.

use serde::{Deserialize, Serialize};

use crate::presence::PresenceSender;
use crate::VOICE_HEADER_SIZE;

/// `[header_len:2 = 78][room_id:32][slot_id:4][counter:8][mac:32]`; the length field
/// tells binds apart from media packets. The relay's answer to a bind has the same
/// layout, keyed for the other direction.
pub const VOICE_BIND_SIZE: usize = 2 + 32 + 4 + 8 + 32;

/// Client to relay, as JSON text frames on the voice WebSocket. Presence blobs are
/// sealed to the group, so the relay only stores and forwards them (base64), stamped
/// with the authenticated device that sent them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    Join { presence: String },
    /// Claim back the slot a dropped connection held, proving it with the slot's token
    /// (base64), and announce the presence as it is now.
    Resume { slot_id: u32, token: String, presence: String },
    Leave,
    Presence { blob: String },
    Speaking { speaking: bool },
    /// Ask for a fresh welcome listing the room's current peers.
    Resync,
    /// How much of each other participant's media this one lost lately, for the relay
    /// to pass to each of them: a sender protects its frames (Opus FEC) against the worst
    /// loss its listeners report.
    Reception { reports: Vec<Reception> },
}

/// The share of a participant's frames lost on the way to the reporter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reception {
    pub slot_id: u32,
    /// Percent of its frames lost lately, 0 to 100.
    pub loss_pct: u8,
}

/// Relay to client, as JSON text frames on the voice WebSocket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// `room` goes in every media packet header; `token` keys the bind packets that tie
    /// the participant's UDP address to `slot_id`. Both are base64. Sent again, with
    /// the current peers, after a resync or a resume.
    Welcome { slot_id: u32, port: u16, room: String, token: String, peers: Vec<PeerEntry> },
    /// The slot a resume named is gone (the relay ended it or restarted); join afresh.
    NotResumed,
    Joined { slot_id: u32, presence: String, from: PresenceSender },
    Left { slot_id: u32 },
    Presence { slot_id: u32, blob: String, from: PresenceSender },
    Speaking { slot_id: u32, speaking: bool },
    /// The participant in `slot_id` lost this share (percent) of our frames lately.
    Reception { slot_id: u32, loss_pct: u8 },
    Error { message: String },
}

/// A participant already in the room, with its latest presence blob and who sent it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerEntry {
    pub slot_id: u32,
    pub presence: String,
    pub from: PresenceSender,
}

/// The header of every media packet:
/// `[header_len:2][room_id:32][slot_id:4][flags:1][epoch:8][seq:4][payload_len:2]`.
/// The relay routes by room and slot, both assigned at the voice join; `epoch` names
/// the MLS epoch whose key encrypted the payload and `sequence` the frame counter it
/// was encrypted under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaHeader {
    pub room_id: [u8; 32],
    pub slot_id: u32,
    pub epoch: u64,
    pub sequence: u32,
}

impl MediaHeader {
    /// A packet carrying `payload` under this header.
    pub fn packet(&self, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(VOICE_HEADER_SIZE + payload.len());
        packet.extend_from_slice(&(VOICE_HEADER_SIZE as u16).to_be_bytes());
        packet.extend_from_slice(&self.room_id);
        packet.extend_from_slice(&self.slot_id.to_be_bytes());
        packet.push(0x00); // flags, none defined yet
        packet.extend_from_slice(&self.epoch.to_be_bytes());
        packet.extend_from_slice(&self.sequence.to_be_bytes());
        packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    /// Split a media packet into its header and payload; `None` for binds, other
    /// header formats and truncated packets.
    pub fn parse(buf: &[u8]) -> Option<(Self, &[u8])> {
        if buf.len() < VOICE_HEADER_SIZE || u16::from_be_bytes([buf[0], buf[1]]) as usize != VOICE_HEADER_SIZE {
            return None;
        }
        let payload_len = u16::from_be_bytes(buf[51..53].try_into().ok()?) as usize;
        let payload = buf.get(VOICE_HEADER_SIZE..VOICE_HEADER_SIZE + payload_len)?;
        let header = Self {
            room_id: buf[2..34].try_into().ok()?,
            slot_id: u32::from_be_bytes(buf[34..38].try_into().ok()?),
            epoch: u64::from_be_bytes(buf[39..47].try_into().ok()?),
            sequence: u32::from_be_bytes(buf[47..51].try_into().ok()?),
        };
        Some((header, payload))
    }
}

const ROOM_DOMAIN: &str = "ghost voice room v1";
const BIND_DOMAIN: &[u8] = b"ghost-voice-bind-v1";
const BIND_ACK_DOMAIN: &[u8] = b"ghost-voice-bind-ack-v1";

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

fn mac(domain: &[u8], token: &[u8; 32], room_id: &[u8; 32], slot_id: u32, counter: u64) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new_keyed(token);
    hasher.update(domain);
    hasher.update(room_id);
    hasher.update(&slot_id.to_be_bytes());
    hasher.update(&counter.to_be_bytes());
    hasher.finalize()
}

impl VoiceBind {
    pub fn sign(token: &[u8; 32], room_id: [u8; 32], slot_id: u32, counter: u64) -> Self {
        Self { room_id, slot_id, counter, mac: mac(BIND_DOMAIN, token, &room_id, slot_id, counter).into() }
    }

    /// Whether the MAC was made with `token` (compared in constant time).
    pub fn verify(&self, token: &[u8; 32]) -> bool {
        mac(BIND_DOMAIN, token, &self.room_id, self.slot_id, self.counter) == blake3::Hash::from(self.mac)
    }

    /// The relay's answer to this bind, once accepted: the same fields, keyed for the
    /// way back, so a bind reflected to its sender does not pass for an answer.
    pub fn answer(&self, token: &[u8; 32]) -> Self {
        Self { mac: mac(BIND_ACK_DOMAIN, token, &self.room_id, self.slot_id, self.counter).into(), ..self.clone() }
    }

    /// Whether this is the relay's answer to a bind made with `token`.
    pub fn verify_answer(&self, token: &[u8; 32]) -> bool {
        mac(BIND_ACK_DOMAIN, token, &self.room_id, self.slot_id, self.counter) == blake3::Hash::from(self.mac)
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
    fn a_bind_and_its_answer_are_told_apart() {
        let token = [7; 32];
        let bind = VoiceBind::sign(&token, [5; 32], 9, 3);
        let answer = VoiceBind::from_bytes(&bind.answer(&token).to_bytes()).unwrap();
        assert!(answer.verify_answer(&token));
        assert!(!answer.verify(&token), "an answer is no bind");
        assert!(!bind.verify_answer(&token), "a bind reflected back is no answer");
        assert!(!answer.verify_answer(&[8; 32]), "another slot's token");
    }

    #[test]
    fn rooms_differ_by_group_and_channel() {
        let a = voice_room_id(&[1; 32], &[2; 32]);
        assert_ne!(a, voice_room_id(&[3; 32], &[2; 32]));
        assert_ne!(a, voice_room_id(&[1; 32], &[4; 32]));
    }

    fn header() -> MediaHeader {
        MediaHeader { room_id: [5; 32], slot_id: 3, epoch: 9, sequence: 77 }
    }

    #[test]
    fn media_packet_roundtrip() {
        let packet = header().packet(b"opus");
        assert_eq!(packet.len(), VOICE_HEADER_SIZE + 4);
        assert_eq!(MediaHeader::parse(&packet), Some((header(), &b"opus"[..])));
    }

    #[test]
    fn media_packets_and_binds_are_told_apart() {
        let media = header().packet(b"");
        assert!(VoiceBind::from_bytes(&media).is_none());
        let bind = VoiceBind::sign(&[7; 32], [5; 32], 3, 1).to_bytes();
        assert!(MediaHeader::parse(&bind).is_none());
    }

    #[test]
    fn truncated_media_packets_are_refused() {
        let packet = header().packet(b"opus");
        assert!(MediaHeader::parse(&packet[..packet.len() - 1]).is_none(), "payload shorter than its length field");
        assert!(MediaHeader::parse(&packet[..VOICE_HEADER_SIZE - 1]).is_none(), "header cut short");
    }

    // Clients and relays of different versions meet, so the JSON shape is fixed.
    #[test]
    fn signaling_json_shape() {
        let join = serde_json::to_value(ClientMsg::Join { presence: "cA==".into() }).unwrap();
        assert_eq!(join, serde_json::json!({ "type": "join", "presence": "cA==" }));
        let sender = PresenceSender { account_fp: [1; 32], device_vk: [2; 32] };
        let welcome: ServerMsg = serde_json::from_value(serde_json::json!({
            "type": "welcome", "slot_id": 2, "port": 7701, "room": "cg==", "token": "dA==",
            "peers": [{ "slot_id": 1, "presence": "cA==", "from": serde_json::to_value(sender).unwrap() }],
        }))
        .unwrap();
        assert_eq!(
            welcome,
            ServerMsg::Welcome {
                slot_id: 2,
                port: 7701,
                room: "cg==".into(),
                token: "dA==".into(),
                peers: vec![PeerEntry { slot_id: 1, presence: "cA==".into(), from: sender }],
            }
        );
        let joined = serde_json::to_value(ServerMsg::Joined { slot_id: 3, presence: "cA==".into(), from: sender }).unwrap();
        assert_eq!(joined["from"]["a"], serde_json::to_value(sender).unwrap()["a"]);
        let resume = serde_json::to_value(ClientMsg::Resume { slot_id: 4, token: "dA==".into(), presence: "cA==".into() }).unwrap();
        assert_eq!(resume, serde_json::json!({ "type": "resume", "slot_id": 4, "token": "dA==", "presence": "cA==" }));
        assert_eq!(serde_json::to_value(ServerMsg::NotResumed).unwrap(), serde_json::json!({ "type": "not_resumed" }));
        let reception = serde_json::to_value(ClientMsg::Reception { reports: vec![Reception { slot_id: 2, loss_pct: 7 }] }).unwrap();
        assert_eq!(reception, serde_json::json!({ "type": "reception", "reports": [{ "slot_id": 2, "loss_pct": 7 }] }));
        let told = serde_json::to_value(ServerMsg::Reception { slot_id: 1, loss_pct: 7 }).unwrap();
        assert_eq!(told, serde_json::json!({ "type": "reception", "slot_id": 1, "loss_pct": 7 }));
    }
}
