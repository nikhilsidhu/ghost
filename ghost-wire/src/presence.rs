//! Presence as relays announce it. Presence blobs are sealed to a group, so the relay
//! cannot read them; what it can vouch for is which authenticated device sent one, and
//! it stamps that on everything it relays. Receivers derive the sender's key from the
//! stamp and bind the blob to it, so no member can pass presence off as another's, and
//! the relay cannot re-attribute a blob it holds.

use serde::{Deserialize, Serialize};

/// The device behind a presence announcement, as the relay saw it authenticate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PresenceSender {
    #[serde(rename = "a", with = "b64_32")]
    pub account_fp: [u8; 32],
    #[serde(rename = "d", with = "b64_32")]
    pub device_vk: [u8; 32],
}

impl PresenceSender {
    /// What a presence seal is bound to: `domain || scope || account || device`, so a
    /// blob opens only for the sender and scope it was made for.
    pub fn binding(&self, domain: &[u8], scope: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(domain.len() + scope.len() + 64);
        aad.extend_from_slice(domain);
        aad.extend_from_slice(scope);
        aad.extend_from_slice(&self.account_fp);
        aad.extend_from_slice(&self.device_vk);
        aad
    }
}

/// A device's voice state as the relay announces it on a server's mailbox, under the
/// `vs` key: in channel `ch` with its sealed presence `p` (base64), or leaving it. The
/// entries of a `vs_snap` have the same shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoiceStateMsg {
    /// The channel, base64.
    pub ch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leave: Option<bool>,
    pub from: PresenceSender,
}

/// A device's online presence as the relay announces it, under the `ps` key: its sealed
/// presence `p` (base64), or that it went offline. The entries of a `ps_snap` have the
/// same shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnlineStateMsg {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leave: Option<bool>,
    pub from: PresenceSender,
}

/// 32 bytes as standard base64, like the other binary fields of these messages.
mod b64_32 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        let bytes = STANDARD.decode(text).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sender() -> PresenceSender {
        PresenceSender { account_fp: [1; 32], device_vk: [2; 32] }
    }

    // Clients and relays of different versions meet, so the JSON shape is fixed.
    #[test]
    fn announcement_json_shapes_are_fixed() {
        let from = serde_json::json!({
            "a": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
            "d": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
        });
        assert_eq!(serde_json::to_value(sender()).unwrap(), from);
        assert!(serde_json::from_value::<PresenceSender>(serde_json::json!({ "a": "AQ==", "d": "Ag==" })).is_err());

        let update = VoiceStateMsg { ch: "Y2g=".into(), p: Some("cA==".into()), leave: None, from: sender() };
        assert_eq!(serde_json::to_value(&update).unwrap(), serde_json::json!({ "ch": "Y2g=", "p": "cA==", "from": from }));
        let leave: VoiceStateMsg = serde_json::from_value(serde_json::json!({ "ch": "Y2g=", "leave": true, "from": from })).unwrap();
        assert_eq!(leave, VoiceStateMsg { ch: "Y2g=".into(), p: None, leave: Some(true), from: sender() });
        let offline = OnlineStateMsg { p: None, leave: Some(true), from: sender() };
        assert_eq!(serde_json::to_value(&offline).unwrap(), serde_json::json!({ "leave": true, "from": from }));
    }

    #[test]
    fn binding_covers_domain_scope_and_sender() {
        let aad = sender().binding(b"dom", b"scope");
        assert_eq!(&aad[..3], b"dom");
        assert_eq!(&aad[3..8], b"scope");
        assert_eq!(&aad[8..40], &[1; 32]);
        assert_eq!(&aad[40..], &[2; 32]);
    }
}
