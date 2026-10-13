//! Sealing and opening presence: who is in a voice channel and who is online, keyed from
//! the group so only members can read it.

use crate::error::{GhostError, Result};
use crate::mls::group::GhostGroup;

use super::GhostClient;

impl GhostClient {
    /// This device, as the relay stamps it on the presence it sends.
    pub fn presence_sender(&self) -> ghost_wire::presence::PresenceSender {
        ghost_wire::presence::PresenceSender {
            account_fp: self.identity.fingerprint,
            device_vk: *self.identity.verifying_key.as_bytes(),
        }
    }

    /// The group must hold a leaf for the stamped sender: that account, signing with
    /// that device key. Otherwise the relay attributed the blob to someone outside it.
    fn require_member_device(group: &GhostGroup, sender: &ghost_wire::presence::PresenceSender) -> Result<()> {
        let present = group.members().any(|m| {
            m.signature_key.as_slice() == sender.device_vk
                && crate::mls::credential::parse_credential(&m.credential).is_ok_and(|c| c.account_fp == sender.account_fp)
        });
        if present {
            Ok(())
        } else {
            Err(GhostError::Crypto("presence from a device that is not in the group".into()))
        }
    }

    /// Derive a per-sender encryption key for voice in this channel.
    /// `voice_salt` is a random value from the sender's presence blob, ensuring
    /// unique keys per voice session even within the same MLS epoch.
    pub fn derive_voice_key(
        &self,
        channel_id: &[u8; 32],
        sender_fp: &[u8; 32],
        device_vk: &[u8; 32],
        voice_salt: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let group = self.group_of_channel(channel_id)?;
        crate::mls::voice::derive_voice_key(group, &self.provider, channel_id, sender_fp, device_vk, voice_salt)
    }

    /// Seal this device's presence in a voice channel. `voice_salt` is a random value
    /// generated once per voice session and reused for all presence updates within it.
    pub fn seal_presence_blob(&self, channel_id: &[u8; 32], muted: bool, deafened: bool, voice_salt: [u8; 32]) -> Result<Vec<u8>> {
        let group = self.group_of_channel(channel_id)?;
        let sender = self.presence_sender();
        let key = crate::mls::voice::derive_presence_key(group, &self.provider, channel_id, &sender)?;
        let state = crate::mls::voice::PresenceState::new(&sender, muted, deafened, voice_salt);
        crate::mls::voice::seal_presence(&key, channel_id, &state)
    }

    /// Open a voice presence blob the relay attributed to `sender`, who must be in the
    /// channel's group.
    pub fn open_presence_blob(
        &self,
        channel_id: &[u8; 32],
        sender: &ghost_wire::presence::PresenceSender,
        blob: &[u8],
    ) -> Result<crate::mls::voice::PresenceState> {
        let group = self.group_of_channel(channel_id)?;
        Self::require_member_device(group, sender)?;
        let key = crate::mls::voice::derive_presence_key(group, &self.provider, channel_id, sender)?;
        crate::mls::voice::open_presence(&key, channel_id, sender, blob)
    }

    /// Seal this device's online presence for a server.
    pub fn seal_online_presence_blob(
        &self,
        server_id: &[u8; 32],
        status: crate::mls::presence::OnlineStatus,
        status_message: Option<String>,
        status_expiry: Option<u64>,
        avatar: Option<crate::mls::presence::AvatarRef>,
    ) -> Result<Vec<u8>> {
        let group = self.default_group(server_id)?;
        let sender = self.presence_sender();
        let key = crate::mls::presence::derive_online_presence_key(group, &self.provider, &sender)?;
        let state = crate::mls::presence::OnlinePresence { status, status_message, status_expiry, avatar };
        crate::mls::presence::seal_online_presence(&key, &sender, &state)
    }

    /// Open an online presence blob the relay attributed to `sender`, who must be in
    /// the server's group.
    pub fn open_online_presence_blob(
        &self,
        server_id: &[u8; 32],
        sender: &ghost_wire::presence::PresenceSender,
        blob: &[u8],
    ) -> Result<crate::mls::presence::OnlinePresence> {
        let group = self.default_group(server_id)?;
        Self::require_member_device(group, sender)?;
        let key = crate::mls::presence::derive_online_presence_key(group, &self.provider, sender)?;
        crate::mls::presence::open_online_presence(&key, sender, blob)
    }
}
