//! The account's own sync state between its devices: the settings store, the messages
//! carrying its changes, the snapshot pushes, and the provision a new device starts from.

use std::time::{Duration, Instant};

use crate::crypto::constants::SYNC_SIGN_PREFIX;
use crate::error::{GhostError, Result};
use crate::wire::{mls_group_mailbox_id, InviteChannel, InviteMember, Outbound, ProvisionPayload, SyncDump, SyncEntry, SyncReceiveResult, SyncServerMeta};
use ghost_wire::now_millis;

use super::GhostClient;

/// A snapshot push owed to the relays: sync state changed, and once the changes have
/// settled they go up as one push.
#[derive(Default)]
pub(super) struct SnapshotPush {
    /// When the first change since the last push happened, if one did.
    since: Option<Instant>,
}

impl SnapshotPush {
    pub(super) fn request(&mut self, now: Instant) {
        self.since.get_or_insert(now);
    }

    /// Whether a push is due, the first change behind it being `settle` old; it counts once.
    pub(super) fn take(&mut self, now: Instant, settle: Duration) -> bool {
        match self.since {
            Some(since) if now.duration_since(since) >= settle => {
                self.since = None;
                true
            }
            _ => false,
        }
    }
}

/// Sender key, its sequence number, generation and signature ahead of a sync message's
/// sealed body. A relay sees the key and sequence number; the rest is for the devices.
const SYNC_HEADER_LEN: usize = 32 + 8 + 4 + 64;

/// What a device signs for a sync message: the account (not a mailbox, so the same bytes
/// go to every relay), its sequence number, the generation and the sealed body.
fn sync_message(account_fp: &[u8; 32], seq: u64, generation: u32, sealed: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SYNC_SIGN_PREFIX.len() + 32 + 8 + 4 + sealed.len());
    msg.extend_from_slice(SYNC_SIGN_PREFIX);
    msg.extend_from_slice(account_fp);
    msg.extend_from_slice(&seq.to_be_bytes());
    msg.extend_from_slice(&generation.to_be_bytes());
    msg.extend_from_slice(sealed);
    msg
}

impl GhostClient {
    /// Note that sync state changed and the relays' snapshots should follow.
    pub fn request_snapshot_push(&mut self) {
        self.snapshot_push.request(Instant::now());
    }

    /// Take a pending snapshot push once the first change behind it is `settle` old,
    /// so a burst of changes costs one push.
    pub fn take_snapshot_push(&mut self, settle: Duration) -> bool {
        self.snapshot_push.take(Instant::now(), settle)
    }

    pub fn sync_get(&self, key: &str) -> Result<Option<(Option<Vec<u8>>, u64)>> {
        self.provider.store().sync_get(key)
    }

    pub fn sync_set(&self, key: &str, value: &[u8], ts: u64) -> Result<bool> {
        self.provider.store().sync_set(key, value, ts)
    }

    pub fn sync_remove(&self, key: &str, ts: u64) -> Result<bool> {
        self.provider.store().sync_remove(key, ts)
    }

    /// This device's state with what it covers, for a snapshot or a provision.
    pub fn sync_dump(&self) -> Result<SyncDump> {
        Ok(SyncDump { covered: self.provider.store().sync_cursors()?, entries: self.provider.store().sync_dump()? })
    }

    /// Merge entries other devices wrote by each key's rule, their clocks clamped to what
    /// this device accepts; returns those that changed this device's state.
    pub fn sync_import(&self, entries: &[SyncEntry]) -> Result<Vec<SyncEntry>> {
        let now = now_millis();
        let clamped: Vec<SyncEntry> =
            entries.iter().map(|(key, value, ts)| (key.clone(), value.clone(), crate::sync::clock::clamp(*ts, now))).collect();
        self.provider.store().sync_import(&clamped)
    }

    /// A snapshot included every message of these devices up to these sequence numbers:
    /// a copy of one arriving later is nothing new, and a gap below is closed.
    pub fn cover_sync(&self, covered: &[([u8; 32], u64)]) -> Result<()> {
        let own = self.identity.verifying_key.to_bytes();
        for (device_vk, high) in covered {
            if *device_vk == own {
                continue;
            }
            let mut window = self.provider.store().sync_cursor(device_vk)?;
            window.cover_up_to(*high);
            self.provider.store().set_sync_cursor(device_vk, &window)?;
        }
        Ok(())
    }

    /// A clock for a write this device makes now, past everything it has seen.
    pub fn sync_tick(&self) -> Result<u64> {
        let mut clock = crate::sync::clock::HybridClock::new(self.provider.store().sync_clock()?);
        let value = clock.tick(now_millis());
        self.provider.store().set_sync_clock(clock.last())?;
        Ok(value)
    }

    /// Take in a clock another device wrote; returns it clamped as it is stored.
    pub fn sync_observe(&self, clock: u64) -> Result<u64> {
        let mut hybrid = crate::sync::clock::HybridClock::new(self.provider.store().sync_clock()?);
        let stored = hybrid.observe(clock, now_millis());
        self.provider.store().set_sync_clock(hybrid.last())?;
        Ok(stored)
    }

    /// The mailbox the account's devices sync through, the same on every relay.
    pub fn account_sync_mailbox(&self) -> [u8; 32] {
        ghost_wire::sync_mailbox_id(&self.identity.fingerprint)
    }

    /// Seal a sync plaintext under the current account key generation, numbered and
    /// signed by this device. The sequence number is reserved before the message leaves.
    /// Format: `[envelope_header][device_vk:32][seq:8][generation:4][signature:64][sealed]`
    pub fn send_sync(&self, plaintext: &[u8]) -> Result<Outbound> {
        use ed25519_dalek::Signer;
        let seed = self.sealing_seed()?;
        let sealed = crate::wire::sync_seal(&*seed.sync_key()?, plaintext)?;
        let seq = self.provider.store().next_sync_seq()?;
        let signature = self.identity.signing_key.sign(&sync_message(&self.identity.fingerprint, seq, seed.generation(), &sealed));
        let header = ghost_wire::encode_envelope(ghost_wire::EnvelopeType::Application, 0);
        let mut blob = Vec::with_capacity(ghost_wire::ENVELOPE_HEADER_SIZE + SYNC_HEADER_LEN + sealed.len());
        blob.extend_from_slice(&header);
        blob.extend_from_slice(self.identity.verifying_key.as_bytes());
        blob.extend_from_slice(&seq.to_be_bytes());
        blob.extend_from_slice(&seed.generation().to_be_bytes());
        blob.extend_from_slice(&signature.to_bytes());
        blob.extend_from_slice(&sealed);
        Ok(Outbound { channel_id: [0u8; 32], mailbox_id: self.account_sync_mailbox(), blob })
    }

    /// Take in a sync blob from any relay. A copy of a message seen already, or this
    /// device's own message back, is `Seen` without being opened. Otherwise the sender
    /// must be an active device of this account by this device's log, which is fetched
    /// again on `UnknownDevice`; a generation not held yet fails with
    /// `AccountKeyUnavailable`, and the message opens once its key set is fetched. The
    /// message counts as seen only once it opened, so a retry after either is not dropped.
    #[cfg_attr(feature = "devtools", tracing::instrument(skip_all))]
    pub fn receive_sync(&mut self, blob: &[u8]) -> Result<SyncReceiveResult> {
        let (envelope_type, _epoch) = ghost_wire::decode_envelope(blob)
            .map_err(|e| GhostError::Format(format!("envelope: {e}")))?;
        if envelope_type != ghost_wire::EnvelopeType::Application {
            return Err(GhostError::Format("the sync mailbox carries no MLS messages".into()));
        }
        let payload = ghost_wire::envelope_payload(blob);
        if payload.len() < SYNC_HEADER_LEN {
            return Err(GhostError::Format("sync payload too short".into()));
        }
        let sender_vk: [u8; 32] = payload[..32].try_into().unwrap();
        let seq = u64::from_be_bytes(payload[32..40].try_into().unwrap());
        let generation = u32::from_be_bytes(payload[40..44].try_into().unwrap());
        let signature = ed25519_dalek::Signature::from_bytes(payload[44..108].try_into().unwrap());
        let sealed = &payload[SYNC_HEADER_LEN..];
        if sender_vk == *self.identity.verifying_key.as_bytes() {
            return Ok(SyncReceiveResult::Seen);
        }
        let mut window = self.provider.store().sync_cursor(&sender_vk)?;
        let gap = match window.accept(seq) {
            crate::sync::window::Arrival::Seen => return Ok(SyncReceiveResult::Seen),
            crate::sync::window::Arrival::New { gap } => gap,
        };

        let log = self.own_log().ok_or_else(|| GhostError::IdentityLog("own identity log is not cached".into()))?;
        match log.devices.get(&sender_vk) {
            None => return Err(GhostError::UnknownDevice { account_fp: self.identity.fingerprint }),
            Some(device) if !device.is_active() => {
                return Err(GhostError::IdentityLog("sync message from a revoked device".into()));
            }
            Some(_) => {}
        }
        ed25519_dalek::VerifyingKey::from_bytes(&sender_vk)
            .map_err(|e| GhostError::InvalidKey(format!("sync sender key: {e}")))?
            .verify_strict(&sync_message(&self.identity.fingerprint, seq, generation, sealed), &signature)
            .map_err(|_| GhostError::AuthenticationFailed)?;
        let seed = self
            .account_seed(generation)?
            .ok_or_else(|| GhostError::AccountKeyUnavailable(format!("generation {generation} is not held yet")))?;
        let plaintext = crate::wire::sync_open(&*seed.sync_key()?, sealed)?;
        self.provider.store().set_sync_cursor(&sender_vk, &window)?;
        Ok(SyncReceiveResult::Application { plaintext, sender: sender_vk, gap })
    }

    /// Export server metadata for provisioning a sibling device (no role check).
    pub fn export_provision_payload(&self, server_id: &[u8; 32]) -> Result<ProvisionPayload> {
        let default_group = self.default_group(server_id)?;
        let meta = self.provider.store().get_server(server_id)?;
        let members = self.provider.store().list_members(server_id)?;
        let channels = self.provider.store().list_channels(server_id)?;
        let mailbox_id = mls_group_mailbox_id(default_group.group_id());

        // Private channels are found through the relay's discovery and joined with the
        // server epoch they are authorized against, not provisioned.
        let invite_channels: Vec<InviteChannel> = channels
            .iter()
            .filter(|c| !self.is_private_channel(&c.channel_id))
            .map(|c| {
                let gi = self.groups.get(&c.channel_id)
                    .and_then(|g| g.export_group_info(&self.provider).ok())
                    .unwrap_or_default();
                InviteChannel {
                    channel_id: c.channel_id,
                    name: c.name.clone(),
                    kind: c.kind,
                    position: c.position,
                    group_info_bytes: gi,
                }
            })
            .collect();

        Ok(ProvisionPayload {
            server_id: *server_id,
            server_name: meta.name,
            kind: meta.kind,
            members: members
                .iter()
                .map(|m| InviteMember {
                    fingerprint: m.fingerprint,
                    display_name: m.display_name.clone(),
                })
                .collect(),
            channels: invite_channels,
            mailbox_id,
            relay_ref: self.server_relay_ref(server_id)?,
            role_names: self.provider.store().list_role_names(server_id)?,
        })
    }

    /// Relay hosting a server, as recorded at join time; `None` means the home relay.
    fn server_relay_ref(&self, server_id: &[u8; 32]) -> Result<Option<ghost_wire::relay_ref::RelayRef>> {
        match self.provider.store().server_relay(server_id)? {
            Some(relay_vk) => Ok(self.provider.store().get_relay(&relay_vk)?),
            None => Ok(None),
        }
    }

    /// Export lightweight server metadata for sync_state (no members).
    pub fn export_server_meta(&self, server_id: &[u8; 32]) -> Result<SyncServerMeta> {
        let default_group = self.default_group(server_id)?;
        let meta = self.provider.store().get_server(server_id)?;
        let channels = self.provider.store().list_channels(server_id)?;
        let mailbox_id = mls_group_mailbox_id(default_group.group_id());

        Ok(SyncServerMeta {
            server_name: meta.name,
            kind: meta.kind,
            mailbox_id,
            channels: channels
                .iter()
                .filter(|c| !self.is_private_channel(&c.channel_id))
                .map(|c| InviteChannel {
                    channel_id: c.channel_id,
                    name: c.name.clone(),
                    kind: c.kind,
                    position: c.position,
                    group_info_bytes: Vec::new(),
                })
                .collect(),
            relay_ref: self.server_relay_ref(server_id)?,
            role_names: self.provider.store().list_role_names(server_id)?,
            removal: self.provider.store().server_removal(server_id)?.map(|r| crate::wire::SyncRemoval { by: r.by }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_of_changes_is_pushed_once_after_it_settles() {
        let start = Instant::now();
        let settle = Duration::from_secs(2);
        let mut push = SnapshotPush::default();
        assert!(!push.take(start, settle), "nothing changed");
        push.request(start);
        push.request(start + Duration::from_secs(1));
        assert!(!push.take(start + Duration::from_secs(1), settle), "the first change is not settled yet");
        assert!(push.take(start + settle, settle), "counted from the first change, not the last");
        assert!(!push.take(start + settle * 2, settle), "once");
    }
}
