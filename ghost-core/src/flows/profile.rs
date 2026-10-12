//! What members see of this account: its display name and avatar, announced in every
//! server the account is in. Each announcement is posted and confirmed per server. A
//! server it did not reach owes it, and is told the name or avatar as it is then when its
//! mailbox next connects (`tell_owed`). The avatar's sealed image goes to each server's
//! relay beside its announcement and is kept here, so a relay that missed it gets the
//! very bytes its hash names.

use std::path::Path;

use ghost_wire::short_id;

use crate::error::{GhostError, Result};
use crate::mls::presence::AvatarRef;
use crate::relay::RelayClient;
use crate::session::avatars;
use crate::storage::profile_owed::ProfilePart;
use crate::wire::{encode_avatar_clear, encode_avatar_update, encode_member_announce, SYNC_KEY_DISPLAY_NAME};

use super::{sync, SharedClient};

/// How many of the account's servers an announcement reached now; the rest are told
/// when their mailboxes next connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reach {
    pub reached: usize,
    pub servers: usize,
}

impl Reach {
    pub fn complete(&self) -> bool {
        self.reached == self.servers
    }
}

/// Take a new display name and announce it in every server; this account's other
/// devices learn it through sync.
pub async fn set_display_name(client: &SharedClient, relay: &RelayClient, data_dir: &Path, name: &str) -> Result<Reach> {
    client.lock().await.set_display_name(name.to_string());
    sync::set_and_push(client, relay, SYNC_KEY_DISPLAY_NAME, name.as_bytes()).await;
    tell_everyone(client, relay, data_dir, ProfilePart::Name).await
}

/// Give the account a new avatar from `image`: sealed under a fresh key that reaches
/// members inside their groups, cached here, its sealed bytes put on each server's relay
/// (which never sees the image) and its hash and key announced to the server's members.
pub async fn set_avatar(client: &SharedClient, relay: &RelayClient, data_dir: &Path, image: &[u8]) -> Result<(AvatarRef, Reach)> {
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    let sealed = crate::crypto::aead::seal(&key, image, "avatar")?;
    let avatar = AvatarRef { hash: blake3::hash(&sealed).into(), key };
    {
        let c = client.lock().await;
        let own = *c.fingerprint();
        for (server_id, _) in c.server_mailboxes() {
            c.store().update_member_avatar(&server_id, &own, &avatar.hash, &avatar.key)?;
        }
        avatars::cache(data_dir, &own, image, &avatar.hash);
    }
    avatars::keep_own_sealed(data_dir, &sealed)?;
    let reach = tell_everyone(client, relay, data_dir, ProfilePart::Avatar).await?;
    Ok((avatar, reach))
}

/// Take the account's avatar down everywhere.
pub async fn clear_avatar(client: &SharedClient, relay: &RelayClient, data_dir: &Path) -> Result<Reach> {
    {
        let c = client.lock().await;
        let own = *c.fingerprint();
        for (server_id, _) in c.server_mailboxes() {
            c.store().clear_member_avatar(&server_id, &own)?;
        }
        avatars::clear(data_dir, &own);
    }
    avatars::forget_own_sealed(data_dir);
    tell_everyone(client, relay, data_dir, ProfilePart::Avatar).await
}

/// Tell every server what is owed of the profile, as it is now; called when the server's
/// mailbox connects.
pub async fn tell_owed(client: &SharedClient, relay: &RelayClient, data_dir: &Path, server_id: &[u8; 32]) {
    let owed = match client.lock().await.store().profile_owed(server_id) {
        Ok(owed) => owed,
        Err(e) => return tracing::warn!("server {}: what the profile owes not read: {e}", short_id(server_id)),
    };
    for part in owed {
        tell(client, relay, data_dir, server_id, part).await;
    }
}

/// Tell every server one part of the profile, each owing it until told.
async fn tell_everyone(client: &SharedClient, relay: &RelayClient, data_dir: &Path, part: ProfilePart) -> Result<Reach> {
    let servers: Vec<[u8; 32]> = client.lock().await.server_mailboxes().into_iter().map(|(server_id, _)| server_id).collect();
    let mut reached = 0;
    for server_id in &servers {
        client.lock().await.store().owe_profile(server_id, part)?;
        if tell(client, relay, data_dir, server_id, part).await {
            reached += 1;
        }
    }
    Ok(Reach { reached, servers: servers.len() })
}

/// Tell one server one part of the profile as it is now; whether it landed, which
/// settles what the server was owed of it.
async fn tell(client: &SharedClient, relay: &RelayClient, data_dir: &Path, server_id: &[u8; 32], part: ProfilePart) -> bool {
    let told = match part {
        ProfilePart::Name => tell_name(client, relay, server_id).await,
        ProfilePart::Avatar => tell_avatar(client, relay, data_dir, server_id).await,
    };
    match told {
        Ok(()) => {
            if let Err(e) = client.lock().await.store().profile_told(server_id, part) {
                tracing::warn!("server {}: {part:?} told but still marked owed: {e}", short_id(server_id));
            }
            true
        }
        Err(e) => {
            tracing::warn!("server {}: {part:?} not told yet, told when it connects again: {e}", short_id(server_id));
            false
        }
    }
}

async fn tell_name(client: &SharedClient, relay: &RelayClient, server_id: &[u8; 32]) -> Result<()> {
    let out = {
        let mut c = client.lock().await;
        let name = c.identity().display_name.clone();
        c.send_control(server_id, encode_member_announce(&name))?
    };
    relay.post_blob(&out.mailbox_id, out.blob).await.map(drop)
}

/// The avatar as this server's member record has it: its sealed bytes put and its hash
/// and key announced, or taken down.
async fn tell_avatar(client: &SharedClient, relay: &RelayClient, data_dir: &Path, server_id: &[u8; 32]) -> Result<()> {
    let (own, avatar) = {
        let c = client.lock().await;
        let own = *c.fingerprint();
        let member = c.store().get_member(server_id, &own)?;
        (own, member.avatar_hash.zip(member.avatar_key).map(|(hash, key)| AvatarRef { hash, key }))
    };
    match avatar {
        Some(avatar) => {
            let sealed = avatars::own_sealed(data_dir)
                .filter(|sealed| <[u8; 32]>::from(blake3::hash(sealed)) == avatar.hash)
                .ok_or_else(|| GhostError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "the avatar's sealed image is not kept here")))?;
            let out = client.lock().await.send_control(server_id, encode_avatar_update(&avatar.hash, &avatar.key))?;
            relay.put_avatar(&out.mailbox_id, &own, sealed).await?;
            relay.post_blob(&out.mailbox_id, out.blob).await.map(drop)
        }
        None => {
            let out = client.lock().await.send_control(server_id, encode_avatar_clear())?;
            relay.delete_avatar(&out.mailbox_id, &own).await?;
            relay.post_blob(&out.mailbox_id, out.blob).await.map(drop)
        }
    }
}
