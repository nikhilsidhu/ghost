//! Server membership changes: kicking a member, and letting a removed one back in.

use crate::error::Result;

use super::channels::post_and_merge;
use super::{now_millis, SharedClient};
use crate::relay::RelayClient;

/// Kick a member from a server: one commit removing the member's leaves from the server
/// group, which also keeps the account from rejoining until someone who may kick lets it
/// back. The relay then proposes removing the member from the server's private channels,
/// which members' devices commit. A commit built on an epoch the group left
/// fails with `GroupMoved`; a lost answer fails with the network error, and the commit,
/// if the relay stored it, comes back through the log like anyone's.
pub async fn kick(client: &SharedClient, relay: &RelayClient, server_id: &[u8; 32], member_fp: &[u8; 32]) -> Result<()> {
    let out = client.lock().await.kick_member(server_id, member_fp, now_millis())?;
    post_and_merge(client, relay, out).await?;
    client.lock().await.store().remove_member(server_id, member_fp)?;
    Ok(())
}

/// Let a removed account back in, so it may rejoin with an invite. Fails as `kick` does.
pub async fn let_back_in(client: &SharedClient, relay: &RelayClient, server_id: &[u8; 32], account: &[u8; 32]) -> Result<()> {
    let out = client.lock().await.let_back_in(server_id, account)?;
    post_and_merge(client, relay, out).await
}
