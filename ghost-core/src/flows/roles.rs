//! Roles and permissions: replacing a server's policy, and naming its roles.

use ghost_wire::policy::ServerPolicy;

use crate::error::Result;
use crate::wire::derive_default_channel_id;

use super::channels::post_and_merge;
use super::{post_op, SharedClient};
use crate::relay::RelayClient;

/// Replace the server's policy: create, change, delete or assign roles, change what
/// everyone may do, or hand over ownership. Checked locally first; the relay and every
/// member check it against the current policy. The relay then removes members from
/// private channels the new policy no longer admits them to.
pub async fn set_server_policy(client: &SharedClient, relay: &RelayClient, server_id: &[u8; 32], policy: &ServerPolicy) -> Result<()> {
    let out = client.lock().await.stage_server_policy(server_id, policy)?;
    post_and_merge(client, relay, out).await
}

/// Give the server's roles the names members see, in one message, stored here once the
/// relay took it. Names are shown, never trusted: the policy alone decides what a role
/// may do.
pub async fn name_roles(client: &SharedClient, relay: &RelayClient, server_id: &[u8; 32], names: &[(u8, String)]) -> Result<()> {
    post_op(client, relay, &derive_default_channel_id(server_id), |c| Ok((c.name_roles(server_id, names)?, ()))).await?;
    let c = client.lock().await;
    for (role_id, name) in names {
        c.store().set_role_name(server_id, *role_id, name)?;
    }
    Ok(())
}
