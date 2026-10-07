//! Roles and permissions: replacing a server's policy.

use ghost_wire::policy::ServerPolicy;

use crate::error::Result;

use super::channels::post_and_merge;
use super::{SharedClient, SharedRelay};

/// Replace the server's policy: create, change, delete or assign roles, change what
/// everyone may do, or hand over ownership. Checked locally first; the relay and every
/// member check it against the current policy. The relay then removes members from
/// private channels the new policy no longer admits them to.
pub async fn set_server_policy(client: &SharedClient, relay: &SharedRelay, server_id: &[u8; 32], policy: &ServerPolicy) -> Result<()> {
    let out = client.lock().await.stage_server_policy(server_id, policy)?;
    post_and_merge(client, relay, out).await
}

/// Bring groups made before policies existed under one: update this device's leaf in
/// every such group to advertise policy support, then, for servers this account owns
/// whose every leaf now supports it, commit the explicit policy matching the implicit
/// one. Run at start; members who have not upgraded hold the second step back.
pub async fn migrate(client: &SharedClient, relay: &SharedRelay) {
    let pending = client.lock().await.channels_needing_capability_update();
    for channel_id in pending {
        let staged = client.lock().await.stage_capabilities_update(&channel_id);
        let result = match staged {
            Ok(out) => post_and_merge(client, relay, out).await,
            Err(e) => Err(e),
        };
        if let Err(e) = result {
            eprintln!("policy migration: capabilities for {}: {e}", hex::encode(&channel_id[..8]));
        }
    }
    let (ready, own) = {
        let c = client.lock().await;
        (c.servers_ready_for_policy(), *c.fingerprint())
    };
    for server_id in ready {
        if let Err(e) = set_server_policy(client, relay, &server_id, &ServerPolicy::new(own)).await {
            eprintln!("policy migration: policy for {}: {e}", hex::encode(&server_id[..8]));
        }
    }
}
