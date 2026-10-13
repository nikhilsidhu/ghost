//! Clients for tests across the crate: in memory, talking to no relay.

use crate::identity::Identity;
use crate::storage::ServerKind;
use super::*;

/// A relay key for groups made in these tests, which talk to no relay.
pub(crate) const TEST_RELAY_VK: [u8; 32] = [0x7E; 32];

pub(crate) fn test_client(seed: [u8; 32]) -> GhostClient {
    let identity = Identity::from_seed(seed).unwrap();
    let mut client = GhostClient::open_in_memory(identity, seed).unwrap();
    client.set_relay_vk(TEST_RELAY_VK);
    // Register own identity so self-validation passes
    register_identity_in_cache(&mut client, &Identity::from_seed(seed).unwrap());
    client
}

/// Put an identity's one-entry account in a client's identity log cache.
pub(crate) fn register_identity_in_cache(client: &mut GhostClient, identity: &Identity) {
    client.idlog_cache.insert_chain(&[identity.own_genesis()]).unwrap();
}

/// `joiner` joins `creator`'s server through an invite, with the join applied on both.
pub(crate) fn join_through_invite(creator: &mut GhostClient, joiner: &mut GhostClient, server_id: &[u8; 32]) {
    let invite = creator.create_invite(server_id, u64::MAX).unwrap();
    let payload = joiner.open_invite(&invite.sealed_payload, &invite.key).unwrap();
    let group_info = creator.export_server_info(server_id).unwrap();
    let (_, channel_results, _) = joiner.join_by_invite(payload, group_info, 1000).unwrap();
    let (channel_id, commit, _) = &channel_results[0];
    creator.receive_any(channel_id, commit, Some(1000)).unwrap();
}

/// Returns (creator, joiner, server_id) with both clients in a shared MLS group.
pub(crate) fn setup_two_clients() -> (GhostClient, GhostClient, [u8; 32]) {
    let mut c1 = test_client([0x01; 32]);
    let mut c2 = test_client([0x02; 32]);

    // Each client needs the other's identity in its cache for validation
    let id1 = Identity::from_seed([0x01; 32]).unwrap();
    let id2 = Identity::from_seed([0x02; 32]).unwrap();
    register_identity_in_cache(&mut c1, &id2);
    register_identity_in_cache(&mut c2, &id1);

    let server_id = c1.create_server("test", ServerKind::Server, 1000).unwrap();
    join_through_invite(&mut c1, &mut c2, &server_id);
    (c1, c2, server_id)
}
