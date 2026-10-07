//! Moving a server to another relay, and following such a move as a member.
//!
//! A server keeps its MLS groups and mailbox ids when it moves; only the relay
//! holding them changes. Members accept a move only from a `ServerLocation` signed
//! by an active device of the server's creator, whichever way it reaches them: an
//! announcement on the old relay, a lookup at the creator's home, or a move link.

use ghost_wire::server_location::ServerLocation;
use tokio::sync::Mutex;

use crate::error::{GhostError, Result};
use crate::relay::RelayClient;
use crate::wire::encode_server_moved;

use super::{account, next_generation, sync, SharedClient, SharedRelay};

const MOVE_LINK_PREFIX: &str = "ghost://move?l=";

/// Text a creator shares out of band when the old relay was the only one members
/// and creator had in common.
pub fn move_link(location: &ServerLocation) -> String {
    format!("{MOVE_LINK_PREFIX}{}", location.encode())
}

pub fn parse_move_link(link: &str) -> Result<ServerLocation> {
    let encoded = link
        .trim()
        .strip_prefix(MOVE_LINK_PREFIX)
        .ok_or_else(|| GhostError::Format("not a server move link".into()))?;
    ServerLocation::decode(encoded).map_err(|e| GhostError::Format(e.to_string()))
}

/// A client for `url` that signs as this device but keeps its own mailbox routes,
/// so requests reach that relay even for mailboxes routed elsewhere.
async fn standalone_client(home: &SharedRelay, url: &str) -> SharedRelay {
    let (mut client, _events) = RelayClient::new(url);
    client.copy_auth_from(&*home.lock().await);
    Mutex::new(client)
}

/// Route a server's mailboxes (and voice channels) to `url` and resubscribe there.
/// `seqs` gives the sequence to resume each mailbox from on the new relay.
async fn reroute(client: &SharedClient, home: &SharedRelay, server_id: &[u8; 32], url: &str, seqs: &[([u8; 32], u64)]) {
    let channels = {
        let c = client.lock().await;
        c.server_channel_mailboxes(server_id)
    };
    let mut view = home.lock().await.at(url);
    let c = client.lock().await;
    for (channel_id, mailbox_id) in channels {
        let seq = seqs.iter().find(|(m, _)| *m == mailbox_id).map_or(0, |(_, s)| *s);
        let _ = c.store().set_last_seen_seq(&mailbox_id, seq);
        view.add_route(mailbox_id);
        view.add_route(channel_id);
        view.subscribe(mailbox_id, seq);
    }
}

/// Move a server this account created to the relay at `target_url`, which must
/// accept this device (in practice the account's home). Members who are listed in
/// the uploaded group state can register there without an invite. Returns the
/// signed location, which the caller can turn into a move link.
pub async fn move_server(
    client: &SharedClient,
    home: &SharedRelay,
    server_id: &[u8; 32],
    target_url: &str,
) -> Result<ServerLocation> {
    let (creator_fp, own_fp, stored_generation, signing_key, channels) = {
        let c = client.lock().await;
        let server = c.store().get_server(server_id)?;
        (
            server.creator_fp,
            *c.fingerprint(),
            c.store().server_location_generation(server_id)?,
            c.signing_key_clone(),
            c.server_channel_mailboxes(server_id),
        )
    };
    if creator_fp != own_fp {
        return Err(GhostError::PermissionDenied("only the server's creator can move it".into()));
    }

    let target = standalone_client(home, target_url).await;
    let info = account::register_at(client, &target, None).await?;

    // 1. Group state at the target first, so members are listed there and may register.
    for (channel_id, mailbox_id) in &channels {
        let group_info = {
            let c = client.lock().await;
            c.export_channel_group_info(channel_id)?
        };
        target.lock().await.put_server_info(mailbox_id, group_info).await?;
    }

    // 2. Announce at the current epoch, which members still on the old relay can read,
    //    and publish the record where members can look it up later.
    let location = ServerLocation::sign(*server_id, next_generation(Some(stored_generation)), info.relay_ref.clone(), &signing_key);
    let announcement = {
        let mut c = client.lock().await;
        c.send_control(server_id, encode_server_moved(&location))?
    };
    if let Err(e) = home.lock().await.post_blob(&announcement.mailbox_id, announcement.blob).await {
        eprintln!("server move: old relay not told: {e}");
    }
    home.lock().await.put_server_location(&own_fp, &location).await?;

    // 3. The target relay becomes each group's external sender, committed at the target.
    let staged = {
        let mut c = client.lock().await;
        c.stage_server_external_sender(server_id, &info.relay_vk)?
    };
    let mut seqs = Vec::new();
    for (channel_id, mailbox_id, commit) in staged {
        let posted = target.lock().await.post_blob(&mailbox_id, commit).await;
        let mut c = client.lock().await;
        match posted {
            Ok(result) => {
                c.merge_pending_commit_for_channel(&channel_id)?;
                seqs.push((mailbox_id, result.seq));
                let group_info = c.export_channel_group_info(&channel_id)?;
                drop(c);
                target.lock().await.put_server_info(&mailbox_id, group_info).await?;
            }
            Err(e) => {
                let _ = c.clear_pending_commit_for_channel(&channel_id);
                return Err(e);
            }
        }
    }

    // 4. Local bookkeeping, live subscriptions, and the account's other devices.
    {
        let c = client.lock().await;
        c.store().set_server_relay(server_id, &info.relay_vk)?;
        c.store().set_server_location_generation(server_id, location.generation)?;
    }
    reroute(client, home, server_id, target_url, &seqs).await;
    if let Err(e) = account::update_mirror_grants(client, home).await {
        eprintln!("server move: mirror grants not updated: {e}");
    }
    sync::server_entry(client, home, server_id).await;
    Ok(location)
}

/// Follow a server move announced by `location`. Returns `true` if this device now
/// uses the new relay, `false` if the record is old or names the current relay.
/// Refuses records not signed by an active device of the server's creator.
pub async fn follow_move(
    client: &SharedClient,
    home: &SharedRelay,
    server_id: &[u8; 32],
    location: &ServerLocation,
) -> Result<bool> {
    let current_relay = {
        let mut c = client.lock().await;
        let server = c.store().get_server(server_id)?;
        if location.server_id != *server_id {
            return Err(GhostError::Format("move record names a different server".into()));
        }
        if location.generation <= c.store().server_location_generation(server_id)? {
            return Ok(false);
        }
        location
            .verify_signature()
            .map_err(|e| GhostError::IdentityLog(e.to_string()))?;
        let creator_log = c.cached_identity_log(&server.creator_fp)?.ok_or_else(|| {
            GhostError::IdentityLog("the server creator's identity log is not cached; cannot verify the move".into())
        })?;
        if !creator_log.is_active_device(&location.signer_vk) {
            return Err(GhostError::IdentityLog("move record is not signed by an active device of the server's creator".into()));
        }
        c.store().server_relay(server_id)?
    };

    if current_relay == Some(location.relay_ref.relay_vk) {
        let c = client.lock().await;
        c.store().set_server_location_generation(server_id, location.generation)?;
        return Ok(false);
    }
    let url = location
        .relay_ref
        .primary_https_url()
        .ok_or_else(|| GhostError::Network("moved server's relay has no reachable endpoint".into()))?
        .to_string();

    let target = standalone_client(home, &url).await;
    let info = account::register_at(client, &target, None).await?;
    if info.relay_vk != location.relay_ref.relay_vk {
        return Err(GhostError::Network(format!("relay at {url} is not the relay the move names")));
    }
    {
        let c = client.lock().await;
        c.store().set_server_relay(server_id, &info.relay_vk)?;
        c.store().set_server_location_generation(server_id, location.generation)?;
    }
    // The new relay's log for each mailbox starts after the move.
    reroute(client, home, server_id, &url, &[]).await;
    if let Err(e) = account::update_mirror_grants(client, home).await {
        eprintln!("server move: mirror grants not updated: {e}");
    }
    sync::server_entry(client, home, server_id).await;
    Ok(true)
}

/// Look up a server's location at its creator's home relay and follow it if newer.
/// For the case where the old relay vanished before announcing anything.
pub async fn check_location(client: &SharedClient, home: &SharedRelay, server_id: &[u8; 32]) -> Result<bool> {
    let (creator_fp, creator_home) = {
        let mut c = client.lock().await;
        let creator_fp = c.store().get_server(server_id)?.creator_fp;
        if creator_fp == *c.fingerprint() {
            return Ok(false);
        }
        let home_url = c
            .cached_identity_log(&creator_fp)?
            .and_then(|log| log.home_relay_ref)
            .and_then(|r| r.primary_https_url().map(str::to_string));
        (creator_fp, home_url)
    };
    let creator_home = creator_home
        .ok_or_else(|| GhostError::IdentityLog("the server creator's home relay is unknown".into()))?;
    let (reader, _events) = RelayClient::new(&creator_home);
    match reader.get_server_location(&creator_fp, server_id).await? {
        Some(location) => follow_move(client, home, server_id, &location).await,
        None => Ok(false),
    }
}

/// `check_location` for every server this account did not create. Failures are
/// logged per server; returns how many servers moved.
pub async fn check_all_locations(client: &SharedClient, home: &SharedRelay) -> usize {
    let servers = {
        let c = client.lock().await;
        let own = *c.fingerprint();
        c.store()
            .list_servers()
            .map(|list| list.into_iter().filter(|s| s.creator_fp != own).map(|s| s.server_id).collect::<Vec<_>>())
            .unwrap_or_default()
    };
    let mut moved = 0;
    for server_id in servers {
        match check_location(client, home, &server_id).await {
            Ok(true) => moved += 1,
            Ok(false) => {}
            Err(e) => eprintln!("server location check {}: {e}", hex::encode(&server_id[..8])),
        }
    }
    moved
}
