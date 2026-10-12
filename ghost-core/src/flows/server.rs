//! Creating a server, moving one to another relay, and following such a move as a
//! member.
//!
//! A server keeps its MLS groups and mailbox ids when it moves; only the relay
//! holding them changes. Members accept a move only from a `ServerLocation` signed
//! by an active device of the server's owner (under its policy), whichever way it
//! reaches them: an announcement on the old relay, a lookup at the owner's home, or
//! a move link.

use ghost_wire::server_location::ServerLocation;
use ghost_wire::short_id;

use crate::error::{GhostError, Result};
use crate::relay::{RelayClient, RelayInfo};
use crate::storage::ServerKind;
use crate::wire::encode_server_moved;

use super::{account, epoch, idlog, next_generation, server_relay_url, sync, SharedClient};

const MOVE_LINK_PREFIX: &str = "ghost://move?l=";

/// Create a server (or a DM, by `kind`) on the home relay: publish its group state,
/// subscribe to it, and tell this account's other devices. Undone when the relay will
/// not take the group state, since a server cannot exist without it; a process that ends
/// before the upload leaves it unpublished, and the next start publishes it.
pub async fn create(client: &SharedClient, home: &RelayClient, name: &str, kind: ServerKind, now: u64) -> Result<[u8; 32]> {
    super::home_key(client, home).await?;
    let (server_id, mailbox_id, group_info) = {
        let mut c = client.lock().await;
        let server_id = c.create_server(name, kind, now)?;
        let prepared = c
            .mailbox_id_for_server(&server_id)
            .ok_or_else(|| GhostError::ServerNotLoaded(name.into()))
            .and_then(|mailbox_id| Ok((mailbox_id, c.export_server_info(&server_id)?)));
        match prepared {
            Ok((mailbox_id, group_info)) => (server_id, mailbox_id, group_info),
            Err(e) => {
                let _ = c.abandon_created_server(&server_id);
                return Err(e);
            }
        }
    };
    if let Err(e) = home.put_server_info(&mailbox_id, group_info).await {
        let _ = client.lock().await.abandon_created_server(&server_id);
        return Err(e);
    }
    client.lock().await.store().server_published(&server_id)?;
    home.subscribe(mailbox_id, 0);
    sync::post_server_provisioned(client, home, &server_id).await;
    sync::server_entry(client, home, &server_id).await;
    Ok(server_id)
}

/// Finish making the servers this device made whose group state never reached the home
/// relay, the process having ended first: publish it and tell this account's other
/// devices, as creating them would have. One the relay will not take yet is tried again
/// at the next start. Run at start.
pub async fn publish_unpublished(client: &SharedClient, home: &RelayClient) {
    let servers = match client.lock().await.store().unpublished_servers() {
        Ok(servers) => servers,
        Err(e) => {
            tracing::warn!("unpublished servers not read: {e}");
            return;
        }
    };
    for server_id in servers {
        let prepared = {
            let c = client.lock().await;
            c.mailbox_id_for_server(&server_id)
                .ok_or_else(|| GhostError::ServerNotLoaded(short_id(&server_id)))
                .and_then(|mailbox_id| Ok((mailbox_id, c.export_server_info(&server_id)?)))
        };
        let published = match prepared {
            Ok((mailbox_id, group_info)) => home.put_server_info(&mailbox_id, group_info).await,
            Err(e) => Err(e),
        };
        if let Err(e) = published {
            tracing::warn!("server {}: group state not published yet: {e}", short_id(&server_id));
            continue;
        }
        if let Err(e) = client.lock().await.store().server_published(&server_id) {
            tracing::warn!("server {}: published, not recorded: {e}", short_id(&server_id));
        }
        sync::post_server_provisioned(client, home, &server_id).await;
        sync::server_entry(client, home, &server_id).await;
    }
}

/// Text an owner shares out of band when the old relay was the only one members
/// and owner had in common.
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
fn standalone_client(home: &RelayClient, url: &str) -> RelayClient {
    let (client, _events) = RelayClient::new(url);
    client.copy_auth_from(home);
    client
}

/// Route a server's mailboxes (and voice channels) to `url` and resubscribe there.
/// `seqs` gives the sequence to resume each mailbox from on the new relay.
async fn reroute(client: &SharedClient, home: &RelayClient, server_id: &[u8; 32], url: &str, seqs: &[([u8; 32], u64)]) {
    let channels = {
        let c = client.lock().await;
        c.server_channel_mailboxes(server_id)
    };
    let view = home.at(url);
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
    home: &RelayClient,
    server_id: &[u8; 32],
    target_url: &str,
) -> Result<ServerLocation> {
    let (owner_fp, own_fp, stored_generation, signing_key) = {
        let c = client.lock().await;
        // Moving the server is one way out of a halt: the state uploaded is this device's,
        // from before the change its rules refused.
        c.store().clear_server_halt(server_id)?;
        (
            c.server_owner(server_id)?,
            *c.fingerprint(),
            c.store().server_location_generation(server_id)?,
            c.signing_key_clone(),
        )
    };
    if owner_fp != own_fp {
        return Err(GhostError::PermissionDenied("only the server's owner can move it".into()));
    }
    // The owner is admitted to every private channel; it must be in each one to move
    // its group, or the channel would stay behind on the old relay. A relay that is gone
    // took the groups this device is not in with it.
    if let Err(e) = super::channels::join_admitted(client, home, server_id).await {
        tracing::warn!("server move: private channels not listed by the old relay: {e}");
    }
    let channels = client.lock().await.server_channel_mailboxes(server_id);

    let target = standalone_client(home, target_url);
    let info = account::register_at(client, home, &target, None).await?;

    // 1. Group state at the target first, so members are listed there and may register.
    //    The server group goes first: the target admits private channel groups only
    //    under a server group it holds.
    for (channel_id, mailbox_id) in &channels {
        let group_info = {
            let c = client.lock().await;
            c.export_channel_group_info(channel_id)?
        };
        target.put_server_info(mailbox_id, group_info).await?;
    }

    // 2. The record goes to this account's home first, which stores it only from an
    //    active device and is where members confirm any copy they are shown; then the
    //    announcement at the current epoch, which members still on the old relay can read.
    let location = ServerLocation::sign(*server_id, next_generation(Some(stored_generation)), info.relay_ref.clone(), &signing_key);
    home.put_server_location(&own_fp, &location).await?;
    let announcement = {
        let mut c = client.lock().await;
        c.send_control(server_id, encode_server_moved(&location))?
    };
    if let Err(e) = home.post_blob(&announcement.mailbox_id, announcement.blob).await {
        tracing::warn!("server move: old relay not told: {e}");
    }

    // 3. The target relay becomes each group's external sender, committed at the target.
    //    One group at a time, server group first: a private channel's commit names the
    //    server group epoch the target holds.
    let mut seqs = Vec::new();
    for (channel_id, mailbox_id) in &channels {
        let (channel_id, mailbox_id) = (*channel_id, *mailbox_id);
        let commit = {
            let mut c = client.lock().await;
            c.stage_external_sender(&channel_id, &info.relay_vk)?
        };
        let posted = target.post_blob(&mailbox_id, commit).await;
        let mut c = client.lock().await;
        match posted {
            Ok(result) => {
                c.merge_pending_commit_for_channel(&channel_id)?;
                seqs.push((mailbox_id, result.seq));
                let group_info = c.export_channel_group_info(&channel_id)?;
                drop(c);
                target.put_server_info(&mailbox_id, group_info).await?;
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
        // The owner's device carried its copy from before any refused change: following
        // the move is also the way out of a halt.
        c.store().clear_server_halt(server_id)?;
    }
    reroute(client, home, server_id, target_url, &seqs).await;
    if let Err(e) = account::update_mirror_grants(client, home).await {
        tracing::warn!("server move: mirror grants not updated: {e}");
    }
    sync::server_entry(client, home, server_id).await;
    Ok(location)
}

/// Follow a server move announced by `location`. Returns `true` if this device now
/// uses the new relay, `false` if the record is old or names the current relay.
///
/// A record counts only once the owner's home confirms it: the home stores a record
/// only from an active device of the owner, so a device revoked since this member last
/// read the owner's log cannot move the server with a record of its own, however fresh
/// the signature looks. The home's copy is followed when it is newer still.
pub async fn follow_move(
    client: &SharedClient,
    home: &RelayClient,
    server_id: &[u8; 32],
    location: &ServerLocation,
) -> Result<bool> {
    let owner_fp = {
        let c = client.lock().await;
        let owner_fp = c.server_owner(server_id)?;
        if location.server_id != *server_id {
            return Err(GhostError::Format("move record names a different server".into()));
        }
        if location.generation <= c.store().server_location_generation(server_id)? {
            return Ok(false);
        }
        location
            .verify_signature()
            .map_err(|e| GhostError::IdentityLog(e.to_string()))?;
        owner_fp
    };
    let named_url = |record: &ServerLocation| -> Result<String> {
        record
            .relay_ref
            .primary_https_url()
            .map(str::to_string)
            .ok_or_else(|| GhostError::Network("moved server's relay has no reachable endpoint".into()))
    };

    // The owner's log as fresh as the relays this device deals with allow, so the home
    // asked below is the owner's current one.
    idlog::refresh_member(client, home, server_id, &owner_fp).await;
    let mut registered = None;
    let location = match confirm_at_owner_home(client, &owner_fp, server_id, location).await? {
        Confirmation::Confirmed(record) => record,
        Confirmation::Unreachable => {
            // The owner's home, as this device knows it, cannot be reached or is unknown
            // (the server's relay may be gone, which is what moves are for). The named
            // relay may hold the owner's log, which can only extend what is cached, and
            // may name a home that answers; reading there means registering first.
            let url = named_url(location)?;
            let target = standalone_client(home, &url);
            let info = account::register_at(client, home, &target, None).await?;
            names_relay(&info, location, &url)?;
            registered = Some(info);
            if let Err(e) = idlog::fetch_and_verify(client, &target, &owner_fp).await {
                tracing::warn!("server move: owner's log not read at the named relay: {e}");
            }
            match confirm_at_owner_home(client, &owner_fp, server_id, location).await? {
                Confirmation::Confirmed(record) => record,
                Confirmation::Unreachable => {
                    return Err(GhostError::Network("the server owner's home cannot be reached to confirm the move; try again later".into()));
                }
            }
        }
    };

    let current_relay = client.lock().await.store().server_relay(server_id)?;
    if current_relay == Some(location.relay_ref.relay_vk) {
        let c = client.lock().await;
        c.store().set_server_location_generation(server_id, location.generation)?;
        return Ok(false);
    }
    let url = named_url(&location)?;
    let info = match registered {
        Some(info) if info.relay_vk == location.relay_ref.relay_vk => info,
        _ => account::register_at(client, home, &standalone_client(home, &url), None).await?,
    };
    names_relay(&info, &location, &url)?;
    {
        let c = client.lock().await;
        c.store().set_server_relay(server_id, &info.relay_vk)?;
        c.store().set_server_location_generation(server_id, location.generation)?;
        // The owner's device carried its copy from before any refused change: following
        // the move is also the way out of a halt.
        c.store().clear_server_halt(server_id)?;
    }
    // The new relay's log for each mailbox starts after the move.
    reroute(client, home, server_id, &url, &[]).await;
    if let Err(e) = account::update_mirror_grants(client, home).await {
        tracing::warn!("server move: mirror grants not updated: {e}");
    }
    sync::server_entry(client, home, server_id).await;
    Ok(true)
}

/// What the owner's home says about a move record this device was shown.
enum Confirmation {
    /// The record to follow: the one shown, or the home's newer one.
    Confirmed(ServerLocation),
    /// The owner's home is unknown to this device or did not answer.
    Unreachable,
}

/// Ask the owner's home, as the cached owner log names it, for the record it holds for
/// the server; the home stores one only from an active device of the owner, so its word
/// stands in for a fresh log. A home that holds no record, or an older or different one,
/// refuses the move.
async fn confirm_at_owner_home(
    client: &SharedClient,
    owner_fp: &[u8; 32],
    server_id: &[u8; 32],
    shown: &ServerLocation,
) -> Result<Confirmation> {
    let owner_home = client
        .lock()
        .await
        .cached_identity_log(owner_fp)?
        .and_then(|log| log.home_relay_ref)
        .and_then(|r| r.primary_https_url().map(str::to_string));
    let Some(owner_home) = owner_home else { return Ok(Confirmation::Unreachable) };
    let (reader, _events) = RelayClient::new(&owner_home);
    let stored = match reader.get_server_location(owner_fp, server_id).await {
        Ok(stored) => stored,
        Err(GhostError::Network(_)) | Err(GhostError::RelayStatus { status: 500..=599, .. }) => return Ok(Confirmation::Unreachable),
        Err(e) => return Err(e),
    };
    match stored {
        Some(stored) if stored.generation > shown.generation && stored.server_id == *server_id => {
            stored.verify_signature().map_err(|e| GhostError::IdentityLog(e.to_string()))?;
            Ok(Confirmation::Confirmed(stored))
        }
        Some(stored) if stored.to_bytes() == shown.to_bytes() => Ok(Confirmation::Confirmed(stored)),
        _ => Err(GhostError::IdentityLog("the server owner's home does not confirm this move".into())),
    }
}

/// Whether the relay reached at `url` is the one a move record names.
fn names_relay(info: &RelayInfo, location: &ServerLocation, url: &str) -> Result<()> {
    if info.relay_vk != location.relay_ref.relay_vk {
        return Err(GhostError::Network(format!("relay at {url} is not the relay the move names")));
    }
    Ok(())
}

/// Follow a move this device was shown in a move link. One whose relay or owner's home
/// cannot be reached now is kept and tried again at each account check
/// (`retry_shown_moves`); the error still says why it was not followed now.
pub async fn follow_move_link(client: &SharedClient, home: &RelayClient, location: &ServerLocation) -> Result<bool> {
    let outcome = follow_move(client, home, &location.server_id, location).await;
    let c = client.lock().await;
    match &outcome {
        Err(GhostError::Network(_) | GhostError::RelayStatus { status: 500..=599, .. }) => {
            c.store().keep_shown_move(&location.server_id, &location.to_bytes())?;
        }
        _ => c.store().forget_shown_move(&location.server_id)?,
    }
    outcome
}

/// Try the kept move records again; returns how many servers moved.
pub async fn retry_shown_moves(client: &SharedClient, home: &RelayClient) -> usize {
    let records = client.lock().await.store().shown_moves().unwrap_or_default();
    let mut moved = 0;
    for record in records {
        let Ok(location) = ServerLocation::from_bytes(&record) else { continue };
        match follow_move_link(client, home, &location).await {
            Ok(true) => moved += 1,
            Ok(false) => {}
            Err(e) => tracing::debug!("server move {} still not followed: {e}", short_id(&location.server_id)),
        }
    }
    moved
}

/// Look up a server's location at its owner's home relay and follow it if newer: for
/// a server whose relay vanished before announcing anything, and for the owner's other
/// devices, whose own home holds the record.
pub async fn check_location(client: &SharedClient, home: &RelayClient, server_id: &[u8; 32]) -> Result<bool> {
    let (owner_fp, owner_home) = {
        let mut c = client.lock().await;
        let owner_fp = c.server_owner(server_id)?;
        let home_url = c
            .cached_identity_log(&owner_fp)?
            .and_then(|log| log.home_relay_ref)
            .and_then(|r| r.primary_https_url().map(str::to_string));
        (owner_fp, home_url)
    };
    let owner_home = owner_home
        .ok_or_else(|| GhostError::IdentityLog("the server owner's home relay is unknown".into()))?;
    let (reader, _events) = RelayClient::new(&owner_home);
    match reader.get_server_location(&owner_fp, server_id).await? {
        Some(location) => follow_move(client, home, server_id, &location).await,
        None => Ok(false),
    }
}

/// `check_location` for every server. Failures are logged per server; returns how many
/// servers moved.
pub async fn check_all_locations(client: &SharedClient, home: &RelayClient) -> usize {
    let servers = {
        let c = client.lock().await;
        c.store().list_servers().map(|list| list.into_iter().map(|s| s.server_id).collect::<Vec<_>>()).unwrap_or_default()
    };
    check_locations(client, home, &servers).await
}

/// `check_location` for the given servers; returns how many moved.
pub async fn check_locations(client: &SharedClient, home: &RelayClient, servers: &[[u8; 32]]) -> usize {
    let mut moved = 0;
    for &server_id in servers {
        match check_location(client, home, &server_id).await {
            Ok(true) => moved += 1,
            Ok(false) => {}
            Err(e) => tracing::warn!("server location check {}: {e}", short_id(&server_id)),
        }
    }
    moved
}

/// Take the relay's version of a halted server after all: rejoin every group of the
/// server at the relay's epoch, the server's own group first so its private channels can
/// name the epoch, then follow the server again.
pub async fn accept_relay_state(client: &SharedClient, relay: &RelayClient, server_id: &[u8; 32]) -> Result<()> {
    let (mailboxes, hosting) = {
        let c = client.lock().await;
        (c.server_channel_mailboxes(server_id), server_relay_url(&c, server_id))
    };
    let relay = relay.at(hosting.as_deref().unwrap_or(&relay.base_url()));
    for (channel_id, mailbox_id) in mailboxes {
        if !epoch::recover(client, &relay, &channel_id, &mailbox_id, "accept relay state").await? {
            return Err(GhostError::Network("the relay refused the rejoin; try again".into()));
        }
    }
    client.lock().await.store().clear_server_halt(server_id)?;
    Ok(())
}
