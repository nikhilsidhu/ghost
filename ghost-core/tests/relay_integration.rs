mod common;

use std::time::Duration;

use ghost_core::client::{GhostClient, ReceiveResult};
use ghost_core::identity::Identity;
use ghost_core::relay::{IncomingBlob, RelayClient, RelayEvent};
use ghost_core::storage::ServerKind;
use ghost_core::wire::{derive_default_channel_id, derive_mls_group_id, mls_group_mailbox_id};

#[tokio::test]
async fn sends_to_a_relay_that_is_down_queue_then_refuse_without_blocking() {
    let relay = common::start_switched_relay().await;
    let s = setup_two_clients([0x01; 32], [0x02; 32]);
    let (send_relay, _) = RelayClient::new(&relay.url());
    common::setup_relay_auth(&relay.url(), &send_relay, &s.sender).await;
    send_relay.subscribe(s.mailbox_id, 0);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // The connection holds what is sent while the relay is down, up to a limit; past it
    // a send is refused at once, because a waiting send would hold up every caller
    // sharing the client.
    relay.go_down();
    let accepted = tokio::time::timeout(Duration::from_secs(5), async {
        (0..5000).filter(|_| send_relay.send(&s.mailbox_id, vec![0u8; 16]).is_ok()).count()
    })
    .await
    .expect("sending to an unreachable relay never waits");
    assert!(accepted > 0, "messages queue for the reconnect");
    assert!(accepted < 5000, "the queue is bounded");
}

#[tokio::test]
async fn message_metadata_preserved_through_relay() {
    let relay_url = common::start_relay().await;
    let mut s = setup_two_clients([0x01; 32], [0x02; 32]);

    let (send_relay, _) = RelayClient::new(&relay_url);
    let (recv_relay, mut events) = RelayClient::new(&relay_url);
    common::setup_relay_auth(&relay_url, &send_relay, &s.sender).await;
    common::setup_relay_auth(&relay_url, &recv_relay, &s.receiver).await;
    publish_group(&send_relay, &s).await;
    send_relay.subscribe(s.mailbox_id, 0);
    recv_relay.subscribe(s.mailbox_id, 0);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send a message with a specific timestamp and references
    let fake_ref = [0xCC; 32];
    let (outbound, message_id) = s
        .sender
        .send_message(
            &s.server_id,
            &s.channel_id,
            b"hello through relay".to_vec(),
            vec![fake_ref],
            2000,
        )
        .unwrap();
    send_relay.send(&s.mailbox_id, outbound.blob).unwrap();

    let incoming = recv_blob(&mut events).await;
    let msg = s
        .receiver
        .receive_blob(&s.channel_id, &incoming.payload, Some(incoming.received_at))
        .unwrap();

    // Verify all metadata survived the relay roundtrip
    assert_eq!(msg.content, b"hello through relay");
    assert_eq!(msg.sender_fp, *s.sender.fingerprint());
    assert_eq!(msg.channel_id, s.channel_id);
    assert_eq!(msg.timestamp, 2000);
    assert_eq!(msg.message_id, message_id);
    assert_eq!(msg.references, vec![fake_ref]);
}

/// Wait for the next blob on an event receiver, ignoring acks/gaps/presence.
async fn recv_blob(events: &mut tokio::sync::mpsc::Receiver<RelayEvent>) -> IncomingBlob {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match events.recv().await {
                Some(RelayEvent::Blob(blob)) => break blob,
                Some(_) => continue,
                None => panic!("event channel closed"),
            }
        }
    })
    .await
    .expect("timed out waiting for blob")
}

/// Set up two GhostClients in a shared MLS group and return everything needed
/// to send/receive through a relay.
struct TwoClientSetup {
    sender: GhostClient,
    receiver: GhostClient,
    server_id: [u8; 32],
    mailbox_id: [u8; 32],
    channel_id: [u8; 32],
}

/// Tell the relay the group's state, as creating a server does, so it knows the epoch
/// posts must name.
async fn publish_group(relay: &RelayClient, s: &TwoClientSetup) {
    relay.put_server_info(&s.mailbox_id, s.sender.export_server_info(&s.server_id).unwrap()).await.unwrap();
}

fn register_identity_in_cache(client: &mut GhostClient, identity: &Identity) {
    client.cache_identity_chain(&[identity.own_genesis()]).unwrap();
}

fn setup_two_clients(sender_seed: [u8; 32], receiver_seed: [u8; 32]) -> TwoClientSetup {
    let id_sender = Identity::from_seed(sender_seed).unwrap();
    let id_receiver = Identity::from_seed(receiver_seed).unwrap();
    let mut sender =
        GhostClient::open_in_memory(Identity::from_seed(sender_seed).unwrap(), sender_seed)
            .unwrap();
    let mut receiver =
        GhostClient::open_in_memory(Identity::from_seed(receiver_seed).unwrap(), receiver_seed)
            .unwrap();

    // Register each other's identities for credential validation
    register_identity_in_cache(&mut sender, &id_receiver);
    register_identity_in_cache(&mut receiver, &id_sender);
    // Groups name a relay as external sender; these tests need no proposals from it.
    sender.set_relay_vk([0x7E; 32]);

    let server_id = sender
        .create_server("test", ServerKind::Server, 1000)
        .unwrap();
    // The receiver joins by external commit on the sender's group state, as invites work.
    let invite = sender.create_invite(&server_id, u64::MAX).unwrap();
    let payload = receiver.open_invite(&invite.sealed_payload, &invite.key).unwrap();
    let group_info = sender.export_server_info(&server_id).unwrap();
    let (_, channel_results, _) = receiver.join_by_invite(payload, group_info, 1000).unwrap();
    let (channel_id, commit, _) = &channel_results[0];
    sender.receive_any(channel_id, commit, Some(1000)).unwrap();

    let mls_gid = derive_mls_group_id(&server_id, &derive_default_channel_id(&server_id));
    let mailbox_id = mls_group_mailbox_id(&mls_gid);
    let channel_id = derive_default_channel_id(&server_id);

    TwoClientSetup {
        sender,
        receiver,
        server_id,
        mailbox_id,
        channel_id,
    }
}

#[tokio::test]
async fn multiple_messages_in_order() {
    let relay_url = common::start_relay().await;
    let mut s = setup_two_clients([0x10; 32], [0x11; 32]);

    let (send_relay, _) = RelayClient::new(&relay_url);
    let (recv_relay, mut events) = RelayClient::new(&relay_url);
    common::setup_relay_auth(&relay_url, &send_relay, &s.sender).await;
    common::setup_relay_auth(&relay_url, &recv_relay, &s.receiver).await;
    publish_group(&send_relay, &s).await;
    send_relay.subscribe(s.mailbox_id, 0);
    recv_relay.subscribe(s.mailbox_id, 0);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let payloads: Vec<&[u8]> = vec![b"msg1", b"msg2", b"msg3"];

    // Send all three messages through the relay
    for (i, payload) in payloads.iter().enumerate() {
        let (outbound, _) = s
            .sender
            .send_message(
                &s.server_id,
                &s.channel_id,
                payload.to_vec(),
                vec![],
                2000 + i as u64,
            )
            .unwrap();
        send_relay
            .send(&s.mailbox_id, outbound.blob)
            .unwrap();
    }

    // Receive and decrypt all three, verifying order
    for expected in &payloads {
        let incoming = recv_blob(&mut events).await;
        let msg = s
            .receiver
            .receive_blob(&s.channel_id, &incoming.payload, Some(incoming.received_at))
            .unwrap();
        assert_eq!(&msg.content, expected);
        assert_eq!(msg.sender_fp, *s.sender.fingerprint());
    }
}

#[tokio::test]
async fn bidirectional_messaging() {
    let relay_url = common::start_relay().await;
    let mut s = setup_two_clients([0x20; 32], [0x21; 32]);

    // Both sides share one relay connection each, both subscribe
    let (relay_a, mut events_a) = RelayClient::new(&relay_url);
    let (relay_b, mut events_b) = RelayClient::new(&relay_url);
    common::setup_relay_auth(&relay_url, &relay_a, &s.sender).await;
    common::setup_relay_auth(&relay_url, &relay_b, &s.receiver).await;
    publish_group(&relay_a, &s).await;
    relay_a.subscribe(s.mailbox_id, 0);
    relay_b.subscribe(s.mailbox_id, 0);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // A (sender) sends to B (receiver)
    let (out_a, _) = s
        .sender
        .send_message(
            &s.server_id,
            &s.channel_id,
            b"from A".to_vec(),
            vec![],
            3000,
        )
        .unwrap();
    relay_a.send(&s.mailbox_id, out_a.blob).unwrap();

    let incoming_b = recv_blob(&mut events_b).await;
    let msg_at_b = s
        .receiver
        .receive_blob(&s.channel_id, &incoming_b.payload, Some(incoming_b.received_at))
        .unwrap();
    assert_eq!(msg_at_b.content, b"from A");
    assert_eq!(msg_at_b.sender_fp, *s.sender.fingerprint());

    // B (receiver) sends to A (sender)
    let (out_b, _) = s
        .receiver
        .send_message(
            &s.server_id,
            &s.channel_id,
            b"from B".to_vec(),
            vec![],
            3001,
        )
        .unwrap();
    relay_b.send(&s.mailbox_id, out_b.blob).unwrap();

    let incoming_a = recv_blob(&mut events_a).await;
    let msg_at_a = s
        .sender
        .receive_blob(&s.channel_id, &incoming_a.payload, Some(incoming_a.received_at))
        .unwrap();
    assert_eq!(msg_at_a.content, b"from B");
    assert_eq!(msg_at_a.sender_fp, *s.receiver.fingerprint());
}

#[tokio::test]
async fn self_message_not_echoed_as_new() {
    let relay_url = common::start_relay().await;
    let mut s = setup_two_clients([0x30; 32], [0x31; 32]);

    // The relay skips echoing a blob back on the same WS connection that sent it.
    // Use a separate connection to send vs receive so the blob is delivered.
    let (send_relay, _) = RelayClient::new(&relay_url);
    let (listen_relay, mut events) = RelayClient::new(&relay_url);
    common::setup_relay_auth(&relay_url, &send_relay, &s.sender).await;
    publish_group(&send_relay, &s).await;
    // Same identity — genesis already pushed, just set auth on the second connection
    listen_relay.set_auth(
        *s.sender.fingerprint(),
        s.sender.verifying_key_bytes(),
        s.sender.signing_key_clone(),
    );
    send_relay.subscribe(s.mailbox_id, 0);
    listen_relay.subscribe(s.mailbox_id, 0);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (outbound, _) = s
        .sender
        .send_message(
            &s.server_id,
            &s.channel_id,
            b"echo test".to_vec(),
            vec![],
            4000,
        )
        .unwrap();
    send_relay
        .send(&s.mailbox_id, outbound.blob)
        .unwrap();

    // The listen connection receives the blob (different WS conn, so relay delivers it)
    let incoming = recv_blob(&mut events).await;

    // receive_any detects self-authored MLS messages and returns Skipped
    let result = s
        .sender
        .receive_any(&s.channel_id, &incoming.payload, Some(incoming.received_at))
        .unwrap();
    assert!(
        matches!(result, ReceiveResult::Skipped),
        "expected Skipped for self-message, got a different variant"
    );
}

#[tokio::test]
async fn a_silent_connection_is_dropped_and_reopened() {
    // A relay that never pings: the only thing keeping the connection alive is the
    // client noticing the silence.
    let mut config = common::relay_config(30);
    config.ws_ping_secs = 3600;
    let relay = common::start_relay_with(config).await;
    let s = setup_two_clients([0x01; 32], [0x02; 32]);
    let (client, mut events) = RelayClient::new(&relay.url());
    common::setup_relay_auth(&relay.url(), &client, &s.sender).await;
    client.set_ws_silence_limit(Duration::from_millis(300));
    client.subscribe(s.mailbox_id, 0);

    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while seen != [true, false, true] {
        let event = tokio::time::timeout_at(deadline, events.recv()).await.expect("the connection reopened after going quiet");
        if let Some(RelayEvent::ConnectionState { connected, .. }) = event {
            seen.push(connected);
        }
    }
}

/// A stand-in relay that completes the WebSocket handshake, reads the resume point and
/// then does only what it is told: `talks` sends a frame every 50 ms, `listens` reads
/// whatever the client sends. Each new connection is served the same way.
async fn bare_relay(talks: bool, listens: bool) -> String {
    use futures_util::{SinkExt, StreamExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(socket).await else { return };
                let (mut sink, mut stream) = ws.split();
                let _resume_point = stream.next().await;
                let reader = async {
                    if listens {
                        while stream.next().await.is_some() {}
                    } else {
                        std::future::pending::<()>().await;
                    }
                };
                let talker = async {
                    if !talks {
                        return std::future::pending::<()>().await;
                    }
                    while sink.send(tokio_tungstenite::tungstenite::Message::text("{}")).await.is_ok() {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                };
                tokio::select! {
                    _ = reader => {}
                    _ = talker => {}
                }
            });
        }
    });
    format!("http://{addr}")
}

/// Waits for the connection to come up, drop and come up again.
async fn reopened(events: &mut tokio::sync::mpsc::Receiver<RelayEvent>, within: Duration, what: &str) {
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + within;
    while seen != [true, false, true] {
        let event = tokio::time::timeout_at(deadline, events.recv()).await.unwrap_or_else(|_| panic!("{what}"));
        if let Some(RelayEvent::ConnectionState { connected, .. }) = event {
            seen.push(connected);
        }
    }
}

/// A relay that keeps talking but takes nothing: the client's writes stall, and the
/// connection is reopened rather than left stuck with its outbox filling behind it.
#[tokio::test]
async fn a_connection_whose_writes_stall_is_reopened() {
    let url = bare_relay(true, false).await;
    let (client, mut events) = RelayClient::new(&url);
    client.set_ws_silence_limit(Duration::from_millis(300));
    let mailbox_id = [0x31; 32];
    client.subscribe(mailbox_id, 0);
    // Far more than the socket buffers hold; what the connection holds goes out once it is up.
    let chunk = "x".repeat(64 * 1024);
    for _ in 0..400 {
        client.send_text(&mailbox_id, chunk.clone()).unwrap();
    }
    reopened(&mut events, Duration::from_secs(10), "a stalled connection was never reopened").await;
}

/// A relay gone quiet is noticed however often the client sends: silence counts from the
/// last frame heard.
#[tokio::test]
async fn a_quiet_relay_is_noticed_while_the_client_keeps_sending() {
    let url = bare_relay(false, true).await;
    let (client, mut events) = RelayClient::new(&url);
    let client = std::sync::Arc::new(client);
    client.set_ws_silence_limit(Duration::from_millis(300));
    let mailbox_id = [0x32; 32];
    client.subscribe(mailbox_id, 0);
    let sender = client.clone();
    let chatter = tokio::spawn(async move {
        loop {
            let _ = sender.send_text(&mailbox_id, "{}".into());
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    reopened(&mut events, Duration::from_secs(3), "a quiet relay was not noticed while the client kept sending").await;
    chatter.abort();
}

/// A relay that answers but does not admit this device to a mailbox is reported once per
/// run of refusals, not on every retry.
#[tokio::test]
async fn a_mailbox_the_relay_refuses_is_reported_once() {
    let relay_url = common::start_relay().await;
    let s = setup_two_clients([0x01; 32], [0x02; 32]);
    let (sender_relay, _) = RelayClient::new(&relay_url);
    common::setup_relay_auth(&relay_url, &sender_relay, &s.sender).await;
    publish_group(&sender_relay, &s).await;

    // A third account the relay knows, but the group does not list.
    let outsider = GhostClient::open_in_memory(Identity::from_seed([0x03; 32]).unwrap(), [0x03; 32]).unwrap();
    let (outsider_relay, mut events) = RelayClient::new(&relay_url);
    common::setup_relay_auth(&relay_url, &outsider_relay, &outsider).await;
    outsider_relay.subscribe(s.mailbox_id, 0);

    let mut refusals = 0;
    let until = tokio::time::Instant::now() + Duration::from_secs(4);
    while let Ok(Some(event)) = tokio::time::timeout_at(until, events.recv()).await {
        match event {
            RelayEvent::Refused { mailbox_id, .. } if mailbox_id == s.mailbox_id => refusals += 1,
            RelayEvent::ConnectionState { connected: true, .. } => panic!("the relay admitted an outsider"),
            _ => {}
        }
    }
    assert_eq!(refusals, 1, "a refusal is reported once, however often the connection retries");
}
