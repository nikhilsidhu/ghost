mod common;

use std::time::Duration;

use ghost_core::client::{GhostClient, ReceiveResult};
use ghost_core::identity::Identity;
use ghost_core::relay::{IncomingBlob, RelayClient, RelayEvent};
use ghost_core::storage::ServerKind;
use ghost_core::wire::{derive_default_channel_id, derive_mls_group_id, mls_group_mailbox_id};
use openmls::key_packages::KeyPackageIn;
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::ProtocolVersion;
use openmls_rust_crypto::RustCrypto;

#[tokio::test]
async fn message_metadata_preserved_through_relay() {
    let relay_url = common::start_relay().await;
    let mut s = setup_two_clients([0x01; 32], [0x02; 32]);

    let (mut send_relay, _) = RelayClient::new(&relay_url);
    let (mut recv_relay, mut events) = RelayClient::new(&relay_url);
    common::setup_relay_auth(&relay_url, &mut send_relay, &s.sender).await;
    common::setup_relay_auth(&relay_url, &mut recv_relay, &s.receiver).await;
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
    send_relay.send(&s.mailbox_id, outbound.blob).await.unwrap();

    let incoming = recv_blob(&mut events).await;
    let msg = s
        .receiver
        .receive_blob(&s.server_id, &incoming.payload, Some(incoming.received_at))
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

fn setup_two_clients(sender_seed: [u8; 32], receiver_seed: [u8; 32]) -> TwoClientSetup {
    let mut sender =
        GhostClient::open_in_memory(Identity::from_seed(sender_seed).unwrap(), sender_seed)
            .unwrap();
    let mut receiver =
        GhostClient::open_in_memory(Identity::from_seed(receiver_seed).unwrap(), receiver_seed)
            .unwrap();

    let server_id = sender
        .create_server("test", ServerKind::Server, 1000)
        .unwrap();
    let kp = receiver.generate_key_package().unwrap();
    let recv_fp = *receiver.fingerprint();
    let recv_name = receiver.identity().display_name.clone();
    let (_, welcome_bytes) = sender
        .invite_member(&server_id, kp, recv_fp, &recv_name, 1000)
        .unwrap();
    receiver
        .join_server(&server_id, &welcome_bytes, "test", ServerKind::Server, 1000)
        .unwrap();

    let mls_gid = derive_mls_group_id(&server_id);
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

    let (mut send_relay, _) = RelayClient::new(&relay_url);
    let (mut recv_relay, mut events) = RelayClient::new(&relay_url);
    common::setup_relay_auth(&relay_url, &mut send_relay, &s.sender).await;
    common::setup_relay_auth(&relay_url, &mut recv_relay, &s.receiver).await;
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
            .await
            .unwrap();
    }

    // Receive and decrypt all three, verifying order
    for expected in &payloads {
        let incoming = recv_blob(&mut events).await;
        let msg = s
            .receiver
            .receive_blob(&s.server_id, &incoming.payload, Some(incoming.received_at))
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
    let (mut relay_a, mut events_a) = RelayClient::new(&relay_url);
    let (mut relay_b, mut events_b) = RelayClient::new(&relay_url);
    common::setup_relay_auth(&relay_url, &mut relay_a, &s.sender).await;
    common::setup_relay_auth(&relay_url, &mut relay_b, &s.receiver).await;
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
    relay_a.send(&s.mailbox_id, out_a.blob).await.unwrap();

    let incoming_b = recv_blob(&mut events_b).await;
    let msg_at_b = s
        .receiver
        .receive_blob(&s.server_id, &incoming_b.payload, Some(incoming_b.received_at))
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
    relay_b.send(&s.mailbox_id, out_b.blob).await.unwrap();

    let incoming_a = recv_blob(&mut events_a).await;
    let msg_at_a = s
        .sender
        .receive_blob(&s.server_id, &incoming_a.payload, Some(incoming_a.received_at))
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
    let (mut send_relay, _) = RelayClient::new(&relay_url);
    let (mut listen_relay, mut events) = RelayClient::new(&relay_url);
    common::setup_relay_auth(&relay_url, &mut send_relay, &s.sender).await;
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
        .await
        .unwrap();

    // The listen connection receives the blob (different WS conn, so relay delivers it)
    let incoming = recv_blob(&mut events).await;

    // receive_any detects self-authored MLS messages and returns Skipped
    let result = s
        .sender
        .receive_any(&s.server_id, &incoming.payload, Some(incoming.received_at))
        .unwrap();
    assert!(
        matches!(result, ReceiveResult::Skipped),
        "expected Skipped for self-message, got a different variant"
    );
}

#[tokio::test]
async fn invite_with_real_key_package() {
    let relay_url = common::start_relay().await;

    let mut inviter =
        GhostClient::open_in_memory(Identity::from_seed([0x40; 32]).unwrap(), [0x40; 32]).unwrap();
    let mut joiner =
        GhostClient::open_in_memory(Identity::from_seed([0x41; 32]).unwrap(), [0x41; 32]).unwrap();

    // Inviter creates a server
    let server_id = inviter
        .create_server("real-invite", ServerKind::Server, 1000)
        .unwrap();

    // Joiner generates a real MLS key package and serializes it
    let kp = joiner.generate_key_package().unwrap();
    let kp_bytes = kp.tls_serialize_detached().unwrap();

    let token = "real-invite-token";
    let (relay_inviter, _) = RelayClient::new(&relay_url);
    let (relay_joiner, _) = RelayClient::new(&relay_url);

    // Relay invite flow: register, post key package, retrieve it
    relay_inviter
        .register_invite(token, u64::MAX)
        .await
        .unwrap();
    relay_joiner
        .post_join(token, kp_bytes.clone())
        .await
        .unwrap();

    let retrieved_kp_bytes = relay_inviter.get_join(token).await.unwrap();
    assert_eq!(retrieved_kp_bytes, kp_bytes);

    // Deserialize and validate the key package on the inviter side
    let kp_in = KeyPackageIn::tls_deserialize_exact(&retrieved_kp_bytes).unwrap();
    let crypto = RustCrypto::default();
    let validated_kp = kp_in.validate(&crypto, ProtocolVersion::Mls10).unwrap();

    // Inviter adds the joiner using the real key package
    let joiner_fp = *joiner.fingerprint();
    let joiner_name = joiner.identity().display_name.clone();
    let (_, welcome_bytes) = inviter
        .invite_member(&server_id, validated_kp, joiner_fp, &joiner_name, 2000)
        .unwrap();

    // Send welcome bytes back through the relay
    relay_inviter
        .post_accept(token, welcome_bytes.clone())
        .await
        .unwrap();
    let retrieved_welcome = relay_joiner.get_accept(token).await.unwrap();
    assert_eq!(retrieved_welcome, welcome_bytes);

    // Joiner processes the welcome
    joiner
        .join_server(
            &server_id,
            &retrieved_welcome,
            "real-invite",
            ServerKind::Server,
            2000,
        )
        .unwrap();

    // Verify both can exchange encrypted messages through the relay
    let mls_gid = derive_mls_group_id(&server_id);
    let mailbox_id = mls_group_mailbox_id(&mls_gid);
    let channel_id = derive_default_channel_id(&server_id);

    let (mut inv_relay, _) = RelayClient::new(&relay_url);
    let (mut join_relay, mut join_events) = RelayClient::new(&relay_url);
    common::setup_relay_auth(&relay_url, &mut inv_relay, &inviter).await;
    common::setup_relay_auth(&relay_url, &mut join_relay, &joiner).await;
    inv_relay.subscribe(mailbox_id, 0);
    join_relay.subscribe(mailbox_id, 0);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (outbound, _) = inviter
        .send_message(
            &server_id,
            &channel_id,
            b"welcome aboard".to_vec(),
            vec![],
            3000,
        )
        .unwrap();
    inv_relay.send(&mailbox_id, outbound.blob).await.unwrap();

    let incoming = recv_blob(&mut join_events).await;
    let msg = joiner
        .receive_blob(&server_id, &incoming.payload, Some(incoming.received_at))
        .unwrap();
    assert_eq!(msg.content, b"welcome aboard");
    assert_eq!(msg.sender_fp, *inviter.fingerprint());
}
