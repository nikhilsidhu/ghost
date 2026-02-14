use std::time::Duration;

use tokio::net::TcpListener;

use ghost_core::client::GhostClient;
use ghost_core::relay::{RelayClient, RelayEvent};
use ghost_core::wire::{derive_default_channel_id, derive_mls_group_id, group_mailbox_id};
use ghost_relay::config::Config;
use ghost_relay::storage::Storage;
use ghost_relay::{routes, state};

async fn start_relay() -> String {
    let config = Config {
        port: 0,
        max_blob_size: 10 * 1024 * 1024,
        ttl: Duration::from_secs(3600),
        voice_port: 0,
        max_voice_participants: 25,
    };
    let storage = Storage::open_in_memory().unwrap();
    let st = state::new_state(config, storage);
    let app = routes::router(st);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://127.0.0.1:{port}")
}

#[tokio::test]
async fn encrypted_message_through_relay() {
    let relay_url = start_relay().await;

    let mut sender = GhostClient::open_in_memory([0x01; 32]).unwrap();
    let mut receiver = GhostClient::open_in_memory([0x02; 32]).unwrap();

    // Local MLS setup
    let group_id = sender.create_group("test", 1000).unwrap();
    let kp = receiver.generate_key_package().unwrap();
    let recv_fp = *receiver.fingerprint();
    let recv_name = receiver.identity().display_name.clone();
    let (_, welcome_bytes) = sender
        .invite_member(&group_id, kp, recv_fp, &recv_name, 1000)
        .unwrap();
    receiver
        .join_group(&group_id, &welcome_bytes, "test", 1000)
        .unwrap();

    let mls_gid = derive_mls_group_id(&group_id);
    let mailbox_id = group_mailbox_id(&mls_gid);
    let channel_id = derive_default_channel_id(&group_id);

    // Connect both to relay
    let (mut send_relay, _) = RelayClient::new(&relay_url);
    let (mut recv_relay, mut events) = RelayClient::new(&relay_url);
    send_relay.subscribe(mailbox_id, 0);
    recv_relay.subscribe(mailbox_id, 0);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Encrypt, send through relay, receive, decrypt
    let (outbound, _) = sender
        .send_message(
            &group_id,
            &channel_id,
            b"hello through relay".to_vec(),
            vec![],
            2000,
        )
        .unwrap();
    assert_eq!(outbound.mailbox_id, mailbox_id);
    send_relay.send(&mailbox_id, outbound.blob).await.unwrap();

    let incoming = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match events.recv().await {
                Some(RelayEvent::Blob(blob)) => break blob,
                Some(RelayEvent::Ack(_)) => continue,
                None => panic!("event channel closed"),
            }
        }
    })
    .await
    .expect("timed out waiting for blob");
    assert_eq!(incoming.mailbox_id, mailbox_id);

    let msg = receiver
        .receive_blob(&group_id, &incoming.payload, Some(incoming.received_at))
        .unwrap();
    assert_eq!(msg.content, b"hello through relay");
    assert_eq!(msg.sender_fp, *sender.fingerprint());
}

#[tokio::test]
async fn invite_roundtrip_via_relay() {
    let relay_url = start_relay().await;
    let (inviter, _) = RelayClient::new(&relay_url);
    let (joiner, _) = RelayClient::new(&relay_url);

    let token = "test-token";

    inviter.register_invite(token, u64::MAX).await.unwrap();
    joiner
        .post_join(token, b"key-package-bytes".to_vec())
        .await
        .unwrap();

    let join_data = inviter.get_join(token).await.unwrap();
    assert_eq!(join_data, b"key-package-bytes");

    inviter
        .post_accept(token, b"welcome-bytes".to_vec())
        .await
        .unwrap();

    let accept_data = joiner.get_accept(token).await.unwrap();
    assert_eq!(accept_data, b"welcome-bytes");
}
