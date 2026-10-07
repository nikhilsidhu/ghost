//! The local cache of members' avatars: fetched sealed from the relay, opened with
//! the key the member announced, and kept as `<fingerprint>.webp` with the hash of
//! the version beside it.

use std::path::{Path, PathBuf};

use crate::flows::{SharedClient, SharedRelay};

/// Directory under the data directory that holds cached avatars.
pub const AVATARS_DIR: &str = "avatars";

fn avatar_paths(data_dir: &Path, fingerprint: &[u8; 32]) -> (PathBuf, PathBuf) {
    let dir = data_dir.join(AVATARS_DIR);
    let fp_hex = hex::encode(fingerprint);
    (dir.join(format!("{fp_hex}.webp")), dir.join(format!("{fp_hex}.hash")))
}

/// Fetch, open and cache a member's avatar unless this version is already cached.
/// Returns whether the cache changed.
pub(super) async fn fetch_if_missing(
    client: &SharedClient,
    relay: &SharedRelay,
    data_dir: &Path,
    server_id: &[u8; 32],
    fingerprint: &[u8; 32],
    avatar_hash: &[u8; 32],
) -> bool {
    let (image_path, hash_path) = avatar_paths(data_dir, fingerprint);
    if std::fs::read(&hash_path).is_ok_and(|stored| stored == avatar_hash.as_slice()) {
        return false;
    }
    let fp_hex = hex::encode(fingerprint);

    let (avatar_key, mailbox_id) = {
        let c = client.lock().await;
        (c.store().get_member_avatar_key(server_id, fingerprint).ok().flatten(), c.mailbox_id_for_server(server_id))
    };
    let Some(avatar_key) = avatar_key else {
        eprintln!("avatar: no key for {fp_hex}, skipping fetch");
        return false;
    };
    let Some(mailbox_id) = mailbox_id else {
        eprintln!("avatar: no mailbox for server {}, skipping fetch for {fp_hex}", hex::encode(server_id));
        return false;
    };

    let sealed = match relay.lock().await.get_avatar(&mailbox_id, fingerprint).await {
        Ok(Some(data)) => data,
        Ok(None) => {
            eprintln!("avatar: relay returned no blob for {fp_hex}");
            return false;
        }
        Err(e) => {
            eprintln!("avatar: fetch failed for {fp_hex}: {e}");
            return false;
        }
    };
    let image = match crate::crypto::aead::open(&avatar_key, &sealed, "avatar") {
        Ok(image) => image,
        Err(e) => {
            eprintln!("avatar: {fp_hex}: {e}");
            return false;
        }
    };

    if let Some(dir) = image_path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&image_path, &image);
    let _ = std::fs::write(&hash_path, avatar_hash);
    true
}

/// Remove a member's cached avatar.
pub(super) fn clear(data_dir: &Path, fingerprint: &[u8; 32]) {
    let (image_path, hash_path) = avatar_paths(data_dir, fingerprint);
    let _ = std::fs::remove_file(image_path);
    let _ = std::fs::remove_file(hash_path);
}
