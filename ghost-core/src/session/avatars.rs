//! The local cache of members' avatars: fetched sealed from the relay, opened with
//! the key the member announced, and kept as `<fingerprint>.avatar` (the image as the
//! member chose it) with the hash of the version beside it. This account's own avatar,
//! set here, is also kept sealed, so a relay that missed it gets the very bytes its hash
//! names.

use std::path::{Path, PathBuf};

use crate::flows::{SharedClient};
use crate::relay::RelayClient;

/// Directory under the data directory that holds cached avatars.
pub const AVATARS_DIR: &str = "avatars";

/// Where a member's avatar image is cached.
pub fn cache_path(data_dir: &Path, fingerprint: &[u8; 32]) -> PathBuf {
    data_dir.join(AVATARS_DIR).join(format!("{}.avatar", hex::encode(fingerprint)))
}

fn avatar_paths(data_dir: &Path, fingerprint: &[u8; 32]) -> (PathBuf, PathBuf) {
    (cache_path(data_dir, fingerprint), data_dir.join(AVATARS_DIR).join(format!("{}.hash", hex::encode(fingerprint))))
}

/// Keep an avatar image as the version `avatar_hash` names, so it is not fetched again.
pub fn cache(data_dir: &Path, fingerprint: &[u8; 32], image: &[u8], avatar_hash: &[u8; 32]) {
    let (image_path, hash_path) = avatar_paths(data_dir, fingerprint);
    if let Some(dir) = image_path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&image_path, image);
    let _ = std::fs::write(&hash_path, avatar_hash);
}

/// Fetch, open and cache a member's avatar unless this version is already cached.
/// Returns whether the cache changed.
pub(super) async fn fetch_if_missing(
    client: &SharedClient,
    relay: &RelayClient,
    data_dir: &Path,
    server_id: &[u8; 32],
    fingerprint: &[u8; 32],
    avatar_hash: &[u8; 32],
) -> bool {
    let (_, hash_path) = avatar_paths(data_dir, fingerprint);
    if std::fs::read(&hash_path).is_ok_and(|stored| stored == avatar_hash.as_slice()) {
        return false;
    }
    let fp_hex = hex::encode(fingerprint);

    let (avatar_key, mailbox_id) = {
        let c = client.lock().await;
        (c.store().get_member_avatar_key(server_id, fingerprint).ok().flatten(), c.mailbox_id_for_server(server_id))
    };
    let Some(avatar_key) = avatar_key else {
        tracing::debug!("avatar: no key for {fp_hex}, skipping fetch");
        return false;
    };
    let Some(mailbox_id) = mailbox_id else {
        tracing::debug!("avatar: no mailbox for server {}, skipping fetch for {fp_hex}", hex::encode(server_id));
        return false;
    };

    let sealed = match relay.get_avatar(&mailbox_id, fingerprint).await {
        Ok(Some(data)) => data,
        Ok(None) => {
            tracing::debug!("avatar: relay returned no blob for {fp_hex}");
            return false;
        }
        Err(e) => {
            tracing::warn!("avatar: fetch failed for {fp_hex}: {e}");
            return false;
        }
    };
    let image = match crate::crypto::aead::open(&avatar_key, &sealed, "avatar") {
        Ok(image) => image,
        Err(e) => {
            tracing::warn!("avatar: {fp_hex}: {e}");
            return false;
        }
    };

    cache(data_dir, fingerprint, &image, avatar_hash);
    true
}

fn own_sealed_path(data_dir: &Path) -> PathBuf {
    data_dir.join(AVATARS_DIR).join("own.sealed")
}

/// Keep the sealed avatar this device set, as the relays are to hold it.
pub fn keep_own_sealed(data_dir: &Path, sealed: &[u8]) -> std::io::Result<()> {
    let path = own_sealed_path(data_dir);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, sealed)
}

/// The sealed avatar this device set, if it still keeps one.
pub fn own_sealed(data_dir: &Path) -> Option<Vec<u8>> {
    std::fs::read(own_sealed_path(data_dir)).ok()
}

/// Forget the sealed avatar this device set: the account took it down.
pub fn forget_own_sealed(data_dir: &Path) {
    let _ = std::fs::remove_file(own_sealed_path(data_dir));
}

/// Remove a member's cached avatar.
pub fn clear(data_dir: &Path, fingerprint: &[u8; 32]) {
    let (image_path, hash_path) = avatar_paths(data_dir, fingerprint);
    let _ = std::fs::remove_file(image_path);
    let _ = std::fs::remove_file(hash_path);
}
