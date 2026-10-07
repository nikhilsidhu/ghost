//! Frame encryption with SFrame (RFC 9605). Each sender has its own key per call, so
//! the frame counter alone keeps nonces unique. Codec-agnostic: any encoded frame.

use sframe::frame::{EncryptedFrameView, MediaFrameView, MonotonicCounter};
use sframe::key::{DecryptionKey, EncryptionKey};
use sframe::CipherSuite;

use crate::MediaError;

const CIPHER_SUITE: CipherSuite = CipherSuite::AesGcm256Sha512;

/// One key per sender, so the SFrame key id is constant.
const KEY_ID: u64 = 0;

/// Seals one sender's frames.
pub struct FrameSealer {
    key: EncryptionKey,
}

impl FrameSealer {
    pub fn new(key: &[u8; 32]) -> Result<Self, MediaError> {
        let key = EncryptionKey::derive_from(CIPHER_SUITE, KEY_ID, key)
            .map_err(|e| MediaError::Crypto(format!("key derive: {e}")))?;
        Ok(Self { key })
    }

    /// Seal `frame` under `counter`, which must never repeat for this key. The result
    /// is `[sframe header][ciphertext][tag]`; the header carries the counter.
    pub fn seal(&self, counter: u32, frame: &[u8]) -> Result<Vec<u8>, MediaError> {
        let mut counter = MonotonicCounter::with_start_value(counter as u64, u64::MAX);
        let media = MediaFrameView::try_new(&mut counter, frame)
            .map_err(|e| MediaError::Crypto(format!("counter: {e}")))?;
        let mut sealed = Vec::new();
        media
            .encrypt_into(&self.key, &mut sealed)
            .map_err(|e| MediaError::Crypto(format!("encrypt: {e}")))?;
        Ok(sealed)
    }
}

/// Opens one sender's frames.
pub struct FrameOpener {
    key: DecryptionKey,
}

impl FrameOpener {
    pub fn new(key: &[u8; 32]) -> Result<Self, MediaError> {
        let key = DecryptionKey::derive_from(CIPHER_SUITE, KEY_ID, key)
            .map_err(|e| MediaError::Crypto(format!("key derive: {e}")))?;
        Ok(Self { key })
    }

    /// Open a sealed frame that its packet labels `sequence`. The label is plaintext
    /// the relay could rewrite, so it must match the counter the frame was sealed under.
    pub fn open(&self, sequence: u32, sealed: &[u8]) -> Result<Vec<u8>, MediaError> {
        let frame = EncryptedFrameView::try_from(sealed)
            .map_err(|e| MediaError::Crypto(format!("parse: {e}")))?;
        if frame.header().counter() != sequence as u64 {
            return Err(MediaError::Crypto("packet sequence differs from the sealed counter".into()));
        }
        let mut opened = Vec::new();
        frame
            .decrypt_into(&self.key, &mut opened)
            .map_err(|e| MediaError::Crypto(format!("decrypt: {e}")))?;
        Ok(opened)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];

    #[test]
    fn frame_roundtrip() {
        let sealed = FrameSealer::new(&KEY).unwrap().seal(1, b"fake opus data here").unwrap();
        let opened = FrameOpener::new(&KEY).unwrap().open(1, &sealed).unwrap();
        assert_eq!(opened, b"fake opus data here");
    }

    #[test]
    fn tampered_sframe_header_fails() {
        let mut sealed = FrameSealer::new(&KEY).unwrap().seal(1, b"opus").unwrap();
        // The SFrame header is authenticated as associated data.
        sealed[0] ^= 0xFF;
        assert!(FrameOpener::new(&KEY).unwrap().open(1, &sealed).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = FrameSealer::new(&KEY).unwrap().seal(1, b"opus").unwrap();
        assert!(FrameOpener::new(&[0x43; 32]).unwrap().open(1, &sealed).is_err());
    }

    #[test]
    fn relabeled_sequence_fails() {
        let sealed = FrameSealer::new(&KEY).unwrap().seal(5, b"opus").unwrap();
        assert!(FrameOpener::new(&KEY).unwrap().open(6, &sealed).is_err());
    }
}
