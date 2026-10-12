//! The media session of a call: the UDP path through the relay and its binds, frame
//! encryption, and the interface the codec crates plug into. It moves encoded frames;
//! what they encode, and the devices they come from, live in the track crates.

pub mod constants;
pub mod crypto;
#[cfg(feature = "devtools")]
pub mod load;
#[cfg(feature = "test-util")]
pub mod netem;
pub mod session;
pub mod track;

pub use session::{FrameSender, Inbound, MediaPath, MediaSession, ReceivedFrame, SessionConfig};
pub use track::{AudioTrack, TrackEvent, TrackIo, TrackQuality};

#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    #[error("frame crypto: {0}")]
    Crypto(String),
    #[error("media transport: {0}")]
    Transport(#[from] std::io::Error),
}
