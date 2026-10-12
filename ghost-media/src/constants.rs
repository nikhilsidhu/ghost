use std::time::Duration;

/// When the first binds go out after the session starts. They come quickly so a lost
/// one costs little audio.
pub const BIND_RETRY_DELAYS_MS: [u64; 4] = [0, 200, 600, 1500];

/// How often binds repeat afterwards, keeping the binding current if our address
/// changes (new network, NAT rebinding).
pub const BIND_INTERVAL: Duration = Duration::from_secs(5);

/// An answer to a bind this recent shows media reaches the relay: binds go out every
/// `BIND_INTERVAL`, so two in a row unanswered, with slack for one late answer, mean it
/// does not.
pub const BIND_ANSWER_FRESH: Duration = Duration::from_secs(12);

/// How long after the binds start before a missing answer counts against the path: the
/// quick first binds are all out within two seconds.
pub const PATH_VERDICT_AFTER: Duration = Duration::from_secs(5);

/// Sealed frames waiting for the UDP socket; more are dropped, as late audio is useless.
pub const OUTBOUND_QUEUE: usize = 64;

/// Received frames waiting for the track.
pub const INBOUND_QUEUE: usize = 128;

/// Frames kept per sender whose key is not known yet (its presence arrives over the
/// WebSocket, which media can overtake): about a second of audio.
pub const UNKEYED_FRAME_LIMIT: usize = 50;
