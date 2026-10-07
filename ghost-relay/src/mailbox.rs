use tokio::sync::{broadcast, watch};

pub struct Mailbox {
    pub seq_tx: watch::Sender<u64>,
    /// Ephemeral voice state broadcasts (not persisted in relay log)
    pub voice_tx: broadcast::Sender<(u64, String)>,
    /// Ephemeral online presence broadcasts
    pub presence_tx: broadcast::Sender<(u64, String)>,
    /// Accounts a private channel of this (server) mailbox now admits; each account's
    /// connections pass the news on as `WS_SIGNAL_CHANNELS`.
    pub channels_tx: broadcast::Sender<[u8; 32]>,
}

impl Mailbox {
    pub fn new() -> Self {
        let (seq_tx, _) = watch::channel(0u64);
        let (voice_tx, _) = broadcast::channel(16);
        let (presence_tx, _) = broadcast::channel(32);
        let (channels_tx, _) = broadcast::channel(32);
        Self { seq_tx, voice_tx, presence_tx, channels_tx }
    }
}
