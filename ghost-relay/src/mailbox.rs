use tokio::sync::{broadcast, watch};

pub struct Mailbox {
    pub seq_tx: watch::Sender<u64>,
    /// Ephemeral voice state broadcasts (not persisted in relay log)
    pub voice_tx: broadcast::Sender<(u64, String)>,
    /// Ephemeral online presence broadcasts
    pub presence_tx: broadcast::Sender<(u64, String)>,
}

impl Mailbox {
    pub fn new() -> Self {
        let (seq_tx, _) = watch::channel(0u64);
        let (voice_tx, _) = broadcast::channel(16);
        let (presence_tx, _) = broadcast::channel(32);
        Self { seq_tx, voice_tx, presence_tx }
    }
}
