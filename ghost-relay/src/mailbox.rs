use tokio::sync::watch;

pub struct Mailbox {
    pub seq_tx: watch::Sender<u64>,
}

impl Mailbox {
    pub fn new() -> Self {
        let (seq_tx, _) = watch::channel(0u64);
        Self { seq_tx }
    }
}
