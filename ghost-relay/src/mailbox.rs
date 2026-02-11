use tokio::sync::broadcast;
use uuid::Uuid;

const CHANNEL_CAPACITY: usize = 256;

#[derive(Clone)]
pub struct BlobNotification {
    pub blob_id: Uuid,
    pub received_at: u64,
    pub payload: Vec<u8>,
}

pub struct Blob {
    pub id: Uuid,
    pub received_at: u64,
    pub payload: Vec<u8>,
}

pub struct Mailbox {
    pub blobs: Vec<Blob>,
    pub tx: broadcast::Sender<BlobNotification>,
}

impl Mailbox {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self {
            blobs: Vec::new(),
            tx,
        }
    }
}
