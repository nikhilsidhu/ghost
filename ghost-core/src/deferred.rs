//! Holding back private channel blobs whose commit was authorized at a server group
//! epoch this device has not reached. Mailboxes arrive independently, so a channel's
//! commit can overtake the server group commit that granted the access it relies on.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::client::GhostClient;
use crate::relay::IncomingBlob;

struct Waiting {
    server_mailbox: [u8; 32],
    epoch: u64,
    blobs: VecDeque<IncomingBlob>,
    since: Instant,
}

/// Blobs held per mailbox. Once a mailbox waits, its later blobs queue behind the
/// held one, so each mailbox is still processed in order.
#[derive(Default)]
pub struct DeferredBlobs {
    waiting: HashMap<[u8; 32], Waiting>,
}

impl DeferredBlobs {
    pub fn is_waiting(&self, mailbox_id: &[u8; 32]) -> bool {
        self.waiting.contains_key(mailbox_id)
    }

    /// Hold `blob` until the server group reaches `epoch`.
    pub fn hold(&mut self, blob: IncomingBlob, server_mailbox: [u8; 32], epoch: u64) {
        let waiting = self.waiting.entry(blob.mailbox_id).or_insert_with(|| Waiting {
            server_mailbox,
            epoch,
            blobs: VecDeque::new(),
            since: Instant::now(),
        });
        waiting.blobs.push_back(blob);
    }

    /// Mailboxes held for longer than `threshold`.
    pub fn held_longer_than(&self, threshold: Duration) -> Vec<[u8; 32]> {
        self.waiting.iter().filter(|(_, w)| w.since.elapsed() > threshold).map(|(mailbox_id, _)| *mailbox_id).collect()
    }

    /// Drop what is held for a mailbox this device no longer reads.
    pub fn forget(&mut self, mailbox_id: &[u8; 32]) {
        self.waiting.remove(mailbox_id);
    }

    /// Queue a blob behind those already held for its mailbox.
    pub fn queue(&mut self, blob: IncomingBlob) {
        if let Some(waiting) = self.waiting.get_mut(&blob.mailbox_id) {
            waiting.blobs.push_back(blob);
        }
    }

    /// Release, in order, every mailbox's blobs whose server group epoch the client has
    /// now reached. The caller processes them again; one that is still too early is
    /// held anew.
    pub fn take_ready(&mut self, client: &GhostClient) -> Vec<IncomingBlob> {
        let ready: Vec<[u8; 32]> = self
            .waiting
            .iter()
            .filter(|(_, w)| client.server_epoch_reached(&w.server_mailbox, w.epoch))
            .map(|(mailbox_id, _)| *mailbox_id)
            .collect();
        ready
            .into_iter()
            .filter_map(|mailbox_id| self.waiting.remove(&mailbox_id))
            .flat_map(|w| w.blobs)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(mailbox_id: [u8; 32], seq: u64) -> IncomingBlob {
        IncomingBlob { mailbox_id, relay_url: "http://relay".into(), seq, received_at: 0, payload: Vec::new() }
    }

    #[test]
    fn a_hold_is_reported_by_how_long_it_has_lasted_and_gone_once_forgotten() {
        let mut deferred = DeferredBlobs::default();
        let (channel, other) = ([1; 32], [2; 32]);
        deferred.hold(blob(channel, 4), [9; 32], 3);
        deferred.queue(blob(channel, 5));
        assert_eq!(deferred.held_longer_than(Duration::ZERO), vec![channel]);
        assert!(deferred.held_longer_than(Duration::from_secs(3600)).is_empty());
        assert!(!deferred.is_waiting(&other));

        deferred.forget(&channel);
        assert!(deferred.held_longer_than(Duration::ZERO).is_empty());
    }
}
