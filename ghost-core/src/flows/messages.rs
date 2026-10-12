//! Sending chat messages. A message is stored as pending first, so it shows at once and
//! survives a restart, then handed to the mailbox's connection, where it counts as sent
//! until the relay answers: an acknowledgement marks it delivered; a dropped connection
//! or a refusal for an epoch the group has left makes it pending again, to be sealed
//! afresh and sent when the connection or the epoch comes back. The desktop app and
//! headless devices send through here alike.

use tokio::sync::oneshot;

use crate::error::{GhostError, Result};
use crate::relay::SendOutcome;
use crate::storage::StoredMessage;

use super::{channels, now_millis, SharedClient};
use crate::relay::RelayClient;

/// Where a message stands once the relay answered or its connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Landed {
    /// The relay stored it, at `seq` of the mailbox.
    Delivered { seq: u64 },
    /// The connection ended before the relay answered: the message is pending and goes
    /// out when the mailbox connects again.
    Queued,
}

/// A message on its way: as stored, and the relay's answer once it comes.
pub struct Sent {
    pub message: StoredMessage,
    pub outcome: oneshot::Receiver<SendOutcome>,
}

/// Store and send a text message in a channel.
pub async fn send_text(
    client: &SharedClient,
    relay: &RelayClient,
    server_id: &[u8; 32],
    channel_id: &[u8; 32],
    content: Vec<u8>,
) -> Result<Sent> {
    // A private channel must be rid of members who lost access before anything is sent.
    channels::remove_excluded(client, relay, channel_id).await?;
    let (outbound, message_id) = {
        let mut c = client.lock().await;
        c.send_message(server_id, channel_id, content, Vec::new(), now_millis())?
    };
    let message = client.lock().await.store().get_message(&message_id)?;
    let outcome = hand_over(client, relay, &outbound.mailbox_id, outbound.blob, message_id).await;
    Ok(Sent { message, outcome })
}

/// Seal a pending message again at the group's current epoch and hand it over, through
/// the same gate as a first send: members a private channel no longer admits are removed
/// first, and a message to a server the account is out of fails with `RemovedFromServer`.
pub async fn resend(client: &SharedClient, relay: &RelayClient, message_id: [u8; 32]) -> Result<oneshot::Receiver<SendOutcome>> {
    let channel_id = client.lock().await.store().get_message(&message_id)?.channel_id;
    channels::remove_excluded(client, relay, &channel_id).await?;
    let outbound = client.lock().await.reseal_message(&message_id)?;
    Ok(hand_over(client, relay, &outbound.mailbox_id, outbound.blob, message_id).await)
}

/// Queue the blob on the mailbox's connection, marking the message sent. Without a
/// connection it is lost for now; the message stays pending and goes out when the
/// mailbox connects.
async fn hand_over(client: &SharedClient, relay: &RelayClient, mailbox_id: &[u8; 32], blob: Vec<u8>, message_id: [u8; 32]) -> oneshot::Receiver<SendOutcome> {
    match relay.send_message(mailbox_id, blob, message_id) {
        Ok(outcome) => {
            if let Err(e) = client.lock().await.store().mark_sent(&message_id) {
                tracing::error!("message {} not marked sent: {e}", ghost_wire::short_id(&message_id));
            }
            outcome
        }
        Err(_) => {
            let (reply, outcome) = oneshot::channel();
            let _ = reply.send(SendOutcome::Lost);
            outcome
        }
    }
}

/// Wait for the relay's answer, for a caller that must know where the message stands: a
/// refusal is the error, and a message whose connection ended unanswered is queued.
pub async fn delivered(outcome: oneshot::Receiver<SendOutcome>) -> Result<Landed> {
    let outcome = outcome.await;
    tracing::debug!("message outcome: {outcome:?}");
    match outcome {
        Ok(SendOutcome::Delivered { seq }) => Ok(Landed::Delivered { seq }),
        Ok(SendOutcome::Refused { status, message }) => {
            Err(GhostError::RelayStatus { status, context: "send message".into(), message })
        }
        Ok(SendOutcome::Lost) | Err(_) => Ok(Landed::Queued),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn landed(outcome: SendOutcome) -> Result<Landed> {
        let (reply, receiver) = oneshot::channel();
        reply.send(outcome).unwrap();
        delivered(receiver).await
    }

    #[tokio::test]
    async fn a_waiting_caller_tells_delivered_from_queued_from_refused() {
        assert_eq!(landed(SendOutcome::Delivered { seq: 7 }).await.unwrap(), Landed::Delivered { seq: 7 });
        assert_eq!(landed(SendOutcome::Lost).await.unwrap(), Landed::Queued);
        let refused = landed(SendOutcome::Refused { status: 403, message: "removed".into() }).await;
        assert!(matches!(refused, Err(GhostError::RelayStatus { status: 403, .. })));
        let (reply, receiver) = oneshot::channel::<SendOutcome>();
        drop(reply);
        assert_eq!(delivered(receiver).await.unwrap(), Landed::Queued, "no answer at all leaves it queued");
    }
}
