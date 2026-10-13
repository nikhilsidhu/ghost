//! Where a call's audio comes from and goes. Devices deliver and take 48 kHz mono;
//! converting to and from what the hardware runs at is theirs to do.
//!
//! Playback runs on the device's real-time thread, which must never wait or touch the
//! allocator: it owns each sender's playout, and the audio thread reaches it only
//! through lock-free queues. Frames and senders go in; what playback is done with comes
//! back to be freed, and what it played comes back for the echo canceller.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ringbuf::traits::{Consumer, Producer, Split};
use ringbuf::{HeapCons, HeapProd, HeapRb};

use crate::constants::*;
use crate::receiver::{PeerStats, PlayoutStats, Receiver};
use crate::AudioControls;

/// A source of devices for calls.
pub trait AudioDevices: Send + Sync + 'static {
    /// Open capture and playback for a call. Runs on the engine's audio thread, which
    /// keeps the result until the call ends; playback pulls from `playback` at the pace
    /// of its own clock.
    fn open(&self, playback: Playback) -> Result<Box<dyn DeviceStreams>, String>;
}

/// The open devices of one call.
pub trait DeviceStreams {
    /// Wait up to `timeout` for the next frame of capture, `FRAME_SAMPLES` long.
    fn read_frame(&mut self, frame: &mut [f32], timeout: Duration) -> CaptureRead;
    /// The microphone capture comes from, by an id that stays the same across restarts:
    /// what its learned volume is kept under.
    fn input_id(&self) -> String;
}

pub enum CaptureRead {
    /// `frame` holds the next 20 ms.
    Frame,
    /// Nothing yet.
    Waiting,
    /// The devices were reopened (the default device changed); capture continues but
    /// is not continuous with what came before.
    Restarted,
    /// The chosen device is not available and another took its place, as the message
    /// says; capture continues, as after `Restarted`.
    Substituted(String),
    /// The devices are gone for good; the call's audio ends.
    Failed(String),
}

/// What the audio thread asks of playback, in order.
enum Command {
    /// A new sender's playout, made on the audio thread so playback never allocates.
    Join(u32, Box<Receiver>),
    Frame { slot_id: u32, sequence: u32, payload: Vec<u8>, arrived: Instant },
    /// The sender in this slot left.
    Leave(u32),
}

/// What playback is done with, for the audio thread to free.
#[allow(dead_code)] // Never read, only dropped.
enum Returned {
    Receiver(Box<Receiver>),
    Payload(Vec<u8>),
}

/// Playback's own state: each sender's playout and its ends of the queues.
struct PlayoutState {
    receivers: Vec<(u32, Box<Receiver>)>,
    commands: HeapCons<Command>,
    // A full queue means the audio thread stopped reading; what does not fit is freed
    // here, rarely and only then.
    returns: HeapProd<Returned>,
    render: HeapProd<f32>,
}

impl PlayoutState {
    fn apply_commands(&mut self) {
        while let Some(command) = self.commands.try_pop() {
            match command {
                Command::Join(slot_id, receiver) => match self.receivers.iter_mut().find(|(slot, _)| *slot == slot_id) {
                    Some((_, held)) => {
                        let replaced = std::mem::replace(held, receiver);
                        let _ = self.returns.try_push(Returned::Receiver(replaced));
                    }
                    None => self.receivers.push((slot_id, receiver)),
                },
                Command::Frame { slot_id, sequence, payload, arrived } => {
                    let unkept = match self.receivers.iter_mut().find(|(slot, _)| *slot == slot_id) {
                        Some((_, receiver)) => receiver.insert(sequence, payload, arrived),
                        None => Some(payload),
                    };
                    if let Some(payload) = unkept {
                        let _ = self.returns.try_push(Returned::Payload(payload));
                    }
                }
                Command::Leave(slot_id) => {
                    if let Some(at) = self.receivers.iter().position(|(slot, _)| *slot == slot_id) {
                        let (_, receiver) = self.receivers.swap_remove(at);
                        let _ = self.returns.try_push(Returned::Receiver(receiver));
                    }
                }
            }
        }
    }
}

struct Shared {
    /// Taken only by output callbacks, never by the audio thread, and only with
    /// `try_lock`: it is held elsewhere only while a reopened stream overlaps the one it
    /// replaces, and then a callback plays silence rather than wait.
    state: Mutex<PlayoutState>,
    controls: Arc<AudioControls>,
}

/// Mixed audio for playback: every sender's playout, summed. Clones share one playout,
/// so a reopened output stream picks up where the old one left off.
#[derive(Clone)]
pub struct Playback {
    shared: Arc<Shared>,
}

impl Playback {
    /// Playback, and the audio thread's link to it.
    pub(crate) fn new(controls: Arc<AudioControls>) -> (Self, PlayoutLink) {
        let (commands_tx, commands_rx) = HeapRb::new(PLAYOUT_COMMAND_QUEUE).split();
        let (returns_tx, returns_rx) = HeapRb::new(PLAYOUT_RETURN_QUEUE).split();
        let (render_tx, render_rx) = HeapRb::new(RENDER_QUEUE).split();
        let state = PlayoutState {
            receivers: Vec::with_capacity(PLAYOUT_SENDER_ROOM),
            commands: commands_rx,
            returns: returns_tx,
            render: render_tx,
        };
        let playback = Self { shared: Arc::new(Shared { state: Mutex::new(state), controls }) };
        let link = PlayoutLink { commands: commands_tx, returns: returns_rx, render: render_rx, backlog: VecDeque::new(), peers: HashMap::new() };
        (playback, link)
    }

    /// Fill `out` with the next stretch of mixed audio. The device's clock drives this;
    /// each sender's playout keeps its own delay. Deafened, playout runs on unheard so
    /// nothing piles up.
    pub fn fill(&self, out: &mut [f32]) {
        #[cfg(feature = "devtools")]
        let started = Instant::now();
        out.fill(0.0);
        let Ok(mut state) = self.shared.state.try_lock() else { return };
        state.apply_commands();
        let deafened = self.shared.controls.deafened.load(Ordering::Relaxed);
        let len = out.len();
        let PlayoutState { receivers, returns, render, .. } = &mut *state;
        for (_, receiver) in receivers.iter_mut() {
            while receiver.output.len() < len {
                receiver.produce();
            }
            for (mixed, sample) in out.iter_mut().zip(receiver.output.drain(..len)) {
                if !deafened {
                    *mixed += sample;
                }
            }
            for payload in receiver.spent.drain(..) {
                let _ = returns.try_push(Returned::Payload(payload));
            }
            receiver.publish();
        }
        for sample in out.iter_mut() {
            *sample = sample.clamp(-1.0, 1.0);
        }
        // The echo canceller learns from what actually plays. A full queue means the
        // audio thread stopped reading; the newest is dropped.
        render.push_slice(out);
        #[cfg(feature = "devtools")]
        self.shared.controls.figures.playback.record(started.elapsed(), Duration::from_secs_f64(len as f64 / SAMPLE_RATE as f64));
    }
}

/// A sender as the audio thread knows it: its playout figures, and what was read of
/// them last.
pub(crate) struct Peer {
    pub stats: Arc<PeerStats>,
    pub reported: PlayoutStats,
}

/// The audio thread's side of playback.
pub(crate) struct PlayoutLink {
    commands: HeapProd<Command>,
    returns: HeapCons<Returned>,
    render: HeapCons<f32>,
    /// Joins and leaves that found the queue full, sent before anything else: unlike a
    /// frame, losing one would leave playback wrong for the rest of the call.
    backlog: VecDeque<Command>,
    /// The senders playback has, by slot.
    pub peers: HashMap<u32, Peer>,
}

impl PlayoutLink {
    /// Send what waited for room, in order; false while the queue is still full.
    fn flush_backlog(&mut self) -> bool {
        while let Some(command) = self.backlog.pop_front() {
            if let Err(command) = self.commands.try_push(command) {
                self.backlog.push_front(command);
                return false;
            }
        }
        true
    }

    fn send_lasting(&mut self, command: Command) {
        if !self.flush_backlog() {
            self.backlog.push_back(command);
        } else if let Err(command) = self.commands.try_push(command) {
            self.backlog.push_back(command);
        }
    }

    /// Hand a frame to its sender's playout, starting one for a sender new to playback.
    pub fn frame(&mut self, slot_id: u32, sequence: u32, payload: Vec<u8>, arrived: Instant) {
        if !self.peers.contains_key(&slot_id) {
            let stats = Arc::new(PeerStats::default());
            match Receiver::new(stats.clone()) {
                Ok(receiver) => self.send_lasting(Command::Join(slot_id, Box::new(receiver))),
                Err(e) => {
                    tracing::warn!("voice: {e}");
                    return;
                }
            }
            self.peers.insert(slot_id, Peer { stats, reported: PlayoutStats::default() });
        }
        // Behind a backlog or a full queue the frame is dropped: playback is behind, and
        // late audio is worth nothing.
        if self.flush_backlog() {
            let _ = self.commands.try_push(Command::Frame { slot_id, sequence, payload, arrived });
        }
    }

    /// The sender in `slot_id` left: drop its playout.
    pub fn peer_left(&mut self, slot_id: u32) {
        if self.peers.remove(&slot_id).is_some() {
            self.send_lasting(Command::Leave(slot_id));
        }
    }

    /// Free what playback is done with, and send what waited for room.
    pub fn collect(&mut self) {
        while self.returns.try_pop().is_some() {}
        self.flush_backlog();
    }

    /// Pass what playback played since the last call to `sink`, in order.
    pub fn played(&mut self, mut sink: impl FnMut(&[f32])) {
        let mut chunk = [0.0f32; FRAME_SAMPLES];
        loop {
            let taken = self.render.pop_slice(&mut chunk);
            if taken == 0 {
                break;
            }
            sink(&chunk[..taken]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded_tone(count: usize) -> Vec<Vec<u8>> {
        let mut encoder = crate::codec::Encoder::voip().unwrap();
        let tone: Vec<f32> = (0..FRAME_SAMPLES).map(|i| (i as f32 * 0.05).sin() * 0.3).collect();
        (0..count).map(|_| encoder.encode_vec_float(&tone)).collect()
    }

    #[test]
    fn playback_plays_what_the_audio_thread_hands_it_and_gives_back_the_rest() {
        let (playback, mut link) = Playback::new(Arc::new(AudioControls::new()));
        let now = Instant::now();
        for (seq, frame) in encoded_tone(3).into_iter().enumerate() {
            link.frame(7, seq as u32, frame, now);
        }
        let mut out = vec![0.0f32; FRAME_SAMPLES];
        playback.fill(&mut out);
        assert!(out.iter().any(|s| s.abs() > 0.01), "the sender is heard");
        assert!(link.peers[&7].stats.playout().played >= 1);

        let mut played = Vec::new();
        link.played(|samples| played.extend_from_slice(samples));
        assert_eq!(played, out, "what played goes back for the echo canceller");

        link.peer_left(7);
        playback.fill(&mut out);
        assert!(link.returns.try_pop().is_some(), "the played frame comes back to be freed");
        link.collect();
        assert!(link.returns.try_pop().is_none());
    }

    #[test]
    fn playback_never_waits_on_a_held_playout() {
        let (playback, mut link) = Playback::new(Arc::new(AudioControls::new()));
        for (seq, frame) in encoded_tone(3).into_iter().enumerate() {
            link.frame(1, seq as u32, frame, Instant::now());
        }
        // Another callback (a reopened stream overlapping the old) holds the playout.
        let held = playback.shared.state.lock().unwrap();
        let mut out = vec![1.0f32; FRAME_SAMPLES];
        playback.fill(&mut out);
        assert!(out.iter().all(|s| *s == 0.0), "silence instead of waiting");
        drop(held);
        playback.fill(&mut out);
        assert!(out.iter().any(|s| s.abs() > 0.01));
    }

    #[test]
    fn joins_and_leaves_wait_out_a_full_queue() {
        let (playback, mut link) = Playback::new(Arc::new(AudioControls::new()));
        let frame = encoded_tone(1).remove(0);
        for seq in 0..PLAYOUT_COMMAND_QUEUE as u32 {
            link.frame(1, seq, frame.clone(), Instant::now());
        }
        // The queue is full: the new sender's join waits rather than being lost.
        link.frame(2, 0, frame.clone(), Instant::now());
        assert_eq!(link.backlog.len(), 1);
        let mut out = vec![0.0f32; FRAME_SAMPLES];
        playback.fill(&mut out);
        link.collect();
        assert!(link.backlog.is_empty());
        link.frame(2, 1, frame, Instant::now());
        playback.fill(&mut out);
        assert!(playback.shared.state.lock().unwrap().receivers.iter().any(|(slot, _)| *slot == 2));
    }
}
