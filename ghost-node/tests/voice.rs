//! Voice calls between headless devices: the core voice loop, the media session and
//! the audio engine the desktop app runs, through a real relay. Each device's
//! microphone plays its own tone, and what it plays back is recorded, so tests check
//! what each caller actually hears. Voice traffic passes through an impairment
//! forwarder, so the same calls run under loss, jitter and NAT rebinding.

mod support;

use std::time::Duration;

use ghost_audio::fake::tone_windows;
use ghost_core::session::ClientEvent;
use ghost_core::voice::VoiceEvent;
use ghost_core::wire::derive_default_channel_id;
use ghost_media::netem::{Forwarder, Impairment};
use ghost_relay::server::RunningRelay;
use support::*;

const ALICE_TONE: f32 = 440.0;
const BOB_TONE: f32 = 660.0;
const CAROL_TONE: f32 = 880.0;
/// A tone a caller switches to, to time how long the change takes to be heard.
const OTHER_TONE: f32 = 550.0;
const AMPLITUDE: f32 = 0.3;
/// Mouth to ear on a clean network: a capture frame, two frames of playout, devices.
const CLEAN_MOUTH_TO_EAR: Duration = Duration::from_millis(100);
/// A 20 ms window carries a tone when the tone holds at least this share of its energy.
const TONE_SHARE: f32 = 0.5;
/// How long to wait for audio to start flowing once a call is up.
const AUDIO_WAIT: Duration = Duration::from_secs(10);
/// How long each measurement listens.
const LISTEN: Duration = Duration::from_secs(2);

/// Alice and Bob in a call in their server's general channel, each microphone playing
/// its own tone.
struct Call {
    forwarder: Forwarder,
    _relay: RunningRelay,
    alice: Peer,
    bob: Peer,
}

fn participants_include(fingerprint: [u8; 32]) -> impl Fn(&ClientEvent) -> Option<()> {
    move |e| match e {
        ClientEvent::Voice(VoiceEvent::Participants(everyone)) if everyone.contains(&fingerprint) => Some(()),
        _ => None,
    }
}

async fn call() -> Call {
    let forwarder = Forwarder::bind(7).await.unwrap();
    let relay = start_relay_behind(&forwarder).await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let server = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server).await;
    let general = derive_default_channel_id(&server);
    alice.device.tone.set_tone(ALICE_TONE, AMPLITUDE);
    bob.device.tone.set_tone(BOB_TONE, AMPLITUDE);

    let (alice_mark, bob_mark) = (alice.device.mark(), bob.device.mark());
    alice.device.voice().join(server, general, false, false).await.unwrap();
    bob.device.voice().join(server, general, false, false).await.unwrap();
    let (alice_fp, bob_fp) = (alice.device.fingerprint().await, bob.device.fingerprint().await);
    alice.expect(alice_mark, "bob in the call", participants_include(bob_fp)).await;
    bob.expect(bob_mark, "alice in the call", participants_include(alice_fp)).await;
    Call { forwarder, _relay: relay, alice, bob }
}

/// Share of the 20 ms windows `listener` played over the next `duration` that carried
/// `frequency`.
async fn hears(listener: &Peer, frequency: f32, duration: Duration) -> f32 {
    let start = listener.device.tone.recorded_len();
    tokio::time::sleep(duration).await;
    let recording = listener.device.tone.recording();
    let windows = tone_windows(&recording[start..], frequency, TONE_SHARE);
    windows.iter().filter(|carried| **carried).count() as f32 / windows.len().max(1) as f32
}

/// Wait until `listener` plays `frequency` steadily (a whole quarter second of it).
async fn wait_until_hears(listener: &Peer, frequency: f32, within: Duration) {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if hears(listener, frequency, Duration::from_millis(250)).await == 1.0 {
            return;
        }
    }
    panic!("{} never heard {frequency} Hz steadily", listener.name);
}

#[tokio::test(flavor = "multi_thread")]
async fn callers_hear_each_other_and_not_themselves() {
    let call = call().await;
    wait_until_hears(&call.bob, ALICE_TONE, AUDIO_WAIT).await;
    wait_until_hears(&call.alice, BOB_TONE, AUDIO_WAIT).await;

    let (bob_hears_alice, alice_hears_bob) = tokio::join!(hears(&call.bob, ALICE_TONE, LISTEN), hears(&call.alice, BOB_TONE, LISTEN));
    assert!(bob_hears_alice > 0.95, "bob heard alice in {bob_hears_alice} of the time");
    assert!(alice_hears_bob > 0.95, "alice heard bob in {alice_hears_bob} of the time");
    let alice_hears_herself = hears(&call.alice, ALICE_TONE, LISTEN).await;
    assert_eq!(alice_hears_herself, 0.0, "nobody hears their own voice back");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_clean_call_has_little_delay() {
    let call = call().await;
    wait_until_hears(&call.bob, ALICE_TONE, AUDIO_WAIT).await;
    let delay = mouth_to_ear(&call.alice, &call.bob, OTHER_TONE).await;
    assert!(delay <= CLEAN_MOUTH_TO_EAR, "mouth to ear took {delay:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn audio_holds_up_under_loss_and_jitter() {
    let call = call().await;
    wait_until_hears(&call.bob, ALICE_TONE, AUDIO_WAIT).await;
    call.forwarder.set_impairment(Impairment {
        loss: 0.1,
        delay: Duration::from_millis(20),
        jitter: Duration::from_millis(40),
    });
    // Give playout a few seconds to settle on the new conditions.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let heard = hears(&call.bob, ALICE_TONE, Duration::from_secs(4)).await;
    assert!(heard > 0.97, "with 10% loss and 0-40 ms jitter each way, bob heard alice in {heard} of the time");
    let pitch = played_frequency(&call.bob, Duration::from_secs(1)).await;
    assert!((pitch - ALICE_TONE).abs() / ALICE_TONE < 0.005, "delay changes moved alice's pitch to {pitch} Hz");
}

#[tokio::test(flavor = "multi_thread")]
async fn audio_rides_out_delay_spikes() {
    let call = call().await;
    wait_until_hears(&call.bob, ALICE_TONE, AUDIO_WAIT).await;
    let spikes = async {
        for _ in 0..4 {
            call.forwarder.spike(Duration::from_millis(200));
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    };
    let (heard, ()) = tokio::join!(hears(&call.bob, ALICE_TONE, Duration::from_secs(8)), spikes);
    assert!(heard > 0.95, "with a 200 ms spike every 2 s, bob heard alice in {heard} of the time");
}

#[tokio::test(flavor = "multi_thread")]
async fn audio_resumes_after_nat_rebinding() {
    let call = call().await;
    wait_until_hears(&call.bob, ALICE_TONE, AUDIO_WAIT).await;
    wait_until_hears(&call.alice, BOB_TONE, AUDIO_WAIT).await;

    // Both callers now reach the relay from new addresses, which only their next
    // periodic bind tells it about.
    call.forwarder.rebind_all();
    let within = ghost_media::constants::BIND_INTERVAL + Duration::from_secs(3);
    tokio::join!(wait_until_hears(&call.bob, ALICE_TONE, within), wait_until_hears(&call.alice, BOB_TONE, within));
}

#[tokio::test(flavor = "multi_thread")]
async fn muting_silences_a_caller_for_everyone() {
    let call = call().await;
    wait_until_hears(&call.bob, ALICE_TONE, AUDIO_WAIT).await;
    let alice_fp = call.alice.device.fingerprint().await;

    let mark = call.bob.device.mark();
    call.alice.device.voice().set_muted(true).await.unwrap();
    call.bob
        .expect(mark, "alice muted", move |e| {
            matches!(e, ClientEvent::Voice(VoiceEvent::MuteState { fingerprint, muted: true, .. }) if *fingerprint == alice_fp)
                .then_some(())
        })
        .await;
    // Let what was already buffered play out.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(hears(&call.bob, ALICE_TONE, LISTEN).await, 0.0, "bob still heard muted alice");

    call.alice.device.voice().set_muted(false).await.unwrap();
    wait_until_hears(&call.bob, ALICE_TONE, AUDIO_WAIT).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn leaving_ends_a_callers_audio_and_presence() {
    let call = call().await;
    wait_until_hears(&call.bob, ALICE_TONE, AUDIO_WAIT).await;
    let bob_fp = call.bob.device.fingerprint().await;

    let mark = call.bob.device.mark();
    call.alice.device.voice().leave().await.unwrap();
    call.bob
        .expect(mark, "alice gone from the call", move |e| match e {
            ClientEvent::Voice(VoiceEvent::Participants(everyone)) if everyone == &vec![bob_fp] => Some(()),
            _ => None,
        })
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(hears(&call.bob, ALICE_TONE, LISTEN).await, 0.0, "bob still heard alice after she left");
}


/// Mouth-to-ear delay: from `speaker` switching its tone to `to` until `listener`
/// first plays it.
async fn mouth_to_ear(speaker: &Peer, listener: &Peer, to: f32) -> Duration {
    let mark = listener.device.tone.recorded_len();
    speaker.device.tone.set_tone(to, AMPLITUDE);
    tokio::time::sleep(Duration::from_secs(1)).await;
    let recording = listener.device.tone.recording();
    let windows = tone_windows(&recording[mark..], to, TONE_SHARE);
    let first = windows.iter().position(|carried| *carried).unwrap_or(windows.len());
    Duration::from_millis(first as u64 * 20)
}

/// Frequency of what `listener` played over the next `duration`, from zero crossings.
async fn played_frequency(listener: &Peer, duration: Duration) -> f32 {
    let mark = listener.device.tone.recorded_len();
    tokio::time::sleep(duration).await;
    let recording = listener.device.tone.recording();
    let samples = &recording[mark..];
    let crossings: Vec<usize> = (1..samples.len()).filter(|&i| samples[i - 1] < 0.0 && samples[i] >= 0.0).collect();
    if crossings.len() < 2 {
        return 0.0;
    }
    (crossings.len() - 1) as f32 * 48_000.0 / (crossings[crossings.len() - 1] - crossings[0]) as f32
}


/// Alice, Bob and Carol in one call, joined in that order so the forwarder sees
/// Alice's address first.
async fn group_call() -> (Call, Peer) {
    let forwarder = Forwarder::bind(11).await.unwrap();
    let relay = start_relay_behind(&forwarder).await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let carol = Peer::new(&relay.url(), "carol").await;
    let server = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server).await;
    invite_into(&alice, &carol, &server).await;
    let general = derive_default_channel_id(&server);
    alice.device.tone.set_tone(ALICE_TONE, AMPLITUDE);
    carol.device.tone.set_tone(CAROL_TONE, AMPLITUDE);
    for peer in [&alice, &bob, &carol] {
        let mark = peer.device.mark();
        peer.device.voice().join(server, general, false, false).await.unwrap();
        peer.expect(mark, "its own place in the call", participants_include(peer.device.fingerprint().await)).await;
        // Let its binds reach the forwarder before the next caller's.
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    (Call { forwarder, _relay: relay, alice, bob }, carol)
}

/// Share of `listener`'s next `duration` of playback in which `frequency` holds at
/// least a quarter of the energy (two callers' tones share it).
async fn hears_in_mix(listener: &Peer, frequency: f32, duration: Duration) -> f32 {
    let start = listener.device.tone.recorded_len();
    tokio::time::sleep(duration).await;
    let recording = listener.device.tone.recording();
    let windows = tone_windows(&recording[start..], frequency, 0.25);
    windows.iter().filter(|carried| **carried).count() as f32 / windows.len().max(1) as f32
}

#[tokio::test(flavor = "multi_thread")]
async fn a_jittery_caller_does_not_disturb_a_clean_one() {
    let (call, carol) = group_call().await;
    let alice_address = call.forwarder.clients()[0];
    call.forwarder.set_client_impairment(
        alice_address,
        Impairment { loss: 0.1, delay: Duration::from_millis(20), jitter: Duration::from_millis(60) },
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    let (carol_heard, alice_heard) = tokio::join!(
        hears_in_mix(&call.bob, CAROL_TONE, Duration::from_secs(4)),
        hears_in_mix(&call.bob, ALICE_TONE, Duration::from_secs(4)),
    );
    assert!(carol_heard > 0.98, "bob heard clean carol in {carol_heard} of the time");
    assert!(alice_heard > 0.9, "bob heard jittery alice in {alice_heard} of the time");
    drop(carol);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_quick_push_to_talk_repress_is_not_clipped() {
    let call = call().await;
    call.alice.device.audio.set_input_mode(ghost_audio::InputMode::PushToTalk);
    call.alice.device.audio.set_ptt_active(true);
    wait_until_hears(&call.bob, ALICE_TONE, AUDIO_WAIT).await;

    call.alice.device.audio.set_ptt_active(false);
    tokio::time::sleep(Duration::from_millis(150)).await;
    let mark = call.bob.device.tone.recorded_len();
    call.alice.device.audio.set_ptt_active(true);
    tokio::time::sleep(Duration::from_millis(800)).await;
    let recording = call.bob.device.tone.recording();
    let windows = tone_windows(&recording[mark..], ALICE_TONE, TONE_SHARE);
    let onset = windows.iter().position(|carried| *carried).expect("bob never heard alice again");
    let onset = Duration::from_millis(onset as u64 * 20);
    assert!(onset <= CLEAN_MOUTH_TO_EAR + Duration::from_millis(40), "alice's speech came back after {onset:?}");
    let after = &windows[onset.as_millis() as usize / 20..];
    assert!(after.iter().all(|carried| *carried), "alice's speech broke up after the re-press");
}
