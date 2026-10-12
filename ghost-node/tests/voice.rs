//! Voice calls between headless devices: the core voice loop, the media session and
//! the audio engine the desktop app runs, through a real relay. Each device's
//! microphone plays its own tone, and what it plays back is recorded, so tests check
//! what each caller actually hears. Voice traffic passes through an impairment
//! forwarder, so the same calls run under loss, jitter and NAT rebinding.

mod support;

use std::time::Duration;

use ghost_audio::fake::tone_windows;
use ghost_core::session::ClientEvent;
use ghost_core::voice::{CallPhase, MediaPath, VoiceEvent};
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

/// Someone who joins the call after the group moved on hears those already in it: they
/// sealed their presence again and rotated their keys when the commit landed.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_joining_after_a_commit_hears_those_already_in_the_call() {
    let call = call().await;
    wait_until_hears(&call.alice, BOB_TONE, AUDIO_WAIT).await;
    let carol = Peer::new(&call._relay.url(), "carol").await;
    let server = call.alice.device.client.lock().await.store().list_servers().unwrap()[0].server_id;
    let before = epoch_of(&call.alice.device, &server).await;
    invite_into(&call.alice, &carol, &server).await;
    eventually(EVENT_WAIT, "the commit adding Carol at Bob's", async || epoch_of(&call.bob.device, &server).await > before).await;

    let mark = carol.device.mark();
    carol.device.voice().join(server, derive_default_channel_id(&server), false, false).await.unwrap();
    carol.expect(mark, "Alice in the call", participants_include(call.alice.device.fingerprint().await)).await;
    // Alice and Bob both play to Carol, so each tone holds about half of what she hears.
    let deadline = tokio::time::Instant::now() + AUDIO_WAIT;
    while hears_in_mix(&carol, ALICE_TONE, LISTEN).await < 0.9 {
        assert!(tokio::time::Instant::now() < deadline, "carol never heard alice, who was in the call before the commit");
    }
    // Those already in the call go on hearing each other across the change.
    wait_until_hears(&call.alice, BOB_TONE, AUDIO_WAIT).await;
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

// --- Calls that do not go to plan ---

/// Alice and Bob in a call through a relay a test can blip or take down, and Carol in
/// the server watching who is in the channel. The voice port itself is reached directly,
/// so media keeps flowing whatever happens to the relay's connections.
struct SwitchedCall {
    relay: ghost_relay::outage::SwitchedRelay,
    alice: Peer,
    bob: Peer,
    carol: Peer,
    server: [u8; 32],
    general: [u8; 32],
}

async fn switched_call() -> SwitchedCall {
    let relay = start_switched_relay().await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let carol = Peer::new(&relay.url(), "carol").await;
    let server = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server).await;
    invite_into(&alice, &carol, &server).await;
    let general = derive_default_channel_id(&server);
    alice.device.tone.set_tone(ALICE_TONE, AMPLITUDE);
    bob.device.tone.set_tone(BOB_TONE, AMPLITUDE);
    let (alice_fp, bob_fp) = (alice.device.fingerprint().await, bob.device.fingerprint().await);
    let (alice_mark, bob_mark, carol_mark) = (alice.device.mark(), bob.device.mark(), carol.device.mark());
    alice.device.voice().join(server, general, false, false).await.unwrap();
    bob.device.voice().join(server, general, false, false).await.unwrap();
    alice.expect(alice_mark, "bob in the call", participants_include(bob_fp)).await;
    bob.expect(bob_mark, "alice in the call", participants_include(alice_fp)).await;
    carol.expect(carol_mark, "both callers in the channel", channel_holds(general, vec![alice_fp, bob_fp])).await;
    wait_until_hears(&bob, ALICE_TONE, AUDIO_WAIT).await;
    SwitchedCall { relay, alice, bob, carol, server, general }
}

/// The voice channel's members, as an observer's roster reports them, once they are
/// exactly `who`.
fn channel_holds(channel: [u8; 32], mut who: Vec<[u8; 32]>) -> impl Fn(&ClientEvent) -> Option<()> {
    who.sort();
    move |e| match e {
        ClientEvent::VoiceChannelMembers { channel_id, members } if *channel_id == channel => {
            let mut there: Vec<[u8; 32]> = members.iter().map(|m| m.fingerprint).collect();
            there.sort();
            (there == who).then_some(())
        }
        _ => None,
    }
}

/// This device's call in `phase`.
fn call_phase(phase: CallPhase) -> impl Fn(&ClientEvent) -> Option<()> {
    move |e| match e {
        ClientEvent::Voice(VoiceEvent::State(state)) if state.phase == Some(phase) => Some(()),
        _ => None,
    }
}

/// This device's call over.
fn call_over(e: &ClientEvent) -> Option<()> {
    matches!(e, ClientEvent::Voice(VoiceEvent::State(state)) if !state.connected).then_some(())
}

/// A voice error saying `text`.
fn voice_error(text: &'static str) -> impl Fn(&ClientEvent) -> Option<()> {
    move |e| matches!(e, ClientEvent::Voice(VoiceEvent::Error(message)) if message.contains(text)).then_some(())
}

/// A signaling blip the relay does not notice: the call claims its slot back, nobody in
/// the room or the server sees it go, and the audio never stops.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_carries_on_through_a_signaling_blip() {
    let call = switched_call().await;
    let alice_fp = call.alice.device.fingerprint().await;
    let (alice_mark, bob_mark, carol_mark) = (call.alice.device.mark(), call.bob.device.mark(), call.carol.device.mark());

    call.relay.blip();
    call.alice.expect(alice_mark, "the call reconnecting", call_phase(CallPhase::Reconnecting)).await;
    call.alice.expect(alice_mark, "the call live again", call_phase(CallPhase::Live)).await;
    assert!(hears(&call.bob, ALICE_TONE, LISTEN).await > 0.9, "bob stopped hearing alice through the blip");

    // Long enough for the relay to drop the old mailbox connections and their grace to run out.
    tokio::time::sleep(Duration::from_secs(6)).await;
    let bob_lost_alice = call.bob.device.events_since(bob_mark).iter().any(|e| {
        matches!(e, ClientEvent::Voice(VoiceEvent::Participants(everyone)) if !everyone.contains(&alice_fp))
    });
    assert!(!bob_lost_alice, "bob saw alice leave the call during the blip");
    let carol_lost_alice = call.carol.device.events_since(carol_mark).iter().any(|e| {
        matches!(e, ClientEvent::VoiceChannelMembers { channel_id, members } if *channel_id == call.general && !members.iter().any(|m| m.fingerprint == alice_fp))
    });
    assert!(!carol_lost_alice, "carol saw alice leave the channel during the blip");
}

/// A relay that came back without the call's slot (it saw the connection end) has the
/// caller join afresh: media starts over on the new slot and is heard again.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_whose_slot_the_relay_ended_comes_back_on_a_new_one() {
    let call = switched_call().await;
    let alice_mark = call.alice.device.mark();

    call.relay.go_down();
    call.alice.expect(alice_mark, "the call reconnecting", call_phase(CallPhase::Reconnecting)).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    call.relay.come_back();
    call.alice.expect(alice_mark, "the call live again", call_phase(CallPhase::Live)).await;
    wait_until_hears(&call.bob, ALICE_TONE, AUDIO_WAIT).await;
    let _ = call.server;
}

/// A relay that stays away past the reconnect window ends the call, saying why.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_ends_with_the_reason_when_the_relay_stays_away() {
    let call = switched_call().await;
    let alice_mark = call.alice.device.mark();

    call.relay.go_down();
    call.alice.expect(alice_mark, "the call reconnecting", call_phase(CallPhase::Reconnecting)).await;
    let ended = call
        .alice
        .device
        .wait_for(alice_mark, Duration::from_secs(40), voice_error("Lost the connection to the voice server"))
        .await;
    assert!(ended.is_some(), "the call never ended: {:#?}", call.alice.device.events_since(alice_mark));
    call.alice.expect(alice_mark, "the call over", call_over).await;
}

/// A full room refuses the join, and the join ends with the relay's reason rather than
/// hanging as a call with no media.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_join_ends_with_the_relays_reason() {
    let relay = start_relay_with(ghost_relay::config::Config { max_voice_participants: 1, ..test_config() }).await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let bob = Peer::new(&relay.url(), "bob").await;
    let server = alice.device.create_server("club").await.unwrap();
    invite_into(&alice, &bob, &server).await;
    let general = derive_default_channel_id(&server);
    let alice_mark = alice.device.mark();
    alice.device.voice().join(server, general, false, false).await.unwrap();
    alice.expect(alice_mark, "alice in the call", call_phase(CallPhase::Live)).await;

    let bob_mark = bob.device.mark();
    bob.device.voice().join(server, general, false, false).await.unwrap();
    bob.expect(bob_mark, "the refusal", voice_error("Could not join: channel full")).await;
    bob.expect(bob_mark, "the join over", call_over).await;
}

/// Someone removed from the server mid-call hears why the call ended.
#[tokio::test(flavor = "multi_thread")]
async fn being_removed_from_the_server_ends_the_call_saying_why() {
    let call = switched_call().await;
    let bob_fp = call.bob.device.fingerprint().await;
    let bob_mark = call.bob.device.mark();
    call.alice.device.kick(&call.server, &bob_fp).await.unwrap();
    call.bob.expect(bob_mark, "the reason the call ended", voice_error("You were removed from this server")).await;
    call.bob.expect(bob_mark, "the call over", call_over).await;
}

/// The relay holds one device per account in a call: another of Alice's devices joining
/// takes her place, and her first device hears why its call ended.
#[tokio::test(flavor = "multi_thread")]
async fn another_device_of_the_account_takes_over_the_call() {
    let call = switched_call().await;
    let (alice_fp, bob_fp) = (call.alice.device.fingerprint().await, call.bob.device.fingerprint().await);
    let folder = tempfile::tempdir().unwrap();
    let mut laptop = call.alice.device.link_device(folder.path(), &call.relay.url(), "laptop").await.unwrap();
    laptop.start();
    let (phone_mark, carol_mark, laptop_mark) = (call.alice.device.mark(), call.carol.device.mark(), laptop.mark());

    laptop.voice().join(call.server, call.general, false, false).await.unwrap();
    let joined = laptop.wait_for(laptop_mark, EVENT_WAIT, participants_include(bob_fp)).await;
    assert!(joined.is_some(), "the laptop never got into the call: {:#?}", laptop.events_since(laptop_mark));
    call.alice.expect(phone_mark, "why the phone's call ended", voice_error("You joined this call from another device")).await;
    call.alice.expect(phone_mark, "the phone's call over", call_over).await;
    // Whatever the devices' order, Carol sees Alice once.
    call.carol.expect(carol_mark, "alice and bob in the channel", channel_holds(call.general, vec![alice_fp, bob_fp])).await;
}

/// Media that cannot reach the relay is reported, and the report clears once it can.
#[tokio::test(flavor = "multi_thread")]
async fn blocked_udp_is_reported_and_clears_once_media_gets_through() {
    let forwarder = Forwarder::bind(13).await.unwrap();
    forwarder.set_impairment(Impairment { loss: 1.0, ..Impairment::default() });
    let relay = start_relay_behind(&forwarder).await;
    let alice = Peer::new(&relay.url(), "alice").await;
    let server = alice.device.create_server("club").await.unwrap();
    let mark = alice.device.mark();
    alice.device.voice().join(server, derive_default_channel_id(&server), false, false).await.unwrap();
    let blocked = |e: &ClientEvent| {
        matches!(e, ClientEvent::Voice(VoiceEvent::State(state)) if state.media_path == Some(MediaPath::Blocked)).then_some(())
    };
    alice.expect(mark, "the media path blocked", blocked).await;
    alice.expect(mark, "the user told", voice_error("No voice traffic reaches the voice server")).await;

    let mark = alice.device.mark();
    forwarder.set_impairment(Impairment::default());
    let open = |e: &ClientEvent| matches!(e, ClientEvent::Voice(VoiceEvent::State(state)) if state.media_path == Some(MediaPath::Open)).then_some(());
    let opened = alice.device.wait_for(mark, ghost_media::constants::BIND_INTERVAL + Duration::from_secs(5), open).await;
    assert!(opened.is_some(), "the path never opened: {:#?}", alice.device.events_since(mark));
}

/// A microphone that fails for good ends the call with the reason, and the server stops
/// showing the caller in the channel, though no leave was asked for.
#[tokio::test(flavor = "multi_thread")]
async fn a_failing_microphone_ends_the_call_and_its_presence() {
    let call = switched_call().await;
    let bob_fp = call.bob.device.fingerprint().await;
    let (alice_mark, carol_mark) = (call.alice.device.mark(), call.carol.device.mark());
    call.alice.device.tone.fail("microphone unplugged");
    call.alice.expect(alice_mark, "the reason the call ended", voice_error("Voice audio stopped: microphone unplugged")).await;
    call.alice.expect(alice_mark, "the call over", call_over).await;
    call.carol.expect(carol_mark, "alice gone from the channel", channel_holds(call.general, vec![bob_fp])).await;
}

/// The server's mailbox connection closing (a close frame withdraws a device's presence at
/// once) while the call's own connection stays up: when the mailbox is back, the caller
/// says again where it is, and the server sees it in the channel.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_announces_again_when_the_servers_mailbox_comes_back() {
    let call = switched_call().await;
    let (alice_fp, bob_fp) = (call.alice.device.fingerprint().await, call.bob.device.fingerprint().await);
    let mailbox_id = call.alice.device.client.lock().await.mailbox_id_for_server(&call.server).unwrap();
    let carol_mark = call.carol.device.mark();

    call.alice.device.relay.unsubscribe(&mailbox_id);
    call.carol.expect(carol_mark, "alice gone from the channel", channel_holds(call.general, vec![bob_fp])).await;
    let last_seen = call.alice.device.client.lock().await.store().get_last_seen_seq(&mailbox_id).unwrap();
    let carol_mark = call.carol.device.mark();
    call.alice.device.relay.subscribe(mailbox_id, last_seen);
    call.carol.expect(carol_mark, "alice back in the channel", channel_holds(call.general, vec![alice_fp, bob_fp])).await;
}
