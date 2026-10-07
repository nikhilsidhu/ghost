# Testing Ghost

Each tier tests what the tiers below it cannot. A bug a higher tier finds should get a
test in the lowest tier that can reproduce it.

| Tier | Where | What only it catches | Run |
|---|---|---|---|
| Unit | `ghost-wire`, `ghost-core`, `ghost-relay` (`src/**`) | encoding, crypto, policy rules, storage | `cargo test -p <crate> --lib` |
| Protocol integration | `ghost-core/tests`, `ghost-relay/tests` | flows between clients and an in-process relay | `cargo test -p ghost-core -p ghost-relay` |
| Scenarios | `ghost-node/tests/scenarios.rs` | the client's real event loop (`ghost_core::session`, the loop the app runs): ordering, retries, recovery, private channels, kicks while offline | `cargo test -p ghost-node --test scenarios` |
| Processes | `ghost-node/tests/process.rs` | the shipped relay binary and headless devices as processes: start-up wiring, SIGKILL then restart on the same database and data directory | `cargo test -p ghost-node --test process` |
| Front end | `ghost-app/src/**/*.test.ts` | store and palette logic against Tauri's mocked IPC, and types generated from the Rust side | `cd ghost-app && npm test && npm run typecheck` |
| Manual | the checklist below | real audio hardware, OS permission prompts, reboots, upgrades, how it feels | before each release |

All automated tiers run in CI (`.github/workflows/ci.yml`) on Linux, macOS and Windows,
plus a check that `ghost-app/src/lib/generated/` matches the Rust types. Regenerate those
with `cargo test -p ghost-app bindings` after changing a DTO or event payload.

On Linux, the keyring tests need a Secret Service: run them inside
`dbus-run-session` with an unlocked GNOME Keyring, as CI does.

## Headless devices

`ghost-node` is a headless Ghost device for tests and debugging:

```
cargo run -p ghost-node -- --data-dir /tmp/node-a --relay http://127.0.0.1:7700 --create alice
```

It reads JSON commands on stdin (`{"id":1,"cmd":"create_server","name":"club"}`, `invite`,
`join`, `say`, `kick`) and writes replies and events as JSON lines. Its device key is a
plain file in the data directory: never use it for a real account.

## Release checklist

Run `./scripts/spawn-instances.sh 3` for a relay and three app instances with separate
data directories, then check what automation cannot:

**Voice and audio**
- [ ] Join voice from two instances; speech is clear both ways, mute and deafen work.
- [ ] Unplug and replug the headset mid-call; audio follows the default device.
- [ ] Push-to-talk with the configured key; voice activity with the sensitivity slider.
- [ ] Noise suppression and volume normalization toggles change what peers hear.

**Platforms**
- [ ] macOS: first voice join shows the microphone permission prompt, and voice works after granting it.
- [ ] macOS release build: the device key lands in the Keychain; restarting the app keeps the account.
- [ ] Linux release build: reboot the machine; the app opens the same account (Secret Service).
- [ ] Windows release build: the device key lands in Credential Manager; restarting keeps the account.

**Upgrades**
- [ ] Install the previous release, create a server with members and messages, upgrade: the server, members and history are intact and messaging continues.
- [ ] A server created before roles existed offers roles once every member has upgraded.

**Multi-device and recovery**
- [ ] Pair a second device; servers and settings appear on it.
- [ ] Recover the account on a fresh machine with the recovery code and passphrase.

**Feel**
- [ ] Join a server by invite link, create and use a private channel, and kick someone, watching for anything slow, confusing or broken.
