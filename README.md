# Ghost

A self-hosted, end-to-end encrypted alternative to Discord. Groups with text and voice
channels, direct messages, and multi-device support, built so the server never sees
plaintext.

> **Status: alpha.** The protocol and implementation are unfinished and have not been
> audited. Do not use this for anything that matters. See [Limitations](#limitations).

## What it is

Ghost is a chat system in the shape of Discord — you join a group, it has text and voice
channels, you talk to people — with the difference that the relay handling your traffic
cannot read it. Message content is encrypted client-side with MLS group keys; the relay
stores opaque blobs for text and forwards opaque packets for voice.

There are no accounts. An identity is an Ed25519 keypair generated on your device, and the
only thing worth backing up is its 32-byte seed. A single client can join groups hosted on
different relays.

### Design principles

- **No accounts.** Identity is a keypair, not a row in someone's user table.
- **No permanent server state.** Text blobs expire after 72 hours. Voice packets are never
  written to disk.
- **Forward secrecy.** Compromising current keys does not reveal past messages.
- **Self-hosted.** The relay is a single binary with no external dependencies.

## Architecture

| Crate | What it does |
|---|---|
| `ghost-core` | Client library: identity, MLS group state, storage, relay client, voice |
| `ghost-relay` | The server: HTTP + WebSocket API (Axum), blob mailboxes, UDP voice SFU |
| `ghost-wire` | Wire protocol: framing, device authentication, Merkle-tree key transparency |
| `ghost-app` | Desktop client: Tauri shell around a SolidJS interface |

Group membership and message keys are managed by [MLS](https://www.rfc-editor.org/rfc/rfc9420)
(via [OpenMLS](https://openmls.tech/)), with one MLS group per channel. Client state lives
in SQLCipher-encrypted SQLite. Voice runs over UDP through a selective forwarding unit that
copies encrypted frames between participants without decrypting them.

The full protocol specification is in [`ghost-protocol/spec.md`](ghost-protocol/spec.md),
covering identity, mailbox derivation, message and blob formats, key exchange, the voice
protocol, the relay API, and security considerations.

## Cryptography

| Purpose | Algorithm | Reference |
|---|---|---|
| Signing | Ed25519 | RFC 8032 |
| Key agreement | X25519 | RFC 7748 |
| Group messaging | MLS (TreeKEM) | RFC 9420 |
| Voice frames | SFrame | RFC 9605 |
| Symmetric encryption | AES-256-GCM | NIST SP 800-38D |
| Hashing | BLAKE3 | https://blake3.io |
| Key derivation (seeds) | HKDF-SHA-256 | RFC 5869 |
| Key derivation (passphrases) | Argon2id | RFC 9106 |
| Device auth channel binding | TLS exporter | RFC 9266 |
| Audio codec | Opus | RFC 6716 |

## Running a relay

```bash
cargo run --release -p ghost-relay
```

Listens on `0.0.0.0:7700` for HTTP and WebSocket traffic and `0.0.0.0:10000/udp` for voice.
Without `GHOST_DB_PATH` it runs entirely in memory and loses state on restart.

| Variable | Default | Meaning |
|---|---|---|
| `GHOST_PORT` | `7700` | HTTP/WebSocket port |
| `GHOST_VOICE_PORT` | `10000` | UDP voice port |
| `GHOST_DB_PATH` | unset | Path to the relay database; in-memory if unset |
| `GHOST_MAX_BLOB_SIZE` | `10485760` | Largest accepted blob, in bytes |
| `GHOST_MAX_VOICE_PARTICIPANTS` | `25` | Per-channel voice cap |
| `GHOST_LOG_RETENTION_HOURS` | `72` | How long blobs are kept |

## Running the app

```bash
cd ghost-app
npm install
npm run tauri dev
```

## Development

To bring up a relay and several app instances against isolated data directories, which is
how group and multi-device behaviour is exercised locally:

```bash
./scripts/spawn-instances.sh 3
```

Tests, including relay integration and multi-device pairing:

```bash
cargo test --workspace
```

## Limitations

- The protocol spec is a draft and the implementation has drifted ahead of it in places.
- No third-party security review. The cryptography is assembled from well-regarded
  libraries, but assembly is where protocols usually break.
- Metadata is not fully protected. The relay learns mailbox identifiers, traffic timing,
  and message sizes even though it cannot read content.
- No mobile client.

## License

AGPL-3.0. See [LICENSE](LICENSE).
