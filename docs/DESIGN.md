# Yappitron v1 design

Yappitron is a self-hosted, end-to-end encrypted messenger that replaces IMO HD. One Flutter codebase covers web, Windows, macOS, Linux, Android and iOS. A Rust backend runs in Docker and can scale across servers.

## Goals

- **End-to-end encryption is mandatory.** The server only ever sees ciphertext.
- **Live typing.** The recipient sees a draft as it is typed (200 ms batching).
- **No metadata logs.** Nothing identifying is logged or persisted beyond what delivery requires.
- **One codebase**, plus a browser client that needs no download.
- **Scalable.** Stateless gateways; add servers without redesign.

## v1 scope

| In v1 | Later |
|---|---|
| Sign up with email, password and username; email verification | Files and images |
| Password reset by email | Read receipts, online status |
| 1:1 text chat, E2EE, found by exact username | Push notifications |
| Message requests (strangers can't message until accepted) | Groups, calls |
| Live typing, per-chat toggle | Disappearing messages |
| Multi-device, history kept forever | 2FA (TOTP), sealed sender |
| Emoji and non-Latin text on the web (fonts served from our own server) | |
| Web, desktop, Android, iOS builds | CI, reproducible web builds |

## Repository layout

```
crates/yap-proto    wire envelopes and versioning
crates/yap-core     client brain: MLS, keys, OPAQUE client, typing frames (sans-IO; native + WASM)
crates/yap-server   gateway: axum, WebSocket, auth, sqlx, migrations
app/                Flutter app (all platforms)
deploy/home         Docker Compose for the home server
deploy/vps          HAProxy + WireGuard for the VPS
docs/               design, protocol, threat model
```

## Accounts and authentication

- **Username**: 3-24 chars, `a-z 0-9 _`, case-insensitive, reserved-name list. Public; it is how people find you.
- **Email**: verified once at signup with a code. The server stores only an HMAC of the address, never the address itself.
- **Password**: OPAQUE (RFC 9807). The server never sees the password. Clients enforce 10+ characters and a local zxcvbn check (no breach-API calls to third parties).
- **Password reset**: enter email, the server HMACs it to find the account and sends a code, then the user re-registers a new OPAQUE record. Encryption keys are untouched.
- **Abuse limits**: rate limits per username and per IP, kept in RAM only. A self-hosted proof-of-work challenge at signup instead of a third-party CAPTCHA.
- **Password != decryption.** The password proves identity. Decryption depends on devices and a **recovery key** shown once at signup. A phished password alone cannot read messages: a new device must be approved by an existing device or the recovery key.
- **Lost everything**: the user can sign in but must reset their encryption identity; contacts see a "keys changed" warning.

## Encryption and history

- **MLS (OpenMLS)** in `yap-core`. A 1:1 chat is a two-member group, so groups later need no migration. Each device is its own group member.
- **History**: MLS forward secrecy stops a new device reading old messages. So each device re-encrypts every message it reads under an account-wide archive key and uploads it; a newly approved device downloads and decrypts the archive. The MLS delivery log can be pruned once all devices acknowledge.
- **Live typing**: frames use a key derived from the MLS exporter for the current epoch, with AEAD. Each frame is a full snapshot of the draft, padded to size buckets (256/512/1024/2048 bytes). Frames are relayed from RAM and never stored.
- **Fallback**: if OpenMLS cannot be made to work on WASM or the bridge, use pairwise Double Ratchet (vodozemac) for 1:1 and add MLS when groups arrive.

## Server

Rust: axum, tokio, sqlx, Postgres, tracing, lettre.

| Table | Holds |
|---|---|
| `accounts` | id, username, email HMAC, OPAQUE record, verified flag |
| `devices` | id, account, public keys, session hash, status (pending/approved/revoked) |
| `key_packages` | per-device MLS key packages |
| `contacts` | request and accept state |
| `conversations`, `members` | MLS group id, members |
| `messages` | conversation, sequence number, ciphertext. No sender, no timestamp |
| `cursors` | last acknowledged sequence number per device |
| `archive` | per-account encrypted history |

The server must know the contact graph and sequence numbers. A `Bus` trait is in-process now and becomes NATS when a second node appears.

## Deployment

- `yap.leafyserver.tech` is an A record to the VPS with the Cloudflare proxy **off** (DNS only).
- VPS: HAProxy in TCP/SNI passthrough (logs off) forwards over WireGuard to the home server.
- Home server (Docker Compose): Caddy terminates TLS (Cloudflare DNS-01), serves the web app, logs off; gateway; Postgres.
- Email through an SMTP relay (Resend). Cloudflare Email Routing for abuse@ and postmaster@.
- Backups: nightly `pg_dump` encrypted with `age`; back up `YAP_SERVER_SECRET` separately.

## Multiple devices (as built)

- A device's status is `pending`, `approved` or `revoked`; the account's first device is
  approved automatically and creates the **history key** and the **recovery key**.
- A new device shows a code and waits. An approved device compares the code, adds the new device
  to every conversation (one commit + Welcome each, retried if another member committed first)
  and seals the history key to it.
- Every device uploads what it reads to a per-account **archive**, sealed under the history key,
  so a device added later can show the messages MLS can no longer decrypt.
- Messages from your other devices are recognised as yours because MLS authenticates the sender.
- The **recovery key** (shown once) lets a person who lost every device read their history again;
  that device becomes the only device and starts new chats (old ones are read-only). See
  `docs/THREAT_MODEL.md` for the trust model and limits.

## Milestones

| | Milestone |
|---|---|
| M0 | Spike: OpenMLS and opaque-ke on native + WASM. Go/no-go, with the vodozemac fallback. **Done:** MLS (including the live-typing key) and OPAQUE pass the same tests natively and inside WASM. The bridge is a byte-level API (see `docs/CORE_API.md`): a C ABI for native and wasm-bindgen for the web, instead of flutter_rust_bridge |
| M1 | Server skeleton, signup/login/reset with OPAQUE + email verification, real network path. **Server half done** (see `docs/API.md`); the real VPS path and client screens remain |
| M2 | Message requests, 1:1 messaging, stored log, offline catch-up. **Done** end to end (server, core, Flutter UI). Verified with 16 server integration tests and a two-browser end-to-end test |
| M3 | Live typing. **Done**: drafts batch every 200 ms and appear live in the other browser; verified end to end |
| M4 | Multi-device approval, history archive, recovery key, identity reset. **Done**: approval with a fingerprint check, adding the device to every conversation, history via the archive, recovery key, device removal. Not done: removing a revoked device from encryption groups |
| M5 | Platform builds, backups, hardening, no-log audit |

## Testing

Local until CI exists (`just test`): Rust integration tests against a real Postgres; native/WASM test vectors; Playwright with two browsers; a no-log audit script.
