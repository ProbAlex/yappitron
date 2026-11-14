# Core API (client crypto boundary)

`yap-core` is the client's brain: MLS encryption, OPAQUE password exchange and live-typing
frames. It does no I/O. Every platform reaches it through one function, [`yap_core::api::call`],
so there is a single definition of the API:

- **Native** (Linux, Windows, macOS, Android, iOS): `crates/yap-ffi` exposes `yap_call` /
  `yap_free` over a C ABI; Dart calls them with `dart:ffi`.
- **Web**: `crates/yap-wasm` exposes `call` through wasm-bindgen; Dart calls it with
  `dart:js_interop`.

Why not flutter_rust_bridge? Its web support needs nightly Rust and cross-origin-isolation
headers. A byte-level API keeps the build on stable Rust, needs no codegen, and is small enough
to audit.

## Wire format

```
request  = method(u16 LE) | argc(u32 LE) | { len(u32 LE) | bytes }*
response = status(u8: 0 ok, 1 error) | count(u32 LE) | { len(u32 LE) | bytes }*
```

On error there is one item: a UTF-8 message. Integers inside arguments are little-endian.
Devices and in-progress OPAQUE exchanges live inside the core and are named by `u32` handles.

## Methods

| Id | Name | Arguments | Result |
|---|---|---|---|
| 1 | `DEVICE_NEW` | name | handle |
| 2 | `DEVICE_IMPORT` | blob, key32 | handle |
| 3 | `DEVICE_EXPORT` | handle, key32 | blob |
| 4 | `DEVICE_FREE` | handle | - |
| 5 | `KEY_PACKAGE` | handle | key package |
| 6 | `CONV_CREATE` | handle, group id | - |
| 7 | `CONV_ADD_MEMBERS` | handle, group id, key package... | commit, welcome |
| 8 | `CONV_JOIN` | handle, welcome | group id |
| 9 | `CONV_ENCRYPT` | handle, group id, plaintext | ciphertext |
| 10 | `CONV_DECRYPT` | handle, group id, ciphertext | plaintext, sender identity (`username/device-id`, authenticated by MLS); error `own message` for the sender's echo |
| 11 | `CONV_APPLY_COMMIT` | handle, group id, commit | - |
| 12 | `CONV_EPOCH` | handle, group id | u64 LE |
| 15 | `CONV_ADD_MEMBERS_STAGED` | handle, group id, key package... | commit, welcome (the commit is NOT applied yet) |
| 16 | `CONV_COMMIT_CONFIRM` | handle, group id | - (apply the staged commit) |
| 17 | `CONV_COMMIT_DISCARD` | handle, group id | - (drop it; the group is unchanged) |
| 18 | `KEY_PACKAGE_SIGNER` | key package | the signature public key it claims |
| 19 | `DEVICE_SIGNER` | handle | this device's signature public key |
| 13 | `TYPING_SEAL` | handle, group id, seq (u64 LE), text | frame |
| 14 | `TYPING_OPEN` | handle, group id, frame | seq (u64 LE), text |
| 20 | `AUTH_REGISTER_START` | password | state handle, request |
| 21 | `AUTH_REGISTER_FINISH` | state handle, password, username, server id, response | upload |
| 22 | `AUTH_LOGIN_START` | password | state handle, request |
| 23 | `AUTH_LOGIN_FINISH` | state handle, password, username, server id, response | finalization, session key |
| 30 | `USERNAME_CANONICALIZE` | text | canonical username |
| 42 | `LINK_KEYPAIR` | - | secret, public (X25519) |
| 43 | `LINK_SEAL` | recipient public key, plaintext | sealed (ephemeral X25519 + HKDF + ChaCha20-Poly1305) |
| 44 | `LINK_OPEN` | secret, sealed | plaintext |
| 45 | `FINGERPRINT` | signature public key, link public key | `A1B2-C3D4-E5F6-0718-293A` (80 bits) |
| 46 | `DERIVE_KEY` | secret, label | 32-byte key (HKDF-SHA256; unrelated per label) |

## Persistence

`DEVICE_EXPORT` returns the whole device (keys + all MLS state) sealed with ChaCha20-Poly1305
under a 32-byte key the platform keeps in its keystore. Call it after every state change and
store the blob; `DEVICE_IMPORT` restores it. Group ids are the server's conversation ids.

## Adding a device

`CONV_ADD_MEMBERS_STAGED` builds the commit and Welcome but leaves the group on its current
epoch, so a commit the server refuses (because someone else committed first) can be rolled back
with `CONV_COMMIT_DISCARD` instead of corrupting this device's state. Groups keep five past
epochs, so messages that were in flight when a device was added can still be read.

## Live typing frames

`TYPING_SEAL` derives a key from the MLS exporter secret of the current epoch, so no extra key
exchange is needed and the key changes whenever membership changes. Frames are full draft
snapshots (a lost frame is harmless), padded to 256/512/1024/2048-byte buckets, and
authenticated with the epoch and conversation id. Frames from a different epoch are rejected.
