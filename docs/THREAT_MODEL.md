# Threat model (v1, draft)

## The server cannot see

- Message content and live-typing content (end-to-end encrypted).
- Passwords (OPAQUE: the server never receives them).
- Email addresses (only a keyed hash is stored).
- Message timestamps and senders (stored log keeps conversation id, sequence number, ciphertext only).

## The server necessarily knows

- Usernames, and which accounts have accepted contact with each other.
- Which devices are connected at a given moment (held in RAM, never persisted).
- Message sizes and the order in which ciphertexts arrive.
- IP addresses of connecting clients, transiently. They are not logged.

## On the device

- **Keys and history** are sealed with ChaCha20-Poly1305 under a random key. On Linux, Windows,
  macOS, Android and iOS that key lives in the platform keystore. **On the web there is no
  hardware keystore**: the key sits in the browser's storage next to the data, which only
  protects against casual access to the disk, not against malicious scripts or someone using
  the unlocked browser.
- **Web fonts**: the web build bundles CanvasKit and a base font, and serves the fonts for emoji
  and every other script (728 small Noto files, fetched one slice at a time on demand) from our
  own server (`scripts/fetch-web-fonts.sh`), so the page never contacts a third party. The strict
  CSP blocks everything else, and the end-to-end tests assert no third-party request is made.
  Native apps use the system fonts.

## Multiple devices

- **Who can add a device.** Only an already-approved device of the same account can add a new
  one to a conversation (an MLS commit the server cannot forge). The server also cannot read the
  history key: it is sealed to the new device's link key by the approving device.
- **What the server could still try.** It could hand the approving device a *different* key
  package or link key than the new device really published. That is why both devices show the
  same short code (a hash of both keys) and the person must compare them. If they differ, nothing
  is approved. This protects against a malicious server, not against a person who approves
  without looking, or who approves a device they did not set up.
- **What an approved device can do.** Read everything, including history: approve only devices
  you control.
- **The history archive** holds every message ever read, sealed under the account's history key
  (the server cannot read it), kept forever. The server sees its size and sequence numbers.
- **The recovery key** unlocks history and signs out every other device. Whoever has it (plus
  the password) can take over the account's history, so it must be kept private. It is shown
  once and cannot be recovered. After a recovery, old chats are read-only on the new device.
- **Removing a device** signs it out and stops delivery, but it remains a member of existing
  encrypted chats until another member removes it (the app does not yet do that). Do not rely on
  removal to lock out a stolen device that someone holds together with network access to the
  encrypted traffic.
- **The server learns** how many devices an account has, their names, and when they were
  approved (not when: no timestamps are stored).

## Known limits

- **Web client**: the server delivers the JavaScript, so a compromised server could ship malicious code. Mitigations: strict CSP, self-hosted assets, published source.
- **Traffic analysis**: timing and size of live-typing frames can leak information. Frames are padded to size buckets; timing is batched at 200 ms.
- **Third parties**: the SMTP relay sees recipient addresses and send times of verification emails. Push services (v0.2) will see that a notification was sent, not its content.
- **No audit**: this code has not been independently reviewed.
