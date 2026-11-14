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
- **Web fonts**: the web build bundles its fonts and CanvasKit, and the strict CSP blocks
  everything else, so the page never contacts a third party (asserted by the end-to-end tests).
  The cost: text needing glyphs the bundled font lacks (some scripts, emoji) may render as boxes
  on the web until a fuller font is bundled. Native apps use system fonts.

## Known limits

- **Web client**: the server delivers the JavaScript, so a compromised server could ship malicious code. Mitigations: strict CSP, self-hosted assets, published source.
- **Traffic analysis**: timing and size of live-typing frames can leak information. Frames are padded to size buckets; timing is batched at 200 ms.
- **Third parties**: the SMTP relay sees recipient addresses and send times of verification emails. Push services (v0.2) will see that a notification was sent, not its content.
- **No audit**: this code has not been independently reviewed.
