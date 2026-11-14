# Photos, videos, files and link previews

Everything here keeps the rule of the whole project: **the server must not be able to read
what people send.** Two mechanisms: encrypted attachments, and sender-built link previews.

## Attachments

1. The sender's app encrypts each file on the device under a fresh random 32-byte key
   (`yap_core::blob`, ChaCha20-Poly1305 in 64 KiB chunks, STREAM-style nonces, so a file cannot
   be truncated, reordered or extended without detection).
2. It uploads only the ciphertext: `PUT /api/v1/conversations/{id}/blobs`. The server stores it
   under a random id and returns that id.
3. The message, which is MLS-encrypted like any other, carries `{id, key, name, type, size,
   width, height}`. Only the two people in the chat (and their devices) get the key.
4. The recipient downloads `GET /api/v1/blobs/{id}`, decrypts with the key from the message, and
   shows it. A changed or corrupted file fails to open instead of being displayed.

The message payload becomes `{"v":2, "ts", "body", "att":[...], "pv":[...]}`; v1 messages (text
only) keep working, and unknown fields are ignored.

**What the server can see:** that a file of N bytes exists, which conversation it belongs to,
and which account uploaded it. **What it cannot see:** the content, the file name, the type, the
dimensions, or any timestamp (none is stored).

**History and new devices.** Attachment details (including the key) are part of the message
record, so they flow into the encrypted history archive like text does: a device added later can
open files sent before it existed, as long as the file is still on the server.

**Storage.** Files live on disk under `YAP_BLOB_DIR` (production: a dataset on the NAS), not in
Postgres. The database holds a small row per file (conversation, uploader, size).

**Limits** (server-enforced, configurable): 100 MB per file (`YAP_MAX_BLOB_MB`), 20 GB per
account (`YAP_BLOB_QUOTA_GB`), 120 uploads per 10 minutes per account. Until the other person
accepts a message request, the sender may upload at most 5 files; nothing can be uploaded to a
declined conversation. Only joined members can upload, members can download, and only the
uploader can delete. An unknown file and a file you may not see give the same answer.

**Display.** Photos show inline (up to 10 MB load automatically; larger ones wait for a tap).
Other files, including videos, show as a tile and are saved to the device on tap. Inline video
playback is not built yet.

## Links

- Links in messages are tappable (http and https only; links containing credentials are
  ignored). Tapping shows the real destination and asks before opening.
- **Link previews** (the card with title, summary and picture) are **off by default**. The server
  cannot read messages, so it cannot find links itself. When the sender turns the setting on, the
  sender's app asks the gateway to fetch the page (`POST /api/v1/link-preview`), builds the card,
  and sends it inside the encrypted message. The card's picture is uploaded as an encrypted
  attachment, so the recipient loads it from our server.

  What this costs: **the server sees the address being previewed** (not who it goes to, and it
  stores and logs nothing). What it buys: the recipient never contacts the website, so the site
  cannot learn their address or that they read the message. The app explains this before the
  setting can be turned on. The server side can be disabled with `YAP_LINK_PREVIEWS=off`.
- **The fetcher is hardened against server-side request forgery**, since it fetches addresses
  chosen by strangers: only http/https on ports 80/443, no credentials, names resolved by our own
  resolver that drops every non-public address (private ranges, loopback, link-local, cloud
  metadata, carrier NAT, IPv6 unique-local, NAT64/6to4), IP literals checked directly (including
  decimal/hex/octal spellings), every redirect re-checked (3 at most), 6 s timeout, 512 KB page
  and 600 KB picture caps, HTML only, no SVG pictures, no cookies or credentials sent, 30
  previews per 10 minutes per account. Tests cover each of these, including that the real
  fetcher refuses a live server on localhost and the LAN address of the NAS.
- Preview text is displayed as text, never interpreted as markup.

## Not built yet

Inline video/audio playback, image thumbnails in the message (large photos load in full),
streaming upload/download for very large files (the file format already supports it), drag and
drop and paste, voice messages, caption editing, deleting a sent file from the chat, cleanup of
files whose message failed to send after a crash, and deleting files when an account is removed.
