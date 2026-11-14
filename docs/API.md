# Server API (v1: accounts, devices, messaging)

JSON over HTTPS. Binary fields are base64url (no padding). Errors are `{"error": "<message>"}`.
Rate limits return `429`. Password flows use OPAQUE (RFC 9807); the password never leaves the
client. Clients must lowercase/validate the username (`yap_proto::username::canonicalize`)
**before** using it as the OPAQUE client identifier. The OPAQUE server identifier is the
service domain, and the context string is `yappitron-v1`.

## Signup (email, then username + password)

| Step | Request | Response |
|---|---|---|
| 1 | `POST /api/v1/signup/request-code` `{email}` | `202` always (no account enumeration) |
| 2 | `POST /api/v1/signup/verify-code` `{email, code}` | `{ticket}` (valid 30 min, single use) |
| 3 | `POST /api/v1/signup/start` `{ticket, username, request}` | `{response}` (409 if username taken) |
| 4 | `POST /api/v1/signup/finish` `{ticket, username, upload}` | `201` |

`request` is the OPAQUE registration request, `upload` the client's finish message.
Codes are 6 digits, valid 10 minutes, and lock after 5 wrong attempts.

## Login

| Step | Request | Response |
|---|---|---|
| 1 | `POST /api/v1/login/start` `{username, request}` | `{login_id, response}` |
| 2 | `POST /api/v1/login/finish` `{login_id, finalization}` | `{session_token}` or `401` |

An unknown username gets a normal-looking `response`; the client simply fails to finish, so a
wrong password and a missing account are indistinguishable. `login_id` is single use and valid
for 2 minutes. Send the token as `Authorization: Bearer <token>`; sessions last 30 days.

## Password reset

Same shape as signup using `/api/v1/reset/{request-code,verify-code,start,finish}` (no `username`
field; the account is found through the verified email). `finish` returns `204` and signs out
every existing session. Encryption keys are unaffected.

## Devices and key packages

Every installation is a **device** and its own MLS member. After login the client registers a
device (first run) or attaches to the one it already has (later logins). A device is `approved`
(reads and sends), `pending` (waiting to be approved) or `revoked`. The **first device of an
account is approved automatically**; every later one starts `pending` and must be approved by an
approved device (see "Multiple devices"). Chat endpoints need a session bound to an *approved*
device (`403` otherwise); a pending device may only manage its key packages, ask to be approved,
and read its own status.

| Request | Response |
|---|---|
| `POST /api/v1/devices` `{name}` | `201 {device_id, status}`; binds this session |
| `POST /api/v1/devices/attach` `{device_id}` | `{device_id, status}`; `403` if the device was removed |
| `PUT /api/v1/devices/me/key-packages` `{key_packages:[b64]}` | `204` (max 100 per call, 200 stored) |
| `GET /api/v1/devices/me/key-packages/count` | `{count}` |
| `POST /api/v1/users/{username}/key-packages` | `{username, devices:[{device_id, key_package}]}` |

The last call hands out one key package from each of that user's devices, **exactly once**
(never the caller's own device). Use your own username to get your other devices.

## Multiple devices

Approving a new device is done by one of the account's approved devices, and the server never
holds a key that decrypts anything:

1. The new device (pending) publishes an X25519 *link key*: `POST /devices/me/link-request`.
   Both devices show a short **fingerprint** (a hash of the new device's MLS signature key and
   its link key). The person confirms the two screens match, which defeats a server that swapped
   either key.
2. The approving device adds the new device to **every conversation** (`POST
   /conversations/{id}/devices`, an MLS commit only an existing member can create) and then
   `POST /devices/{id}/approve` with a **bundle**: the account's history key sealed to the link
   key.
3. The new device collects the bundle, opens it, joins its Welcomes and imports the history
   archive.

| Request | Response |
|---|---|
| `GET /api/v1/devices` | `{devices:[{id,name,status,current}]}` (not revoked) |
| `GET /api/v1/devices/me` | `{device_id, status}` (works while pending) |
| `POST /api/v1/devices/me/link-request` `{link_pub}` | `204` (pending only; tells approved devices) |
| `GET /api/v1/devices/pending` | `{pending:[{device_id,name,link_pub}]}` (approved only) |
| `POST /api/v1/devices/{id}/key-package` | `{key_package}`: one package of another device of the SAME account (pending or approved) |
| `POST /api/v1/devices/{id}/approve` `{bundle}` | `204`; the device becomes approved |
| `GET` / `DELETE /api/v1/devices/me/bundle` | the sealed bundle, picked up once |
| `POST /api/v1/devices/{id}/revoke` | `204`; signs the device out, deletes its keys, memberships and sessions. The last approved device cannot be removed (`409`) |
| `POST /api/v1/conversations/{id}/devices` `{commit, welcome, recipients, base_seq}` | `{seq}`. `409 "conversation changed"` if another commit landed after `base_seq` (catch up and retry); `409 "already a member"` |

Pending devices are never handed out to people starting conversations, and cannot be added to a
conversation by anyone but an approved device of their own account.

## History archive and recovery

MLS forward secrecy means a new device cannot decrypt old messages. So every device also seals
each message it reads under the account's **history key** (never sent to the server) and uploads
it; a new device downloads the entries and decrypts them with the key from its bundle.

| Request | Response |
|---|---|
| `PUT /api/v1/archive/{conversation}` `{entries:[{seq,data}]}` | `204`; per account, duplicates ignored, max 100 per call |
| `GET /api/v1/archive/{conversation}?after=&limit=` | `{entries:[{seq,data}]}` |
| `PUT /api/v1/account/keys` `{wrapped_hist_key, recovery_auth}` | `204`; the history key sealed under the **recovery key**, plus a token derived from it (only its hash is stored) |
| `GET /api/v1/account/keys` | `{wrapped_hist_key}` |
| `POST /api/v1/devices/me/recover` `{recovery_auth}` | `{wrapped_hist_key, revoked_devices}`. "I lost every device": makes THIS device the only approved device and signs out the rest. `403` for a wrong key; 5 tries per hour |

After a recovery the device is not a member of the account's existing encryption groups. Those
conversations stay readable (from the archive) but read-only; talking again means starting a new
conversation.

## Conversations and message requests

A conversation id is also the MLS group id (a UUID). To start one the creator takes key
packages (the other person's devices and their own other devices), builds the MLS group and a
single Welcome, and posts it. The other person sees a **message request** (`state: invited`).

| Request | Response |
|---|---|
| `POST /api/v1/conversations` `{id, member, welcome, recipients:[device_id]}` | `201` |
| `GET /api/v1/conversations` | `{conversations:[{id, state, last_seq, members:[{username,state}]}]}` |
| `POST /api/v1/conversations/{id}/accept` | `204` |
| `POST /api/v1/conversations/{id}/decline` | `204`; removes the request and its Welcomes |
| `POST /api/v1/conversations/{id}/messages` `{kind, data}` | `{seq}` (`kind`: 0 commit, 1 message) |
| `GET /api/v1/conversations/{id}/messages?after=&limit=` | `{messages:[{seq,kind,data}]}` |
| `POST /api/v1/conversations/{id}/ack` `{seq}` | `204` |
| `GET /api/v1/welcomes` | `{welcomes:[{id,conversation_id,join_seq,data}]}` |
| `DELETE /api/v1/welcomes/{id}` | `204` (after joining locally) |

- Until the other person accepts, the creator may send at most 5 messages, and live typing is
  not relayed. After a decline, posting is refused.
- The server assigns a gapless per-conversation sequence number and stores only
  `(conversation, seq, kind, ciphertext)`: **no sender and no timestamp**. Clients put the real
  time inside the encrypted payload. A sender does not receive its own message back; MLS also
  cannot decrypt a sender's own ciphertext, so the sender keeps the plaintext locally.

## WebSocket (`/ws`)

JSON text frames. The first frame must be `{"t":"auth","token":"<session token>"}` within 5
seconds, from a session bound to a device (a pending device may connect to hear that it was
approved; it receives no conversation data).

| Direction | Frame |
|---|---|
| client -> server | `{"t":"typing","c":conv,"f":b64}`, `{"t":"ack","c":conv,"seq":n}`, `{"t":"ping"}` |
| server -> client | `{"t":"ready"}`, `{"t":"synced"}`, `{"t":"link_request","device_id","name"}`, `{"t":"approved"}`, `{"t":"revoked"}`, `{"t":"devices_changed"}`, `{"t":"msg","c","seq","k","d"}`, `{"t":"welcome","id","c","join_seq","d"}`, `{"t":"member","c","u","s"}`, `{"t":"typing","c","f"}`, `{"t":"pong"}` |

After `ready` the server replays everything the device has not acknowledged (welcomes and log
entries), then sends `synced`; everything after that is live. The replay can include the
device's own messages (a sender's cursor is not advanced past messages it has not acknowledged);
the core reports those as `own message` and clients skip them. Clients de-duplicate by sequence number and, if they see a gap, refetch over REST.
**Typing frames** are opaque ciphertext relayed from RAM to the other joined members' live
connections: never stored, at most 20 per second per connection, at most 4 KB, and dropped for
non-members or while a request is pending.

## Attachments and link previews

See [MEDIA.md](MEDIA.md) for the design.

- `PUT /api/v1/conversations/{id}/blobs` (raw encrypted bytes, `Content-Length` honest or not;
  the server enforces the cap while reading) -> `{id, size}`. 404 if attachments are off,
  403 if not a joined member / declined / over the pre-acceptance limit, 413 if too large or the
  account's quota is reached, 429 if uploading too fast.
- `GET /api/v1/blobs/{id}` -> the encrypted bytes. 404 for an unknown file *and* for one you may
  not see.
- `DELETE /api/v1/blobs/{id}` -> 204; only the uploader.
- `POST /api/v1/link-preview` `{url}` -> `{url, title, description, site, image?: {mime, data}}`
  (`data` base64url). 400 with a plain reason if the page cannot be previewed; 404 if disabled.

## Other

- `GET /api/v1/me` -> `{username}` (needs a session)
- `GET /healthz` -> `ok`

## What the server stores

Per account: id, username, an HMAC of the email, and the OPAQUE record. Per device: a label and
its pending key packages. Per conversation: members and the encrypted log. Per attachment: a random id, its conversation, the uploading account and its size (the encrypted file itself is on disk). No plaintext email,
no IP address, no creation/login/message timestamps, no message sender. See [THREAT_MODEL.md](THREAT_MODEL.md).
