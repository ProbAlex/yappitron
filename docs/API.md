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
device (first run) or attaches to the one it already has (later logins); chat endpoints
require a session bound to a device (`403` otherwise).

| Request | Response |
|---|---|
| `POST /api/v1/devices` `{name}` | `201 {device_id}`; binds this session |
| `POST /api/v1/devices/attach` `{device_id}` | `204` (must be the account's own device) |
| `PUT /api/v1/devices/me/key-packages` `{key_packages:[b64]}` | `204` (max 100 per call, 200 stored) |
| `GET /api/v1/devices/me/key-packages/count` | `{count}` |
| `POST /api/v1/users/{username}/key-packages` | `{username, devices:[{device_id, key_package}]}` |

The last call hands out one key package from each of that user's devices, **exactly once**
(never the caller's own device). Use your own username to get your other devices.

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
seconds, from a session bound to a device.

| Direction | Frame |
|---|---|
| client -> server | `{"t":"typing","c":conv,"f":b64}`, `{"t":"ack","c":conv,"seq":n}`, `{"t":"ping"}` |
| server -> client | `{"t":"ready"}`, `{"t":"msg","c","seq","k","d"}`, `{"t":"welcome","id","c","join_seq","d"}`, `{"t":"member","c","u","s"}`, `{"t":"typing","c","f"}`, `{"t":"pong"}` |

After `ready` the server replays everything the device has not acknowledged (welcomes and log
entries). Clients de-duplicate by sequence number and, if they see a gap, refetch over REST.
**Typing frames** are opaque ciphertext relayed from RAM to the other joined members' live
connections: never stored, at most 20 per second per connection, at most 4 KB, and dropped for
non-members or while a request is pending.

## Other

- `GET /api/v1/me` -> `{username}` (needs a session)
- `GET /healthz` -> `ok`

## What the server stores

Per account: id, username, an HMAC of the email, and the OPAQUE record. Per device: a label and
its pending key packages. Per conversation: members and the encrypted log. No plaintext email,
no IP address, no creation/login/message timestamps, no message sender. See [THREAT_MODEL.md](THREAT_MODEL.md).
