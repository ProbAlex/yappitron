# Account API (v1, milestone M1)

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

## Other

- `GET /api/v1/me` -> `{username}` (needs a session)
- `GET /healthz` -> `ok`

## What the server stores

Per account: id, username, an HMAC of the email, and the OPAQUE record. No plaintext email, no
IP address, no creation or login timestamps. See [THREAT_MODEL.md](THREAT_MODEL.md).
