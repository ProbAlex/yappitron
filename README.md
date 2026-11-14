# Yappitron

A self-hosted, end-to-end encrypted messenger with **live typing**: see what the other person is typing as they type it. Built to replace IMO HD.

- One Flutter codebase: web, Windows, macOS, Linux, Android, iOS
- Rust backend in Docker, designed to scale across servers
- End-to-end encryption (MLS), OPAQUE password login, no metadata logs

> **Status: early development.** The crypto core, accounts, the messaging server and the Flutter app (web and Linux desktop verified) work end to end, including live typing and multiple devices per account, and are covered by automated tests. Mobile and other desktop builds are not verified yet. This is pre-release software. Not audited. Do not use for high-risk communication.

See [docs/DESIGN.md](docs/DESIGN.md) for the design, [docs/API.md](docs/API.md) for the server API, [docs/CORE_API.md](docs/CORE_API.md) for the client crypto boundary, and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what the server can and cannot see.

## Layout

```
crates/yap-proto    wire envelopes
crates/yap-core     client core: MLS, OPAQUE client, typing frames (native + WASM)
crates/yap-ffi      C ABI over the core (native Flutter platforms)
crates/yap-wasm     wasm-bindgen binding over the core (browser)
crates/yap-server   gateway server
app/                Flutter app (UI, API client, local storage)
e2e/                browser end-to-end tests (Playwright)
deploy/             Docker Compose (home) and HAProxy/WireGuard (VPS)
docs/               design and threat model
```

## Development

Requires Rust (stable) with the `wasm32-unknown-unknown` target, the Flutter SDK, Docker, and
[just](https://github.com/casey/just) (optional: the recipes are plain commands).

```sh
just test         # Rust unit + core tests (server integration tests skip without a database)
just test-server  # server integration tests against a throwaway Postgres (needs Docker)
just app-test     # Dart tests: the real Rust core called over FFI
just wasm-test    # run the core's MLS + OPAQUE tests inside WASM (needs wasm-bindgen-cli)
just web-app      # build the Rust core to WASM and the Flutter web app
just e2e          # two real browsers chat through a real gateway (after `just web-app`)
just lint         # fmt + clippy
```

Quickest way to try it: `just web-app && scripts/dev.sh start`, then open http://127.0.0.1:18095
(or point the Linux app at it). Verification codes are written to a file instead of emailed:
`scripts/dev.sh code`.

To run the pieces yourself, run Postgres and the gateway (`cargo run -p yap-server`) with the variables
from `.env.example`. For local development set `YAP_DEV_MAIL_FILE` (emails, including the
verification code, are appended to that file instead of being sent) and `YAP_WEB_DIR=app/build/web`
(the gateway then also serves the web app). `YAP_DOMAIN` must equal the hostname you browse to,
because OPAQUE binds it into the login.

Desktop (Linux verified): `cd app && flutter build linux --release` builds the Rust core as part
of the app and bundles it. Web: `just web-app`, then serve `app/build/web` (the gateway does it
with `YAP_WEB_DIR`). Other platforms need their native build integration; see "Status".

Copy `.env.example` to `.env` for local config. Never commit `.env`.

## License

[AGPL-3.0-or-later](LICENSE)
