# Yappitron

A self-hosted, end-to-end encrypted messenger with **live typing**: see what the other person is typing as they type it. Built to replace IMO HD.

- One Flutter codebase: web, Windows, macOS, Linux, Android, iOS
- Rust backend in Docker, designed to scale across servers
- End-to-end encryption (MLS), OPAQUE password login, no metadata logs

> **Status: early development.** M0 (crypto spike) and the server half of M1 (accounts) are done; there is no client UI yet. Not audited. Do not use for high-risk communication.

See [docs/DESIGN.md](docs/DESIGN.md) for the design, [docs/API.md](docs/API.md) for the account API, and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what the server can and cannot see.

## Layout

```
crates/yap-proto    wire envelopes
crates/yap-core     client core: MLS, OPAQUE client, typing frames (native + WASM)
crates/yap-server   gateway server
app/                Flutter app
deploy/             Docker Compose (home) and HAProxy/WireGuard (VPS)
docs/               design and threat model
```

## Development

Requires Rust (stable) with the `wasm32-unknown-unknown` target, and [just](https://github.com/casey/just).

```sh
just test         # unit + core tests (server integration tests skip without a database)
just test-server  # server integration tests against a throwaway Postgres (needs Docker)
just lint         # fmt + clippy
just wasm-test    # run the core's MLS + OPAQUE tests inside WASM (needs wasm-bindgen-cli)
```

Copy `.env.example` to `.env` for local config. Never commit `.env`.

## License

[AGPL-3.0-or-later](LICENSE)
