# Local task runner (https://github.com/casey/just). CI will call these same tasks later.

default:
    @just --list

fmt:
    cargo fmt --all

lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace

# Make sure the shared core still compiles for the browser.
wasm-check:
    cargo check -p yap-core --target wasm32-unknown-unknown

# Run the core's tests inside WASM (Node). Needs wasm-bindgen-cli, see .cargo/config.toml.
wasm-test:
    cargo test -p yap-core --target wasm32-unknown-unknown --test wasm

# Start the home stack (gateway + postgres) from deploy/home.
up:
    docker compose -f deploy/home/compose.yml --env-file .env up -d --build

down:
    docker compose -f deploy/home/compose.yml --env-file .env down

# Fail if logs contain IPs or email addresses (no-log audit). Added in milestone M5.
