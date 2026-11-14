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

# Server integration tests against a throwaway Postgres container (needs Docker).
test-server:
    -docker rm -f yap-test-pg
    docker run -d --rm --name yap-test-pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=yaptest -p 127.0.0.1:54329:5432 --tmpfs /var/lib/postgresql/data postgres:17-alpine
    until docker exec yap-test-pg pg_isready -U postgres -d yaptest; do sleep 1; done
    TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:54329/yaptest cargo test -p yap-server
    docker rm -f yap-test-pg

# Make sure the shared core still compiles for the browser.
wasm-check:
    cargo check -p yap-core --target wasm32-unknown-unknown

# Run the core's tests inside WASM (Node). Needs wasm-bindgen-cli, see .cargo/config.toml.
wasm-test:
    cargo test -p yap-core --target wasm32-unknown-unknown --test wasm

# Compile the Rust core for the browser into app/web/yap_wasm (needs wasm-bindgen-cli).
web-core:
    cargo build -p yap-wasm --target wasm32-unknown-unknown --release
    wasm-bindgen --target web --no-typescript --out-dir app/web/yap_wasm target/wasm32-unknown-unknown/release/yap_wasm.wasm

# Build the web app. CanvasKit and fonts are bundled (nothing is fetched from a CDN) and the
# output satisfies the strict Content-Security-Policy.
web-app: web-core
    cd app && flutter build web --release --no-web-resources-cdn --csp

# Run Dart unit tests against the real core over FFI.
app-test:
    cargo build -p yap-ffi
    cd app && YAP_NATIVE_LIB=$(pwd)/../target/debug/libyap_ffi.so flutter test

# Browser end-to-end tests: two real browsers chat through a real gateway (needs `just web-app`).
e2e:
    e2e/run.sh

# Start the home stack (gateway + postgres) from deploy/home.
up:
    docker compose -f deploy/home/compose.yml --env-file .env up -d --build

down:
    docker compose -f deploy/home/compose.yml --env-file .env down

# Fail if logs contain IPs or email addresses (no-log audit). Added in milestone M5.
