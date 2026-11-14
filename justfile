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

# Start the home stack (gateway + postgres) from deploy/home.
up:
    docker compose -f deploy/home/compose.yml --env-file .env up -d --build

down:
    docker compose -f deploy/home/compose.yml --env-file .env down

# Fail if logs contain IPs or email addresses (no-log audit). Added in milestone M5.
