#!/usr/bin/env bash
# Runs the browser end-to-end tests against a real gateway and a throwaway Postgres.
#
# Needs: Docker, a built web app (`just web-app`), and Playwright's Chromium
# (`cd e2e && npm install && npx playwright install chromium`).
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$(pwd)
PG=yap-e2e-pg
PORT=${E2E_PORT:-18090}
WORK=$(mktemp -d)
MAIL="$WORK/mail.jsonl"
GATEWAY_PID=""

cleanup() {
  [ -n "$GATEWAY_PID" ] && kill "$GATEWAY_PID" 2>/dev/null || true
  docker rm -f "$PG" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

[ -f app/build/web/index.html ] || { echo "build the web app first: just web-app" >&2; exit 1; }

docker rm -f "$PG" >/dev/null 2>&1 || true
docker run -d --rm --name "$PG" -e POSTGRES_PASSWORD=e2e -e POSTGRES_DB=yape2e \
  -p 127.0.0.1:54330:5432 --tmpfs /var/lib/postgresql/data postgres:17-alpine >/dev/null
until docker exec "$PG" pg_isready -U postgres -d yape2e >/dev/null 2>&1; do sleep 1; done

cargo build -p yap-server
# The server's domain must equal the host the browser uses: OPAQUE binds it into the login.
DATABASE_URL=postgres://postgres:e2e@127.0.0.1:54330/yape2e \
YAP_BIND=127.0.0.1:$PORT \
YAP_DOMAIN=127.0.0.1 \
YAP_SERVER_SECRET=$(openssl rand -base64 48) \
YAP_DEV_MAIL_FILE="$MAIL" \
YAP_WEB_DIR="$ROOT/app/build/web" \
RUST_LOG=warn \
  ./target/debug/yap-server >"$WORK/gateway.log" 2>&1 &
GATEWAY_PID=$!
until curl -fs "http://127.0.0.1:$PORT/healthz" >/dev/null; do sleep 0.5; done

cd e2e
set +e
E2E_URL="http://127.0.0.1:$PORT" E2E_MAIL_FILE="$MAIL" npx playwright test "$@"
STATUS=$?
if [ $STATUS -ne 0 ]; then echo "--- gateway log ---"; cat "$WORK/gateway.log"; fi
exit $STATUS
