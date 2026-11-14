#!/usr/bin/env bash
# One-command local stack for trying Yappitron on this machine.
#
#   scripts/dev.sh start   start Postgres (throwaway) + the gateway, serving the web app
#   scripts/dev.sh code    print the newest verification code (emails are NOT sent; see below)
#   scripts/dev.sh stop    stop and remove everything
#   scripts/dev.sh status
#
# Needs: Docker, a built web app (`just web-app`). Verification "emails" are appended to
# $WORK/mail.jsonl instead of being sent (YAP_DEV_MAIL_FILE, development only).
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$(pwd)
PORT=${PORT:-18095}
WORK=${WORK:-/tmp/yappitron-dev}
PG=yap-dev-pg
PGPORT=${PGPORT:-54331}
PIDFILE="$WORK/gateway.pid"
MAIL="$WORK/mail.jsonl"
URL="http://127.0.0.1:$PORT"

running() { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

case "${1:-start}" in
  start)
    if running; then echo "already running at $URL"; exit 0; fi
    [ -f app/build/web/index.html ] || { echo "build the web app first: just web-app" >&2; exit 1; }
    mkdir -p "$WORK"; : > "$MAIL"
    docker rm -f "$PG" >/dev/null 2>&1 || true
    docker run -d --rm --name "$PG" -e POSTGRES_PASSWORD=dev -e POSTGRES_DB=yappitron \
      -p 127.0.0.1:"$PGPORT":5432 --tmpfs /var/lib/postgresql/data postgres:17-alpine >/dev/null
    until docker exec "$PG" pg_isready -U postgres -d yappitron >/dev/null 2>&1; do sleep 1; done
    cargo build -p yap-server
    # YAP_DOMAIN must equal the host you browse to: OPAQUE binds it into every login.
    DATABASE_URL=postgres://postgres:dev@127.0.0.1:"$PGPORT"/yappitron \
    YAP_BIND=127.0.0.1:"$PORT" YAP_DOMAIN=127.0.0.1 \
    YAP_SERVER_SECRET=$(openssl rand -base64 48) \
    YAP_DEV_MAIL_FILE="$MAIL" YAP_WEB_DIR="$ROOT/app/build/web" RUST_LOG=warn \
      setsid nohup ./target/debug/yap-server >"$WORK/gateway.log" 2>&1 < /dev/null &
    echo $! > "$PIDFILE"
    until curl -fs "$URL/healthz" >/dev/null 2>&1; do sleep 0.5; done
    echo "Yappitron is running:  $URL"
    echo "  web app:   open $URL in a browser"
    echo "  Linux app: point it at $URL (tap the server name under the login form)"
    echo "  codes:     scripts/dev.sh code   (nothing is emailed in this mode)"
    echo "  stop:      scripts/dev.sh stop"
    ;;
  code)
    [ -s "$MAIL" ] || { echo "no code yet: request one in the app first" >&2; exit 1; }
    tail -n 1 "$MAIL" | python3 -c 'import sys,json,re; m=json.loads(sys.stdin.read()); print(re.search(r"\d{6}", m["subject"]).group(0), " (for", m["to"] + ")")'
    ;;
  stop)
    if [ -f "$PIDFILE" ]; then kill "$(cat "$PIDFILE")" 2>/dev/null || true; rm -f "$PIDFILE"; fi
    docker rm -f "$PG" >/dev/null 2>&1 || true
    echo "stopped"
    ;;
  status)
    if running; then echo "running at $URL"; else echo "not running"; fi
    ;;
  *) echo "usage: $0 {start|code|stop|status}" >&2; exit 2 ;;
esac
