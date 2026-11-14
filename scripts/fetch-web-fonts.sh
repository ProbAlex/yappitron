#!/usr/bin/env bash
# Mirror the fallback fonts Flutter's web engine can ask for (emoji, CJK, Arabic, Thai, ...)
# into the built web app, so the page never contacts Google's font servers.
#
#   scripts/fetch-web-fonts.sh [path/to/build/web]     (default: app/build/web)
#
# The list of files comes straight from the engine inside main.dart.js, so it always matches the
# Flutter version that built the app. Files are fetched once (re-runs skip what exists).
# The Noto fonts are licensed under the SIL Open Font License 1.1, which allows redistribution.
set -euo pipefail

cd "$(dirname "$0")/.."
WEB=${1:-app/build/web}
BASE=https://fonts.gstatic.com/s
JS="$WEB/main.dart.js"
OUT="$WEB/fonts/s"
[ -f "$JS" ] || { echo "build the web app first (missing $JS)" >&2; exit 1; }

LIST=$(mktemp)
trap 'rm -f "$LIST"' EXIT
grep -oE '[a-z0-9]+/v[0-9]+/[A-Za-z0-9_-]+(\.[0-9]+)?\.(woff2|ttf)' "$JS" | sort -u > "$LIST"
TOTAL=$(wc -l < "$LIST")
echo "engine knows $TOTAL fallback font files; fetching the ones not already in $OUT"

mkdir -p "$OUT"
export OUT BASE
fetch_one() {
  path=$1
  dest="$OUT/$path"
  [ -s "$dest" ] && return 0
  mkdir -p "$(dirname "$dest")"
  if curl -fsS --retry 3 --retry-delay 2 -o "$dest.part" "$BASE/$path"; then
    mv "$dest.part" "$dest"
  else
    rm -f "$dest.part"; echo "FAILED $path" >&2; return 1
  fi
}
export -f fetch_one
FAILED=0
xargs -a "$LIST" -P 8 -I{} bash -c 'fetch_one {}' || FAILED=1

cat > "$WEB/fonts/NOTICE.txt" <<'NOTICE'
The files under fonts/s/ are Noto fonts (Copyright The Noto Project Authors), served from this
site instead of Google's servers so visitors' browsers do not contact a third party.
They are licensed under the SIL Open Font License, Version 1.1: https://openfontlicense.org
NOTICE

HAVE=$(find "$OUT" -type f -name '*.woff2' | wc -l)
echo "mirrored $HAVE of $TOTAL files ($(du -sh "$OUT" | cut -f1))"
[ "$FAILED" = 0 ] || { echo "some files failed to download; the glyphs they cover will show as boxes" >&2; exit 1; }
