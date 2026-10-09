#!/usr/bin/env bash
# Stage Directory Keep and, optionally, start the lab console.
# This does not join a domain and does not download Tomcat unless asked.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="stage"
PORT="${ADHK_PORT:-8765}"

for arg in "$@"; do
  case "$arg" in
    --run) MODE="run" ;;
    --with-tomcat) MODE="tomcat" ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/pip" install --upgrade pip
"$ROOT/.venv/bin/pip" install -r "$ROOT/requirements.txt"
(
  cd "$ROOT"
  "$ROOT/.venv/bin/python" - <<PY
from ad_housekeeping.web import stage_bundle
print(stage_bundle())
PY
)

echo "Staged Tomcat context: $ROOT/dist/tomcat/webapps/ad-housekeeping"
echo "Python console will listen on http://127.0.0.1:${PORT}"

if [[ "$MODE" == "tomcat" ]]; then
  VERSION="10.1.60"
  CACHE="$ROOT/dist/cache"
  mkdir -p "$CACHE"
  ZIP="apache-tomcat-${VERSION}.tar.gz"
  URL="https://downloads.apache.org/tomcat/tomcat-10/v${VERSION}/bin/${ZIP}"
  SUM_URL="${URL}.sha512"
  curl -fsSL "$URL" -o "$CACHE/$ZIP"
  curl -fsSL "$SUM_URL" -o "$CACHE/${ZIP}.sha512"
  (
    cd "$CACHE"
    # Apache publishes "hash *filename". sha512sum -c accepts that form.
    sha512sum -c "${ZIP}.sha512"
  )
  mkdir -p "$ROOT/dist/apache-tomcat"
  tar -xzf "$CACHE/$ZIP" -C "$ROOT/dist/apache-tomcat" --strip-components=1
  rm -rf "$ROOT/dist/apache-tomcat/webapps/ad-housekeeping"
  cp -a "$ROOT/dist/tomcat/webapps/ad-housekeeping" "$ROOT/dist/apache-tomcat/webapps/ad-housekeeping"
  echo "Tomcat expanded to $ROOT/dist/apache-tomcat"
  echo "Start it with: $ROOT/dist/apache-tomcat/bin/catalina.sh start"
  echo "Start the console first so the front door has somewhere to send people."
fi

if [[ "$MODE" == "run" || "$MODE" == "tomcat" ]]; then
  cd "$ROOT"
  exec "$ROOT/.venv/bin/python" -m ad_housekeeping
fi
