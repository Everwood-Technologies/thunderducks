#!/usr/bin/env bash
# Guest-side bootstrap: install Thunderducks Pond + nginx UI on Ubuntu/Debian.
#
# Run as root inside the VM/LXC (or via pct/qm guest exec from the PVE helper).
#
# Env:
#   TDUCKS_VERSION=v0.1.0-alpha.1   (required for prereleases; default alpha.1)
#   TDUCKS_REPO=Everwood-Technologies/thunderducks
#   POND_WEB_REF=main               (git ref for clients/web + nginx conf)
#   POND_SKIP_NGINX=0
#   POND_SKIP_TDUCKS=0
#   POND_HTTP_PORT=80
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "error: run as root" >&2
  exit 1
fi

REPO="${TDUCKS_REPO:-Everwood-Technologies/thunderducks}"
VERSION="${TDUCKS_VERSION:-v0.1.0-alpha.1}"
WEB_REF="${POND_WEB_REF:-main}"
SKIP_NGINX="${POND_SKIP_NGINX:-0}"
SKIP_TDUCKS="${POND_SKIP_TDUCKS:-0}"
HTTP_PORT="${POND_HTTP_PORT:-80}"
WEB_ROOT="${POND_WEB_ROOT:-/var/www/pond}"
RAW="https://raw.githubusercontent.com/${REPO}"

export DEBIAN_FRONTEND=noninteractive

log() { echo "pond-guest: $*"; }
die() { echo "pond-guest: error: $*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }

apt_install() {
  apt-get update -y
  apt-get install -y --no-install-recommends "$@"
}

log "apt packages (curl ca-certificates nginx unzip)"
apt_install ca-certificates curl nginx unzip python3

if [[ "$SKIP_TDUCKS" != "1" ]]; then
  log "install tducks ${VERSION}"
  curl -fsSL "${RAW}/main/scripts/install-tducks.sh" \
    | TDUCKS_VERSION="${VERSION}" TDUCKS_REPO="${REPO}" bash
  systemctl enable --now tducks.service
  # Ensure loopback RPC (nginx proxies; do not LAN-bind admin RPC by default)
  if [[ -f /etc/thunderducks/tducks.env ]]; then
    if grep -q '^TD_BIND=' /etc/thunderducks/tducks.env 2>/dev/null; then
      sed -i 's|^TD_BIND=.*|TD_BIND=127.0.0.1:8788|' /etc/thunderducks/tducks.env
    else
      echo 'TD_BIND=127.0.0.1:8788' >>/etc/thunderducks/tducks.env
    fi
  else
    mkdir -p /etc/thunderducks
    cat >/etc/thunderducks/tducks.env <<'EOF'
# Pond guest defaults — RPC stays loopback; nginx serves UI + proxies /v1
TD_BIND=127.0.0.1:8788
TD_DATA_DIR=/var/lib/thunderducks
EOF
  fi
  systemctl restart tducks.service || true
else
  log "skip tducks install"
fi

if [[ "$SKIP_NGINX" != "1" ]]; then
  log "deploy pond web UI → ${WEB_ROOT}"
  mkdir -p "${WEB_ROOT}/dist"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  # Prefer sparse raw fetches (no full git clone required).
  fetch() {
    local path="$1" dest="$2"
    curl -fsSL "${RAW}/${WEB_REF}/${path}" -o "$dest" \
      || die "failed to fetch ${path} @ ${WEB_REF}"
  }

  fetch clients/web/index.html "${WEB_ROOT}/index.html"
  fetch clients/web/package.json "${tmp}/package.json"
  fetch clients/web/package-lock.json "${tmp}/package-lock.json" || true
  fetch clients/web/tsconfig.json "${tmp}/tsconfig.json"
  mkdir -p "${tmp}/src"
  fetch clients/web/src/rpc.ts "${tmp}/src/rpc.ts"
  fetch clients/web/src/index.ts "${tmp}/src/index.ts"
  fetch clients/web/src/smoke.test.ts "${tmp}/src/smoke.test.ts" || true

  if command -v npm >/dev/null 2>&1 || apt-get install -y --no-install-recommends npm >/dev/null 2>&1; then
    log "build web client (tsc)"
    (
      cd "$tmp"
      # Minimal build: only need dist/rpc.js + types optional
      npm install --no-audit --no-fund >/dev/null
      npx --yes tsc -p tsconfig.json
      cp -a dist/*.js "${WEB_ROOT}/dist/" 2>/dev/null || true
      # index may import ./dist/rpc.js
      [[ -f dist/rpc.js ]] || die "web build missing dist/rpc.js"
      cp -a dist/rpc.js "${WEB_ROOT}/dist/rpc.js"
      [[ -f dist/index.js ]] && cp -a dist/index.js "${WEB_ROOT}/dist/index.js" || true
    )
  else
    die "npm/tsc unavailable — cannot build web UI"
  fi

  # Patch index.html import path is already ./dist/rpc.js
  chown -R www-data:www-data "${WEB_ROOT}" 2>/dev/null || chown -R nginx:nginx "${WEB_ROOT}" 2>/dev/null || true

  log "install nginx site"
  conf_dst="/etc/nginx/sites-available/pond-ui.conf"
  fetch packaging/nginx/pond-ui.conf "$conf_dst"
  # Optional non-80 port
  if [[ "$HTTP_PORT" != "80" ]]; then
    sed -i "s/listen 80/listen ${HTTP_PORT}/g; s/listen \\[::\\]:80/listen [::]:${HTTP_PORT}/g" "$conf_dst"
  fi
  rm -f /etc/nginx/sites-enabled/default
  ln -sfn "$conf_dst" /etc/nginx/sites-enabled/pond-ui.conf
  nginx -t
  systemctl enable --now nginx
  systemctl reload nginx
else
  log "skip nginx"
fi

# Health checks
log "verify tducks health"
for _ in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8788/health >/dev/null; then
    break
  fi
  sleep 0.5
done
curl -sf http://127.0.0.1:8788/health | grep -q ok || die "tducks /health failed"
if [[ "$SKIP_NGINX" != "1" ]]; then
  curl -sf "http://127.0.0.1:${HTTP_PORT}/health" | grep -q ok || die "nginx /health proxy failed"
  curl -sf "http://127.0.0.1:${HTTP_PORT}/" | grep -qi thunderducks || die "nginx UI root failed"
fi

ip_guess="$(hostname -I 2>/dev/null | awk '{print $1}')"
log "OK"
echo
echo "Pond guest ready"
echo "  tducks RPC (loopback): http://127.0.0.1:8788"
echo "  UI + proxied API:      http://${ip_guess:-<guest-ip>}:${HTTP_PORT}/"
echo "  claim: open UI → first-run wizard (save recovery code offline)"
echo "  version: ${VERSION}"
echo
echo "Do not expose :8788 to WAN. Prefer LAN/tailnet only for :${HTTP_PORT}."
