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

apt_install() {
  apt-get update -y
  apt-get install -y --no-install-recommends "$@"
}

disable_host_firewall_http() {
  # LXC templates sometimes enable ufw with default deny; open HTTP for alpha LAN.
  if command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -qi 'Status: active'; then
      log "ufw active — allowing ${HTTP_PORT}/tcp"
      ufw allow "${HTTP_PORT}/tcp" || true
      ufw allow OpenSSH || true
    fi
  fi
  # nftables/iptables hard deny is uncommon on fresh Ubuntu CT; skip unless present.
}

log "apt packages (curl ca-certificates nginx unzip)"
apt_install ca-certificates curl nginx unzip python3

if [[ "$SKIP_TDUCKS" != "1" ]]; then
  log "install tducks ${VERSION}"
  curl -fsSL "${RAW}/main/scripts/install-tducks.sh" \
    | TDUCKS_VERSION="${VERSION}" TDUCKS_REPO="${REPO}" bash
  systemctl enable --now tducks.service || true
  mkdir -p /etc/thunderducks
  if [[ -f /etc/thunderducks/tducks.env ]]; then
    if grep -q '^TD_BIND=' /etc/thunderducks/tducks.env 2>/dev/null; then
      sed -i 's|^TD_BIND=.*|TD_BIND=127.0.0.1:8788|' /etc/thunderducks/tducks.env
    else
      echo 'TD_BIND=127.0.0.1:8788' >>/etc/thunderducks/tducks.env
    fi
  else
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
  POND_WEB_TMP="$(mktemp -d)"
  trap 'rm -rf "${POND_WEB_TMP:-}" 2>/dev/null || true' EXIT

  fetch() {
    local path="$1" dest="$2"
    curl -fsSL "${RAW}/${WEB_REF}/${path}" -o "$dest" \
      || die "failed to fetch ${path} @ ${WEB_REF}"
  }

  fetch clients/web/index.html "${WEB_ROOT}/index.html"
  fetch clients/web/package.json "${POND_WEB_TMP}/package.json"
  fetch clients/web/package-lock.json "${POND_WEB_TMP}/package-lock.json" || true
  fetch clients/web/tsconfig.json "${POND_WEB_TMP}/tsconfig.json"
  mkdir -p "${POND_WEB_TMP}/src"
  fetch clients/web/src/rpc.ts "${POND_WEB_TMP}/src/rpc.ts"
  fetch clients/web/src/index.ts "${POND_WEB_TMP}/src/index.ts"
  fetch clients/web/src/smoke.test.ts "${POND_WEB_TMP}/src/smoke.test.ts" || true

  if ! command -v npm >/dev/null 2>&1; then
    apt_install npm
  fi
  log "build web client (tsc)"
  (
    cd "${POND_WEB_TMP}"
    npm install --no-audit --no-fund >/dev/null
    npx --yes tsc -p tsconfig.json
    [[ -f dist/rpc.js ]] || die "web build missing dist/rpc.js"
    cp -a dist/rpc.js "${WEB_ROOT}/dist/rpc.js"
    [[ -f dist/index.js ]] && cp -a dist/index.js "${WEB_ROOT}/dist/index.js" || true
  )
  chown -R www-data:www-data "${WEB_ROOT}" 2>/dev/null || true

  log "install nginx site"
  conf_dst="/etc/nginx/sites-available/pond-ui.conf"
  fetch packaging/nginx/pond-ui.conf "$conf_dst"
  if [[ "$HTTP_PORT" != "80" ]]; then
    sed -i \
      -e "s/listen 80 default_server/listen ${HTTP_PORT} default_server/g" \
      -e "s/listen \\[::\\]:80 default_server/listen [::]:${HTTP_PORT} default_server/g" \
      -e "s/listen 80;/listen ${HTTP_PORT};/g" \
      -e "s/listen \\[::\\]:80;/listen [::]:${HTTP_PORT};/g" \
      "$conf_dst"
  fi

  # Own :80 exclusively
  rm -f /etc/nginx/sites-enabled/default \
        /etc/nginx/sites-enabled/default.conf \
        /etc/nginx/sites-enabled/*default* 2>/dev/null || true
  if [[ -f /etc/nginx/conf.d/default.conf ]]; then
    mv -f /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf.disabled || true
  fi
  ln -sfn "$conf_dst" /etc/nginx/sites-enabled/pond-ui.conf

  # Ensure nginx.conf includes sites-enabled (Debian/Ubuntu default)
  if ! grep -q 'sites-enabled' /etc/nginx/nginx.conf 2>/dev/null; then
    log "warn: nginx.conf may not include sites-enabled — check manually"
  fi

  nginx -t
  systemctl enable nginx
  systemctl restart nginx
  sleep 1
  disable_host_firewall_http
else
  log "skip nginx"
fi

log "verify tducks health"
td_body=""
for _ in $(seq 1 40); do
  td_body="$(curl -sS --max-time 3 http://127.0.0.1:8788/health 2>/dev/null || true)"
  if printf '%s' "$td_body" | grep -q '"ok"'; then
    break
  fi
  sleep 0.5
done
printf '%s' "$td_body" | grep -q '"ok"' || die "tducks /health failed (got: ${td_body:-empty}). Is tducks running?"

if [[ "$SKIP_NGINX" != "1" ]]; then
  log "verify nginx proxy + UI"
  ngx_body=""
  ngx_ok=0
  for _ in $(seq 1 20); do
    ngx_body="$(curl -sS --max-time 5 -4 -H 'Host: localhost' \
      "http://127.0.0.1:${HTTP_PORT}/health" 2>/dev/null || true)"
    if printf '%s' "$ngx_body" | grep -q '"ok"'; then
      ngx_ok=1
      break
    fi
    # 502 right after restart — give tducks/nginx another beat
    sleep 0.5
  done
  if [[ "$ngx_ok" -ne 1 ]]; then
    log "nginx /health proxy failed — diagnostics follow"
    echo "=== tducks ==="
    systemctl --no-pager --full status tducks || true
    curl -sS -D- --max-time 3 http://127.0.0.1:8788/health || true
    echo
    echo "=== nginx ==="
    systemctl --no-pager --full status nginx || true
    curl -sS -D- --max-time 3 -4 "http://127.0.0.1:${HTTP_PORT}/health" || true
    echo
    echo "=== listeners ==="
    ss -lntp 2>/dev/null || netstat -lntp 2>/dev/null || true
    echo "=== enabled sites ==="
    ls -la /etc/nginx/sites-enabled/ 2>/dev/null || true
    echo "=== nginx -T (listen/proxy) ==="
    nginx -T 2>/dev/null | grep -E 'listen |server_name|location|proxy_pass|root ' | head -100 || true
    die "nginx /health proxy failed (got: ${ngx_body:-empty})"
  fi

  root_body="$(curl -sS --max-time 5 -4 "http://127.0.0.1:${HTTP_PORT}/" 2>/dev/null || true)"
  printf '%s' "$root_body" | grep -qi thunderducks \
    || die "nginx UI root failed (first 200: $(printf '%.200s' "${root_body:-empty}"))"

  # Confirm nginx is not loopback-only
  if ss -lntp 2>/dev/null | grep -E ":${HTTP_PORT}\\b" | grep -q '127.0.0.1'; then
    if ! ss -lntp 2>/dev/null | grep -E ":${HTTP_PORT}\\b" | grep -qvE '127.0.0.1|\[::1\]'; then
      log "warn: port ${HTTP_PORT} may be loopback-only — check listen directives"
    fi
  fi
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
