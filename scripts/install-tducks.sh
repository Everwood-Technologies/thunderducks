#!/usr/bin/env bash
# Thunderducks Pond DIY install — Linux amd64/arm64
# Installs tducks binary + systemd unit + data dir.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Everwood-Technologies/thunderducks/main/scripts/install-tducks.sh | sudo bash
#   sudo ./scripts/install-tducks.sh
#   sudo ./scripts/install-tducks.sh --from-file ./tducks
#   sudo ./scripts/install-tducks.sh --version v0.1.0
#   sudo ./scripts/install-tducks.sh --bind 0.0.0.0:8788   # LAN (firewall yourself)
#
# Env:
#   TDUCKS_VERSION=v0.1.0   (or "latest")
#   TDUCKS_BIND=127.0.0.1:8788
#   TDUCKS_REPO=Everwood-Technologies/thunderducks
set -euo pipefail

REPO="${TDUCKS_REPO:-Everwood-Technologies/thunderducks}"
VERSION="${TDUCKS_VERSION:-latest}"
BIND="${TDUCKS_BIND:-127.0.0.1:8788}"
PREFIX="${TDUCKS_PREFIX:-/usr}"
UNIT_DST="/etc/systemd/system/tducks.service"
BIN_DST="${PREFIX}/bin/tducks"
DATA_DIR="/var/lib/thunderducks"
CONF_DIR="/etc/thunderducks"
FROM_FILE=""
SKIP_START=0

die() { echo "error: $*" >&2; exit 1; }
need_root() { [[ "$(id -u)" -eq 0 ]] || die "run as root (sudo)"; }

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    --bind) BIND="${2:-}"; shift 2 ;;
    --from-file) FROM_FILE="${2:-}"; shift 2 ;;
    --prefix) PREFIX="${2:-}"; BIN_DST="${PREFIX}/bin/tducks"; shift 2 ;;
    --skip-start) SKIP_START=1; shift ;;
    *) die "unknown arg: $1" ;;
  esac
done

need_root

detect_target() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) echo "x86_64-unknown-linux-gnu" ;;
    aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
    *) die "unsupported arch: $arch (need x86_64 or aarch64)" ;;
  esac
}

ensure_user() {
  if ! id tducks &>/dev/null; then
    useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin tducks
  fi
  mkdir -p "$DATA_DIR" "$CONF_DIR"
  chown -R tducks:tducks "$DATA_DIR"
  chmod 750 "$DATA_DIR"
}

install_from_file() {
  local src="$1"
  [[ -f "$src" ]] || die "binary not found: $src"
  install -m 0755 "$src" "$BIN_DST"
}

download_release() {
  local target asset url tmp
  target="$(detect_target)"
  command -v curl >/dev/null || die "curl required"
  command -v tar >/dev/null || die "tar required"

  if [[ "$VERSION" == "latest" ]]; then
    # Resolve latest tag via GitHub API (no jq required)
    VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
    [[ -n "$VERSION" ]] || die "could not resolve latest release (publish a GitHub Release first, or pass --from-file / --version)"
  fi

  asset="tducks-${VERSION}-${target}.tar.gz"
  url="https://github.com/${REPO}/releases/download/${VERSION}/${asset}"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  echo "downloading $url"
  curl -fsSL -o "$tmp/$asset" "$url" || die "download failed — is release $VERSION published for $target?"
  tar -xzf "$tmp/$asset" -C "$tmp"
  if [[ -f "$tmp/tducks" ]]; then
    install_from_file "$tmp/tducks"
  elif [[ -f "$tmp/tducks-${VERSION}-${target}/tducks" ]]; then
    install_from_file "$tmp/tducks-${VERSION}-${target}/tducks"
  else
    # tarball may nest or name with target
    local found
    found="$(find "$tmp" -type f -name tducks | head -1)"
    [[ -n "$found" ]] || die "tducks binary missing inside $asset"
    install_from_file "$found"
  fi
}

install_unit() {
  cat >"$UNIT_DST" <<EOF
[Unit]
Description=Thunderducks Pond node (tducks)
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=tducks
Group=tducks
Environment=TD_DATA_DIR=${DATA_DIR}
Environment=TD_BIND=${BIND}
EnvironmentFile=-${CONF_DIR}/tducks.env
ExecStart=${BIN_DST} serve --bind \${TD_BIND}
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictSUIDSGID=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

  if [[ ! -f "${CONF_DIR}/tducks.env" ]]; then
    cat >"${CONF_DIR}/tducks.env" <<EOF
# Thunderducks Pond node env
TD_BIND=${BIND}
TD_DATA_DIR=${DATA_DIR}
EOF
    chmod 644 "${CONF_DIR}/tducks.env"
  fi

  systemctl daemon-reload
  systemctl enable tducks.service
  if [[ "$SKIP_START" -eq 0 ]]; then
    systemctl restart tducks.service
    sleep 0.5
    systemctl --no-pager --full status tducks.service || true
  fi
}

main() {
  echo "Thunderducks Pond DIY install"
  echo "  bind: $BIND"
  ensure_user
  if [[ -n "$FROM_FILE" ]]; then
    install_from_file "$FROM_FILE"
  else
    download_release
  fi
  install_unit
  echo
  echo "OK — tducks installed"
  echo "  binary: $BIN_DST"
  echo "  data:   $DATA_DIR"
  echo "  unit:   tducks.service"
  echo "  status: systemctl status tducks"
  echo "  logs:   journalctl -u tducks -f"
  echo "  rpc:    curl -s http://${BIND}/health || curl -s http://127.0.0.1:8788/health"
  echo
  echo "Note: default bind is loopback. For LAN clients set TD_BIND in ${CONF_DIR}/tducks.env and open firewall carefully."
}

main
