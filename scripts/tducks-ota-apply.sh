#!/usr/bin/env bash
# Thunderducks OTA apply helper (runs as root via systemd oneshot / path unit).
# Reads $TD_DATA_DIR/ota/pending.json, installs staged binary, optionally restarts.
#
# pending.json:
#   { "version":"0.2.0", "staged_path":"/var/lib/thunderducks/ota/tducks-0.2.0.bin",
#     "restart": true, "requested_ms": 123 }
set -euo pipefail

DATA_DIR="${TD_DATA_DIR:-/var/lib/thunderducks}"
BIN_DST="${TD_OTA_BIN_PATH:-/usr/bin/tducks}"
UNIT="${TD_OTA_UNIT:-tducks.service}"
PENDING="${DATA_DIR}/ota/pending.json"
STATE="${DATA_DIR}/ota-state.json"
LOCK_DIR="${DATA_DIR}/ota/.apply.lock"
RESULT="${DATA_DIR}/ota/last-apply.json"

die() { echo "ota-apply: error: $*" >&2; exit 1; }
log() { echo "ota-apply: $*"; }

write_result() {
  local ok="$1" msg="$2"
  mkdir -p "$(dirname "$RESULT")"
  python3 - "$RESULT" "$ok" "$msg" <<'PY'
import json, sys, time
path, ok, msg = sys.argv[1], sys.argv[2] == "1", sys.argv[3]
open(path, "w").write(json.dumps({
    "ok": ok,
    "message": msg,
    "ts_ms": int(time.time() * 1000),
}, indent=2) + "\n")
PY
}

[[ "$(id -u)" -eq 0 ]] || die "must run as root"
[[ -f "$PENDING" ]] || die "no pending OTA at $PENDING"
command -v python3 >/dev/null || die "python3 required"

mapfile -t PARSED < <(python3 - "$PENDING" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
print(p.get("version") or "")
print(p.get("staged_path") or "")
print("1" if p.get("restart", True) else "0")
PY
)
VERSION="${PARSED[0]:-}"
STAGED="${PARSED[1]:-}"
DO_RESTART="${PARSED[2]:-1}"

[[ -n "$VERSION" ]] || die "pending.version missing"
[[ -n "$STAGED" ]] || die "pending.staged_path missing"
[[ -f "$STAGED" ]] || die "staged binary missing: $STAGED"

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  die "another apply is in progress ($LOCK_DIR)"
fi
cleanup() { rmdir "$LOCK_DIR" 2>/dev/null || true; }
trap cleanup EXIT

sz="$(wc -c <"$STAGED" | tr -d ' ')"
[[ "$sz" -gt 1024 ]] || die "staged file too small ($sz bytes)"

# Atomic install: write sibling then rename into place.
tmp="${BIN_DST}.ota-new.$$"
install -m 0755 "$STAGED" "$tmp"
chown root:root "$tmp" 2>/dev/null || true
mv -f "$tmp" "$BIN_DST"
log "installed $BIN_DST ($sz bytes) version=$VERSION"

# Merge ota-state.json and clear pending.
python3 - "$STATE" "$PENDING" "$VERSION" "$STAGED" "$BIN_DST" <<'PY'
import json, os, sys, time
state_path, pending_path, version, staged, bin_dst = sys.argv[1:6]
st = {}
if os.path.isfile(state_path):
    try:
        st = json.load(open(state_path))
    except Exception:
        st = {}
st["last_apply"] = f"installed {version} -> {bin_dst}"
st["last_apply_ok"] = True
st["last_apply_ms"] = int(time.time() * 1000)
st["installed_version"] = version
st["staged_path"] = staged
st["pending"] = None
st["last_error"] = None
open(state_path, "w").write(json.dumps(st, indent=2) + "\n")
os.remove(pending_path)
print("ota-apply: state updated, pending cleared")
PY

write_result 1 "installed ${VERSION}"

if [[ "$DO_RESTART" == "1" ]]; then
  if command -v systemctl >/dev/null; then
    log "restarting ${UNIT}"
    # Detach restart so this oneshot can exit cleanly if unit graph is tight.
    systemd-run --unit="tducks-ota-restart-$$" --on-active=1s \
      /bin/systemctl restart "${UNIT}" >/dev/null 2>&1 \
      || systemctl restart "${UNIT}" \
      || die "systemctl restart ${UNIT} failed"
  else
    log "systemctl unavailable — binary installed; restart tducks manually"
  fi
else
  log "restart skipped (pending.restart=false)"
fi

log "ok"
