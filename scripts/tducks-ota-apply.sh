#!/usr/bin/env bash
# Thunderducks OTA apply / rollback helper (root via systemd oneshot / path unit).
#
# pending.json apply:
#   { "action":"apply", "version":"0.2.0",
#     "staged_path":"/var/lib/thunderducks/ota/tducks-0.2.0.bin",
#     "restart": true, "requested_ms": 123 }
#
# pending.json rollback:
#   { "action":"rollback", "version":"0.1.0",
#     "staged_path":"/var/lib/thunderducks/ota/previous/tducks.bin",
#     "restart": true, "requested_ms": 123, "from_version":"0.2.0" }
#
# On apply: copies current $BIN_DST -> ota/previous/ before installing staged.
set -euo pipefail

DATA_DIR="${TD_DATA_DIR:-/var/lib/thunderducks}"
BIN_DST="${TD_OTA_BIN_PATH:-/usr/bin/tducks}"
UNIT="${TD_OTA_UNIT:-tducks.service}"
KEEP_PREV="${TD_OTA_KEEP_PREVIOUS:-true}"
PENDING="${DATA_DIR}/ota/pending.json"
STATE="${DATA_DIR}/ota-state.json"
PREV_DIR="${DATA_DIR}/ota/previous"
PREV_BIN="${PREV_DIR}/tducks.bin"
PREV_META="${PREV_DIR}/meta.json"
LOCK_DIR="${DATA_DIR}/ota/.apply.lock"
RESULT="${DATA_DIR}/ota/last-apply.json"

die() { echo "ota-apply: error: $*" >&2; exit 1; }
log() { echo "ota-apply: $*"; }

write_result() {
  local ok="$1" msg="$2" action="${3:-apply}" version="${4:-}"
  mkdir -p "$(dirname "$RESULT")"
  python3 - "$RESULT" "$ok" "$msg" "$action" "$version" <<'PY'
import json, sys, time
path, ok, msg, action, version = sys.argv[1], sys.argv[2] == "1", sys.argv[3], sys.argv[4], sys.argv[5]
open(path, "w").write(json.dumps({
    "ok": ok,
    "message": msg,
    "action": action or "apply",
    "version": version or None,
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
action = (p.get("action") or "apply").strip().lower()
if action not in ("apply", "rollback"):
    action = "apply"
print(action)
print(p.get("version") or "")
print(p.get("staged_path") or "")
print("1" if p.get("restart", True) else "0")
print(p.get("from_version") or "")
PY
)
ACTION="${PARSED[0]:-apply}"
VERSION="${PARSED[1]:-}"
STAGED="${PARSED[2]:-}"
DO_RESTART="${PARSED[3]:-1}"
FROM_VERSION="${PARSED[4]:-}"

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

keep_prev=1
case "$(printf '%s' "$KEEP_PREV" | tr '[:upper:]' '[:lower:]')" in
  0|false|no|off) keep_prev=0 ;;
esac

PREVIOUS_PATH=""
PREVIOUS_VERSION=""

read_installed_version() {
  python3 - "$STATE" <<'PY'
import json, os, sys
p = sys.argv[1]
if os.path.isfile(p):
    try:
        st = json.load(open(p))
        v = st.get("installed_version") or ""
        if v:
            print(v)
            raise SystemExit
    except SystemExit:
        raise
    except Exception:
        pass
print("")
PY
}

# --- Backup current binary before apply ---
if [[ "$ACTION" == "apply" && "$keep_prev" -eq 1 && -f "$BIN_DST" ]]; then
  mkdir -p "$PREV_DIR"
  PREVIOUS_VERSION="$(read_installed_version)"
  if [[ -z "$PREVIOUS_VERSION" ]]; then
    PREVIOUS_VERSION="$("$BIN_DST" --version 2>/dev/null | awk '{print $NF; exit}' || true)"
  fi
  if [[ -z "$PREVIOUS_VERSION" ]]; then
    PREVIOUS_VERSION="unknown"
  fi
  ver_safe="${PREVIOUS_VERSION//\//_}"
  prev_ver_path="${PREV_DIR}/tducks-${ver_safe}.bin"
  cp -a "$BIN_DST" "$prev_ver_path"
  cp -a "$BIN_DST" "$PREV_BIN"
  PREVIOUS_PATH="$PREV_BIN"
  python3 - "$PREV_META" "$PREVIOUS_VERSION" "$PREVIOUS_PATH" "$prev_ver_path" <<'PY'
import json, sys, time
meta, ver, path, ver_path = sys.argv[1:5]
open(meta, "w").write(json.dumps({
    "version": ver,
    "path": path,
    "versioned_path": ver_path,
    "saved_ms": int(time.time() * 1000),
}, indent=2) + "\n")
PY
  log "backed up previous binary version=${PREVIOUS_VERSION} -> ${PREVIOUS_PATH}"
fi

# For rollback, save the binary we're rolling away from.
if [[ "$ACTION" == "rollback" && "$keep_prev" -eq 1 && -f "$BIN_DST" ]]; then
  mkdir -p "$PREV_DIR"
  rolled_from="${FROM_VERSION:-}"
  if [[ -z "$rolled_from" ]]; then
    rolled_from="$(read_installed_version)"
  fi
  [[ -n "$rolled_from" ]] || rolled_from="unknown"
  ver_safe="${rolled_from//\//_}"
  cp -a "$BIN_DST" "${PREV_DIR}/tducks-rolled-from-${ver_safe}.bin"
  log "saved rolled-from binary version=${rolled_from}"
fi

# Atomic install: write sibling then rename into place.
tmp="${BIN_DST}.ota-new.$$"
install -m 0755 "$STAGED" "$tmp"
chown root:root "$tmp" 2>/dev/null || true
mv -f "$tmp" "$BIN_DST"
log "installed $BIN_DST ($sz bytes) action=${ACTION} version=${VERSION}"

# Merge ota-state.json and clear pending.
python3 - "$STATE" "$PENDING" "$VERSION" "$STAGED" "$BIN_DST" "$ACTION" \
  "$PREVIOUS_VERSION" "$PREVIOUS_PATH" "$PREV_META" "$FROM_VERSION" <<'PY'
import json, os, sys, time

(
    state_path,
    pending_path,
    version,
    staged,
    bin_dst,
    action,
    prev_ver,
    prev_path,
    prev_meta,
    from_version,
) = sys.argv[1:11]

st = {}
if os.path.isfile(state_path):
    try:
        st = json.load(open(state_path))
    except Exception:
        st = {}

now = int(time.time() * 1000)

if action == "rollback":
    st["last_apply"] = "rolled back to %s -> %s" % (version, bin_dst)
    st["last_rollback_ms"] = now
    st["last_rollback_version"] = version
    st["last_action"] = "rollback"
    if from_version:
        st["previous_version"] = from_version
    rolled_name = "tducks-rolled-from-%s.bin" % (from_version or "unknown").replace("/", "_")
    prev_dir = os.path.dirname(prev_meta) if prev_meta else ""
    rolled = os.path.join(prev_dir, rolled_name) if prev_dir else ""
    if prev_path and os.path.isfile(prev_path):
        st["previous_path"] = prev_path
    if rolled and os.path.isfile(rolled):
        st["rolled_from_path"] = rolled
        st["rolled_from_version"] = from_version or None
else:
    st["last_apply"] = "installed %s -> %s" % (version, bin_dst)
    st["last_action"] = "apply"
    if prev_path and os.path.isfile(prev_path):
        st["previous_version"] = prev_ver or None
        st["previous_path"] = prev_path
        st["previous_saved_ms"] = now
    elif prev_meta and os.path.isfile(prev_meta):
        try:
            meta = json.load(open(prev_meta))
            st["previous_version"] = meta.get("version")
            st["previous_path"] = meta.get("path")
            st["previous_saved_ms"] = meta.get("saved_ms")
        except Exception:
            pass

st["last_apply_ok"] = True
st["last_apply_ms"] = now
st["installed_version"] = version
st["staged_path"] = staged
st["pending"] = None
st["last_error"] = None
open(state_path, "w").write(json.dumps(st, indent=2) + "\n")
os.remove(pending_path)
print("ota-apply: state updated, pending cleared (action=%s)" % action)
PY

write_result 1 "${ACTION} ${VERSION}" "$ACTION" "$VERSION"

if [[ "$DO_RESTART" == "1" ]]; then
  if command -v systemctl >/dev/null; then
    log "restarting ${UNIT}"
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
