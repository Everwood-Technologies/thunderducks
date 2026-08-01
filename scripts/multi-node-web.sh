#!/usr/bin/env bash
# Start 3 localhost nodes + bootstrap a shared Megolm room for web-client demos.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

A_RPC="${A_RPC:-127.0.0.1:8788}"
B_RPC="${B_RPC:-127.0.0.1:8789}"
C_RPC="${C_RPC:-127.0.0.1:8790}"
ROOM_NAME="${ROOM_NAME:-pond}"
WEB_PORT="${WEB_PORT:-8090}"
STATE_DIR="${STATE_DIR:-/tmp/td-multi-node}"
KEEP_ALIVE="${KEEP_ALIVE:-1}"
mkdir -p "$STATE_DIR"

echo "== build =="
cargo build -q -p tducks

BIN=./target/debug/tducks
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

start_node() {
  local bind="$1" log="$2"
  "$BIN" serve --bind "$bind" >"$log" 2>&1 &
  PIDS+=($!)
}

wait_health() {
  local base="$1"
  for _ in $(seq 1 50); do
    if curl -sf "$base/health" >/dev/null; then return 0; fi
    sleep 0.1
  done
  echo "health timeout for $base" >&2
  return 1
}

json_get() {
  python3 -c 'import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1], {"d": d}))' "$1"
}

echo "== start nodes =="
start_node "$A_RPC" "$STATE_DIR/a.log"
start_node "$B_RPC" "$STATE_DIR/b.log"
start_node "$C_RPC" "$STATE_DIR/c.log"
wait_health "http://$A_RPC"
wait_health "http://$B_RPC"
wait_health "http://$C_RPC"

A="http://$A_RPC"
B="http://$B_RPC"
C="http://$C_RPC"

echo "== identities =="
A_ST=$(curl -sf "$A/v1/status")
B_ST=$(curl -sf "$B/v1/status")
C_ST=$(curl -sf "$C/v1/status")
A_DEV=$(printf '%s' "$A_ST" | json_get "d['device_id']")
B_DEV=$(printf '%s' "$B_ST" | json_get "d['device_id']")
C_DEV=$(printf '%s' "$C_ST" | json_get "d['device_id']")
A_P2P=$(printf '%s' "$A_ST" | json_get "d.get('p2p_uri') or ''")
B_P2P=$(printf '%s' "$B_ST" | json_get "d.get('p2p_uri') or ''")
C_P2P=$(printf '%s' "$C_ST" | json_get "d.get('p2p_uri') or ''")
echo "alice device=${A_DEV:0:12}… p2p=$A_P2P rpc=$A"
echo "bob   device=${B_DEV:0:12}… p2p=$B_P2P rpc=$B"
echo "cara  device=${C_DEV:0:12}… p2p=$C_P2P rpc=$C"

# register peers with BOTH http RPC (reliable fanout) and P2P (best-effort)
curl -sf -X POST "$A/v1/peers" -H 'content-type: application/json' \
  -d "{\"name\":\"bob\",\"rpc\":\"$B\",\"p2p\":\"$B_P2P\"}" >/dev/null
curl -sf -X POST "$A/v1/peers" -H 'content-type: application/json' \
  -d "{\"name\":\"cara\",\"rpc\":\"$C\",\"p2p\":\"$C_P2P\"}" >/dev/null
curl -sf -X POST "$B/v1/peers" -H 'content-type: application/json' \
  -d "{\"name\":\"alice\",\"rpc\":\"$A\",\"p2p\":\"$A_P2P\"}" >/dev/null
curl -sf -X POST "$B/v1/peers" -H 'content-type: application/json' \
  -d "{\"name\":\"cara\",\"rpc\":\"$C\",\"p2p\":\"$C_P2P\"}" >/dev/null
curl -sf -X POST "$C/v1/peers" -H 'content-type: application/json' \
  -d "{\"name\":\"alice\",\"rpc\":\"$A\",\"p2p\":\"$A_P2P\"}" >/dev/null
curl -sf -X POST "$C/v1/peers" -H 'content-type: application/json' \
  -d "{\"name\":\"bob\",\"rpc\":\"$B\",\"p2p\":\"$B_P2P\"}" >/dev/null

echo "== alice creates room =="
ROOM=$(curl -sf -X POST "$A/v1/rooms" -H 'content-type: application/json' \
  -d "{\"name\":\"$ROOM_NAME\"}" | json_get "d['room_id']")
echo "room_id=$ROOM"

echo "== sync room DAG A→B, A→C =="
curl -sf -X POST "$B/v1/sync/peer" -H 'content-type: application/json' \
  -d "{\"peer_rpc\":\"$A\",\"room_id\":\"$ROOM\"}" >/dev/null
curl -sf -X POST "$C/v1/sync/peer" -H 'content-type: application/json' \
  -d "{\"peer_rpc\":\"$A\",\"room_id\":\"$ROOM\"}" >/dev/null

echo "== share Megolm session A→B, A→C =="
curl -sf -X POST "$A/v1/e2ee/share-session" -H 'content-type: application/json' \
  -d "{\"peer_rpc\":\"$B\",\"room_id\":\"$ROOM\"}" >/dev/null
curl -sf -X POST "$A/v1/e2ee/share-session" -H 'content-type: application/json' \
  -d "{\"peer_rpc\":\"$C\",\"room_id\":\"$ROOM\"}" >/dev/null

echo "== alice sends group message (auto fanout) =="
ALICE_SEND=$(curl -sf -X POST "$A/v1/messages" -H 'content-type: application/json' \
  -d "{\"room_id\":\"$ROOM\",\"text\":\"hello-pond-from-alice\"}")
echo "alice send: $ALICE_SEND"
sleep 0.2

echo "== bob + cara list (decrypt) =="
B_TXT=$(curl -sf -X POST "$B/v1/messages/list" -H 'content-type: application/json' \
  -d "{\"room_id\":\"$ROOM\"}" | json_get "d['messages'][0]['text']")
C_TXT=$(curl -sf -X POST "$C/v1/messages/list" -H 'content-type: application/json' \
  -d "{\"room_id\":\"$ROOM\"}" | json_get "d['messages'][0]['text']")
echo "bob sees:  $B_TXT"
echo "cara sees: $C_TXT"
if [[ "$B_TXT" != "hello-pond-from-alice" || "$C_TXT" != "hello-pond-from-alice" ]]; then
  echo "FAIL: group decrypt mismatch" >&2
  exit 1
fi

echo "== bob replies (auto fanout on send) =="
BOB_SEND=$(curl -sf -X POST "$B/v1/messages" -H 'content-type: application/json' \
  -d "{\"room_id\":\"$ROOM\",\"text\":\"hello-from-bob\"}")
echo "bob send: $BOB_SEND"
sleep 0.2

A_LIST=$(curl -sf -X POST "$A/v1/messages/list" -H 'content-type: application/json' \
  -d "{\"room_id\":\"$ROOM\"}")
B_LIST=$(curl -sf -X POST "$B/v1/messages/list" -H 'content-type: application/json' \
  -d "{\"room_id\":\"$ROOM\"}")
C_LIST=$(curl -sf -X POST "$C/v1/messages/list" -H 'content-type: application/json' \
  -d "{\"room_id\":\"$ROOM\"}")
A_N=$(printf '%s' "$A_LIST" | json_get "len(d['messages'])")
B_N=$(printf '%s' "$B_LIST" | json_get "len(d['messages'])")
C_N=$(printf '%s' "$C_LIST" | json_get "len(d['messages'])")
echo "message counts A=$A_N B=$B_N C=$C_N"
echo "alice texts: $(printf '%s' "$A_LIST" | json_get "[m.get('text') for m in d['messages']]")"
echo "bob texts:   $(printf '%s' "$B_LIST" | json_get "[m.get('text') for m in d['messages']]")"
echo "cara texts:  $(printf '%s' "$C_LIST" | json_get "[m.get('text') for m in d['messages']]")"
if [[ "$A_N" -lt 2 || "$B_N" -lt 2 || "$C_N" -lt 2 ]]; then
  echo "FAIL: expected >=2 messages on each node" >&2
  exit 1
fi
for label_list in "alice:$A_LIST" "bob:$B_LIST" "cara:$C_LIST"; do
  label="${label_list%%:*}"
  body="${label_list#*:}"
  if printf '%s' "$body" | grep -q 'e2ee:decrypt-failed'; then
    echo "FAIL: $label has decrypt-failed (auto fanout broken)" >&2
    printf '%s\n' "$body" >&2
    exit 1
  fi
done
echo "OK: all nodes decrypt both messages (send-just-works)"

cat >"$STATE_DIR/endpoints.json" <<EOF
{
  "room_id": "$ROOM",
  "room_name": "$ROOM_NAME",
  "nodes": {
    "alice": {"rpc": "$A", "device_id": "$A_DEV", "p2p": "$A_P2P"},
    "bob":   {"rpc": "$B", "device_id": "$B_DEV", "p2p": "$B_P2P"},
    "cara":  {"rpc": "$C", "device_id": "$C_DEV", "p2p": "$C_P2P"}
  },
  "web": {
    "alice": "http://127.0.0.1:$WEB_PORT/index.html?rpc=$A&room=$ROOM&name=alice",
    "bob":   "http://127.0.0.1:$WEB_PORT/index.html?rpc=$B&room=$ROOM&name=bob",
    "cara":  "http://127.0.0.1:$WEB_PORT/index.html?rpc=$C&room=$ROOM&name=cara"
  }
}
EOF

echo "== build + start static web on :$WEB_PORT =="
(
  cd clients/web
  npm run build -s
  python3 -m http.server "$WEB_PORT" --bind 127.0.0.1 >"$STATE_DIR/web.log" 2>&1
) &
PIDS+=($!)
sleep 0.4

echo
echo "OK multi-node pond ready"
echo "state: $STATE_DIR/endpoints.json"
python3 -m json.tool "$STATE_DIR/endpoints.json"
echo
echo "Open three browser tabs (localhost only):"
python3 - <<PY
import json
from pathlib import Path
d=json.loads(Path("$STATE_DIR/endpoints.json").read_text())
for k,v in d["web"].items():
    print(f"  {k}: {v}")
PY
echo
if [[ "$KEEP_ALIVE" == "1" ]]; then
  echo "Nodes stay up until you Ctrl-C this script."
  while true; do sleep 3600; done
else
  echo "KEEP_ALIVE=0 — leaving processes running (trap disabled)."
  trap - EXIT
fi
