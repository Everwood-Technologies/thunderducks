#!/usr/bin/env bash
# Thunderducks dev harness: multi-process smoke + P1 operator demos.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RPC_BIND="${RPC_BIND:-127.0.0.1:8788}"
RELAY_BIND="${RELAY_BIND:-127.0.0.1:7700}"
WITH_RELAY="${WITH_RELAY:-0}"
WITH_P1="${WITH_P1:-1}"

echo "== build =="
cargo build -q -p tducks -p td-relay -p td-node --examples

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

echo "== start node RPC on $RPC_BIND =="
./target/debug/tducks serve --bind "$RPC_BIND" &
PIDS+=($!)
sleep 0.4

if [[ "$WITH_RELAY" == "1" ]]; then
  echo "== start relay on $RELAY_BIND =="
  ./target/debug/td-relay --bind "$RELAY_BIND" --db /tmp/td-harness-relay.sqlite &
  PIDS+=($!)
  sleep 0.3
fi

echo "== CLI happy-path (in-process) =="
./target/debug/tducks happy-path

echo "== CLI smoke against RPC =="
./target/debug/tducks --rpc "http://$RPC_BIND" smoke || {
  ./target/debug/tducks --rpc "http://$RPC_BIND" status
  ROOM=$(./target/debug/tducks --rpc "http://$RPC_BIND" create-room harness | python3 -c 'import sys,json; print(json.load(sys.stdin)["room_id"])')
  ./target/debug/tducks --rpc "http://$RPC_BIND" send "$ROOM" "harness-honk" >/dev/null
  ./target/debug/tducks --rpc "http://$RPC_BIND" recv "$ROOM"
}

echo "== bot post =="
if command -v node >/dev/null; then
  TD_RPC="http://$RPC_BIND" node clients/bot/src/honk-bot.js "harness-bot-honk" || true
fi

if [[ "$WITH_P1" == "1" ]]; then
  echo "== P1.2 two-user P2P =="
  ./target/debug/examples/two_user_p2p
  echo "== P1.3 relay offline catch-up + direct P2P =="
  ./target/debug/examples/relay_offline_catchup
fi

echo "== harness ok =="
