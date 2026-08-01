#!/usr/bin/env bash
# P1.3 — offline relay catch-up then direct P2P (spawns real td-relay).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
echo "== build =="
cargo build -q -p td-relay -p td-node --example relay_offline_catchup
echo "== relay_offline_catchup =="
cargo run -q -p td-node --example relay_offline_catchup
echo "== ok =="
