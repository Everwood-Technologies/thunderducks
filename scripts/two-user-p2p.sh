#!/usr/bin/env bash
# P1.2 — two distinct users exchange signed events over localhost TCP P2P.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
echo "== build =="
cargo build -q -p td-node --example two_user_p2p
echo "== two_user_p2p =="
cargo run -q -p td-node --example two_user_p2p
echo "== ok =="
