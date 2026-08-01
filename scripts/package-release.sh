#!/usr/bin/env bash
# Local release tarball helper (amd64 host by default).
# Usage:
#   ./scripts/package-release.sh
#   VERSION=v0.1.0 ./scripts/package-release.sh
#   TARGET=aarch64-unknown-linux-gnu ./scripts/package-release.sh  # needs linker
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
VERSION="${VERSION:-dev-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
TARGET="${TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
OUT_DIR="${OUT_DIR:-$ROOT/dist}"
STAGE_NAME="tducks-${VERSION}-${TARGET}"
STAGE="$OUT_DIR/$STAGE_NAME"

echo "building tducks release for $TARGET ..."
if [[ "$TARGET" == "$(rustc -vV | sed -n 's/^host: //p')" ]]; then
  cargo build -p tducks --release
  BIN="$ROOT/target/release/tducks"
else
  rustup target add "$TARGET" 2>/dev/null || true
  cargo build -p tducks --release --target "$TARGET"
  BIN="$ROOT/target/${TARGET}/release/tducks"
fi
[[ -x "$BIN" ]] || { echo "missing $BIN" >&2; exit 1; }

rm -rf "$STAGE"
mkdir -p "$STAGE"
cp "$BIN" "$STAGE/tducks"
chmod +x "$STAGE/tducks"
cp README.md LICENSE "$STAGE/" 2>/dev/null || cp README.md "$STAGE/"
cp packaging/systemd/tducks.service "$STAGE/"
cp packaging/tducks.env.example "$STAGE/"
cp scripts/install-tducks.sh "$STAGE/"
mkdir -p "$OUT_DIR"
tar -czf "$OUT_DIR/${STAGE_NAME}.tar.gz" -C "$OUT_DIR" "$STAGE_NAME"
echo "wrote $OUT_DIR/${STAGE_NAME}.tar.gz"
ls -la "$OUT_DIR/${STAGE_NAME}.tar.gz"
"$STAGE/tducks" version
