# Contributing

## Development

1. Install a recent stable Rust toolchain (`rustup`) and Node 22+ for clients.
2. Rust:
   ```bash
   cargo test --workspace
   cargo fmt --all
   cargo clippy --workspace --all-targets -- -D warnings
   ```
3. Web client:
   ```bash
   cargo build -p tducks
   cd clients/web && npm install && npm test
   ```
4. Widgets + bot:
   ```bash
   cargo build -p tducks
   cd clients/widget-sdk && npm install && npm test
   cd ../bot && npm test
   ```
5. Dev harness + P1 operator demos:
   ```bash
   ./scripts/dev-harness.sh
   ./scripts/two-user-p2p.sh
   ./scripts/relay-offline-catchup.sh
   ```
6. Benches (release):
   ```bash
   cargo run -p td-event --example ingest_bench --release
   cargo run -p td-crypto --example e2ee_bench --release
   ```

## Process

Non-trivial architecture changes follow AIDLC planning when material.

## Security

See [SECURITY.md](./SECURITY.md). Do not file public issues for sensitive vulnerabilities.

## License

By contributing, you agree your contributions are licensed under **AGPL-3.0-only**.
