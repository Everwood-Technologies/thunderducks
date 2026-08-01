# Thunderducks

Event-driven, maximally decentralized hybrid P2P **E2EE** chat — no tokens, no blockchain bus.

> Codename is intentionally ridiculous. Protocol crates use `td-*` / `tducks`.

## Status

**M5 accepted (with caveats)** — Waves A–F shipped. See [`docs/mvp-accept.md`](./docs/mvp-accept.md) and [`docs/post-mvp-backlog.md`](./docs/post-mvp-backlog.md).

**Site:** https://everwood-technologies.github.io/thunderducks/

| Layer | Choice |
|-------|--------|
| Core | Rust-first monorepo |
| Events | Signed events + per-room causal DAG |
| Crypto | vodozemac (Olm/MegOlm); **RPC messages Megolm by default** |
| Transport | P2P-first; optional untrusted relay assist |
| Identity | Multi-device (≥2); WebAuthn/passkey RPC + device-link |
| Clients | CLI (`tducks`) + TypeScript web |
| Widgets | iframe + JS SDK (deny-by-default) |
| License | **AGPL-3.0-only** |

## Workspace layout

```text
crates/
  td-event/     signed events, DAG, store
  td-crypto/    device keys, E2EE
  td-net/       P2P dial/listen
  td-node/      node runtime + RPC
  td-cli/       CLI (bin: tducks)
relays/
  td-relay/     optional assist relay
clients/
  web/          TS client + widget host
  widget-sdk/   iframe postMessage SDK (deny-by-default)
  bot/          sample bot (public RPC only)
docs/
  threat-model.md
  architecture.md
  bench.md
  harness.md
scripts/
  dev-harness.sh
  two-user-p2p.sh
  relay-offline-catchup.sh
  install-tducks.sh   Pond DIY systemd install
  package-release.sh  local release tarball
packaging/
  systemd/tducks.service
  tducks.env.example
```

## Install node (Pond DIY)

Linux amd64/arm64 + systemd — see [`docs/install.md`](./docs/install.md).

```bash
# from this repo after building:
cargo build -p tducks --release
sudo ./scripts/install-tducks.sh --from-file ./target/release/tducks
# or after a GitHub Release tag v*:
# curl -fsSL .../scripts/install-tducks.sh | sudo bash
```

Appliance product draft: [`docs/pond-appliance.md`](./docs/pond-appliance.md).  
Remote access (tailnet + relay): [`docs/remote-access.md`](./docs/remote-access.md).

## Dev harness

```bash
./scripts/dev-harness.sh
# optional relay: WITH_RELAY=1 ./scripts/dev-harness.sh
# P1 operator demos only:
./scripts/two-user-p2p.sh
./scripts/relay-offline-catchup.sh
```

## Quick start

```bash
# Rust 1.75+ recommended
cargo test --workspace
cargo run -p tducks -- serve --bind 127.0.0.1:8788
# another terminal:
cargo run -p tducks -- --rpc http://127.0.0.1:8788 smoke
```

## Non-goals (MVP)

- Tokens, gas, L1 consensus, smart contracts
- Mandatory global DHT
- Tauri / mobile store apps
- Perfect metadata privacy

## Docs

- [Install / Pond DIY](./docs/install.md)
- [Pond appliance one-pager](./docs/pond-appliance.md)
- [MVP accept checklist](./docs/mvp-accept.md)
- [Post-MVP backlog](./docs/post-mvp-backlog.md)
- [Operator harness](./docs/harness.md)
- [Benches](./docs/bench.md)
- [Threat model](./docs/threat-model.md)
- [Threat model ↔ impl diff](./docs/threat-model-diff.md)
- [Architecture](./docs/architecture.md)
- [Security policy](./SECURITY.md)

## License

[AGPL-3.0-only](./LICENSE)
