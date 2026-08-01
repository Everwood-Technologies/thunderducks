# Thunderducks

Event-driven, maximally decentralized hybrid P2P **E2EE** chat — no tokens, no blockchain bus.

> Codename is intentionally ridiculous. Protocol crates use `td-*` / `tducks`.

## Status

**M5 accepted (with caveats)** — Waves A–F shipped. See [`docs/mvp-accept.md`](./docs/mvp-accept.md) and [`docs/post-mvp-backlog.md`](./docs/post-mvp-backlog.md).

| Layer | Choice |
|-------|--------|
| Core | Rust-first monorepo |
| Events | Signed events + per-room causal DAG |
| Crypto | vodozemac (Olm/MegOlm), 1:1 **and groups** |
| Transport | P2P-first; optional untrusted relay assist |
| Identity | Multi-device (≥2); passkeys **stubbed** as device-link (WebAuthn later) |
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
scripts/
  dev-harness.sh
```

## Dev harness

```bash
./scripts/dev-harness.sh
# optional relay: WITH_RELAY=1 ./scripts/dev-harness.sh
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

- [MVP accept checklist](./docs/mvp-accept.md)
- [Post-MVP backlog](./docs/post-mvp-backlog.md)
- [Benches](./docs/bench.md)
- [Threat model](./docs/threat-model.md)
- [Architecture](./docs/architecture.md)
- [Security policy](./SECURITY.md)

## License

[AGPL-3.0-only](./LICENSE)
