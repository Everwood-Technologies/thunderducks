# Thunderducks

Event-driven, maximally decentralized hybrid P2P **E2EE** chat — no tokens, no blockchain bus.

> Codename is intentionally ridiculous. Protocol crates use `td-*` / `tducks`.

## Status

**MVP construction** — Waves A–D landed (events, identity, P2P, E2EE, rooms, relay assist, multi-device sync). Wave E next (CLI + web).

| Layer | Choice |
|-------|--------|
| Core | Rust-first monorepo |
| Events | Signed events + per-room causal DAG |
| Crypto | vodozemac (Olm/MegOlm), 1:1 **and groups** |
| Transport | P2P-first; optional untrusted relay assist |
| Identity | Passkeys + multi-device (≥2) |
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
  web/          TS client (soon)
  widget-sdk/   JS SDK (soon)
docs/
  threat-model.md
  architecture.md
```

## Quick start

```bash
# Rust 1.75+ recommended
cargo test --workspace
cargo run -p tducks
```

## Non-goals (MVP)

- Tokens, gas, L1 consensus, smart contracts
- Mandatory global DHT
- Tauri / mobile store apps
- Perfect metadata privacy

## License

[AGPL-3.0-only](./LICENSE)
