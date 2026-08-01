# Architecture — Thunderducks MVP

**Status:** Construction baseline from AIDLC Gate 3 design locks  
**Codename:** Thunderducks · **Repo:** `Everwood-Technologies/thunderducks` · **License:** AGPL-3.0-only

## One-liner

Event-driven, maximally decentralized hybrid P2P E2EE chat mesh with developer-first widgets — **no tokens, no blockchain bus**.

## Design locks (summary)

| # | Topic | Lock |
|---|--------|------|
| 1 | Language | Rust-first core + CLI; TS web/widget only |
| 2 | E2EE | vodozemac (Olm/MegOlm); groups in MVP |
| 3 | Events | Signed events + per-room causal DAG |
| 4 | Transport | P2P-first (QUIC bias); manual/QR + optional mDNS |
| 5 | Relays | Untrusted assist only; zero-relay path required |
| 6 | Identity | Passkeys + multi-device (≥2); CLI browser-assisted link |
| 7 | TS bridge | Local node RPC first; WASM later |
| 8 | Clients | CLI + web; no Tauri in MVP |
| 9 | Widgets | iframe + JS SDK; deny-by-default |
| 10 | Layout | Cargo workspace monorepo (this tree) |
| 11 | Store | SQLite embedded |
| 12 | Bar | Multi-device E2EE slice + honest benches |

## Decentralization ladder

1. Direct **P2P** event exchange (best)
2. User/community **relays** (assist)
3. Federated operator nodes (interop + catch-up)
4. **Never:** global validator set or paid token bus

## Component map

```text
crates/
  td-event/    signed event codec, DAG, store traits + SQLite
  td-crypto/   device keys, vodozemac wrappers
  td-net/      dial/listen, framed exchange, peer URI
  td-node/     runtime, local RPC, orchestration
  td-cli/      tducks binary
relays/
  td-relay/    optional store-and-forward (ciphertext only)
clients/
  web/         TypeScript UI
  widget-sdk/  iframe postMessage SDK
```

## Event model

- Canonical unit: **signed application event**
- Per-room **causal DAG** (hash-linked parents)
- Content-addressed ids; idempotent ingest
- Ciphertext in payload blob; plaintext only on devices after E2EE
- **Not** a blockchain: no global consensus, mempool, gas, or L1 SDK

## E2EE

- Library: **vodozemac**
- 1:1 Olm sessions → MegOlm-style **group** sessions in MVP
- Device fanout under each user
- Relays never hold session keys

## Transport

- Primary: direct peer connection (QUIC preferred; TCP fallback acceptable in spikes)
- Transport auth ≠ content E2EE (Noise/TLS class)
- Discovery MVP: manual peer URI/QR; optional LAN mDNS
- No mandatory global DHT day one

## Identity & multi-device

- User root: passkey / WebAuthn (target); **MVP uses device-link stub** until WebAuthn lands
- Per-device identity + E2EE keys
- New device: approve from existing device; encrypted history catch-up
- CLI: browser-assisted link flow

## Clients

- **CLI (`tducks`):** developer and headless paths
- **Web TS:** rooms UX + device-link; talks to **local `td-node` RPC** (HTTP JSON; SSE later)
- Tauri deferred

## Widgets & bots

- Host: iframe + postMessage
- Permission manifest default deny
- No key material to widgets
- Bots: public API only

## Construction waves (Gate 4)

```
A foundation → B event/identity/net → C e2ee/rooms → D relay/sync → E clients → F widgets/harness
```

See AIDLC session artifacts for full plan and acceptance criteria.

## References

- `docs/threat-model.md`
- AIDLC session (operator workspace): gates 0–4 locked under session `d7b503bb-8032-427f-9e58-49033baf68c9`

## Public site (planned)

Docs + marketing will ship via **GitHub Pages** when ready. See `docs/site-and-pages.md`. Not on the critical path for Waves B–F.
