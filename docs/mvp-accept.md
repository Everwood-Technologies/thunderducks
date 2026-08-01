# MVP acceptance checklist (Gate 4)

Recorded against `main` (Waves A–F + P1.2/P1.3 harness). Legend: ✅ met · ⚠️ partial/honest caveat · ❌ not met.

## Functional

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Public repo AGPL-3.0 | ✅ | `Everwood-Technologies/thunderducks`, `LICENSE` |
| Two users E2EE 1:1 via direct P2P | ✅ | `scripts/two-user-p2p.sh` / example `two_user_p2p` + Olm unit tests |
| Group E2EE ≥3 devices | ✅ | `td-crypto` Megolm 3-device fanout tests + e2ee bench |
| One user 2 linked devices converge | ✅ | Wave D sync tests + CLI/link paths |
| Relay assist ciphertext; P2P without relay | ✅ | `scripts/relay-offline-catchup.sh` + relay unit tests; sqlite plaintext-free check |
| CLI + web enroll/link → room → send/recv | ✅ | `tducks smoke` / `happy-path`; `clients/web` npm smoke |
| Demo widget + bot public API | ✅ | `widget-sdk` + `clients/bot`; CI `widgets` job |
| Automated tests: DAG, crypto, membership, relay non-plaintext | ✅ | workspace `cargo test` + widget deny tests |

## Non-goals held

| Criterion | Status |
|-----------|--------|
| No token/gas/chain dependency | ✅ |
| No mandatory global DHT | ✅ |
| No Tauri requirement | ✅ |

## Performance (honest)

| Criterion | Status | Numbers |
|-----------|--------|---------|
| Signed-event ingest ≥1k evt/s aspirational | ✅ | ~33.7k ingest/s (N=5000) on builder host — `docs/bench.md` |
| E2EE group path real numbers | ✅ | ~13.2k msg/s encrypt+2×decrypt (N=1000) |

## Security review bar

| Criterion | Status |
|-----------|--------|
| Threat model matches impl (directional) | ✅ | [`docs/threat-model-diff.md`](./threat-model-diff.md) — gaps explicit (plaintext RPC path, no Noise/TLS, passkey stub) |
| Widgets denied keys by test | ✅ | `clients/widget-sdk` security tests |
| Relays untrusted in design + tests | ✅ | opaque envelopes; no plaintext API |

## MVP claim

**M5 vertical slice: ACCEPTED with caveats.** P1.1–P1.4 + Pages landed. Default RPC message path is **Megolm**; WebAuthn ceremony on RPC; transport still raw TCP; not production-ready.

Next: `docs/post-mvp-backlog.md`, `docs/threat-model-diff.md`.
