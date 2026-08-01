# MVP acceptance checklist (Gate 4)

Recorded against `main` @ **97f98ae** (Waves A–F). Legend: ✅ met · ⚠️ partial/honest caveat · ❌ not met.

## Functional

| Criterion | Status | Evidence |
|-----------|--------|----------|
| Public repo AGPL-3.0 | ✅ | `Everwood-Technologies/thunderducks`, `LICENSE` |
| Two users E2EE 1:1 via direct P2P | ⚠️ | P2P framed path + Olm tests; operator multi-process 2-user demo still thin (P1.2) |
| Group E2EE ≥3 devices | ✅ | `td-crypto` Megolm 3-device fanout tests + e2ee bench |
| One user 2 linked devices converge | ✅ | Wave D sync tests + CLI/link paths |
| Relay assist ciphertext; P2P without relay | ⚠️ | Relay opaque envelope + unit tests; full offline→online script glue is P1.3 |
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
| Threat model matches impl (directional) | ⚠️ | Needs explicit diff pass (P1.4); no known contradiction |
| Widgets denied keys by test | ✅ | `clients/widget-sdk` security tests |
| Relays untrusted in design + tests | ✅ | opaque envelopes; no plaintext API |

## MVP claim

**M5 vertical slice: ACCEPTED with caveats** (P2P multi-user operator script, relay coexistence script, WebAuthn stub, threat-model diff). Not production-ready.

Next: `docs/post-mvp-backlog.md`.
