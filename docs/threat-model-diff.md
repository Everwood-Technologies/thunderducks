# Threat model ↔ implementation diff (P1.4)

**Date:** 2026-08-01  
**Against:** `docs/threat-model.md` + `docs/architecture.md`  
**Code HEAD at write:** `55b7a78` (update if stale)  
**Verdict:** **Directional match with material honesty gaps.** No known contradiction that invalidates M5. Not production-ready.

Legend: ✅ met · ⚠️ partial / MVP-honest gap · ❌ missing / contradicts model

---

## Review checklist (from threat model)

| Check | Status | Evidence |
|-------|--------|----------|
| Can a relay read or forge content? | ⚠️ | **Cannot forge** signed user events (no signing keys). **Cannot read room plaintext via API** (opaque `RelayEnvelope` only). MVP seal for harness/sync is **XOR-pad over signed-event JSON** (`DeviceNode::seal_for_relay`) — fine for “relay DB has no plaintext marker” tests, **not** a claim of production E2EE-at-rest to a curious relay operator who stores ciphertext. Real path should wrap Megolm/Olm ciphertext before put. |
| Can a widget touch keys? | ✅ | `FORBIDDEN_PERMISSIONS` + hard deny on `keys.*` / private / signing in `clients/widget-sdk`; CI security tests. Host API surface has no key accessors. |
| Happy path P2P without relay? | ✅ | `two_user_p2p` example + unit P2P framed exchange; relay optional in harness. |
| New metadata leaks documented? | ⚠️ | This doc; residual risks below. |

---

## Priority threats

### 1. Malicious / compromised operator or relay — highest

| Control in model | Impl status | Notes |
|------------------|-------------|-------|
| Content E2EE; relays see envelopes only | ⚠️ | Relay store/API: ciphertext blobs only (`td-relay`). **RPC send path stores plaintext JSON `{"text":...}` in signed event payload** — E2EE library exists (`td-crypto` vodozemac) and is tested, but **node RPC / CLI / web happy path do not encrypt payloads before commit**. Confidentiality vs relay holds only if clients put sealed envelopes; local node and anyone with RPC see plaintext. |
| Operators untrusted for confidentiality & authenticity of content | ✅ / ⚠️ | Authenticity: signatures + verify on ingest. Confidentiality: see above. |
| Zero-relay path when peers online | ✅ | P2P framed TCP; P1.2 operator demo. |
| Relays cannot mint valid user events | ✅ | No relay signing; verify_event on ingest. |
| Tests: relay DB/API no plaintext | ✅ | Unit + P1.3 sqlite marker check. |

**Residual (model):** metadata, traffic analysis, DoS by drop/delay — **unchanged; accepted for MVP.**

**New residual (impl):**
- Localhost RPC is **unauthenticated** and CORS `Any` — fine only if bound to loopback and never exposed.
- Relay rate-limit is per-sender device id (best-effort DoS cushion, not availability SLA).

### 2. Network observer

| Control in model | Impl status | Notes |
|------------------|-------------|-------|
| Transport auth (Noise/TLS) separate from content E2EE | ❌ / ⚠️ | **Not implemented.** `td-net` is length-prefixed JSON frames on **raw TCP**. Comment in crate: “QUIC/Noise come later.” |
| Ciphertext payloads on the wire for message content | ⚠️ | P2P currently ships **signed events with plaintext payloads** on the wire in demos/RPC path. E2EE ciphertext types exist for Olm/Megolm but are not the default wire format for CLI/web. |
| Prefer direct P2P | ✅ | Design + demos. |

**Residual:** IP correlation, peer URI leakage — **yes, worse than model hoped** until transport auth + payload E2EE on default path.

### 3. Malicious bot / widget

| Control in model | Impl status | Notes |
|------------------|-------------|-------|
| iframe + postMessage; deny-by-default | ✅ | `widget-sdk` protocol `td-widget-v1`. |
| Never E2EE keys / Megolm sessions to widgets | ✅ | Hard deny + tests. |
| Bots: public API only, least privilege | ⚠️ | Bot uses same `/v1/messages` as users (no separate bot ACL). **No key export** in bot client. Anyone who can hit RPC can post/list — acceptable only for localhost trust model. |
| Widget cannot read keys / other-origin room plaintext | ✅ / ⚠️ | Keys: tested. Cross-room: host must only grant room ids it intends; demo grants `room.send`/`room.read` for a chosen room — not a full multi-room isolation matrix in CI. |

**Residual:** over-broad grants; host XSS — **still on host author.**

### 4. Compromised end device

| Control in model | Impl status | Notes |
|------------------|-------------|-------|
| Passkeys reduce phishing | ⚠️ | **Stubbed** as local device-link; WebAuthn not shipped (P1.1). |
| Per-device keys; link needs existing-device approval | ✅ | `td-crypto` `LinkRegistry` approve flow; RPC `link-secondary`. |
| Honest limits: full disk beats app E2EE | ✅ | Documented in model; still true. |

---

## Architecture locks vs code

| Lock | Status | Drift |
|------|--------|-------|
| Rust-first + TS web/widget | ✅ | Matches monorepo. |
| vodozemac Olm/Megolm | ⚠️ | Library + tests/benches; **not default on RPC send/list path**. |
| Signed events + per-room DAG | ✅ | `td-event` + `DeviceNode`. |
| P2P-first QUIC bias | ⚠️ | **TCP framed only**; QUIC backlog P3.1. |
| Relays untrusted assist | ✅ | Opaque envelopes + optional. |
| Passkeys + multi-device ≥2 | ⚠️ | Multi-device yes; passkeys stub. |
| Local node RPC | ✅ | axum HTTP JSON; no SSE yet (P3.2). |
| Widgets deny-by-default | ✅ | |
| SQLite embedded | ⚠️ | Relay uses SQLite; event store trait/SQLite in `td-event`; node runtime is largely in-memory DAG for MVP RPC process lifetime. |
| No tokens/chain | ✅ | |

---

## Trust boundary diagram — honesty update

```
[Passkey authenticator]     ← not wired (device-link stub)
        │
[Device td-node / RPC] ── signed events (payload often PLAINTEXT today) ── [Peer]
        │ plaintext at RPC and in-process node
   ┌────┴────┐
   │ widget  │  sandboxed; no keys ✅
   └─────────┘
        │ optional RelayEnvelope ciphertext (seal quality = client responsibility)
   [td-relay]  no plaintext API ✅; no transport TLS ❌
```

---

## Severity-ranked gaps (actionable)

| Sev | Gap | Suggested follow-up |
|-----|-----|---------------------|
| **High** (prod) | RPC/CLI/web message path does not apply Olm/Megolm to payloads | Wire `td-crypto` into send/recv before any non-localhost deploy |
| **High** (prod) | No Noise/TLS/QUIC on P2P or relay TCP | P3.1 + transport auth spike |
| **High** (ops) | RPC unauthenticated + CORS Any | Bind loopback only (document); authn if ever remote (P3.4) |
| **Med** | Passkeys stubbed | P1.1 WebAuthn |
| **Med** | Relay seal XOR demo-grade | Document + replace with real E2EE ciphertext wrap |
| **Med** | Bot shares user message API | Optional bot token / capability scope later |
| **Low** | Widget cross-room isolation matrix thin | Extra host tests with two rooms |
| **Low** | In-memory node vs “SQLite store” lock | Persist `DeviceNode` to SQLite for crash safety |

---

## What is solid (keep)

- Event signatures + verify on ingest  
- Room membership helpers reject evil join/ban paths in `td-event` tests  
- Multi-device link approval cryptography  
- Relay non-plaintext API + rate limit + P1.3 operator proof  
- Widget key denial tests in CI  
- P2P-without-relay operator proof (P1.2)  
- Group E2EE primitive tests (3-device Megolm fanout) even if not default UX path  

---

## MVP claim impact

| mvp-accept row | After P1.4 |
|----------------|------------|
| Threat model matches impl (directional) | ✅ **with this diff published** — gaps explicit, not silent |
| Relays untrusted | ✅ remains (API/DB); seal quality caveat documented |
| Widgets denied keys | ✅ unchanged |

**M5 remains accepted with caveats.** Stronger caveat language: **default product path is signed plaintext events over localhost RPC and raw TCP P2P; vodozemac is implemented and tested but not the default wire path for CLI/web yet.**

---

## Sign-off

- Diff performed against threat model priority order and architecture locks.  
- No change to cryptographic libraries required for this doc-only pass.  
- Next engineering priority if hardening: **encrypt event payloads on send** + **transport auth**, then WebAuthn.
