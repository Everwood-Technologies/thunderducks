# Post-MVP backlog

Prioritized work after Gate 4 Waves A–F / M5 vertical slice (`97f98ae`).

Honest MVP status: the construction plan is **shipped**. Gaps below are real; none block claiming M5 with the caveats listed.

## P0 — trust & ops (do soon)

| ID | Item | Why | Notes |
|----|------|-----|-------|
| P0.1 | **Rotate GitHub PATs** pasted in chat | Credential hygiene | Classic PAT used for `repo`+`workflow`+`read:org`; revoke old tokens in GitHub settings |
| P0.2 | **SECURITY.md** + vulnerability contact | Public AGPL repo baseline | Landed in this polish pass |
| P0.3 | Host **healthcheck** (OpenClaw box) | Operator exposure | Separate thread; pick posture Convenience/Balanced/Strict |

## P1 — product honesty gaps

| ID | Item | Why | Effort |
|----|------|-----|--------|
| P1.1 | **WebAuthn / passkeys** (replace device-link stub as primary UX) | Gate 3 identity lock; docs still say passkeys | M–L; keep device-link as recovery |
| P1.2 | **True multi-user P2P demo script** | ✅ done — `scripts/two-user-p2p.sh` + `td-node` example `two_user_p2p` | done |
| P1.3 | **Relay + P2P coexistence script** | ✅ done — `scripts/relay-offline-catchup.sh` + example `relay_offline_catchup` | done |
| P1.4 | Threat-model ↔ impl **diff pass** | Security review bar | S; annotate any drift |

## P2 — docs / public face

| ID | Item | Why |
|----|------|-----|
| P2.1 | **GitHub Pages** flip (`docs/site-and-pages.md`) | Marketing + docs URL |
| P2.2 | Expand CONTRIBUTING (widget/bot test commands, harness) | Onboarding |
| P2.3 | Protocol notes (event encoding, room membership, relay envelope) | External contributors |
| P2.4 | README badges (CI, license, pages when live) | Polish |

## P3 — engineering depth (post-MVP)

| ID | Item |
|----|------|
| P3.1 | QUIC transport (TCP framed is MVP fallback) |
| P3.2 | SSE/websocket live message push (RPC is request/response today) |
| P3.3 | Encrypted history catch-up packaging polish |
| P3.4 | Rate limits / authn on node RPC if ever non-localhost |
| P3.5 | Widget permission UX in web UI (grant/revoke UI) |
| P3.6 | Mobile / Tauri (explicitly deferred) |
| P3.7 | Metadata-privacy hardening (not MVP) |

## Suggested order

1. P0.1 PAT rotate (human)  
2. P0.2 SECURITY.md ✅  
3. P1.2/P1.3 harness glue ✅  
4. P1.4 threat-model ↔ impl diff  
5. P2.1 Pages when you want a public face  
6. P1.1 WebAuthn when identity UX matters  
7. P3.* as interest/funding allows  

## Out of scope forever (unless new Gate)

- Tokens, gas, L1, chain bus  
- Mandatory global DHT day one  
- “Production relay operator program” without separate design gate  
