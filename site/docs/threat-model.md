# Threat Model — Thunderducks MVP

**Status:** Construction baseline (AIDLC Gates 0–4)  
**Priority order** is intentional; design and tests must respect it.

## Assets

| Asset | Sensitivity |
|-------|-------------|
| Message plaintext (1:1 and group) | Critical |
| E2EE keys (device, Olm/MegOlm sessions) | Critical |
| User/device identity bindings | High |
| Membership / room graph | Medium–High (metadata) |
| Relay-stored ciphertext envelopes | Medium (traffic analysis) |
| Widget-accessible APIs | High if over-privileged |

## Actors

1. **Honest user / honest device**
2. **Network observer** (passive or active on-path)
3. **Malicious or compromised relay / federated operator**
4. **Malicious peer** (protocol-speaking adversary)
5. **Malicious bot / widget**
6. **Thief with unlocked/compromised end device**

## Priority threats (MVP)

### 1. Malicious or compromised operator / relay (highest)

**Goal of adversary:** read content, forge messages, selectively drop/reorder to break availability or confuse state.

**Controls:**
- Content is E2EE end-to-end; relays see envelopes only.
- Operators are **untrusted for confidentiality and authenticity of content**.
- Protocol must work **with zero relays** when peers are online (P2P-first).
- Event integrity via signatures + per-room DAG; relays cannot mint valid user events.
- Tests: relay DB / API must not expose plaintext.

**Residual risk:** metadata (who talks to whom, sizes, timing), traffic analysis, DoS by drop/delay.

### 2. Network observer

**Goal:** recover plaintext or long-term identity graphs from transit.

**Controls:**
- Transport auth (Noise/TLS) separate from content E2EE.
- Ciphertext payloads on the wire for message content.
- Prefer direct P2P to avoid standing third-party hops when possible.

**Residual risk:** IP-level correlation, peer URI leakage, mDNS on LAN.

### 3. Malicious bot / widget

**Goal:** exfiltrate plaintext or keys from the client host.

**Controls:**
- iframe + postMessage JS SDK; **deny-by-default** permission manifest.
- Widgets **never** receive E2EE keys or raw MegOlm sessions.
- Bots use public bot/event APIs only, least privilege.
- Automated test: widget cannot read keys or other-origin room plaintext.

**Residual risk:** user-granted over-broad permissions; XSS in host if host is sloppy (host hardening required).

### 4. Compromised end device

**Goal:** full account takeover / history read.

**Controls:**
- Passkeys reduce phishing of “password to network.”
- Per-device keys; linking requires existing-device approval.
- Document honest limits: full disk compromise beats app-level E2EE.

**Residual risk:** malware with user-session access reads plaintext at rest in client DB.

## Non-goals (MVP honesty)

- Perfect metadata privacy / global mixnets
- Resistance to nation-state global passive adversary at internet scale
- Secure element / remote attestation requirements
- Formal verification of full stack

## Trust boundaries

```
[Passkey authenticator] 
        │
[Device td-node] ──E2EE── [Peer device]
        │ plaintext only here
   ┌────┴────┐
   │ widget  │  (sandboxed, no keys)
   └─────────┘
        │ ciphertext envelopes only
   [optional relay / federated assist]
```

## Multi-device notes

- Peer ≈ **device**, not human.
- Compromising one device compromises that device’s keys and any keys it holds; revoke/link flows are Wave C/D work items.
- History catch-up is encrypted to the new device; relays still only see ciphertext.

## Review checklist (every wave)

- [x] Can a relay read or forge content? (must be no) — see `docs/threat-model-diff.md` (forge: no; plaintext API: no; seal quality caveat)
- [x] Can a widget touch keys? (must be no) — widget-sdk CI
- [x] Does happy path still work P2P without relay? — P1.2 harness
- [x] Are new metadata leaks documented? — `docs/threat-model-diff.md` (P1.4)

Full impl diff: [`docs/threat-model-diff.md`](./threat-model-diff.md).
