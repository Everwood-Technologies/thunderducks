# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| `main` (0.x MVP) | Best-effort — pre-production research software |

Thunderducks is **not** production-hardened. Treat all releases before a future stable tag as experimental.

## Threat model

See [`docs/threat-model.md`](./docs/threat-model.md). Design priority:

1. Malicious operator / relay  
2. Network observer  
3. Malicious bot / widget  
4. Compromised device  

Relays are **untrusted assist only** (opaque ciphertext). Widgets are **deny-by-default** and must never receive key material.

## Reporting a vulnerability

**Do not** open a public GitHub issue for sensitive reports.

Preferred:

1. Email the Everwood Technologies maintainers via the contact listed on the GitHub org, **or**
2. Open a **private** security advisory on the GitHub repo (Security → Advisories → New draft), **or**
3. Contact the primary maintainer (`mlwood-dev` on GitHub) with a non-exploit summary and a way to coordinate details.

Include:

- Affected commit/tag if known  
- Impact (key exposure, plaintext leak, auth bypass, RCE, etc.)  
- Minimal reproduction **without** a full public exploit chain when possible  
- Whether you plan to disclose and on what timeline  

We will acknowledge when we can and work toward a fix or honest “won’t fix / out of scope for MVP” response.

## Non-goals for reporters

- Issues that require physical access or an already-compromised device end-state (still useful feedback; lower severity for MVP)  
- Social engineering of individual users  
- DDoS against third-party infrastructure  

## Safe harbor

Good-faith research that avoids privacy violations, data destruction, and service degradation is welcome. Do not access other users’ data or pivot beyond the test surface.

## Cryptography

We rely on **vodozemac** and well-known primitives rather than home-grown ratchets. Crypto design review is always appreciated; please flag API misuse, not just primitive novelty.
