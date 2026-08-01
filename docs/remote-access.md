# Remote access (Pond)

**Status:** first engineering slice (not production-hardened)  
**Product lock:** both **tailnet** (Tailscale-class) **and** untrusted **Thunderducks relay** — not “open WAN ports” as default.

## Goals

1. Reach a Pond from phones/laptops off-LAN without exposing admin RPC to the public internet.
2. Keep relays **untrusted assist** (ciphertext envelopes only).
3. Prefer private mesh (tailnet) for interactive RPC/UI; use relay for offline catch-up / CGNAT assist.

## Modes

| Mode | How | RPC bind | Notes |
|------|-----|----------|--------|
| **Local only** (default) | DIY install | `127.0.0.1:8788` | Safest; web on same host or SSH tunnel |
| **Tailnet / LAN** | Tailscale (or similar) + advertise host | often still loopback + reverse proxy, or `0.0.0.0` on tailnet NIC | Set `TD_ADVERTISE_HOST` to tailnet IP/DNS |
| **Relay assist** | `td-relay` + `TD_RELAY_URI` | unchanged | Opaque envelopes; **Olm per-recipient (v2)** preferred, AEAD v1 fallback (`TD_RELAY_KEY`) |

Do **not** publish `:8788` to the open internet. If you bind non-loopback, owner-session gating turns on for admin mutations.

## Environment / CLI

| Variable / flag | Purpose |
|-----------------|---------|
| `TD_BIND` / `--bind` | RPC listen (default `127.0.0.1:8788`) |
| `TD_DATA_DIR` / `--data-dir` | Durable identity + claim |
| `TD_P2P_BIND` / `--p2p-bind` | P2P listen (default `127.0.0.1:0`) — use `0.0.0.0:0` for LAN/tailnet peers |
| `TD_ADVERTISE_HOST` / `--advertise-host` | Host/IP rewritten into `rpc_base` + `p2p_uri` |
| `TD_RELAY_URI` / `--relay-uri` | Assist relay `td://host:port` or `td-noise://host:port` |
| `TD_RELAY_KEY` / `--relay-key` | Fallback shared AEAD key (v1) when Olm session missing; UTF-8 or 64-hex → blake3 |
| `TD_P2P_NOISE` / `--p2p-noise` | Advertise `td-noise://` + Noise_XX on P2P accept (default **false**) |
| `TD_P2P_QUIC` / `--p2p-quic` | Advertise `td-quic://` + QUIC accept (default **false**; takes precedence over noise) |
| `TD_TLS_CERT` / `--tls-cert` | PEM cert for **in-process HTTPS** RPC |
| `TD_TLS_KEY` / `--tls-key` | PEM private key for HTTPS RPC |
| `TD_TLS_SELF_SIGNED` / `--tls-self-signed` | Ephemeral self-signed HTTPS (dev only; default **false**) |
| `TD_REQUIRE_OWNER` / `--require-owner` | When bind is **non-loopback**, require owner session for **non-public** routes (default **true**) |
| `TD_RATE_LIMIT` / `--rate-limit` | Per-IP sliding-window rate limits (default **true**) |

```bash
# Example: node reachable on tailnet IP for URI advertising; RPC still loopback + tailscale serve/proxy preferred
export TD_DATA_DIR=/var/lib/thunderducks
export TD_ADVERTISE_HOST=100.x.y.z
export TD_P2P_BIND=0.0.0.0:0
export TD_RELAY_URI=td://relay.example:7700
export TD_RELAY_KEY='long-random-shared-secret'
# optional: TD_P2P_NOISE=true  or  TD_P2P_QUIC=true
# optional HTTPS: TD_TLS_CERT=/etc/ssl/pond.crt TD_TLS_KEY=/etc/ssl/pond.key
# dev only: TD_TLS_SELF_SIGNED=true
tducks serve --bind 127.0.0.1:8788 --data-dir "$TD_DATA_DIR"
```

Non-loopback RPC (only on trusted LAN/tailnet NIC):

```bash
tducks serve --bind 0.0.0.0:8788 --data-dir /var/lib/thunderducks \
  --advertise-host 100.x.y.z --p2p-bind 0.0.0.0:0
# owner_gate=on → claim/recovery login before pair / add-peer / link-secondary
```

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/v1/status` | Includes `rpc_base`, `p2p_uri`, `advertise_host`, `relay_uri`, `require_owner` |
| GET | `/v1/remote` | Remote/relay snapshot (same family as `/v1/p2p`) |
| POST | `/v1/relay/poll` | Fetch+ingest sealed envelopes for this device |
| POST | `/v1/relay/push` | Push outbox events sealed to linked devices via relay |

Background poller runs every ~10s when `TD_RELAY_URI` is set.

## Owner gate + rate limits (P3.4)

When `require_owner` is true (non-loopback bind + default flag):

| Class | Paths |
|-------|--------|
| **Public (no owner)** | `GET /health`, `GET /v1/status`, `GET/POST /v1/claim`, `POST /v1/recovery/login`, `GET/DELETE /v1/owner/session`, `POST /v1/pair/redeem`, `GET /v1/p2p`, `GET /v1/remote` |
| **Owner required** | Everything else: rooms, messages, peers, devices, passkeys, e2ee, sync, pair mint/list, relay push/poll |

Auth: `Authorization: Bearer <owner_token>` or `x-td-owner-token`. SSE may pass `?owner_token=` (EventSource cannot set headers).

`POST /v1/pair` always requires owner (even on loopback).

### Rate limits (per client IP, in-memory)

| Bucket | Limit |
|--------|--------|
| `POST /v1/recovery/login`, `POST /v1/claim` | 10 / 60s |
| `POST /v1/pair/redeem` | 20 / 60s |
| `messages/wait`, `messages/stream` | 120 / 60s |
| other writes | 180 / 60s |
| other reads | 600 / 60s |

Exceeding → `429` + `Retry-After`. Toggle with `TD_RATE_LIMIT=false` for local load tests only.

P2P can use **Noise_XX** (`td-noise://`) or **QUIC** (`td-quic://` / `TD_P2P_QUIC`). RPC supports **in-process HTTPS** (`TD_TLS_CERT`+`TD_TLS_KEY` or `TD_TLS_SELF_SIGNED`). Keep bind private (tailnet/LAN) even with TLS.

## Tailnet recipe (recommended)

1. Install Tailscale (or headscale) on the Pond host.
2. Keep `TD_BIND=127.0.0.1:8788`.
3. Expose UI/RPC only via tailnet ACL + `tailscale serve` / reverse proxy, **or** bind RPC to the tailnet IP only.
4. Set `TD_ADVERTISE_HOST` to the stable tailnet name/IP so pair links and `p2p_uri` are useful off-LAN.
5. Optional: run `td-relay` on a cheap VPS for offline catch-up; point `TD_RELAY_URI` at it.

## Relay recipe

```bash
# VPS
td-relay --bind 0.0.0.0:7700 --db /var/lib/td-relay/relay.sqlite

# Pond
export TD_RELAY_URI=td://relay.example.com:7700
# same TD_RELAY_PAD on peers that should open each other's demo seals
```

Honest limits:

- Relay never sees room plaintext API. Preferred device-side seal is **Olm per-recipient (v2)** after `POST /v1/e2ee/trust-keys` (or share-session which caches keys). Shared-key AEAD (`TD_RELAY_KEY`, v1) is fallback only when no Olm session exists.
- Noise_XX and QUIC available for P2P; HTTPS RPC in-process (or still terminate-at-proxy / Tailscale serve).
- Pair links still embed RPC base; use advertise host + recovery unlock on the client.
- OTA / Wi‑Fi: see [`ota-wifi.md`](./ota-wifi.md).

## Operator check

```bash
curl -s http://127.0.0.1:8788/v1/remote | jq .
curl -s http://127.0.0.1:8788/v1/status | jq '{rpc_base,p2p_uri,advertise_host,relay_uri,require_owner}'
```

## Related

- [`pond-appliance.md`](./pond-appliance.md) — product lock “remote both”
- [`install.md`](./install.md) — DIY systemd
- [`threat-model.md`](./threat-model.md) / [`threat-model-diff.md`](./threat-model-diff.md)
- [`harness.md`](./harness.md) — P1.3 relay offline catch-up
