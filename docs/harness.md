# Operator harness

Runnable multi-process demos for MVP acceptance gaps P1.2 / P1.3.

## Scripts

| Script | What it proves |
|--------|----------------|
| `./scripts/two-user-p2p.sh` | **P1.2** — two distinct device identities exchange signed events over real localhost TCP P2P (no shared memory, no relay) |
| `./scripts/relay-offline-catchup.sh` | **P1.3** — Bob offline → Alice puts **opaque** envelope on real `td-relay` → Bob fetch/open/ack → later **direct P2P** without relay; sqlite must not contain plaintext marker |
| `./scripts/dev-harness.sh` | Full smoke (RPC + CLI + bot) and, by default, both P1 demos (`WITH_P1=0` to skip) |
| `./scripts/multi-node-web.sh` | **3 nodes + web UI** — Alice/Bob/Cara on `:8788-8790`, shared Megolm room, static web on `:8090` |

## Examples (Rust)

```bash
cargo run -p td-node --example two_user_p2p
cargo build -p td-relay
cargo run -p td-node --example relay_offline_catchup
```

## Env

| Var | Default | Meaning |
|-----|---------|---------|
| `WITH_P1` | `1` | Run P1.2/P1.3 inside `dev-harness.sh` |
| `WITH_RELAY` | `0` | Also start a long-lived harness relay on `RELAY_BIND` |
| `RPC_BIND` | `127.0.0.1:8788` | Node RPC |
| `RELAY_BIND` | `127.0.0.1:7700` | Long-lived harness relay |
| `TD_RELAY_BIN` | `target/debug/td-relay` | Override relay binary for P1.3 |

## Multi-node web demo (3 devices)

```bash
./scripts/multi-node-web.sh
# Ctrl-C stops all three nodes + static web
# one-shot bootstrap without keep-alive:
KEEP_ALIVE=0 ./scripts/multi-node-web.sh
```

Starts Alice/Bob/Cara on `127.0.0.1:8788-8790`, creates a shared room, shares Megolm session keys, proves group decrypt, serves `clients/web` on `:8090`.

Endpoints written to `/tmp/td-multi-node/endpoints.json`.

Open three tabs from that file’s `web` URLs (or `?rpc=&room=&name=`).

New RPC used by the demo:

- `POST /v1/sync/peer` — bidirectional DAG sync with peer HTTP RPC
- `POST /v1/e2ee/share-session` — export Megolm session key to peer (localhost demo path)
- auto P2P listener on each node (`status.p2p_uri`); send fans out framed events best-effort

## Notes

- P2P path is length-prefixed framed events on TCP (`td://host:port`). QUIC later.
- Relay outer layer is opaque ciphertext at rest; MVP seal is XOR-pad over signed-event JSON (same as unit tests) — not a claim of production E2EE-at-rest on the wire to the relay beyond “relay never sees room plaintext API”.
- Megolm room keys are **Olm-wrapped** on fanout/share (`GET /v1/e2ee/olm-keys`, `POST /v1/e2ee/import-olm`, `POST /v1/e2ee/share-session` path=olm). Plaintext `import-session` remains as a legacy/compat path only.
- **send-just-works (P0):** `POST /v1/messages` auto-shares the room Megolm session and delta-ingests to every peer with an HTTP `rpc` endpoint (`fanout_ok` / `fanout_peers` in the response). Register peers with `rpc` (not only `td://` P2P) for reliable multi-node decrypt.
- **shared room Megolm (B2):** one outbound Megolm session per room. Fanout delivers an Olm-wrapped `RoomOutboundPackage` (pickle + inbound session_key). Peers import outbound so **any member can encrypt with the same `session_id`**; first-writer wins if sessions diverge; ratchet only advances (never regresses). Import path: `olm-room-outbound` (legacy inbound-only `olm` still accepted).
- **live SSE (A2 / P3.2):** `GET /v1/messages/stream?room_id=…` Server-Sent Events — `snapshot` then `messages` on change (15s keep-alive). Web UI uses EventSource by default (`?live=0` off, `?live=poll` long-poll fallback). Background peer sync still runs so fan-in from other nodes reaches the local DAG and wakes SSE.
- **live long-poll (compat):** `POST /v1/messages/wait` `{ room_id, since_count, timeout_ms }` still works; now notify-driven (not 200ms busy-poll).
