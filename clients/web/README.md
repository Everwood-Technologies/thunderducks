# Thunderducks web client

TypeScript client (Wave E). Talks to a local `td-node` HTTP RPC on localhost.

## Quick start

```bash
# terminal 1 — node RPC
cargo run -p tducks -- serve --bind 127.0.0.1:8788

# terminal 2 — build + smoke test (spawns its own serve)
cd clients/web
npm install
npm test
```

Open `index.html` (after `npm run build`) with `?rpc=http://127.0.0.1:8788` for a minimal UI.

## RPC surface

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | liveness |
| GET | `/v1/status` | device + rooms |
| POST | `/v1/devices/link-secondary` | multi-device link |
| POST | `/v1/peers` | remember peer URI |
| POST | `/v1/rooms` | create room |
| POST | `/v1/messages` | send text |
| POST | `/v1/messages/list` | recv/list |

Passkeys are stubbed as device-link for MVP; full WebAuthn lands later.
