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

Open `index.html` (after `npm run build`). Defaults to **same-origin** (for nginx reverse-proxy). Local override: `?rpc=http://127.0.0.1:8788`.

## RPC surface

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | liveness |
| GET | `/v1/status` | device + rooms |
| POST | `/v1/devices/link-secondary` | multi-device link |
| POST | `/v1/peers` | remember peer URI |
| POST | `/v1/rooms` | create room |
| POST | `/v1/messages` | send text (Megolm-encrypted payload) |
| POST | `/v1/messages/list` | recv/list (decrypt on node) |
| POST | `/v1/passkeys/register/begin` | WebAuthn creation options |
| POST | `/v1/passkeys/register/finish` | store credential |
| POST | `/v1/passkeys/auth/begin` | WebAuthn request options |
| POST | `/v1/passkeys/auth/finish` | verify assertion |
| GET | `/v1/passkeys` | list credentials |

Messages on `/v1/messages` are **Megolm-encrypted** by default (node decrypts for list).

Passkeys: RPC `/v1/passkeys/*` supports WebAuthn register/auth ceremony (ES256).
Browser `navigator.credentials` UI can call begin/finish; device-link remains for multi-device.
