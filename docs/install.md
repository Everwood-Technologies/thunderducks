# Install Thunderducks node (Pond DIY)

Linux **amd64** and **arm64**. This is the packaging foundation for **Thunderducks Pond** (appliance image later uses the same unit + binary).

## Quick install (release binary)

After a GitHub Release `v*` exists:

```bash
curl -fsSL https://raw.githubusercontent.com/Everwood-Technologies/thunderducks/main/scripts/install-tducks.sh | sudo bash
```

Pin a version:

```bash
curl -fsSL https://raw.githubusercontent.com/Everwood-Technologies/thunderducks/main/scripts/install-tducks.sh \
  | sudo TDUCKS_VERSION=v0.1.0 bash
# or
sudo ./scripts/install-tducks.sh --version v0.1.0
```

What it does:

1. Creates system user `tducks`
2. Installs `/usr/bin/tducks`
3. Creates `/var/lib/thunderducks` (data) + `/etc/thunderducks/tducks.env`
4. Installs systemd unit `tducks.service`, enables + starts it
5. Default RPC bind: **`127.0.0.1:8788`** (loopback only)

## Build from source (this repo)

```bash
cargo build -p tducks --release
sudo ./scripts/install-tducks.sh --from-file ./target/release/tducks
```

Cross-check:

```bash
systemctl status tducks
curl -s http://127.0.0.1:8788/health
tducks --rpc http://127.0.0.1:8788 status
```

## systemd

Unit template: [`packaging/systemd/tducks.service`](../packaging/systemd/tducks.service)

```bash
sudo systemctl status tducks
sudo journalctl -u tducks -f
sudo systemctl restart tducks
```

### Bind address

Default is loopback (safe). For LAN clients (Pond-like):

```bash
# /etc/thunderducks/tducks.env
TD_BIND=0.0.0.0:8788
```

```bash
sudo systemctl restart tducks
# firewall: allow only trusted LAN — do not expose admin RPC to WAN
```

## Release artifacts

GitHub Actions [`.github/workflows/release.yml`](../.github/workflows/release.yml):

| Trigger | Result |
|---------|--------|
| Push tag `v*` (e.g. `v0.1.0`) | Build **linux gnu amd64 + arm64**, attach `.tar.gz` to Release |
| `workflow_dispatch` | Build artifacts only (snapshot) |

Tarball name:

```text
tducks-<tag>-x86_64-unknown-linux-gnu.tar.gz
tducks-<tag>-aarch64-unknown-linux-gnu.tar.gz
```

Contents: `tducks` binary, unit file, env example, install script, README.

### Cut a release

```bash
git tag v0.1.0
git push origin v0.1.0
# wait for Actions "release" workflow → GitHub Release assets
```

## Uninstall

```bash
sudo systemctl disable --now tducks
sudo rm -f /etc/systemd/system/tducks.service /usr/bin/tducks
sudo systemctl daemon-reload
# keep or wipe data:
# sudo rm -rf /var/lib/thunderducks /etc/thunderducks
# sudo userdel tducks
```

## Pond appliance

Retail/image path uses this same binary + unit. See [`pond-appliance.md`](./pond-appliance.md).

## First-run claim + pairing (web)

With a node running and the web client pointed at it (`?rpc=`):

1. Unclaimed node → **Claim Pond** wizard (name + one-time recovery code).
2. Claimed node → chat UI; **Pair device** mints a 10-minute token/link (`?pair=`).
3. Other device opens the pair link → redeem → continue to chat.

| Method | Path | Purpose |
|--------|------|---------|
| GET/POST | `/v1/claim` | Status / claim owner (mints owner session on claim) |
| POST | `/v1/recovery/login` | Unlock with recovery code → owner session token |
| GET/DELETE | `/v1/owner/session` | Check / revoke owner session (`Authorization: Bearer`) |
| GET/POST | `/v1/pair` | List / mint pair token (**POST requires owner session**) |
| POST | `/v1/pair/redeem` | Redeem pair token |

Recovery code is shown **once** at claim; only a hash is stored on the node.

### Recovery login (owner session)

1. Claim (or later: enter recovery code) → node returns `owner_token` (24h, in-memory).
2. Web stores it in `sessionStorage`; send as `Authorization: Bearer <token>` or `x-td-owner-token`.
3. **Pair device** mint requires a valid owner session (chat/list still open on localhost trust model).
4. Restart wipes sessions → unlock again with the recovery code (`?unlock=1` forces the UI).
5. Failed logins: 5 strikes → 60s lockout (in-memory).

### Durable claim + identity

With `TD_DATA_DIR` / `--data-dir` (systemd default: `/var/lib/thunderducks`):

| File | Contents |
|------|----------|
| `identity.key` | 32-byte ed25519 seed (mode `0600`) — stable device id across restarts |
| `claim.json` | Owner claim: display name + recovery **hash** only (no plaintext code) |

```bash
tducks serve --bind 127.0.0.1:8788 --data-dir /var/lib/thunderducks
# or: TD_DATA_DIR=/var/lib/thunderducks tducks serve --bind 127.0.0.1:8788
```

Without a data dir, claim/identity stay **in-memory** (tests / smoke only).

Pair tokens remain short-lived and in-memory by design.

**Still later Pond phases:** full RPC authn (not just pair mint), OTA, Wi‑Fi wizard, tailnet/relay UX.

## Security notes

- DIY default: RPC on **localhost only**
- Service runs as unprivileged `tducks` with systemd hardening flags
- Do **not** publish `:8788` to the public internet without authn (still open backlog item)
