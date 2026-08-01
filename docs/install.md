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

**Not in this slice:** first-run claim UI, OTA, Wi‑Fi wizard, tailnet/relay UX (later Pond phases).

## Security notes

- DIY default: RPC on **localhost only**
- Service runs as unprivileged `tducks` with systemd hardening flags
- Do **not** publish `:8788` to the public internet without authn (still open backlog item)
