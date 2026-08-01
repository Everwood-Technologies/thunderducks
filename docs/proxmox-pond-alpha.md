# Proxmox Pond alpha guest (KVM / LXC)

Spin up an Ubuntu guest on **Proxmox VE**, install **Thunderducks Pond** (`tducks`), and serve the web UI with **nginx** (static files + reverse-proxy to loopback RPC).

## What you get

```text
Proxmox host
  └─ CT/VM pond-alpha (Ubuntu 24.04)
       ├─ tducks.service     → 127.0.0.1:8788  (not LAN-exposed)
       ├─ nginx :80          → /var/www/pond + proxy /v1 + /health
       └─ /var/lib/thunderducks  (claim, identity, events.sqlite, e2ee.json, OTA state)
```

Browser opens **`http://<guest-ip>/`** — same-origin API (no `?rpc=` needed).

## Prerequisites (PVE host)

- Root shell on Proxmox
- Bridge (default `vmbr0`) with DHCP or a static `--ipconfig`
- Storage for rootfs (e.g. `local-lvm`) + template storage (e.g. `local`)
- Outbound HTTPS for GitHub release + raw content
- **LXC:** `pct`, `pveam`
- **KVM:** `qm`, Ubuntu cloud image, **qemu-guest-agent** path for auto-bootstrap

## One-shot (recommended: LXC)

From this repo on the PVE host (or curl the script):

```bash
# copy or:
curl -fsSL https://raw.githubusercontent.com/Everwood-Technologies/thunderducks/main/scripts/proxmox-pond-create.sh \
  -o /tmp/proxmox-pond-create.sh
chmod +x /tmp/proxmox-pond-create.sh

sudo /tmp/proxmox-pond-create.sh \
  --type lxc \
  --id 120 \
  --hostname pond-alpha \
  --bridge vmbr0 \
  --storage local-lvm \
  --template-storage local \
  --version v0.1.0-alpha.2
```

Then open the printed `http://<ip>/` URL → **claim** → save recovery code offline → **snapshot**.

> **Pin `v0.1.0-alpha.2+`** for rooms/messages that survive reboot. `alpha.1` only persisted claim/identity.

### Useful flags

| Flag | Meaning |
|------|---------|
| `--type lxc\|kvm` | Guest kind (default **lxc**) |
| `--id N` | CT/VM id |
| `--force` | Destroy existing id first |
| `--password SECRET` | root (LXC) / cloud-init (KVM) password (default `pond1`, min 5 chars) |
| `--ssh-key ~/.ssh/id_ed25519.pub` | Install pubkey |
| `--ipconfig ip=192.168.1.50/24,gw=192.168.1.1` | Static net |
| `--no-bootstrap` | Create only; print/run guest script yourself |
| `--print-bootstrap` | Print guest install script only |
| `--version v0.1.0-alpha.1` | Pin Pond release (required for prereleases) |
| `--cloudimg /path/to/noble-server-cloudimg-amd64.img` | **KVM required** |
| `--memory 2048 --cores 2 --disk 16` | Resources |

## KVM notes

```bash
# Example: download Ubuntu 24.04 cloud image on PVE
mkdir -p /var/lib/vz/template/iso
curl -L -o /var/lib/vz/template/iso/noble-server-cloudimg-amd64.img \
  https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img

sudo ./scripts/proxmox-pond-create.sh \
  --type kvm \
  --id 121 \
  --hostname pond-kvm \
  --bridge vmbr0 \
  --storage local-lvm \
  --cloudimg /var/lib/vz/template/iso/noble-server-cloudimg-amd64.img \
  --version v0.1.0-alpha.1
```

Auto-bootstrap uses **`qm guest exec`** (qemu-guest-agent). If the agent never comes up, the script prints the guest bootstrap command — SSH in and run it.

Prefer **LXC** for fastest alpha; use **KVM** when you want closer-to-appliance (full systemd, OTA restart behavior, etc.).

## Guest-only bootstrap

If the CT/VM already exists:

```bash
# on guest as root
curl -fsSL https://raw.githubusercontent.com/Everwood-Technologies/thunderducks/main/scripts/pond-guest-bootstrap.sh \
  | sudo TDUCKS_VERSION=v0.1.0-alpha.1 bash
```

This installs:

1. `tducks` via `install-tducks.sh` (systemd + data dir + OTA path unit)
2. nginx site [`packaging/nginx/pond-ui.conf`](../packaging/nginx/pond-ui.conf)
3. Built web client under `/var/www/pond` (fetch sources from GitHub + `tsc`)

## Security posture

| Surface | Default |
|---------|---------|
| `tducks` RPC | **127.0.0.1:8788** only |
| nginx | **:80** on guest NIC (LAN) |
| WAN | **Do not** port-forward :80/:8788 to the internet |
| Remote | Tailscale on guest or PVE later; see [`remote-access.md`](./remote-access.md) |
| Password | Change default `pond1` immediately |

Non-loopback access to admin APIs goes through nginx → still hits loopback tducks; **owner session** rules apply based on tducks bind (loopback remains trust-local for most routes). For stricter alpha, put the guest on a management VLAN / tailnet only.

## Alpha checklist

1. `curl -s http://<ip>/health` → ok  
2. Open UI → claim → store recovery code offline  
3. Snapshot guest  
4. Reboot guest → still claimed, same device id  
5. Recovery unlock after restart (sessions are in-memory)  
6. Optional: OTA apply + rollback drill  
7. Optional: Tailscale; set `TD_ADVERTISE_HOST`  

## Scripts

| Script | Where | Role |
|--------|--------|------|
| [`scripts/proxmox-pond-create.sh`](../scripts/proxmox-pond-create.sh) | **PVE host** | Create LXC/KVM + run bootstrap |
| [`scripts/pond-guest-bootstrap.sh`](../scripts/pond-guest-bootstrap.sh) | **Guest** | tducks + nginx + UI |
| [`scripts/install-tducks.sh`](../scripts/install-tducks.sh) | Guest | Node binary + systemd |
| [`packaging/nginx/pond-ui.conf`](../packaging/nginx/pond-ui.conf) | Guest | Site config |

## Honest limits

- Helper targets **amd64** Ubuntu 24.04 templates/images first  
- Web UI is the minimal TS client (not retail appliance chrome)  
- KVM cloud-init + guest-agent path varies by image; LXC is more reliable for day-1  
- No automatic HTTPS/certs yet (add tailnet or terminate TLS on host reverse-proxy if needed)  
- Nested Docker is **not** used — Pond stays host systemd inside the guest  
