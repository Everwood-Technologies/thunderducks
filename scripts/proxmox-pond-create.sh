#!/usr/bin/env bash
# Create a Proxmox VE guest (KVM or LXC) with Ubuntu + Thunderducks Pond + nginx UI.
#
# Run as root on the Proxmox host (needs qm/pct, and ideally pveam).
#
# Examples:
#   # LXC (fastest dogfood) — downloads Ubuntu 24.04 template if missing
#   sudo ./scripts/proxmox-pond-create.sh --type lxc --id 120 --hostname pond-alpha \
#     --bridge vmbr0 --storage local-lvm --template-storage local
#
#   # KVM from an existing Ubuntu cloud image already downloaded to a storage
#   sudo ./scripts/proxmox-pond-create.sh --type kvm --id 121 --hostname pond-kvm \
#     --bridge vmbr0 --storage local-lvm \
#     --cloudimg /var/lib/vz/template/iso/noble-server-cloudimg-amd64.img
#
#   # Only print guest bootstrap command (no create)
#   ./scripts/proxmox-pond-create.sh --print-bootstrap
#
# After create, guest is bootstrapped with:
#   scripts/pond-guest-bootstrap.sh  (tducks alpha + nginx UI)
#
# Env defaults (overridable):
#   TDUCKS_VERSION=v0.1.0-alpha.1
#   POND_PASSWORD=pond1  (root/ubuntu password; Proxmox requires >= 5 chars)
#   POND_SSH_KEY=        (path to pubkey; optional)
#   POND_MEMORY_MB=2048  POND_CORES=2  POND_DISK_GB=16
set -euo pipefail

TYPE="lxc" # lxc | kvm
VMID=""
HOSTNAME="pond-alpha"
BRIDGE="vmbr0"
STORAGE="local-lvm"
TEMPLATE_STORAGE="local"
CLOUDIMG=""
LXC_TEMPLATE="" # empty → auto ubuntu-24.04
MEMORY_MB="${POND_MEMORY_MB:-2048}"
CORES="${POND_CORES:-2}"
DISK_GB="${POND_DISK_GB:-16}"
PASSWORD="${POND_PASSWORD:-pond1}"
SSH_KEY="${POND_SSH_KEY:-}"
VERSION="${TDUCKS_VERSION:-v0.1.0-alpha.1}"
REPO="${TDUCKS_REPO:-Everwood-Technologies/thunderducks}"
WEB_REF="${POND_WEB_REF:-main}"
START=1
BOOTSTRAP=1
PRINT_BOOTSTRAP=0
FORCE=0
IPCONFIG="" # e.g. ip=192.168.1.50/24,gw=192.168.1.1  (empty = DHCP)
CIUSER="ubuntu"

die() { echo "proxmox-pond: error: $*" >&2; exit 1; }
log() { echo "proxmox-pond: $*"; }
need_root() { [[ "$(id -u)" -eq 0 ]] || die "run as root on the Proxmox host"; }

usage() {
  sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage ;;
    --type) TYPE="${2:-}"; shift 2 ;;
    --id|--vmid) VMID="${2:-}"; shift 2 ;;
    --hostname) HOSTNAME="${2:-}"; shift 2 ;;
    --bridge) BRIDGE="${2:-}"; shift 2 ;;
    --storage) STORAGE="${2:-}"; shift 2 ;;
    --template-storage) TEMPLATE_STORAGE="${2:-}"; shift 2 ;;
    --cloudimg) CLOUDIMG="${2:-}"; shift 2 ;;
    --lxc-template) LXC_TEMPLATE="${2:-}"; shift 2 ;;
    --memory) MEMORY_MB="${2:-}"; shift 2 ;;
    --cores) CORES="${2:-}"; shift 2 ;;
    --disk) DISK_GB="${2:-}"; shift 2 ;;
    --password) PASSWORD="${2:-}"; shift 2 ;;
    --ssh-key) SSH_KEY="${2:-}"; shift 2 ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    --ipconfig) IPCONFIG="${2:-}"; shift 2 ;;
    --ciuser) CIUSER="${2:-}"; shift 2 ;;
    --no-start) START=0; shift ;;
    --no-bootstrap) BOOTSTRAP=0; shift ;;
    --print-bootstrap) PRINT_BOOTSTRAP=1; shift ;;
    --force) FORCE=1; shift ;;
    *) die "unknown arg: $1" ;;
  esac
done

bootstrap_script() {
  cat <<EOF
export DEBIAN_FRONTEND=noninteractive
export TDUCKS_VERSION='${VERSION}'
export TDUCKS_REPO='${REPO}'
export POND_WEB_REF='${WEB_REF}'
curl -fsSL 'https://raw.githubusercontent.com/${REPO}/${WEB_REF}/scripts/pond-guest-bootstrap.sh' | bash
EOF
}

if [[ "$PRINT_BOOTSTRAP" -eq 1 ]]; then
  bootstrap_script
  exit 0
fi

need_root
[[ -n "$VMID" ]] || die "--id <vmid> required"
[[ "$TYPE" == "lxc" || "$TYPE" == "kvm" ]] || die "--type must be lxc or kvm"
[[ "${#PASSWORD}" -ge 5 ]] || die "password must be at least 5 characters (Proxmox rule); set --password or POND_PASSWORD"

command -v pvesh >/dev/null 2>&1 || die "not a Proxmox host? (pvesh missing)"

guest_exists() {
  if [[ "$TYPE" == "lxc" ]]; then
    pct status "$VMID" &>/dev/null
  else
    qm status "$VMID" &>/dev/null
  fi
}

if guest_exists; then
  if [[ "$FORCE" -eq 1 ]]; then
    log "destroying existing ${TYPE} ${VMID}"
    if [[ "$TYPE" == "lxc" ]]; then
      pct stop "$VMID" 2>/dev/null || true
      pct destroy "$VMID" --force 1
    else
      qm stop "$VMID" 2>/dev/null || true
      qm destroy "$VMID" --purge 1
    fi
  else
    die "VMID ${VMID} already exists (pass --force to replace)"
  fi
fi

wait_guest_up() {
  local i
  for i in $(seq 1 90); do
    if [[ "$TYPE" == "lxc" ]]; then
      pct status "$VMID" 2>/dev/null | grep -q running && return 0
    else
      qm status "$VMID" 2>/dev/null | grep -q running && return 0
    fi
    sleep 2
  done
  return 1
}

wait_guest_exec() {
  # Wait until pct/qm guest exec works (network + agent/ssh-less channel).
  local i
  for i in $(seq 1 120); do
    if [[ "$TYPE" == "lxc" ]]; then
      if pct exec "$VMID" -- true 2>/dev/null; then return 0; fi
    else
      if qm guest exec "$VMID" -- true 2>/dev/null | grep -q '"exitcode": 0'; then return 0; fi
      # fallback: some PVE versions print plain
      if qm guest exec "$VMID" -- true &>/dev/null; then return 0; fi
    fi
    sleep 3
  done
  return 1
}

run_in_guest() {
  local cmd="$1"
  if [[ "$TYPE" == "lxc" ]]; then
    pct exec "$VMID" -- bash -lc "$cmd"
  else
    # qm guest exec needs guest-agent
    qm guest exec "$VMID" -- bash -lc "$cmd"
  fi
}

# --- Create LXC ---
create_lxc() {
  command -v pct >/dev/null || die "pct not found"
  command -v pveam >/dev/null || die "pveam not found"

  local tmpl="$LXC_TEMPLATE"
  if [[ -z "$tmpl" ]]; then
    log "resolving Ubuntu 24.04 LXC template on storage ${TEMPLATE_STORAGE}"
    # Prefer already-downloaded
    tmpl="$(pveam list "$TEMPLATE_STORAGE" 2>/dev/null | awk '/ubuntu-24\.04-standard.*amd64/ {print $1; exit}')"
    if [[ -z "$tmpl" ]]; then
      log "downloading ubuntu-24.04 template (this can take a few minutes)"
      local avail
      avail="$(pveam available --section system 2>/dev/null | awk '/ubuntu-24\.04-standard.*amd64/ {print $2; exit}')"
      [[ -n "$avail" ]] || die "no ubuntu-24.04-standard amd64 template in pveam available"
      pveam download "$TEMPLATE_STORAGE" "$avail"
      tmpl="${TEMPLATE_STORAGE}:vztmpl/${avail}"
    fi
  fi
  log "using template $tmpl"

  local -a create_args=(
    "$VMID" "$tmpl"
    --hostname "$HOSTNAME"
    --memory "$MEMORY_MB"
    --cores "$CORES"
    --rootfs "${STORAGE}:${DISK_GB}"
    --net0 "name=eth0,bridge=${BRIDGE},ip=dhcp,type=veth"
    --unprivileged 1
    --features "nesting=1"
    --onboot 0
    --start 0
    --password "$PASSWORD"
  )
  if [[ -n "$SSH_KEY" && -f "$SSH_KEY" ]]; then
    create_args+=(--ssh-public-keys "$SSH_KEY")
  fi
  if [[ -n "$IPCONFIG" ]]; then
    # Override net0 with static if requested (pct syntax uses ip= in net0)
    # IPCONFIG example: ip=192.168.1.50/24,gw=192.168.1.1
    create_args=()
    create_args=(
      "$VMID" "$tmpl"
      --hostname "$HOSTNAME"
      --memory "$MEMORY_MB"
      --cores "$CORES"
      --rootfs "${STORAGE}:${DISK_GB}"
      --net0 "name=eth0,bridge=${BRIDGE},${IPCONFIG},type=veth"
      --unprivileged 1
      --features "nesting=1"
      --onboot 0
      --start 0
      --password "$PASSWORD"
    )
    if [[ -n "$SSH_KEY" && -f "$SSH_KEY" ]]; then
      create_args+=(--ssh-public-keys "$SSH_KEY")
    fi
  fi

  pct create "${create_args[@]}"
  # systemd in container
  pct set "$VMID" --ostype ubuntu 2>/dev/null || true

  if [[ "$START" -eq 1 ]]; then
    log "starting CT ${VMID}"
    pct start "$VMID"
    wait_guest_up || die "CT did not reach running"
  fi
}

# --- Create KVM (cloud-init) ---
create_kvm() {
  command -v qm >/dev/null || die "qm not found"
  [[ -n "$CLOUDIMG" ]] || die "KVM requires --cloudimg /path/to/ubuntu-cloudimg.img (qcow2/raw)"
  [[ -f "$CLOUDIMG" ]] || die "cloud image not found: $CLOUDIMG"

  log "creating VM ${VMID} from cloud image"
  qm create "$VMID" \
    --name "$HOSTNAME" \
    --memory "$MEMORY_MB" \
    --cores "$CORES" \
    --net0 "virtio,bridge=${BRIDGE}" \
    --ostype l26 \
    --agent enabled=1 \
    --scsihw virtio-scsi-pci \
    --serial0 socket \
    --vga serial0

  # Import disk
  qm importdisk "$VMID" "$CLOUDIMG" "$STORAGE" --format qcow2
  # Find imported volume name
  local vol
  vol="$(pvesm list "$STORAGE" | awk -v id="$VMID" '$1 ~ ("vm-" id "-disk") {print $1; exit}')"
  [[ -n "$vol" ]] || vol="$(qm config "$VMID" | awk -F': ' '/^unused0:/ {print $2; exit}')"
  [[ -n "$vol" ]] || die "could not find imported disk volume for VMID ${VMID}"

  qm set "$VMID" \
    --scsi0 "${vol}" \
    --boot order=scsi0 \
    --ide2 "${STORAGE}:cloudinit" \
    --ciuser "$CIUSER" \
    --cipassword "$PASSWORD" \
    --ipconfig0 "${IPCONFIG:-ip=dhcp}"

  if [[ -n "$SSH_KEY" && -f "$SSH_KEY" ]]; then
    qm set "$VMID" --sshkeys "$SSH_KEY"
  fi

  # Grow disk if needed (cloud images are small)
  qm resize "$VMID" scsi0 "${DISK_GB}G" 2>/dev/null || true

  if [[ "$START" -eq 1 ]]; then
    log "starting VM ${VMID} (cloud-init first boot)"
    qm start "$VMID"
    wait_guest_up || die "VM did not reach running"
    log "waiting for qemu-guest-agent (install may take a minute on first boot)"
    # cloud image may need package install for agent — try enable via cloud-init package default
    if ! wait_guest_exec; then
      log "guest-agent not ready; attempting SSH-less bootstrap via cloud-init vendor data is not configured"
      log "fall back: ssh into the VM and run:"
      bootstrap_script | sed 's/^/  /'
      die "qemu-guest-agent unavailable — start VM with agent package or bootstrap manually"
    fi
  fi
}

log "create ${TYPE} vmid=${VMID} hostname=${HOSTNAME} storage=${STORAGE} bridge=${BRIDGE}"
if [[ "$TYPE" == "lxc" ]]; then
  create_lxc
else
  create_kvm
fi

if [[ "$BOOTSTRAP" -eq 1 && "$START" -eq 1 ]]; then
  log "waiting for guest exec channel"
  wait_guest_exec || die "guest exec not ready"
  log "running pond-guest-bootstrap (${VERSION})"
  # Stream bootstrap into guest
  run_in_guest "$(bootstrap_script)"
else
  log "skip bootstrap (print with --print-bootstrap)"
fi

# Best-effort IP discovery
IP=""
if [[ "$TYPE" == "lxc" ]]; then
  IP="$(pct exec "$VMID" -- hostname -I 2>/dev/null | awk '{print $1}')" || true
else
  IP="$(qm guest cmd "$VMID" network-get-interfaces 2>/dev/null | python3 -c '
import sys,json
try:
  d=json.load(sys.stdin)
except Exception:
  sys.exit(0)
for n in d if isinstance(d,list) else []:
  for a in n.get("ip-addresses") or []:
    if a.get("ip-address-type")=="ipv4" and not a.get("ip-address","").startswith("127."):
      print(a["ip-address"]); raise SystemExit
' 2>/dev/null)" || true
fi

echo
log "OK"
echo "  type:     ${TYPE}"
echo "  vmid:     ${VMID}"
echo "  hostname: ${HOSTNAME}"
echo "  version:  ${VERSION}"
if [[ -n "$IP" ]]; then
  echo "  UI:       http://${IP}/"
  echo "  health:   http://${IP}/health"
else
  echo "  UI:       http://<guest-ip>/"
  echo "  (discover IP: pct exec ${VMID} -- hostname -I   or   qm guest cmd ${VMID} network-get-interfaces)"
fi
echo "  console:  $([[ "$TYPE" == "lxc" ]] && echo "pct enter ${VMID}" || echo "qm terminal ${VMID}")"
echo "  password: ${PASSWORD}  (change me)"
echo
echo "Next: open UI → claim Pond → save recovery code offline → snapshot the guest."
echo "Do not publish guest :80 to WAN without auth/tailnet; tducks RPC stays on guest loopback."
