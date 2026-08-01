# Thunderducks Pond — Appliance One-Pager

**Status:** product draft (not a hardware commitment)  
**Date:** 2026-08-01  
**Codename:** **Pond** (household / small-team always-on node)  
**Parent product:** Thunderducks (`tducks` full node + thin clients)

---

## One sentence

Sell a **preinstalled always-on Thunderducks node**: plug in Ethernet, claim the box, pair phones — **phones are clients; the Pond holds identity, keys, and the room DAG.**

---

## Problem

- A real Thunderducks **node** needs uptime, disk, stable networking, and background P2P — phones are bad at that.
- DIY “run a binary on a VPS” works for us, not for normal buyers.
- Relays must stay **untrusted assist**; sovereignty requires **hardware the user owns**.

## Solution

A small **network appliance** (commodity mini PC + our image) that ships ready for first-boot setup:

```text
[Phone / laptop thin client]
        │  LAN / tailnet / relay-assisted
        ▼
[ Pond appliance = full tducks node ]
        │
        ▼
[ optional untrusted relay ]
```

---

## Buyer / jobs-to-be-done

| Buyer | Job | Why buy hardware |
|-------|-----|------------------|
| **Privacy-first household** | Family/friends chat without Big Chat | Own the node; no account farm |
| **Small team / guild** | Always-on room for 5–30 people | Reliable peer; not “whose laptop is open” |
| **Self-hoster** | Run Thunderducks beside other home lab gear | Appliance UX > bare binary |
| **Everwood dogfood** | Eat own cooking on Proxmox + physical box | Image parity |

**Not the buyer (v1):** people who only want a mobile app with no home hardware (offer hosted node later, optional).

---

## Product promise

> Unbox → Ethernet → power → open setup URL → passkey/claim → invite QR → phones chat.  
> Factory reset and encrypted backup are first-class.

---

## SKU ladder

| SKU | What ships | Hardware | Price band (rough, USD) | Who |
|-----|------------|----------|-------------------------|-----|
| **Pond DIY** | Free image + docs + `tducks` release binaries | BYO Pi / mini PC / VM | **$0** software | Tinkerers |
| **Pond Mini** | Preinstalled box + power + Ethernet-first | Fanless/small mini PC | **$249–399** | Default retail |
| **Pond Pro** | Mini + more CPU/RAM/disk; optional dual-NIC | Stronger mini PC | **$449–699** | Power users / small org |
| **Pond Cloud** *(later)* | Managed VM running same image | Our Proxmox/VPS | **$X/mo** | No-hardware buyers |

**v1 retail focus:** **Pond Mini** only. DIY image is the funnel and support escape hatch. Pro/Cloud later.

### SKU decision locks (draft)

| Lock | Choice |
|------|--------|
| Source of truth | **Pond node**, never the phone |
| Arch priority | **amd64 first**, arm64 second |
| Network default | **Ethernet required** for setup; Wi‑Fi optional add-on |
| Remote access | Tailnet and/or Thunderducks relay — **not** “open random WAN ports” as default |
| SSH on retail | **Off or setup-local only** by default; advanced toggle |
| License | Software **AGPL-3.0**; hardware + support are the SKU |
| Custom PCB v1 | **No** — ODM/commodity board only |

---

## BOM — Pond Mini (target)

Commodity mini PC, rebranded enclosure optional later.

| Component | Target | Notes |
|-----------|--------|--------|
| SoC | Intel **N100 / N150** class (or equiv. Ryzen/Intel) | Quiet, enough CPU, wide ODM supply |
| RAM | **16 GB** (8 GB absolute floor) | Headroom for OS + node + updates |
| Storage | **256 GB NVMe** (512 GB preferred) | Avoid SD cards; endurance matters |
| NIC | **1× GbE** minimum | 2.5GbE nice-to-have on Pro |
| Video | HDMI optional | Headless OK; HDMI helps support |
| Power | USB-C or barrel, **≤20W idle goal** | Wall-wart included |
| Ports | USB-A for recovery stick | Factory reset / reimage |
| Thermals | Fanless or low-noise | Living-room acceptable |
| RTC | Nice-to-have | Clock skew less painful |
| TPM / secure boot | Optional v1 | Nice for measured boot later |
| Wi‑Fi | Optional module | Ethernet-first SKU avoids Wi‑Fi support hell |
| Enclosure | Stock ODM + sticker / simple sleeve | Custom plastic = phase 2 |
| BOM cost target | **~$120–220** | Sell Mini ~2× BOM + support margin |
| Retail target | **~$299** sweet spot | Compete on setup, not TFLOPS |

### BOM — Pond Pro (delta)

- 32 GB RAM option  
- 1 TB NVMe  
- Stronger CPU (N305 / Ryzen 5 class)  
- 2.5GbE or dual NIC  
- Retail ~$499–599  

### BOM — avoid (v1)

- Raspberry Pi as **retail** SKU (DIY only)  
- Custom carrier boards  
- Cellular modem in-box  
- HDD  
- GPU SKUs  

### Comparable form factors (market context)

- Umbrel Home / Start9-class “sovereignty box”  
- Home Assistant appliance UX (not HA’s stack)  
- Generic N100 mini PCs (Beelink-class etc.) as white-label candidates  

---

## Setup flow (retail UX)

### Out of box

1. Plug **Ethernet** to LAN router.  
2. Plug power.  
3. Wait for ready (LED or ~60s).  
4. Phone/laptop opens **`http://pond.local`** (mDNS) or printed setup IP on claim card.  
5. **Claim wizard:**
   - Create owner passkey (WebAuthn) + printed recovery code  
   - Name the Pond  
   - Optional: enable Tailscale/Headscale / relay assist  
   - Create first room  
6. **Pair clients:** QR → web/app joins as thin client to this node.  
7. Invite others (link / QR). Done.

### Day-2 ops

| Action | UX |
|--------|----|
| Update | One-button signed OTA |
| Backup | Encrypted identity + keys + room tips download |
| Restore | Upload backup on new/reimaged Pond |
| Factory reset | Hold button / USB reimage + wipe keys |
| Add device | QR pair additional phone/laptop |
| Move house | Ethernet on new LAN; reclaim via backup if needed |

---

## Software image (same for DIY / Mini / Pro / VM)

**Pond Image** contents (logical):

| Layer | Choice |
|-------|--------|
| Base OS | Debian/Ubuntu Server LTS or immutable variant |
| Node | `tducks` systemd service, auto-restart |
| Data | `/var/lib/thunderducks` (SQLite, keys, config) |
| Local UI | First-run wizard + admin status (bind LAN) |
| Firewall | default-deny inbound; allow LAN admin + node P2P as configured |
| SSH | disabled by default on retail; optional advanced |
| mDNS | `pond.local` |
| Updates | signed release channel |
| Metrics/telemetry | **off by default** |
| Dogfood twin | Same image as Proxmox VM |

### Ports (draft)

| Port | Bind | Purpose |
|------|------|---------|
| RPC/admin UI | LAN only (not WAN) | Setup + clients on trust LAN |
| P2P | configurable / hole-punch / relay | Peer mesh |
| SSH | off default | Support escape hatch |

Exact port map follows packaging work (slice C).

---

## Non-goals (v1 appliance)

- Phone as full always-on node  
- Custom silicon / PCB  
- App Store supernode  
- Blockchain / tokens / mining  
- Mandatory public IP or UPnP  
- Multi-tenant hostile users on one Pond (personal/household trust boundary)  
- Replacing general NAS/Umbrel app store  
- Perfect metadata privacy  

---

## Business model (draft)

| Stream | Notes |
|--------|--------|
| **Hardware margin** | Mini/Pro units |
| **Support** | Optional email/Discord tier |
| **Cloud Pond** | Later subscription |
| **Software** | AGPL upstream — image scripts open; no fake open core theater |

Compliance note: AGPL on network service implies source offer obligations for modified networked instances — document for Cloud Pond before offering it.

---

## Success metrics (first 50 units)

- Unbox-to-first-message **< 15 minutes** on home Ethernet  
- Support tickets per unit **< 0.5** in first 30 days  
- Factory reset + restore works on video runbook  
- DIY image installs on clean Debian in **one script**  
- Zero requirement to open WAN :22  

---

## Dependencies on Thunderducks software (build order)

Must exist before retail hardware spend:

1. **Linux amd64 (+ arm64) release binaries** or OCI image  
2. **systemd install path** (enable on boot)  
3. **First-run claim + pairing API/UI**  
4. **Remote access path** (tailnet and/or relay) under CGNAT  
5. **Backup / restore / factory reset**  
6. **Signed update channel**  
7. Then: ODM sample → burn-in → pilot cohort  

Current repo: strong node MVP; **packaging + claim UX + remote path** are the gap.

---

## Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Support burden (Wi‑Fi, CGNAT) | Ethernet-first; tailnet/relay default remote story |
| Inventory | No custom plastic until 20–50 pilot units sell-through |
| SD card death | NVMe only on retail |
| User loses device | Recovery codes + encrypted backup |
| AGPL + hosted | Legal checklist before Cloud Pond |
| Competing with free DIY | Win on **time-to-first-message**, not specs |
| Security incident on appliance | Secure defaults, no open admin WAN, update channel |

---

## Recommended path

| Phase | Deliverable | Hardware |
|-------|-------------|----------|
| **P0** | This one-pager (done) | — |
| **P1** | Release + systemd + DIY install docs | Proxmox VM dogfood |
| **P2** | First-run wizard + pairing + backup | VM + 1 sample mini PC |
| **P3** | OTA + retail defaults (SSH off, ufw) | 3–5 burn-in units |
| **P4** | Pond Mini pilot (10–20 units) | ODM white-label |
| **P5** | Pond Pro / Cloud optional | Expand SKU |

**Do not** order enclosures until P2 works on a $200 Amazon mini PC.

---

## Open decisions (for Mike)

1. Retail brand: **Thunderducks Pond** vs quieter brand (e.g. Everwood Pond)?  
2. Remote default: **Tailscale-class** vs **first-party relay** vs both?  
3. Wi‑Fi: skip on Mini v1 or include? (recommend **skip**)  
4. Target retail price anchor: **$299** OK?  
5. Pilot channel: friends / Discord / small store?

---

## Next engineering slice (when ready)

**C — packaging:** `amd64`/`arm64` release artifacts + `tducks.service` + one-line DIY install — unblocks every SKU above without buying plastic.

---

## Related

- [`architecture.md`](./architecture.md)  
- [`threat-model.md`](./threat-model.md)  
- [`post-mvp-backlog.md`](./post-mvp-backlog.md)  
- [`mvp-accept.md`](./mvp-accept.md)  
