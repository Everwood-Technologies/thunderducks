# OTA + Wi‑Fi wizard (Pond appliance)

**Status:** OTA auto-apply + restart shipped  
**APIs:** owner-gated mutations; durable under `TD_DATA_DIR`

## Wi‑Fi

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/v1/wifi` | public status (no PSK) | Configured SSID, iface, last apply |
| POST | `/v1/wifi/scan` | owner when non-loopback | Best-effort `nmcli` scan |
| POST | `/v1/wifi/apply` | **always owner** | Save SSID/PSK + best-effort `nmcli connect` |

```bash
curl -s -X POST http://127.0.0.1:8788/v1/wifi/apply \
  -H "Authorization: Bearer $OWNER" \
  -H 'content-type: application/json' \
  -d '{"ssid":"HomeLAN","psk":"secret"}'
```

Persists to `$TD_DATA_DIR/wifi.json` (mode `0600` when possible).  
If `nmcli` is missing, config is still saved (`backend: stub`).

Env: `TD_WIFI_IFACE` (default `wlan0`).

## OTA

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/v1/ota` | public status | Version, pending, last apply, helper result |
| POST | `/v1/ota/check` | **owner** | Fetch manifest from `TD_OTA_MANIFEST_URL` |
| POST | `/v1/ota/apply` | **owner** | Download → stage → **auto-apply + restart** |

### Flow (auto-apply)

1. Owner calls `POST /v1/ota/check` (manifest + optional ed25519 verify).
2. Owner calls `POST /v1/ota/apply`:
   - Downloads artifact, verifies blake3 (`sha256` field name).
   - Writes `$TD_DATA_DIR/ota/tducks-<ver>.bin`.
   - If `TD_OTA_AUTO_APPLY` (default **true**): writes `ota/pending.json`.
   - Best-effort `systemctl start tducks-ota-apply.service`.
3. **Root helper** (`tducks-ota-apply.service`, also triggered by **path unit** on `pending.json`):
   - Atomically installs staged binary → `/usr/bin/tducks` (or `TD_OTA_BIN_PATH`).
   - Updates `ota-state.json`, clears pending.
   - Restarts `tducks.service` when `restart: true` (default; `TD_OTA_RESTART`).

```bash
# Check + apply (owner session required)
curl -s -X POST http://127.0.0.1:8788/v1/ota/check -H "Authorization: Bearer $OWNER"
curl -s -X POST http://127.0.0.1:8788/v1/ota/apply -H "Authorization: Bearer $OWNER"
curl -s http://127.0.0.1:8788/v1/ota | jq .
```

DIY install enables the path unit automatically:

```bash
systemctl status tducks-ota-apply.path
journalctl -u tducks-ota-apply.service -n 50
```

Manual root apply (if path unit missing):

```bash
sudo TD_DATA_DIR=/var/lib/thunderducks /usr/lib/thunderducks/tducks-ota-apply.sh
```

### Manifest JSON

```json
{
  "version": "0.2.0",
  "url": "https://example.com/tducks-0.2.0.bin",
  "sha256": "<blake3 hex of artifact>",
  "signature": "<optional ed25519 hex over version\\nurl\\nsha256>",
  "channel": "stable"
}
```

| Env | Purpose |
|-----|---------|
| `TD_OTA_MANIFEST_URL` | HTTPS URL of manifest JSON |
| `TD_OTA_CHANNEL` | Channel label (default `stable`) |
| `TD_OTA_PUBKEY` | 32-byte ed25519 verifying key hex — when set, manifest **must** be signed |
| `TD_OTA_AUTO_APPLY` | Write pending + kick helper (default **true**; set `false` to stage only) |
| `TD_OTA_RESTART` | Helper restarts unit after install (default **true**) |
| `TD_OTA_BIN_PATH` | Install target binary (default `/usr/bin/tducks`) |
| `TD_OTA_UNIT` | systemd unit to restart (default `tducks.service`) |

### Trust boundary

- Node runs as `tducks` (unprivileged): **download + stage + write pending only**.
- Install + restart run as **root** via oneshot/path unit — not from the node process.
- `ProtectSystem=strict` on main unit is preserved; helper is a separate root oneshot.

Honest limits: no rollback chain yet; hash field is **blake3** (name kept `sha256`); helper needs `python3` + `systemctl` on appliance images.

## Related

- [`install.md`](./install.md)
- [`pond-appliance.md`](./pond-appliance.md)
- [`remote-access.md`](./remote-access.md)
