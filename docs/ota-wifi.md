# OTA + Wi‑Fi wizard (Pond appliance)

**Status:** first engineering slice  
**APIs:** owner-gated mutations; durable under `TD_DATA_DIR`

## Wi‑Fi

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/v1/wifi` | public status (no PSK) | Configured SSID, iface, last apply |
| POST | `/v1/wifi/scan` | owner when non-loopback | Best-effort `nmcli` scan |
| POST | `/v1/wifi/apply` | **always owner** | Save SSID/PSK + best-effort `nmcli connect` |

```bash
# Apply (requires owner session)
curl -s -X POST http://127.0.0.1:8788/v1/wifi/apply \
  -H "Authorization: Bearer $OWNER" \
  -H 'content-type: application/json' \
  -d '{"ssid":"HomeLAN","psk":"secret"}'
```

Persists to `$TD_DATA_DIR/wifi.json` (mode `0600` when possible).  
If `nmcli` is missing, config is still saved (`backend: stub`).

Env: `TD_WIFI_IFACE` (default `wlan0`).

## OTA (signed channel stub)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/v1/ota` | public status | Current version, last check, staged path |
| POST | `/v1/ota/check` | **owner** | Fetch manifest from `TD_OTA_MANIFEST_URL` |
| POST | `/v1/ota/apply` | **owner** | Download artifact → `$TD_DATA_DIR/ota/` |

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
| `TD_OTA_MANIFEST_URL` | HTTPS (or file) URL of manifest JSON |
| `TD_OTA_CHANNEL` | Channel label (default `stable`) |
| `TD_OTA_PUBKEY` | 32-byte ed25519 verifying key hex — when set, manifest **must** be signed |

Apply stages the binary only; operator finishes with:

```bash
sudo ./scripts/install-tducks.sh --from-file /var/lib/thunderducks/ota/tducks-0.2.0.bin
sudo systemctl restart tducks
```

Honest limits: no automatic service replace yet; hash field is **blake3** (name kept `sha256` for wire simplicity).

## Related

- [`install.md`](./install.md)
- [`pond-appliance.md`](./pond-appliance.md)
- [`remote-access.md`](./remote-access.md)
