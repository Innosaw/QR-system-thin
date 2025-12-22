## Thin Pi image (customer-flash profile)

This is the minimal Pi profile intended for customer-owned hardware:
- Multi-scanner capture (USB dongles/hub)
- Local admin mapping UI (`/admin`)
- Thin-mode forwarding to `v2.innosaw.work` (server-side logic)
- Offline queue + local append-only scan archive

### Full setup guide (flashing + first login + mapping)

See: `thin_pi/THIN_PI_SETUP_GUIDE.md`

### Install
On a fresh **Raspberry Pi OS Lite (64-bit)**:

```bash
sudo bash thin_pi/install_thin_pi.sh
```

### After install
- Open local admin mapping UI:
  - `http://<pi-ip>:5006/admin`
- Local help:
  - `http://<pi-ip>:5006/help`
- Detect dongles:

```bash
cd ~/qr-system
./.venv/bin/python detect_dongles.py
```

Then update `config.json`:
- `scanners{}` mapping (`/dev/input/by-path/...` → station_code)
- `cloud_v2.enabled=true`
- `cloud_v2.thin_mode=true`
- `cloud_v2.station_tokens{}` (per-station tokens)


