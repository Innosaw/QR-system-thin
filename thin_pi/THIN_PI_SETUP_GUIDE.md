# Thin Pi v2 Setup Guide (Customer Flash Image)

This guide covers:
- Flashing the Thin Pi image using **Raspberry Pi Imager**
- First boot + how to log in / access the UI
- Recommended **order of operations** (cloud → Pi)
- Mapping USB scanner dongles to station codes

---

## 0) What you need

- A **Raspberry Pi** (the model your kit specifies)
- Recommended models:
  - **Pi 5** (recommended)
  - **Pi 4** (works well)
  - Other Pis with a 40‑pin GPIO header may work; performance varies
- **Power supply**
- **microSD card** (quality card recommended)
- A **powered USB hub** + your USB scanner dongles
- Network access (Ethernet recommended for first setup)
- A laptop/PC on the same network

---

## 1) Download + install Raspberry Pi Imager

- Download Raspberry Pi Imager: `https://www.raspberrypi.com/software/`
- Install it for Windows/Mac/Linux (standard installer flow).

---

## 2) Flash the Thin Pi image with Raspberry Pi Imager

1. Insert the microSD card into your computer.
2. Open **Raspberry Pi Imager**.
3. Click **Choose OS** → **Use custom** → select the provided Thin Pi image file:
   - Usually `*.img` or compressed `*.img.xz`
4. Click **Choose Storage** → select your microSD card.
5. Apply **OS customisation** (this is where Wi‑Fi/SSH/user are set):
   - In some Imager versions you click **Next** and it pops up “Apply OS customisation?” → choose **Edit settings**
   - In other versions there is a **gear icon** / **Customisation** step
   - If you don’t see any customisation options, update Raspberry Pi Imager to the latest version
6. In OS customisation, set:
   - **Username**: **`pi`** (keep it standard so support can always use `pi@<ip>`)
   - **Password**: set a password you’ll record
   - **Hostname**: optional (nice-to-have, not required)
   - **Enable SSH**: ON (password auth is fine for LAN setup)
   - **Configure wireless LAN**: customers should enter **their** Wi‑Fi details here (or skip Wi‑Fi and use Ethernet)
   - **Locale/timezone/keyboard**: set for the shop
7. Click **Write** and wait for it to finish.
8. Safely eject the microSD.

---

## 3) First boot: power up + find the Pi on the network

1. Insert the microSD into the Pi.
2. Plug in **Ethernet** (recommended for first-time setup) and power on.
3. Find the Pi’s IP address:
   - From your router/DHCP client list, or
   - If mDNS works on your network: try `ping <hostname>.local`
   - Optional: plug the Pi into a monitor via **HDMI** (many images show the IP on-screen after boot)

### Important note about `<pi-ip>`

Any URL shown like `http://<pi-ip>:5006/...` means: **replace `<pi-ip>` with the Pi’s current IP address**.

Example:
- `http://192.168.68.113:5006/admin`

### Recommended: keep the Pi IP from changing

To avoid bookmarks breaking, set a **DHCP reservation** (sometimes called “Static DHCP” / “Address reservation”) in your router so this Pi always gets the same IP address.

### SSH login

From another computer on the same network:

```bash
ssh <username>@<pi-ip>
```

Example:

```bash
ssh pi@192.168.1.50
```

---

## 4) View the Thin Pi system (UI)

Open in a browser (same network):

- **Dashboard**: `http://<pi-ip>:5006/`
- **Admin Mapping**: `http://<pi-ip>:5006/admin`
- **Raw Scans**: `http://<pi-ip>:5006/raw_scans`
- **Help**: `http://<pi-ip>:5006/help`

---

## 4.5) Install the Thin Pi software (fresh OS install)

If you flashed a normal Raspberry Pi OS image (not a pre-built Innosaw image), install thin mode like this:

```bash
curl -fsSL https://raw.githubusercontent.com/Innosaw/QR-system-thin/main/thin_pi/install_thin_pi.sh -o install_thin_pi.sh
sudo bash install_thin_pi.sh
```

This installs to: `~/qr-system` and starts the service: `innosaw-thin`

---

## 4.6) Wi‑Fi setup (optional)

Recommended: do first-time setup on **Ethernet**, then switch to Wi‑Fi only if needed.

### Option A (easiest): set Wi‑Fi in Raspberry Pi Imager

When flashing Raspberry Pi OS, use **OS customisation** to enter Wi‑Fi SSID/password.

### Option B: HDMI + keyboard on the Pi

Run:

```bash
sudo nmtui
```

Then join the shop Wi‑Fi.

Suggested walkthrough (screenshots can be added later):
- Select **Activate a connection**
- Pick the Wi‑Fi network (SSID) → Enter
- Enter password → Enter
- Back → Quit

### Option C: Windows PowerShell (copy/paste)

If SSH is enabled and you know the Pi’s IP:

```bash
ssh pi@<pi-ip> "sudo nmcli dev wifi connect '<ssid>' password '<wifi-password>'"
```

If this fails, fall back to Option B.

---

## 5) Recommended order of operations (cloud → Pi)

### A) Cloud first (recommended)

1. In the Cloud dashboard, create/verify:
   - the **shop**
   - the set of **stations** (CNC/Edge/Dowel/Sort/Pull/QC/etc.)
2. In Cloud Admin, generate a **Pairing Code** (often labeled “Pair a Pi”).

### B) Then the Pi

1. Flash + boot the Pi (steps above).
2. Plug in the powered USB hub + all scanner dongles.
3. Open `http://<pi-ip>:5006/admin` and do:
   - **Detect USB Dongles**
   - **Station Mapping** (map each device path to a station code)
4. **Cloud Pairing (no manual tokens):**
   - In Admin Mapping, paste the Cloud Base URL (usually `https://v2.innosaw.work`)
   - Paste the pairing code
   - Click **Pair**

When pairing succeeds, the Pi stores station tokens locally and starts forwarding scans.

---

## 6) Map dongles (how to choose the right device paths)

In **Admin Mapping** (`/admin`):

1. Click **Detect** under “Detect USB Dongles”
2. For each dongle, click **Use** to copy its stable device path into the mapping form
3. Choose the **Station Code**
4. Click **Save**
5. Repeat for each station/dongle

### Important notes

- Prefer stable paths like:
  - `/dev/input/by-path/...` (recommended by the UI)
- If you move dongles to different USB ports, the path can change.
  - Best practice: keep the hub + dongles in a consistent physical layout and label them.

---

## 7) Verify everything is working

### Check service is running

```bash
sudo systemctl status innosaw-thin --no-pager
```

### Watch live logs while scanning

```bash
sudo journalctl -u innosaw-thin -f
```

You should see lines like “Cloud v2 forwarded scan (thin mode).”

---

## 8) (Optional) Protect admin actions with a password

Thin Pi supports optional password protection for write/admin actions via:

- `/etc/innosaw-thin.env`

On the Pi:

```bash
sudo nano /etc/innosaw-thin.env
sudo systemctl restart innosaw-thin
```

Uncomment and set:
- `INNOSAW_ADMIN_PASSWORD=...`
- `INNOSAW_SHOP_PASSWORD=...`

---

## 9) After setup: making a “golden image” safely

Before you clone/distribute an SD image, read:
- `PRE_FLASH_PRIVACY_CHECKLIST.md`

If you want a quick “wipe scan history” before imaging:
- Open `http://<pi-ip>:5006/admin` → “Clear Local Scan Data (for imaging)”


