#!/usr/bin/env bash
set -euo pipefail

# Thin Pi installer (customer-flash image profile)
# - Multi-scanner input
# - Local admin mapping UI (shop_dashboard.py)
# - Thin-mode forwarding to v2 (server-side logic) with offline queue + local archive
#
# Usage:
#   sudo bash thin_pi/install_thin_pi.sh
#
# Notes:
# - This does not enable camera/OpenCV.
# - This keeps logic minimal on the Pi; parsing/routing should happen in v2 when thin_mode=true.

PI_USER="${SUDO_USER:-pi}"
INSTALL_DIR="/home/${PI_USER}/qr-system"
ENV_FILE="/etc/innosaw-thin.env"
SERVICE_NAME="innosaw-thin"
# Repo URL for the thin installer.
# Default points at the thin-only repo (public) so installs never require a GitHub login.
# To override (internal/dev), set:
#   INNOSAW_THIN_REPO_URL=https://github.com/Innosaw/QR-system.git
REPO_URL="${INNOSAW_THIN_REPO_URL:-https://github.com/Innosaw/QR-system-thin.git}"

echo "[1/7] Base packages"
apt-get update -y
apt-get install -y git python3 python3-venv python3-pip python3-dev build-essential rpi.gpio-common

# Allow GPIO access for LED/buzzer feedback
usermod -aG gpio "${PI_USER}" || true

echo "[2/7] Install dir"
mkdir -p "${INSTALL_DIR}"
chown -R "${PI_USER}:${PI_USER}" "${INSTALL_DIR}"

echo "[3/7] Repo (sparse checkout)"
if [[ ! -d "${INSTALL_DIR}/.git" ]]; then
  sudo -u "${PI_USER}" bash -lc "
    cd \"${INSTALL_DIR}\"
    git clone --depth 1 --filter=blob:none --sparse \"${REPO_URL}\" .
    # We need non-cone mode because we include individual files at repo root.
    # Leading slashes required for no-cone mode paths.
    git sparse-checkout init --no-cone
    git sparse-checkout set \
      /qr_scanner.py \
      /multi_scanner_manager.py \
      /detect_dongles.py \
      /shop_dashboard.py \
      /authz.py \
      /path_utils.py \
      /bin_management.py \
      /database_schema.py \
      /cloud_v2/pi_client.py \
      /static/common.css \
      /templates/admin.html \
      /templates/admin_thin.html \
      /templates/admin_login.html \
      /templates/help_thin.html \
      /templates/shop_dashboard.html \
      /templates/shop_dashboard_thin.html \
      /templates/raw_scans_thin.html \
      /config.example.json \
      /thin_pi/THIN_PI_SETUP_GUIDE.md \
      /thin_pi/thin_pi_runtime.py \
      /thin_pi/requirements.txt \
      /thin_pi/innosaw-thin.service \
      /thin_pi/install_thin_pi.sh
  "
else
  # Existing install: refresh sparse-checkout list so newly added thin templates are included.
  sudo -u "${PI_USER}" bash -lc "
    cd \"${INSTALL_DIR}\"
    git sparse-checkout init --no-cone || true
    git sparse-checkout set \
      /qr_scanner.py \
      /multi_scanner_manager.py \
      /detect_dongles.py \
      /shop_dashboard.py \
      /authz.py \
      /path_utils.py \
      /bin_management.py \
      /database_schema.py \
      /cloud_v2/pi_client.py \
      /static/common.css \
      /templates/admin.html \
      /templates/admin_thin.html \
      /templates/admin_login.html \
      /templates/help_thin.html \
      /templates/shop_dashboard.html \
      /templates/shop_dashboard_thin.html \
      /templates/raw_scans_thin.html \
      /config.example.json \
      /thin_pi/THIN_PI_SETUP_GUIDE.md \
      /thin_pi/thin_pi_runtime.py \
      /thin_pi/requirements.txt \
      /thin_pi/innosaw-thin.service \
      /thin_pi/install_thin_pi.sh
    git pull
  "
fi

echo "[4/7] Python venv + deps"
sudo -u "${PI_USER}" bash -lc "
  cd \"${INSTALL_DIR}\"
  python3 -m venv .venv
  source .venv/bin/activate
  pip install --upgrade pip
  pip install -r thin_pi/requirements.txt
"

echo "[5/7] Default config (if missing)"
if [[ ! -f "${INSTALL_DIR}/config.json" ]]; then
  cp "${INSTALL_DIR}/config.example.json" "${INSTALL_DIR}/config.json"
  chown "${PI_USER}:${PI_USER}" "${INSTALL_DIR}/config.json"
fi

echo "[6/7] Environment file"
umask 077
cat > "${ENV_FILE}" <<EOF
# Optional overrides for thin runtime
INNOSAW_CONFIG_PATH=config.json
INNOSAW_DASHBOARD_HOST=0.0.0.0
INNOSAW_DASHBOARD_PORT=5006
INNOSAW_THIN_MODE=1

# Optional: protect /admin with passwords (uncomment and set)
# INNOSAW_ADMIN_PASSWORD=change-me
# INNOSAW_SHOP_PASSWORD=change-me
EOF
chmod 600 "${ENV_FILE}"

echo "[7/7] Systemd service"
cp "${INSTALL_DIR}/thin_pi/innosaw-thin.service" "/etc/systemd/system/${SERVICE_NAME}.service"

# Ensure service file points at the correct user/path
sed -i "s|User=pi|User=${PI_USER}|g" "/etc/systemd/system/${SERVICE_NAME}.service"
sed -i "s|Group=pi|Group=${PI_USER}|g" "/etc/systemd/system/${SERVICE_NAME}.service"
sed -i "s|WorkingDirectory=/home/pi/qr-system|WorkingDirectory=${INSTALL_DIR}|g" "/etc/systemd/system/${SERVICE_NAME}.service"
sed -i "s|ExecStart=/home/pi/qr-system/.venv/bin/python /home/pi/qr-system/thin_pi/thin_pi_runtime.py|ExecStart=${INSTALL_DIR}/.venv/bin/python ${INSTALL_DIR}/thin_pi/thin_pi_runtime.py|g" "/etc/systemd/system/${SERVICE_NAME}.service"

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service"
systemctl restart "${SERVICE_NAME}.service"

echo ""
echo "=== Thin Pi installed ==="
echo "Service:  sudo systemctl status ${SERVICE_NAME}.service --no-pager"
echo "Admin UI: http://<pi-ip>:5006/admin"
echo ""
echo "Next:"
echo "- Plug in scanners"
echo "- Run: python3 detect_dongles.py"
echo "- Update config.json scanners{} mappings"
echo "- Set cloud_v2.enabled=true and cloud_v2.thin_mode=true and station_tokens{}"
echo ""


