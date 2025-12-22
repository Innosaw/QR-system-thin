#!/usr/bin/env python3
"""
Thin Pi runtime (customer-flash image)

- Multi-scanner input (USB hub + multiple dongles)
- Optional GPIO feedback (LED/buzzer)
- Local admin mapping UI (shop_dashboard.py /admin)
- Cloud v2 forwarding (thin_mode) with offline queue + local archive

This intentionally avoids running the full legacy Pi stack (api_server, bin manager UI, etc.).
"""

from __future__ import annotations

import os
import signal
import sys
import threading
import time
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    try:
        return int((os.environ.get(name) or "").strip() or default)
    except Exception:
        return default


def main() -> int:
    # Ensure repo root is on sys.path so imports work when installed via sparse checkout.
    repo_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo_root))

    # Import late so sys.path is ready
    from multi_scanner_manager import MultiScannerManager
    import shop_dashboard

    config_path = os.environ.get("INNOSAW_CONFIG_PATH", "config.json")
    bind_host = os.environ.get("INNOSAW_DASHBOARD_HOST", "0.0.0.0")
    bind_port = _env_int("INNOSAW_DASHBOARD_PORT", 5006)

    mgr = MultiScannerManager(config_file=config_path)
    mgr.load_scanners()
    mgr.start_all()

    # Attach to dashboard so /api/scanner/restart/<path> works and runtime status is visible
    shop_dashboard.app.scanner_manager = mgr

    stop_event = threading.Event()

    def _handle_signal(_sig, _frame):
        stop_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # Run the dashboard (blocking) in main thread.
    # Flask dev server is OK for LAN admin mapping; keep it single-process to share mgr instance.
    try:
        shop_dashboard.app.run(host=bind_host, port=bind_port, debug=False)
    finally:
        try:
            mgr.stop_all()
        except Exception:
            pass

    # If we ever get here, wait briefly for threads to stop.
    t0 = time.time()
    while time.time() - t0 < 2.0 and not stop_event.is_set():
        time.sleep(0.1)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


