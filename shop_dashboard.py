#!/usr/bin/env python3
"""
Simple Shop Dashboard for Local Access
Visual interface for shop staff to view system status
"""

from flask import Flask, render_template, jsonify, request, send_file, session, redirect, url_for
import logging
from datetime import datetime, timedelta
from pathlib import Path
import json
import os
import re
from flask import Response
from jinja2 import TemplateNotFound
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
from typing import Optional
import socket
import io
import zipfile
import platform

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None

try:
    from path_utils import resolve_path
except Exception:  # pragma: no cover
    def resolve_path(p):
        return (Path(__file__).parent / str(p)).resolve()

from authz import (
    check_password as _check_password_env,
    clear_role as _clear_role,
    current_role as _current_role,
    is_auth_enabled as _is_auth_enabled,
    require_role as _require_role,
    set_role as _set_role,
)

# Import database functions
try:
    from database_schema import get_db_connection, get_setting, set_setting
except ImportError:
    logging.warning("database_schema not available, API endpoints will use HTTP requests")
    get_db_connection = None
    get_setting = None
    set_setting = None

# Optional: Mozaik reparsing support (re-import an already-imported run)
try:
    from mozaik_mzklbl_importer import reparse_mzklbl_import
except Exception:
    reparse_mzklbl_import = None


def _get_setting(key: str, default: str = '') -> str:
    if not get_setting:
        return default
    try:
        return get_setting(key, default) or default
    except Exception:
        return default


def _set_setting(key: str, value: str) -> None:
    if not set_setting:
        raise RuntimeError('settings not available')
    set_setting(key, value)


def _auth_enabled() -> bool:
    """Auth is enabled if either:
    - env passwords are configured (INNOSAW_*), OR
    - DB passwords are configured (admin_password_hash and/or shop_password_hash)

    This keeps existing installs unchanged unless you set a password.
    """
    if _is_auth_enabled():
        return True
    return bool(_get_setting('admin_password_hash', '').strip() or _get_setting('shop_password_hash', '').strip())


def _check_password_db(password: str):
    """Validate password against DB-stored hashes.

    Returns (ok, role).
    """
    stored_admin = _get_setting('admin_password_hash', '').strip()
    stored_shop = _get_setting('shop_password_hash', '').strip()
    if not stored_admin and not stored_shop:
        return False, 'viewer'

    import hashlib

    pw = (password or '')
    h = hashlib.sha256(pw.encode()).hexdigest()
    if stored_admin and h == stored_admin:
        return True, 'admin'
    if stored_shop and h == stored_shop:
        return True, 'shop'
    return False, 'viewer'

# Try to import access control
try:
    from access_control import AccessControl
    access_control = AccessControl()
except Exception as e:
    logging.warning(f"Access control not available: {e}")
    access_control = None

# Set template folder - try multiple locations
import os
script_dir = Path(__file__).parent.absolute()
template_dirs = [
    script_dir / 'templates',
    Path('/home/pi/qr-scanner/templates'),
    Path(os.getcwd()) / 'templates',
    Path('templates')
]

template_folder = None
template_file = None
for td in template_dirs:
    template_path = td / 'shop_dashboard.html'
    if template_path.exists():
        template_folder = str(td)
        template_file = str(template_path)
        logging.info(f"✅ Found template at: {template_file}")
        break

if template_folder:
    app = Flask(__name__, template_folder=template_folder, static_folder=str(Path(template_folder).parent / 'static'))
    logging.info(f"📁 Using template folder: {template_folder}")
else:
    app = Flask(__name__, static_folder='static')
    logging.warning(f"⚠️  Template folder not found. Checked: {[str(td) for td in template_dirs]}")

app.secret_key = 'qr-scanner-admin-secret-key-change-in-production'  # Change this in production!

app.scanner_manager = None  # Will be set by manufacturing_system

# Initialize access control with error handling
try:
    access_control = AccessControl()
except Exception as e:
    logging.warning(f"Access control initialization failed: {e}")
    access_control = None


def _allowed_cors_origin(origin: str) -> Optional[str]:
    """Allow CORS between qr.<domain> and bins.<domain> (and same-origin)."""
    if not origin:
        return None
    try:
        parsed = urlparse(origin)
        origin_host = (parsed.hostname or '').lower()
        if not origin_host:
            return None

        request_host = (request.host.split(':', 1)[0] or '').lower()

        # Always allow same-origin
        if origin_host == request_host:
            return origin

        def base_domain(hostname: str) -> Optional[str]:
            parts = hostname.split('.')
            if len(parts) >= 3 and parts[0] in ('qr', 'bins'):
                return '.'.join(parts[1:])
            return None

        req_base = base_domain(request_host)
        origin_base = base_domain(origin_host)
        if req_base and origin_base and req_base == origin_base:
            return origin
    except Exception:
        return None

    return None


def _api_5007_available(timeout_s: float = 0.25) -> bool:
    """Return True if the legacy API server (:5007) is reachable on localhost.

    Thin Pi images don't run the legacy API server; in that mode we provide
    local implementations for a small subset of admin endpoints.
    """
    try:
        with socket.create_connection(("127.0.0.1", 5007), timeout=timeout_s):
            return True
    except Exception:
        return False


def _config_path() -> Path:
    """Return the effective config path.

    Thin runtime sets INNOSAW_CONFIG_PATH; use it everywhere so admin writes
    and scanner runtime reads stay consistent.
    """
    try:
        p = (os.environ.get('INNOSAW_CONFIG_PATH') or '').strip()
        if p:
            return resolve_path(p)
    except Exception:
        pass
    return resolve_path('config.json')


def _thin_mode_enabled() -> bool:
    """Determine if the Pi should render thin-mode templates."""
    try:
        if (os.environ.get('INNOSAW_THIN_MODE') or '').strip() in ('1', 'true', 'True', 'yes', 'YES'):
            return True
    except Exception:
        pass
    try:
        cfg_path = _config_path()
        if cfg_path.exists():
            with open(cfg_path, 'r') as f:
                cfg = json.load(f) or {}
            cloud = cfg.get('cloud_v2', {}) or {}
            return bool(cloud.get('thin_mode'))
    except Exception:
        return False
    return False


def _cloud_dashboard_url() -> str:
    """Link to the cloud dashboard if configured; default to v2.innosaw.work."""
    try:
        cfg_path = _config_path()
        if cfg_path.exists():
            with open(cfg_path, 'r') as f:
                cfg = json.load(f) or {}
            cloud = cfg.get('cloud_v2', {}) or {}
            url = (cloud.get('base_url') or '').strip()
            if url:
                return url.rstrip('/') + '/'
    except Exception:
        pass
    return 'https://v2.innosaw.work/'


@app.after_request
def _add_cors_headers(resp):
    # Only add CORS for the endpoints we expect cross-subdomain browser fetches from.
    if request.method == 'GET' and request.path.startswith('/api/scans'):
        origin = request.headers.get('Origin', '')
        allowed = _allowed_cors_origin(origin)
        if allowed:
            resp.headers['Access-Control-Allow-Origin'] = allowed
            resp.headers['Vary'] = 'Origin'
    return resp

@app.route('/')
def dashboard():
    """Main dashboard page"""
    try:
        # Check if template file exists
        if template_file and Path(template_file).exists():
            if _thin_mode_enabled():
                return render_template('shop_dashboard_thin.html', cloud_url=_cloud_dashboard_url())
            return render_template('shop_dashboard.html')
        else:
            # Try to find template in current working directory
            cwd_template = Path(os.getcwd()) / 'templates' / 'shop_dashboard.html'
            if cwd_template.exists():
                if _thin_mode_enabled():
                    return render_template('shop_dashboard_thin.html', cloud_url=_cloud_dashboard_url())
                return render_template('shop_dashboard.html')
            else:
                raise FileNotFoundError(f"Template not found. Checked: {template_file if template_file else 'None'}")
    except Exception as e:
        logging.error(f"Template error: {e}", exc_info=True)
        # Return a working dashboard with inline HTML
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Manufacturing Scanner Dashboard</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; padding: 20px; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
                .container { max-width: 1200px; margin: 0 auto; }
                .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
                .status-card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
                .status-card h3 { font-size: 14px; color: #666; margin-bottom: 10px; text-transform: uppercase; }
                .status-card .value { font-size: 32px; font-weight: bold; color: #667eea; }
                .btn { padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 14px; background: #667eea; color: white; margin-top: 20px; }
                .btn:hover { background: #5568d3; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🏭 Manufacturing Scanner System</h1>
                <div style="opacity: 0.9; font-size: 14px;">Real-time Status Dashboard</div>
            </div>
            <div class="container">
                <div class="status-grid">
                    <div class="status-card">
                        <h3>System Status</h3>
                        <div class="value" id="service-status">Loading...</div>
                        <div style="font-size: 12px; color: #999; margin-top: 5px;">QR Scanner Service</div>
                    </div>
                    <div class="status-card">
                        <h3>Active Scanners</h3>
                        <div class="value" id="active-scanners">0</div>
                        <div style="font-size: 12px; color: #999; margin-top: 5px;">Connected Devices</div>
                    </div>
                    <div class="status-card">
                        <h3>Scans (24h)</h3>
                        <div class="value" id="scan-count">0</div>
                        <div style="font-size: 12px; color: #999; margin-top: 5px;">Total Scans</div>
                    </div>
                </div>
                <button class="btn" onclick="restartService()">🔄 Restart Service</button>
                <button class="btn" onclick="refreshStatus()" style="margin-left: 10px;">🔄 Refresh</button>
                <div style="margin-top: 20px; padding: 15px; background: #fff3cd; border-radius: 8px; color: #856404;">
                    <strong>Note:</strong> Template file not found. Using inline dashboard. 
                    <br>To fix: Ensure templates/shop_dashboard.html exists in /home/pi/qr-scanner/templates/
                </div>
            </div>
            <script>
                function updateStatus() {
                    fetch('/api/status').then(r => r.json()).then(data => {
                        document.getElementById('service-status').textContent = data.service_status ? '🟢 Running' : '🔴 Stopped';
                        document.getElementById('active-scanners').textContent = Object.keys(data.scanners || {}).length;
                        document.getElementById('scan-count').textContent = data.recent_scans?.last_24_hours || 0;
                    }).catch(e => console.error('Error:', e));
                }
                function restartService() {
                    if (!confirm('Restart QR Scanner service?')) return;
                    fetch('/api/service/restart', {method: 'POST'}).then(r => r.json()).then(data => {
                        alert(data.success ? 'Service restarted' : 'Error: ' + (data.error || 'Unknown'));
                        setTimeout(updateStatus, 2000);
                    });
                }
                function refreshStatus() { updateStatus(); }
                setInterval(updateStatus, 5000);
                updateStatus();
            </script>
        </body>
        </html>
        """, 200

@app.route('/api/status')
def get_status():
    """Get system status"""
    try:
        def _configured_scanners_status() -> dict:
            """Best-effort: return configured scanners from config.json.

            This is used when the runtime scanner manager is not attached or
            hasn't loaded scanners yet.
            """
            try:
                cfg_path = _config_path()
                with open(cfg_path, 'r') as f:
                    cfg = json.load(f)
                scanners = cfg.get('scanners', {}) or {}
            except Exception:
                scanners = {}

            status = {}
            for device_path, station_cfg in (scanners or {}).items():
                try:
                    station_code = (station_cfg or {}).get('station_code') or ''
                    display_name = (station_cfg or {}).get('display_name') or ''
                except Exception:
                    station_code = ''
                    display_name = ''

                try:
                    connected = Path(str(device_path)).exists()
                except Exception:
                    connected = None

                status[str(device_path)] = {
                    'station_code': station_code,
                    'display_name': display_name,
                    'running': False,
                    'thread_alive': False,
                    'connected': connected,
                    'source': 'config',
                }
            return status

        configured_status = _configured_scanners_status()

        # Check runtime scanner status from the running scanner manager.
        runtime_status = {}
        if hasattr(app, 'scanner_manager') and app.scanner_manager:
            try:
                runtime_status = app.scanner_manager.get_scanner_status() or {}
            except Exception as e:
                logging.warning(f"Could not get scanner status: {e}")
                runtime_status = {'error': str(e)}

        # Merge runtime status onto configured status so the dashboard always lists all configured stations.
        scanner_status = dict(configured_status or {})
        if isinstance(runtime_status, dict) and runtime_status.get('error'):
            # Keep configured list; runtime has an error.
            pass
        elif isinstance(runtime_status, dict):
            for device_path, st in runtime_status.items():
                if not isinstance(st, dict):
                    continue
                entry = scanner_status.get(device_path) or {
                    'station_code': '',
                    'display_name': '',
                    'running': False,
                    'thread_alive': False,
                    'connected': None,
                    'source': 'runtime',
                }
                entry.update(st)
                entry['source'] = 'runtime'

                if entry.get('connected', None) is None:
                    try:
                        entry['connected'] = Path(str(device_path)).exists()
                    except Exception:
                        entry['connected'] = None

                scanner_status[device_path] = entry
        
        # Get recent scan count (legacy count). In thin runtime this may be 0;
        # the thin dashboard also shows recent archive entries.
        recent_scans = get_recent_scan_count()

        runtime_attached = bool(getattr(app, 'scanner_manager', None))
        thin_mode = _thin_mode_enabled()
        
        status = {
            'timestamp': datetime.now().isoformat(),
            'scanners': scanner_status,
            'recent_scans': recent_scans,
            'system_uptime': get_system_uptime(),
            # If thin runtime is running, we're in-process; consider this "up"
            # even if the legacy service check doesn't apply.
            'service_status': True if (thin_mode and runtime_attached) else get_service_status(),
            'thin_mode': thin_mode,
            'runtime_attached': runtime_attached,
        }
        
        return jsonify(status)
    except Exception as e:
        logging.error(f"Error getting status: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans/recent')
def get_recent_scans():
    """Get recent scans (last 24 hours)"""
    try:
        # Read from log file or database
        scans = get_recent_scans_from_log()
        return jsonify({'scans': scans})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/scans')
def scans_page():
    """Searchable scan log page (like Google Sheets Scan_Log)."""
    try:
        return render_template('scans.html')
    except Exception as e:
        logging.error(f"Error rendering scans page: {e}", exc_info=True)
        return f"<h1>Error loading scans page</h1><p>{e}</p>", 500


@app.route('/admin')
def admin_page():
    """Admin page with password protection"""
    # If any auth is enabled, require admin role for the admin panel.
    if _auth_enabled() and _current_role(session) != 'admin':
        return render_template('admin_login.html')

    # Check if password is set
    try:
        if get_db_connection:
            from database_schema import get_setting
            password_hash = get_setting('admin_password_hash', '')
            if password_hash and not session.get('admin_authenticated'):
                # Password is set but not authenticated - show login
                return render_template('admin_login.html')
    except Exception as e:
        logging.warning(f"Error checking admin password: {e}")
    
    # Authenticated or no password set
    try:
        if _thin_mode_enabled():
            return render_template('admin_thin.html', cloud_url=_cloud_dashboard_url())
        return render_template('admin.html')
    except Exception as e:
        logging.error(f"Error rendering admin page: {e}", exc_info=True)
        return f"<h1>Error loading admin page</h1><p>{e}</p>", 500


@app.route('/raw_scans')
def raw_scans_page():
    """Thin mode: raw scan history viewer (local)."""
    try:
        if _thin_mode_enabled():
            return render_template('raw_scans_thin.html', cloud_url=_cloud_dashboard_url())
        return redirect('/scans')
    except TemplateNotFound:
        # If sparse-checkout hasn't pulled the template yet, provide a functional inline page.
        cloud_url = _cloud_dashboard_url()
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          <title>Raw Scans (Thin)</title>
          <link rel="stylesheet" href="/static/common.css?v=20251222">
          <style>
            .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }}
            .row {{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; }}
            .small {{ font-size:12px; color:#666; }}
          </style>
        </head>
        <body>
          <div class="header">
            <h1>📄 Raw Scans (Thin)</h1>
            <div class="subtitle">Template not installed yet. This is a fallback view.</div>
            <div class="nav">
              <a href="/">Dashboard</a>
              <a href="/admin">Admin Mapping</a>
              <a class="active" href="/raw_scans">Raw Scans</a>
              <a href="{cloud_url}" target="_blank" rel="noopener">Cloud Dashboard</a>
            </div>
          </div>
          <div class="container">
            <div class="card">
              <div class="row">
                <span class="small">Showing last</span>
                <input id="limit" type="number" min="1" max="1000" value="250" style="width:110px;">
                <button class="btn btn-secondary" onclick="refresh()">Refresh</button>
                <a class="btn btn-primary" href="/api/thin/raw_scans/download">Download Raw JSONL</a>
              </div>
              <div style="margin-top:10px;">
                <input id="filter" placeholder="Filter..." style="min-width:280px;">
                <span class="small" id="count">0</span>
              </div>
            </div>
            <div class="card"><div id="list"><em>Loading…</em></div></div>
          </div>
          <script>
            let items = [];
            function esc(v) {{ return String(v ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }}
            function render() {{
              const box = document.getElementById('list');
              const q = (document.getElementById('filter').value || '').trim().toLowerCase();
              const filtered = !q ? items : items.filter(it => (String(it.station_code||'').toLowerCase().includes(q) || String(it.raw_data||it.data||'').toLowerCase().includes(q)));
              document.getElementById('count').textContent = `${{filtered.length}} scans`;
              if (!filtered.length) {{ box.innerHTML = '<em>No scans found.</em>'; return; }}
              box.innerHTML = filtered.map(it => `
                <div style="padding:8px; border-bottom:1px solid #eee;">
                  <div><strong>${{esc(it.station_code || 'Unknown')}}</strong> <span class="small">${{esc(it.timestamp || '')}}</span></div>
                  <div class="mono" style="font-size:12px; margin-top:4px;">${{esc(it.raw_data || it.data || '')}}</div>
                </div>`).join('');
            }}
            async function refresh() {{
              const n = Math.max(1, Math.min(1000, parseInt(document.getElementById('limit').value || '250', 10) || 250));
              const res = await fetch(`/api/thin/recent_scans?limit=${{n}}`);
              const data = await res.json();
              items = data.items || [];
              render();
            }}
            document.getElementById('filter').addEventListener('input', render);
            refresh();
          </script>
        </body>
        </html>
        """, 200
    except Exception as e:
        logging.error(f"Error rendering raw scans page: {e}", exc_info=True)
        return f"<h1>Error loading raw scans page</h1><p>{e}</p>", 500


@app.route('/help')
def help_page():
    """Help / setup walkthrough."""
    try:
        if _thin_mode_enabled():
            return render_template('help_thin.html', cloud_url=_cloud_dashboard_url())
        return render_template('help.html')
    except TemplateNotFound:
        cloud_url = _cloud_dashboard_url()
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          <title>Help (Thin)</title>
          <link rel="stylesheet" href="/static/common.css?v=20251222">
          <style>
            .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }}
            .muted {{ color:#666; font-size: 13px; }}
          </style>
        </head>
        <body>
          <div class="header">
            <h1>❓ Help (Thin)</h1>
            <div class="subtitle">Template not installed yet. This is a fallback view.</div>
            <div class="nav">
              <a href="/">Dashboard</a>
              <a href="/admin">Admin Mapping</a>
              <a href="/raw_scans">Raw Scans</a>
              <a class="active" href="/help">Help</a>
              <a href="{cloud_url}" target="_blank" rel="noopener">Cloud Dashboard</a>
            </div>
          </div>
          <div class="container">
            <div class="card">
              <p><strong>UI URLs</strong></p>
              <ul>
                <li><span class="mono">http://&lt;pi-ip&gt;:5006/</span></li>
                <li><span class="mono">http://&lt;pi-ip&gt;:5006/admin</span></li>
                <li><span class="mono">http://&lt;pi-ip&gt;:5006/raw_scans</span></li>
              </ul>
              <p class="muted">Tip: keep username <span class="mono">pi</span> so support can use <span class="mono">ssh pi@&lt;pi-ip&gt;</span>.</p>
              <p><strong>Order (cloud → Pi)</strong></p>
              <ol>
                <li>Create stations in cloud</li>
                <li>Generate pairing code</li>
                <li>Map dongles in <span class="mono">/admin</span></li>
                <li>Paste pairing code in <span class="mono">/admin</span> → Pair</li>
              </ol>
              <p class="muted">Cloud help: <a href="{cloud_url.rstrip('/')}/help#pi" target="_blank" rel="noopener">{cloud_url.rstrip('/')}/help#pi</a></p>
            </div>
          </div>
        </body>
        </html>
        """


def _recent_scans_from_db(limit: int) -> list:
    """Best-effort: fetch recent scan rows from local SQLite DB (includes station_code)."""
    if not get_db_connection:
        return []
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT timestamp, station_code, raw_data, station_display_name, operator_id FROM scans ORDER BY id DESC LIMIT ?",
            (int(limit),)
        )
        rows = cursor.fetchall() or []
        conn.close()
        out = []
        for r in rows:
            try:
                out.append({
                    'timestamp': str(r['timestamp']),
                    'station_code': r['station_code'],
                    'station_display_name': r.get('station_display_name') if hasattr(r, 'get') else r['station_display_name'],
                    'raw_data': r['raw_data'],
                    'operator_id': r.get('operator_id') if hasattr(r, 'get') else r['operator_id'],
                })
            except Exception:
                # sqlite3.Row supports dict-like access
                out.append({
                    'timestamp': str(r[0]),
                    'station_code': r[1],
                    'raw_data': r[2],
                })
        return out
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return []


@app.route('/login')
def login_page():
    """General login (shop/admin) to enable saving/editing."""
    return render_template('login.html')


@app.route('/api/auth/status', methods=['GET'])
def api_auth_status():
    return jsonify({
        'enabled': _auth_enabled(),
        'role': _current_role(session),
        'db_admin_password_set': bool(_get_setting('admin_password_hash', '').strip()),
        'db_shop_password_set': bool(_get_setting('shop_password_hash', '').strip()),
    })


@app.route('/api/auth/login', methods=['POST'])
def api_auth_login():
    """Login using either env-configured passwords or DB-stored passwords."""
    if not _auth_enabled():
        return jsonify({'authenticated': False, 'error': 'Auth not enabled on this server.'}), 501

    data = request.get_json(silent=True) or {}

    ok, role = (False, 'viewer')
    if _is_auth_enabled():
        ok, role = _check_password_env(data.get('password', ''))
    if not ok:
        ok, role = _check_password_db(data.get('password', ''))
    if not ok:
        return jsonify({'authenticated': False, 'error': 'Invalid password'}), 401

    _set_role(session, role)
    return jsonify({'authenticated': True, 'role': role})


@app.route('/api/auth/logout', methods=['POST'])
def api_auth_logout():
    _clear_role(session)
    return jsonify({'success': True, 'role': _current_role(session)})


@app.route('/api/shop/password/set', methods=['POST'])
def shop_set_password_local():
    """Set (or change) shop password hash in settings.

    Requires admin role if an admin password already exists.
    """
    stored_admin = _get_setting('admin_password_hash', '').strip()
    stored_shop = _get_setting('shop_password_hash', '').strip()

    # Enforce admin-first setup so we don't end up with a system that has a
    # shop password but no way to authenticate as admin.
    if not stored_admin and stored_shop:
        return jsonify({'error': 'Admin password must be set first.'}), 400

    if stored_admin and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authenticated. Please log in as admin first.'}), 401

    data = request.get_json(silent=True) or {}
    password = (data.get('password') or '').strip()
    if not password:
        return jsonify({'error': 'Password required'}), 400

    import hashlib

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    _set_setting('shop_password_hash', password_hash)
    return jsonify({'success': True})


@app.route('/api/scans', methods=['GET'])
def scans_proxy():
    """Proxy scan queries to the API server on :5007."""
    # If API is up, use it. If not, fall back to direct DB query.
    resp, status = _proxy_api_5007("/api/scans", method="GET", params=request.args)
    if status != 503 or not get_db_connection:
        return resp, status

    try:
        # DB fallback (same filters supported as api_server.py)
        station = request.args.get('station')
        station_display_name = request.args.get('station_display_name')
        job_like = request.args.get('job_name') or request.args.get('job')
        cabinet_assembly = request.args.get('cabinet_assembly')
        cabinet_name = request.args.get('cabinet_name')
        part_name = request.args.get('part_name')
        gcode = request.args.get('gcode')
        part_num = request.args.get('part_num')
        opening_letter = request.args.get('opening_letter')
        material = request.args.get('material')
        material_thickness = request.args.get('material_thickness')
        run_name = request.args.get('run_name')
        raw = request.args.get('raw')
        operator_id = request.args.get('operator_id')
        date = request.args.get('date')
        limit = int(request.args.get('limit', 200))
        offset = int(request.args.get('offset', 0))
        room_num = request.args.get('room_num')
        cabinet_num = request.args.get('cabinet_num')
        room_code = request.args.get('room_code')
        cabinet_code = request.args.get('cabinet_code')
        cab_type = request.args.get('cab_type')

        conn = get_db_connection()
        cursor = conn.cursor()

        where = ['1=1']
        params = []

        if station:
            where.append('station_code = ?')
            params.append(station)

        if station_display_name:
            where.append('station_display_name = ?')
            params.append(station_display_name)
        if date:
            where.append('DATE(timestamp) = ?')
            params.append(date)
        if job_like:
            where.append('job_name LIKE ?')
            params.append(f'%{job_like}%')
        if cabinet_assembly:
            where.append('cabinet_assembly LIKE ?')
            params.append(f'%{cabinet_assembly}%')
        if cabinet_name:
            where.append('cabinet_name LIKE ?')
            params.append(f'%{cabinet_name}%')
        if part_name:
            where.append('part_name LIKE ?')
            params.append(f'%{part_name}%')
        if gcode:
            where.append('gcode LIKE ?')
            params.append(f'%{gcode}%')
        if part_num:
            where.append('part_num LIKE ?')
            params.append(f'%{part_num}%')
        if opening_letter:
            where.append('opening_letter LIKE ?')
            params.append(f'%{opening_letter}%')
        if material:
            where.append('material LIKE ?')
            params.append(f'%{material}%')
        if material_thickness:
            where.append('material_thickness LIKE ?')
            params.append(f'%{material_thickness}%')
        if run_name:
            where.append('run_name LIKE ?')
            params.append(f'%{run_name}%')
        if raw:
            where.append('raw_data LIKE ?')
            params.append(f'%{raw}%')
        if operator_id:
            where.append('operator_id LIKE ?')
            params.append(f'%{operator_id}%')
        if room_num:
            where.append('room_num = ?')
            params.append(int(room_num))
        if cabinet_num:
            where.append('cabinet_num = ?')
            params.append(int(cabinet_num))
        if room_code:
            where.append('room_code LIKE ?')
            params.append(f'%{room_code}%')
        if cabinet_code:
            where.append('cabinet_code LIKE ?')
            params.append(f'%{cabinet_code}%')
        if cab_type:
            where.append('cab_type = ?')
            params.append(cab_type)

        where_sql = ' AND '.join(where)
        cursor.execute(f'SELECT COUNT(*) as count FROM scans WHERE {where_sql}', params)
        total = int(cursor.fetchone()['count'])

        cursor.execute(
            f'SELECT * FROM scans WHERE {where_sql} ORDER BY timestamp DESC LIMIT ? OFFSET ?',
            [*params, limit, offset]
        )
        scans = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return jsonify({'scans': scans, 'count': len(scans), 'total': total, 'limit': limit, 'offset': offset, 'fallback': 'db'}), 200
    except Exception as e:
        logging.error(f"DB fallback for /api/scans failed: {e}", exc_info=True)
        return jsonify({'error': 'API unavailable', 'details': str(e)}), 503


@app.route('/api/stations', methods=['GET'])
def stations_fallback():
    """Station metrics compatible with api_server.py /api/stations.

    Cloud deployments often expose only the dashboard origin (qr.<domain>) but not the API server (:5007).
    The web_app uses this endpoint to populate the station list.
    """
    if not get_db_connection:
        return jsonify({'stations': []}), 200

    stations = ['H08', 'H10', 'Edge', 'Dowel', 'Sort', 'Pull', 'Assembly', 'QC']
    today = datetime.now().date().isoformat()
    metrics_by_station = {
        s: {
            'station_code': s,
            'scans_today': 0,
            'scans_this_week': 0,
            'jobs_today': 0,
            'date': today,
            'last_scan': None,
        }
        for s in stations
    }

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT
                station_code,
                SUM(CASE WHEN DATE(timestamp) = DATE('now', 'localtime') THEN 1 ELSE 0 END) AS scans_today,
                SUM(CASE WHEN timestamp >= DATETIME('now', '-7 days', 'localtime') THEN 1 ELSE 0 END) AS scans_this_week,
                COUNT(DISTINCT CASE WHEN DATE(timestamp) = DATE('now', 'localtime') THEN job_name END) AS jobs_today,
                MAX(timestamp) AS last_scan
            FROM scans
            WHERE station_code IS NOT NULL AND station_code != ''
            GROUP BY station_code
        ''')

        for row in cursor.fetchall():
            station_code = row['station_code']
            if station_code not in metrics_by_station:
                metrics_by_station[station_code] = {
                    'station_code': station_code,
                    'scans_today': 0,
                    'scans_this_week': 0,
                    'jobs_today': 0,
                    'date': today,
                    'last_scan': None,
                }

            m = metrics_by_station[station_code]
            m['scans_today'] = int(row['scans_today'] or 0)
            m['scans_this_week'] = int(row['scans_this_week'] or 0)
            m['jobs_today'] = int(row['jobs_today'] or 0)
            m['last_scan'] = row['last_scan']

        conn.close()
        return jsonify({'stations': list(metrics_by_station.values())}), 200
    except Exception as e:
        logging.error(f"/api/stations fallback failed: {e}", exc_info=True)
        return jsonify({'stations': [], 'error': str(e)}), 500


@app.route('/api/operators', methods=['GET', 'POST'])
def operators_proxy():
    """Proxy operators to API server (:5007)."""
    if request.method == 'GET':
        if not _api_5007_available():
            # Thin Pi mode: we don't manage operator rosters locally.
            return jsonify({'operators': []}), 200
        return _proxy_api_5007("/api/operators", method="GET", params=request.args)
    if _auth_enabled() and _current_role(session) == 'viewer':
        return jsonify({'error': 'Not authorized to save. Enter a password at /login.', 'required_role': 'shop'}), 403
    if not _api_5007_available():
        return jsonify({'error': 'Not supported in thin mode'}), 501
    return _proxy_api_5007("/api/operators", method="POST", json_body=(request.get_json(silent=True) or {}))


@app.route('/api/autocomplete/<field>', methods=['GET'])
def autocomplete(field: str):
    """Return distinct values for fast scan log searching (job/material/part)."""
    if not get_db_connection:
        return jsonify({'values': []})

    allowed = {
        'job_name': 'job_name',
        'material': 'material',
        'material_thickness': 'material_thickness',
        'part_name': 'part_name',
        'run_name': 'run_name',
        'operator_id': 'operator_id',
    }
    col = allowed.get(field)
    if not col:
        return jsonify({'error': 'Invalid field'}), 400

    q = (request.args.get('q') or '').strip()
    limit = int(request.args.get('limit', 50))
    limit = max(1, min(limit, 200))

    conn = get_db_connection()
    cursor = conn.cursor()

    where = f"{col} IS NOT NULL AND {col} != ''"
    params = []
    if q:
        where += f" AND {col} LIKE ?"
        params.append(f'%{q}%')

    cursor.execute(f'''
        SELECT {col} as v, COUNT(*) as c
        FROM scans
        WHERE {where}
        GROUP BY {col}
        ORDER BY c DESC
        LIMIT ?
    ''', [*params, limit])

    values = [r['v'] for r in cursor.fetchall()]
    conn.close()
    return jsonify({'values': values})

@app.route('/api/service/restart', methods=['POST'])
def restart_service():
    """Restart QR scanner service"""
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403

    user = request.remote_user or 'anonymous'
    client_ip = request.remote_addr
    
    # Check permission if access control is available
    if access_control:
        if not access_control.check_permission(user, 'restart_service', client_ip):
            return jsonify({'error': 'Permission denied'}), 403
    
    try:
        import subprocess
        result = subprocess.run(['sudo', 'systemctl', 'restart', 'qr-scanner'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return jsonify({'success': True, 'message': 'Service restarted'})
        else:
            return jsonify({'error': result.stderr}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scanner/restart/<path:device_path>', methods=['POST'])
def restart_scanner(device_path):
    """Restart a single scanner without affecting others"""
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403

    # Decode the device path (may have slashes encoded)
    device_path = '/' + device_path if not device_path.startswith('/') else device_path
    
    if not app.scanner_manager:
        return jsonify({'error': 'Scanner manager not available'}), 503
    
    try:
        success, message = app.scanner_manager.restart_scanner(device_path)
        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'error': message}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scanner/restart_by_station/<station_code>', methods=['POST'])
def restart_scanner_by_station(station_code):
    """Restart scanner by station code (H08, H10, QC, etc.)"""
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403

    if not app.scanner_manager:
        return jsonify({'error': 'Scanner manager not available'}), 503
    
    try:
        # Find device path for this station code
        for device_path, scanner in app.scanner_manager.scanners.items():
            if scanner.station_code == station_code:
                success, message = app.scanner_manager.restart_scanner(device_path)
                if success:
                    return jsonify({'success': True, 'message': message})
                else:
                    return jsonify({'error': message}), 400
        
        return jsonify({'error': f'Station {station_code} not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
def get_logs():
    """Get recent logs"""
    user = request.remote_user or 'anonymous'
    client_ip = request.remote_addr
    
    # Check permission if access control is available
    if access_control:
        if not access_control.check_permission(user, 'view_logs', client_ip):
            return jsonify({'error': 'Permission denied'}), 403
    
    try:
        import subprocess
        result = subprocess.run(['sudo', 'journalctl', '-u', 'qr-scanner', '-n', '50', '--no-pager'],
                              capture_output=True, text=True, timeout=5)
        logs = result.stdout.split('\n')
        return jsonify({'logs': logs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_recent_scan_count():
    """Get count of recent scans"""
    try:
        # Try to count from log file
        scans = get_recent_scans_from_log()
        now = datetime.now()
        last_hour = 0
        last_24h = 0
        
        for scan in scans:
            try:
                if scan.get('timestamp'):
                    scan_time = datetime.strptime(scan['timestamp'], '%Y-%m-%d %H:%M:%S')
                    delta = now - scan_time
                    if delta.total_seconds() < 3600:
                        last_hour += 1
                    if delta.total_seconds() < 86400:
                        last_24h += 1
            except:
                pass
        
        return {'last_hour': last_hour, 'last_24_hours': last_24h}
    except:
        return {'last_hour': 0, 'last_24_hours': 0}

def get_recent_scans_from_log():
    """Get recent scans from log file"""
    def _tail_lines(path: Path, max_lines: int = 50, max_bytes: int = 256 * 1024) -> list:
        """Read the last N lines from a potentially large file efficiently.

        Avoids f.readlines() which loads the whole file into RAM.
        """
        try:
            if max_lines <= 0:
                return []
            size = path.stat().st_size
            if size <= 0:
                return []

            # Read from end in chunks until we have enough newlines.
            chunk_size = 8192
            data = b""
            with open(path, 'rb') as f:
                offset = 0
                while True:
                    offset = min(size, offset + chunk_size)
                    f.seek(size - offset)
                    data = f.read(offset) + b""  # ensure bytes

                    # Limit bytes held in memory.
                    if len(data) > max_bytes:
                        data = data[-max_bytes:]

                    if data.count(b'\n') >= max_lines + 1 or offset >= size:
                        break

            text = data.decode('utf-8', errors='replace')
            lines = text.splitlines()
            return lines[-max_lines:]
        except Exception:
            return []

    # Try multiple possible log file locations
    log_paths = [
        Path('logs/qr_scanner.log'),
        Path('/home/pi/qr-scanner/logs/qr_scanner.log'),
        Path('qr_scanner.log')
    ]
    
    scans = []
    for log_file in log_paths:
        if log_file.exists():
            try:
                # Read only the last 50 lines (do not load the whole file)
                for line in _tail_lines(log_file, max_lines=50):
                    if 'Successfully processed scan' in line or 'Scan processed' in line:
                        scans.append({'timestamp': line[:19] if len(line) > 19 else '', 'data': line.strip()})
                break
            except Exception as e:
                logging.warning(f"Could not read log file {log_file}: {e}")
                continue
    
    return scans[:20]  # Return last 20

def get_system_uptime():
    """Get system uptime"""
    try:
        import subprocess
        result = subprocess.run(['uptime'], capture_output=True, text=True)
        return result.stdout.strip()
    except:
        return "Unknown"

def get_service_status():
    """Get service status"""
    try:
        import subprocess
        result = subprocess.run(['systemctl', 'is-active', 'qr-scanner'], 
                              capture_output=True, text=True)
        return result.stdout.strip() == 'active'
    except:
        return False

# ============================================
# DASHBOARD PAGES
# ============================================

@app.route('/maintenance')
def maintenance_page():
    """Maintenance tracking dashboard"""
    try:
        return render_template('maintenance.html')
    except Exception as e:
        logging.error(f"Error rendering maintenance page: {e}", exc_info=True)
        return f"<h1>Error loading maintenance page</h1><p>{e}</p>", 500


@app.route('/recuts')
def recuts_page():
    """Recut tracking dashboard"""
    try:
        return render_template('recuts.html')
    except Exception as e:
        logging.error(f"Error rendering recuts page: {e}", exc_info=True)
        return f"<h1>Error loading recuts page</h1><p>{e}</p>", 500

@app.route('/inventory')
def inventory_page():
    """Material inventory dashboard"""
    try:
        return render_template('inventory.html')
    except Exception as e:
        logging.error(f"Error rendering inventory page: {e}", exc_info=True)
        return f"<h1>Error loading inventory page</h1><p>{e}</p>", 500

@app.route('/tools')
def tools_page():
    """Tool life monitoring dashboard"""
    try:
        return render_template('tools.html')
    except Exception as e:
        logging.error(f"Error rendering tools page: {e}", exc_info=True)
        return f"<h1>Error loading tools page</h1><p>{e}</p>", 500

@app.route('/reports')
def reports_page():
    """Station reports dashboard"""
    try:
        return render_template('reports.html')
    except Exception as e:
        logging.error(f"Error rendering reports page: {e}", exc_info=True)
        return f"<h1>Error loading reports page</h1><p>{e}</p>", 500


@app.route('/mobile')
def mobile_scan_page():
    """Mobile/tablet scan page (camera + manual input)."""
    try:
        return render_template('mobile_scan.html')
    except Exception as e:
        logging.error(f"Error rendering mobile scan page: {e}", exc_info=True)
        return f"<h1>Error loading mobile scan page</h1><p>{e}</p>", 500

# ============================================
# API ENDPOINTS FOR DASHBOARDS
# ============================================

@app.route('/api/maintenance/logs')
def get_maintenance_logs():
    """Get maintenance logs for dashboard"""
    try:
        # Prefer direct DB access if available (avoids 503s when :5007 API is down)
        limit = request.args.get('limit', 50, type=int)
        machine = request.args.get('machine')

        if get_db_connection:
            conn = get_db_connection()
            cursor = conn.cursor()

            query = 'SELECT * FROM maintenance_log WHERE 1=1'
            params = []
            if machine:
                query += ' AND machine = ?'
                params.append(machine)
            query += ' ORDER BY timestamp DESC LIMIT ?'
            params.append(limit)
            cursor.execute(query, params)
            logs = [dict(row) for row in cursor.fetchall()]
            conn.close()

            for r in logs:
                p = (r.get('photo_path') or '').strip()
                r['photo_url'] = ('/api/' + p.replace('\\', '/')) if p else None

            return jsonify({'maintenance_logs': logs})

        # Fallback to HTTP API
        import requests
        api_url = 'http://localhost:5007/api/maintenance'
        params = {'limit': limit}
        if machine:
            params['machine'] = machine
        response = requests.get(api_url, params=params, timeout=5)
        if response.status_code == 200:
            return jsonify(response.json())
        return jsonify({'error': 'API unavailable'}), 503
    except Exception as e:
        logging.error(f"Error fetching maintenance logs: {e}")
        return jsonify({'error': str(e)}), 500


def _save_maintenance_photo_local(photo):
    """Save a maintenance photo locally under uploads/maintenance and return photo_path value."""
    try:
        uploads_dir = (Path(__file__).parent / 'uploads' / 'maintenance')
        uploads_dir.mkdir(parents=True, exist_ok=True)

        original = secure_filename(getattr(photo, 'filename', '') or '')
        ext = ''
        if '.' in original:
            ext = '.' + original.split('.')[-1].lower()
        ts = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        fname = f"maintenance_{ts}{ext}" if ext else f"maintenance_{ts}.jpg"
        fp = uploads_dir / fname
        photo.save(fp)
        return f"uploads/maintenance/{fname}"
    except Exception:
        return None


def _parse_contains_list(s: str):
    parts = []
    for p in (s or '').split(','):
        v = p.strip().lower()
        if v:
            parts.append(v)
    return parts


def _count_scans_for_tool_between(cursor, machine: str, start_ts, end_ts, tool_row: dict, unit_type: str = 'parts') -> int:
    """Count scans between start/end for a tool, using tool's count_* rules."""
    unit_type = (unit_type or 'parts').strip().lower()
    if unit_type not in ('parts', 'sheets'):
        unit_type = 'parts'

    where = ["station_code = ?"]
    params = [machine]

    if start_ts:
        where.append('timestamp > ?')
        params.append(start_ts)
    if end_ts:
        where.append('timestamp <= ?')
        params.append(end_ts)

    material_terms = _parse_contains_list(tool_row.get('count_material_contains') or '')
    part_terms = _parse_contains_list(tool_row.get('count_part_name_contains') or '')
    requires_opening = 1 if int(tool_row.get('count_requires_opening') or 0) else 0

    if material_terms:
        ors = ' OR '.join(['LOWER(COALESCE(material, "")) LIKE ?' for _ in material_terms])
        where.append(f'({ors})')
        params.extend([f'%{t}%' for t in material_terms])

    if part_terms:
        ors = ' OR '.join(['LOWER(COALESCE(part_name, "")) LIKE ?' for _ in part_terms])
        where.append(f'({ors})')
        params.extend([f'%{t}%' for t in part_terms])

    if requires_opening:
        where.append("COALESCE(opening_letter, '') <> ''")

    where_sql = ' AND '.join(where)

    if unit_type == 'sheets':
        sql = f'''
            SELECT COUNT(*) as c FROM (
                SELECT DISTINCT
                    COALESCE(NULLIF(block_id, ''), DATE(timestamp)) as grp_block,
                    COALESCE(gcode, '') as grp_gcode,
                    COALESCE(job_name, '') as grp_job,
                    COALESCE(run_name, '') as grp_run,
                    COALESCE(material, '') as grp_mat
                FROM scans
                WHERE {where_sql}
                  AND COALESCE(gcode, '') <> ''
            ) t
        '''
        cursor.execute(sql, params)
        r = cursor.fetchone()
        return int((r['c'] if r else 0) or 0)

    cursor.execute(f'SELECT COUNT(*) as c FROM scans WHERE {where_sql}', params)
    r = cursor.fetchone()
    return int((r['c'] if r else 0) or 0)


@app.route('/api/maintenance', methods=['POST'])
def add_maintenance_proxy():
    """Proxy maintenance creation to API server (:5007). Supports multipart photo upload."""
    if _auth_enabled() and _current_role(session) == 'viewer':
        return jsonify({'error': 'Not authorized to save. Enter a password at /login.', 'required_role': 'shop'}), 403

    try:
        # Prefer direct DB insert if available (avoids 503s when :5007 API is down)
        if get_db_connection:
            data = {}
            photo_path = None

            if request.content_type and 'multipart/form-data' in request.content_type:
                data = dict(request.form or {})
                try:
                    photo = request.files.get('photo')
                    if photo and getattr(photo, 'filename', ''):
                        photo_path = _save_maintenance_photo_local(photo)
                except Exception:
                    photo_path = None
            else:
                data = request.get_json(silent=True) or {}

            conn = get_db_connection()
            cursor = conn.cursor()

            machine = data.get('machine')
            event_type = data.get('event_type', 'maintenance')

            # Calculate parts since last maintenance of same event_type
            cursor.execute('''
                SELECT MAX(timestamp) as last_maint FROM maintenance_log
                WHERE machine = ? AND event_type = ?
            ''', (machine, event_type))
            row = cursor.fetchone()
            last_maint = row['last_maint'] if row else None

            parts_since = 0
            if last_maint:
                cursor.execute('''
                    SELECT COUNT(*) as count FROM scans
                    WHERE station_code = ? AND timestamp > ?
                ''', (machine, last_maint))
                r2 = cursor.fetchone()
                parts_since = int((r2['count'] if r2 else 0) or 0)

            # Duration
            duration = None
            if data.get('duration_minutes') not in (None, '', 'null'):
                try:
                    duration = float(data.get('duration_minutes'))
                except Exception:
                    duration = None
            if duration is None and data.get('time_start') and data.get('time_end'):
                try:
                    start = datetime.fromisoformat(data['time_start'])
                    end = datetime.fromisoformat(data['time_end'])
                    duration = (end - start).total_seconds() / 60
                except Exception:
                    duration = None

            resolved_flag = 1 if str(data.get('resolved', '')).lower() in ('1', 'true', 'yes', 'on') else 0
            resolved_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S') if resolved_flag else None

            cursor.execute('''
                INSERT INTO maintenance_log (
                    machine, event_type, tool, operator_id, reason, description, notes,
                    time_start, time_end, duration_minutes, parts_since_last, photo_path,
                    assigned_to, resolved, resolved_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                machine,
                event_type,
                data.get('tool'),
                data.get('operator_id'),
                data.get('reason'),
                data.get('description'),
                data.get('notes'),
                data.get('time_start'),
                data.get('time_end'),
                duration,
                parts_since,
                photo_path,
                data.get('assigned_to'),
                resolved_flag,
                resolved_at,
            ))

            log_id = cursor.lastrowid
            conn.commit()
            conn.close()

            return jsonify({'success': True, 'maintenance_id': log_id, 'parts_since_last': parts_since, 'photo_path': photo_path}), 200

        # Fallback to HTTP API
        import requests
        api_url = 'http://localhost:5007/api/maintenance'
        if request.content_type and 'multipart/form-data' in request.content_type:
            files = {}
            if 'photo' in request.files:
                f = request.files['photo']
                if f and getattr(f, 'filename', ''):
                    files['photo'] = (f.filename, f.stream, f.mimetype)
            data = dict(request.form or {})
            resp = requests.post(api_url, files=files if files else None, data=data, timeout=30)
            return jsonify(resp.json()), resp.status_code
        payload = request.get_json(silent=True) or {}
        resp = requests.post(api_url, json=payload, timeout=15)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        logging.error(f"Error proxying maintenance POST: {e}")
        return jsonify({'error': 'API unavailable', 'details': str(e)}), 503


@app.route('/api/maintenance/<int:log_id>', methods=['PUT', 'DELETE'])
def maintenance_mutation_proxy(log_id: int):
    """Proxy maintenance update/delete to API server (:5007)."""
    if _auth_enabled() and request.method == 'PUT' and _current_role(session) == 'viewer':
        return jsonify({'error': 'Not authorized to save. Enter a password at /login.', 'required_role': 'shop'}), 403
    if _auth_enabled() and request.method == 'DELETE' and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized to delete. Admin password required.', 'required_role': 'admin'}), 403

    # Prefer DB mutations if available
    if get_db_connection:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM maintenance_log WHERE id = ?', (log_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({'error': 'Not found'}), 404

        if request.method == 'DELETE':
            # Delete attached photo file if present
            try:
                p = (row['photo_path'] or '').strip()
                if p:
                    # p is like uploads/maintenance/<file>
                    fname = Path(p).name
                    fp = (Path(__file__).parent / 'uploads' / 'maintenance' / fname)
                    if fp.exists():
                        fp.unlink()
            except Exception:
                pass
            cursor.execute('DELETE FROM maintenance_log WHERE id = ?', (log_id,))
            conn.commit()
            conn.close()
            return jsonify({'success': True}), 200

        # PUT: currently used by UI for resolved toggle
        payload = request.get_json(silent=True) or {}
        resolved_flag = 1 if bool(payload.get('resolved')) else 0
        resolved_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S') if resolved_flag else None
        cursor.execute('UPDATE maintenance_log SET resolved = ?, resolved_at = ? WHERE id = ?', (resolved_flag, resolved_at, log_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'id': log_id, 'resolved': resolved_flag, 'resolved_at': resolved_at}), 200

    # Fallback to HTTP API
    if request.method == 'PUT':
        return _proxy_api_5007(f'/api/maintenance/{log_id}', method='PUT', json_body=(request.get_json(silent=True) or {}))
    return _proxy_api_5007(f'/api/maintenance/{log_id}', method='DELETE')


@app.route('/api/uploads/maintenance/<path:filename>', methods=['GET'])
def maintenance_upload_proxy(filename: str):
    """Proxy maintenance images from API server (:5007) so the UI can stay on :5006."""
    try:
        import requests
        url = f'http://localhost:5007/api/uploads/maintenance/{filename}'
        resp = requests.get(url, stream=True, timeout=15)
        if resp.status_code != 200:
            # Fallback: serve local file if present
            local_fp = (Path(__file__).parent / 'uploads' / 'maintenance' / Path(filename).name)
            if local_fp.exists():
                return send_file(str(local_fp))
            return jsonify({'error': 'Not found'}), resp.status_code
        return Response(resp.content, status=200, content_type=resp.headers.get('Content-Type', 'application/octet-stream'))
    except Exception as e:
        logging.error(f"Error proxying maintenance image: {e}")
        # Fallback: serve local file if present
        local_fp = (Path(__file__).parent / 'uploads' / 'maintenance' / Path(filename).name)
        if local_fp.exists():
            return send_file(str(local_fp))
        return jsonify({'error': 'API unavailable', 'details': str(e)}), 503


@app.route('/api/recuts', methods=['GET', 'POST'])
def recuts_proxy():
    """Proxy recuts to API server (:5007). Supports multipart photo upload on POST."""
    # First try API server
    if request.method == 'GET':
        resp, status = _proxy_api_5007('/api/recuts', method='GET', params=request.args)
        if status != 503:
            return resp, status
        # Fallback: query DB directly
        if not get_db_connection:
            return resp, status
        try:
            pending = (request.args.get('pending', 'false') or '').lower() == 'true'
            limit = int(request.args.get('limit', 50))
            machine = request.args.get('machine')
            request_type = request.args.get('request_type')
            fix_station = request.args.get('fix_station')
            job_name = request.args.get('job_name')
            gcode = request.args.get('gcode')
            part_name = request.args.get('part_name')
            operator_id = request.args.get('operator_id')
            caused_by = request.args.get('caused_by')
            q = request.args.get('q')

            conn = get_db_connection()
            cursor = conn.cursor()
            where = []
            params = []
            if pending:
                where.append('recut_completed = 0')
            if machine:
                where.append('machine = ?')
                params.append(machine)
            if request_type:
                where.append('request_type = ?')
                params.append(request_type)
            if fix_station:
                where.append('fix_station = ?')
                params.append(fix_station)
            if job_name:
                where.append('job_name LIKE ?')
                params.append(f'%{job_name}%')
            if gcode:
                where.append('gcode LIKE ?')
                params.append(f'%{gcode}%')
            if part_name:
                where.append('part_name LIKE ?')
                params.append(f'%{part_name}%')
            if operator_id:
                where.append('operator_id = ?')
                params.append(operator_id)
            if caused_by:
                where.append('caused_by = ?')
                params.append(caused_by)
            if q:
                where.append('(job_name LIKE ? OR cabinet_name LIKE ? OR part_name LIKE ? OR gcode LIKE ? OR notes LIKE ? OR operator_id LIKE ? OR caused_by LIKE ?)')
                like = f'%{q}%'
                params.extend([like, like, like, like, like, like, like])

            sql = 'SELECT * FROM recuts'
            if where:
                sql += ' WHERE ' + ' AND '.join(where)
            sql += ' ORDER BY timestamp DESC LIMIT ?'
            params.append(limit)
            cursor.execute(sql, params)
            recuts = [dict(r) for r in cursor.fetchall()]
            conn.close()

            for r in recuts:
                p = (r.get('photo_path') or '').strip()
                r['photo_url'] = ('/api/' + p.replace('\\', '/')) if p else None

            return jsonify({'recuts': recuts}), 200
        except Exception as e:
            logging.error(f"DB fallback recuts GET failed: {e}")
            return jsonify({'error': 'API unavailable', 'details': str(e)}), 503

    # POST
    if _auth_enabled() and _current_role(session) == 'viewer':
        return jsonify({'error': 'Not authorized to save. Enter a password at /login.', 'required_role': 'shop'}), 403

    try:
        import requests
        api_url = 'http://localhost:5007/api/recuts'
        if request.content_type and 'multipart/form-data' in request.content_type:
            files = {}
            if 'photo' in request.files:
                f = request.files['photo']
                if f and getattr(f, 'filename', ''):
                    try:
                        f.stream.seek(0)
                    except Exception:
                        pass
                    files['photo'] = (f.filename, f.read(), f.mimetype or 'application/octet-stream')
            data = dict(request.form or {})
            resp = requests.post(api_url, files=files if files else None, data=data, timeout=30)
            return jsonify(resp.json()), resp.status_code
        payload = request.get_json(silent=True) or {}
        resp = requests.post(api_url, json=payload, timeout=15)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        logging.error(f"Error proxying recuts POST: {e}")
        # Fallback: insert into DB directly (and save photo locally) if available
        if not get_db_connection:
            return jsonify({'error': 'API unavailable', 'details': str(e)}), 503
        try:
            RECUT_UPLOADS_DIR = (Path(__file__).parent / 'uploads' / 'recuts')
            RECUT_UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

            data = dict(request.form or {})
            photo_path = None
            if request.content_type and 'multipart/form-data' in request.content_type:
                photo = request.files.get('photo')
                if photo and getattr(photo, 'filename', ''):
                    original = secure_filename(photo.filename or '')
                    if original:
                        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        name = f"recut_{stamp}_{original}"
                        path = RECUT_UPLOADS_DIR / name
                        photo.save(str(path))
                        photo_path = f"uploads/recuts/{name}"

            request_type = (data.get('request_type') or '').strip() or 'recut'
            fix_station = (data.get('fix_station') or '').strip() or None
            caused_by = (data.get('caused_by') or '').strip() or None

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO recuts (
                    machine, request_type, fix_station,
                    job_name, cabinet_name, part_name, gcode,
                    operator_id, caused_by, reason, notes, photo_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data.get('machine'),
                request_type,
                fix_station,
                data.get('job_name'),
                data.get('cabinet_name'),
                data.get('part_name'),
                data.get('gcode'),
                data.get('operator_id'),
                caused_by,
                data.get('reason'),
                data.get('notes'),
                photo_path
            ))
            recut_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return jsonify({'success': True, 'recut_id': recut_id, 'photo_path': photo_path}), 200
        except Exception as e2:
            logging.error(f"DB fallback recuts POST failed: {e2}")
            return jsonify({'error': 'API unavailable', 'details': str(e2)}), 503


@app.route('/api/recuts/<int:recut_id>', methods=['PUT'])
def recut_update_proxy(recut_id: int):
    """Proxy recut completion updates to API server (:5007) with DB fallback."""
    if _auth_enabled() and _current_role(session) == 'viewer':
        return jsonify({'error': 'Not authorized to save. Enter a password at /login.', 'required_role': 'shop'}), 403

    resp, status = _proxy_api_5007(f'/api/recuts/{recut_id}', method='PUT', json_body=(request.get_json(silent=True) or {}))
    if status != 503:
        return resp, status
    if not get_db_connection:
        return resp, status
    try:
        data = request.get_json(silent=True) or {}
        recut_completed = 1 if bool(data.get('recut_completed')) else 0
        completed_by = (data.get('completed_by') or '').strip() or None
        completed_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S') if recut_completed else None
        if recut_completed and not completed_by:
            return jsonify({'error': 'completed_by is required'}), 400
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE recuts SET recut_completed = ?, completed_at = ?, completed_by = ? WHERE id = ?',
                       (recut_completed, completed_at, completed_by, recut_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'error': 'API unavailable', 'details': str(e)}), 503


@app.route('/api/recuts/<int:recut_id>', methods=['DELETE'])
def recut_delete_proxy(recut_id: int):
    """Proxy recut delete to API server (:5007) with DB fallback."""
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized to delete. Admin password required.', 'required_role': 'admin'}), 403

    resp, status = _proxy_api_5007(f'/api/recuts/{recut_id}', method='DELETE')
    if status != 503:
        return resp, status
    if not get_db_connection:
        return resp, status
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT photo_path FROM recuts WHERE id = ?', (recut_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({'error': 'Not found'}), 404
        photo_path = (row['photo_path'] or '').strip()
        cursor.execute('DELETE FROM recuts WHERE id = ?', (recut_id,))
        conn.commit()
        conn.close()

        # best-effort delete file
        try:
            if photo_path:
                fname = Path(photo_path.replace('\\', '/')).name
                p = RECUT_UPLOADS_DIR / fname
                if p.exists():
                    p.unlink()
        except Exception:
            pass

        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'error': 'API unavailable', 'details': str(e)}), 503


@app.route('/api/uploads/recuts/<path:filename>', methods=['GET'])
def recut_upload_proxy(filename: str):
    """Serve local recut images if present; otherwise proxy from API server (:5007)."""
    # First check local file (if recuts were created via dashboard fallback)
    try:
        local_dir = (Path(__file__).parent / 'uploads' / 'recuts')
        safe = Path(filename).name
        p = local_dir / safe
        if p.exists():
            return send_file(str(p))
    except Exception:
        pass
    try:
        import requests
        url = f'http://localhost:5007/api/uploads/recuts/{filename}'
        resp = requests.get(url, stream=True, timeout=15)
        if resp.status_code != 200:
            return jsonify({'error': 'Not found'}), resp.status_code
        return Response(resp.content, status=200, content_type=resp.headers.get('Content-Type', 'application/octet-stream'))
    except Exception as e:
        logging.error(f"Error proxying recut image: {e}")
        return jsonify({'error': 'API unavailable', 'details': str(e)}), 503

# ============================================
# INVENTORY API PROXIES (shop dashboard -> API server)
# ============================================

def _proxy_api_5007(path: str, method: str = "GET", params=None, json_body=None):
    """Proxy request to local API server on port 5007."""
    import requests
    base = "http://localhost:5007"
    url = f"{base}{path}"
    try:
        resp = requests.request(method, url, params=params, json=json_body, timeout=10)
        # Try JSON, fallback to raw text
        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text}
        return jsonify(data), resp.status_code
    except Exception as e:
        logging.error(f"Error proxying to API {url}: {e}")
        return jsonify({"error": "API unavailable", "details": str(e)}), 503


def _proxy_bin_manager_5000_multipart(path: str):
    """Proxy a multipart/form-data upload to the bin manager on port 5000."""
    import requests
    base = "http://localhost:5000"
    url = f"{base}{path}"
    try:
        files = {}
        if 'csv_file' in request.files:
            f = request.files['csv_file']
            try:
                f.stream.seek(0)
            except Exception:
                pass
            files['csv_file'] = (f.filename or 'cabinet_library.csv', f.read(), f.mimetype or 'text/csv')
        resp = requests.post(url, files=files, timeout=60)
        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text}
        return jsonify(data), resp.status_code
    except Exception as e:
        logging.error(f"Error proxying to bin manager {url}: {e}")
        return jsonify({"success": False, "error": "Bin manager unavailable", "details": str(e)}), 503


def _proxy_bin_manager_5000(path: str, method: str = "GET", params=None, json_body=None):
    """Proxy JSON/standard requests to the bin manager on port 5000."""
    import requests
    base = "http://localhost:5000"
    url = f"{base}{path}"
    try:
        resp = requests.request(method, url, params=params, json=json_body, timeout=15)
        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text}
        return jsonify(data), resp.status_code
    except Exception as e:
        logging.error(f"Error proxying to bin manager {url}: {e}")
        return jsonify({"error": "Bin manager unavailable", "details": str(e)}), 503


@app.route('/api/inventory/stats', methods=['GET'])
def inventory_stats_proxy():
    return _proxy_api_5007("/api/inventory/stats", method="GET", params=request.args)


@app.route('/api/inventory/consumption_by_material', methods=['GET'])
def inventory_consumption_by_material_proxy():
    return _proxy_api_5007("/api/inventory/consumption_by_material", method="GET", params=request.args)


@app.route('/api/inventory/materials', methods=['GET', 'POST'])
def inventory_materials_proxy():
    if request.method == 'GET':
        return _proxy_api_5007("/api/inventory/materials", method="GET", params=request.args)
    if _auth_enabled() and _current_role(session) == 'viewer':
        return jsonify({'error': 'Not authorized to save. Enter a password at /login.', 'required_role': 'shop'}), 403
    return _proxy_api_5007("/api/inventory/materials", method="POST", json_body=(request.get_json(silent=True) or {}))


@app.route('/api/inventory/materials/<int:material_id>', methods=['GET', 'PUT', 'DELETE'])
def inventory_material_proxy(material_id: int):
    if request.method == 'GET':
        return _proxy_api_5007(f"/api/inventory/materials/{material_id}", method="GET", params=request.args)
    if request.method == 'PUT':
        if _auth_enabled() and _current_role(session) == 'viewer':
            return jsonify({'error': 'Not authorized to save. Enter a password at /login.', 'required_role': 'shop'}), 403
        return _proxy_api_5007(f"/api/inventory/materials/{material_id}", method="PUT", json_body=(request.get_json(silent=True) or {}))
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized to delete. Admin password required.', 'required_role': 'admin'}), 403
    return _proxy_api_5007(f"/api/inventory/materials/{material_id}", method="DELETE", json_body=None)


@app.route('/api/inventory/materials/receive', methods=['POST'])
def inventory_receive_proxy():
    if _auth_enabled() and _current_role(session) == 'viewer':
        return jsonify({'error': 'Not authorized to save. Enter a password at /login.', 'required_role': 'shop'}), 403
    return _proxy_api_5007("/api/inventory/materials/receive", method="POST", json_body=(request.get_json(silent=True) or {}))


@app.route('/api/inventory/materials/consume', methods=['POST'])
def inventory_consume_proxy():
    if _auth_enabled() and _current_role(session) == 'viewer':
        return jsonify({'error': 'Not authorized to save. Enter a password at /login.', 'required_role': 'shop'}), 403
    return _proxy_api_5007("/api/inventory/materials/consume", method="POST", json_body=(request.get_json(silent=True) or {}))


@app.route('/api/inventory/materials/adjust', methods=['POST'])
def inventory_adjust_proxy():
    if _auth_enabled() and _current_role(session) == 'viewer':
        return jsonify({'error': 'Not authorized to save. Enter a password at /login.', 'required_role': 'shop'}), 403
    return _proxy_api_5007("/api/inventory/materials/adjust", method="POST", json_body=(request.get_json(silent=True) or {}))

@app.route('/api/inventory/materials/bulk_update', methods=['POST'])
def inventory_bulk_update_proxy():
    if _auth_enabled() and _current_role(session) == 'viewer':
        return jsonify({'error': 'Not authorized to save. Enter a password at /login.', 'required_role': 'shop'}), 403
    return _proxy_api_5007("/api/inventory/materials/bulk_update", method="POST", json_body=(request.get_json(silent=True) or {}))


@app.route('/api/inventory/transactions', methods=['GET'])
def inventory_transactions_proxy():
    return _proxy_api_5007("/api/inventory/transactions", method="GET", params=request.args)


@app.route('/api/inventory/import/materials_csv', methods=['POST'])
def inventory_import_materials_csv_proxy():
    """Proxy CSV upload to API server (:5007)."""
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized to import. Admin password required.', 'required_role': 'admin'}), 403
    try:
        import requests
        api_base = "http://localhost:5007"
        files = {}
        if 'file' in request.files:
            f = request.files['file']
            # Ensure bytes are actually sent (streams can be at EOF depending on server stack)
            try:
                f.stream.seek(0)
            except Exception:
                pass
            files['file'] = (f.filename or 'materials.csv', f.read(), f.mimetype or 'text/csv')
        data = {
            'default_category': request.form.get('default_category', ''),
        }
        resp = requests.post(f"{api_base}/api/inventory/import/materials_csv", files=files, data=data, timeout=30)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({'error': 'API unavailable', 'details': str(e)}), 503


@app.route('/api/bin_manager/import_cabinet_library_csv', methods=['POST'])
def bin_manager_import_cabinet_library_csv_proxy():
    """Proxy cabinet library CSV import to the bin manager (:5000)."""
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized to import. Admin password required.', 'required_role': 'admin'}), 403
    return _proxy_bin_manager_5000_multipart('/api/import_cabinet_library_csv')


@app.route('/api/bin_manager/cabinet_library', methods=['GET'])
def bin_manager_cabinet_library_proxy():
    return _proxy_bin_manager_5000('/api/cabinet_library', method='GET', params=request.args)


@app.route('/api/bin_manager/cabinet_library/part', methods=['POST', 'PUT', 'DELETE'])
def bin_manager_cabinet_library_part_proxy():
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized to edit cabinet library. Admin password required.', 'required_role': 'admin'}), 403
    if request.method == 'POST':
        return _proxy_bin_manager_5000('/api/cabinet_library/part', method='POST', json_body=(request.get_json(silent=True) or {}))
    if request.method == 'PUT':
        return _proxy_bin_manager_5000('/api/cabinet_library/part', method='PUT', json_body=(request.get_json(silent=True) or {}))
    # DELETE
    body = request.get_json(silent=True)
    return _proxy_bin_manager_5000('/api/cabinet_library/part', method='DELETE', params=request.args, json_body=(body or {}))


@app.route('/api/bin_manager/cabinet_library/cabinet/<path:cabinet_name>', methods=['DELETE'])
def bin_manager_cabinet_library_delete_cabinet_proxy(cabinet_name: str):
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized to delete cabinet type. Admin password required.', 'required_role': 'admin'}), 403
    return _proxy_bin_manager_5000(f'/api/cabinet_library/cabinet/{cabinet_name}', method='DELETE')


@app.route('/api/bin_manager/cabinet_library/reclassify_drawers', methods=['POST'])
def bin_manager_cabinet_library_reclassify_drawers_proxy():
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403
    return _proxy_bin_manager_5000('/api/cabinet_library/reclassify_drawers', method='POST', json_body=(request.get_json(silent=True) or {}))


@app.route('/api/admin/scans/purge', methods=['POST'])
def admin_purge_scans_proxy():
    """Proxy purge to API server (:5007)."""
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403
    return _proxy_api_5007("/api/admin/scans/purge", method="POST", json_body=(request.get_json(silent=True) or {}))


@app.route('/api/admin/dongles/detect', methods=['GET'])
def admin_detect_dongles_proxy():
    """Proxy dongle detection to API server"""
    if _api_5007_available():
        return _proxy_api_5007("/api/admin/dongles/detect", method="GET", params=request.args)

    # Thin Pi local implementation
    try:
        from detect_dongles import detect_scanners
        scanners = detect_scanners() or []
        return jsonify({'scanners': scanners, 'count': len(scanners)}), 200
    except Exception as e:
        return jsonify({'scanners': [], 'count': 0, 'error': str(e)}), 500


@app.route('/api/admin/stations', methods=['GET', 'POST'])
def admin_stations_proxy():
    """Proxy station management to API server"""
    if request.method == 'GET':
        if _api_5007_available():
            return _proxy_api_5007("/api/admin/stations", method="GET", params=request.args)
        # Thin Pi local implementation: read scanners{} from config.json
        try:
            cfg_path = _config_path()
            if not cfg_path.exists():
                return jsonify({'stations': []}), 200
            with open(cfg_path, 'r') as f:
                cfg = json.load(f) or {}
            scanners = cfg.get('scanners', {}) or {}
            stations = []
            for device_path, st_cfg in (scanners or {}).items():
                if not isinstance(st_cfg, dict):
                    continue
                stations.append({
                    'device_path': device_path,
                    'station_code': st_cfg.get('station_code'),
                    'station_sheet': st_cfg.get('station_sheet'),
                    'display_name': st_cfg.get('display_name') or st_cfg.get('station_code'),
                })
            return jsonify({'stations': stations}), 200
        except Exception as e:
            return jsonify({'stations': [], 'error': str(e)}), 500
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403
    if _api_5007_available():
        return _proxy_api_5007("/api/admin/stations", method="POST", json_body=(request.get_json(silent=True) or {}))

    # Thin Pi local implementation: update scanners{} in config.json
    try:
        body = request.get_json(silent=True) or {}
        cfg_path = _config_path()
        cfg = {}
        if cfg_path.exists():
            with open(cfg_path, 'r') as f:
                cfg = json.load(f) or {}

        # Accept either full scanners dict or stations list from the admin UI.
        new_scanners = None
        if isinstance(body.get('scanners'), dict):
            new_scanners = body.get('scanners')
        elif isinstance(body.get('stations'), list):
            new_scanners = {}
            for row in body.get('stations') or []:
                if not isinstance(row, dict):
                    continue
                dp = (row.get('device_path') or '').strip()
                sc = (row.get('station_code') or '').strip()
                if not dp or not sc:
                    continue
                new_scanners[dp] = {
                    'station_code': sc,
                    'station_sheet': (row.get('station_sheet') or '').strip() or None,
                    'display_name': (row.get('display_name') or '').strip() or None,
                }
        else:
            return jsonify({'error': 'Invalid payload'}), 400

        cfg['scanners'] = new_scanners or {}
        # Mark multi-scanner mode when multiple scanners are configured.
        cfg['multi_scanner_mode'] = bool(cfg['scanners'])

        with open(cfg_path, 'w') as f:
            json.dump(cfg, f, indent=2)

        # If running in thin runtime, apply changes immediately (in addition to file watch).
        try:
            mgr = getattr(app, 'scanner_manager', None)
            if mgr and hasattr(mgr, '_apply_scanner_config_delta'):
                mgr._apply_scanner_config_delta(cfg.get('scanners', {}) or {})  # type: ignore[attr-defined]
        except Exception:
            pass

        return jsonify({'success': True, 'stations': [{'device_path': k, **(v or {})} for k, v in (cfg['scanners'] or {}).items()]}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/operator_barcodes', methods=['GET', 'POST'])
def admin_operator_barcodes():
    """Manage operator badge barcodes (barcode -> operator_id) stored in DB settings."""
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403
    if not get_setting or not set_setting:
        return jsonify({'error': 'Settings not available on this server'}), 501

    key = 'operator_barcode_map_json'

    def _load_map() -> dict:
        try:
            raw = (get_setting(key, '{}') or '{}')
            mp = json.loads(raw) if isinstance(raw, str) else raw
            return mp if isinstance(mp, dict) else {}
        except Exception:
            return {}

    def _save_map(mp: dict) -> None:
        # Normalize
        out = {}
        for k, v in (mp or {}).items():
            kk = (str(k) or '').strip()
            vv = (str(v) or '').strip()
            if kk and vv:
                out[kk] = vv
        set_setting(key, json.dumps(out))

    if request.method == 'GET':
        mp = _load_map()
        items = [{'barcode': k, 'operator_id': v} for k, v in sorted(mp.items(), key=lambda kv: kv[0])]
        return jsonify({'mappings': items, 'count': len(items)}), 200

    body = request.get_json(silent=True) or {}
    barcode = (body.get('barcode') or '').strip()
    operator_id = (body.get('operator_id') or '').strip()
    delete = bool(body.get('delete'))

    mp = _load_map()
    if delete:
        if barcode:
            mp.pop(barcode, None)
            _save_map(mp)
        items = [{'barcode': k, 'operator_id': v} for k, v in sorted(mp.items(), key=lambda kv: kv[0])]
        return jsonify({'success': True, 'mappings': items, 'count': len(items)}), 200

    if not barcode or not operator_id:
        return jsonify({'error': 'barcode and operator_id are required'}), 400

    mp[barcode] = operator_id
    _save_map(mp)
    items = [{'barcode': k, 'operator_id': v} for k, v in sorted(mp.items(), key=lambda kv: kv[0])]
    return jsonify({'success': True, 'mappings': items, 'count': len(items)}), 200


@app.route('/api/admin/scan_defaults', methods=['GET', 'POST'])
def api_admin_scan_defaults():
    """Manage v1 scan parsing defaults (CSV field mapping / barcode mapping) stored in DB settings.

    Shape matches v2's scan_defaults:
      { csv_fallback: { delimiter: "auto"|"|"|","|"^"|"\t", columns: [..] } , field_labels: {..}, custom_labels: {..} }
    """
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403
    if not get_setting or not set_setting:
        return jsonify({'error': 'Settings not available on this server'}), 501

    key = 'scan_defaults_json'

    def _load() -> dict:
        try:
            raw = (get_setting(key, '{}') or '{}')
            d = json.loads(raw) if isinstance(raw, str) else raw
            return d if isinstance(d, dict) else {}
        except Exception:
            return {}

    if request.method == 'GET':
        return jsonify({'scan_defaults': _load()}), 200

    body = request.get_json(silent=True) or {}
    defaults = body.get('scan_defaults')
    if not isinstance(defaults, dict):
        return jsonify({'error': 'scan_defaults dict required'}), 400

    # Keep to safe keys only (no code injection)
    allowed = {'tracking_mode', 'csv_fallback', 'custom_labels', 'field_labels'}
    clean = {k: v for k, v in defaults.items() if k in allowed}
    set_setting(key, json.dumps(clean))
    return jsonify({'success': True, 'scan_defaults': clean}), 200


@app.route('/api/admin/assembly_unit_rules', methods=['GET', 'POST'])
def api_admin_assembly_unit_rules():
    """Manage Assembly grouping rules (Case/Drawer/Door/QC/etc) stored in DB settings."""
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403

    if not set_setting:
        return jsonify({'error': 'Settings not available on this server'}), 501

    key = 'assembly_unit_rules_json'

    def _load() -> dict:
        try:
            raw = get_setting(key, '') if get_setting else ''
            if not raw:
                return {}
            parsed = json.loads(raw) if isinstance(raw, str) else raw
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    if request.method == 'GET':
        return jsonify({'rules': _load()}), 200

    body = request.get_json(silent=True) or {}
    rules = body.get('rules')
    if not isinstance(rules, dict):
        return jsonify({'error': 'rules dict required'}), 400

    # Store as JSON (kept in DB, used by scanner + api_server via database_schema.classify_assembly_unit)
    try:
        set_setting(key, json.dumps(rules))
    except Exception as e:
        return jsonify({'error': f'Failed to save rules: {e}'}), 500
    return jsonify({'success': True, 'rules': rules}), 200


@app.route('/api/admin/assembly_unit_rules/test', methods=['POST'])
def api_admin_assembly_unit_rules_test():
    """Test Assembly grouping rules against a sample context without saving."""
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403
    body = request.get_json(silent=True) or {}
    ctx = body.get('ctx') or {}
    rules = body.get('rules')  # optional override
    try:
        from database_schema import classify_assembly_unit  # type: ignore
        unit = classify_assembly_unit(
            part_name=str(ctx.get('part_name') or ''),
            station_code=str(ctx.get('station_code') or 'Assembly'),
            station_display_name=str(ctx.get('station_display_name') or ''),
            opening_letter=str(ctx.get('opening_letter') or ''),
            rules_override=(rules if isinstance(rules, dict) else None),
        )
        return jsonify({'unit': unit}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/kiosk_layout', methods=['GET', 'POST'])
def api_admin_kiosk_layout():
    """Manage station kiosk layout config stored in DB settings.

    This enables a no-code kiosk builder on /mobile kiosk mode.
    """
    if request.method == 'POST':
        if _auth_enabled() and _current_role(session) != 'admin':
            return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403
    else:
        # GET: allow viewer/shop role too
        if _auth_enabled() and _current_role(session) not in ['admin', 'shop', 'viewer']:
            return jsonify({'error': 'Authentication required'}), 401

    if not get_setting or not set_setting:
        return jsonify({'error': 'Settings not available on this server'}), 501

    key = 'kiosk_layout_json'

    def _load() -> dict:
        try:
            raw = (get_setting(key, '{}') or '{}')
            d = json.loads(raw) if isinstance(raw, str) else raw
            return d if isinstance(d, dict) else {}
        except Exception:
            return {}

    if request.method == 'GET':
        return jsonify({'layout': _load()}), 200

    body = request.get_json(silent=True) or {}
    layout = body.get('layout')
    if not isinstance(layout, dict):
        return jsonify({'error': 'layout dict required'}), 400

    # Keep keys constrained so we don't store arbitrary giant blobs
    allowed_top = {'version', 'defaults', 'stations', 'station_types', 'bin_config'}
    clean = {k: v for k, v in layout.items() if k in allowed_top}
    if 'version' not in clean:
        clean['version'] = 1

    try:
        set_setting(key, json.dumps(clean))
    except Exception as e:
        return jsonify({'error': f'Failed to save layout: {e}'}), 500
    return jsonify({'success': True, 'layout': clean}), 200


@app.route('/api/thin/recent_scans', methods=['GET'])
def thin_recent_scans():
    """Return recent scans from the thin-mode local archive JSONL (best effort)."""
    limit = 10
    try:
        limit = int(request.args.get('limit', '10'))
        if limit < 1:
            limit = 1
        if limit > 1000:
            limit = 1000
    except Exception:
        limit = 10

    try:
        # Prefer local DB first when available (it includes station_code).
        # This also fixes cases where cloud forwarding is disabled and scans are only logged locally.
        db_items = _recent_scans_from_db(limit) or []
        if db_items:
            return jsonify({'items': db_items, 'count': len(db_items), 'source': 'db'}), 200

        cfg_path = _config_path()
        cfg = {}
        if cfg_path.exists():
            with open(cfg_path, 'r') as f:
                cfg = json.load(f) or {}
        cloud = cfg.get('cloud_v2', {}) or {}
        thin_cfg = cfg.get('thin', {}) if isinstance(cfg.get('thin'), dict) else {}

        # Prefer thin local archive (always written, includes station_code)
        local_archive_path = (thin_cfg.get('local_archive_path') or cfg.get('local_archive_path') or 'local_backup/raw_scans.jsonl')
        local_ap = Path(str(local_archive_path))
        if not local_ap.is_absolute():
            local_ap = Path(os.getcwd()) / local_ap
        if local_ap.exists():
            ap = local_ap
            archive_kind = 'local_archive'
        else:
            archive_path = (cloud.get('archive_path') or 'cloud_backup/scans_archive.jsonl')
            ap = Path(str(archive_path))
            if not ap.is_absolute():
                ap = Path(os.getcwd()) / ap
            archive_kind = 'cloud_archive'

        if not ap.exists():
            items = get_recent_scans_from_log() or []
            return jsonify({'items': items, 'count': len(items), 'source': 'log', 'archive_path': str(ap)}), 200

        # Read last N lines without loading entire file.
        lines = []
        with open(ap, 'rb') as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 4096
            data = b''
            while size > 0 and len(lines) <= limit:
                read_size = block if size >= block else size
                size -= read_size
                f.seek(size)
                data = f.read(read_size) + data
                lines = data.splitlines()
        tail = lines[-limit:]
        items = []
        for bline in reversed(tail):
            try:
                obj = json.loads(bline.decode('utf-8', errors='replace'))
                if isinstance(obj, dict):
                    items.append(obj)
            except Exception:
                continue
        if not items:
            # If archive exists but empty, still try log fallback for UX.
            fallback = get_recent_scans_from_log() or []
            if fallback:
                return jsonify({'items': fallback, 'count': len(fallback), 'source': 'log', 'archive_path': str(ap)}), 200
        return jsonify({'items': items, 'count': len(items), 'source': archive_kind, 'archive_path': str(ap)}), 200
    except Exception as e:
        return jsonify({'items': [], 'count': 0, 'error': str(e)}), 500


@app.route('/api/thin/backup/download', methods=['GET'])
def thin_backup_download():
    """Download a zip containing thin Pi local support artifacts (no import required)."""
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403

    cfg_path = _config_path()
    cfg = {}
    try:
        if cfg_path.exists():
            with open(cfg_path, 'r') as f:
                cfg = json.load(f) or {}
    except Exception:
        cfg = {}

    cloud = cfg.get('cloud_v2', {}) or {}
    archive_path = (cloud.get('archive_path') or 'cloud_backup/scans_archive.jsonl')
    queue_path = (cloud.get('queue_path') or 'cloud_queue/scans.jsonl')

    def _abs(p: str) -> Path:
        pp = Path(str(p))
        if not pp.is_absolute():
            pp = Path(os.getcwd()) / pp
        return pp

    files = [
        ('config.json', cfg_path),
        ('cloud_backup/scans_archive.jsonl', _abs(archive_path)),
        ('cloud_queue/scans.jsonl', _abs(queue_path)),
        ('logs/qr_scanner.log', _abs('logs/qr_scanner.log')),
        ('qr_scanner.log', _abs('qr_scanner.log')),
    ]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode='w', compression=zipfile.ZIP_DEFLATED) as z:
        # Always include a small metadata file
        try:
            meta = {
                'timestamp': datetime.now().isoformat(),
                'cwd': os.getcwd(),
                'config_path': str(cfg_path),
                'thin_mode': _thin_mode_enabled(),
            }
            z.writestr('backup_meta.json', json.dumps(meta, indent=2))
        except Exception:
            pass

        for arcname, path in files:
            try:
                if path and Path(path).exists() and Path(path).is_file():
                    z.write(str(path), arcname)
            except Exception:
                continue

    buf.seek(0)
    return send_file(
        buf,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'innosaw-thin-backup-{datetime.now().strftime("%Y%m%d-%H%M%S")}.zip'
    )


@app.route('/api/thin/raw_scans/download', methods=['GET'])
def thin_raw_scans_download():
    """Download raw scan data only (JSONL)."""
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403

    # Prefer DB export if available (ensures station_code is present).
    try:
        db_items = _recent_scans_from_db(5000) or []
        if db_items:
            text = "\n".join(json.dumps(it, separators=(",", ":"), ensure_ascii=False) for it in db_items) + "\n"
            buf = io.BytesIO(text.encode('utf-8'))
            buf.seek(0)
            return send_file(
                buf,
                mimetype='text/plain; charset=utf-8',
                as_attachment=True,
                download_name=f'raw-scans-db-{datetime.now().strftime("%Y%m%d-%H%M%S")}.jsonl'
            )
    except Exception:
        pass

    # Otherwise: prefer thin local archive if present, then cloud archive.
    try:
        cfg_path = _config_path()
        cfg = {}
        if cfg_path.exists():
            with open(cfg_path, 'r') as f:
                cfg = json.load(f) or {}
        thin_cfg = cfg.get('thin', {}) if isinstance(cfg.get('thin'), dict) else {}
        local_archive_path = (thin_cfg.get('local_archive_path') or cfg.get('local_archive_path') or 'local_backup/raw_scans.jsonl')
        local_ap = Path(str(local_archive_path))
        if not local_ap.is_absolute():
            local_ap = Path(os.getcwd()) / local_ap
        if local_ap.exists() and local_ap.is_file():
            return send_file(
                str(local_ap),
                mimetype='text/plain; charset=utf-8',
                as_attachment=True,
                download_name=f'raw-scans-local-{datetime.now().strftime("%Y%m%d-%H%M%S")}.jsonl'
            )
        cloud = cfg.get('cloud_v2', {}) or {}
        archive_path = (cloud.get('archive_path') or 'cloud_backup/scans_archive.jsonl')
        ap = Path(str(archive_path))
        if not ap.is_absolute():
            ap = Path(os.getcwd()) / ap
        if ap.exists() and ap.is_file():
            return send_file(
                str(ap),
                mimetype='text/plain; charset=utf-8',
                as_attachment=True,
                download_name=f'raw-scans-{datetime.now().strftime("%Y%m%d-%H%M%S")}.jsonl'
            )
    except Exception:
        pass

    # Final fallback: synthesize JSONL from recent log entries.
    try:
        items = get_recent_scans_from_log() or []
        text = "\n".join(json.dumps(it, separators=(",", ":"), ensure_ascii=False) for it in items) + ("\n" if items else "")
        buf = io.BytesIO(text.encode('utf-8'))
        buf.seek(0)
        return send_file(
            buf,
            mimetype='text/plain; charset=utf-8',
            as_attachment=True,
            download_name=f'raw-scans-log-fallback-{datetime.now().strftime("%Y%m%d-%H%M%S")}.jsonl'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/thin/clear_local_data', methods=['POST'])
def thin_clear_local_data():
    """
    Thin Pi: clear local scan artifacts (for golden-image / privacy cleanup).

    Deletes (best effort):
    - thin local archive (default: local_backup/raw_scans.jsonl)
    - cloud retry queue (default: cloud_queue/scans.jsonl)
    - cloud archive (default: cloud_backup/scans_archive.jsonl)
    - logs (logs/*.log* and root qr_scanner.log if present)
    """
    if not _thin_mode_enabled():
        return jsonify({'error': 'Not supported outside thin mode'}), 400
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403

    cfg_path = _config_path()
    cfg = {}
    try:
        if cfg_path.exists():
            with open(cfg_path, 'r') as f:
                cfg = json.load(f) or {}
    except Exception:
        cfg = {}

    cloud = cfg.get('cloud_v2', {}) or {}
    thin_cfg = cfg.get('thin', {}) if isinstance(cfg.get('thin'), dict) else {}

    def _abs(p: str) -> Path:
        pp = Path(str(p))
        if not pp.is_absolute():
            pp = Path(os.getcwd()) / pp
        return pp

    local_archive_path = (thin_cfg.get('local_archive_path') or cfg.get('local_archive_path') or 'local_backup/raw_scans.jsonl')
    queue_path = (cloud.get('queue_path') or 'cloud_queue/scans.jsonl')
    archive_path = (cloud.get('archive_path') or 'cloud_backup/scans_archive.jsonl')

    targets = [
        ('local_backup/raw_scans.jsonl', _abs(local_archive_path)),
        ('cloud_queue/scans.jsonl', _abs(queue_path)),
        ('cloud_backup/scans_archive.jsonl', _abs(archive_path)),
        ('logs/qr_scanner.log', _abs('logs/qr_scanner.log')),
        ('qr_scanner.log', _abs('qr_scanner.log')),
    ]

    deleted = []
    missing = []
    errors = []

    for label, p in targets:
        try:
            if p.exists() and p.is_file():
                p.unlink()
                deleted.append({'label': label, 'path': str(p)})
            else:
                missing.append({'label': label, 'path': str(p)})
        except Exception as e:
            errors.append({'label': label, 'path': str(p), 'error': str(e)})

    # Rotated logs in logs/
    try:
        log_dir = _abs('logs')
        if log_dir.exists() and log_dir.is_dir():
            for lp in log_dir.glob('*.log*'):
                try:
                    if lp.is_file():
                        lp.unlink()
                        deleted.append({'label': 'logs/*', 'path': str(lp)})
                except Exception as e:
                    errors.append({'label': 'logs/*', 'path': str(lp), 'error': str(e)})
    except Exception:
        pass

    return jsonify({'success': True, 'deleted': deleted, 'missing': missing, 'errors': errors}), (200 if not errors else 207)


@app.route('/api/thin/pair/claim', methods=['POST'])
def thin_pair_claim():
    """Thin Pi: claim a one-time pairing code from cloud and store station tokens locally."""
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403

    body = request.get_json(silent=True) or {}
    base_url = (body.get('base_url') or _cloud_dashboard_url() or '').strip().rstrip('/')
    code = (body.get('code') or '').strip()
    if not base_url or not code:
        return jsonify({'error': 'base_url and code required'}), 400

    device = None
    try:
        device = (platform.node() or '') or None
    except Exception:
        device = None

    # Call cloud
    url = f"{base_url}/api/pair/claim"
    try:
        if requests is None:
            return jsonify({'error': 'requests not installed on this Pi image'}), 500
        resp = requests.post(url, json={'code': code, 'device': device}, timeout=12)
        data = resp.json() if resp.headers.get('content-type', '').lower().startswith('application/json') else {}
        if resp.status_code >= 400:
            return jsonify({'error': data.get('error') or f'HTTP {resp.status_code} from cloud'}), 400
        if not isinstance(data, dict) or not data.get('station_tokens'):
            return jsonify({'error': 'Cloud pairing succeeded but returned no station_tokens'}), 500
    except Exception as e:
        return jsonify({'error': f'Pairing failed: {e}'}), 500

    station_tokens = data.get('station_tokens') or {}
    if not isinstance(station_tokens, dict) or not station_tokens:
        return jsonify({'error': 'No station_tokens returned'}), 500

    # Write to local config.json
    try:
        cfg_path = _config_path()
        cfg = {}
        if cfg_path.exists():
            with open(cfg_path, 'r') as f:
                cfg = json.load(f) or {}
        cloud = cfg.get('cloud_v2', {}) if isinstance(cfg.get('cloud_v2'), dict) else {}
        cloud['enabled'] = True
        cloud['base_url'] = base_url
        cloud['thin_mode'] = True
        cloud['station_tokens'] = station_tokens
        # Keep queue/archive defaults if not set
        cloud.setdefault('queue_path', 'cloud_queue/scans.jsonl')
        cloud.setdefault('archive_path', 'cloud_backup/scans_archive.jsonl')
        cfg['cloud_v2'] = cloud
        cfg['paired_cloud_shop_id'] = data.get('shop_id')
        cfg['paired_at'] = datetime.now().isoformat()
        with open(cfg_path, 'w') as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        return jsonify({'error': f'Failed saving config.json: {e}'}), 500

    # Apply immediately: token changes don't trigger the config delta watcher, so restart scanners.
    try:
        mgr = getattr(app, 'scanner_manager', None)
        if mgr and hasattr(mgr, 'restart_scanner'):
            for device_path in list(getattr(mgr, 'scanners', {}).keys()):
                try:
                    mgr.restart_scanner(device_path)
                except Exception:
                    continue
    except Exception:
        pass

    return jsonify({'success': True, 'station_tokens': station_tokens, 'shop_id': data.get('shop_id')}), 200


@app.route('/api/thin/cloud/stations', methods=['GET'])
def thin_cloud_stations():
    """Thin Pi: fetch active station list from cloud using an existing station token."""
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403

    cfg_path = _config_path()
    cfg = {}
    if cfg_path.exists():
        try:
            with open(cfg_path, 'r') as f:
                cfg = json.load(f) or {}
        except Exception:
            cfg = {}
    cloud = cfg.get('cloud_v2', {}) if isinstance(cfg.get('cloud_v2'), dict) else {}
    base_url = (cloud.get('base_url') or _cloud_dashboard_url() or '').strip().rstrip('/')
    tokens = cloud.get('station_tokens') if isinstance(cloud.get('station_tokens'), dict) else {}
    token = ''
    try:
        # pick any token to authenticate shop scope
        token = next((str(v).strip() for v in tokens.values() if str(v).strip()), '')
    except Exception:
        token = ''
    if not base_url or not token:
        return jsonify({'stations': []}), 200
    if requests is None:
        return jsonify({'error': 'requests not installed'}), 500
    try:
        resp = requests.get(f"{base_url}/api/stations", headers={'Authorization': f"Bearer {token}"}, timeout=10)
        data = resp.json() if resp.headers.get('content-type', '').lower().startswith('application/json') else {}
        if resp.status_code >= 400:
            return jsonify({'error': data.get('error') or f'HTTP {resp.status_code}'}), 400
        return jsonify({'stations': data.get('stations') or []}), 200
    except Exception as e:
        return jsonify({'error': str(e), 'stations': []}), 500


@app.route('/api/admin/password/check', methods=['POST'])
def admin_check_password_proxy():
    """Admin-only login.

    If env-based auth is enabled, validates against INNOSAW_ADMIN_PASSWORD.
    Otherwise, falls back to the existing API-server-backed admin password.
    """
    if _is_auth_enabled():
        data = request.get_json(silent=True) or {}
        ok, role = _check_password_env(data.get('password', ''))
        if ok and role == 'admin':
            _set_role(session, 'admin')
            return jsonify({'authenticated': True, 'role': 'admin'}), 200
        return jsonify({'authenticated': False, 'error': 'Admin password required'}), 401

    resp, status = _proxy_api_5007("/api/admin/password/check", method="POST", json_body=(request.get_json(silent=True) or {}))
    if status == 200:
        try:
            data = resp.get_json() if hasattr(resp, 'get_json') else {}
            if data.get('authenticated'):
                session['admin_authenticated'] = True
                _set_role(session, 'admin')
        except Exception:
            pass
    return resp, status


@app.route('/api/scans/web', methods=['POST'])
def scans_web_post():
    """Allow browser/tablet to submit scans to local v1 DB.

    This mirrors v2's /api/scans/web behavior but writes to the local v1 SQLite DB.
    """
    # Require at least shop role when auth enabled.
    if _auth_enabled() and _current_role(session) not in ('shop', 'admin'):
        return jsonify({'error': 'Not authorized. Please log in (shop or admin).'}), 401

    payload = request.get_json(silent=True) or {}
    station_code = (payload.get('station_code') or '').strip()
    raw_data = (payload.get('raw_data') or '').strip()
    operator_id = (payload.get('operator_id') or '').strip() or None
    if not station_code:
        return jsonify({'error': 'station_code required'}), 400
    if not raw_data:
        return jsonify({'error': 'raw_data required'}), 400

    # Best-effort station display name from config.json scanners mapping.
    station_display_name = None
    try:
        cfg_path = _config_path()
        if cfg_path.exists():
            with open(cfg_path, 'r') as f:
                cfg = json.load(f) or {}
            scanners = cfg.get('scanners', {}) or {}
            for _dp, st_cfg in (scanners or {}).items():
                if not isinstance(st_cfg, dict):
                    continue
                if (str(st_cfg.get('station_code') or '').strip() == station_code):
                    station_display_name = (st_cfg.get('display_name') or st_cfg.get('station_code') or '').strip() or None
                    break
    except Exception:
        station_display_name = None

    try:
        # Parse using the same parser logic (includes scan_defaults csv mapping support)
        try:
            # Local import to avoid pulling in camera deps unless needed
            from qr_scanner import QRDataParser  # type: ignore
        except Exception as ie:
            return jsonify({'error': f'QRDataParser import failed: {ie}'}), 500

        parser = QRDataParser(station_code)
        parsed = parser.parse_scan_data(raw_data, operator=(operator_id or ''))
        fields = parsed.get('parsed_fields') or {}
        from database_schema import log_scan  # type: ignore
        scan_id = log_scan(
            station_code=station_code,
            station_display_name=station_display_name,
            raw_data=raw_data,
            parsed_fields=fields,
            operator_id=operator_id,
        )
        return jsonify({'success': True, 'scan_id': scan_id}), 200
    except Exception as e:
        logging.error("Web scan submit failed: %s", e, exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/password/set', methods=['POST'])
def admin_set_password_proxy():
    """Proxy password set to API server"""
    # If env-based auth is enabled, password is configured outside the app.
    if _is_auth_enabled():
        return jsonify({'error': 'Password is configured via server environment.'}), 400

    resp, status = _proxy_api_5007("/api/admin/password/set", method="POST", json_body=(request.get_json(silent=True) or {}))
    # If password was set successfully and this was first time, authenticate session
    if status == 200:
        try:
            data = resp.get_json() if hasattr(resp, 'get_json') else {}
            if data.get('success'):
                session['admin_authenticated'] = True
                _set_role(session, 'admin')
        except:
            pass
    return resp, status


@app.route('/api/admin/recuts/purge', methods=['POST'])
def admin_purge_recuts_proxy():
    """Proxy recut purge to API server (:5007)."""
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403
    return _proxy_api_5007("/api/admin/recuts/purge", method="POST", json_body=(request.get_json(silent=True) or {}))


@app.route('/api/admin/db/backup', methods=['POST'])
def admin_backup_db_proxy():
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403
    return _proxy_api_5007("/api/admin/db/backup", method="POST", json_body=(request.get_json(silent=True) or {}))


@app.route('/api/admin/db/backups', methods=['GET'])
def admin_list_db_backups_proxy():
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403
    if _api_5007_available():
        return _proxy_api_5007("/api/admin/db/backups", method="GET", params=request.args)
    # Thin Pi mode: no DB backup tooling here (cloud handles real backups).
    return jsonify({'backups': [], 'note': 'thin mode'}), 200


@app.route('/api/admin/db/backups/<path:filename>', methods=['GET'])
def admin_download_db_backup_proxy(filename: str):
    """Proxy a DB backup download from API server (:5007) while keeping admin auth on the dashboard origin."""
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403
    try:
        import requests
        from urllib.parse import quote

        safe = quote(filename, safe='')
        url = f'http://localhost:5007/api/admin/db/backups/{safe}'
        resp = requests.get(url, stream=True, timeout=30)
        if resp.status_code != 200:
            try:
                data = resp.json()
            except Exception:
                data = {'error': 'Download failed', 'raw': resp.text}
            return jsonify(data), resp.status_code

        headers = {}
        ct = resp.headers.get('Content-Type')
        if ct:
            headers['Content-Type'] = ct
        cd = resp.headers.get('Content-Disposition')
        if cd:
            headers['Content-Disposition'] = cd
        return Response(resp.content, status=200, headers=headers)
    except Exception as e:
        logging.error(f"Error proxying DB backup download: {e}")
        return jsonify({'error': 'API unavailable', 'details': str(e)}), 503


@app.route('/api/admin/uploads/backup', methods=['POST'])
def admin_backup_uploads_proxy():
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403
    return _proxy_api_5007("/api/admin/uploads/backup", method="POST", json_body=(request.get_json(silent=True) or {}))


@app.route('/api/admin/uploads/backups', methods=['GET'])
def admin_list_uploads_backups_proxy():
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403
    return _proxy_api_5007("/api/admin/uploads/backups", method="GET", params=request.args)


@app.route('/api/admin/uploads/backups/<path:filename>', methods=['GET'])
def admin_download_uploads_backup_proxy(filename: str):
    """Proxy an uploads backup download from API server (:5007) while keeping admin auth on the dashboard origin."""
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403
    try:
        import requests
        from urllib.parse import quote

        safe = quote(filename, safe='')
        url = f'http://localhost:5007/api/admin/uploads/backups/{safe}'
        resp = requests.get(url, stream=True, timeout=60)
        if resp.status_code != 200:
            try:
                data = resp.json()
            except Exception:
                data = {'error': 'Download failed', 'raw': resp.text}
            return jsonify(data), resp.status_code

        headers = {}
        ct = resp.headers.get('Content-Type')
        if ct:
            headers['Content-Type'] = ct
        cd = resp.headers.get('Content-Disposition')
        if cd:
            headers['Content-Disposition'] = cd
        return Response(resp.content, status=200, headers=headers)
    except Exception as e:
        logging.error(f"Error proxying uploads backup download: {e}")
        return jsonify({'error': 'API unavailable', 'details': str(e)}), 503

@app.route('/api/tools/inventory')
def get_tools_inventory():
    """Get tool inventory for dashboard"""
    try:
        # Prefer API server (computed per-tool counters)
        return _proxy_api_5007('/api/tools/inventory', method='GET', params=request.args)
    except Exception as e:
        logging.error(f"Error fetching tools inventory (proxy): {e}")
        # Fallback: old simple DB read (no computed counters)
        try:
            if get_db_connection:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM tools WHERE status = "active" ORDER BY machine, tool_name')
                tools = [dict(row) for row in cursor.fetchall()]
                conn.close()
                return jsonify({'tools': tools})
        except Exception as e2:
            logging.error(f"Fallback DB tools inventory failed: {e2}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/tools', methods=['POST'])
def create_tool_proxy():
    if _auth_enabled() and _current_role(session) == 'viewer':
        return jsonify({'error': 'Not authorized to save. Enter a password at /login.', 'required_role': 'shop'}), 403
    return _proxy_api_5007('/api/tools', method='POST', json_body=(request.get_json(silent=True) or {}))


@app.route('/api/tools/<int:tool_id>', methods=['PUT', 'DELETE'])
def tool_mutation_proxy(tool_id: int):
    if request.method == 'PUT':
        if _auth_enabled() and _current_role(session) == 'viewer':
            return jsonify({'error': 'Not authorized to save. Enter a password at /login.', 'required_role': 'shop'}), 403
        return _proxy_api_5007(f'/api/tools/{tool_id}', method='PUT', json_body=(request.get_json(silent=True) or {}))
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized to delete. Admin password required.', 'required_role': 'admin'}), 403
    return _proxy_api_5007(f'/api/tools/{tool_id}', method='DELETE')


@app.route('/api/tools/change', methods=['POST'])
def log_tool_change_proxy():
    if _auth_enabled() and _current_role(session) == 'viewer':
        return jsonify({'error': 'Not authorized to save. Enter a password at /login.', 'required_role': 'shop'}), 403
    return _proxy_api_5007('/api/tools/change', method='POST', json_body=(request.get_json(silent=True) or {}))


@app.route('/api/tools/change_bulk', methods=['POST'])
def log_tool_change_bulk_proxy():
    if _auth_enabled() and _current_role(session) == 'viewer':
        return jsonify({'error': 'Not authorized to save. Enter a password at /login.', 'required_role': 'shop'}), 403
    return _proxy_api_5007('/api/tools/change_bulk', method='POST', json_body=(request.get_json(silent=True) or {}))

@app.route('/api/tools/changes')
def get_tools_changes():
    """Get tool change history for dashboard"""
    try:
        if get_db_connection:
            # Use database directly
            conn = get_db_connection()
            cursor = conn.cursor()
            
            limit = request.args.get('limit', 50, type=int)
            machine = request.args.get('machine')
            
            query = 'SELECT * FROM tool_changes WHERE 1=1'
            params = []
            
            if machine:
                query += ' AND machine = ?'
                params.append(machine)
            
            query += ' ORDER BY timestamp DESC LIMIT ?'
            params.append(limit)
            
            cursor.execute(query, params)
            changes = [dict(row) for row in cursor.fetchall()]

            # Enrich missing counters for old rows where parts/sheets were not recorded
            # (historical rows often have NULL -> UI showed '-')
            tool_cache = {}
            for ch in changes:
                if ch.get('parts_on_old_tool') is not None or ch.get('sheets_on_old_tool') is not None:
                    continue
                old_id = ch.get('old_tool_id')
                if not old_id:
                    continue

                try:
                    old_id_int = int(old_id)
                except Exception:
                    continue

                if old_id_int not in tool_cache:
                    cursor.execute('SELECT * FROM tools WHERE id = ?', (old_id_int,))
                    tr = cursor.fetchone()
                    tool_cache[old_id_int] = dict(tr) if tr else None

                tool_row = tool_cache.get(old_id_int)
                if not tool_row:
                    continue

                # Determine counting window: previous change -> this change
                ts = ch.get('timestamp')
                cursor.execute('''
                    SELECT MAX(timestamp) as prev_ts
                    FROM tool_changes
                    WHERE machine = ? AND old_tool_id = ? AND timestamp < ?
                ''', (ch.get('machine'), old_id_int, ts))
                prev = cursor.fetchone()
                start_ts = (prev['prev_ts'] if prev else None) or tool_row.get('installed_at')
                end_ts = ts

                unit_type = (tool_row.get('unit_type') or '').strip().lower() or ('sheets' if ch.get('machine') in ['H08', 'H10'] else 'parts')
                count = _count_scans_for_tool_between(cursor, ch.get('machine'), start_ts, end_ts, tool_row, unit_type=unit_type)
                if unit_type == 'sheets':
                    ch['sheets_on_old_tool'] = count
                    ch['parts_on_old_tool'] = 0
                else:
                    ch['parts_on_old_tool'] = count
                    ch['sheets_on_old_tool'] = 0

            conn.close()
            
            return jsonify({'tool_changes': changes})
        else:
            # Fallback to HTTP API
            import requests
            api_url = 'http://localhost:5007/api/tools/changes'
            limit = request.args.get('limit', 50, type=int)
            machine = request.args.get('machine')
            
            params = {'limit': limit}
            if machine:
                params['machine'] = machine
            
            response = requests.get(api_url, params=params, timeout=5)
            if response.status_code == 200:
                return jsonify(response.json())
            else:
                return jsonify({'error': 'API unavailable'}), 503
    except Exception as e:
        logging.error(f"Error fetching tool changes: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================
# TOOLING (layout + on-hand)
# ============================================

@app.route('/api/tooling/catalog', methods=['GET', 'POST'])
def tooling_catalog_proxy():
    if request.method == 'GET':
        return _proxy_api_5007('/api/tooling/catalog', method='GET', params=request.args)
    if _auth_enabled() and _current_role(session) == 'viewer':
        return jsonify({'error': 'Not authorized to save. Enter a password at /login.', 'required_role': 'shop'}), 403
    return _proxy_api_5007('/api/tooling/catalog', method='POST', json_body=(request.get_json(silent=True) or {}))


@app.route('/api/tooling/layout/<machine>', methods=['GET', 'POST'])
def tooling_layout_proxy(machine: str):
    if request.method == 'GET':
        return _proxy_api_5007(f'/api/tooling/layout/{machine}', method='GET', params=request.args)
    if _auth_enabled() and _current_role(session) == 'viewer':
        return jsonify({'error': 'Not authorized to save. Enter a password at /login.', 'required_role': 'shop'}), 403
    return _proxy_api_5007(f'/api/tooling/layout/{machine}', method='POST', json_body=(request.get_json(silent=True) or {}))


@app.route('/api/tooling/stock/adjust', methods=['POST'])
def tooling_stock_adjust_proxy():
    if _auth_enabled() and _current_role(session) == 'viewer':
        return jsonify({'error': 'Not authorized to save. Enter a password at /login.', 'required_role': 'shop'}), 403
    return _proxy_api_5007('/api/tooling/stock/adjust', method='POST', json_body=(request.get_json(silent=True) or {}))

@app.route('/api/reports/stations')
def get_station_reports():
    """Get station reports data"""
    try:
        if get_db_connection:
            # Use database directly
            from database_schema import get_station_metrics
            stations = ['H08', 'H10', 'Edge', 'Dowel', 'Sort', 'Pull', 'Assembly', 'QC']
            metrics = []
            for station in stations:
                metrics.append(get_station_metrics(station))
            return jsonify({'stations': metrics})
        else:
            # Fallback to HTTP API
            import requests
            api_url = 'http://localhost:5007/api/stations'
            response = requests.get(api_url, timeout=5)
            if response.status_code == 200:
                return jsonify(response.json())
            else:
                return jsonify({'error': 'API unavailable'}), 503
    except Exception as e:
        logging.error(f"Error fetching station reports: {e}")
        return jsonify({'error': str(e)}), 500

def _get_station_display_names():
    """Helper to get friendly names from config.json"""
    try:
        config_path = Path(__file__).parent / 'config.json'
        if config_path.exists():
            with open(config_path, 'r') as f:
                config = json.load(f)
            scanners = config.get('scanners', {})
            names = {}
            for _, cfg in scanners.items():
                code = cfg.get('station_code')
                name = cfg.get('display_name')
                if code and name:
                    names[code] = name
            return names
    except Exception:
        pass
    return {}

@app.route('/api/reports/daily')
def get_daily_report():
    """Get daily production report"""
    try:
        display_names = _get_station_display_names()
        if get_db_connection:
            # Use database directly
            conn = get_db_connection()
            cursor = conn.cursor()
            date = request.args.get('date', datetime.now().strftime('%Y-%m-%d'))
            
            report = {
                'date': date,
                'generated_at': datetime.now().isoformat(),
                'stations': {}
            }
            
            # Get metrics for each station
            for station in ['H08', 'H10', 'Edge', 'Dowel', 'Sort', 'Pull', 'Assembly', 'QC', 'Sand', 'Wrap']:
                cursor.execute('''
                    SELECT COUNT(*) as scans, COUNT(DISTINCT job_name) as jobs
                    FROM scans WHERE station_code = ? AND DATE(timestamp) = ?
                ''', (station, date))
                row = cursor.fetchone()
                report['stations'][station] = {
                    'scans': row['scans'],
                    'jobs': row['jobs'],
                    'display_name': display_names.get(station, station)
                }
            
            # Get bin summary
            cursor.execute('SELECT COUNT(*) as occupied FROM (SELECT DISTINCT bin_number FROM bin_contents)')
            report['bins_occupied'] = cursor.fetchone()['occupied']
            
            # Get maintenance events
            cursor.execute('''
                SELECT COUNT(*) as count FROM maintenance_log WHERE DATE(timestamp) = ?
            ''', (date,))
            report['maintenance_events'] = cursor.fetchone()['count']
            
            conn.close()
            return jsonify(report)
        else:
            # Fallback to HTTP API
            import requests
            date = request.args.get('date', datetime.now().strftime('%Y-%m-%d'))
            api_url = f'http://localhost:5007/api/export/report?date={date}'
            response = requests.get(api_url, timeout=5)
            if response.status_code == 200:
                return jsonify(response.json())
            else:
                return jsonify({'error': 'API unavailable'}), 503
    except Exception as e:
        logging.error(f"Error fetching daily report: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/kiosk/cnc/status', methods=['GET'])
def get_kiosk_cnc_status():
    """Get active CNC sheet status for kiosk view"""
    try:
        station_code = request.args.get('station', '').strip()
        if not station_code:
            return jsonify({'error': 'station required'}), 400
            
        if not get_db_connection:
            return jsonify({'error': 'Database unavailable'}), 503
            
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # In v1, we infer 'active' sheet from the latest open cycle for this station
        cursor.execute("PRAGMA table_info(station_cycles)")
        columns = {row['name'] for row in cursor.fetchall()}
        
        where = "station_code = ? AND status != 'closed'"
        if 'auto_closed' in columns:
            where += " AND auto_closed = 0"
            
        cursor.execute(f'''
            SELECT job_name, gcode, start_time
            FROM station_cycles
            WHERE {where}
            ORDER BY start_time DESC LIMIT 1
        ''', (station_code,))
        row = cursor.fetchone()
        
        # Get material if column exists
        material = None
        if row and 'material' in columns:
            cursor.execute("SELECT material FROM station_cycles WHERE id = (SELECT id FROM station_cycles WHERE station_code = ? AND status != 'closed' ORDER BY start_time DESC LIMIT 1)", (station_code,))
            m_row = cursor.fetchone()
            material = m_row['material'] if m_row else None
        
        # Sheets today count
        today = datetime.now().strftime('%Y-%m-%d')
        cursor.execute('''
            SELECT COUNT(*) as count FROM station_cycles 
            WHERE station_code = ? AND DATE(start_time) = ?
        ''', (station_code, today))
        count_row = cursor.fetchone()
        
        conn.close()
        
        return jsonify({
            "active": bool(row),
            "job_name": row['job_name'] if row else None,
            "material_name": material,
            "gcode": row['gcode'] if row else None,
            "sheets_today": count_row['count'] if count_row else 0
        })
    except Exception as e:
        logging.error(f"Error fetching kiosk CNC status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/kiosk/station_totals', methods=['GET'])
def get_kiosk_station_totals():
    """Get scan counts and recent parts for a station"""
    try:
        station_code = request.args.get('station', '').strip()
        if not station_code:
            return jsonify({'error': 'station required'}), 400
            
        if not get_db_connection:
            return jsonify({'error': 'Database unavailable'}), 503
            
        conn = get_db_connection()
        cursor = conn.cursor()
        today = datetime.now().strftime('%Y-%m-%d')
        
        # Scans today
        cursor.execute('''
            SELECT COUNT(*) as count FROM scans 
            WHERE station_code = ? AND DATE(timestamp) = ?
        ''', (station_code, today))
        count_row = cursor.fetchone()
        
        # Recent parts (for sanding/wrap list)
        cursor.execute("PRAGMA table_info(scans)")
        scans_cols = {row['name'] for row in cursor.fetchall()}
        
        sel_cols = ['job_name', 'timestamp']
        if 'cabinet_assembly' in scans_cols: sel_cols.append('cabinet_assembly')
        if 'part_name' in scans_cols: sel_cols.append('part_name')
        if 'part_length' in scans_cols: sel_cols.append('part_length')
        if 'part_width' in scans_cols: sel_cols.append('part_width')
        
        sel_sql = ", ".join(sel_cols)
        cursor.execute(f'''
            SELECT {sel_sql}
            FROM scans
            WHERE station_code = ? AND DATE(timestamp) = ?
            ORDER BY timestamp DESC LIMIT 50
        ''', (station_code, today))
        
        parts = []
        total_sqft = 0.0
        for r in cursor.fetchall():
            d = {
                'job_name': r['job_name'],
                'cabinet_assembly': r.get('cabinet_assembly') if 'cabinet_assembly' in scans_cols else None,
                'part_name': r.get('part_name') if 'part_name' in scans_cols else None,
                'timestamp': r['timestamp']
            }
            # Calculate SQFT if possible
            if 'part_length' in scans_cols and 'part_width' in scans_cols:
                l_in = _length_to_inches_best_effort(r.get('part_length')) or 0.0
                w_in = _length_to_inches_best_effort(r.get('part_width')) or 0.0
                sqft = (l_in * w_in) / 144.0
                d['sqft'] = round(sqft, 2)
                total_sqft += sqft
            
            parts.append(d)
            
        conn.close()
        return jsonify({
            "count": count_row['count'] if count_row else 0,
            "parts": parts,
            "total_sqft": round(total_sqft, 2)
        })
    except Exception as e:
        logging.error(f"Error fetching kiosk station totals: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/sheet_processing_times', methods=['GET'])
def get_sheet_processing_times():
    """Get sheet processing times for H08/H10 stations with filtering"""
    try:
        if not get_db_connection:
            # Proxy to API server
            resp, status = _proxy_api_5007("/api/sheet_processing_times", method="GET", params=request.args)
            return resp, status
        
        station = request.args.get('station')
        material = request.args.get('material')
        job_name = request.args.get('job_name')
        run_name = request.args.get('run_name')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        auto_closed_only = request.args.get('auto_closed_only', 'false').lower() == 'true'
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Don't force status='closed' here. Some deployments leave cycles open
        # (missing/failed close scan), which would otherwise make reports look empty.
        where = []
        params = []
        
        if station and station in ['H08', 'H10']:
            where.append('station_code = ?')
            params.append(station)
        else:
            where.append('station_code IN (?, ?)')
            params.extend(['H08', 'H10'])
        
        if material:
            where.append('material LIKE ?')
            params.append(f'%{material}%')
        
        if job_name:
            where.append('job_name LIKE ?')
            params.append(f'%{job_name}%')
        
        if run_name:
            where.append('run_name LIKE ?')
            params.append(f'%{run_name}%')
        
        if date_from:
            where.append('DATE(start_time) >= ?')
            params.append(date_from)
        
        if date_to:
            where.append('DATE(start_time) <= ?')
            params.append(date_to)
        
        if auto_closed_only:
            where.append('auto_closed = 1')
        
        where_sql = ' AND '.join(where)
        
        # Get total count
        cursor.execute(f'SELECT COUNT(*) as count FROM station_cycles WHERE {where_sql}', params)
        total_count = int(cursor.fetchone()['count'])
        
        # Get cycles
        query = f'''
            SELECT 
                id, station_code, cycle_key, job_name, gcode, 
                start_time, end_time, duration_seconds,
                operator_id, 
                ROUND(duration_seconds / 60.0, 2) as duration_minutes
            FROM station_cycles 
            WHERE {where_sql}
            ORDER BY start_time DESC
            LIMIT ? OFFSET ?
        '''
        cursor.execute(query, [*params, limit, offset])
        rows = cursor.fetchall()
        
        # Check for optional columns (material, run_name, auto_closed)
        cursor.execute("PRAGMA table_info(station_cycles)")
        columns = {row['name'] for row in cursor.fetchall()}
        
        cycles = []
        for r in rows:
            c = dict(r)
            if 'material' in columns:
                # Re-fetch row with material if column exists
                cursor.execute(f"SELECT material FROM station_cycles WHERE id = ?", (c['id'],))
                c['material'] = cursor.fetchone()['material']
            else:
                c['material'] = None
                
            if 'run_name' in columns:
                cursor.execute(f"SELECT run_name FROM station_cycles WHERE id = ?", (c['id'],))
                c['run_name'] = cursor.fetchone()['run_name']
            else:
                c['run_name'] = None

            if 'auto_closed' in columns:
                cursor.execute(f"SELECT auto_closed, auto_closed_at_station FROM station_cycles WHERE id = ?", (c['id'],))
                res = cursor.fetchone()
                c['auto_closed'] = res['auto_closed']
                c['auto_closed_at_station'] = res['auto_closed_at_station']
            else:
                c['auto_closed'] = 0
                c['auto_closed_at_station'] = None
                
            cycles.append(c)
            
        conn.close()
        
        return jsonify({
            'cycles': cycles,
            'count': len(cycles),
            'total': total_count,
            'limit': limit,
            'offset': offset
        })
    except Exception as e:
        logging.error(f"Error getting sheet processing times: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/assembly_times', methods=['GET'])
def get_assembly_times():
    """Get assembly processing times for Assembly station with filtering"""
    try:
        if not get_db_connection:
            # Proxy to API server
            resp, status = _proxy_api_5007("/api/assembly_times", method="GET", params=request.args)
            return resp, status
        
        operator_id = request.args.get('operator_id')
        station_display_name = request.args.get('station_display_name')
        station_code = request.args.get('station') or request.args.get('station_code')
        cabinet_name = request.args.get('cabinet_name')
        cabinet_assembly = request.args.get('cabinet_assembly')
        job_name = request.args.get('job_name')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Don't force status='closed' here. Some deployments leave cycles open
        # (missing/failed close scan), which would otherwise make reports look empty.
        where = []
        params = []

        if station_code:
            where.append('station_code = ?')
            params.append(station_code)
        else:
            where.append('station_code = ?')
            params.append('Assembly')

        if station_display_name:
            where.append('station_display_name = ?')
            params.append(station_display_name)
        
        if operator_id:
            where.append('operator_id LIKE ?')
            params.append(f'%{operator_id}%')
        
        if cabinet_name:
            where.append('(cabinet_name LIKE ? OR cabinet_assembly LIKE ? OR cycle_key LIKE ?)')
            params.extend([f'%{cabinet_name}%', f'%{cabinet_name}%', f'%{cabinet_name}%'])
        
        if cabinet_assembly:
            where.append('cabinet_assembly = ?')
            params.append(cabinet_assembly)
        
        if job_name:
            where.append('job_name LIKE ?')
            params.append(f'%{job_name}%')
        
        if date_from:
            where.append('DATE(start_time) >= ?')
            params.append(date_from)
        
        if date_to:
            where.append('DATE(start_time) <= ?')
            params.append(date_to)
        
        where_sql = ' AND '.join(where)
        
        # Get total count
        cursor.execute(f'SELECT COUNT(*) as count FROM station_cycles WHERE {where_sql}', params)
        total_count = int(cursor.fetchone()['count'])
        
        # Get cycles
        query = f'''
            SELECT 
                id, station_code, station_display_name, cycle_key, job_name,
                cabinet_assembly, cabinet_name, part_name, opening_letter, assembly_unit,
                start_time, end_time, duration_seconds,
                operator_id,
                ROUND(duration_seconds / 60.0, 2) as duration_minutes
            FROM station_cycles 
            WHERE {where_sql}
            ORDER BY start_time DESC
            LIMIT ? OFFSET ?
        '''
        cursor.execute(query, [*params, limit, offset])
        cycles = [dict(row) for row in cursor.fetchall()]
        # Back-compat cleanup: older records stored cabinet name in cabinet_assembly.
        for c in cycles:
            cab_assy = (c.get('cabinet_assembly') or '').strip()
            cab_name = (c.get('cabinet_name') or '').strip()
            looks_like_rc = False
            if cab_assy:
                import re
                looks_like_rc = bool(re.match(r'^\s*R\d+\s*C\d+\s*$', cab_assy, re.IGNORECASE))
            if cab_assy and (not looks_like_rc) and (not cab_name):
                c['cabinet_name'] = cab_assy
                c['cabinet_assembly'] = None
            if not (c.get('assembly_unit') or '').strip():
                pn = (c.get('part_name') or '').strip()
                pn_lower = pn.lower()
                if '*' in pn:
                    c['assembly_unit'] = 'Insert'
                elif 'tray' in pn_lower:
                    c['assembly_unit'] = 'Tray'
                elif 'door' in pn_lower:
                    c['assembly_unit'] = 'Door'
                elif 'drawer' in pn_lower:
                    c['assembly_unit'] = 'Drawer Front'
                elif 'dwr' in pn_lower or 'drw' in pn_lower:
                    c['assembly_unit'] = 'Drawer Box'
                else:
                    c['assembly_unit'] = 'Case'
        conn.close()
        
        return jsonify({
            'cycles': cycles,
            'count': len(cycles),
            'total': total_count,
            'limit': limit,
            'offset': offset
        })
    except Exception as e:
        logging.error(f"Error getting assembly times: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/timing')
def get_timing_report():
    """Station timing metrics (cycle times + time-between-parts)"""
    try:
        if not get_db_connection:
            # Fallback: proxy to API server later if desired
            import requests
            resp = requests.get('http://localhost:5007/api/reports/timing', params=request.args, timeout=5)
            return jsonify(resp.json()), resp.status_code

        date = request.args.get('date', datetime.now().strftime('%Y-%m-%d'))
        conn = get_db_connection()
        cursor = conn.cursor()

        out = {'date': date, 'stations': {}}
        stations = ['H08', 'H10', 'Edge', 'Dowel', 'Assembly', 'Band', 'Banding']

        for st in stations:
            # Avg cycle time (H08/H10/Assembly)
            cursor.execute('''
                SELECT COUNT(*) as closed_count,
                       AVG(duration_seconds) as avg_sec,
                       MIN(duration_seconds) as min_sec,
                       MAX(duration_seconds) as max_sec
                FROM station_cycles
                WHERE station_code = ?
                  AND status = 'closed'
                  AND DATE(start_time) = ?
            ''', (st, date))
            cyc = cursor.fetchone()

            # Time between scans (Edge/Dowel/Banding) computed from scan timestamps
            cursor.execute('''
                SELECT timestamp
                FROM scans
                WHERE station_code = ?
                  AND DATE(timestamp) = ?
                ORDER BY timestamp ASC
            ''', (st, date))
            rows = cursor.fetchall()

            gaps_sec = []
            prev = None
            for r in rows:
                try:
                    t = datetime.strptime(r['timestamp'], '%Y-%m-%d %H:%M:%S')
                except Exception:
                    continue
                if prev is not None:
                    gaps_sec.append((t - prev).total_seconds())
                prev = t

            gap_avg = (sum(gaps_sec) / len(gaps_sec)) if gaps_sec else None
            gap_max = (max(gaps_sec) if gaps_sec else None)

            out['stations'][st] = {
                'cycle_closed_count': int(cyc['closed_count'] or 0),
                'cycle_avg_seconds': float(cyc['avg_sec']) if cyc['avg_sec'] is not None else None,
                'cycle_min_seconds': float(cyc['min_sec']) if cyc['min_sec'] is not None else None,
                'cycle_max_seconds': float(cyc['max_sec']) if cyc['max_sec'] is not None else None,
                'gap_avg_seconds': gap_avg,
                'gap_max_seconds': gap_max,
                'scan_count': len(rows),
            }

        # Also expose per-display-name rollups for stations that have multiple physical scanners.
        try:
            cursor.execute('''
                SELECT station_code, station_display_name,
                       COUNT(*) as closed_count,
                       AVG(duration_seconds) as avg_sec,
                       MIN(duration_seconds) as min_sec,
                       MAX(duration_seconds) as max_sec
                FROM station_cycles
                WHERE status = 'closed'
                  AND DATE(start_time) = ?
                  AND station_display_name IS NOT NULL
                  AND TRIM(COALESCE(station_display_name,'')) <> ''
                GROUP BY station_code, station_display_name
            ''', (date,))
            rows = cursor.fetchall()
            if rows:
                out['stations_by_display'] = {}
                for r in rows:
                    key = f"{r['station_code']}::{r['station_display_name']}"
                    out['stations_by_display'][key] = {
                        'station_code': r['station_code'],
                        'station_display_name': r['station_display_name'],
                        'cycle_closed_count': int(r['closed_count'] or 0),
                        'cycle_avg_seconds': float(r['avg_sec']) if r['avg_sec'] is not None else None,
                        'cycle_min_seconds': float(r['min_sec']) if r['min_sec'] is not None else None,
                        'cycle_max_seconds': float(r['max_sec']) if r['max_sec'] is not None else None,
                    }
        except Exception:
            pass

        conn.close()
        return jsonify(out)
    except Exception as e:
        logging.error(f"Error building timing report: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


def _parse_scan_ts(ts: str):
    """Parse scan timestamp strings from SQLite into datetime.

    Supports common formats observed in this repo:
    - YYYY-MM-DD HH:MM:SS
    - YYYY-MM-DDTHH:MM:SS(.sss)(Z)
    """
    if not ts:
        return None
    s = str(ts).strip()
    if not s:
        return None
    try:
        return datetime.strptime(s, '%Y-%m-%d %H:%M:%S')
    except Exception:
        pass
    try:
        # Normalize ISO-ish strings
        s2 = s.replace('Z', '')
        if 'T' in s2:
            # fromisoformat supports fractional seconds
            return datetime.fromisoformat(s2)
    except Exception:
        return None
    return None


def _build_work_blocks(rows, gap_minutes: int):
    """Build work blocks from ordered scan rows.

    A block continues until there is a pause of >= gap_minutes between scans.
    """
    gap_seconds = max(0, int(gap_minutes)) * 60
    blocks = []
    current = None
    prev_dt = None

    for r in rows:
        dt = _parse_scan_ts(r.get('timestamp'))
        st = (r.get('station_code') or '').strip()
        op = (r.get('operator_id') or '').strip()
        if not dt or not st:
            continue

        if current is None:
            current = {
                'station_code': st,
                'start_time': dt,
                'end_time': dt,
                'scan_count': 1,
                'operator_id': op or '',
            }
            prev_dt = dt
            continue

        # If station changes (shouldn't in per-station queries), force-close block.
        if st != current['station_code']:
            blocks.append(current)
            current = {
                'station_code': st,
                'start_time': dt,
                'end_time': dt,
                'scan_count': 1,
                'operator_id': op or '',
            }
            prev_dt = dt
            continue

        gap = (dt - prev_dt).total_seconds() if prev_dt else 0
        if gap_seconds and gap >= gap_seconds:
            blocks.append(current)
            current = {
                'station_code': st,
                'start_time': dt,
                'end_time': dt,
                'scan_count': 1,
                'operator_id': op or '',
            }
        else:
            current['end_time'] = dt
            current['scan_count'] += 1

        # Track operator within the block.
        # If multiple operators appear, mark as Mixed.
        if op:
            cur_op = (current.get('operator_id') or '').strip()
            if not cur_op:
                current['operator_id'] = op
            elif cur_op != op and cur_op.lower() != 'mixed':
                current['operator_id'] = 'Mixed'

        prev_dt = dt

    if current is not None:
        blocks.append(current)

    # Add durations
    for b in blocks:
        dur = (b['end_time'] - b['start_time']).total_seconds()
        b['duration_seconds'] = max(0, int(dur))
        b['duration_minutes'] = round(b['duration_seconds'] / 60.0, 2)
        b['avg_seconds_per_part'] = round((b['duration_seconds'] / b['scan_count']), 2) if b.get('scan_count') else None
        b['avg_minutes_per_part'] = round((b['avg_seconds_per_part'] / 60.0), 2) if b.get('avg_seconds_per_part') is not None else None
        b['start_time'] = b['start_time'].strftime('%Y-%m-%d %H:%M:%S')
        b['end_time'] = b['end_time'].strftime('%Y-%m-%d %H:%M:%S')

    return blocks


# ============================================================
# Mozaik (.mzklbl) expected-parts reporting
# ============================================================

_MZ_INCLUDED_OVERRIDES = [
    'dwr stretcher',
    'drw stretcher',
    'drawer stretcher',
]

_MZ_EXCLUDED_KEYWORDS = [
    'door', 'doors',
    'drawer', 'drawers',
    'dwr', 'drw',
    'tray', 'trays',
    'front',
    'face',
    'back',
    'uback',
    'leg', 'legs',
    'adjustable',
    'pull', 'pulls',
]


def _mz_part_text(part_name: str, shorthand: str, comment: str) -> str:
    return f"{part_name or ''} {shorthand or ''} {comment or ''}".strip().lower()


def _mz_part_group(part_name: str, shorthand: str = '', comment: str = '') -> str:
    """Classify part into groups consistent with the CasePartsManager exclusions."""
    t = _mz_part_text(part_name, shorthand, comment)
    for phrase in _MZ_INCLUDED_OVERRIDES:
        if phrase in t:
            return 'case'

    if 'door' in t:
        return 'door'
    if 'tray' in t:
        return 'tray'

    if 'drawer' in t or 'dwr' in t or 'drw' in t:
        if 'front' in t:
            return 'drawer_front'
        return 'drawer'

    if 'front' in t:
        return 'drawer_front'
    if 'uback' in t or (('back' in t) and ('drawer' not in t) and ('dwr' not in t) and ('drw' not in t)):
        return 'back'
    if 'face' in t:
        return 'face'
    if 'leg' in t:
        return 'legs'
    if 'adjustable' in t:
        return 'adjustable'
    if 'pull' in t:
        return 'hardware'

    return 'case'


def _mz_is_case_part(part_name: str, shorthand: str = '', comment: str = '') -> bool:
    g = _mz_part_group(part_name, shorthand, comment)
    return g == 'case'


def _mz_canonical_gcode(val: str) -> str:
    """Normalize gcode names so S01R04.TCN and S1R4.tcn match."""
    s = (val or '').strip().upper()
    if not s:
        return ''
    # Strip any folder path
    if '/' in s:
        s = s.rsplit('/', 1)[-1]
    if '\\' in s:
        s = s.rsplit('\\', 1)[-1]

    # Canonicalize sheet/run patterns
    import re
    m = re.search(r"\bS\s*(\d+)\s*R\s*(\d+)\b", s)
    if m:
        try:
            sheet = int(m.group(1))
            run = int(m.group(2))
            return f"S{sheet}R{run:02d}.TCN"
        except Exception:
            pass

    m2 = re.search(r"\bS\s*(\d+)\b", s)
    if m2 and s.endswith('.TCN'):
        try:
            sheet = int(m2.group(1))
            return f"S{sheet}.TCN"
        except Exception:
            pass

    return s


def _mz_try_query_exists(cursor, sql: str, args: tuple) -> bool:
    cursor.execute(sql, args)
    return cursor.fetchone() is not None


@app.route('/api/reports/mozaik/imports')
def api_reports_mozaik_imports():
    """List imported Mozaik runs (mzklbl imports)."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Tables are created by the importer; return empty if not present.
        if not _mz_try_query_exists(cur, "SELECT name FROM sqlite_master WHERE type='table' AND name=?", ('mozaik_imports',)):
            conn.close()
            return jsonify({'imports': []})

        cur.execute('''
            SELECT id, imported_at, source_filename,
                   job_name, run_name, run_number,
                   sheets_count, parts_count, status
            FROM mozaik_imports
            ORDER BY imported_at DESC, id DESC
            LIMIT 200
        ''')
        rows = cur.fetchall() or []
        out = []
        for r in rows:
            out.append({
                'id': r['id'],
                'imported_at': r['imported_at'],
                'source_filename': r['source_filename'],
                'job_name': r['job_name'],
                'run_name': r['run_name'],
                'run_number': r['run_number'],
                'sheets_count': r['sheets_count'],
                'parts_count': r['parts_count'],
                'status': r['status'],
            })
        conn.close()
        return jsonify({'imports': out})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/mozaik/run_summary')
def api_reports_mozaik_run_summary():
    """Expected vs scanned summary for one Mozaik import.

    Semantics:
    - If a CNC scan exists for a sheet/run gcode, then ALL parts on that sheet/run
      are treated as scanned (CNC-only workflow).
    """
    try:
        import_id = request.args.get('import_id', type=int)
        if not import_id:
            return jsonify({'error': 'import_id is required'}), 400

        conn = get_db_connection()
        cur = conn.cursor()

        if not _mz_try_query_exists(cur, "SELECT name FROM sqlite_master WHERE type='table' AND name=?", ('mozaik_imports',)):
            conn.close()
            return jsonify({'error': 'Mozaik imports not found'}), 404

        cur.execute('SELECT id, job_name, run_name, run_number, status FROM mozaik_imports WHERE id = ?', (import_id,))
        imp = cur.fetchone()
        if not imp:
            conn.close()
            return jsonify({'error': 'Import not found'}), 404

        job_name = (imp['job_name'] or '').strip()

        # Build a map of (canonical_gcode -> earliest scan timestamp)
        scan_map = {}
        if job_name:
            cur.execute('''
                SELECT gcode, MIN(timestamp) AS first_ts
                FROM scans
                WHERE job_name = ?
                  AND station_code IN ('H08','H10')
                  AND gcode IS NOT NULL
                  AND TRIM(gcode) <> ''
                GROUP BY gcode
            ''', (job_name,))
            for r in (cur.fetchall() or []):
                key = _mz_canonical_gcode(r['gcode'] or '')
                if not key:
                    continue
                ts = r['first_ts']
                if key not in scan_map or (ts and ts < scan_map[key]):
                    scan_map[key] = ts

        # Pull all parts for this import and aggregate by (sheet_id, material_name, gcode)
        try:
            cur.execute('''
                SELECT sheet_id, material_name, material_thickness,
                       gcode_filename, gcode_guess,
                       sheet_w_mm, sheet_l_mm,
                       part_name, part_shorthand_name, part_comment
                FROM mozaik_expected_parts
                WHERE import_id = ?
            ''', (import_id,))
            rows = cur.fetchall() or []
        except Exception:
            # Backward compatibility (older DB schema)
            cur.execute('''
                SELECT sheet_id, material_name, material_thickness,
                       gcode_filename, gcode_guess,
                       part_name, part_shorthand_name, part_comment
                FROM mozaik_expected_parts
                WHERE import_id = ?
            ''', (import_id,))
            rows = cur.fetchall() or []

        groups = {}
        for r in rows:
            sheet_id = r['sheet_id']
            material_name = (r['material_name'] or '').strip()
            thickness = (r['material_thickness'] or '').strip()
            gcode = (r['gcode_filename'] or '').strip() or (r['gcode_guess'] or '').strip()
            gkey = _mz_canonical_gcode(gcode)
            gk = (sheet_id, material_name, thickness, gkey)

            if gk not in groups:
                groups[gk] = {
                    'sheet_id': sheet_id,
                    'material_name': material_name,
                    'material_thickness': thickness,
                    'sheet_w_mm': None,
                    'sheet_l_mm': None,
                    'gcode': gkey or gcode,
                    'expected_parts': 0,
                    'expected_case_parts': 0,
                }

            # Keep first non-null sheet dims we see.
            if groups[gk].get('sheet_w_mm') is None:
                try:
                    groups[gk]['sheet_w_mm'] = r['sheet_w_mm'] if 'sheet_w_mm' in r.keys() else None
                except Exception:
                    pass
            if groups[gk].get('sheet_l_mm') is None:
                try:
                    groups[gk]['sheet_l_mm'] = r['sheet_l_mm'] if 'sheet_l_mm' in r.keys() else None
                except Exception:
                    pass

            groups[gk]['expected_parts'] += 1
            if _mz_is_case_part(r['part_name'] or '', r['part_shorthand_name'] or '', r['part_comment'] or ''):
                groups[gk]['expected_case_parts'] += 1

        out = []
        for _, g in sorted(groups.items(), key=lambda kv: ((kv[1].get('sheet_id') or 0), kv[1].get('material_name') or '', kv[1].get('gcode') or '')):
            gcode = (g.get('gcode') or '').strip()
            has_scan = bool(gcode and (gcode in scan_map))
            scanned_parts = g['expected_parts'] if has_scan else 0
            scanned_case_parts = g['expected_case_parts'] if has_scan else 0
            out.append({
                **g,
                'has_cnc_scan': has_scan,
                'first_cnc_scan_ts': scan_map.get(gcode),
                'scanned_parts': scanned_parts,
                'scanned_case_parts': scanned_case_parts,
            })

        conn.close()
        return jsonify({
            'import': {
                'id': imp['id'],
                'job_name': imp['job_name'],
                'run_name': imp['run_name'],
                'run_number': imp['run_number'],
                'status': imp['status'],
            },
            'groups': out,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/mozaik/parts')
def api_reports_mozaik_parts():
    """List expected parts for an import, with scanned=true/false.

    scanned semantics: if CNC scan exists for the part's sheet/run gcode, the part is scanned.
    """
    try:
        import_id = request.args.get('import_id', type=int)
        if not import_id:
            return jsonify({'error': 'import_id is required'}), 400

        sheet_id = request.args.get('sheet_id', type=int)
        limit = request.args.get('limit', default=2000, type=int)
        limit = max(50, min(limit, 20000))

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute('SELECT job_name FROM mozaik_imports WHERE id = ?', (import_id,))
        imp = cur.fetchone()
        if not imp:
            conn.close()
            return jsonify({'error': 'Import not found'}), 404
        job_name = (imp['job_name'] or '').strip()

        scan_set = set()
        if job_name:
            cur.execute('''
                SELECT gcode
                FROM scans
                WHERE job_name = ?
                  AND station_code IN ('H08','H10')
                  AND gcode IS NOT NULL
                  AND TRIM(gcode) <> ''
                GROUP BY gcode
            ''', (job_name,))
            for r in (cur.fetchall() or []):
                key = _mz_canonical_gcode(r['gcode'] or '')
                if key:
                    scan_set.add(key)

        where = 'WHERE import_id = ?'
        args = [import_id]
        if sheet_id is not None:
            where += ' AND sheet_id = ?'
            args.append(sheet_id)

        try:
            cur.execute(f'''
                SELECT id, sheet_id, material_name, material_thickness,
                       gcode_filename, gcode_guess,
                       sheet_w_mm, sheet_l_mm,
                       part_w_mm, part_l_mm,
                       part_edge_band, part_band_temp_symbol,
                       part_no, part_name, part_shorthand_name, part_comment,
                       cabinet_assembly, cabinet_name, room_name, opening_letter,
                       part_x_mm, part_y_mm, part_rot, geometry_json
                FROM mozaik_expected_parts
                {where}
                ORDER BY sheet_id ASC, cabinet_assembly ASC, opening_letter ASC, part_no ASC
                LIMIT ?
            ''', tuple(args + [limit]))
        except Exception:
            # Backward compatibility (older DB schema)
            cur.execute(f'''
                SELECT id, sheet_id, material_name, material_thickness,
                       gcode_filename, gcode_guess,
                       part_no, part_name, part_shorthand_name, part_comment,
                       cabinet_assembly, cabinet_name, room_name, opening_letter
                FROM mozaik_expected_parts
                {where}
                ORDER BY sheet_id ASC, cabinet_assembly ASC, opening_letter ASC, part_no ASC
                LIMIT ?
            ''', tuple(args + [limit]))

        out = []
        for r in (cur.fetchall() or []):
            gcode = (r['gcode_filename'] or '').strip() or (r['gcode_guess'] or '').strip()
            gkey = _mz_canonical_gcode(gcode)
            scanned = bool(gkey and (gkey in scan_set))
            grp = _mz_part_group(r['part_name'] or '', r['part_shorthand_name'] or '', r['part_comment'] or '')
            out.append({
                'expected_part_id': r['id'],
                'sheet_id': r['sheet_id'],
                'material_name': r['material_name'],
                'material_thickness': r['material_thickness'],
                'sheet_w_mm': r['sheet_w_mm'] if 'sheet_w_mm' in r.keys() else None,
                'sheet_l_mm': r['sheet_l_mm'] if 'sheet_l_mm' in r.keys() else None,
                'gcode': gkey or gcode,
                'part_w_mm': r['part_w_mm'] if 'part_w_mm' in r.keys() else None,
                'part_l_mm': r['part_l_mm'] if 'part_l_mm' in r.keys() else None,
                'part_edge_band': r['part_edge_band'] if 'part_edge_band' in r.keys() else None,
                'part_band_temp_symbol': r['part_band_temp_symbol'] if 'part_band_temp_symbol' in r.keys() else None,
                'part_no': r['part_no'],
                'part_name': r['part_name'],
                'part_shorthand_name': r['part_shorthand_name'],
                'part_comment': r['part_comment'],
                'part_x_mm': r['part_x_mm'] if 'part_x_mm' in r.keys() else None,
                'part_y_mm': r['part_y_mm'] if 'part_y_mm' in r.keys() else None,
                'part_rot_deg': r['part_rot'] if 'part_rot' in r.keys() else 0,
                'geometry': r['geometry_json'] if 'geometry_json' in r.keys() else None,
                'geometry_json': r['geometry_json'] if 'geometry_json' in r.keys() else None,
                'cabinet_assembly': r['cabinet_assembly'],
                'cabinet_name': r['cabinet_name'],
                'room_name': r['room_name'],
                'opening_letter': r['opening_letter'],
                'part_group': grp,
                'is_case_part': (grp == 'case'),
                'scanned': scanned,
            })

        conn.close()
        return jsonify({'parts': out, 'limit': limit})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/mozaik/delete_import', methods=['POST'])
def api_admin_mozaik_delete_import():
    """Delete a Mozaik import/run so it stops affecting tracking."""
    try:
        body = request.get_json(silent=True) or {}
        import_id = body.get('import_id')
        try:
            import_id = int(import_id)
        except Exception:
            import_id = None

        if not import_id:
            return jsonify({'error': 'import_id is required'}), 400

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute('SELECT id FROM mozaik_imports WHERE id = ?', (import_id,))
        if not cur.fetchone():
            conn.close()
            return jsonify({'error': 'Import not found'}), 404

        cur.execute('DELETE FROM mozaik_expected_parts WHERE import_id = ?', (import_id,))
        parts_deleted = cur.rowcount or 0
        cur.execute('DELETE FROM mozaik_imports WHERE id = ?', (import_id,))
        imports_deleted = cur.rowcount or 0

        conn.commit()
        conn.close()

        return jsonify({'deleted_imports': imports_deleted, 'deleted_parts': parts_deleted})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/mozaik/reparse_import', methods=['POST'])
def api_admin_mozaik_reparse_import():
    """Reparse a Mozaik import/run to refresh expected-part fields."""
    try:
        if not reparse_mzklbl_import:
            return jsonify({'error': 'Reparse not available'}), 503

        body = request.get_json(silent=True) or {}
        import_id = body.get('import_id')
        try:
            import_id = int(import_id)
        except Exception:
            import_id = None

        if not import_id:
            return jsonify({'error': 'import_id is required'}), 400

        ok, msg = reparse_mzklbl_import(import_id)
        if not ok:
            return jsonify({'error': msg}), 400
        return jsonify({'ok': True, 'message': msg})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/job_time')
def api_reports_job_time():
    """Job total time summary.

    Computes:
    - Work blocks per station (gap-based) from scans
    - Cycle totals from station_cycles (Assembly/H08/H10 where present)
    - Cabinet rollups (scans + Assembly cycle minutes)
    - Notes (projects.notes + recuts.notes)

    Query params:
    - job_name (required)
    - date_from/date_to (YYYY-MM-DD) optional; defaults to min/max scan dates for job
    - gap_minutes (default 20)
    """
    try:
        if not get_db_connection:
            return jsonify({'error': 'DB unavailable'}), 503

        job_name = (request.args.get('job_name') or '').strip()
        if not job_name:
            return jsonify({'error': 'job_name is required'}), 400

        resolved_from = None

        gap_minutes = request.args.get('gap_minutes', 20, type=int)
        gap_minutes = max(1, min(gap_minutes, 240))

        date_from = (request.args.get('date_from') or '').strip()
        date_to = (request.args.get('date_to') or '').strip()

        conn = get_db_connection()
        cursor = conn.cursor()

        # If exact job has no scans, try a partial match (LIKE) and pick the most-common job.
        cursor.execute('SELECT COUNT(*) as c FROM scans WHERE job_name = ?', (job_name,))
        cnt_row = cursor.fetchone()
        exact_count = int((cnt_row['c'] if cnt_row else 0) or 0)
        if exact_count == 0:
            cursor.execute('''
                SELECT job_name, COUNT(*) as c
                FROM scans
                WHERE job_name LIKE ?
                GROUP BY job_name
                ORDER BY c DESC
                LIMIT 1
            ''', (f'%{job_name}%',))
            m = cursor.fetchone()
            if m and (m['job_name'] or '').strip():
                resolved_from = job_name
                job_name = (m['job_name'] or '').strip()
            else:
                conn.close()
                return jsonify({'error': 'No scans found for job'}), 404

        # If date window isn't specified, use min/max scan timestamps for the (resolved) job.
        if not date_from and not date_to:
            cursor.execute('SELECT MIN(timestamp) as min_ts, MAX(timestamp) as max_ts FROM scans WHERE job_name = ?', (job_name,))
            r = cursor.fetchone()
            min_ts = (r['min_ts'] if r else None)
            max_ts = (r['max_ts'] if r else None)
            if not min_ts or not max_ts:
                conn.close()
                return jsonify({'error': 'No scans found for job'}), 404

            min_dt = _parse_scan_ts(min_ts)
            max_dt = _parse_scan_ts(max_ts)
            if not min_dt or not max_dt:
                # Fallback to DATE() if timestamps are oddly formatted.
                cursor.execute('SELECT MIN(DATE(timestamp)) as d1, MAX(DATE(timestamp)) as d2 FROM scans WHERE job_name = ?', (job_name,))
                r2 = cursor.fetchone()
                date_from = (r2['d1'] if r2 else None) or datetime.now().strftime('%Y-%m-%d')
                date_to = (r2['d2'] if r2 else None) or date_from
            else:
                date_from = min_dt.strftime('%Y-%m-%d')
                date_to = max_dt.strftime('%Y-%m-%d')

        # Parse requested date window
        try:
            dt_from = datetime.strptime(date_from, '%Y-%m-%d') if date_from else None
            dt_to = datetime.strptime(date_to, '%Y-%m-%d') if date_to else None
        except Exception:
            conn.close()
            return jsonify({'error': 'Invalid date_from/date_to. Expected YYYY-MM-DD.'}), 400

        if not dt_from:
            dt_from = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        if not dt_to:
            dt_to = dt_from

        start_str = dt_from.strftime('%Y-%m-%d 00:00:00')
        end_str = dt_to.strftime('%Y-%m-%d 23:59:59')

        # Pull job scans in window
        cursor.execute('''
            SELECT timestamp, station_code, station_display_name, operator_id,
                   cabinet_assembly, cabinet_name
            FROM scans
            WHERE job_name = ?
              AND timestamp >= ?
              AND timestamp <= ?
            ORDER BY timestamp ASC
        ''', (job_name, start_str, end_str))
        scan_rows = [dict(r) for r in cursor.fetchall()]

        if not scan_rows:
            conn.close()
            return jsonify({
                'job_name': job_name,
                'date_from': dt_from.strftime('%Y-%m-%d'),
                'date_to': dt_to.strftime('%Y-%m-%d'),
                'scan_count': 0,
                'stations': [],
                'cabinets': [],
                'notes': {},
            })

        # Group scans by station_code + station_display_name (if present)
        groups = {}
        first_scan = scan_rows[0].get('timestamp')
        last_scan = scan_rows[-1].get('timestamp')

        # Cabinet rollup from scans
        cabinets = {}

        for r in scan_rows:
            st = (r.get('station_code') or '').strip()
            sd = (r.get('station_display_name') or '').strip()
            key = f"{st}::{sd}" if sd else st
            if key not in groups:
                groups[key] = {
                    'station_code': st,
                    'station_display_name': sd or None,
                    'rows': []
                }
            groups[key]['rows'].append({
                'timestamp': r.get('timestamp'),
                'station_code': st,
                'operator_id': r.get('operator_id')
            })

            cab_assy = (r.get('cabinet_assembly') or '').strip()
            cab_name = (r.get('cabinet_name') or '').strip()
            cab_key = cab_assy or cab_name
            if cab_key:
                if cab_key not in cabinets:
                    cabinets[cab_key] = {
                        'cabinet_assembly': cab_assy or None,
                        'cabinet_name': cab_name or None,
                        'scan_count': 0,
                        'first_scan': r.get('timestamp'),
                        'last_scan': r.get('timestamp'),
                        'qc_scans': 0,
                        'assembly_scans': 0,
                    }
                c = cabinets[cab_key]
                c['scan_count'] += 1
                c['last_scan'] = r.get('timestamp')
                if not c.get('first_scan'):
                    c['first_scan'] = r.get('timestamp')
                if st == 'QC':
                    c['qc_scans'] += 1
                if st == 'Assembly':
                    c['assembly_scans'] += 1

        stations_out = []
        total_block_sec = 0
        for g in groups.values():
            blocks = _build_work_blocks(g['rows'], gap_minutes=gap_minutes)
            block_sec = int(sum((b.get('duration_seconds') or 0) for b in blocks))
            total_block_sec += block_sec
            stations_out.append({
                'station_code': g['station_code'],
                'station_display_name': g['station_display_name'],
                'scan_count': int(len(g['rows'])),
                'block_count': int(len(blocks)),
                'block_seconds': block_sec,
                'block_minutes': round(block_sec / 60.0, 2),
            })

        # Cycle totals by station (where present)
        cursor.execute('''
            SELECT station_code,
                   NULLIF(TRIM(COALESCE(station_display_name,'')), '') as station_display_name,
                   COUNT(*) as cycle_count,
                   SUM(CASE WHEN status = 'closed' THEN 1 ELSE 0 END) as cycle_closed_count,
                   SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as cycle_open_count,
                   SUM(COALESCE(duration_seconds, 0)) as duration_seconds
            FROM station_cycles
            WHERE job_name = ?
              AND start_time >= ?
              AND start_time <= ?
            GROUP BY station_code, NULLIF(TRIM(COALESCE(station_display_name,'')), '')
        ''', (job_name, start_str, end_str))
        cycle_rows = [dict(r) for r in cursor.fetchall()]
        cycle_map = {}
        for r in cycle_rows:
            st = (r.get('station_code') or '').strip()
            sd = (r.get('station_display_name') or '').strip()
            key = f"{st}::{sd}" if sd else st
            cycle_map[key] = {
                'cycle_count': int(r.get('cycle_count') or 0),
                'cycle_closed_count': int(r.get('cycle_closed_count') or 0),
                'cycle_open_count': int(r.get('cycle_open_count') or 0),
                'cycle_seconds': float(r.get('duration_seconds') or 0),
                'cycle_minutes': round(float(r.get('duration_seconds') or 0) / 60.0, 2),
            }

        # Attach cycle info to stations
        total_cycle_sec = 0
        for s in stations_out:
            st = (s.get('station_code') or '').strip()
            sd = (s.get('station_display_name') or '').strip()
            key = f"{st}::{sd}" if sd else st
            cyc = cycle_map.get(key) or {'cycle_count': 0, 'cycle_closed_count': 0, 'cycle_open_count': 0, 'cycle_seconds': 0, 'cycle_minutes': 0}
            s.update(cyc)
            total_cycle_sec += int(float(cyc.get('cycle_seconds') or 0))
            s['total_seconds'] = int((s.get('block_seconds') or 0) + int(float(cyc.get('cycle_seconds') or 0)))
            s['total_minutes'] = round(s['total_seconds'] / 60.0, 2)

        # Assembly cycle minutes by cabinet
        cursor.execute('''
            SELECT NULLIF(TRIM(COALESCE(cabinet_assembly,'')), '') as cabinet_assembly,
                   NULLIF(TRIM(COALESCE(cabinet_name,'')), '') as cabinet_name,
                   SUM(COALESCE(duration_seconds, 0)) as duration_seconds,
                   COUNT(*) as cycles
            FROM station_cycles
            WHERE station_code = 'Assembly'
              AND job_name = ?
              AND start_time >= ?
              AND start_time <= ?
            GROUP BY NULLIF(TRIM(COALESCE(cabinet_assembly,'')), ''), NULLIF(TRIM(COALESCE(cabinet_name,'')), '')
        ''', (job_name, start_str, end_str))
        assy_by_cab = [dict(r) for r in cursor.fetchall()]
        assy_lookup = {}
        for r in assy_by_cab:
            cab_key = (r.get('cabinet_assembly') or '').strip() or (r.get('cabinet_name') or '').strip()
            if not cab_key:
                continue
            assy_lookup[cab_key] = {
                'assembly_cycle_seconds': float(r.get('duration_seconds') or 0),
                'assembly_cycle_minutes': round(float(r.get('duration_seconds') or 0) / 60.0, 2),
                'assembly_cycle_count': int(r.get('cycles') or 0),
            }

        cabinets_out = []
        for c in cabinets.values():
            cab_key = ((c.get('cabinet_assembly') or '').strip() or (c.get('cabinet_name') or '').strip())
            cyc = assy_lookup.get(cab_key) or {'assembly_cycle_seconds': 0, 'assembly_cycle_minutes': 0, 'assembly_cycle_count': 0}
            c.update(cyc)
            cabinets_out.append(c)

        # Notes: project notes + recut notes
        notes = {}
        try:
            cursor.execute('SELECT job_name, customer_name, status, due_date, notes FROM projects WHERE job_name = ?', (job_name,))
            prow = cursor.fetchone()
            if prow:
                notes['project'] = {
                    'job_name': prow['job_name'],
                    'customer_name': prow['customer_name'],
                    'status': prow['status'],
                    'due_date': prow['due_date'],
                    'notes': prow['notes'],
                }
        except Exception:
            pass

        recuts = []
        try:
            cursor.execute('''
                SELECT timestamp, machine, request_type, fix_station, cabinet_name, part_name, reason, notes, photo_path
                FROM recuts
                WHERE job_name = ?
                  AND timestamp >= ?
                  AND timestamp <= ?
                ORDER BY timestamp DESC
                LIMIT 200
            ''', (job_name, start_str, end_str))
            recuts = [dict(r) for r in cursor.fetchall()]
            notes['recuts'] = recuts
        except Exception:
            notes['recuts'] = []

        conn.close()

        # Sort outputs
        stations_out.sort(key=lambda x: ((x.get('station_code') or ''), (x.get('station_display_name') or '')))
        cabinets_out.sort(key=lambda x: ((x.get('cabinet_assembly') or ''), (x.get('cabinet_name') or '')))

        return jsonify({
            'job_name': job_name,
            'resolved_from': resolved_from,
            'date_from': dt_from.strftime('%Y-%m-%d'),
            'date_to': dt_to.strftime('%Y-%m-%d'),
            'gap_minutes': gap_minutes,
            'scan_count': int(len(scan_rows)),
            'first_scan': first_scan,
            'last_scan': last_scan,
            'total_block_seconds': int(total_block_sec),
            'total_block_minutes': round(total_block_sec / 60.0, 2),
            'total_cycle_seconds': int(total_cycle_sec),
            'total_cycle_minutes': round(total_cycle_sec / 60.0, 2),
            'stations': stations_out,
            'cabinets': cabinets_out,
            'notes': notes,
        })
    except Exception as e:
        logging.error(f"Error building job time report: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


def _parse_mixed_number_in(s: str):
    """Parse numeric strings like '12', '12.5', '12 1/2', '1/4' as inches."""
    t = (s or '').strip()
    if not t:
        return None
    try:
        return float(t)
    except Exception:
        pass
    m = re.match(r'^\s*(\d+)\s+(\d+)\s*/\s*(\d+)\s*$', t)
    if m:
        try:
            whole = float(m.group(1))
            num = float(m.group(2))
            den = float(m.group(3))
            if den == 0:
                return None
            return whole + (num / den)
        except Exception:
            return None
    m2 = re.match(r'^\s*(\d+)\s*/\s*(\d+)\s*$', t)
    if m2:
        try:
            num = float(m2.group(1))
            den = float(m2.group(2))
            if den == 0:
                return None
            return num / den
        except Exception:
            return None
    return None


def _length_to_inches_best_effort(x):
    """Heuristic inches converter: if numeric and >300 assume mm, else inches/fractions."""
    s = ('' if x is None else str(x)).strip()
    if not s:
        return None
    try:
        # If it's a plain number and "large", assume mm.
        if s.replace('.', '', 1).isdigit():
            v = float(s)
            if v > 300:
                return v / 25.4
    except Exception:
        pass
    v2 = _parse_mixed_number_in(s)
    return v2


_EDGE_RE = re.compile(r"^\s*([A-Za-z]{1,3})\s*[-_]?\s*([0-6])\s*,\s*([0-6])\s*,\s*([0-6])\s*,\s*([0-6])\s*$")


def _parse_edge_code(x):
    """Parse edge band code strings like 'P-1,0,0,0' -> {prefix, edges}."""
    s = ('' if x is None else str(x)).strip()
    if not s:
        return None
    s2 = re.sub(r"\s+", "", s)
    m = _EDGE_RE.match(s2)
    if not m:
        return None
    prefix = (m.group(1) or '').upper()
    edges = [int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))]
    return {'prefix': prefix, 'edges': edges}


def _norm_edge_key(x):
    parsed = _parse_edge_code(x)
    if parsed:
        return str(parsed.get('prefix') or '')[:120]
    s = ('' if x is None else str(x)).strip()
    if not s:
        return ''
    for sep in [',', '|', ';']:
        if sep in s:
            s = s.split(sep, 1)[0].strip()
    return s[:120]


def _part_dedupe_key(d: dict) -> str:
    g = (str(d.get('gcode') or d.get('gcode_filename') or '')).strip()
    p = (str(d.get('part_num') or d.get('part_number') or '')).strip()
    if g and p:
        return f"{g}::{p}"
    j = (str(d.get('job_name') or '')).strip()
    pn = (str(d.get('part_name') or '')).strip()
    return f"{j}::{p or pn}"


BUILTIN_CUSTOM_REPORTS_V1 = {
    "edge_band_usage": {
        "key": "edge_band_usage",
        "name": "Edge band usage (band index + linear feet)",
        "active": True,
        "built_in": True,
        "config": {
            "kind": "aggregate",
            "group_by": ["edge_prefix", "band_index"],
            "filters": [{"field": "edge_material", "op": "exists"}],
            "metrics": [
                {"key": "parts", "op": "count_distinct_part"},
                {"key": "linear_feet", "op": "sum_edge_lf"},
            ],
            "dedupe": True,
            "exclude_band_indexes": [6],
        },
    },
    "sand_throughput": {
        "key": "sand_throughput",
        "name": "Sanding throughput (parts + avg gap)",
        "active": True,
        "built_in": True,
        "config": {
            "kind": "aggregate",
            "group_by": ["station_code", "station_display_name"],
            "filters": [{"field": "station_code", "op": "contains", "value": "sand"}],
            "metrics": [
                {"key": "scans", "op": "count"},
                {"key": "parts", "op": "count_distinct_part"},
                {"key": "avg_gap_seconds", "op": "avg_gap_seconds"},
            ],
        },
    },
}


def _load_custom_report_defs_v1() -> list:
    """Load user-defined custom reports from DB settings (best effort)."""
    if not get_setting:
        return []
    try:
        raw = (get_setting('custom_report_defs_json', '[]') or '[]')
        d = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(d, list):
            return []
        out = []
        for r in d:
            if not isinstance(r, dict):
                continue
            key = (r.get('key') or '').strip()
            name = (r.get('name') or key).strip()
            cfg = r.get('config') if isinstance(r.get('config'), dict) else {}
            if not key:
                continue
            out.append({'key': key, 'name': name, 'active': (r.get('active') is not False), 'built_in': False, 'config': cfg})
        return out[:200]
    except Exception:
        return []


def _save_custom_report_defs_v1(items: list) -> None:
    if not set_setting:
        raise RuntimeError('settings not available')
    safe = []
    for r in (items or []):
        if not isinstance(r, dict):
            continue
        key = (r.get('key') or '').strip()
        if not key or key in BUILTIN_CUSTOM_REPORTS_V1:
            continue
        name = (r.get('name') or key).strip()[:120]
        cfg = r.get('config') if isinstance(r.get('config'), dict) else {}
        # Keep config to a safe subset
        out_cfg = {
            "kind": (str(cfg.get("kind") or "aggregate").strip().lower() or "aggregate"),
            "group_by": list(cfg.get("group_by") or []),
            "filters": list(cfg.get("filters") or []),
            "metrics": list(cfg.get("metrics") or []),
        }
        if "dedupe" in cfg:
            out_cfg["dedupe"] = bool(cfg.get("dedupe"))
        if "exclude_band_indexes" in cfg and isinstance(cfg.get("exclude_band_indexes"), list):
            out_cfg["exclude_band_indexes"] = [int(x) for x in cfg.get("exclude_band_indexes") if str(x).strip().lstrip("-").isdigit()]
        safe.append({"key": key[:80], "name": name, "config": out_cfg, "active": (r.get("active") is not False)})
    set_setting('custom_report_defs_json', json.dumps(safe))


def _apply_filters_v1(row: dict, filters: list) -> bool:
    for f in (filters or []):
        if not isinstance(f, dict):
            continue
        field = (f.get("field") or "").strip()
        op = (f.get("op") or "exists").strip().lower()
        val = f.get("value")
        rv = row.get(field)
        rs = ("" if rv is None else str(rv))
        if op == "exists":
            if not rs.strip():
                return False
        elif op == "equals":
            if (rs.strip().lower() != ("" if val is None else str(val)).strip().lower()):
                return False
        elif op == "contains":
            if (("" if val is None else str(val)).strip().lower() not in rs.lower()):
                return False
        elif op == "startswith":
            if not rs.lower().startswith(("" if val is None else str(val)).strip().lower()):
                return False
    return True


@app.route('/api/reports/custom/defs', methods=['GET', 'POST'])
def api_reports_custom_defs_v1():
    """v1 custom report definitions (built-ins + optional saved)."""
    if not get_db_connection:
        return jsonify({'error': 'DB unavailable'}), 503

    if request.method == 'GET':
        saved = _load_custom_report_defs_v1()
        out = [BUILTIN_CUSTOM_REPORTS_V1[k] for k in sorted(BUILTIN_CUSTOM_REPORTS_V1.keys())]
        out.extend(saved)
        return jsonify({'reports': out})

    # POST (admin only)
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403
    if not set_setting:
        return jsonify({'error': 'Settings not available on this server'}), 501
    body = request.get_json(silent=True) or {}
    key = (body.get('key') or '').strip()
    name = (body.get('name') or '').strip()
    config = body.get('config') if isinstance(body.get('config'), dict) else None
    if not key or not config:
        return jsonify({'error': 'key + config required'}), 400
    if key in BUILTIN_CUSTOM_REPORTS_V1:
        return jsonify({'error': 'built-in report keys cannot be overwritten'}), 400
    saved = _load_custom_report_defs_v1()
    saved = [r for r in saved if (r.get('key') or '') != key]
    saved.append({'key': key, 'name': (name or key), 'config': config, 'active': True})
    try:
        _save_custom_report_defs_v1(saved)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/custom/defs/<path:key>', methods=['DELETE'])
def api_reports_custom_defs_delete_v1(key: str):
    if _auth_enabled() and _current_role(session) != 'admin':
        return jsonify({'error': 'Not authorized. Admin password required.', 'required_role': 'admin'}), 403
    kk = (key or '').strip()
    if kk in BUILTIN_CUSTOM_REPORTS_V1:
        return jsonify({'error': 'built-in report keys cannot be deleted'}), 400
    try:
        saved = _load_custom_report_defs_v1()
        before = len(saved)
        saved2 = [r for r in saved if (r.get('key') or '') != kk]
        _save_custom_report_defs_v1(saved2)
        return jsonify({'success': True, 'deleted': (before - len(saved2))})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/custom/run')
def api_reports_custom_run_v1():
    """Run a custom report against v1 scans (single-shop)."""
    try:
        if not get_db_connection:
            return jsonify({'error': 'DB unavailable'}), 503
        key = (request.args.get('key') or '').strip()
        if not key:
            return jsonify({'error': 'key required'}), 400

        # Find report definition
        rd = BUILTIN_CUSTOM_REPORTS_V1.get(key)
        if not rd:
            for r in _load_custom_report_defs_v1():
                if (r.get('key') or '').strip() == key:
                    rd = r
                    break
        if not rd:
            return jsonify({'error': 'report not found'}), 404

        cfg = rd.get('config') if isinstance(rd.get('config'), dict) else {}
        group_by = list(cfg.get('group_by') or [])
        filters = list(cfg.get('filters') or [])
        metrics = list(cfg.get('metrics') or [])
        dedupe = bool(cfg.get('dedupe', False))
        exclude_band = set()
        try:
            xbi = cfg.get('exclude_band_indexes')
            if isinstance(xbi, list):
                exclude_band = {int(x) for x in xbi if str(x).strip().lstrip('-').isdigit()}
        except Exception:
            exclude_band = set()
        if key == 'edge_band_usage' and not exclude_band:
            exclude_band = {6}

        # Optional quick filters
        job_q = (request.args.get('job') or '').strip().lower()
        edge_pref_q = (request.args.get('edge_prefix') or '').strip().upper()

        date_from = (request.args.get('date_from') or '').strip()
        date_to = (request.args.get('date_to') or '').strip()
        # Default to today
        if not date_from and not date_to:
            d = datetime.now().strftime('%Y-%m-%d')
            date_from = d
            date_to = d
        try:
            dt_from = datetime.strptime(date_from, '%Y-%m-%d') if date_from else None
            dt_to = datetime.strptime(date_to, '%Y-%m-%d') if date_to else None
        except Exception:
            return jsonify({'error': 'Invalid date_from/date_to. Expected YYYY-MM-DD.'}), 400
        if not dt_from:
            dt_from = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        if not dt_to:
            dt_to = dt_from
        start_str = dt_from.strftime('%Y-%m-%d 00:00:00')
        end_str = dt_to.strftime('%Y-%m-%d 23:59:59')

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('''
            SELECT timestamp, station_code, station_display_name, job_name, run_name, material,
                   part_name, part_num, part_length, part_width, edge_material, gcode,
                   cabinet_assembly, cabinet_name, opening_letter, operator_id
            FROM scans
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp ASC
        ''', (start_str, end_str))
        rows = [dict(r) for r in (cur.fetchall() or [])]
        conn.close()

        data_rows = []
        for d in rows:
            if job_q and job_q not in (str(d.get('job_name') or '')).lower():
                continue
            if edge_pref_q:
                ec = _parse_edge_code(d.get('edge_material'))
                pref = (ec.get('prefix') if ec else _norm_edge_key(d.get('edge_material'))).upper()
                if pref != edge_pref_q:
                    continue
            # enrich edge fields
            d['edge_key'] = _norm_edge_key(d.get('edge_material'))
            ec = _parse_edge_code(d.get('edge_material'))
            if ec:
                d['edge_prefix'] = ec.get('prefix')
                d['_edge_edges'] = ec.get('edges')
            else:
                d['edge_prefix'] = d.get('edge_key')
                d['_edge_edges'] = None
            if _apply_filters_v1(d, filters):
                data_rows.append(d)

        # Aggregate engine
        agg = {}
        seen_parts = set()

        def _ensure_group(gk, d0):
            if gk not in agg:
                agg[gk] = {k: d0.get(k) for k in group_by}
                for m in metrics:
                    agg[gk][m.get('key')] = 0
                agg[gk]['__seen_parts'] = set()
                agg[gk]['__last_ts'] = None
                agg[gk]['__gap_sum'] = 0.0
                agg[gk]['__gap_n'] = 0

        def _count_distinct(gk, d0, metric_key):
            sp = agg[gk].get('__seen_parts')
            if not isinstance(sp, set):
                sp = set()
                agg[gk]['__seen_parts'] = sp
            dk = _part_dedupe_key(d0)
            if dk and dk not in sp:
                sp.add(dk)
                agg[gk][metric_key] = int(agg[gk].get(metric_key) or 0) + 1

        def _update_gap(gk, ts):
            last = agg[gk].get('__last_ts')
            if last and isinstance(last, datetime) and isinstance(ts, datetime):
                dt = (ts - last).total_seconds()
                if dt >= 0:
                    agg[gk]['__gap_sum'] = float(agg[gk].get('__gap_sum') or 0.0) + float(dt)
                    agg[gk]['__gap_n'] = int(agg[gk].get('__gap_n') or 0) + 1
            agg[gk]['__last_ts'] = ts

        for d in data_rows:
            # Parse timestamp for gap metrics
            ts = _parse_scan_ts(d.get('timestamp'))

            edges = d.get('_edge_edges')
            if key == 'edge_band_usage':
                if isinstance(edges, list) and len(edges) == 4:
                    # Only dedupe if there is at least one countable band
                    has_countable = False
                    try:
                        for bi0 in edges:
                            bi = int(bi0 or 0)
                            if bi > 0 and bi not in exclude_band:
                                has_countable = True
                                break
                    except Exception:
                        has_countable = False
                    if not has_countable:
                        continue
                    if dedupe:
                        pk = _part_dedupe_key(d)
                        if pk and pk in seen_parts:
                            continue
                        if pk:
                            seen_parts.add(pk)
                    L_in = _length_to_inches_best_effort(d.get('part_length')) or 0.0
                    W_in = _length_to_inches_best_effort(d.get('part_width')) or 0.0
                    side_in = [L_in, W_in, L_in, W_in]
                    prefix = (d.get('edge_prefix') or '')
                    for side_idx, band_idx in enumerate(edges):
                        bi = int(band_idx or 0)
                        if bi <= 0 or bi in exclude_band:
                            continue
                        d2 = dict(d)
                        d2['edge_prefix'] = prefix
                        d2['band_index'] = bi
                        inches = float(side_in[side_idx] or 0.0)
                        lf_add = (inches / 12.0) if inches > 0 else 0.0
                        gk = tuple(d2.get(k) for k in group_by) if group_by else tuple()
                        _ensure_group(gk, d2)
                        for m in metrics:
                            mk = str(m.get('key'))
                            op = (m.get('op') or '').strip().lower()
                            if op == 'count':
                                agg[gk][mk] = int(agg[gk].get(mk) or 0) + 1
                            elif op == 'count_distinct_part':
                                _count_distinct(gk, d2, mk)
                            elif op in ('sum_edge_lf', 'sum_length_ft'):
                                agg[gk][mk] = float(agg[gk].get(mk) or 0.0) + float(lf_add)
                    continue
                # fallback (rare)
                d2 = dict(d)
                d2['band_index'] = None
                gk = tuple(d2.get(k) for k in group_by) if group_by else tuple()
                _ensure_group(gk, d2)
                for m in metrics:
                    mk = str(m.get('key'))
                    op = (m.get('op') or '').strip().lower()
                    if op == 'count_distinct_part':
                        _count_distinct(gk, d2, mk)
                continue

            # generic aggregation (sand etc)
            gk = tuple(d.get(k) for k in group_by) if group_by else tuple()
            _ensure_group(gk, d)
            for m in metrics:
                mk = str(m.get('key'))
                op = (m.get('op') or '').strip().lower()
                if op == 'count':
                    agg[gk][mk] = int(agg[gk].get(mk) or 0) + 1
                elif op == 'count_distinct_part':
                    _count_distinct(gk, d, mk)
                elif op == 'avg_gap_seconds':
                    if isinstance(ts, datetime):
                        _update_gap(gk, ts)

        out_rows = []
        for v in agg.values():
            v.pop('__seen_parts', None)
            last_ts = v.pop('__last_ts', None)
            gap_sum = float(v.pop('__gap_sum', 0.0) or 0.0)
            gap_n = int(v.pop('__gap_n', 0) or 0)
            # finalize avg_gap_seconds if present
            if 'avg_gap_seconds' in v:
                v['avg_gap_seconds'] = round((gap_sum / gap_n), 1) if gap_n > 0 else None
            if 'linear_feet' in v and isinstance(v.get('linear_feet'), (int, float)):
                try:
                    v['linear_feet'] = round(float(v.get('linear_feet') or 0.0), 2)
                except Exception:
                    pass
            out_rows.append(v)

        if group_by:
            out_rows.sort(key=lambda x: (str(x.get(group_by[0]) or '')))
        columns = [*group_by, *[str(m.get('key')) for m in metrics]]
        return jsonify({
            'report': {'key': rd.get('key'), 'name': rd.get('name')},
            'columns': columns,
            'rows': out_rows,
            'row_count': len(out_rows),
            'source_rows': len(data_rows),
        })
    except Exception as e:
        logging.error(f"Error running custom report: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/blocks')
def api_reports_blocks():
    """Work blocks: continuous scanning until a pause of >= gap_minutes splits a new block."""
    try:
        if not get_db_connection:
            return jsonify({'error': 'DB unavailable'}), 503

        station = (request.args.get('station') or '').strip()
        gap_minutes = request.args.get('gap_minutes', 20, type=int)
        limit = request.args.get('limit', 500, type=int)
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        date = request.args.get('date')

        # Default window = selected date (or today)
        if not date_from and not date_to:
            d = date or datetime.now().strftime('%Y-%m-%d')
            date_from = d
            date_to = d

        # Build inclusive date window [date_from 00:00:00, date_to 23:59:59]
        try:
            dt_from = datetime.strptime(date_from, '%Y-%m-%d') if date_from else None
            dt_to = datetime.strptime(date_to, '%Y-%m-%d') if date_to else None
        except Exception:
            return jsonify({'error': 'Invalid date_from/date_to. Expected YYYY-MM-DD.'}), 400

        if not dt_from:
            dt_from = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        if not dt_to:
            dt_to = dt_from

        start_str = dt_from.strftime('%Y-%m-%d 00:00:00')
        end_str = dt_to.strftime('%Y-%m-%d 23:59:59')

        stations = [station] if station else ['H08', 'H10', 'Edge', 'Dowel', 'Sort', 'Pull', 'Assembly', 'QC', 'Band', 'Banding']
        conn = get_db_connection()
        cursor = conn.cursor()

        blocks_out = []
        for st in stations:
            cursor.execute('''
                                SELECT timestamp, station_code, operator_id
                FROM scans
                WHERE station_code = ?
                  AND timestamp >= ?
                  AND timestamp <= ?
                ORDER BY timestamp ASC
            ''', (st, start_str, end_str))
            rows = [dict(r) for r in cursor.fetchall()]
            blocks = _build_work_blocks(rows, gap_minutes=gap_minutes)
            for b in blocks:
                b['date_from'] = dt_from.strftime('%Y-%m-%d')
                b['date_to'] = dt_to.strftime('%Y-%m-%d')
                b['gap_minutes'] = gap_minutes
            blocks_out.extend(blocks)

        conn.close()

        # Sort newest first
        def _key(b):
            return b.get('start_time') or ''
        blocks_out.sort(key=_key, reverse=True)

        if limit and limit > 0:
            blocks_out = blocks_out[:limit]

        return jsonify({
            'date_from': dt_from.strftime('%Y-%m-%d'),
            'date_to': dt_to.strftime('%Y-%m-%d'),
            'gap_minutes': gap_minutes,
            'station': station,
            'count': len(blocks_out),
            'blocks': blocks_out,
        })
    except Exception as e:
        logging.error(f"Error building blocks report: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/utilization')
def api_reports_utilization():
    """Utilization = sum of work-block durations over a window (day/week/month)."""
    try:
        if not get_db_connection:
            return jsonify({'error': 'DB unavailable'}), 503

        window = (request.args.get('window') or 'day').strip().lower()
        as_of = request.args.get('date') or datetime.now().strftime('%Y-%m-%d')
        gap_minutes = request.args.get('gap_minutes', 20, type=int)
        gaps_raw = (request.args.get('gaps') or '').strip()

        gaps_by_station = {}
        if gaps_raw:
            # Format: H08=60,H10=60,Assembly=60
            for pair in gaps_raw.split(','):
                pair = (pair or '').strip()
                if not pair or '=' not in pair:
                    continue
                k, v = pair.split('=', 1)
                st = (k or '').strip()
                try:
                    mv = int(str(v).strip())
                except Exception:
                    continue
                if not st:
                    continue
                mv = max(1, min(mv, 240))
                gaps_by_station[st] = mv

        try:
            as_of_dt = datetime.strptime(as_of, '%Y-%m-%d')
        except Exception:
            return jsonify({'error': 'Invalid date. Expected YYYY-MM-DD.'}), 400

        if window == 'day':
            dt_from = as_of_dt
            dt_to = as_of_dt
        elif window == 'week':
            dt_to = as_of_dt
            dt_from = as_of_dt - timedelta(days=6)
        elif window == 'month':
            dt_to = as_of_dt
            dt_from = as_of_dt - timedelta(days=29)
        else:
            return jsonify({'error': "Invalid window. Use day|week|month."}), 400

        start_str = dt_from.strftime('%Y-%m-%d 00:00:00')
        end_str = dt_to.strftime('%Y-%m-%d 23:59:59')

        stations = ['H08', 'H10', 'Edge', 'Dowel', 'Sort', 'Pull', 'Assembly', 'QC', 'Band', 'Banding']
        conn = get_db_connection()
        cursor = conn.cursor()

        out = []
        for st in stations:
            gap_for_station = gaps_by_station.get(st, gap_minutes)
            cursor.execute('''
                SELECT timestamp, station_code
                FROM scans
                WHERE station_code = ?
                  AND timestamp >= ?
                  AND timestamp <= ?
                ORDER BY timestamp ASC
            ''', (st, start_str, end_str))
            rows = [dict(r) for r in cursor.fetchall()]
            blocks = _build_work_blocks(rows, gap_minutes=gap_for_station)
            active_seconds = sum(int(b.get('duration_seconds') or 0) for b in blocks)
            scan_count = sum(int(b.get('scan_count') or 0) for b in blocks)
            out.append({
                'station_code': st,
                'active_seconds': active_seconds,
                'active_minutes': round(active_seconds / 60.0, 2),
                'active_hours': round(active_seconds / 3600.0, 2),
                'block_count': len(blocks),
                'scan_count': scan_count,
                'gap_minutes_used': int(gap_for_station),
            })

        conn.close()

        return jsonify({
            'window': window,
            'date_from': dt_from.strftime('%Y-%m-%d'),
            'date_to': dt_to.strftime('%Y-%m-%d'),
            'gap_minutes': gap_minutes,
            'stations': out,
        })
    except Exception as e:
        logging.error(f"Error building utilization report: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    bind_host = os.environ.get('INNOSAW_BIND_HOST', '0.0.0.0')
    bind_port = int(os.environ.get('INNOSAW_SHOP_DASHBOARD_PORT', '5006'))
    app.run(host=bind_host, port=bind_port, debug=False)

