#!/usr/bin/env python3
"""
Manufacturing System Database Schema
Central SQLite database for all Pi-based tracking

Tables:
- scans: All scan history
- bins: Current bin contents  
- blocks: Work session tracking
- maintenance_log: Machine maintenance records
- tool_changes: Tool change history with part counts
- recuts: Recut requests
- materials: Raw material inventory
- parts_wip: Work in progress parts
- cabinets: Cabinet/project tracking
- cabinet_recipes: Expected parts per cabinet
- operators: Operator information
- webhooks: Notification webhook configs
"""

import sqlite3
import logging
import os
import shutil
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple, Union
import re

# Database path
# Default (legacy): <repo>/data/manufacturing.db
# Recommended for production appliances: set QR_SCANNER_DATA_DIR (or INNOSAW_DATA_DIR)
# to a stable location outside the git working tree, e.g. /var/lib/qr-scanner
_REPO_DATA_DIR = Path(__file__).parent / "data"
_DATA_DIR_ENV = (os.environ.get('QR_SCANNER_DATA_DIR') or os.environ.get('INNOSAW_DATA_DIR') or '').strip()
DATA_DIR = (Path(_DATA_DIR_ENV).expanduser() if _DATA_DIR_ENV else _REPO_DATA_DIR)
DB_PATH = DATA_DIR / "manufacturing.db"

# ============================================================
# Assembly unit (group) classification rules (DB-backed)
# ============================================================

_ASSEMBLY_RULES_CACHE = {
    "ts": 0.0,
    "raw": None,
    "parsed": None,
}


def _default_assembly_unit_rules() -> dict:
    """
    Default rules (ordered). First match wins.

    Notes:
    - This is intentionally simple and stable (substring matching).
    - Admin UI can override via settings key: assembly_unit_rules_json
    """
    return {
        "version": 1,
        "default": "Case",
        "rules": [
            {"unit": "QC", "when": {"station_display_name_contains": ["qc"]}},
            {"unit": "Insert", "when": {"part_name_contains": ["*"]}},
            {"unit": "Tray", "when": {"part_name_contains": ["tray"]}},
            {"unit": "Door", "when": {"part_name_contains": ["door"]}},
            {"unit": "Drawer Front", "when": {"part_name_contains": ["drawer"]}},
            {"unit": "Drawer Box", "when": {"part_name_contains": ["dwr", "drw"]}},
        ],
    }


def _parse_assembly_unit_rules(raw_val) -> dict:
    if raw_val is None:
        return _default_assembly_unit_rules()

    # Accept dict already
    if isinstance(raw_val, dict):
        cfg = raw_val
    else:
        s = (str(raw_val) or "").strip()
        if not s:
            return _default_assembly_unit_rules()
        try:
            cfg = json.loads(s)  # type: ignore[name-defined]
        except Exception:
            return _default_assembly_unit_rules()

    if not isinstance(cfg, dict):
        return _default_assembly_unit_rules()

    rules = cfg.get("rules")
    if not isinstance(rules, list):
        return _default_assembly_unit_rules()

    # Ensure required keys exist
    out = {
        "version": int(cfg.get("version") or 1),
        "default": str(cfg.get("default") or "Case"),
        "rules": [],
    }
    for r in rules:
        if not isinstance(r, dict):
            continue
        unit = (r.get("unit") or "").strip()
        when = r.get("when")
        if not unit or not isinstance(when, dict):
            continue
        out["rules"].append({"unit": unit, "when": when})
    if not out["rules"]:
        return _default_assembly_unit_rules()
    return out


def _load_assembly_unit_rules_cached(force: bool = False) -> dict:
    """
    Load rules from settings with a short cache.
    Uses a new DB connection via get_setting; keep cache to avoid per-scan overhead.
    """
    import time as _time

    now = _time.time()
    ttl = 5.0
    if (not force) and _ASSEMBLY_RULES_CACHE.get("parsed") and (now - float(_ASSEMBLY_RULES_CACHE.get("ts") or 0.0)) < ttl:
        return _ASSEMBLY_RULES_CACHE["parsed"]  # type: ignore[return-value]

    raw = None
    try:
        raw = get_setting("assembly_unit_rules_json", "")  # type: ignore[name-defined]
    except Exception:
        raw = ""

    # If unchanged, refresh ts only
    if (not force) and (raw == _ASSEMBLY_RULES_CACHE.get("raw")) and _ASSEMBLY_RULES_CACHE.get("parsed") is not None:
        _ASSEMBLY_RULES_CACHE["ts"] = now
        return _ASSEMBLY_RULES_CACHE["parsed"]  # type: ignore[return-value]

    parsed = _parse_assembly_unit_rules(raw)
    _ASSEMBLY_RULES_CACHE["ts"] = now
    _ASSEMBLY_RULES_CACHE["raw"] = raw
    _ASSEMBLY_RULES_CACHE["parsed"] = parsed
    return parsed


def classify_assembly_unit(
    part_name: str,
    station_code: str = None,
    station_display_name: str = None,
    opening_letter: str = None,
    rules_override: dict = None,
) -> str:
    """
    Return assembly unit/group label for a scan (Case/Drawer/Door/QC/etc).

    rules_override: optional dict matching the rules schema (used by Admin "Test" UI).
    """
    cfg = _parse_assembly_unit_rules(rules_override) if isinstance(rules_override, dict) else _load_assembly_unit_rules_cached()
    default_unit = (cfg.get("default") or "Case").strip() or "Case"

    pn = (part_name or "")
    pn_l = pn.lower()
    sd = (station_display_name or "")
    sd_l = sd.lower()
    sc = (station_code or "")
    sc_l = sc.lower()
    ol = (opening_letter or "")
    ol_l = ol.lower()

    def _contains_all(hay: str, needles: list) -> bool:
        for n in needles:
            if not n:
                continue
            if str(n).lower() not in hay:
                return False
        return True

    def _contains_any(hay: str, needles: list) -> bool:
        for n in needles:
            if not n:
                continue
            if str(n).lower() in hay:
                return True
        return False

    for rule in (cfg.get("rules") or []):
        if not isinstance(rule, dict):
            continue
        unit = (rule.get("unit") or "").strip()
        when = rule.get("when")
        if not unit or not isinstance(when, dict):
            continue

        ok = True

        # Substring matching fields
        if "part_name_contains" in when:
            lst = when.get("part_name_contains") or []
            if isinstance(lst, str):
                lst = [lst]
            ok = ok and _contains_any(pn_l, list(lst))

        if "station_display_name_contains" in when:
            lst = when.get("station_display_name_contains") or []
            if isinstance(lst, str):
                lst = [lst]
            ok = ok and _contains_any(sd_l, list(lst))

        if "station_code_contains" in when:
            lst = when.get("station_code_contains") or []
            if isinstance(lst, str):
                lst = [lst]
            ok = ok and _contains_any(sc_l, list(lst))

        if "opening_letter_contains" in when:
            lst = when.get("opening_letter_contains") or []
            if isinstance(lst, str):
                lst = [lst]
            ok = ok and _contains_any(ol_l, list(lst))

        # Exact match fields
        if "station_code_equals" in when:
            lst = when.get("station_code_equals") or []
            if isinstance(lst, str):
                lst = [lst]
            ok = ok and (sc_l in [str(x).lower() for x in list(lst)])

        if "opening_letter_equals" in when:
            lst = when.get("opening_letter_equals") or []
            if isinstance(lst, str):
                lst = [lst]
            ok = ok and (ol_l in [str(x).lower() for x in list(lst)])

        # Regex support (optional)
        if ok and "part_name_regex" in when:
            try:
                pat = str(when.get("part_name_regex") or "")
                if pat:
                    ok = ok and bool(re.search(pat, pn, flags=re.IGNORECASE))
            except Exception:
                ok = False

        if ok and "station_display_name_regex" in when:
            try:
                pat = str(when.get("station_display_name_regex") or "")
                if pat:
                    ok = ok and bool(re.search(pat, sd, flags=re.IGNORECASE))
            except Exception:
                ok = False

        if ok:
            return unit

    # Fallback: keep legacy behavior if no rules match
    if "*" in pn:
        return "Insert"
    if "tray" in pn_l:
        return "Tray"
    if "door" in pn_l:
        return "Door"
    if "drawer" in pn_l:
        return "Drawer Front"
    if "dwr" in pn_l or "drw" in pn_l:
        return "Drawer Box"
    return default_unit


def _maybe_seed_db_from_repo_location() -> None:
    """If DB_PATH points outside the repo and doesn't exist yet, copy the legacy DB over once."""
    try:
        if DATA_DIR == _REPO_DATA_DIR:
            return
        if DB_PATH.exists():
            return
        legacy = _REPO_DATA_DIR / 'manufacturing.db'
        if not legacy.exists():
            return
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(legacy, DB_PATH)
        logging.info("Seeded DB from legacy location: %s -> %s", legacy, DB_PATH)
    except Exception as e:
        # Never prevent startup due to a convenience copy.
        logging.warning("DB seed/migration skipped: %s", e)

def _slugify_tool_code(name: str) -> str:
    s = (name or '').strip().lower()
    s = re.sub(r'[^a-z0-9]+', '_', s)
    s = re.sub(r'_+', '_', s).strip('_')
    return ('T_' + (s[:40] if s else 'tool')).upper()


def _sync_tooling_catalog_from_tools(cursor) -> None:
    """
    Make Tooling Layout dropdowns reflect Tool Inventory entries.
    - Ensure every tool has a tool_code (derive if missing)
    - Upsert tool_catalog rows from tools
    - Ensure tool_stock rows exist for each tool_code
    """
    # Ensure tool_code exists for all tools
    cursor.execute("SELECT id, tool_name, tool_code FROM tools")
    rows = cursor.fetchall()
    for r in rows:
        if not (r['tool_code'] or '').strip():
            code = _slugify_tool_code(r['tool_name'] or f"tool_{r['id']}")
            cursor.execute("UPDATE tools SET tool_code = ? WHERE id = ?", (code, r['id']))

    # Upsert into tool_catalog + ensure tool_stock
    cursor.execute("SELECT tool_code, tool_name, tool_type, machine, notes FROM tools WHERE tool_code IS NOT NULL AND TRIM(tool_code) <> ''")
    for r in cursor.fetchall():
        cursor.execute('''
            INSERT INTO tool_catalog (tool_code, tool_name, tool_type, category, notes)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(tool_code) DO UPDATE SET
                tool_name = excluded.tool_name,
                tool_type = COALESCE(excluded.tool_type, tool_catalog.tool_type),
                notes = COALESCE(excluded.notes, tool_catalog.notes)
        ''', (r['tool_code'], r['tool_name'], r['tool_type'], r['machine'], r['notes']))
        cursor.execute('INSERT OR IGNORE INTO tool_stock (tool_code, qty_on_hand) VALUES (?, 0)', (r['tool_code'],))


def get_db_connection():
    """Get database connection with row factory"""
    _maybe_seed_db_from_repo_location()
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    """Initialize all database tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # ============================================
    # SCAN TRACKING
    # ============================================
    
    # All scans history
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            station_code TEXT NOT NULL,
            raw_data TEXT,
            gcode TEXT,
            part_num TEXT,
            material TEXT,
            run_name TEXT,
            opening_letter TEXT,
            job_name TEXT,
            cabinet_name TEXT,
            cabinet_assembly TEXT,
            room_num INTEGER,
            cabinet_num INTEGER,
            room_code TEXT,
            cabinet_code TEXT,
            cab_type TEXT,
            part_name TEXT,
            operator_id TEXT,
            bin_number INTEGER,
            block_id TEXT,
            processed BOOLEAN DEFAULT 1
        )
    ''')

    # Ensure schema migrations for scans table (older DB files won't have new columns)
    # IMPORTANT: do this BEFORE creating indexes that reference newly-added columns.
    _ensure_table_columns(cursor, 'scans', {
        'part_num': 'TEXT',
        'run_name': 'TEXT',
        'opening_letter': 'TEXT',
        'room_num': 'INTEGER',
        'cabinet_num': 'INTEGER',
        'room_code': 'TEXT',
        'cabinet_code': 'TEXT',
        'cab_type': 'TEXT',
        'station_display_name': 'TEXT',
        'material_thickness': 'TEXT',
        'part_length': 'TEXT',
        'part_width': 'TEXT',
        'edge_material': 'TEXT',
    })

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_station ON scans(station_code)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_job ON scans(job_name)')

    # These indexes may not be creatable on very old DBs until after migration runs.
    try:
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_room ON scans(room_num)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_cabnum ON scans(cabinet_num)')
    except Exception as e:
        logging.warning(f"Could not create room/cabinet indexes yet: {e}")

    try:
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_room_code ON scans(room_code)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_cab_code ON scans(cabinet_code)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_cab_type ON scans(cab_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_run_name ON scans(run_name)')
    except Exception as e:
        logging.warning(f"Could not create room/cab code indexes yet: {e}")
    
    # ============================================
    # BIN MANAGEMENT
    # ============================================
    
    # Current bin contents (parts in bins)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bin_contents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bin_number INTEGER NOT NULL,
            part_number TEXT NOT NULL,
            cabinet_name TEXT,
            job_name TEXT,
            quantity INTEGER DEFAULT 1,
            raw_data TEXT,
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            added_by TEXT,
            station_code TEXT
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_bins_number ON bin_contents(bin_number)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_bins_cabinet ON bin_contents(cabinet_name)')
    
    # Bin history (all add/remove actions)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bin_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            bin_number INTEGER NOT NULL,
            action TEXT NOT NULL,  -- 'add', 'pull', 'clear'
            part_number TEXT,
            cabinet_name TEXT,
            job_name TEXT,
            quantity INTEGER DEFAULT 1,
            operator_id TEXT,
            station_code TEXT
        )
    ''')
    
    # ============================================
    # WORK BLOCKS/SESSIONS
    # ============================================
    
    # Work blocks (groups of scans in a session)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date DATE NOT NULL,
            station_code TEXT NOT NULL,
            block_id TEXT NOT NULL,
            start_time DATETIME,
            end_time DATETIME,
            duration_minutes REAL,
            scan_count INTEGER DEFAULT 0,
            first_gcode TEXT,
            first_job TEXT,
            unit_type TEXT,  -- 'Sheets' or 'Parts'
            UNIQUE(date, station_code, block_id)
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocks_date ON blocks(date)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocks_station ON blocks(station_code)')

    # ============================================
    # STATION CYCLES (start/end duration tracking)
    # ============================================

    # Cycle timing for stations that have natural start/end events (H08/H10, Assembly)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS station_cycles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            station_code TEXT NOT NULL,
            cycle_key TEXT NOT NULL,      -- e.g. "S01R01.TCN|152 Carriage Court" or "R1C5"
            job_name TEXT,
            gcode TEXT,
            cabinet_assembly TEXT,
            start_time DATETIME NOT NULL,
            end_time DATETIME,
            duration_seconds REAL,
            operator_id TEXT,
            status TEXT DEFAULT 'open'     -- 'open' or 'closed'
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cycles_station ON station_cycles(station_code)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cycles_key ON station_cycles(cycle_key)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cycles_start ON station_cycles(start_time)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cycles_status ON station_cycles(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cycles_station_status ON station_cycles(station_code, status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cycles_job ON station_cycles(job_name)')
    
    # Add new columns for sheet processing tracking (migration)
    _ensure_table_columns(cursor, 'station_cycles', {
        'auto_closed': 'INTEGER DEFAULT 0',
        'auto_closed_at_station': 'TEXT',
        'material': 'TEXT',
        'run_name': 'TEXT',
        'station_display_name': 'TEXT',
        # Assembly cycle metadata (safe to add even if not used elsewhere)
        'cabinet_name': 'TEXT',
        'part_name': 'TEXT',
        'opening_letter': 'TEXT',
        'assembly_unit': 'TEXT'
    })

    # Indexes that depend on migrated columns
    try:
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cycles_material ON station_cycles(material)')
    except Exception as e:
        logging.warning(f"Could not create idx_cycles_material yet: {e}")

    # Indexes for station_display_name (safe if column exists after migration)
    try:
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_station_display ON scans(station_display_name)')
    except Exception as e:
        logging.warning(f"Could not create idx_scans_station_display yet: {e}")

    try:
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_material_thickness ON scans(material_thickness)')
    except Exception as e:
        logging.warning(f"Could not create idx_scans_material_thickness yet: {e}")
    try:
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cycles_station_display ON station_cycles(station_display_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cycles_station_display_status ON station_cycles(station_display_name, status)')
    except Exception as e:
        logging.warning(f"Could not create cycles station_display indexes yet: {e}")
    
    # ============================================
    # MAINTENANCE TRACKING
    # ============================================
    
    # Maintenance log
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS maintenance_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            machine TEXT NOT NULL,
            event_type TEXT NOT NULL,  -- 'maintenance', 'repair', 'inspection'
            tool TEXT,
            operator_id TEXT,
            reason TEXT,
            description TEXT,
            notes TEXT,
            time_start DATETIME,
            time_end DATETIME,
            duration_minutes REAL,
            parts_since_last INTEGER,
            photo_path TEXT,
            assigned_to TEXT,
            resolved_at DATETIME,
            resolved BOOLEAN DEFAULT 0
        )
    ''')
    _ensure_table_columns(cursor, 'maintenance_log', {
        'description': 'TEXT',
        'photo_path': 'TEXT',
        'assigned_to': 'TEXT',
        'resolved_at': 'DATETIME',
    })
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_maintenance_machine ON maintenance_log(machine)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_maintenance_date ON maintenance_log(timestamp)')
    
    # ============================================
    # TOOL TRACKING
    # ============================================
    
    # Tool inventory
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tools (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_name TEXT NOT NULL,
            tool_code TEXT,
            tool_type TEXT,  -- 'router_bit', 'saw_blade', 'drill_bit'
            machine TEXT,
            compatible_machines TEXT,     -- comma-separated list, e.g. "H08,H10"
            unit_type TEXT DEFAULT 'parts',  -- 'parts' or 'sheets'
            count_material_contains TEXT, -- optional comma-separated substrings, e.g. "ply,birch"
            count_part_name_contains TEXT,-- optional comma-separated substrings, e.g. "door"
            count_requires_opening INTEGER DEFAULT 0, -- 1 = only count scans with opening_letter present
            installed_at DATETIME,
            parts_processed INTEGER DEFAULT 0,
            sheets_processed INTEGER DEFAULT 0,
            expected_life INTEGER,  -- expected parts/sheets before change
            status TEXT DEFAULT 'active',  -- 'active', 'worn', 'replaced'
            notes TEXT
        )
    ''')

    _ensure_table_columns(cursor, 'tools', {
        'tool_code': 'TEXT',
        'compatible_machines': 'TEXT',
        "unit_type": "TEXT DEFAULT 'parts'",
        'count_material_contains': 'TEXT',
        'count_part_name_contains': 'TEXT',
        'count_requires_opening': 'INTEGER DEFAULT 0',
    })
    
    # Tool change history
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tool_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            machine TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            old_tool_id INTEGER,
            new_tool_id INTEGER,
            operator_id TEXT,
            reason TEXT,  -- 'worn', 'broken', 'upgrade', 'scheduled'
            notes TEXT,
            parts_on_old_tool INTEGER,
            sheets_on_old_tool INTEGER,
            time_start DATETIME,
            time_end DATETIME,
            duration_minutes REAL
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_tool_changes_machine ON tool_changes(machine)')

    # ============================================
    # TOOLING LAYOUT + ON-HAND INVENTORY
    # ============================================

    # Catalog of tools (code -> name/metadata)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tool_catalog (
            tool_code TEXT PRIMARY KEY,   -- e.g. 3750
            tool_name TEXT NOT NULL,      -- e.g. "3/8 Compression"
            tool_type TEXT,               -- e.g. "router_bit", "drill_bit"
            category TEXT,                -- optional subgroup
            notes TEXT
        )
    ''')

    _ensure_table_columns(cursor, 'tool_catalog', {
        'tool_type': 'TEXT',
    })

    # On-hand inventory for each tool_code
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tool_stock (
            tool_code TEXT PRIMARY KEY,
            qty_on_hand INTEGER DEFAULT 0,
            reorder_point INTEGER DEFAULT 0,
            supplier TEXT,
            supplier_sku TEXT,
            order_url TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (tool_code) REFERENCES tool_catalog(tool_code)
        )
    ''')

    # Machine tooling layout (slot -> tool_code)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tool_slots (
            machine TEXT NOT NULL,        -- e.g. H08, H10
            slot_code TEXT NOT NULL,      -- e.g. "301", "1", "600-608", "RackA-1"
            tool_code TEXT,
            slot_group TEXT,              -- e.g. "Back Rack", "Left Rack", "Tool Changer"
            group_order INTEGER DEFAULT 0,
            slot_label TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (machine, slot_code),
            FOREIGN KEY (tool_code) REFERENCES tool_catalog(tool_code)
        )
    ''')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_tool_slots_machine ON tool_slots(machine)')

    # Ensure schema migrations for tool_slots table (older DB files won't have new columns)
    _ensure_table_columns(cursor, 'tool_slots', {
        'slot_group': 'TEXT',
        'group_order': 'INTEGER',
    })

    # Seed default slots for H08 and H10 (safe/ignore if already present)
    default_h08_slots = [str(i) for i in range(1, 9)] + [str(i) for i in range(301, 312)]
    for slot in default_h08_slots:
        cursor.execute('''
            INSERT OR IGNORE INTO tool_slots (machine, slot_code, slot_group, group_order, slot_label)
            VALUES ('H08', ?, ?, ?, ?)
        ''', (
            slot,
            'Drill Block (1-8)' if slot.isdigit() and (1 <= int(slot) <= 8) else 'Rack',
            10 if slot.isdigit() and (1 <= int(slot) <= 8) else 20,
            f'H08 Slot {slot}'
        ))

    # H10: positions 1-12 plus racks 300-310 and 600-608 (per your screenshot)
    default_h10_slots = [str(i) for i in range(1, 13)] + [str(i) for i in range(300, 311)] + [str(i) for i in range(600, 609)] + ['161', '71']
    for slot in default_h10_slots:
        group = 'Other'
        order = 99
        if slot.isdigit():
            n = int(slot)
            if 1 <= n <= 12:
                group, order = 'Drill Block (1-12)', 10
            elif 600 <= n <= 608:
                group, order = 'Left Rack (600-608)', 20
            elif 300 <= n <= 310:
                group, order = 'Back Rack (300-310)', 30
        cursor.execute('''
            INSERT OR IGNORE INTO tool_slots (machine, slot_code, slot_group, group_order, slot_label)
            VALUES ('H10', ?, ?, ?, ?)
        ''', (slot, group, order, f'H10 Slot {slot}'))

    # Backfill default groups for existing rows that don't have slot_group yet
    cursor.execute('''
        UPDATE tool_slots
        SET slot_group = CASE
            WHEN machine = 'H08' AND CAST(slot_code AS INTEGER) BETWEEN 1 AND 8 THEN 'Drill Block (1-8)'
            WHEN machine = 'H08' AND CAST(slot_code AS INTEGER) BETWEEN 301 AND 311 THEN 'Rack'
            WHEN machine = 'H10' AND CAST(slot_code AS INTEGER) BETWEEN 1 AND 12 THEN 'Drill Block (1-12)'
            WHEN machine = 'H10' AND CAST(slot_code AS INTEGER) BETWEEN 600 AND 608 THEN 'Left Rack (600-608)'
            WHEN machine = 'H10' AND CAST(slot_code AS INTEGER) BETWEEN 300 AND 310 THEN 'Back Rack (300-310)'
            ELSE COALESCE(slot_group, 'Other')
        END,
        group_order = CASE
            WHEN machine = 'H08' AND CAST(slot_code AS INTEGER) BETWEEN 1 AND 8 THEN 10
            WHEN machine = 'H08' AND CAST(slot_code AS INTEGER) BETWEEN 301 AND 311 THEN 20
            WHEN machine = 'H10' AND CAST(slot_code AS INTEGER) BETWEEN 1 AND 12 THEN 10
            WHEN machine = 'H10' AND CAST(slot_code AS INTEGER) BETWEEN 600 AND 608 THEN 20
            WHEN machine = 'H10' AND CAST(slot_code AS INTEGER) BETWEEN 300 AND 310 THEN 30
            ELSE COALESCE(group_order, 99)
        END
        WHERE slot_group IS NULL OR TRIM(slot_group) = ''
    ''')

    # Fix legacy "Tool Changer" labels in existing DBs
    cursor.execute('''
        UPDATE tool_slots
        SET slot_group = 'Drill Block (1-8)'
        WHERE machine = 'H08' AND CAST(slot_code AS INTEGER) BETWEEN 1 AND 8 AND slot_group LIKE 'Tool Changer%'
    ''')
    cursor.execute('''
        UPDATE tool_slots
        SET slot_group = 'Drill Block (1-12)'
        WHERE machine = 'H10' AND CAST(slot_code AS INTEGER) BETWEEN 1 AND 12 AND slot_group LIKE 'Tool Changer%'
    ''')

    # Seed H08 catalog example from your tool list (ignore if already present)
    h08_catalog_seed = [
        ('5444', '300-04-0444M Planfräser', 'router_bit', 'H08', ''),
        ('8400', '40MM PCD Frost', 'router_bit', 'H08', ''),
        ('4370', '7/16" DS Frost', 'router_bit', 'H08', ''),
        ('3750', '3/8" Compression Frost', 'router_bit', 'H08', ''),
        ('3751', '3/8" Chipbreaker', 'router_bit', 'H08', ''),
        ('2500', '1/4" Frost', 'router_bit', 'H08', ''),
        ('2001', '.2" DS', 'router_bit', 'H08', ''),
        ('1250', '1/8" Up Long Frost', 'router_bit', 'H08', ''),
        ('1251', '1/8" DS short', 'router_bit', 'H08', ''),
        ('1108', '60V Amana', 'router_bit', 'H08', ''),
        ('1028', '91 V Frost PCD', 'router_bit', 'H08', ''),
    ]
    for tool_code, tool_name, tool_type, category, notes in h08_catalog_seed:
        cursor.execute('''
            INSERT OR IGNORE INTO tool_catalog (tool_code, tool_name, tool_type, category, notes)
            VALUES (?, ?, ?, ?, ?)
        ''', (tool_code, tool_name, tool_type, category, notes))
        cursor.execute('INSERT OR IGNORE INTO tool_stock (tool_code, qty_on_hand) VALUES (?, 0)', (tool_code,))

    # Sync tooling dropdown catalog from Tool Inventory (so dropdown matches what you added on the Pi)
    try:
        _sync_tooling_catalog_from_tools(cursor)
    except Exception as e:
        logging.warning(f"Tooling catalog sync from tools failed: {e}")
    
    # ============================================
    # RECUT TRACKING
    # ============================================
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS recuts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            machine TEXT,
            request_type TEXT DEFAULT 'recut',
            fix_station TEXT,
            job_name TEXT,
            cabinet_name TEXT,
            part_name TEXT,
            gcode TEXT,
            operator_id TEXT,
            caused_by TEXT,
            reason TEXT,  -- 'defect', 'damage', 'wrong_material', 'machine_error'
            notes TEXT,
            photo_path TEXT,
            recut_completed BOOLEAN DEFAULT 0,
            completed_at DATETIME,
            completed_by TEXT
        )
    ''')
    _ensure_table_columns(cursor, 'recuts', {
        'request_type': "TEXT DEFAULT 'recut'",
        'fix_station': 'TEXT',
        'caused_by': 'TEXT',
        'photo_path': 'TEXT',
        'recut_completed': 'BOOLEAN DEFAULT 0',
        'completed_at': 'DATETIME',
        'completed_by': 'TEXT',
    })
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_recuts_job ON recuts(job_name)')
    try:
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_recuts_fix_station ON recuts(fix_station)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_recuts_request_type ON recuts(request_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_recuts_caused_by ON recuts(caused_by)')
    except Exception as e:
        logging.warning(f"Could not create recuts indexes yet: {e}")
    
    # ============================================
    # INVENTORY - RAW MATERIALS
    # ============================================
    
    # Material types
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS material_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            material_group TEXT DEFAULT 'other',  -- 'sheet_goods','hardware','edge_banding','consumables','fasteners','other'
            category TEXT,  -- 'plywood', 'melamine', 'mdf', 'hardwood'
            thickness TEXT,
            unit TEXT DEFAULT 'sheet',
            cost_per_unit REAL,
            supplier TEXT,
            supplier_sku TEXT,
            order_url TEXT,
            reorder_point INTEGER DEFAULT 10,
            notes TEXT
        )
    ''')

    _ensure_table_columns(cursor, 'material_types', {
        'material_group': "TEXT DEFAULT 'other'",
        'supplier_sku': 'TEXT',
        'order_url': 'TEXT',
    })

    try:
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_material_types_group ON material_types(material_group)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_material_types_category ON material_types(category)')
    except Exception as e:
        logging.warning(f"Could not create material_types group/category indexes yet: {e}")
    
    # Material inventory
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS material_inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            material_type_id INTEGER,
            quantity INTEGER DEFAULT 0,
            location TEXT,
            last_received DATETIME,
            last_consumed DATETIME,
            FOREIGN KEY (material_type_id) REFERENCES material_types(id)
        )
    ''')
    
    # Material transactions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS material_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            material_type_id INTEGER,
            transaction_type TEXT,  -- 'receive', 'consume', 'adjust', 'waste'
            quantity INTEGER,
            job_name TEXT,
            operator_id TEXT,
            notes TEXT,
            FOREIGN KEY (material_type_id) REFERENCES material_types(id)
        )
    ''')
    
    # ============================================
    # PROJECT/CABINET TRACKING
    # ============================================
    
    # Projects (jobs)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_name TEXT NOT NULL UNIQUE,
            customer_name TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            due_date DATE,
            status TEXT DEFAULT 'active',  -- 'active', 'complete', 'shipped', 'hold'
            total_cabinets INTEGER DEFAULT 0,
            cabinets_complete INTEGER DEFAULT 0,
            notes TEXT
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_projects_status ON projects(status)')
    
    # Cabinets
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cabinets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER,
            job_name TEXT,
            cabinet_assembly TEXT NOT NULL,  -- e.g., 'R1C5'
            cabinet_name TEXT,  -- e.g., 'Base Cabinet 2 Doors'
            total_parts INTEGER DEFAULT 0,
            parts_cut INTEGER DEFAULT 0,
            parts_in_bins INTEGER DEFAULT 0,
            parts_assembled INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending',  -- 'pending', 'cutting', 'sorting', 'ready', 'assembled', 'complete'
            ready_for_assembly BOOLEAN DEFAULT 0,
            assembled_at DATETIME,
            FOREIGN KEY (project_id) REFERENCES projects(id)
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cabinets_job ON cabinets(job_name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cabinets_status ON cabinets(status)')
    
    # Cabinet recipes (expected parts)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cabinet_recipes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cabinet_assembly TEXT NOT NULL,
            cabinet_name TEXT,
            part_name TEXT NOT NULL,
            quantity INTEGER DEFAULT 1,
            material_type TEXT,
            UNIQUE(cabinet_assembly, part_name)
        )
    ''')
    
    # ============================================
    # MOZAIK INTEGRATION
    # ============================================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mozaik_imports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            imported_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_filename TEXT,
            source_path TEXT,
            file_hash TEXT UNIQUE,
            job_name TEXT,
            run_name TEXT,
            run_number INTEGER,
            created_at DATETIME,
            created_by TEXT,
            target_cpu_display_name TEXT,
            sheets_count INTEGER DEFAULT 0,
            parts_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'imported',
            error TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mozaik_expected_parts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            import_id INTEGER NOT NULL,
            job_name TEXT,
            run_name TEXT,
            run_number INTEGER,
            material_name TEXT,
            material_abbr TEXT,
            material_thickness TEXT,
            sheet_id INTEGER,
            pattern_num TEXT,
            gcode_filename TEXT,
            gcode_guess TEXT,
            sheet_w_mm REAL,
            sheet_l_mm REAL,
            part_xml_id TEXT,
            part_no TEXT,
            part_name TEXT,
            part_shorthand_name TEXT,
            part_comment TEXT,
            part_edge_band TEXT,
            part_band_temp_symbol TEXT,
            part_color TEXT,
            part_dxf_filename TEXT,
            part_is_remnant INTEGER,
            part_x_mm REAL,
            part_y_mm REAL,
            part_rot INTEGER,
            part_w_mm REAL,
            part_l_mm REAL,
            cabinet_assembly TEXT,
            cabinet_name TEXT,
            room_name TEXT,
            opening_letter TEXT,
            geometry_json TEXT,
            UNIQUE(import_id, sheet_id, material_name, part_xml_id),
            FOREIGN KEY (import_id) REFERENCES mozaik_imports(id)
        )
    ''')

    _ensure_table_columns(cursor, 'mozaik_expected_parts', {
        'sheet_w_mm': 'REAL',
        'sheet_l_mm': 'REAL',
        'part_w_mm': 'REAL',
        'part_l_mm': 'REAL',
        'part_edge_band': 'TEXT',
        'part_band_temp_symbol': 'TEXT',
        'part_color': 'TEXT',
        'part_dxf_filename': 'TEXT',
        'part_is_remnant': 'INTEGER',
        'part_x_mm': 'REAL',
        'part_y_mm': 'REAL',
        'part_rot': 'INTEGER',
        'geometry_json': 'TEXT',
    })

    # ============================================
    # OPERATORS
    # ============================================
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS operators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            operator_id TEXT NOT NULL UNIQUE,
            name TEXT,
            role TEXT,  -- 'operator', 'lead', 'supervisor', 'admin'
            active BOOLEAN DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            pin_hash TEXT
        )
    ''')
    
    # Operator sessions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS operator_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            operator_id TEXT,
            station_code TEXT,
            login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            logout_time DATETIME,
            duration_minutes REAL,
            scans_count INTEGER DEFAULT 0
        )
    ''')
    
    # ============================================
    # WEBHOOKS / NOTIFICATIONS
    # ============================================
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            webhook_type TEXT,  -- 'teams', 'slack', 'email', 'custom'
            events TEXT,  -- comma-separated: 'maintenance,recut,tool_change,low_stock'
            active BOOLEAN DEFAULT 1,
            auth_header TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Notification log
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notification_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            webhook_id INTEGER,
            event_type TEXT,
            payload TEXT,
            response_code INTEGER,
            success BOOLEAN,
            error_message TEXT,
            FOREIGN KEY (webhook_id) REFERENCES webhooks(id)
        )
    ''')
    
    # ============================================
    # SYSTEM SETTINGS
    # ============================================
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert default settings
    default_settings = [
        ('station_code', 'H08'),
        ('station_name', 'CNC Station'),
        ('total_bins', '40'),
        ('block_timeout_minutes', '30'),
        ('duplicate_scan_seconds', '3'),
        ('google_sheets_enabled', 'false'),
        ('webhook_enabled', 'true'),
    ]
    for key, value in default_settings:
        cursor.execute('''
            INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)
        ''', (key, value))
    
    # Backfill derived numeric fields (safe / best-effort)
    _backfill_room_cabinet_numbers(cursor)
    _backfill_scan_material_thickness(cursor)

    conn.commit()
    conn.close()
    logging.info("Database initialized successfully")


# ============================================
# HELPER FUNCTIONS
# ============================================

def _ensure_table_columns(cursor, table_name: str, columns: Dict[str, str]) -> None:
    """Add missing columns to an existing SQLite table (lightweight migration)."""
    cursor.execute(f'PRAGMA table_info({table_name})')
    existing = {row['name'] for row in cursor.fetchall()}
    for col, col_type in columns.items():
        if col in existing:
            continue
        try:
            cursor.execute(f'ALTER TABLE {table_name} ADD COLUMN {col} {col_type}')
            logging.info(f"✅ Migrated {table_name}: added column {col} {col_type}")
        except Exception as e:
            logging.warning(f"Could not add column {col} to {table_name}: {e}")


def _backfill_room_cabinet_numbers(cursor) -> None:
    """Backfill derived cabinet fields for existing scans where possible."""
    try:
        # Only run if columns exist
        cursor.execute('PRAGMA table_info(scans)')
        cols = {row['name'] for row in cursor.fetchall()}
        if 'cabinet_assembly' not in cols:
            return

        cursor.execute('''
            SELECT id, cabinet_assembly
            FROM scans
            WHERE cabinet_assembly IS NOT NULL
              AND cabinet_assembly != ''
              AND (
                room_num IS NULL OR cabinet_num IS NULL
                OR room_code IS NULL OR cabinet_code IS NULL OR cab_type IS NULL
                OR (cabinet_assembly LIKE '%N%' AND cab_type != 'non_cabinet')
              )
            LIMIT 5000
        ''')
        rows = cursor.fetchall()
        for r in rows:
            cab_assembly = r['cabinet_assembly']
            room_num, cabinet_num, room_code, cabinet_code, cab_type = _parse_cabinet_assembly(str(cab_assembly))
            cursor.execute(
                'UPDATE scans SET room_num = ?, cabinet_num = ?, room_code = ?, cabinet_code = ?, cab_type = ? WHERE id = ?',
                (room_num, cabinet_num, room_code, cabinet_code, cab_type, r['id'])
            )
    except Exception as e:
        logging.warning(f"Room/Cabinet backfill skipped: {e}")


def _backfill_scan_material_thickness(cursor) -> None:
    """Backfill scans.material_thickness from Mozaik expected parts when unambiguous."""
    try:
        cursor.execute('PRAGMA table_info(scans)')
        scan_cols = {row['name'] for row in cursor.fetchall()}
        if 'material_thickness' not in scan_cols:
            return

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='mozaik_expected_parts'")
        if not cursor.fetchone():
            return

        # Consider only pairs where scans are missing thickness.
        cursor.execute('''
            SELECT job_name, gcode
            FROM scans
            WHERE (material_thickness IS NULL OR TRIM(material_thickness) = '')
              AND job_name IS NOT NULL AND TRIM(job_name) <> ''
              AND gcode IS NOT NULL AND TRIM(gcode) <> ''
            GROUP BY job_name, gcode
            LIMIT 5000
        ''')
        pairs = cursor.fetchall()
        for r in pairs:
            job_name = (r['job_name'] or '').strip()
            gcode = (r['gcode'] or '').strip()
            if not job_name or not gcode:
                continue

            cursor.execute('''
                SELECT DISTINCT TRIM(material_thickness) AS t
                FROM mozaik_expected_parts
                WHERE job_name = ?
                  AND (
                    COALESCE(gcode_filename,'') = ?
                    OR COALESCE(gcode_guess,'') = ?
                  )
                  AND material_thickness IS NOT NULL
                  AND TRIM(material_thickness) <> ''
                LIMIT 5
            ''', (job_name, gcode, gcode))
            ts = [row['t'] for row in cursor.fetchall() if (row['t'] or '').strip()]
            ts = sorted(set(ts))
            if len(ts) != 1:
                continue
            thickness = ts[0]

            cursor.execute('''
                UPDATE scans
                SET material_thickness = ?
                WHERE job_name = ?
                  AND gcode = ?
                  AND (material_thickness IS NULL OR TRIM(material_thickness) = '')
            ''', (thickness, job_name, gcode))
    except Exception as e:
        logging.warning(f"Material thickness backfill skipped: {e}")


def _lookup_mozaik_material_thickness(cursor, job_name: str, gcode: str) -> Optional[str]:
    """Return Mozaik thickness for a job+gcode if exactly one thickness exists."""
    try:
        if not (job_name or '').strip() or not (gcode or '').strip():
            return None

        cursor.execute('PRAGMA table_info(scans)')
        scan_cols = {row['name'] for row in cursor.fetchall()}
        if 'material_thickness' not in scan_cols:
            return None

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='mozaik_expected_parts'")
        if not cursor.fetchone():
            return None

        cursor.execute('''
            SELECT DISTINCT TRIM(material_thickness) AS t
            FROM mozaik_expected_parts
            WHERE job_name = ?
              AND (
                COALESCE(gcode_filename,'') = ?
                OR COALESCE(gcode_guess,'') = ?
              )
              AND material_thickness IS NOT NULL
              AND TRIM(material_thickness) <> ''
            LIMIT 5
        ''', ((job_name or '').strip(), (gcode or '').strip(), (gcode or '').strip()))
        ts = [row['t'] for row in cursor.fetchall() if (row['t'] or '').strip()]
        ts = sorted(set(ts))
        if len(ts) == 1:
            return ts[0]
        return None
    except Exception:
        return None


def _parse_cabinet_assembly(cab_assembly: str) -> Tuple[Optional[int], Optional[int], Optional[str], Optional[str], Optional[str]]:
    """
    Parse cabinet assembly identifiers.

    Patterns:
    - R1C14 -> room_num=1, cabinet_num=14, room_code=R1, cabinet_code=C14, cab_type=cabinet
    - 121 (Mozaik single-room) -> room_num=1, cabinet_num=121, room_code=R1, cabinet_code=C121, cab_type=cabinet
    - R0... -> room_num=0, cab_type=order_entry (order entry / special)
    - N1 -> cab_type=non_cabinet, cabinet_code=N1
    - R0N1 -> room_num=0, cabinet_code=N1, cab_type=order_entry
    """
    s = (cab_assembly or '').strip()
    if not s:
        return None, None, None, None, None

    m = re.search(r'R\s*(\d+)\s*C\s*(\d+)', s, flags=re.IGNORECASE)
    if m:
        rn = int(m.group(1))
        cn = int(m.group(2))
        return rn, cn, f'R{rn}', f'C{cn}', 'cabinet'

    # Room 0 (order entry). If it includes N#, treat it as a non-cab item that happens in room 0.
    if re.match(r'^R\s*0', s, flags=re.IGNORECASE):
        rn = 0
        m2 = re.search(r'N\s*(\d+)', s, flags=re.IGNORECASE)
        if m2:
            n = int(m2.group(1))
            ncode = f"N{n}"
            return rn, n, 'R0', ncode, 'non_cabinet'
        return rn, None, 'R0', None, 'order_entry'

    # Non-cabinet items (allow suffix like N10(2/2))
    m3 = re.match(r'^N\s*(\d+)', s, flags=re.IGNORECASE)
    if m3:
        n = int(m3.group(1))
        ncode = f"N{n}"
        return None, n, None, ncode, 'non_cabinet'

    # Mozaik single-room numeric cabinet id => assume Room 1
    m4 = re.match(r'^(\d+)', s)
    if m4:
        cn = int(m4.group(1))
        return 1, cn, 'R1', f'C{cn}', 'cabinet'

    return None, None, None, s, 'unknown'


def ensure_schema() -> None:
    """Ensure DB schema/migrations are applied (safe to call repeatedly)."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        init_database()
        # init_database() already commits/closes; reopen for backfill
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        # init_database() already logs details

def get_setting(key: str, default: str = None) -> str:
    """Get a setting value"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
    row = cursor.fetchone()
    conn.close()
    return row['value'] if row else default


def set_setting(key: str, value: str):
    """Set a setting value"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO settings (key, value, updated_at) 
        VALUES (?, ?, CURRENT_TIMESTAMP)
    ''', (key, value))
    conn.commit()
    conn.close()


def log_scan(station_code: str, raw_data: str, parsed_fields: dict, operator_id: str = None, station_display_name: str = None) -> int:
    """Log a scan to the database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    scan_dt = datetime.now()
    scan_ts = scan_dt.strftime('%Y-%m-%d %H:%M:%S')

    cab_assembly = parsed_fields.get('cabinet_assembly') or ''
    room_num, cabinet_num, room_code, cabinet_code, cab_type = _parse_cabinet_assembly(str(cab_assembly))

    material_thickness = (parsed_fields.get('material_thickness') or '').strip() or None
    if not material_thickness:
        material_thickness = _lookup_mozaik_material_thickness(
            cursor=cursor,
            job_name=(parsed_fields.get('job_name') or ''),
            gcode=(parsed_fields.get('gcode') or ''),
        )

    cursor.execute('''
        INSERT INTO scans (
            timestamp, station_code, station_display_name, raw_data, gcode, material, material_thickness, job_name,
            part_num, run_name, opening_letter, cabinet_name, cabinet_assembly,
            room_num, cabinet_num, room_code, cabinet_code, cab_type,
            part_name, operator_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        scan_ts,
        station_code,
        (station_display_name or '').strip() or None,
        raw_data,
        parsed_fields.get('gcode'),
        parsed_fields.get('material'),
        material_thickness,
        parsed_fields.get('job_name'),
        parsed_fields.get('part_num'),
        parsed_fields.get('run_name'),
        parsed_fields.get('opening_letter'),
        parsed_fields.get('cabinet_name'),
        cab_assembly,
        room_num,
        cabinet_num,
        room_code,
        cabinet_code,
        cab_type,
        parsed_fields.get('part_name'),
        operator_id
    ))
    scan_id = cursor.lastrowid

    # Update block/session tracking (H08/H10/Edge/Dowel by default)
    try:
        block_id = _update_station_block_from_scan(
            cursor=cursor,
            station_code=station_code,
            scan_dt=scan_dt,
            gcode=parsed_fields.get('gcode'),
            job_name=parsed_fields.get('job_name')
        )
        if block_id:
            cursor.execute('UPDATE scans SET block_id = ? WHERE id = ?', (block_id, scan_id))
    except Exception as e:
        logging.warning(f"Failed to update station block: {e}")

    # Update cycle timing (H08/H10 + Assembly)
    try:
        _update_station_cycle_from_scan(
            cursor=cursor,
            station_code=station_code,
            scan_dt=scan_dt,
            parsed_fields=parsed_fields,
            operator_id=operator_id,
            station_display_name=station_display_name
        )
    except Exception as e:
        logging.warning(f"Failed to update station cycle timing: {e}")
    
    # Handle Assembly station - check if part is in bin and clear/hold bin
    if station_code == 'Assembly':
        try:
            from bin_management import BinManager
            bin_manager = BinManager()
            
            part_number = parsed_fields.get('part_number') or parsed_fields.get('gcode') or parsed_fields.get('part_num') or ''
            cabinet_name = parsed_fields.get('cabinet_name') or ''
            job_name = parsed_fields.get('job_name') or ''
            
            if part_number:
                # Check if part is in a bin - put on hold (yellow) instead of clearing
                # This allows tracking while still showing the bin needs attention
                success, message, bin_num = bin_manager.handle_assembly_scan(
                    part_number=part_number,
                    cabinet_name=cabinet_name,
                    job_name=job_name,
                    operator_id=operator_id or 'Assembly',
                    clear_bin=False  # Put on hold instead of clearing
                )
                if success and bin_num:
                    logging.info(f"Assembly scan: {message}")
        except ImportError:
            logging.warning("BinManager not available - skipping Assembly bin handling")
        except Exception as e:
            logging.warning(f"Failed to handle Assembly bin logic: {e}")
    
    # Auto-consume materials for H08/H10 stations (count 1 sheet per sheet-group, not per part scan)
    if station_code in ['H08', 'H10']:
        material_name = parsed_fields.get('material')
        gcode = parsed_fields.get('gcode') or ''
        job_name = parsed_fields.get('job_name') or ''
        run_name = parsed_fields.get('run_name') or ''
        if material_name and gcode:
            try:
                # Only consume on the FIRST scan within a sheet group:
                # (block_id + gcode/job/run/material). This matches legacy Sheets behavior
                # where multiple parts from the same nested sheet count as one sheet.
                if block_id:
                    cursor.execute('''
                        SELECT COUNT(1) as c
                        FROM scans
                        WHERE station_code = ?
                          AND block_id = ?
                          AND COALESCE(gcode, '') = ?
                          AND COALESCE(job_name, '') = ?
                          AND COALESCE(run_name, '') = ?
                          AND COALESCE(material, '') = ?
                          AND id < ?
                    ''', (station_code, block_id, gcode, job_name, run_name, material_name, scan_id))
                    prior = int(cursor.fetchone()['c'] or 0)
                    if prior == 0:
                        consume_material_from_scan(
                            cursor,
                            material_name,
                            quantity=1,
                            job_name=job_name,
                            operator_id=operator_id,
                            scan_id=scan_id
                        )
            except Exception as e:
                logging.warning(f"Auto-consume sheet-group check failed: {e}")
    
    conn.commit()
    conn.close()
    return scan_id


def _update_station_block_from_scan(cursor, station_code: str, scan_dt: datetime, gcode: str = None, job_name: str = None) -> Optional[str]:
    """Update/append station work blocks (session grouping) similar to googlecode.js logBlockData()."""
    if station_code not in ['H08', 'H10', 'Edge', 'Dowel', 'Band', 'Banding']:
        return None

    date_str = scan_dt.strftime('%Y-%m-%d')
    time_str = scan_dt.strftime('%Y-%m-%d %H:%M:%S')

    timeout_min = 30
    try:
        timeout_min = int(get_setting('block_timeout_minutes', '30') or 30)
    except Exception:
        timeout_min = 30

    unit_type = 'Sheets' if station_code in ['H08', 'H10'] else 'Parts'

    cursor.execute('''
        SELECT id, block_id, start_time, end_time, scan_count
        FROM blocks
        WHERE date = ? AND station_code = ?
        ORDER BY id DESC
        LIMIT 1
    ''', (date_str, station_code))
    last = cursor.fetchone()

    def _minutes_diff(end_time_str: str) -> float:
        try:
            end_dt = datetime.strptime(end_time_str, '%Y-%m-%d %H:%M:%S')
            return (scan_dt - end_dt).total_seconds() / 60.0
        except Exception:
            return 999999.0

    if last and last['end_time'] and _minutes_diff(last['end_time']) <= timeout_min:
        # Update existing block
        start_time_str = last['start_time'] or time_str
        try:
            start_dt = datetime.strptime(start_time_str, '%Y-%m-%d %H:%M:%S')
            duration_min = (scan_dt - start_dt).total_seconds() / 60.0
        except Exception:
            duration_min = 0.0

        cursor.execute('''
            UPDATE blocks
            SET end_time = ?, duration_minutes = ?, scan_count = scan_count + 1
            WHERE id = ?
        ''', (time_str, round(duration_min, 1), last['id']))
        return last['block_id']

    # Create new block
    next_num = 1
    if last and last['block_id']:
        try:
            next_num = int(str(last['block_id']).replace('B', '').strip()) + 1
        except Exception:
            next_num = 1
    block_id = f'B{next_num}'

    cursor.execute('''
        INSERT INTO blocks (date, station_code, block_id, start_time, end_time, duration_minutes, scan_count, first_gcode, first_job, unit_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        date_str, station_code, block_id,
        time_str, time_str, 0.0, 1,
        gcode, job_name, unit_type
    ))
    return block_id


def _update_station_cycle_from_scan(cursor, station_code: str, scan_dt: datetime, parsed_fields: dict, operator_id: str = None, station_display_name: str = None) -> None:
    """Track start/end cycles for stations where scan pairs represent duration."""
    # Defensive migration: make sure new cycle columns exist even if the service
    # didn't restart cleanly after a git pull.
    try:
        _ensure_table_columns(cursor, 'station_cycles', {
            'auto_closed': 'INTEGER DEFAULT 0',
            'auto_closed_at_station': 'TEXT',
            'material': 'TEXT',
            'run_name': 'TEXT',
            'station_display_name': 'TEXT',
            'cabinet_name': 'TEXT',
            'part_name': 'TEXT',
            'opening_letter': 'TEXT',
            'assembly_unit': 'TEXT',
        })
    except Exception:
        pass

    if station_code in ['H08', 'H10']:
        gcode = parsed_fields.get('gcode') or ''
        job = parsed_fields.get('job_name') or ''
        if not gcode or not job:
            return
        cycle_key = f"{gcode}|{job}"
        if station_display_name:
            cursor.execute('''
                SELECT id, start_time FROM station_cycles
                WHERE station_code = ? AND station_display_name = ? AND cycle_key = ? AND status = 'open'
                ORDER BY id DESC
                LIMIT 1
            ''', (station_code, station_display_name, cycle_key))
        else:
            cursor.execute('''
                SELECT id, start_time FROM station_cycles
                WHERE station_code = ? AND (station_display_name IS NULL OR TRIM(COALESCE(station_display_name,'')) = '')
                  AND cycle_key = ? AND status = 'open'
                ORDER BY id DESC
                LIMIT 1
            ''', (station_code, cycle_key))
        open_row = cursor.fetchone()

        if open_row:
            # Close cycle
            start_dt = datetime.strptime(open_row['start_time'], '%Y-%m-%d %H:%M:%S')
            duration_sec = (scan_dt - start_dt).total_seconds()
            cursor.execute('''
                UPDATE station_cycles
                SET end_time = ?, duration_seconds = ?, status = 'closed', auto_closed = 0
                WHERE id = ?
            ''', (scan_dt.strftime('%Y-%m-%d %H:%M:%S'), duration_sec, open_row['id']))
        else:
            # Open cycle - include material and run_name if available
            material = parsed_fields.get('material') or ''
            run_name = parsed_fields.get('run_name') or ''
            cursor.execute('''
                INSERT INTO station_cycles (
                    station_code, station_display_name,
                    cycle_key, job_name, gcode,
                    start_time, operator_id, status,
                    auto_closed, material, run_name
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'open', 0, ?, ?)
            ''', (
                station_code,
                (station_display_name or '').strip() or None,
                cycle_key,
                job,
                gcode,
                scan_dt.strftime('%Y-%m-%d %H:%M:%S'),
                operator_id,
                material,
                run_name
            ))
        return
    
    # Fallback: Check for open H08/H10 cycles when parts are scanned at Edge/Banding
    # This handles cases where operators forget to scan the sheet a second time
    if station_code in ['Edge', 'Banding', 'Band']:
        gcode = parsed_fields.get('gcode') or ''
        job = parsed_fields.get('job_name') or ''
        run_name = parsed_fields.get('run_name') or ''
        material = parsed_fields.get('material') or ''
        
        if gcode and job:
            # Try to match by gcode + job (primary match)
            cycle_key = f"{gcode}|{job}"
            for cutting_station in ['H08', 'H10']:
                cursor.execute('''
                    SELECT id, start_time, station_code FROM station_cycles
                    WHERE station_code = ? AND cycle_key = ? AND status = 'open'
                    ORDER BY id DESC
                    LIMIT 1
                ''', (cutting_station, cycle_key))
                open_cycle = cursor.fetchone()
                
                if open_cycle:
                    # Found open cycle - close it (fallback timer stop)
                    start_dt = datetime.strptime(open_cycle['start_time'], '%Y-%m-%d %H:%M:%S')
                    duration_sec = (scan_dt - start_dt).total_seconds()
                    cursor.execute('''
                        UPDATE station_cycles
                        SET end_time = ?, duration_seconds = ?, status = 'closed', auto_closed = 1, auto_closed_at_station = ?
                        WHERE id = ?
                    ''', (scan_dt.strftime('%Y-%m-%d %H:%M:%S'), duration_sec, station_code, open_cycle['id']))
                    logging.info(f"Auto-closed {cutting_station} cycle {open_cycle['id']} (gcode={gcode}, job={job}) at {station_code} station")
                    return

    if station_code == 'Assembly':
        cabinet_assembly = (parsed_fields.get('cabinet_assembly') or '').strip()
        cabinet_name = (parsed_fields.get('cabinet_name') or '').strip()
        cabinet_number = (parsed_fields.get('cabinet_number') or '').strip()

        # Prefer the cabinet number (e.g., R2C20) for cycle identity.
        # Fall back to cabinet name if the label doesn't contain R#C#.
        cycle_key = cabinet_assembly or cabinet_name or cabinet_number
        if not cycle_key:
            return

        part_name = (parsed_fields.get('part_name') or '').strip()
        opening_letter = (parsed_fields.get('opening_letter') or '').strip()
        job_name = (parsed_fields.get('job_name') or '').strip()

        # Assembly unit/group classification (DB-backed rules; first-match-wins)
        assembly_unit = classify_assembly_unit(
            part_name=part_name,
            station_code=station_code,
            station_display_name=station_display_name,
            opening_letter=opening_letter,
        )
        
        if station_display_name:
            cursor.execute('''
                SELECT id, start_time FROM station_cycles
                WHERE station_code = ? AND station_display_name = ? AND cycle_key = ? AND status = 'open'
                ORDER BY id DESC
                LIMIT 1
            ''', (station_code, station_display_name, cycle_key))
        else:
            cursor.execute('''
                SELECT id, start_time FROM station_cycles
                WHERE station_code = ? AND (station_display_name IS NULL OR TRIM(COALESCE(station_display_name,'')) = '')
                  AND cycle_key = ? AND status = 'open'
                ORDER BY id DESC
                LIMIT 1
            ''', (station_code, cycle_key))
        open_row = cursor.fetchone()

        if open_row:
            # Close cycle (second scan of same cabinet)
            start_dt = datetime.strptime(open_row['start_time'], '%Y-%m-%d %H:%M:%S')
            duration_sec = (scan_dt - start_dt).total_seconds()
            cursor.execute('''
                UPDATE station_cycles
                SET end_time = ?, duration_seconds = ?, status = 'closed', auto_closed = 0,
                    cabinet_assembly = COALESCE(NULLIF(TRIM(COALESCE(cabinet_assembly,'')), ''), ?),
                    cabinet_name = COALESCE(NULLIF(TRIM(COALESCE(cabinet_name,'')), ''), ?),
                    part_name = ?, opening_letter = ?, assembly_unit = ?
                WHERE id = ?
            ''', (
                scan_dt.strftime('%Y-%m-%d %H:%M:%S'),
                duration_sec,
                cabinet_assembly or None,
                cabinet_name or None,
                part_name or None,
                opening_letter or None,
                assembly_unit,
                open_row['id']
            ))
        else:
            # Open cycle (first scan of cabinet)
            cursor.execute('''
                INSERT INTO station_cycles (
                    station_code, station_display_name,
                    cycle_key, cabinet_assembly, cabinet_name, job_name,
                    part_name, opening_letter, assembly_unit,
                    start_time, operator_id, status, auto_closed
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 0)
            ''', (
                station_code,
                (station_display_name or '').strip() or None,
                cycle_key,
                cabinet_assembly or None,
                cabinet_name or None,
                job_name,
                part_name or None,
                opening_letter or None,
                assembly_unit,
                scan_dt.strftime('%Y-%m-%d %H:%M:%S'),
                operator_id
            ))
        return


def consume_material_from_scan(cursor, material_name: str, quantity: int = 1, 
                              job_name: str = None, operator_id: str = None, scan_id: int = None):
    """Consume material inventory when a scan happens at H08/H10"""
    try:
        # Find or create material type
        cursor.execute('SELECT id FROM material_types WHERE name = ?', (material_name,))
        material_type_row = cursor.fetchone()
        
        if material_type_row:
            material_type_id = material_type_row['id']
        else:
            # Create new material type
            cursor.execute('''
                INSERT INTO material_types (name, category, unit)
                VALUES (?, 'unknown', 'sheet')
            ''', (material_name,))
            material_type_id = cursor.lastrowid
        
        # Update inventory (consume)
        cursor.execute('''
            UPDATE material_inventory 
            SET quantity = quantity - ?, last_consumed = CURRENT_TIMESTAMP
            WHERE material_type_id = ?
        ''', (quantity, material_type_id))
        
        # If no inventory record exists, create one with negative quantity
        if cursor.rowcount == 0:
            cursor.execute('''
                INSERT INTO material_inventory (material_type_id, quantity, last_consumed)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (material_type_id, -quantity))
        
        # Log transaction
        cursor.execute('''
            INSERT INTO material_transactions (
                material_type_id, transaction_type, quantity, job_name, operator_id, notes
            ) VALUES (?, 'consume', ?, ?, ?, ?)
        ''', (material_type_id, quantity, job_name, operator_id, f'Auto-consumed from scan #{scan_id}'))
        
        logging.info(f"Material consumed: {material_name} ({quantity} sheet(s))")
        
    except Exception as e:
        logging.error(f"Failed to consume material '{material_name}': {e}")
        # Don't raise - allow scan to continue even if material tracking fails


def log_recut(machine: str, parsed_fields: dict, operator_id: str = None, reason: str = None, notes: str = None):
    """Create a recut record from a part scan."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO recuts (
                machine, job_name, cabinet_name, part_name, gcode,
                operator_id, reason, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            machine,
            parsed_fields.get('job_name'),
            parsed_fields.get('cabinet_name'),
            parsed_fields.get('part_name'),
            parsed_fields.get('gcode'),
            operator_id,
            reason or 'defect',
            notes
        ))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        try:
            conn.close()
        except Exception:
            pass
        logging.warning(f"Failed to log recut: {e}")
        return False


def get_station_metrics(station_code: str, date: str = None) -> dict:
    """Get metrics for a station"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if date is None:
        date = datetime.now().strftime('%Y-%m-%d')
    
    # Today's scan count
    cursor.execute('''
        SELECT COUNT(*) as count FROM scans 
        WHERE station_code = ? AND DATE(timestamp) = ?
    ''', (station_code, date))
    today_count = cursor.fetchone()['count']
    
    # This week's scan count
    cursor.execute('''
        SELECT COUNT(*) as count FROM scans 
        WHERE station_code = ? AND timestamp >= DATE('now', '-7 days')
    ''', (station_code,))
    week_count = cursor.fetchone()['count']
    
    # Unique jobs today
    cursor.execute('''
        SELECT COUNT(DISTINCT job_name) as count FROM scans 
        WHERE station_code = ? AND DATE(timestamp) = ?
    ''', (station_code, date))
    jobs_today = cursor.fetchone()['count']
    
    conn.close()
    
    return {
        'station_code': station_code,
        'date': date,
        'scans_today': today_count,
        'scans_this_week': week_count,
        'jobs_today': jobs_today
    }


def get_project_status(job_name: str) -> dict:
    """Get project completion status"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get project info
    cursor.execute('SELECT * FROM projects WHERE job_name = ?', (job_name,))
    project = cursor.fetchone()
    
    # Get cabinet statuses
    cursor.execute('''
        SELECT * FROM cabinets WHERE job_name = ? ORDER BY cabinet_assembly
    ''', (job_name,))
    cabinets = cursor.fetchall()
    
    conn.close()
    
    if not project:
        return {'error': 'Project not found'}
    
    total = len(cabinets)
    complete = sum(1 for c in cabinets if c['status'] == 'complete')
    ready = sum(1 for c in cabinets if c['ready_for_assembly'])
    
    return {
        'job_name': job_name,
        'status': project['status'],
        'total_cabinets': total,
        'cabinets_complete': complete,
        'cabinets_ready': ready,
        'completion_percent': round(complete / total * 100, 1) if total > 0 else 0,
        'cabinets': [dict(c) for c in cabinets]
    }


# Initialize database on import
# Ensure schema is applied whenever this module is imported by the running system.
try:
    init_database()
except Exception as e:
    logging.warning(f"Database schema init on import failed: {e}")

if __name__ == '__main__':
    print("Database initialized!")
    print(f"Database path: {DB_PATH}")



