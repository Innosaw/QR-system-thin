#!/usr/bin/env python3
"""
Bin Management and Monitoring System
Tracks parts in 40 bins, monitors completion status, and provides visual display
"""

import json
import sqlite3
import time
import threading
import os
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
import logging
from flask import Flask, render_template, jsonify, request, session, g
from urllib.parse import urlparse
from typing import Optional
from path_utils import resolve_path
from werkzeug.utils import secure_filename

from authz import has_role as _has_role, is_auth_enabled as _env_auth_enabled

try:
    from database_schema import get_setting
except Exception:
    get_setting = None

try:
    from database_schema import get_db_connection
except Exception:
    get_db_connection = None

# Import case parts logic
try:
    from case_parts_logic import CasePartsManager
    HAS_CASE_LOGIC = True
except ImportError:
    HAS_CASE_LOGIC = False
    print("⚠️  Case parts logic not available")

class BinManager:
    """Manages bin tracking and cabinet completion status"""
    
    def __init__(self, db_path: str = "data/bin_tracking.db", num_bins: int = 40):
        self.db_path = resolve_path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.num_bins = num_bins

        # Short TTL caches to avoid expensive recomputation under frequent polling.
        # Tunable via env vars on the Pi.
        self._cache_lock = threading.Lock()
        self._case_ready_cache_ts = 0.0
        self._case_ready_cache_value: Optional[List[Dict]] = None
        self._case_ready_cache_ttl = float(os.getenv('INNOSAW_CASE_READY_CACHE_SECONDS', '3'))

        self._cabinet_library_cache_ts = 0.0
        self._cabinet_library_cache_value: Optional[Dict] = None
        self._cabinet_library_cache_ttl = float(os.getenv('INNOSAW_CABINET_LIBRARY_CACHE_SECONDS', '30'))

        # Incremented any time bin_contents changes. Used to avoid recomputing case readiness
        # on every dashboard poll.
        self._bin_contents_version = 0
        self._case_ready_last_refresh_version = -1
        
        # Initialize case parts logic
        if HAS_CASE_LOGIC:
            self.case_manager = CasePartsManager(str(self.db_path))
        else:
            self.case_manager = None
        
        self.init_database()

    def _bump_bin_contents_version(self) -> None:
        with self._cache_lock:
            self._bin_contents_version += 1
            # Force a refresh next time (and don't serve stale readiness for too long).
            self._case_ready_cache_ts = 0.0
    
    def init_database(self):
        """Initialize bin tracking database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS bin_contents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bin_number INTEGER NOT NULL,
                    part_number TEXT NOT NULL,
                    cabinet_name TEXT NOT NULL,
                    job_name TEXT,
                    quantity INTEGER DEFAULT 1,
                    scan_timestamp TEXT NOT NULL,
                    operator_id TEXT,
                    station_code TEXT,
                    status TEXT DEFAULT 'in_bin',  -- 'in_bin', 'pulled', 'assembled', 'on_hold'
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS cabinet_recipes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cabinet_name TEXT NOT NULL,
                    part_number TEXT NOT NULL,
                    required_quantity INTEGER DEFAULT 1,
                    part_category TEXT,  -- 'door', 'drawer', 'panel', 'hardware'
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS cabinet_status (
                    cabinet_name TEXT PRIMARY KEY,
                    total_parts_required INTEGER,
                    parts_in_bins INTEGER DEFAULT 0,
                    parts_ready INTEGER DEFAULT 0,
                    completion_percentage REAL DEFAULT 0.0,
                    ready_for_assembly BOOLEAN DEFAULT 0,
                    job_name TEXT,
                    priority INTEGER DEFAULT 0,
                    target_date TEXT,
                    last_updated TEXT DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS bin_scan_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bin_number INTEGER NOT NULL,
                    scan_type TEXT NOT NULL,  -- 'sort_in', 'pull_out', 'verify'
                    part_number TEXT,
                    cabinet_name TEXT,
                    operator_id TEXT,
                    timestamp TEXT NOT NULL,
                    result TEXT NOT NULL  -- 'success', 'error', 'duplicate'
                );
                
                CREATE INDEX IF NOT EXISTS idx_bin_contents ON bin_contents(bin_number, status);
                CREATE INDEX IF NOT EXISTS idx_cabinet_recipes ON cabinet_recipes(cabinet_name);
                CREATE INDEX IF NOT EXISTS idx_cabinet_status ON cabinet_status(ready_for_assembly, priority);
                CREATE INDEX IF NOT EXISTS idx_bin_scan_log ON bin_scan_log(timestamp, scan_type);
            ''')

            # Lightweight migrations for new metadata fields
            try:
                cur = conn.cursor()
                cur.execute("PRAGMA table_info(bin_contents)")
                existing_cols = {row[1] for row in cur.fetchall()}  # row[1] = name
                to_add = {
                    'cabinet_type': 'TEXT',   # cabinet type/name from QR (e.g., "Base Cabinet 2 Doors")
                    'part_name': 'TEXT',      # part name from QR (e.g., "UBack", "Top")
                    'gcode': 'TEXT',          # gcode filename (if available)
                }
                for col, ddl in to_add.items():
                    if col in existing_cols:
                        continue
                    try:
                        cur.execute(f"ALTER TABLE bin_contents ADD COLUMN {col} {ddl}")
                        logging.info(f"✅ Migrated bin_contents: added {col}")
                    except Exception as e:
                        logging.warning(f"Could not add column {col} to bin_contents: {e}")
            except Exception as e:
                logging.warning(f"bin_contents migration skipped: {e}")

    # ============================================================
    # Mozaik expected-parts integration (manufacturing.db)
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

    def _mz_part_text(self, part_name: str, shorthand: str, comment: str) -> str:
        return f"{part_name or ''} {shorthand or ''} {comment or ''}".strip().lower()

    def _mz_part_group(self, part_name: str, shorthand: str = '', comment: str = '') -> str:
        t = self._mz_part_text(part_name, shorthand, comment)
        for phrase in self._MZ_INCLUDED_OVERRIDES:
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

    def _mz_normalize_part_name(self, name: str) -> str:
        if self.case_manager:
            try:
                return self.case_manager.normalize_part_name(name)
            except Exception:
                pass

        # Basic fallback: normalize UEnd/FEnd to End while preserving (L)/(R)
        s = (name or '').strip()
        if not s:
            return ''
        try:
            return re.sub(r'^[UF]End\s*\(', 'End (', s, flags=re.IGNORECASE).strip()
        except Exception:
            return s

    def _mozaik_available(self) -> bool:
        if not get_db_connection:
            return False
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='mozaik_imports'")
            ok = cur.fetchone() is not None
            conn.close()
            return ok
        except Exception:
            return False

    def get_mozaik_cabinet_breakdown(self, job_name: str, cabinet_assembly: str) -> Dict:
        """Return Mozaik required parts for a cabinet instance (cabinet_assembly).

        Output shape matches get_cabinet_parts_breakdown():
          { source, job_name, cabinet_assembly, case_parts[], excluded_parts[] }

        Each part entry uses the same keys as the cabinet library:
          { part_number, part_category, required_quantity }
        """
        job_name = (job_name or '').strip()
        cabinet_assembly = (cabinet_assembly or '').strip()
        if not job_name or not cabinet_assembly:
            return {'error': 'job_name and cabinet_assembly are required'}
        if not self._mozaik_available():
            return {'error': 'Mozaik not available'}

        conn = get_db_connection()
        cur = conn.cursor()
        # Only count active imports
        cur.execute('''
            SELECT p.part_name, p.part_shorthand_name, p.part_comment
            FROM mozaik_expected_parts p
            JOIN mozaik_imports i ON i.id = p.import_id
            WHERE i.job_name = ?
              AND i.status = 'imported'
              AND p.cabinet_assembly = ?
        ''', (job_name, cabinet_assembly))
        rows = cur.fetchall() or []
        conn.close()

        if not rows:
            return {
                'source': 'mozaik',
                'job_name': job_name,
                'cabinet_assembly': cabinet_assembly,
                'case_parts': [],
                'excluded_parts': [],
            }

        # Aggregate required quantities by normalized part name
        agg: Dict[str, Dict] = {}
        for r in rows:
            part_name = (r['part_name'] if isinstance(r, sqlite3.Row) else r[0]) or ''
            shorthand = (r['part_shorthand_name'] if isinstance(r, sqlite3.Row) else r[1]) or ''
            comment = (r['part_comment'] if isinstance(r, sqlite3.Row) else r[2]) or ''

            display = (str(part_name).strip() or str(comment).strip() or str(shorthand).strip() or '').strip()
            if not display:
                continue

            normalized = self._mz_normalize_part_name(display)
            if not normalized:
                continue

            if normalized not in agg:
                agg[normalized] = {
                    'display': display,
                    'required_quantity': 0,
                    'part_category': self._mz_part_group(str(part_name), str(shorthand), str(comment)),
                }
            agg[normalized]['required_quantity'] += 1

        case_parts = []
        excluded_parts = []
        for _, v in sorted(agg.items(), key=lambda kv: kv[0]):
            entry = {
                'part_number': v['display'],
                'part_category': v.get('part_category') or 'custom',
                'category': v.get('part_category') or 'custom',
                'required_quantity': int(v.get('required_quantity') or 1),
                'required': int(v.get('required_quantity') or 1),
            }
            if (v.get('part_category') or '') == 'case':
                case_parts.append(entry)
            else:
                excluded_parts.append(entry)

        return {
            'source': 'mozaik',
            'job_name': job_name,
            'cabinet_assembly': cabinet_assembly,
            'case_parts': case_parts,
            'excluded_parts': excluded_parts,
        }
    
    def add_part_to_bin(self, bin_number: int, part_number: str, cabinet_name: str,
                       job_name: str = "", quantity: int = 1, operator_id: str = "",
                       station_code: str = "Sort",
                       cabinet_type: str = "", part_name: str = "", gcode: str = "") -> Tuple[bool, str]:
        """Add part to bin (from Sort station)"""
        try:
            if bin_number < 1 or bin_number > self.num_bins:
                return False, f"Invalid bin number: {bin_number} (must be 1-{self.num_bins})"
            
            with sqlite3.connect(self.db_path) as conn:
                # Check if part already exists in bin
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, quantity FROM bin_contents 
                    WHERE bin_number = ? AND part_number = ? AND cabinet_name = ? AND status = 'in_bin'
                ''', (bin_number, part_number, cabinet_name))
                
                existing = cursor.fetchone()
                
                if existing:
                    # Update quantity
                    new_quantity = existing[1] + quantity
                    cursor.execute('''
                        UPDATE bin_contents 
                        SET quantity = ?, scan_timestamp = ?, operator_id = ?,
                            cabinet_type = COALESCE(NULLIF(?, ''), cabinet_type),
                            part_name = COALESCE(NULLIF(?, ''), part_name),
                            gcode = COALESCE(NULLIF(?, ''), gcode)
                        WHERE id = ?
                    ''', (new_quantity, datetime.now().isoformat(), operator_id,
                          cabinet_type or "", part_name or "", gcode or "",
                          existing[0]))
                    
                    message = f"Updated {part_number} in bin {bin_number}: quantity now {new_quantity}"
                else:
                    # Check if bin is on hold - clear hold when Sort scan adds a part
                    cursor.execute('''
                        SELECT COUNT(*) as count FROM bin_contents 
                        WHERE bin_number = ? AND status = 'on_hold'
                    ''', (bin_number,))
                    hold_count = cursor.fetchone()[0]
                    
                    # Add new part
                    cursor.execute('''
                        INSERT INTO bin_contents 
                        (bin_number, part_number, cabinet_name, job_name, quantity, 
                         scan_timestamp, operator_id, station_code, status,
                         cabinet_type, part_name, gcode)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'in_bin', ?, ?, ?)
                    ''', (bin_number, part_number, cabinet_name, job_name, quantity, 
                         datetime.now().isoformat(), operator_id, station_code,
                         cabinet_type or "", part_name or "", gcode or ""))
                    
                    # If bin was on hold, clear the hold when Sort scan occurs
                    # (Sort scan means bin is being refilled, so clear the hold)
                    if hold_count > 0:
                        cursor.execute('''
                            UPDATE bin_contents 
                            SET status = 'pulled', scan_timestamp = ?
                            WHERE bin_number = ? AND status = 'on_hold'
                        ''', (datetime.now().isoformat(), bin_number))
                        message = f"Added {part_number} to bin {bin_number} for {cabinet_name} (cleared hold)"
                    else:
                        message = f"Added {part_number} to bin {bin_number} for {cabinet_name}"
                
                # Log the scan
                cursor.execute('''
                    INSERT INTO bin_scan_log 
                    (bin_number, scan_type, part_number, cabinet_name, operator_id, timestamp, result)
                    VALUES (?, 'sort_in', ?, ?, ?, ?, 'success')
                ''', (bin_number, part_number, cabinet_name, operator_id, datetime.now().isoformat()))
                
                # Update cabinet status
                self._update_cabinet_status(cabinet_name, conn)

                # Case readiness depends on bin contents.
                self._bump_bin_contents_version()
                
                logging.info(message)
                return True, message
        
        except Exception as e:
            error_msg = f"Failed to add part to bin: {e}"
            logging.error(error_msg)
            return False, error_msg
    
    def pull_part_from_bin(self, bin_number: int, part_number: str = "", cabinet_name: str = "",
                          operator_id: str = "", station_code: str = "Pull") -> Tuple[bool, str]:
        """Pull part from bin (from Pull station)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Find parts to pull
                if part_number and cabinet_name:
                    # Specific part
                    cursor.execute('''
                        SELECT id, part_number, cabinet_name, quantity FROM bin_contents 
                        WHERE bin_number = ? AND part_number = ? AND cabinet_name = ? AND status = 'in_bin'
                        ORDER BY scan_timestamp ASC
                    ''', (bin_number, part_number, cabinet_name))
                elif cabinet_name:
                    # Any part for this cabinet
                    cursor.execute('''
                        SELECT id, part_number, cabinet_name, quantity FROM bin_contents 
                        WHERE bin_number = ? AND cabinet_name = ? AND status = 'in_bin'
                        ORDER BY scan_timestamp ASC
                    ''', (bin_number, cabinet_name))
                else:
                    # Any part in bin
                    cursor.execute('''
                        SELECT id, part_number, cabinet_name, quantity FROM bin_contents 
                        WHERE bin_number = ? AND status = 'in_bin'
                        ORDER BY scan_timestamp ASC
                    ''', (bin_number,))
                
                parts_to_pull = cursor.fetchall()
                
                if not parts_to_pull:
                    return False, f"No parts found in bin {bin_number}"
                
                pulled_parts = []
                for part_id, p_num, c_name, qty in parts_to_pull:
                    # Mark as pulled
                    cursor.execute('''
                        UPDATE bin_contents 
                        SET status = 'pulled', operator_id = ?, scan_timestamp = ?
                        WHERE id = ?
                    ''', (operator_id, datetime.now().isoformat(), part_id))
                    
                    pulled_parts.append(f"{p_num} (qty: {qty}) for {c_name}")
                    
                    # Log the pull
                    cursor.execute('''
                        INSERT INTO bin_scan_log 
                        (bin_number, scan_type, part_number, cabinet_name, operator_id, timestamp, result)
                        VALUES (?, 'pull_out', ?, ?, ?, ?, 'success')
                    ''', (bin_number, p_num, c_name, operator_id, datetime.now().isoformat()))
                    
                    # Update cabinet status
                    self._update_cabinet_status(c_name, conn)

                self._bump_bin_contents_version()
                
                message = f"Pulled from bin {bin_number}: {'; '.join(pulled_parts)}"
                logging.info(message)
                return True, message
        
        except Exception as e:
            error_msg = f"Failed to pull part from bin: {e}"
            logging.error(error_msg)
            return False, error_msg
    
    def clear_bin(self, bin_number: int, operator_id: str = "manual") -> Tuple[bool, str]:
        """Clear all parts from a bin (manual override)"""
        try:
            if bin_number < 1 or bin_number > self.num_bins:
                return False, f"Invalid bin number: {bin_number}"
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get all parts in bin for logging
                cursor.execute('''
                    SELECT part_number, cabinet_name FROM bin_contents 
                    WHERE bin_number = ? AND status = 'in_bin'
                ''', (bin_number,))
                parts = cursor.fetchall()
                
                if not parts:
                    return True, f"Bin {bin_number} was already empty"
                
                # Mark all parts as manually cleared
                cursor.execute('''
                    UPDATE bin_contents 
                    SET status = 'cleared', operator_id = ?, scan_timestamp = ?
                    WHERE bin_number = ? AND status = 'in_bin'
                ''', (operator_id, datetime.now().isoformat(), bin_number))
                
                # Log the clear operation
                cursor.execute('''
                    INSERT INTO bin_scan_log 
                    (bin_number, scan_type, part_number, cabinet_name, operator_id, timestamp, result)
                    VALUES (?, 'manual_clear', ?, ?, ?, ?, 'success')
                ''', (bin_number, f"{len(parts)} parts", "ALL", operator_id, datetime.now().isoformat()))
                
                # Update cabinet statuses for affected cabinets
                affected_cabinets = set(p[1] for p in parts if p[1])
                for cabinet in affected_cabinets:
                    self._update_cabinet_status(cabinet, conn)

                self._bump_bin_contents_version()
                
                message = f"Cleared {len(parts)} parts from bin {bin_number}"
                logging.info(message)
                return True, message
        
        except Exception as e:
            error_msg = f"Failed to clear bin: {e}"
            logging.error(error_msg)
            return False, error_msg
    
    def handle_assembly_scan(self, part_number: str, cabinet_name: str = "", 
                            job_name: str = "", operator_id: str = "Assembly",
                            clear_bin: bool = False) -> Tuple[bool, str, Optional[int]]:
        """
        Handle Assembly station scanning a part.
        If part is in a bin, either clear it or put bin on hold.
        Returns: (success, message, bin_number_if_found)
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Find the part in any bin
                # Try multiple matching strategies:
                # 1. Exact match on part_number
                # 2. Contains match on part_number (for CSV strings)
                # 3. Match on part_name if available
                # 4. Match on gcode if stored separately
                cursor.execute('''
                    SELECT id, bin_number, part_number, cabinet_name, quantity, part_name
                    FROM bin_contents 
                    WHERE (
                        part_number = ? 
                        OR part_number LIKE ? 
                        OR part_number LIKE ?
                        OR part_name = ?
                    )
                    AND status = 'in_bin'
                    ORDER BY scan_timestamp DESC
                    LIMIT 1
                ''', (part_number, f'%{part_number}%', f'%,{part_number},%', part_number))
                
                part_in_bin = cursor.fetchone()
                
                if not part_in_bin:
                    # Part not in any bin - nothing to do
                    return True, f"Part {part_number} not found in any bin", None
                
                bin_num = part_in_bin[1]
                part_id = part_in_bin[0]
                
                if clear_bin:
                    # Clear the entire bin (assume all parts were pulled)
                    cursor.execute('''
                        UPDATE bin_contents 
                        SET status = 'pulled', operator_id = ?, scan_timestamp = ?
                        WHERE bin_number = ? AND status = 'in_bin'
                    ''', (operator_id, datetime.now().isoformat(), bin_num))
                    
                    # Log the action
                    cursor.execute('''
                        INSERT INTO bin_scan_log 
                        (bin_number, scan_type, part_number, cabinet_name, operator_id, timestamp, result)
                        VALUES (?, 'assembly_pull', ?, ?, ?, ?, 'success')
                    ''', (bin_num, part_number, cabinet_name, operator_id, datetime.now().isoformat()))
                    
                    conn.commit()
                    return True, f"Cleared bin {bin_num} - part {part_number} assembled", bin_num
                else:
                    # Put bin on hold (yellow status)
                    cursor.execute('''
                        UPDATE bin_contents 
                        SET status = 'on_hold', operator_id = ?, scan_timestamp = ?
                        WHERE bin_number = ? AND status = 'in_bin'
                    ''', (operator_id, datetime.now().isoformat(), bin_num))
                    
                    # Log the action
                    cursor.execute('''
                        INSERT INTO bin_scan_log 
                        (bin_number, scan_type, part_number, cabinet_name, operator_id, timestamp, result)
                        VALUES (?, 'assembly_hold', ?, ?, ?, ?, 'success')
                    ''', (bin_num, part_number, cabinet_name, operator_id, datetime.now().isoformat()))
                    
                    conn.commit()
                    return True, f"Bin {bin_num} put on hold - part {part_number} assembled", bin_num
                    
        except Exception as e:
            logging.error(f"Failed to handle assembly scan: {e}")
            return False, f"Error: {str(e)}", None
    
    def clear_hold_if_visually_free(self, bin_number: int, operator_id: str = "Sort", force: bool = False) -> Tuple[bool, str]:
        """
        Clear hold status from a bin.
        If force=False, only clears if bin is visually free (no parts visible).
        If force=True, clears hold status regardless of bin contents.
        Called when Sort station scans a bin that's on hold, or manually via API.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if not force:
                    # Check if bin has any parts in 'in_bin' status (visually present)
                    cursor.execute('''
                        SELECT COUNT(*) as count FROM bin_contents 
                        WHERE bin_number = ? AND status = 'in_bin'
                    ''', (bin_number,))
                    
                    in_bin_count = cursor.fetchone()[0]
                    
                    if in_bin_count > 0:
                        # Bin still has parts - keep on hold unless forced
                        return True, f"Bin {bin_number} still has {in_bin_count} part(s) - keeping hold status"
                
                # Clear all hold status (either visually free or forced)
                cursor.execute('''
                    UPDATE bin_contents 
                    SET status = 'pulled', operator_id = ?, scan_timestamp = ?
                    WHERE bin_number = ? AND status = 'on_hold'
                ''', (operator_id, datetime.now().isoformat(), bin_number))
                
                cleared_count = cursor.rowcount
                
                if cleared_count > 0:
                    # Log the action
                    cursor.execute('''
                        INSERT INTO bin_scan_log 
                        (bin_number, scan_type, part_number, cabinet_name, operator_id, timestamp, result)
                        VALUES (?, 'clear_hold', 'ALL', 'ALL', ?, ?, 'success')
                    ''', (bin_number, operator_id, datetime.now().isoformat()))
                    
                    conn.commit()
                    return True, f"Cleared hold status from bin {bin_number} ({cleared_count} parts)"
                else:
                    return True, f"Bin {bin_number} has no hold status to clear"
                    
        except Exception as e:
            logging.error(f"Failed to clear hold status: {e}")
            return False, f"Error: {str(e)}"

    def remove_part_from_bin(self, bin_number: int, part_number: str, cabinet_name: str = "",
                            operator_id: str = "manual") -> Tuple[bool, str]:
        """Remove a specific part from a bin (manual override)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Find the specific part
                if cabinet_name:
                    cursor.execute('''
                        SELECT id, cabinet_name FROM bin_contents 
                        WHERE bin_number = ? AND part_number = ? AND cabinet_name = ? AND status = 'in_bin'
                        LIMIT 1
                    ''', (bin_number, part_number, cabinet_name))
                else:
                    cursor.execute('''
                        SELECT id, cabinet_name FROM bin_contents 
                        WHERE bin_number = ? AND part_number = ? AND status = 'in_bin'
                        LIMIT 1
                    ''', (bin_number, part_number))
                
                result = cursor.fetchone()
                
                if not result:
                    return False, f"Part not found in bin {bin_number}"
                
                part_id, cab_name = result
                
                # Mark as manually removed
                cursor.execute('''
                    UPDATE bin_contents 
                    SET status = 'removed', operator_id = ?, scan_timestamp = ?
                    WHERE id = ?
                ''', (operator_id, datetime.now().isoformat(), part_id))
                
                # Log the removal
                cursor.execute('''
                    INSERT INTO bin_scan_log 
                    (bin_number, scan_type, part_number, cabinet_name, operator_id, timestamp, result)
                    VALUES (?, 'manual_remove', ?, ?, ?, ?, 'success')
                ''', (bin_number, part_number, cab_name, operator_id, datetime.now().isoformat()))
                
                # Update cabinet status
                if cab_name:
                    self._update_cabinet_status(cab_name, conn)

                self._bump_bin_contents_version()
                
                message = f"Removed {part_number} from bin {bin_number}"
                logging.info(message)
                return True, message
        
        except Exception as e:
            error_msg = f"Failed to remove part from bin: {e}"
            logging.error(error_msg)
            return False, error_msg
    
    def get_bin_contents(self, bin_number: Optional[int] = None) -> Dict:
        """Get contents of specific bin or all bins"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if bin_number:
                    cursor.execute('''
                        SELECT part_number, cabinet_name, cabinet_type, job_name, quantity, scan_timestamp, operator_id, status
                        FROM bin_contents 
                        WHERE bin_number = ? AND (status = 'in_bin' OR status = 'on_hold')
                        ORDER BY scan_timestamp DESC
                    ''', (bin_number,))
                    
                    contents = []
                    for row in cursor.fetchall():
                        contents.append({
                            'part_number': row[0],
                            'cabinet_name': row[1],
                            'cabinet_type': row[2] or row[1],  # Fallback to cabinet_name if cabinet_type is empty
                            'job_name': row[3],
                            'quantity': row[4],
                            'scan_timestamp': row[5],
                            'operator_id': row[6],
                            'status': row[7]  # Include status
                        })
                    
                    return {bin_number: contents}
                else:
                    # All bins - include both in_bin and on_hold
                    cursor.execute('''
                        SELECT bin_number, part_number, cabinet_name, cabinet_type, job_name, quantity, scan_timestamp, operator_id, status
                        FROM bin_contents 
                        WHERE status = 'in_bin' OR status = 'on_hold'
                        ORDER BY bin_number, scan_timestamp DESC
                    ''', ())
                    
                    bins = {}
                    for i in range(1, self.num_bins + 1):
                        bins[i] = []
                    
                    for row in cursor.fetchall():
                        bin_num = row[0]
                        if bin_num not in bins:
                            bins[bin_num] = []
                        
                        bins[bin_num].append({
                            'part_number': row[1],
                            'cabinet_name': row[2],
                            'cabinet_type': row[3] or row[2],  # Fallback to cabinet_name if cabinet_type is empty
                            'job_name': row[4],
                            'quantity': row[5],
                            'scan_timestamp': row[6],
                            'operator_id': row[7],
                            'status': row[8]  # Include status
                        })
                    
                    return bins
        
        except Exception as e:
            logging.error(f"Failed to get bin contents: {e}")
            return {}
    
    def get_cabinet_status(self, cabinet_name: Optional[str] = None) -> Dict:
        """Get cabinet completion status"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if cabinet_name:
                    cursor.execute('''
                        SELECT * FROM cabinet_status WHERE cabinet_name = ?
                    ''', (cabinet_name,))
                    
                    row = cursor.fetchone()
                    if row:
                        columns = [desc[0] for desc in cursor.description]
                        return {cabinet_name: dict(zip(columns, row))}
                    else:
                        return {}
                else:
                    cursor.execute('''
                        SELECT * FROM cabinet_status 
                        ORDER BY ready_for_assembly DESC, priority DESC, completion_percentage DESC
                    ''')
                    
                    cabinets = {}
                    columns = [desc[0] for desc in cursor.description]
                    
                    for row in cursor.fetchall():
                        cabinet_data = dict(zip(columns, row))
                        cabinets[cabinet_data['cabinet_name']] = cabinet_data
                    
                    return cabinets
        
        except Exception as e:
            logging.error(f"Failed to get cabinet status: {e}")
            return {}
    
    def _update_cabinet_status(self, cabinet_name: str, conn: sqlite3.Connection):
        """Update cabinet completion status (both full and case-only)"""
        try:
            cursor = conn.cursor()

            # Best-effort: get job_name for this cabinet instance (needed for Mozaik override)
            job_name = ''
            try:
                cursor.execute('''
                    SELECT job_name
                    FROM bin_contents
                    WHERE cabinet_name = ? AND job_name IS NOT NULL AND TRIM(job_name) <> ''
                    LIMIT 1
                ''', (cabinet_name,))
                jr = cursor.fetchone()
                if jr and jr[0]:
                    job_name = str(jr[0]).strip()
            except Exception:
                job_name = ''
            
            # Count ALL parts in bins for this cabinet
            cursor.execute('''
                SELECT COUNT(*), SUM(quantity) FROM bin_contents 
                WHERE cabinet_name = ? AND status = 'in_bin'
            ''', (cabinet_name,))
            
            parts_in_bins_result = cursor.fetchone()
            parts_count = parts_in_bins_result[0] if parts_in_bins_result[0] else 0
            parts_quantity = parts_in_bins_result[1] if parts_in_bins_result[1] else 0
            
            # Get required parts count (if we have recipe data)
            cursor.execute('''
                SELECT COUNT(*), SUM(required_quantity) FROM cabinet_recipes 
                WHERE cabinet_name = ?
            ''', (cabinet_name,))
            
            required_result = cursor.fetchone()
            required_count = required_result[0] if required_result[0] else 1  # Default to 1 if no recipe
            required_quantity = required_result[1] if required_result[1] else parts_quantity  # Use actual if no recipe

            # Mozaik override: if this cabinet instance exists in Mozaik expected parts for the job,
            # use those as the requirements (supersedes cabinet library/recipes).
            mozaik_case_required_map: Dict[str, int] = {}
            mozaik_total_required = None
            try:
                if job_name and self._mozaik_available():
                    breakdown = self.get_mozaik_cabinet_breakdown(job_name, cabinet_name)
                    if isinstance(breakdown, dict) and (breakdown.get('case_parts') or breakdown.get('excluded_parts') is not None):
                        cps = breakdown.get('case_parts') or []
                        exs = breakdown.get('excluded_parts') or []
                        # Only override if we actually found any expected parts for this cabinet
                        total = 0
                        for p in cps:
                            total += int(p.get('required_quantity') or 1)
                            n = self._mz_normalize_part_name(str(p.get('part_number') or ''))
                            if n:
                                mozaik_case_required_map[n] = mozaik_case_required_map.get(n, 0) + int(p.get('required_quantity') or 1)
                        for p in exs:
                            total += int(p.get('required_quantity') or 1)
                        if total > 0:
                            mozaik_total_required = total
                            required_quantity = total
            except Exception as e:
                logging.warning(f"Mozaik override skipped for {cabinet_name}: {e}")
            
            # Calculate completion percentage (all parts)
            completion_percentage = min(100.0, (parts_quantity / max(required_quantity, 1)) * 100)
            ready_for_assembly = completion_percentage >= 100.0
            
            # **NEW: Case-only readiness logic**
            case_ready = False
            if self.case_manager:
                try:
                    # If Mozaik requirements exist for this cabinet instance, compute case-ready against
                    # the expected case parts for *this instance*.
                    if mozaik_total_required is not None and mozaik_case_required_map:
                        # Count available parts in bins for this cabinet instance by normalized part name
                        cursor.execute('''
                            SELECT part_name, part_number, quantity
                            FROM bin_contents
                            WHERE cabinet_name = ? AND status = 'in_bin'
                        ''', (cabinet_name,))

                        available_by_part: Dict[str, int] = {}
                        for part_name, part_number_raw, qty in cursor.fetchall():
                            name = ''
                            try:
                                name = (part_name or '').strip()
                                if not name:
                                    name = self.case_manager.derive_part_name(part_name, part_number_raw)
                            except Exception:
                                name = (part_name or '').strip() or ''
                            name = self._mz_normalize_part_name(name)
                            if not name:
                                continue
                            try:
                                q = int(qty)
                            except Exception:
                                q = 1
                            available_by_part[name] = available_by_part.get(name, 0) + q

                        all_present = True
                        for req_part, req_qty in mozaik_case_required_map.items():
                            if available_by_part.get(req_part, 0) < req_qty:
                                all_present = False
                                break
                        case_ready = bool(all_present)
                    else:
                        # Default: Update case readiness using the cabinet library (by type)
                        self.case_manager.update_case_readiness(cabinet_name, conn)
                        case_status = self.case_manager.get_cabinet_case_status(cabinet_name)
                        if cabinet_name in case_status:
                            case_ready = case_status[cabinet_name].get('case_ready_for_assembly', False)
                            logging.info(f"Cabinet {cabinet_name} case readiness: {'READY' if case_ready else 'NOT READY'}")
                except Exception as e:
                    logging.error(f"Failed to update case readiness for {cabinet_name}: {e}")
            
            # Use case readiness for assembly status (ignore doors/drawers)
            final_ready_status = case_ready if self.case_manager else ready_for_assembly
            
            # Update or insert cabinet status
            cursor.execute('''
                INSERT OR REPLACE INTO cabinet_status 
                (cabinet_name, total_parts_required, parts_in_bins, parts_ready, 
                 completion_percentage, ready_for_assembly, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (cabinet_name, required_quantity, parts_count, parts_quantity,
                 completion_percentage, final_ready_status, datetime.now().isoformat()))
            
        except Exception as e:
            logging.error(f"Failed to update cabinet status for {cabinet_name}: {e}")
    
    def import_cabinet_recipes_from_sheets(self, sheets_config: Dict) -> bool:
        """Import cabinet recipes from Google Sheets"""
        logging.warning("Google Sheets integration removed; cabinet recipes import from Sheets is disabled.")
        return False
        try:
            scope = ['https://spreadsheets.google.com/feeds',
                    'https://www.googleapis.com/auth/drive']
            
            creds = ServiceAccountCredentials.from_json_keyfile_name(
                sheets_config['credentials_file'], scope)
            client = gspread.authorize(creds)
            
            workbook = client.open_by_key(sheets_config['sheet_id'])
            
            # Try to find cabinet recipes sheet
            recipes_sheet = None
            for sheet_name in ['Cabinet_Recipes', 'Recipes', 'Parts_List']:
                try:
                    recipes_sheet = workbook.worksheet(sheet_name)
                    break
                except:
                    continue
            
            if not recipes_sheet:
                logging.warning("No cabinet recipes sheet found")
                return False
            
            # Get all data
            data = recipes_sheet.get_all_values()
            if len(data) < 2:  # Need header + at least one row
                return False
            
            headers = data[0]
            rows = data[1:]
            
            # Expected columns: Cabinet_Name, Part_Name/Part_Number, Quantity
            cabinet_col = None
            part_col = None
            qty_col = None
            
            for i, header in enumerate(headers):
                header_lower = header.lower()
                if 'cabinet' in header_lower and 'name' in header_lower:
                    cabinet_col = i
                elif 'part' in header_lower and ('name' in header_lower or 'number' in header_lower):
                    part_col = i
                elif 'quantity' in header_lower or 'qty' in header_lower:
                    qty_col = i
            
            if cabinet_col is None or part_col is None:
                logging.error("Required columns not found in recipes sheet")
                return False
            
            # Import recipes
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Clear existing recipes
                cursor.execute('DELETE FROM cabinet_recipes')
                
                imported_count = 0
                for row in rows:
                    if len(row) > max(cabinet_col, part_col):
                        cabinet_name = row[cabinet_col].strip()
                        part_number = row[part_col].strip()
                        quantity = 1
                        
                        if qty_col is not None and len(row) > qty_col:
                            try:
                                quantity = int(row[qty_col])
                            except:
                                quantity = 1
                        
                        if cabinet_name and part_number:
                            cursor.execute('''
                                INSERT INTO cabinet_recipes (cabinet_name, part_number, required_quantity)
                                VALUES (?, ?, ?)
                            ''', (cabinet_name, part_number, quantity))
                            imported_count += 1
            
            logging.info(f"Imported {imported_count} cabinet recipes from Google Sheets")
            return True
            
        except Exception as e:
            logging.error(f"Failed to import cabinet recipes: {e}")
            return False
    
    def import_case_requirements_from_sheets(self, sheets_config: Dict) -> bool:
        """Import case requirements and categorize parts (excludes doors/drawers)"""
        logging.warning("Google Sheets integration removed; case requirements import from Sheets is disabled.")
        return False
        if not self.case_manager:
            logging.warning("Case manager not available")
            return False
        
        try:
            scope = ['https://spreadsheets.google.com/feeds',
                    'https://www.googleapis.com/auth/drive']
            
            creds = ServiceAccountCredentials.from_json_keyfile_name(
                sheets_config['credentials_file'], scope)
            client = gspread.authorize(creds)
            
            workbook = client.open_by_key(sheets_config['sheet_id'])
            
            # Try to find parts list sheet
            parts_sheet = None
            for sheet_name in ['Parts_List', 'Cabinet_Parts', 'Case_Parts']:
                try:
                    parts_sheet = workbook.worksheet(sheet_name)
                    break
                except:
                    continue
            
            if not parts_sheet:
                logging.warning("No case parts sheet found")
                return False
            
            # Get all data
            data = parts_sheet.get_all_values()
            if len(data) < 2:  # Need header + at least one row
                return False
            
            headers = data[0]
            rows = data[1:]
            
            # Expected columns: Cabinet_Name, Part_Name/Part_Number, Quantity
            cabinet_col = None
            part_col = None
            qty_col = None
            
            for i, header in enumerate(headers):
                header_lower = header.lower()
                if 'cabinet' in header_lower and 'name' in header_lower:
                    cabinet_col = i
                elif 'part' in header_lower and ('name' in header_lower or 'number' in header_lower):
                    part_col = i
                elif 'quantity' in header_lower or 'qty' in header_lower:
                    qty_col = i
            
            if cabinet_col is None or part_col is None:
                logging.error("Required columns not found in parts sheet")
                return False
            
            # Convert to format expected by case manager
            cabinet_parts_data = []
            for row in rows:
                if len(row) > max(cabinet_col, part_col):
                    cabinet_name = row[cabinet_col].strip()
                    part_number = row[part_col].strip()
                    quantity = 1
                    
                    if qty_col is not None and len(row) > qty_col:
                        try:
                            quantity = int(row[qty_col])
                        except:
                            quantity = 1
                    
                    if cabinet_name and part_number:
                        cabinet_parts_data.append({
                            'cabinet_name': cabinet_name,
                            'part_number': part_number,
                            'quantity': quantity
                        })
            
            # Import using case parts manager
            success = self.case_manager.import_cabinet_requirements(cabinet_parts_data)
            
            if success:
                logging.info(f"Imported {len(cabinet_parts_data)} parts with case logic from Google Sheets")
            
            return success
            
        except Exception as e:
            logging.error(f"Failed to import case requirements: {e}")
            return False
    
    def get_case_ready_cabinets(self) -> List[Dict]:
        """Get cabinets that are ready for case assembly (excludes doors/drawers)"""
        if not self.case_manager:
            return []

        try:
            now = time.monotonic()
            with self._cache_lock:
                cached = self._case_ready_cache_value
                current_version = self._bin_contents_version
                # If bin contents haven't changed since the last refresh, keep serving cached
                # results even if the TTL is exceeded.
                if cached is not None and self._case_ready_last_refresh_version == current_version:
                    return list(cached)

                # Otherwise, respect TTL to avoid hammering the DB during bursts.
                if cached is not None and (now - self._case_ready_cache_ts) < self._case_ready_cache_ttl:
                    return list(cached)

            # Keep status table current; otherwise UI can show an empty list even when bins are full.
            try:
                self.case_manager.update_all_case_readiness()
            except Exception as e:
                logging.error(f"Failed to refresh case readiness table: {e}")
                # If refresh fails, return last known good cache if available.
                with self._cache_lock:
                    if self._case_ready_cache_value is not None:
                        return list(self._case_ready_cache_value)

            ready = self.case_manager.get_case_ready_cabinets() or []

            # Mozaik override: if expected parts exist for a cabinet instance, readiness should be
            # determined from Mozaik + current bin contents (not the library).
            try:
                if self._mozaik_available():
                    ready_by_name: Dict[str, Dict] = {}
                    for cab in ready:
                        nm = (cab.get('cabinet_name') or '').strip() if isinstance(cab, dict) else ''
                        if nm:
                            ready_by_name[nm] = cab

                    with sqlite3.connect(self.db_path) as conn:
                        conn.row_factory = sqlite3.Row
                        cur = conn.cursor()
                        cur.execute('''
                            SELECT cabinet_name, job_name
                            FROM bin_contents
                            WHERE status = 'in_bin'
                              AND cabinet_name IS NOT NULL AND TRIM(cabinet_name) <> ''
                              AND job_name IS NOT NULL AND TRIM(job_name) <> ''
                            GROUP BY cabinet_name
                        ''')
                        candidates = cur.fetchall() or []

                        for r in candidates:
                            cabinet_name = (r['cabinet_name'] or '').strip()
                            job_name = (r['job_name'] or '').strip()
                            if not cabinet_name or not job_name:
                                continue

                            breakdown = self.get_mozaik_cabinet_breakdown(job_name, cabinet_name)
                            if not isinstance(breakdown, dict):
                                continue

                            cps = breakdown.get('case_parts') or []
                            exs = breakdown.get('excluded_parts') or []

                            total_expected = 0
                            required_case_qty = 0
                            for p in cps:
                                q = int(p.get('required_quantity') or p.get('required') or 1)
                                required_case_qty += q
                                total_expected += q
                            for p in exs:
                                total_expected += int(p.get('required_quantity') or p.get('required') or 1)

                            # If this cabinet isn't in Mozaik, don't override.
                            if total_expected <= 0 or required_case_qty <= 0:
                                continue

                            cur.execute('''
                                SELECT part_number, part_name, quantity
                                FROM bin_contents
                                WHERE status = 'in_bin' AND cabinet_name = ?
                            ''', (cabinet_name,))
                            available_case_qty = 0
                            for row in cur.fetchall() or []:
                                part_number = (row['part_number'] or '').strip()
                                part_name = (row['part_name'] or '').strip()
                                if not part_name:
                                    try:
                                        part_name = self.case_manager.derive_part_name(part_name, part_number)
                                    except Exception:
                                        part_name = ''
                                group = self._mz_part_group(part_name or part_number, shorthand=part_number, comment='')
                                if group != 'case':
                                    continue
                                try:
                                    q = int(row['quantity'] or 1)
                                except Exception:
                                    q = 1
                                available_case_qty += q

                            case_ready = available_case_qty >= required_case_qty
                            if case_ready:
                                ready_by_name[cabinet_name] = {
                                    'cabinet_name': cabinet_name,
                                    'cabinet_numbers': [],
                                    'available_parts': available_case_qty,
                                    'required_parts': required_case_qty,
                                    'case_completion': min(100.0, (available_case_qty / max(required_case_qty, 1)) * 100.0),
                                    'job_name': job_name,
                                    'source': 'mozaik',
                                }
                            else:
                                # If library marked it ready but Mozaik says not ready, remove it.
                                ready_by_name.pop(cabinet_name, None)

                    ready = list(ready_by_name.values())
            except Exception as e:
                logging.warning(f"Mozaik override for case-ready list skipped: {e}")

            with self._cache_lock:
                self._case_ready_cache_value = list(ready)
                self._case_ready_cache_ts = time.monotonic()
                self._case_ready_last_refresh_version = self._bin_contents_version
            return ready
        except Exception as e:
            logging.error(f"Failed to get case ready cabinets: {e}")
            return []

    def get_cabinet_library(self) -> Dict:
        """Return cabinet case-part library (cached) from the case logic DB."""
        if not self.case_manager:
            return {'error': 'Case parts logic not available'}

        now = time.monotonic()
        with self._cache_lock:
            cached = self._cabinet_library_cache_value
            if cached is not None and (now - self._cabinet_library_cache_ts) < self._cabinet_library_cache_ttl:
                return cached

        with sqlite3.connect(self.case_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT cabinet_name, part_number, part_category, required_quantity, is_case_part
                FROM case_parts_requirements
                ORDER BY cabinet_name, is_case_part DESC, part_category, part_number
            ''')

            library: Dict[str, Dict[str, List[Dict]]] = {}
            for row in cursor.fetchall():
                cabinet_name = row[0]
                if cabinet_name not in library:
                    library[cabinet_name] = {
                        'case_parts': [],
                        'excluded_parts': []
                    }

                part_info = {
                    'part_number': row[1],
                    'part_category': row[2],
                    'required_quantity': row[3]
                }

                if row[4] == 1:  # is_case_part
                    library[cabinet_name]['case_parts'].append(part_info)
                else:
                    library[cabinet_name]['excluded_parts'].append(part_info)

        result = {
            'cabinet_count': len(library),
            'cabinets': library
        }
        with self._cache_lock:
            self._cabinet_library_cache_value = result
            self._cabinet_library_cache_ts = time.monotonic()
        return result

    def invalidate_cabinet_library_cache(self) -> None:
        with self._cache_lock:
            self._cabinet_library_cache_value = None
            self._cabinet_library_cache_ts = 0.0

    def get_recent_cabinet_instances_for_type(self, cabinet_type: str, limit: int = 5) -> Dict[str, List[str]]:
        """Best-effort: derive cabinet instance ids (e.g. R1C125) and cabinet numbers (e.g. 125) for a cabinet TYPE.

        This is used for display only (sidebar list). Case readiness itself is still computed by cabinet type.
        """
        cabinet_type = (cabinet_type or '').strip()
        if not cabinet_type:
            return {'cabinet_instances': [], 'cabinet_numbers': []}

        def _extract_instance_from_payload(part_number_raw: str) -> str:
            raw = (part_number_raw or '').strip()
            if ',' not in raw:
                return ''
            parts = [p.strip() for p in raw.split(',')]
            # gcode,part_num,job_name,cabinet_type,cabinet_instance,part_name,...
            if len(parts) >= 5 and parts[4]:
                return parts[4]
            return ''

        def _derive_type(cabinet_type_raw: str, part_number_raw: str) -> str:
            ct = (cabinet_type_raw or '').strip()
            if ct:
                return ct
            raw = (part_number_raw or '').strip()
            if ',' not in raw:
                return ''
            parts = [p.strip() for p in raw.split(',')]
            if len(parts) >= 4 and parts[3]:
                return parts[3]
            return ''

        def _extract_number(instance_id: str) -> str:
            s = (instance_id or '').strip()
            m = re.search(r'(\d+)\s*$', s)
            return m.group(1) if m else ''

        instances: List[str] = []
        numbers: List[str] = []
        seen_instances: Set[str] = set()
        seen_numbers: Set[str] = set()

        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.cursor()
                cols = {row[1] for row in cur.execute("PRAGMA table_info(bin_contents)").fetchall()}
                has_cabinet_type = 'cabinet_type' in cols

                if has_cabinet_type:
                    cur.execute('''
                        SELECT cabinet_name, cabinet_type, part_number
                        FROM bin_contents
                        WHERE status = 'in_bin'
                          AND (cabinet_type = ? OR cabinet_type IS NULL OR cabinet_type = '')
                        ORDER BY scan_timestamp DESC
                        LIMIT 400
                    ''', (cabinet_type,))
                    rows = cur.fetchall()
                else:
                    cur.execute('''
                        SELECT cabinet_name, part_number
                        FROM bin_contents
                        WHERE status = 'in_bin'
                        ORDER BY scan_timestamp DESC
                        LIMIT 400
                    ''')
                    rows = [(cab_name, '', part_number_raw) for cab_name, part_number_raw in cur.fetchall()]

                for cab_name, cab_type_raw, part_number_raw in rows:
                    derived = _derive_type(cab_type_raw, part_number_raw)
                    if derived != cabinet_type:
                        continue

                    instance_id = (cab_name or '').strip() or _extract_instance_from_payload(part_number_raw)
                    if instance_id and instance_id not in seen_instances:
                        seen_instances.add(instance_id)
                        instances.append(instance_id)

                    num = _extract_number(instance_id)
                    if num and num not in seen_numbers:
                        seen_numbers.add(num)
                        numbers.append(num)

                    if len(instances) >= limit and len(numbers) >= limit:
                        break
        except Exception:
            return {'cabinet_instances': instances[:limit], 'cabinet_numbers': numbers[:limit]}

        return {'cabinet_instances': instances[:limit], 'cabinet_numbers': numbers[:limit]}
    
    def get_cabinet_parts_breakdown(self, cabinet_name: str) -> Dict:
        """Get detailed breakdown of case vs excluded parts"""
        if not self.case_manager:
            return {}
        
        try:
            return self.case_manager.get_parts_breakdown(cabinet_name)
        except Exception as e:
            logging.error(f"Failed to get parts breakdown: {e}")
            return {}

    def get_bin_statistics(self) -> Dict:
        """Get bin usage statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Bin occupancy
                cursor.execute('''
                    SELECT bin_number, COUNT(*), SUM(quantity) FROM bin_contents
                    WHERE status = 'in_bin'
                    GROUP BY bin_number
                ''')

                bin_occupancy = {}
                for bin_num, part_count, total_qty in cursor.fetchall():
                    bin_occupancy[bin_num] = {
                        'part_types': part_count,
                        'total_quantity': total_qty
                    }

                # Empty bins
                occupied_bins = set(bin_occupancy.keys())
                all_bins = set(range(1, self.num_bins + 1))
                empty_bins = all_bins - occupied_bins

                # Cabinet readiness (now using case logic)
                cursor.execute('''
                    SELECT COUNT(*) as total_cabinets,
                           SUM(CASE WHEN ready_for_assembly = 1 THEN 1 ELSE 0 END) as ready_cabinets,
                           AVG(completion_percentage) as avg_completion
                    FROM cabinet_status
                ''')

                cabinet_stats = cursor.fetchone()

                # Additional case-only statistics
                case_stats = {}
                if self.case_manager:
                    try:
                        case_ready_cabinets = self.get_case_ready_cabinets()
                        case_stats = {
                            'case_ready_count': len(case_ready_cabinets),
                            'case_ready_cabinets': [cab['cabinet_name'] for cab in case_ready_cabinets]
                        }
                    except Exception:
                        case_stats = {'case_ready_count': 0, 'case_ready_cabinets': []}

                return {
                    'total_bins': self.num_bins,
                    'occupied_bins': len(occupied_bins),
                    'empty_bins': len(empty_bins),
                    'empty_bin_list': sorted(list(empty_bins)),
                    'bin_occupancy': bin_occupancy,
                    'cabinet_statistics': {
                        'total_cabinets': cabinet_stats[0] if cabinet_stats and cabinet_stats[0] else 0,
                        'ready_cabinets': cabinet_stats[1] if cabinet_stats and cabinet_stats[1] else 0,
                        'average_completion': cabinet_stats[2] if cabinet_stats and cabinet_stats[2] else 0.0
                    },
                    'case_statistics': case_stats
                }

        except Exception as e:
            logging.error(f"Failed to get bin statistics: {e}", exc_info=True)
            return {}


def _import_case_requirements_csv(file_bytes: bytes, filename: str = "cabinet_library.csv") -> Dict:
    """
    Import cabinet library CSV into case_parts_requirements.

    Expected columns:
    - cabinet_type
    - part_name
    - quantity
    """
    if not bin_manager.case_manager:
        return {'success': False, 'error': 'Case parts logic not available'}

    import csv
    import io
    import sqlite3

    text = file_bytes.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    required_cols = {"cabinet_type", "part_name", "quantity"}
    if not reader.fieldnames:
        return {'success': False, 'error': 'CSV missing header row'}
    missing = required_cols - set([h.strip() for h in reader.fieldnames if h])
    if missing:
        return {'success': False, 'error': f'CSV missing columns: {sorted(missing)}'}

    # Group by cabinet_type
    grouped = {}
    row_count = 0
    for row in reader:
        row_count += 1
        cab = (row.get("cabinet_type") or "").strip()
        part = (row.get("part_name") or "").strip()
        qty_raw = (row.get("quantity") or "").strip()
        if not cab or not part:
            continue
        try:
            qty = int(float(qty_raw)) if qty_raw else 1
        except Exception:
            qty = 1
        if qty <= 0:
            continue
        grouped.setdefault(cab, {})
        grouped[cab][part] = grouped[cab].get(part, 0) + qty

    if not grouped:
        return {'success': False, 'error': 'No valid rows found in CSV'}

    # Merge/update per cabinet type (don't delete existing parts not in CSV)
    cm = bin_manager.case_manager
    try:
        with sqlite3.connect(cm.db_path) as conn:
            cur = conn.cursor()
            updated = 0
            created = 0
            for cab_type, parts in grouped.items():
                # Get existing parts for this cabinet type to track what we're updating
                cur.execute("SELECT part_number FROM case_parts_requirements WHERE cabinet_name = ?", (cab_type,))
                existing_parts = set(row[0] for row in cur.fetchall())
                
                # Update or insert parts from CSV
                for part_name, qty in parts.items():
                    is_case = 1 if cm.is_case_part(part_name) else 0
                    category = cm.categorize_part(part_name)
                    cur.execute(
                        """
                        INSERT OR REPLACE INTO case_parts_requirements
                        (cabinet_name, part_number, part_category, required_quantity, is_case_part)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (cab_type, part_name, category, qty, is_case),
                    )
                    updated += 1
                    if part_name in existing_parts:
                        existing_parts.remove(part_name)
                
                # Note: We don't delete parts that exist in the database but aren't in the CSV
                # This allows merging multiple CSVs to build up a complete library
                # If you want to remove a part, you'd need to explicitly set quantity to 0 or remove it manually
                
                created += 1
            conn.commit()
        return {
            'success': True,
            'cabinet_types': len(grouped),
            'rows_read': row_count,
            'requirements_written': updated,
            'filename': filename,
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

# Flask web application for bin monitoring display
app = Flask(__name__)
# Must match shop_dashboard secret so login session works across ports.
app.secret_key = os.environ.get('INNOSAW_FLASK_SECRET_KEY') or 'qr-scanner-admin-secret-key-change-in-production'
bin_manager = BinManager(num_bins=40)


# Optional lightweight request metrics (disabled by default)
_REQ_METRICS_ENABLED = (os.environ.get('INNOSAW_REQUEST_METRICS') or '').strip().lower() in ('1', 'true', 'yes', 'on')
_REQ_METRICS_INTERVAL_S = 60.0
_REQ_METRICS_LOCK = threading.Lock()
_REQ_METRICS_WINDOW_START = time.time()
_REQ_METRICS = {}  # key -> {count, total_ms, statuses{code_prefix -> count}}


def _req_metrics_key() -> str:
    # Keep cardinality low: method + path (no query string)
    return f"{request.method} {request.path}"


def _record_req_metric(status_code: int, duration_ms: float) -> None:
    key = _req_metrics_key()
    prefix = f"{int(status_code) // 100}xx"
    with _REQ_METRICS_LOCK:
        entry = _REQ_METRICS.get(key)
        if not entry:
            entry = {'count': 0, 'total_ms': 0.0, 'statuses': {}}
            _REQ_METRICS[key] = entry
        entry['count'] += 1
        entry['total_ms'] += float(duration_ms)
        entry['statuses'][prefix] = int(entry['statuses'].get(prefix, 0)) + 1


def _maybe_log_req_metrics() -> None:
    global _REQ_METRICS_WINDOW_START
    now = time.time()
    with _REQ_METRICS_LOCK:
        elapsed = now - _REQ_METRICS_WINDOW_START
        if elapsed < _REQ_METRICS_INTERVAL_S:
            return
        if not _REQ_METRICS:
            _REQ_METRICS_WINDOW_START = now
            return

        # Top endpoints by volume in the last window
        items = sorted(_REQ_METRICS.items(), key=lambda kv: kv[1]['count'], reverse=True)[:10]
        lines = []
        for key, entry in items:
            avg_ms = (entry['total_ms'] / entry['count']) if entry['count'] else 0.0
            statuses = entry.get('statuses', {})
            status_bits = ','.join(f"{k}:{v}" for k, v in sorted(statuses.items()))
            lines.append(f"{key} count={entry['count']} avg_ms={avg_ms:.1f} {status_bits}")

        logging.info(
            "HTTP metrics (last %.0fs): %s",
            elapsed,
            " | ".join(lines)
        )

        # Reset window
        _REQ_METRICS.clear()
        _REQ_METRICS_WINDOW_START = now


def _get_setting(key: str, default: str = '') -> str:
    if not get_setting:
        return default
    try:
        return get_setting(key, default) or default
    except Exception:
        return default


def _auth_enabled() -> bool:
    # Enabled when either env passwords are set OR DB password hashes exist.
    if _env_auth_enabled():
        return True
    return bool(_get_setting('admin_password_hash', '').strip() or _get_setting('shop_password_hash', '').strip())


def _dashboard_login_url() -> str:
    """Best-effort login URL for the Shop Dashboard.

    - If this request is on bins.<base-domain>, link to qr.<base-domain>/login.
    - Otherwise fall back to same host on :5006.
    """
    host = (request.host.split(':', 1)[0] or '').strip()
    xf_proto = (request.headers.get('X-Forwarded-Proto') or '').split(',')[0].strip().lower()
    scheme = xf_proto if xf_proto in ('http', 'https') else request.scheme

    if host.lower().startswith('bins.'):
        return f"{scheme}://qr.{host[5:]}/login"

    # Local fallback: same host but dashboard port.
    return f"{scheme}://{host}:5006/login"


@app.before_request
def _enforce_write_auth():
    """Block bin/cabinet mutations unless authorized.

    Note: This protects direct access to :5000 (bin manager). If auth is not
    enabled (no passwords configured), behavior stays as before.
    """
    if _REQ_METRICS_ENABLED:
        g._req_start_monotonic = time.monotonic()

    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return None

    if not request.path.startswith('/api/'):
        return None

    if not _auth_enabled():
        return None

    required_role = 'shop'
    if request.path.startswith('/api/cabinet_library') or request.path.startswith('/api/import_cabinet_library_csv') or request.path.startswith('/api/case_requirements/import_csv'):
        required_role = 'admin'

    if _has_role(session, required_role):
        return None

    return (
        jsonify(
            {
                'error': 'Not authorized to save. Enter a password at /login on the dashboard.',
                'required_role': required_role,
                'login_url': _dashboard_login_url(),
            }
        ),
        403,
    )


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


@app.after_request
def _add_cors_headers(resp):
    if _REQ_METRICS_ENABLED:
        try:
            start = getattr(g, '_req_start_monotonic', None)
            if start is None:
                # Non-standard paths or early failures; still count, but duration is unknown.
                duration_ms = 0.0
            else:
                duration_ms = (time.monotonic() - float(start)) * 1000.0
            _record_req_metric(getattr(resp, 'status_code', 0) or 0, duration_ms)
            _maybe_log_req_metrics()
        except Exception:
            pass

    if request.method == 'GET' and request.path in ('/api/bin_contents', '/api/bin_statistics'):
        origin = request.headers.get('Origin', '')
        allowed = _allowed_cors_origin(origin)
        if allowed:
            resp.headers['Access-Control-Allow-Origin'] = allowed
            resp.headers['Vary'] = 'Origin'
    return resp

# Material tracker for API endpoints
try:
    from material_tracking import MaterialTracker
    material_tracker = MaterialTracker()
except ImportError:
    material_tracker = None

@app.route('/')
def bin_monitor_dashboard():
    """Main dashboard showing all bins and cabinet status"""
    return render_template('bin_dashboard.html')

@app.route('/api/bin_contents')
def api_bin_contents():
    """API endpoint for bin contents"""
    bin_number = request.args.get('bin_number', type=int)
    contents = bin_manager.get_bin_contents(bin_number)
    return jsonify(contents)

@app.route('/api/cabinet_status') 
def api_cabinet_status():
    """API endpoint for cabinet status"""
    cabinet_name = request.args.get('cabinet_name')
    status = bin_manager.get_cabinet_status(cabinet_name)
    return jsonify(status)

@app.route('/api/bin_statistics')
def api_bin_statistics():
    """API endpoint for bin statistics"""
    try:
        stats = bin_manager.get_bin_statistics()
        return jsonify(stats)
    except Exception as e:
        logging.error(f"/api/bin_statistics failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/ready_cabinets')
def api_ready_cabinets():
    """API endpoint for ready cabinets (for LED integration)"""
    try:
        all_status = bin_manager.get_cabinet_status()
        ready_cabinets = []
        
        for cabinet_name, status in all_status.items():
            if status.get('ready_for_assembly', False):
                ready_cabinets.append({
                    'cabinet_name': cabinet_name,
                    'completion_percentage': status.get('completion_percentage', 0),
                    'parts_ready': status.get('parts_ready', 0),
                    'job_name': status.get('job_name', ''),
                    'bins_with_parts': []  # Could populate this with bin locations
                })
        
        return jsonify({
            'ready_count': len(ready_cabinets),
            'ready_cabinets': ready_cabinets
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/case_ready_cabinets')
def api_case_ready_cabinets():
    """API endpoint for case-ready cabinets (excludes doors/drawers)"""
    try:
        case_ready = bin_manager.get_case_ready_cabinets() or []

        # Optional: tag cabinets that have Mozaik requirements available.
        mozaik_types = set()
        try:
            if getattr(bin_manager, '_mozaik_available', None) and bin_manager._mozaik_available():
                conn = get_db_connection()
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute('''
                    SELECT DISTINCT p.cabinet_name
                    FROM mozaik_expected_parts p
                    JOIN mozaik_imports i ON i.id = p.import_id
                    WHERE i.status = 'imported'
                      AND p.cabinet_name IS NOT NULL AND TRIM(p.cabinet_name) <> ''
                ''')
                for r in cur.fetchall() or []:
                    try:
                        mozaik_types.add((r['cabinet_name'] if isinstance(r, sqlite3.Row) else r[0]).strip())
                    except Exception:
                        continue
                conn.close()
        except Exception:
            mozaik_types = set()

        # Enrich response with best-effort cabinet instance/number hints for display.
        for item in case_ready:
            try:
                if not isinstance(item, dict):
                    continue
                cab_type = (item.get('cabinet_name') or '').strip()

                # Default to library unless we can detect Mozaik data for this cabinet type.
                if 'source' not in item:
                    item['source'] = 'mozaik' if cab_type in mozaik_types else 'library'

                extra = bin_manager.get_recent_cabinet_instances_for_type(cab_type, limit=5)
                item['cabinet_instances'] = extra.get('cabinet_instances') or []
                item['cabinet_numbers'] = extra.get('cabinet_numbers') or []
            except Exception:
                # Display-only hints; never fail the endpoint.
                continue
        return jsonify({
            'case_ready_count': len(case_ready),
            'case_ready_cabinets': case_ready
        })
        
    except Exception as e:
        return jsonify({'case_ready_count': 0, 'case_ready_cabinets': [], 'error': str(e)}), 500


@app.route('/api/bin_manual_add_part', methods=['POST'])
def api_bin_manual_add_part():
    """Manually add a missing part to a bin (used from the Bin Edit modal)."""
    try:
        data = request.json or {}
        bin_number = data.get('bin_number')
        cabinet_name = (data.get('cabinet_name') or '').strip()
        cabinet_type = (data.get('cabinet_type') or '').strip()
        part_name = (data.get('part_name') or '').strip()
        job_name = (data.get('job_name') or '').strip()

        try:
            quantity = int(data.get('quantity') or 1)
        except Exception:
            quantity = 1
        if quantity < 1:
            quantity = 1

        if not bin_number or not cabinet_name or not cabinet_type or not part_name:
            return jsonify({'success': False, 'error': 'Missing bin_number, cabinet_name, cabinet_type, or part_name'}), 400

        # Store a CSV-like payload so existing extractors keep working:
        # gcode,part_num,job_name,cabinet_type,cabinet_instance,part_name
        part_number_raw = f"MANUAL,0,{job_name},{cabinet_type},{cabinet_name},{part_name}"

        success, message = bin_manager.add_part_to_bin(
            int(bin_number),
            part_number_raw,
            cabinet_name,
            job_name=job_name,
            quantity=quantity,
            operator_id='manual',
            station_code='Manual',
            cabinet_type=cabinet_type,
            part_name=part_name,
            gcode='MANUAL'
        )
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/case_requirements/import_csv', methods=['POST'])
def api_import_case_requirements_csv():
    """Upload a cabinet library CSV to define case-ready requirements by cabinet type."""
    try:
        if not bin_manager.case_manager:
            return jsonify({'success': False, 'error': 'Case parts logic not available'}), 400

        f = request.files.get('file')
        if not f or not getattr(f, 'filename', ''):
            return jsonify({'success': False, 'error': 'Missing file'}), 400

        safe = secure_filename(f.filename) or 'cabinet_library.csv'
        data = f.read()
        res = _import_case_requirements_csv(data, filename=safe)
        code = 200 if res.get('success') else 400
        return jsonify(res), code
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/scans', methods=['GET'])
def api_scans_proxy():
    """Proxy scan history requests to API server"""
    try:
        import requests
        # Forward request to API server on port 5007
        api_url = 'http://localhost:5007/api/scans'
        
        # Forward all query parameters
        response = requests.get(api_url, params=request.args, timeout=10)
        
        # Return the response with same status code
        return jsonify(response.json()), response.status_code
    except requests.exceptions.ConnectionError:
        # API server not available - try database directly
        try:
            from database_schema import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Build WHERE clause from query parameters
            where = []
            params = []
            
            part_name = request.args.get('part_name')
            cabinet_name = request.args.get('cabinet_name')
            job_name = request.args.get('job_name')
            cab_type = request.args.get('cab_type')
            limit = int(request.args.get('limit', 50))
            
            if part_name:
                where.append('part_name LIKE ?')
                params.append(f'%{part_name}%')
            
            if cabinet_name:
                where.append('cabinet_name LIKE ?')
                params.append(f'%{cabinet_name}%')
            
            if job_name:
                where.append('job_name LIKE ?')
                params.append(f'%{job_name}%')
            
            if cab_type:
                where.append('cab_type = ?')
                params.append(cab_type)
            
            where_sql = ' AND '.join(where) if where else '1=1'
            
            query = f'SELECT * FROM scans WHERE {where_sql} ORDER BY timestamp DESC LIMIT ?'
            cursor.execute(query, [*params, limit])
            scans = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            return jsonify({'scans': scans, 'count': len(scans)})
        except Exception as e:
            logging.error(f"Error proxying scans: {e}", exc_info=True)
            return jsonify({'error': f'API server unavailable and database fallback failed: {str(e)}'}), 503
    except Exception as e:
        logging.error(f"Error proxying scans: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/cabinet_breakdown/<cabinet_name>')
def api_cabinet_breakdown(cabinet_name):
    """API endpoint for detailed cabinet parts breakdown"""
    try:
        breakdown = bin_manager.get_cabinet_parts_breakdown(cabinet_name)
        return jsonify(breakdown)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/mozaik/cabinet_breakdown')
def api_mozaik_cabinet_breakdown():
    """Mozaik override: required parts for a cabinet instance from imported .mzklbl.

    Query params:
      - job_name (required)
      - cabinet_assembly (required)  e.g. R6C601
    """
    try:
        job_name = (request.args.get('job_name') or '').strip()
        cabinet_assembly = (request.args.get('cabinet_assembly') or '').strip()
        if not job_name or not cabinet_assembly:
            return jsonify({'error': 'job_name and cabinet_assembly are required'}), 400

        breakdown = bin_manager.get_mozaik_cabinet_breakdown(job_name, cabinet_assembly)
        if breakdown.get('error'):
            return jsonify(breakdown), 404
        return jsonify(breakdown)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cabinet_library')
def api_cabinet_library():
    """API endpoint to view imported cabinet library"""
    try:
        if not bin_manager.case_manager:
            return jsonify({'error': 'Case parts logic not available'}), 503

        return jsonify(bin_manager.get_cabinet_library())
        
    except Exception as e:
        logging.error(f"Failed to get cabinet library: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/cabinet_library/part', methods=['POST'])
def api_cabinet_library_add_part():
    """Add a cabinet library part (case or excluded)."""
    try:
        if not bin_manager.case_manager:
            return jsonify({'error': 'Case parts logic not available'}), 503

        data = request.get_json(silent=True) or {}
        cabinet_name = (data.get('cabinet_name') or '').strip()
        part_number = (data.get('part_number') or '').strip()
        required_quantity = data.get('required_quantity', 1)
        is_case_part = data.get('is_case_part', True)
        part_category = (data.get('part_category') or '').strip()

        if not cabinet_name or not part_number:
            return jsonify({'error': 'cabinet_name and part_number are required'}), 400

        try:
            required_quantity = int(required_quantity)
        except Exception:
            required_quantity = 1

        is_case_part_int = 1 if bool(is_case_part) else 0

        # Default category based on existing logic if not provided
        if not part_category:
            try:
                part_category = bin_manager.case_manager.categorize_part(part_number)
            except Exception:
                part_category = 'custom'

        with sqlite3.connect(bin_manager.case_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO case_parts_requirements
                (cabinet_name, part_number, part_category, required_quantity, is_case_part)
                VALUES (?, ?, ?, ?, ?)
            ''', (cabinet_name, part_number, part_category, required_quantity, is_case_part_int))

            try:
                bin_manager.case_manager.update_case_readiness(cabinet_name, conn)
            except Exception:
                pass

        try:
            bin_manager.invalidate_cabinet_library_cache()
        except Exception:
            pass

        return jsonify({'success': True})

    except Exception as e:
        logging.error(f"Failed to add cabinet library part: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/cabinet_library/part', methods=['PUT'])
def api_cabinet_library_update_part():
    """Update required_quantity and/or is_case_part for a cabinet library part."""
    try:
        if not bin_manager.case_manager:
            return jsonify({'error': 'Case parts logic not available'}), 503

        data = request.get_json(silent=True) or {}
        cabinet_name = (data.get('cabinet_name') or '').strip()
        part_number = (data.get('part_number') or '').strip()

        if not cabinet_name or not part_number:
            return jsonify({'error': 'cabinet_name and part_number are required'}), 400

        required_quantity = data.get('required_quantity', None)
        is_case_part = data.get('is_case_part', None)
        part_category = data.get('part_category', None)

        sets = []
        params = []
        if required_quantity is not None:
            try:
                required_quantity = int(required_quantity)
            except Exception:
                required_quantity = 1
            sets.append('required_quantity = ?')
            params.append(required_quantity)

        if is_case_part is not None:
            sets.append('is_case_part = ?')
            params.append(1 if bool(is_case_part) else 0)

        if part_category is not None:
            sets.append('part_category = ?')
            params.append(str(part_category).strip() or 'custom')

        if not sets:
            return jsonify({'error': 'No fields to update'}), 400

        with sqlite3.connect(bin_manager.case_manager.db_path) as conn:
            cursor = conn.cursor()
            params.extend([cabinet_name, part_number])
            cursor.execute(
                f"UPDATE case_parts_requirements SET {', '.join(sets)} WHERE cabinet_name = ? AND part_number = ?",
                params,
            )
            if cursor.rowcount == 0:
                return jsonify({'error': 'Part not found'}), 404

            try:
                bin_manager.case_manager.update_case_readiness(cabinet_name, conn)
            except Exception:
                pass

        return jsonify({'success': True})

    except Exception as e:
        logging.error(f"Failed to update cabinet library part: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/cabinet_library/part', methods=['DELETE'])
def api_cabinet_library_delete_part():
    """Delete a single part from a cabinet type."""
    try:
        if not bin_manager.case_manager:
            return jsonify({'error': 'Case parts logic not available'}), 503

        data = request.get_json(silent=True) or {}
        cabinet_name = (data.get('cabinet_name') or request.args.get('cabinet_name') or '').strip()
        part_number = (data.get('part_number') or request.args.get('part_number') or '').strip()

        if not cabinet_name or not part_number:
            return jsonify({'error': 'cabinet_name and part_number are required'}), 400

        with sqlite3.connect(bin_manager.case_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'DELETE FROM case_parts_requirements WHERE cabinet_name = ? AND part_number = ?',
                (cabinet_name, part_number),
            )
            deleted = cursor.rowcount

            try:
                bin_manager.case_manager.update_case_readiness(cabinet_name, conn)
            except Exception:
                pass

        return jsonify({'success': True, 'deleted': deleted})

    except Exception as e:
        logging.error(f"Failed to delete cabinet library part: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/cabinet_library/cabinet/<path:cabinet_name>', methods=['DELETE'])
def api_cabinet_library_delete_cabinet(cabinet_name: str):
    """Delete an entire cabinet type from the library."""
    try:
        if not bin_manager.case_manager:
            return jsonify({'error': 'Case parts logic not available'}), 503

        cabinet_name = (cabinet_name or '').strip()
        if not cabinet_name:
            return jsonify({'error': 'cabinet_name is required'}), 400

        with sqlite3.connect(bin_manager.case_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM case_parts_requirements WHERE cabinet_name = ?', (cabinet_name,))
            deleted_parts = cursor.rowcount
            cursor.execute('DELETE FROM case_readiness_status WHERE cabinet_name = ?', (cabinet_name,))
            return jsonify({'success': True, 'deleted_parts': deleted_parts})

    except Exception as e:
        logging.error(f"Failed to delete cabinet type from library: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/cabinet_library/reclassify_drawers', methods=['POST'])
def api_cabinet_library_reclassify_drawers():
    """Globally reclassify drawer-box parts as excluded across all cabinet types.

    Rule:
    - Exclude any part with 'dwr', 'drw', 'drawer' in the name
    - EXCEPT keep '*stretcher*' variants (dwr/drw/drawer stretcher) as case parts
    """
    try:
        if not bin_manager.case_manager:
            return jsonify({'error': 'Case parts logic not available'}), 503

        with sqlite3.connect(bin_manager.case_manager.db_path) as conn:
            cursor = conn.cursor()

            # Cabinets affected (for refreshing case readiness)
            cursor.execute('''
                SELECT DISTINCT cabinet_name
                FROM case_parts_requirements
                WHERE lower(part_number) LIKE '%dwr%'
                   OR lower(part_number) LIKE '%drw%'
                   OR lower(part_number) LIKE '%drawer%'
            ''')
            affected = [r[0] for r in cursor.fetchall()]

            # First: mark all drawer-ish parts as excluded
            cursor.execute('''
                UPDATE case_parts_requirements
                   SET is_case_part = 0,
                       part_category = 'drawer'
                 WHERE (lower(part_number) LIKE '%dwr%'
                     OR lower(part_number) LIKE '%drw%'
                     OR lower(part_number) LIKE '%drawer%')
            ''')
            excluded_count = cursor.rowcount

            # Then: re-include stretcher exceptions
            cursor.execute('''
                UPDATE case_parts_requirements
                   SET is_case_part = 1,
                       part_category = 'stretcher'
                 WHERE lower(part_number) LIKE '%dwr stretcher%'
                    OR lower(part_number) LIKE '%drw stretcher%'
                    OR lower(part_number) LIKE '%drawer stretcher%'
            ''')
            included_count = cursor.rowcount

            # Refresh case readiness for affected cabinet types
            refreshed = 0
            for cab in affected:
                try:
                    bin_manager.case_manager.update_case_readiness(cab, conn)
                    refreshed += 1
                except Exception:
                    pass

        return jsonify({
            'success': True,
            'affected_cabinets': len(affected),
            'excluded_updated': excluded_count,
            'stretcher_included': included_count,
            'refreshed': refreshed,
        })

    except Exception as e:
        logging.error(f"Failed to reclassify drawer parts: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/bin_clear/<int:bin_number>', methods=['POST'])
def api_bin_clear(bin_number):
    """API endpoint to clear all parts from a bin"""
    try:
        success, message = bin_manager.clear_bin(bin_number)
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bin_clear_hold/<int:bin_number>', methods=['POST'])
def api_bin_clear_hold(bin_number):
    """API endpoint to clear hold status from a bin (force clear)"""
    try:
        success, message = bin_manager.clear_hold_if_visually_free(bin_number, operator_id="manual", force=True)
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bin_remove_part', methods=['POST'])
def api_bin_remove_part():
    """API endpoint to remove a specific part from a bin"""
    try:
        data = request.json
        bin_number = data.get('bin_number')
        part_number = data.get('part_number')
        cabinet_name = data.get('cabinet_name', '')
        
        if not bin_number or not part_number:
            return jsonify({'success': False, 'error': 'Missing bin_number or part_number'}), 400
        
        success, message = bin_manager.remove_part_from_bin(bin_number, part_number, cabinet_name)
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/material_inventory')
def api_material_inventory():
    """API endpoint for material inventory"""
    try:
        if not material_tracker:
            return jsonify({'error': 'Material tracking not available'}), 503
        
        inventory = material_tracker.get_material_inventory()
        return jsonify({
            'inventory': inventory,
            'total_materials': len(inventory)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/material_usage_stats')
def api_material_usage_stats():
    """API endpoint for material usage statistics"""
    try:
        if not material_tracker:
            return jsonify({'error': 'Material tracking not available'}), 503
        
        hours_back = request.args.get('hours', 24, type=int)
        stats = material_tracker.get_material_usage_stats(hours_back)
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/process_material_scan', methods=['POST'])
def api_process_material_scan():
    """API endpoint for processing material scans"""
    try:
        if not material_tracker:
            return jsonify({'error': 'Material tracking not available'}), 503
        
        data = request.json
        qr_data = data.get('qr_data', {})
        operator_id = data.get('operator_id', '')
        station_code = data.get('station_code', '')
        
        success, message = material_tracker.process_material_scan(qr_data, operator_id, station_code)
        
        return jsonify({
            'success': success,
            'message': message
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/import_cabinet_library_csv', methods=['POST'])
def api_import_cabinet_library_csv():
    """API endpoint to import cabinet library from CSV file"""
    try:
        if 'csv_file' not in request.files:
            return jsonify({'success': False, 'error': 'No CSV file provided'}), 400
        
        csv_file = request.files['csv_file']
        
        if csv_file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        # Read CSV file
        import csv
        import io
        
        # Read file content
        csv_content = csv_file.read().decode('utf-8')
        csv_reader = csv.DictReader(io.StringIO(csv_content))
        
        # Parse CSV and build cabinet parts data
        cabinet_parts_data = []
        cabinet_types = set()
        
        for row in csv_reader:
            cabinet_type = row.get('cabinet_type', '').strip()
            part_name = row.get('part_name', '').strip()
            quantity = row.get('quantity', '1').strip()
            
            if not cabinet_type or not part_name:
                continue
            
            try:
                qty = int(quantity)
            except:
                qty = 1
            
            cabinet_types.add(cabinet_type)
            cabinet_parts_data.append({
                'cabinet_name': cabinet_type,
                'part_number': part_name,
                'quantity': qty
            })
        
        # Import using case manager (merge with existing data, don't clear)
        if bin_manager.case_manager:
            success = bin_manager.case_manager.import_cabinet_requirements(cabinet_parts_data, clear_existing=False)
        else:
            # Fallback: import into cabinet_recipes table
            with sqlite3.connect(bin_manager.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM cabinet_recipes')
                
                for part_data in cabinet_parts_data:
                    cursor.execute('''
                        INSERT INTO cabinet_recipes (cabinet_name, part_number, required_quantity)
                        VALUES (?, ?, ?)
                    ''', (part_data['cabinet_name'], part_data['part_number'], part_data['quantity']))
                
                success = True
        
        if success:
            logging.info(f"Imported {len(cabinet_parts_data)} parts from CSV for {len(cabinet_types)} cabinet types")
            return jsonify({
                'success': True,
                'message': 'Cabinet library imported successfully',
                'cabinet_types': len(cabinet_types),
                'parts_imported': len(cabinet_parts_data)
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to import cabinet library'
            }), 500
        
    except Exception as e:
        logging.error(f"Failed to import cabinet library from CSV: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

def start_web_server(host=None, port=8080, debug=False):
    """Start the web server for bin monitoring"""
    if host is None:
        host = os.environ.get('INNOSAW_BIND_HOST', '0.0.0.0')
    app.run(host=host, port=port, debug=debug, threaded=True)

def main():
    """Test bin management system"""
    
    # Initialize bin manager
    bin_mgr = BinManager()
    
    # Test adding parts to bins
    print("Testing bin operations...")
    
    test_operations = [
        # (operation, bin_number, part_number, cabinet_name, job_name, quantity, operator)
        ('add', 1, 'DOOR_001', 'Upper_Cabinet_A', 'Kitchen_Project_2024', 2, 'OP001'),
        ('add', 1, 'DOOR_002', 'Upper_Cabinet_A', 'Kitchen_Project_2024', 1, 'OP001'),
        ('add', 2, 'DRAWER_001', 'Base_Cabinet_B', 'Kitchen_Project_2024', 1, 'OP002'),
        ('add', 3, 'PANEL_001', 'Upper_Cabinet_A', 'Kitchen_Project_2024', 2, 'OP001'),
        ('pull', 1, 'DOOR_001', 'Upper_Cabinet_A', '', 0, 'OP003'),
    ]
    
    for op_type, bin_num, part, cabinet, job, qty, operator in test_operations:
        if op_type == 'add':
            success, message = bin_mgr.add_part_to_bin(bin_num, part, cabinet, job, qty, operator)
        elif op_type == 'pull':
            success, message = bin_mgr.pull_part_from_bin(bin_num, part, cabinet, operator)
        
        print(f"{op_type.upper()}: {message}")
    
    # Check bin contents
    print(f"\nBin contents:")
    contents = bin_mgr.get_bin_contents()
    for bin_num in range(1, 6):  # Check first 5 bins
        if contents.get(bin_num):
            print(f"  Bin {bin_num}: {len(contents[bin_num])} items")
            for item in contents[bin_num]:
                print(f"    - {item['part_number']} for {item['cabinet_name']} (qty: {item['quantity']})")
        else:
            print(f"  Bin {bin_num}: Empty")
    
    # Check cabinet status
    print(f"\nCabinet status:")
    cabinet_status = bin_mgr.get_cabinet_status()
    for cabinet_name, status in cabinet_status.items():
        ready_status = "✓ READY" if status['ready_for_assembly'] else f"{status['completion_percentage']:.1f}% complete"
        print(f"  {cabinet_name}: {ready_status} ({status['parts_ready']}/{status['total_parts_required']} parts)")
    
    # Get statistics
    print(f"\nBin statistics:")
    stats = bin_mgr.get_bin_statistics()
    print(f"  Total bins: {stats['total_bins']}")
    print(f"  Occupied bins: {stats['occupied_bins']}")
    print(f"  Empty bins: {stats['empty_bins']} (bins: {stats['empty_bin_list'][:10]}...)")
    print(f"  Ready cabinets: {stats['cabinet_statistics']['ready_cabinets']}/{stats['cabinet_statistics']['total_cabinets']}")

if __name__ == "__main__":
    main()