#!/usr/bin/env python3
"""
Raspberry Pi QR Code Scanner for Manufacturing Operations
Provides structured data output, duplicate detection, and local DB logging.
"""

import json
import time
import logging
import logging.handlers
import threading
import os
import re
from datetime import datetime
from queue import Queue, Full
from pathlib import Path
from path_utils import get_base_dir, resolve_path

# Camera-mode dependencies are lazy-loaded so barcode-only deployments don't
# import OpenCV/pyzbar (and their memory/CPU cost) unless camera mode is
# explicitly enabled and used.
cv2 = None
pyzbar = None
CAMERA_DEPS_AVAILABLE = False

try:
    import RPi.GPIO as GPIO
    GPIO_AVAILABLE = True
except (ImportError, RuntimeError):
    GPIO = None
    GPIO_AVAILABLE = False

try:
    import evdev
    from evdev import ecodes, InputDevice
    EVDEV_AVAILABLE = True
except ImportError:
    evdev = None
    ecodes = None
    InputDevice = None
    EVDEV_AVAILABLE = False

BASE_DIR = get_base_dir()
LOG_DIR = BASE_DIR / 'logs'
if LOG_DIR.exists() and LOG_DIR.is_file():
    # Auto-heal common failure mode: a file named "logs" blocks directory creation
    backup_name = BASE_DIR / f"logs.bak_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    try:
        LOG_DIR.rename(backup_name)
    except Exception:
        # If rename fails (permissions), fall back to unlink
        try:
            LOG_DIR.unlink()
        except Exception:
            pass
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / 'qr_scanner.log'

# Configure logging (rotate to prevent multi-GB logs)
def _build_log_handlers():
    try:
        max_mb = int((os.environ.get('INNOSAW_LOG_MAX_MB') or '50').strip())
    except Exception:
        max_mb = 50
    if max_mb <= 0:
        max_mb = 50

    try:
        backups = int((os.environ.get('INNOSAW_LOG_BACKUPS') or '3').strip())
    except Exception:
        backups = 3
    if backups < 0:
        backups = 0

    rotating = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=max_mb * 1024 * 1024,
        backupCount=backups,
    )
    stream = logging.StreamHandler()
    return [rotating, stream]


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=_build_log_handlers(),
)

class QRScannerConfig:
    """Configuration management for QR Scanner"""
    
    def __init__(self, config_file='config.json'):
        self.config_file = resolve_path(config_file)
        self.default_config = {
            "station_id": "Station_1_H08",
            "station_code": "H08",
            "scanning": {
                "scan_timeout": 5.0,
                "duplicate_timeout": 30.0,
                "auto_advance": True,
                "bin_context_timeout": 20.0,
                "recut_context_timeout": 30.0
            },
            "gpio": {
                "led_pin": 18,
                "buzzer_pin": 16,
                "button_pin": 21
            },
            "input": {
                "mode": "barcode_scanner",
                "barcode_device": "",
                # Safety latch: camera mode is ignored unless explicitly enabled.
                "allow_camera_mode": False
            },
            # Optional: forward scan events to Cloud v2 (disabled by default to preserve legacy behavior)
            "cloud_v2": {
                "enabled": False,
                "base_url": "https://v2.innosaw.work",
                "station_token": "",
                "station_tokens": {},
                # When true, Pi becomes a thin client:
                # - no local parsing/routing/bin logic
                # - forwards raw scans to cloud for server-side processing
                # Still keeps duplicate detection + optional offline queue.
                "thin_mode": False,
                # Do NOT send operator values by default (avoid personal data)
                "send_operator": False,
                "timeout_seconds": 8,
                # Optional local retry queue (JSONL). Leave blank to disable queuing.
                "queue_path": "cloud_queue/scans.jsonl",
                # Optional local append-only archive of all scan payloads (JSONL).
                "archive_path": "cloud_backup/scans_archive.jsonl",
                "flush_batch_size": 200
            }
        }
        self.load_config()
    
    def load_config(self):
        """Load configuration from file or create default"""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = self.default_config.copy()
            self.save_config()
    
    def save_config(self):
        """Save current configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def get(self, key_path, default=None):
        """Get nested configuration value"""
        keys = key_path.split('.')
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

class QRDataParser:
    """Parse and validate QR code data according to station requirements"""
    
    def __init__(self, station_code):
        self.station_code = station_code
        self.routing = {
            "H08": "Station_1_H08", 
            "H10": "Station_2_H10",
            "Edge": "Station_3_Edge", 
            "Dowel": "Station_4_Dowel",
            "Sort": "Station_5_Sorting", 
            "Pull": "Station_6_Pulling",
            "Assembly": "Station_7_Assembly", 
            "QC": "Station_8_QC",
            "Wrap": "Station_9_Wrapping", 
            "Ship": "Station_10_Shipping"
        }
    
    def parse_scan_data(self, scan_text, operator=""):
        """Parse QR scan data into structured format"""
        try:
            parts = [part.strip() for part in scan_text.split(",")]
            timestamp = datetime.now()
            
            if len(parts) < 1:
                raise ValueError(f"Insufficient data parts: {len(parts)}")
            
            # Check if first part is a station code prefix
            # If so, strip it since station is determined by device mapping
            station_prefixes = ["H08", "H10", "QC", "Edge", "Dowel", "Sort", "Pull", "Assembly"]
            first_part = parts[0].strip()
            
            if first_part in station_prefixes:
                # Station prefix detected - strip it
                # Station is determined by USB device, not scan data
                parts = parts[1:]  # Remove station prefix
                logging.debug(f"📝 Stripped station prefix '{first_part}' from scan data")
            
            # Use configured station code (from device mapping)
            station = self.station_code
            
            # Build structured data object
            parsed_data = {
                "timestamp": timestamp,
                "station_code": station,  # Use configured station, not from scan
                "station_sheet": self.routing.get(station),
                "operator": operator,
                "raw_data": scan_text,  # Keep original for logging
                "parts": parts,  # Data parts (station prefix already removed if present)
                "parsed_fields": {}
            }
            
            # Station-specific parsing (parts already have station prefix removed if present)
            #
            # Primary label format (new):
            # {Gcode_Filename},{Part_Num},{Job_Name},{Cab_Name},{Cab_Assembly_Num},{Part_Name},{Part_Material},{Run_Name},{Opening_letter}
            #
            # Backward compatible (old):
            # {Gcode_Filename},{Part_Num},{Job_Name},{Cab_Name},{Cab_Assembly_Num},{Part_Name},{Part_Material},{Opening_letter}
            # or older cutting format (H08/H10): {Gcode_Filename},{Material},{Job_Name},{Qty}
            #
            def _get(i: int) -> str:
                return parts[i] if len(parts) > i else ""

            # Special-case older H08/H10 cutting scans (gcode, material, job, qty)
            if station in ["H08", "H10"] and len(parts) == 4:
                parsed_data["parsed_fields"] = {
                    "gcode": _get(0),
                    "material": _get(1),
                    "job_name": _get(2),
                    "quantity": _get(3),
                }
                return parsed_data

            gcode = _get(0)
            part_num = _get(1)
            job_name = _get(2)
            cab_name = _get(3)
            cab_assembly = _get(4)
            part_name = _get(5)

            material_name = _get(6)
            run_name = ""
            opening_letter = ""
            if len(parts) >= 9:
                run_name = _get(7)
                opening_letter = _get(8)
            elif len(parts) == 8:
                opening_letter = _get(7)
            else:
                # Legacy: no material/run/opening
                material_name = ""
                run_name = ""
                opening_letter = ""

            # Stations that primarily scan part labels
            if station in ["H08", "H10", "Edge", "Dowel", "Assembly", "QC", "Wrap", "Ship"]:
                parsed_data["parsed_fields"] = {
                    "gcode": gcode,
                    "part_num": part_num,
                    "job_name": job_name,
                    "cabinet_name": cab_name,
                    "cabinet_assembly": cab_assembly,
                    "part_name": part_name,
                    "material": material_name,
                    "run_name": run_name,
                    "opening_letter": opening_letter
                }
            elif station in ["Sort", "Pull"]:
                # Sort/Pull stations may scan BIN labels; those are generally handled earlier,
                # but keep robust parsing here for direct station scans.
                if gcode.upper().startswith("BIN") and len(parts) <= 3:
                    parsed_data["parsed_fields"] = {
                        "bin_number": gcode,
                        "part_number": _get(1),
                        "cabinet_assembly": _get(2)
                    }
                else:
                    parsed_data["parsed_fields"] = {
                        "gcode": gcode,
                        "part_num": part_num,
                        "job_name": job_name,
                        "cabinet_name": cab_name,
                        "cabinet_assembly": cab_assembly,
                        "part_name": part_name,
                        "material": material_name,
                        "run_name": run_name,
                        "opening_letter": opening_letter
                    }
            elif station == "QC":
                # QC station accepts any format - just store all parts
                parsed_data["parsed_fields"] = {
                    "data": parts  # Store all parts as-is
                }
            
            return parsed_data
            
        except Exception as e:
            logging.error(f"Parse error for '{scan_text}': {e}")
            raise

def _camera_deps_required():
    global cv2, pyzbar, CAMERA_DEPS_AVAILABLE
    if not CAMERA_DEPS_AVAILABLE:
        try:
            import cv2 as _cv2  # type: ignore
            from pyzbar import pyzbar as _pyzbar  # type: ignore
            cv2 = _cv2
            pyzbar = _pyzbar
            CAMERA_DEPS_AVAILABLE = True
        except Exception as e:
            raise RuntimeError(
                "Camera mode requires OpenCV (cv2) and pyzbar, but they are not available. "
                "Keep input.mode='barcode_scanner' or install camera dependencies. "
                f"(import error: {e})"
            )
        """Process H08/H10 station with start/end time tracking"""
        timestamp = data['timestamp']
        fields = data['parsed_fields']
        parts_list = data.get('parts', [])
        
        # Look for existing entry to update end time
        all_values = sheet.get_all_values()
        matched_row = None
        
        for i in range(len(all_values) - 1, 0, -1):  # Search from bottom
            row = all_values[i]
            if (len(row) > 3 and 
                row[1] == fields['gcode'] and 
                row[3] == fields['job_name']):
                matched_row = i + 1  # Convert to 1-indexed
                break
        
        if matched_row:
            # Update existing row with end time
            sheet.update_cell(matched_row, 11, timestamp.strftime('%Y-%m-%d %H:%M:%S'))
            
            # Calculate duration if start time exists
            start_time_str = sheet.cell(matched_row, 10).value
            if start_time_str:
                try:
                    start_time = datetime.strptime(start_time_str, '%Y-%m-%d %H:%M:%S')
                    duration = (timestamp - start_time).total_seconds() / 60
                    sheet.update_cell(matched_row, 12, f"{duration:.2f}")
                except ValueError:
                    pass
        else:
            # Add new row with start time
            timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            row_data = [timestamp_str]
            row_data.extend(parts_list)
            row_data.append(data['operator'])
            row_data.append(data['station_code'])
            row_data.append(timestamp_str)  # Start time
            row_data.append("")           # End time placeholder
            row_data.append("")           # Duration placeholder
            sheet.append_row(row_data)
    
    def _process_edge_dowel_station(self, sheet, data):
        """Process Edge/Dowel stations with block tracking"""
        timestamp = data['timestamp']
        parts = data['parts']
        
        # Get last row for block calculation
        all_values = sheet.get_all_values()
        time_since = ""
        block_id = "B1"
        
        if len(all_values) > 1:
            last_row = all_values[-1]
            if last_row and last_row[0]:
                try:
                    last_time = datetime.strptime(last_row[0], '%Y-%m-%d %H:%M:%S')
                    diff_minutes = (timestamp - last_time).total_seconds() / 60
                    time_since = f"{diff_minutes:.2f}"
                    last_block = last_row[-1] if last_row[-1] else "B1"
                    last_block_num = int(last_block.replace("B", "")) if last_block.startswith("B") else 1
                    block_id = f"B{last_block_num + 1}" if diff_minutes > 30 else last_block
                except (ValueError, IndexError):
                    pass
        
        row_data = [timestamp.strftime('%Y-%m-%d %H:%M:%S')]
        row_data.extend(parts)
        row_data.append(data['operator'])
        row_data.append(data['station_code'])
        row_data.append(time_since)
        row_data.append(block_id)
        sheet.append_row(row_data)
    
    def _process_sort_pull_station(self, sheet, data):
        """Process Sort/Pull stations with bin tracking"""
        timestamp = data['timestamp']
        fields = data['parsed_fields']
        parts = data.get('parts', [])
        
        # Extract part data from the scan (new format):
        # parts[0]=gcode, parts[1]=part_num, parts[2]=job_name, parts[3]=cab_name,
        # parts[4]=cab_assembly, parts[5]=part_name, parts[6]=part_material, parts[7]=opening_letter
        gcode = parts[0] if len(parts) > 0 else ""
        part_num = parts[1] if len(parts) > 1 else ""
        job_name = parts[2] if len(parts) > 2 else ""
        cab_name = parts[3] if len(parts) > 3 else ""
        cab_assembly = parts[4] if len(parts) > 4 else ""
        part_name = parts[5] if len(parts) > 5 else ""
        
        bin_number = fields.get('bin_number', '')
        pair_validated = fields.get('pair_validated', 'NO')
        
        # Always add a new row for each bin+part scan (no update logic - each scan is unique)
        # Columns: A=Timestamp, B=Gcode, C=Part_Num, D=Job_Name, E=Cab_Name, F=Cab_Assembly, G=Part_Name, H=Operator, I=Station, J=Bin, K=Validated
        row_data = [
            timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            gcode,
            part_num,
            job_name,
            cab_name,
            cab_assembly,
            part_name,
            data['operator'],
            data['station_code'],
            bin_number,
            pair_validated
        ]
        
        try:
            result = sheet.append_row(row_data)
            logging.info(f"📊 Appended {data['station_code']} row to Google Sheets: Bin={bin_number}, Part={gcode}")
            logging.info(f"📊 Sheet response: {result}")
        except Exception as e:
            logging.error(f"❌ Failed to append {data['station_code']} row to sheet: {e}")
    
    def _process_assembly_station(self, sheet, data):
        """Process Assembly station with cabinet tracking"""
        timestamp = data['timestamp']
        parts_list = data.get('parts', [])
        cabinet_num = parts_list[4] if len(parts_list) > 4 else ""
        
        # Look for existing cabinet entry
        all_values = sheet.get_all_values()
        found_row = None
        
        for i in range(len(all_values) - 1, 0, -1):
            row = all_values[i]
            if len(row) > 5 and row[5] == cabinet_num:
                found_row = i + 1
                break
        
        if found_row:
            start_time_str = sheet.cell(found_row, 10).value
            if not start_time_str:
                # Set start time
                sheet.update_cell(found_row, 10, timestamp.strftime('%Y-%m-%d %H:%M:%S'))
            else:
                # Set end time and calculate duration
                sheet.update_cell(found_row, 11, timestamp.strftime('%Y-%m-%d %H:%M:%S'))
                try:
                    start_time = datetime.strptime(start_time_str, '%Y-%m-%d %H:%M:%S')
                    duration = (timestamp - start_time).total_seconds() / 60
                    sheet.update_cell(found_row, 12, f"{duration:.2f}")
                except ValueError:
                    pass
        else:
            # Add new assembly entry
            timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            row_data = [timestamp_str]
            row_data.extend(parts_list)
            row_data.append(data['operator'])
            row_data.append(data['station_code'])
            row_data.append(timestamp_str)  # Start time
            row_data.append("")
            row_data.append("")
            sheet.append_row(row_data)

class BarcodeScannerListener:
    """Read scan strings from a USB barcode scanner (keyboard wedge)."""

    SHIFT_KEYS = {ecodes.KEY_LEFTSHIFT, ecodes.KEY_RIGHTSHIFT} if EVDEV_AVAILABLE else set()

    KEY_MAP = {
        **{f"KEY_{i}": str(i) for i in range(10)},
        "KEY_MINUS": "-",
        "KEY_EQUAL": "=",
        "KEY_SPACE": " ",
        "KEY_COMMA": ",",
        "KEY_DOT": ".",
        "KEY_SLASH": "/",
        "KEY_SEMICOLON": ";",
        "KEY_APOSTROPHE": "'",
        "KEY_LEFTBRACE": "[",
        "KEY_RIGHTBRACE": "]",
        "KEY_BACKSLASH": "\\",
    }
    KEY_MAP.update({f"KEY_{chr(code)}": chr(code + 32) for code in range(ord('A'), ord('Z') + 1)})

    SHIFT_MAP = {
        "KEY_1": "!",
        "KEY_2": "@",
        "KEY_3": "#",
        "KEY_4": "$",
        "KEY_5": "%",
        "KEY_6": "^",
        "KEY_7": "&",
        "KEY_8": "*",
        "KEY_9": "(",
        "KEY_0": ")",
        "KEY_MINUS": "_",
        "KEY_EQUAL": "+",
        "KEY_LEFTBRACE": "{",
        "KEY_RIGHTBRACE": "}",
        "KEY_BACKSLASH": "|",
        "KEY_SEMICOLON": ":",
        "KEY_APOSTROPHE": '"',
        "KEY_COMMA": "<",
        "KEY_DOT": ">",
        "KEY_SLASH": "?",
    }
    SHIFT_MAP.update({f"KEY_{chr(code)}": chr(code) for code in range(ord('A'), ord('Z') + 1)})

    def __init__(self, device_path=None):
        if not EVDEV_AVAILABLE:
            raise RuntimeError("evdev not available; install evdev to use barcode scanners")
        self.device_path = device_path or self._auto_detect_device()
        self._closed = threading.Event()
        self.device = None

        # Optional observability (disabled by default)
        # Set INNOSAW_SCANNER_HEARTBEAT_SECONDS=60 (or similar) to enable.
        try:
            self._heartbeat_interval_s = float(os.getenv('INNOSAW_SCANNER_HEARTBEAT_SECONDS', '0') or '0')
        except Exception:
            self._heartbeat_interval_s = 0.0
        self._last_heartbeat_log_ts = 0.0
        self._last_event_ts = 0.0
        self._last_scan_ts = 0.0
        self._events_seen = 0
        self._scans_yielded = 0
        self._reconnects = 0
        self._last_error_log_ts = 0.0
        self._last_error = ''

        self._open_device()

    def _open_device(self):
        self.device = InputDevice(self.device_path)
        try:
            self.device.grab()
        except OSError:
            logging.warning("Unable to grab %s; scanner keystrokes may reach the desktop", self.device_path)
        logging.info("Using barcode scanner device %s (%s)", self.device_path, self.device.name)
        now = time.time()
        if not self._last_event_ts:
            self._last_event_ts = now
        if not self._last_scan_ts:
            self._last_scan_ts = now

    def _maybe_log_heartbeat(self, now: float) -> None:
        if not self._heartbeat_interval_s or self._heartbeat_interval_s <= 0:
            return
        if self._last_heartbeat_log_ts and (now - self._last_heartbeat_log_ts) < self._heartbeat_interval_s:
            return

        self._last_heartbeat_log_ts = now
        since_event = now - (self._last_event_ts or now)
        since_scan = now - (self._last_scan_ts or now)
        logging.info(
            "Scanner heartbeat: device=%s events=%s scans=%s reconnects=%s since_event=%.1fs since_scan=%.1fs last_error=%s",
            self.device_path,
            self._events_seen,
            self._scans_yielded,
            self._reconnects,
            since_event,
            since_scan,
            (self._last_error or "-"),
        )

    def _auto_detect_device(self):
        devices = evdev.list_devices()
        if not devices:
            raise RuntimeError("No input devices found. Connect the barcode scanner or set input.barcode_device")

        preferred = []
        keyboard_like = []
        diagnostics = []

        for path in devices:
            dev = InputDevice(path)
            try:
                name = (dev.name or "unknown").lower()
                caps = dev.capabilities().get(ecodes.EV_KEY, [])
                has_keyboard = bool(caps) and ecodes.KEY_ENTER in caps
                diagnostics.append(f"{path} ({dev.name})")

                if not has_keyboard:
                    continue

                if any(keyword in name for keyword in ("scanner", "barcode", "honeywell", "symbol", "datalogic")):
                    preferred.append(path)
                else:
                    keyboard_like.append(path)
            finally:
                dev.close()

        logging.info("Input devices detected: %s", ", ".join(diagnostics))

        if preferred:
            return preferred[0]
        if keyboard_like:
            return keyboard_like[0]

        raise RuntimeError(
            "No keyboard-like input devices found. Set input.barcode_device in config.json to the correct /dev/input/eventX path."
        )

    def stream_scans(self):
        """Yield decoded scan strings.

        This blocks while waiting for input, but if the underlying device goes away
        (USB hiccup, hub reset, etc.) we back off and retry instead of spinning.
        """
        buffer = ""
        shift_active = False
        backoff_s = 0.25
        backoff_max_s = 10.0

        while not self._closed.is_set():
            try:
                for event in self.device.read_loop():
                    if self._closed.is_set():
                        return

                    now = time.time()
                    self._last_event_ts = now
                    self._events_seen += 1
                    self._maybe_log_heartbeat(now)

                    if event.type != ecodes.EV_KEY:
                        continue

                    if event.code in self.SHIFT_KEYS:
                        shift_active = event.value == 1
                        continue

                    if event.value != 1:  # only handle key down
                        continue

                    if event.code == ecodes.KEY_ENTER:
                        data = buffer.strip()
                        if data:
                            self._last_scan_ts = time.time()
                            self._scans_yielded += 1
                            yield data
                        buffer = ""
                        continue

                    key_name = evdev.ecodes.KEY[event.code]
                    char = self._lookup_char(key_name, shift_active)
                    shift_active = False
                    if char:
                        buffer += char

                # read_loop should be infinite; if it ends, treat as device issue.
                raise OSError("evdev read_loop ended")
            except Exception as exc:
                if self._closed.is_set():
                    return

                # Avoid tight exception loops on flaky USB devices.
                self._last_error = str(exc)
                now = time.time()
                # Rate-limit warning logs so a flapping device doesn't DOS the SD card.
                if (now - self._last_error_log_ts) >= 5.0:
                    logging.warning(
                        "Barcode device read error (%s). Will retry in %.2fs", exc, backoff_s
                    )
                    self._last_error_log_ts = now
                try:
                    if self.device:
                        try:
                            self.device.ungrab()
                        except Exception:
                            pass
                        try:
                            self.device.close()
                        except Exception:
                            pass
                finally:
                    self.device = None

                time.sleep(backoff_s)
                backoff_s = min(backoff_s * 2.0, backoff_max_s)

                # Attempt to reopen the configured path. If this fails, we keep backing off.
                try:
                    self._reconnects += 1
                    self._open_device()
                    buffer = ""
                    shift_active = False
                    backoff_s = 0.25
                except Exception as reopen_exc:
                    logging.warning(
                        "Barcode device reopen failed (%s). Continuing retries.", reopen_exc
                    )

    def _lookup_char(self, key_name, shift_active):
        if shift_active:
            return self.SHIFT_MAP.get(key_name) or self.KEY_MAP.get(key_name)
        return self.KEY_MAP.get(key_name)

    def close(self):
        self._closed.set()
        try:
            if self.device:
                try:
                    self.device.ungrab()
                except Exception:
                    pass
                self.device.close()
        except Exception:
            pass

class DuplicateDetector:
    """Prevent duplicate scans within timeout period"""
    
    def __init__(self, timeout=30.0):
        self.timeout = timeout
        self.recent_scans = {}
        self.lock = threading.Lock()
    
    def is_duplicate(self, scan_text):
        """Check if scan is duplicate within timeout period"""
        with self.lock:
            current_time = time.time()
            
            # Clean old entries
            expired_keys = []
            for key, timestamp in self.recent_scans.items():
                if current_time - timestamp > self.timeout:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.recent_scans[key]
            
            # Check for duplicate
            if scan_text in self.recent_scans:
                return True
            
            # Record new scan
            self.recent_scans[scan_text] = current_time
            return False

class HardwareController:
    """Control GPIO hardware (LED, buzzer, button)"""
    
    def __init__(self, config):
        self.config = config
        self.enabled = GPIO_AVAILABLE
        self.led_pin = config.get('gpio.led_pin', 18)
        self.buzzer_pin = config.get('gpio.buzzer_pin', 16)
        self.button_pin = config.get('gpio.button_pin', 21)
        
        if not GPIO_AVAILABLE:
            logging.warning("GPIO not available; hardware feedback disabled")
            return
        
        try:
            GPIO.setwarnings(False)
            GPIO.setmode(GPIO.BCM)
            GPIO.setup(self.led_pin, GPIO.OUT)
            GPIO.setup(self.buzzer_pin, GPIO.OUT)
            GPIO.setup(self.button_pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
            self.led_off()
        except Exception as exc:
            logging.warning(f"GPIO initialization failed: {exc}")
            self.enabled = False
    
    def led_on(self):
        """Turn on LED"""
        if self.enabled:
            GPIO.output(self.led_pin, GPIO.HIGH)
    
    def led_off(self):
        """Turn off LED"""
        if self.enabled:
            GPIO.output(self.led_pin, GPIO.LOW)
    
    def beep_success(self):
        """Success beep pattern"""
        if self.enabled:
            GPIO.output(self.buzzer_pin, GPIO.HIGH)
            time.sleep(0.1)
            GPIO.output(self.buzzer_pin, GPIO.LOW)
    
    def beep_error(self):
        """Error beep pattern"""
        if not self.enabled:
            return
        for _ in range(3):
            GPIO.output(self.buzzer_pin, GPIO.HIGH)
            time.sleep(0.1)
            GPIO.output(self.buzzer_pin, GPIO.LOW)
            time.sleep(0.1)
    
    def button_pressed(self):
        """Check if button is pressed"""
        if not self.enabled:
            return False
        return GPIO.input(self.button_pin) == GPIO.LOW
    
    def cleanup(self):
        """Clean up GPIO"""
        if self.enabled:
            GPIO.cleanup()

class QRScanner:
    """Main QR Scanner application"""
    BIN_PATTERN = re.compile(r'^\s*(sort|pull)[\s,_-]*(?:bin[\s,_-]*)?(\d{1,3})\s*$', re.IGNORECASE)
    # Marker scanned BEFORE a part label; the next part label will be logged as a recut/remake
    # Accept common variations: "recut", "recuts", "remake"
    RECUT_PATTERN = re.compile(r'^\s*(recut|recuts|remake)(?:[:\s_-]+(.+))?\s*$', re.IGNORECASE)
    OPERATOR_PATTERNS = [
        # Match operator badges even if scanners prepend extra characters (we use .search())
        re.compile(r'operator[:\s-]+(.+?)\s*$', re.IGNORECASE),
        re.compile(r'login(?:[_\s-]*op)?[:\s-]+(.+?)\s*$', re.IGNORECASE),
        re.compile(r'op(?:erator)?[_\s-]*id[:\s-]+(.+?)\s*$', re.IGNORECASE),
    ]
    
    def __init__(self, config_file='config.json'):
        self.config = QRScannerConfig(config_file)
        self.parser = QRDataParser(self.config.get('station_code'))
        self.duplicate_detector = DuplicateDetector(
            self.config.get('scanning.duplicate_timeout', 30.0)
        )
        self.hardware = HardwareController(self.config)
        requested_mode = (self.config.get('input.mode', 'barcode_scanner') or 'barcode_scanner').lower()
        allow_camera_mode = bool(self.config.get('input.allow_camera_mode', False))
        if requested_mode != 'barcode_scanner' and not allow_camera_mode:
            logging.warning(
                "Input mode '%s' requested but camera mode is disabled. "
                "Forcing input.mode='barcode_scanner'.",
                requested_mode,
            )
            self.input_mode = 'barcode_scanner'
        else:
            self.input_mode = requested_mode
        self.barcode_listener = None
        if self.input_mode == 'barcode_scanner':
            device_path = self.config.get('input.barcode_device')
            self.barcode_listener = BarcodeScannerListener(device_path)
        
        self.current_operator = ""
        self.current_operator_date = ""
        self._load_operator_state()
        self.running = False
        self.camera = None
        # Bound the queue so a burst of unique/noisy decodes can't exhaust RAM.
        try:
            queue_maxsize = int(self.config.get('scanning.queue_maxsize', 200))
        except Exception:
            queue_maxsize = 200
        if queue_maxsize <= 0:
            queue_maxsize = 200
        self.scan_queue = Queue(maxsize=queue_maxsize)
        self.pending_bin = None
        self.pending_recut = None
        self._led_off_timer = None
        self.bin_context_timeout = float(
            self.config.get('scanning.bin_context_timeout', 20.0)
        )
        self.recut_context_timeout = float(
            self.config.get('scanning.recut_context_timeout', 30.0)
        )
        # Recut/remake parts should be put into a known bin for tracking (Bin Manager)
        # Config option: scanning.remake_bin_number (defaults to 99)
        self.remake_bin_number = 99
        try:
            rb = self.config.get('scanning.remake_bin_number', 99)
            self.remake_bin_number = int(str(rb).strip())
        except Exception:
            self.remake_bin_number = 99
        self._cloud_sink = None
        self._cloud_send_operator = False
        # Initialize optional Cloud v2 forwarder (safe: disabled unless explicitly enabled)
        self._init_cloud_v2_forwarder(self.config.get("station_code"))

    def _init_cloud_v2_forwarder(self, station_code: str):
        """Initialize Cloud v2 forwarder based on config and station_code."""
        self._cloud_sink = None
        self._cloud_send_operator = False
        try:
            if not bool(self.config.get("cloud_v2.enabled", False)):
                return

            base_url = (self.config.get("cloud_v2.base_url", "") or "").strip()
            if not base_url:
                logging.warning("cloud_v2.enabled=true but missing cloud_v2.base_url; forwarding disabled.")
                return

            # Token selection priority:
            # 1) cloud_v2.station_tokens[station_code] (multi-scanner best practice)
            # 2) cloud_v2.station_token (single-station / shared token)
            token = ""
            station_tokens = self.config.get("cloud_v2.station_tokens", {})
            if isinstance(station_tokens, dict) and station_code:
                # Be tolerant to casing differences between station config and token map keys.
                token = (station_tokens.get(station_code) or "").strip()
                if not token:
                    token = (station_tokens.get(str(station_code).upper()) or "").strip()
                if not token:
                    token = (station_tokens.get(str(station_code).lower()) or "").strip()
            if not token:
                token = (self.config.get("cloud_v2.station_token", "") or "").strip()
            if not token:
                logging.warning("cloud_v2.enabled=true but missing station token(s); forwarding disabled.")
                return

            from cloud_v2.pi_client import CloudV2Config, CloudV2ScanSink

            queue_path = (self.config.get("cloud_v2.queue_path", "") or "").strip()
            if queue_path:
                qp = Path(queue_path)
                if not qp.is_absolute():
                    qp = (BASE_DIR / qp).resolve()
                queue_path = str(qp)
            else:
                queue_path = None

            archive_path = (self.config.get("cloud_v2.archive_path", "") or "").strip()
            if archive_path:
                ap = Path(archive_path)
                if not ap.is_absolute():
                    ap = (BASE_DIR / ap).resolve()
                archive_path = str(ap)
            else:
                archive_path = None

            try:
                timeout_s = int(self.config.get("cloud_v2.timeout_seconds", 8))
            except Exception:
                timeout_s = 8
            try:
                flush_batch = int(self.config.get("cloud_v2.flush_batch_size", 200))
            except Exception:
                flush_batch = 200

            self._cloud_send_operator = bool(self.config.get("cloud_v2.send_operator", False))
            self._cloud_sink = CloudV2ScanSink(
                CloudV2Config(
                    base_url=base_url,
                    station_token=token,
                    timeout_seconds=timeout_s,
                    queue_path=queue_path,
                    archive_path=archive_path,
                    flush_batch_size=flush_batch,
                )
            )
            logging.info("Cloud v2 forwarding enabled for %s -> %s", station_code or "UNKNOWN", base_url)
        except Exception as e:
            logging.warning("Cloud v2 forwarder init failed (ignored): %s", e)
    
    def initialize_camera(self):
        """Initialize camera for QR scanning"""
        _camera_deps_required()
        try:
            device_id = self.config.get('camera.device_id', 0)
            self.camera = cv2.VideoCapture(device_id)
            
            if not self.camera.isOpened():
                raise RuntimeError(f"Cannot open camera device {device_id}")
            
            # Set camera properties
            resolution = self.config.get('camera.resolution', [640, 480])
            fps = self.config.get('camera.fps', 30)
            
            self.camera.set(cv2.CAP_PROP_FRAME_WIDTH, resolution[0])
            self.camera.set(cv2.CAP_PROP_FRAME_HEIGHT, resolution[1])
            self.camera.set(cv2.CAP_PROP_FPS, fps)
            
            logging.info(f"Camera initialized: {resolution[0]}x{resolution[1]} @ {fps}fps")
            
        except Exception as e:
            logging.error(f"Failed to initialize camera: {e}")
            raise
    
    def scan_qr_codes(self, frame):
        """Scan QR codes from camera frame"""
        _camera_deps_required()
        try:
            # Convert to grayscale for better detection
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            
            # Detect QR codes
            qr_codes = pyzbar.decode(gray)
            
            detected_codes = []
            for qr in qr_codes:
                # Extract QR code data
                data = qr.data.decode('utf-8')
                rect = qr.rect
                
                detected_codes.append({
                    'data': data,
                    'rect': rect,
                    'type': qr.type
                })
                
                # Draw bounding box on frame
                cv2.rectangle(frame, (rect.left, rect.top),
                            (rect.left + rect.width, rect.top + rect.height),
                            (0, 255, 0), 2)
                
                # Add text label
                cv2.putText(frame, data, (rect.left, rect.top - 10),
                           cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 1)
            
            return detected_codes, frame
            
        except Exception as e:
            logging.error(f"QR scanning error: {e}")
            return [], frame
    
    def _operator_setting_keys(self):
        station = self.config.get('station_code') or 'UNKNOWN'
        return (f'current_operator_{station}', f'current_operator_date_{station}')

    def _load_operator_state(self):
        """Load last operator for this station (if from today)."""
        try:
            from database_schema import get_setting, set_setting
            op_key, date_key = self._operator_setting_keys()
            saved_op = (get_setting(op_key, '') or '').strip()
            saved_date = (get_setting(date_key, '') or '').strip()
            today = datetime.now().strftime('%Y-%m-%d')
            if saved_op and saved_date == today:
                self.current_operator = saved_op
                self.current_operator_date = saved_date
                logging.info("Loaded operator for today: %s", saved_op)
            else:
                # Clear stale operator state
                self.current_operator = ""
                self.current_operator_date = today
                set_setting(op_key, '')
                set_setting(date_key, today)
        except Exception as e:
            logging.debug("Operator state load skipped: %s", e)

    def _persist_operator_state(self):
        """Persist current operator for this station for the current day."""
        try:
            from database_schema import set_setting
            op_key, date_key = self._operator_setting_keys()
            set_setting(op_key, self.current_operator or '')
            set_setting(date_key, self.current_operator_date or datetime.now().strftime('%Y-%m-%d'))
        except Exception as e:
            logging.debug("Operator state persist skipped: %s", e)

    def _ensure_operator_for_today(self):
        """Clear operator if day has rolled over (single shift assumption)."""
        today = datetime.now().strftime('%Y-%m-%d')
        cur_date = getattr(self, 'current_operator_date', '')
        if cur_date and cur_date == today:
            return
        # Day changed (or not set): clear operator
        cur_op = getattr(self, 'current_operator', '')
        if cur_op:
            logging.info("New day detected; clearing operator '%s'", cur_op)
        self.current_operator = ""
        self.current_operator_date = today
        self._persist_operator_state()

    def process_scan(self, scan_data):
        """Process a detected QR code"""
        try:
            self._ensure_operator_for_today()
            # Operator badge scans do not hit Google Sheets
            if self._try_handle_operator_scan(scan_data):
                return True
            
            # If configured as a thin client, skip local routing/logic and forward raw scan to cloud.
            if self._cloud_sink and bool(self.config.get("cloud_v2.thin_mode", False)):
                if self.duplicate_detector.is_duplicate(scan_data):
                    logging.warning(f"Duplicate scan ignored: {scan_data}")
                    self.hardware.beep_error()
                    return False

                # Avoid personal data: only send operator if explicitly enabled AND looks like a short code.
                operator_id = None
                if self._cloud_send_operator and self.current_operator:
                    op = (self.current_operator or "").strip()
                    if 1 <= len(op) <= 6 and re.fullmatch(r"[A-Za-z0-9_-]+", op):
                        operator_id = op.upper() if op.isalpha() else op

                payload = {
                    "station_code": self.config.get("station_code"),
                    "station_display_name": getattr(self, "station_display_name", None),
                    "raw_data": scan_data,
                    "operator_id": operator_id,
                }
                delivered = self._cloud_sink.submit_scan(payload)
                if delivered:
                    logging.info("Cloud v2 forwarded scan (thin mode).")
                else:
                    logging.info("Cloud v2 queued scan for retry (thin mode).")
                self.hardware.beep_success()
                self.hardware.led_on()
                try:
                    if self._led_off_timer is not None:
                        self._led_off_timer.cancel()
                except Exception:
                    pass
                self._led_off_timer = threading.Timer(1.0, self.hardware.led_off)
                self._led_off_timer.daemon = True
                self._led_off_timer.start()
                return True

            # Bin routing scans are lightweight and do not require parsing
            if self._try_handle_bin_scan(scan_data):
                return True

            # Recut marker: next part scan becomes a recut record
            if self._try_handle_recut_scan(scan_data):
                return True
            
            # Check for duplicates - BUT skip if there's a pending Pull context
            # (Pull operations need to scan the same part that was just sorted)
            has_pending_pull = (self.pending_bin and 
                               self.pending_bin.get('station') == 'Pull' and 
                               not self._pending_bin_expired())
            # Also skip duplicate blocking if we have a pending RECUT marker,
            # because the recut workflow commonly re-scans the same label.
            has_pending_recut = (self.pending_recut and (not self._pending_recut_expired()))
            
            if not has_pending_pull and not has_pending_recut and self.duplicate_detector.is_duplicate(scan_data):
                logging.warning(f"Duplicate scan ignored: {scan_data}")
                self.hardware.beep_error()
                return False
            
            # Parse scan data
            parsed_data = self.parser.parse_scan_data(scan_data, self.current_operator)
            
            # Log to database (triggers auto-consumption for H08/H10)
            try:
                from database_schema import log_scan
                log_scan(
                    station_code=parsed_data['station_code'],
                    station_display_name=getattr(self, 'station_display_name', None),
                    raw_data=parsed_data['raw_data'],
                    parsed_fields=parsed_data['parsed_fields'],
                    operator_id=self.current_operator if self.current_operator else None
                )
            except Exception as e:
                logging.warning(f"Failed to log scan to database: {e}")

            # If we have a pending recut context, log recut for this part scan
            try:
                self._maybe_emit_recut_event(parsed_data)
            except Exception as e:
                logging.warning(f"Failed to log recut event: {e}")
            
            logging.info(f"Successfully processed scan: {scan_data}")
            self.hardware.beep_success()
            self.hardware.led_on()
            
            # Brief LED indication (avoid spawning unbounded timer threads)
            try:
                if self._led_off_timer is not None:
                    self._led_off_timer.cancel()
            except Exception:
                pass
            self._led_off_timer = threading.Timer(1.0, self.hardware.led_off)
            self._led_off_timer.daemon = True
            self._led_off_timer.start()
            
            # Pair with pending bin assignment if present
            self._maybe_emit_bin_event(parsed_data)

            # Forward to Cloud v2 (optional)
            try:
                if self._cloud_sink:
                    # Avoid personal data: only send operator if explicitly enabled AND looks like a short code.
                    operator_id = None
                    if self._cloud_send_operator and self.current_operator:
                        op = (self.current_operator or "").strip()
                        if 1 <= len(op) <= 6 and re.fullmatch(r"[A-Za-z0-9_-]+", op):
                            operator_id = op.upper() if op.isalpha() else op

                    payload = {
                        "station_code": parsed_data.get("station_code"),
                        "station_display_name": getattr(self, "station_display_name", None),
                        "raw_data": parsed_data.get("raw_data"),
                        "parsed_fields": parsed_data.get("parsed_fields") or {},
                        "operator_id": operator_id,
                    }
                    self._cloud_sink.submit_scan(payload)
            except Exception as e:
                logging.debug("Cloud v2 forward skipped: %s", e)
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to process scan '{scan_data}': {e}")
            self.hardware.beep_error()
            return False
    
    def run(self):
        """Main scanner loop"""
        self.running = True
        logging.info(
            "Starting QR Scanner for station %s (mode: %s)",
            self.config.get('station_code'),
            self.input_mode
        )
        try:
            if self.input_mode == 'barcode_scanner':
                self._run_barcode_mode()
            else:
                # Extra guardrail: camera mode must be explicitly enabled.
                if not bool(self.config.get('input.allow_camera_mode', False)):
                    raise RuntimeError(
                        "Camera mode is disabled by config. Set input.allow_camera_mode=true "
                        "only when you intentionally want camera scanning."
                    )
                self._run_camera_mode()
        except KeyboardInterrupt:
            logging.info("Scanner stopped by user")
        except Exception as e:
            logging.error(f"Scanner error: {e}")
        finally:
            self.cleanup()

    def _run_camera_mode(self):
        _camera_deps_required()
        self.initialize_camera()
        processing_thread = threading.Thread(target=self._processing_loop)
        processing_thread.daemon = True
        processing_thread.start()

        scan_timeout = float(self.config.get('scanning.scan_timeout', 5.0))
        # Use a pruning duplicate detector to avoid unbounded growth.
        camera_dedupe = DuplicateDetector(timeout=scan_timeout)

        while self.running:
            ret, frame = self.camera.read()
            if not ret:
                logging.error("Failed to read frame from camera")
                break

            detected_codes, annotated_frame = self.scan_qr_codes(frame)
            for code in detected_codes:
                scan_data = code['data']
                if camera_dedupe.is_duplicate(scan_data):
                    continue
                try:
                    self.scan_queue.put_nowait(scan_data)
                except Full:
                    # Drop scans if the processing thread can't keep up.
                    # This keeps the process healthy under overload/noisy input.
                    logging.warning("Scan queue full; dropping scan")

            try:
                cv2.imshow('QR Scanner', annotated_frame)
                key = cv2.waitKey(1) & 0xFF
                if key in (ord('q'), 27):
                    break
                if key == ord('r'):
                    logging.info("Manual restart requested")
                    break
            except cv2.error:
                time.sleep(0.1)

            if self.hardware.button_pressed():
                logging.info("Hardware button pressed - stopping scanner")
                break

    def _run_barcode_mode(self):
        if not self.barcode_listener:
            raise RuntimeError("Barcode input selected but no listener configured")
        logging.info("Listening for barcode scans on %s", self.barcode_listener.device_path)
        for scan_data in self.barcode_listener.stream_scans():
            if not self.running:
                break
            self.process_scan(scan_data)
            if self.hardware.button_pressed():
                logging.info("Hardware button pressed - stopping scanner")
                break
    
    def _processing_loop(self):
        """Background thread for processing scans"""
        while self.running:
            try:
                # Get scan from queue (with timeout)
                scan_data = self.scan_queue.get(timeout=1.0)
                self.process_scan(scan_data)
                self.scan_queue.task_done()
            except:
                continue  # Timeout or queue empty
    
    def _try_handle_operator_scan(self, scan_text):
        text = scan_text.strip()
        for pattern in self.OPERATOR_PATTERNS:
            match = pattern.search(text)
            if not match:
                continue
            operator_value = match.group(1).strip()
            if not operator_value:
                continue
            # Normalize shorthand codes like JM -> uppercase, but keep names as-is
            if len(operator_value) <= 4 and operator_value.isalpha():
                operator_value = operator_value.upper()
            self.current_operator = operator_value
            self.current_operator_date = datetime.now().strftime('%Y-%m-%d')
            self._persist_operator_state()
            logging.info("Operator logged in: %s", operator_value)
            self.hardware.beep_success()
            return True
        return False

    def _try_handle_bin_scan(self, scan_text):
        match = self.BIN_PATTERN.match(scan_text.strip())
        if not match:
            return False
        station = match.group(1).capitalize()
        bin_number = match.group(2).zfill(2)
        if station not in ("Sort", "Pull"):
            return False
        bin_code = f"BIN{bin_number}"
        self.pending_bin = {
            'station': station,
            'bin_code': bin_code,
            'raw_text': scan_text.strip(),
            'timestamp': time.time()
        }
        logging.info("Captured %s bin context for %s", station, bin_code)
        self.hardware.beep_success()
        return True

    def _pending_recut_expired(self):
        if not self.pending_recut:
            return False
        return (time.time() - self.pending_recut['timestamp']) > self.recut_context_timeout

    def _try_handle_recut_scan(self, scan_text):
        """If scan is a RECUT marker, store a short-lived context for the next part scan."""
        text = scan_text.strip()
        # Some scanners prefix the station code (e.g., "Edge,recut"). Strip known prefixes for marker matching.
        try:
            parts = [p.strip() for p in text.split(',')]
            station_prefixes = {"H08", "H10", "QC", "Edge", "Dowel", "Sort", "Pull", "Assembly", "Wrap", "Ship"}
            if len(parts) >= 2 and parts[0] in station_prefixes:
                # For marker scans, we only care about the remaining payload
                text = ','.join(parts[1:]).strip()
        except Exception:
            pass

        m = self.RECUT_PATTERN.match(text)
        if not m:
            return False
        keyword = (m.group(1) or '').strip().lower()
        detail = (m.group(2) or '').strip()
        self.pending_recut = {
            'keyword': keyword or 'recut',
            'detail': detail,
            'raw_text': text,
            'timestamp': time.time(),
            'operator': self.current_operator or None
        }
        logging.info("Captured RECUT context (%s)", self.pending_recut.get('keyword'))
        self.hardware.beep_success()
        return True

    def _maybe_emit_recut_event(self, parsed_data):
        if not self.pending_recut:
            return
        if self._pending_recut_expired():
            logging.warning("Pending RECUT context expired before part scan")
            self.pending_recut = None
            return
        fields = parsed_data.get('parsed_fields') or {}
        # Only accept true part-label scans (must have gcode + job or cabinet/part)
        if not fields.get('gcode'):
            return
        try:
            # Match the Recuts page "Add Recut" reason values
            allowed = {'defect', 'damage', 'wrong_material', 'machine_error'}
            keyword = (self.pending_recut.get('keyword') or '').strip().lower()
            detail = (self.pending_recut.get('detail') or '').strip().lower()
            detail_norm = detail.replace(' ', '_').replace('-', '_')

            reason_value = None
            if detail_norm in allowed:
                reason_value = detail_norm
            elif 'damage' in detail_norm:
                reason_value = 'damage'
            elif 'wrong' in detail_norm and 'material' in detail_norm:
                reason_value = 'wrong_material'
            elif 'material' == detail_norm:
                reason_value = 'wrong_material'
            elif 'machine' in detail_norm or 'error' in detail_norm or 'tool' in detail_norm:
                reason_value = 'machine_error'

            if not reason_value:
                # If they explicitly scanned "remake", default to defect; otherwise default to defect as a safe baseline.
                reason_value = 'defect'

            notes = f"Scanner marker: {self.pending_recut.get('raw_text')}"
            if detail and detail_norm not in allowed:
                notes += f" | detail: {detail}"

            from database_schema import log_recut
            log_recut(
                machine=parsed_data.get('station_code'),
                parsed_fields=fields,
                operator_id=self.pending_recut.get('operator'),
                reason=reason_value,
                notes=notes
            )
            logging.info("📌 RECUT logged for %s %s", fields.get('job_name'), fields.get('part_name'))
            # Also put this part into the remake bin (Bin Manager) for easy physical tracking
            try:
                bin_code = f"BIN{str(self.remake_bin_number).zfill(2)}"
                self._submit_bin_record("Sort", bin_code, parsed_data)
                logging.info("📦 Added RECUT part to remake bin %s", bin_code)
            except Exception as exc:
                logging.warning("Failed to add RECUT part to remake bin: %s", exc)
        finally:
            self.pending_recut = None
    
    def _pending_bin_expired(self):
        if not self.pending_bin:
            return False
        return (time.time() - self.pending_bin['timestamp']) > self.bin_context_timeout
    
    def _maybe_emit_bin_event(self, last_scan_data):
        if not self.pending_bin:
            return
        if self._pending_bin_expired():
            logging.warning(
                "Pending %s bin %s expired before part scan",
                self.pending_bin['station'],
                self.pending_bin['bin_code']
            )
            self.pending_bin = None
            return
        station = self.pending_bin['station']
        bin_code = self.pending_bin['bin_code']
        try:
            # Pass part data to record for proper logging and bin management
            self._submit_bin_record(station, bin_code, last_scan_data)
            logging.info(
                "Logged %s bin %s after scan %s",
                station,
                bin_code,
                last_scan_data.get('raw_data', 'unknown')
            )
        except Exception as exc:
            logging.error("Failed to log %s bin %s: %s", station, bin_code, exc)
        finally:
            self.pending_bin = None
    
    def _submit_bin_record(self, station_code, bin_code, part_data=None):
        """Submit bin record to Google Sheets AND update bin database"""
        station_sheet = self.parser.routing.get(station_code)
        if not station_sheet:
            logging.error("No station sheet mapping for %s", station_code)
            return
        
        timestamp = datetime.now()
        
        # Extract part info from the scanned data
        part_number = ""
        cabinet_name = ""
        job_name = ""
        raw_data = ""
        material = ""
        cab_assembly_num = ""
        part_name = ""
        part_num = ""
        run_name = ""
        opening_letter = ""
        canonical_part_key = ""
        
        if part_data:
            raw_data = part_data.get('raw_data', '')
            parts = part_data.get('parts', [])
            fields = part_data.get('parsed_fields', {})
            
            # New format:
            # gcode, part_num, job_name, cab_name, cab_assembly, part_name, part_material, opening_letter?
            part_number = fields.get('gcode') or (parts[0] if len(parts) > 0 else "")
            part_num = fields.get('part_num') or (parts[1] if len(parts) > 1 else "")
            job_name = fields.get('job_name') or (parts[2] if len(parts) > 2 else "")
            cabinet_name = fields.get('cabinet_name') or (parts[3] if len(parts) > 3 else "")
            cab_assembly_num = fields.get('cabinet_assembly') or (parts[4] if len(parts) > 4 else "")
            part_name = fields.get('part_name') or (parts[5] if len(parts) > 5 else "")

            # New format: gcode, part_num, job, cab_name, cab_assembly, part_name, material, run_name, opening_letter
            material = fields.get('material') or (parts[6] if len(parts) > 6 else "")
            if len(parts) >= 9:
                run_name = fields.get('run_name') or parts[7]
                opening_letter = fields.get('opening_letter') or parts[8]
            else:
                run_name = fields.get('run_name') or ""
                opening_letter = fields.get('opening_letter') or (parts[7] if len(parts) > 7 else "")

            # Use station-independent canonical key for matching (avoids Edge/H08 prefixes differing per station)
            # parts list is already station-prefix-stripped by the parser.
            try:
                canonical_part_key = ",".join([p for p in (parts or []) if p is not None])
            except Exception:
                canonical_part_key = ""
        
        # Extract bin number (remove BIN prefix if present)
        bin_number = int(bin_code.replace('BIN', '').strip()) if 'BIN' in bin_code else int(bin_code)
        bin_formatted = f"BIN{str(bin_number).zfill(2)}"
        
        # Update bin database (add or remove part)
        try:
            from bin_management import BinManager
            bin_manager = BinManager()
            
            if station_code == "Sort":
                # Add part to bin - store station-independent canonical label so Pull can match from any station
                success, message = bin_manager.add_part_to_bin(
                    bin_number=bin_number,
                    part_number=canonical_part_key or raw_data or part_number,
                    cabinet_name=cab_assembly_num or cabinet_name,
                    job_name=job_name,
                    quantity=1,
                    operator_id=self.current_operator,
                    station_code=station_code,
                    cabinet_type=cabinet_name or "",
                    part_name=part_name or "",
                    gcode=part_number or ""
                )
                logging.info(f"📥 BIN ADD: {message}")
            elif station_code == "Pull":
                # Remove part from bin - match on canonical label (same string regardless of station prefix)
                success, message = bin_manager.pull_part_from_bin(
                    bin_number=bin_number,
                    part_number=canonical_part_key or raw_data or part_number,
                    cabinet_name=cab_assembly_num or cabinet_name,
                    operator_id=self.current_operator,
                    station_code=station_code
                )
                logging.info(f"📤 BIN PULL: {message}")
        except ImportError:
            logging.warning("BinManager not available - bin database not updated")
        except Exception as e:
            logging.error(f"Failed to update bin database: {e}")
        
        # Google Sheets integration removed; bin events are persisted via local DB only.
    
    def cleanup(self):
        """Clean up resources"""
        self.running = False
        
        if self.camera:
            self.camera.release()
        
        if self.barcode_listener:
            self.barcode_listener.close()
        try:
            cv2.destroyAllWindows()
        except cv2.error:
            pass
        self.hardware.cleanup()
        
        logging.info("Scanner cleanup completed")

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Raspberry Pi QR Scanner')
    parser.add_argument('--config', default='config.json',
                       help='Configuration file path')
    parser.add_argument('--station', 
                       help='Override station code')
    
    args = parser.parse_args()
    
    try:
        # Create scanner instance
        scanner = QRScanner(args.config)
        
        # Override station if specified
        if args.station:
            scanner.config.config['station_code'] = args.station
            scanner.parser = QRDataParser(args.station)
        
        # Run scanner
        scanner.run()
        
    except Exception as e:
        logging.error(f"Failed to start scanner: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())