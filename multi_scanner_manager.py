#!/usr/bin/env python3
"""
Multi-Scanner Manager for Single Pi with USB Hub
Handles multiple Tera USB dongles connected via USB hub
Supports Sort/Pull routing from any station
"""

import logging
import threading
import re
import json
from datetime import datetime
from pathlib import Path
import json
import time
from pathlib import Path
from queue import Queue
from datetime import datetime
from qr_scanner import (
    QRScanner, QRScannerConfig, QRDataParser,
    DuplicateDetector, HardwareController,
    BarcodeScannerListener
)
from path_utils import resolve_path

# Global lock for thread-safe scan processing
# Prevents data jumbling when multiple scanners scan simultaneously
SCAN_PROCESS_LOCK = threading.Lock()

# Import bin management for Sort/Pull operations
try:
    from bin_management import BinManager
    BIN_MANAGER_AVAILABLE = True
except ImportError:
    BinManager = None
    BIN_MANAGER_AVAILABLE = False
    logging.warning("BinManager not available - Sort/Pull bin operations disabled")

class MultiScannerManager:
    """Manage multiple scanners on one Pi"""
    
    def __init__(self, config_file='config.json'):
        self.config_file = resolve_path(config_file)
        self.config = QRScannerConfig(str(self.config_file))
        self.scanners = {}
        self.scanner_threads = {}
        self.running = False

        self._cfg_lock = threading.Lock()
        self._config_watch_stop = threading.Event()
        self._config_watch_thread = None
        self._config_mtime_ns = None
        
        # Load scanner configurations
        self.scanner_configs = self._read_scanner_configs()
        
        if not self.scanner_configs:
            logging.warning("⚠️  No scanners configured in config.json 'scanners' section")
            logging.warning("   Run detect_dongles.py to find connected devices")

    def _read_scanner_configs(self) -> dict:
        """Read scanners mapping directly from config.json.

        We intentionally read the raw JSON file rather than relying on
        QRScannerConfig so we can detect live edits made by the admin UI.
        """
        try:
            if not self.config_file.exists():
                return {}
            with open(self.config_file, 'r') as f:
                cfg = json.load(f)
            scanners = cfg.get('scanners', {})
            return scanners if isinstance(scanners, dict) else {}
        except Exception as e:
            logging.warning(f"⚠️  Could not read scanners from {self.config_file}: {e}")
            return {}

    def _get_config_mtime_ns(self):
        try:
            return self.config_file.stat().st_mtime_ns
        except Exception:
            return None

    def _start_config_watch(self):
        if self._config_watch_thread and self._config_watch_thread.is_alive():
            return
        self._config_watch_stop.clear()
        self._config_mtime_ns = self._get_config_mtime_ns()
        t = threading.Thread(target=self._watch_config_loop, daemon=True)
        t.start()
        self._config_watch_thread = t

    def _stop_config_watch(self):
        try:
            self._config_watch_stop.set()
            if self._config_watch_thread and self._config_watch_thread.is_alive():
                self._config_watch_thread.join(timeout=2.0)
        except Exception:
            pass

    def _watch_config_loop(self):
        """Poll config.json for updates and apply deltas live."""
        while not self._config_watch_stop.is_set():
            try:
                mtime = self._get_config_mtime_ns()
                if mtime and mtime != self._config_mtime_ns:
                    self._config_mtime_ns = mtime
                    new_configs = self._read_scanner_configs()
                    self._apply_scanner_config_delta(new_configs)
            except Exception as e:
                logging.debug(f"Config watch loop error: {e}")
            time.sleep(2.0)

    def _apply_scanner_config_delta(self, new_configs: dict):
        """Apply changes to scanner mappings without restarting the whole service."""
        if not isinstance(new_configs, dict):
            return

        with self._cfg_lock:
            old_configs = self.scanner_configs or {}

            old_paths = set(old_configs.keys())
            new_paths = set(new_configs.keys())

            removed = old_paths - new_paths
            added = new_paths - old_paths
            common = old_paths & new_paths

            # Stop removed scanners
            for device_path in removed:
                scanner = self.scanners.get(device_path)
                if scanner:
                    try:
                        logging.info(f"🛑 Removing scanner mapping: {device_path}")
                        scanner.running = False
                        if scanner.barcode_listener:
                            try:
                                scanner.barcode_listener.close()
                            except Exception:
                                pass
                    except Exception:
                        pass
                self.scanners.pop(device_path, None)
                self.scanner_threads.pop(device_path, None)

            # Add new scanners
            for device_path in added:
                station_config = new_configs.get(device_path, {}) or {}
                station_code = station_config.get('station_code')
                if not station_code:
                    logging.warning(f"⚠️  New mapping missing station_code: {device_path}")
                    continue
                try:
                    logging.info(f"➕ Adding scanner mapping: {device_path} → {station_code}")
                    scanner = self._create_scanner(device_path, station_config)
                    self.scanners[device_path] = scanner
                    if self.running:
                        thread = threading.Thread(
                            target=self._run_scanner,
                            args=(scanner, device_path),
                            daemon=True
                        )
                        thread.start()
                        self.scanner_threads[device_path] = thread
                except Exception as e:
                    logging.error(f"❌ Failed to add scanner {device_path}: {e}")

            # Restart scanners whose station assignment changed
            for device_path in common:
                old = old_configs.get(device_path, {}) or {}
                new = new_configs.get(device_path, {}) or {}
                if (old.get('station_code') != new.get('station_code')):
                    new_code = new.get('station_code')
                    logging.info(
                        f"🔁 Scanner mapping changed: {device_path} {old.get('station_code')} → {new_code}"
                    )
                    # Update cached config first, so restart uses fresh values.
                    self.scanner_configs[device_path] = new
                    self.restart_scanner(
                        device_path,
                        station_code=new.get('station_code')
                    )

            self.scanner_configs = new_configs

    def _create_scanner(self, device_path: str, station_config: dict):
        station_code = station_config.get('station_code')
        station_display_name = station_config.get('display_name')
        if not station_code:
            raise ValueError(f"No station_code for {device_path}")
        return QRScannerForStation(
            config_file=str(self.config_file),
            device_path=device_path,
            station_code=station_code,
            station_display_name=station_display_name
        )
    
    def load_scanners(self):
        """Load all configured scanners"""
        # Refresh mappings in case config.json changed since initialization.
        self.scanner_configs = self._read_scanner_configs()
        if not self.scanner_configs:
            return
        
        logging.info(f"📷 Loading {len(self.scanner_configs)} scanner(s)...")
        
        for device_path, station_config in self.scanner_configs.items():
            try:
                # Create scanner instance with specific station code
                scanner = self._create_scanner(device_path, station_config)
                
                self.scanners[device_path] = scanner
                logging.info(f"✅ Configured scanner: {device_path} → {station_config.get('station_code')}")
                
            except Exception as e:
                logging.error(f"❌ Failed to load scanner {device_path}: {e}")
    
    def start_all(self):
        """Start all scanners in separate threads"""
        # Ensure we have up-to-date scanner mappings.
        if not self.scanners and self._read_scanner_configs():
            self.load_scanners()

        if not self.scanners:
            logging.warning("⚠️  No scanners to start")
            return
        
        self.running = True
        logging.info(f"🚀 Starting {len(self.scanners)} scanner(s)...")
        
        for device_path, scanner in self.scanners.items():
            try:
                thread = threading.Thread(
                    target=self._run_scanner,
                    args=(scanner, device_path),
                    daemon=True
                )
                thread.start()
                self.scanner_threads[device_path] = thread
                logging.info(f"✅ Started scanner thread: {device_path}")
            except Exception as e:
                logging.error(f"❌ Failed to start scanner {device_path}: {e}")

        # Watch for config.json edits from the admin UI.
        self._start_config_watch()
    
    def _run_scanner(self, scanner, device_path):
        """Run a single scanner in its thread"""
        try:
            logging.info(f"📷 Scanner {device_path} running...")
            scanner.run()
        except Exception as e:
            logging.error(f"❌ Scanner {device_path} error: {e}")
    
    def stop_all(self):
        """Stop all scanners"""
        logging.info("🛑 Stopping all scanners...")
        self.running = False

        self._stop_config_watch()
        
        for device_path, scanner in self.scanners.items():
            try:
                scanner.running = False
                if scanner.barcode_listener:
                    scanner.barcode_listener.close()
                logging.info(f"✅ Stopped scanner: {device_path}")
            except Exception as e:
                logging.error(f"❌ Error stopping scanner {device_path}: {e}")
        
        self.scanners.clear()
        self.scanner_threads.clear()
    
    def get_scanner_count(self):
        """Get number of configured scanners"""
        return len(self.scanners)
    
    def get_scanner_status(self):
        """Get status of all scanners"""
        status = {}
        for device_path, scanner in self.scanners.items():
            status[device_path] = {
                'station_code': scanner.parser.station_code,
                'running': scanner.running,
                'thread_alive': self.scanner_threads.get(device_path, threading.Thread()).is_alive() if device_path in self.scanner_threads else False
            }
        return status
    
    def restart_scanner(self, device_path, station_code=None):
        """Restart a single scanner without affecting others"""
        if device_path not in self.scanners:
            return False, f"Scanner not found: {device_path}"
        
        try:
            scanner = self.scanners[device_path]
            effective_station_code = station_code or scanner.station_code
            
            logging.info(f"🔄 Restarting scanner {effective_station_code} ({device_path})...")
            
            # Stop the existing scanner
            scanner.running = False
            if scanner.barcode_listener:
                try:
                    scanner.barcode_listener.close()
                except:
                    pass
            
            # Wait for thread to finish
            if device_path in self.scanner_threads:
                old_thread = self.scanner_threads[device_path]
                if old_thread.is_alive():
                    old_thread.join(timeout=2)
            
            # Get station config
            station_config = (self.scanner_configs or {}).get(device_path, {}) or {}
            
            # Create new scanner instance
            new_scanner = QRScannerForStation(
                config_file=str(self.config_file),
                device_path=device_path,
                station_code=effective_station_code
            )
            
            self.scanners[device_path] = new_scanner
            
            # Start new thread
            thread = threading.Thread(
                target=self._run_scanner,
                args=(new_scanner, device_path),
                daemon=True
            )
            thread.start()
            self.scanner_threads[device_path] = thread
            
            logging.info(f"✅ Scanner {effective_station_code} restarted successfully")
            return True, f"Scanner {effective_station_code} restarted"
            
        except Exception as e:
            logging.error(f"❌ Failed to restart scanner {device_path}: {e}")
            return False, str(e)

class QRScannerForStation(QRScanner):
    """QR Scanner configured for a specific station and device
    
    Supports Sort/Pull routing: when a scan contains "Sort" or "Pull" prefix,
    it routes to bin manager updates accordingly.
    """
    
    # Pattern to detect Sort/Pull routing in scan data
    # Matches: "Sort,BIN01,PartNum,CabinetName,..." or "Pull,BIN05,PartNum,..."
    SORT_PULL_PATTERN = re.compile(
        r'^(Sort|Pull)\s*[,\s]\s*(?:BIN)?(\d{1,3})\s*[,\s]\s*([^,]+)\s*[,\s]\s*([^,]+)(?:\s*[,\s]\s*(.*))?$',
        re.IGNORECASE
    )
    
    # Simpler pattern for just Sort/Pull with bin number
    SIMPLE_SORT_PULL_PATTERN = re.compile(
        r'^(Sort|Pull)\s*[,\s]\s*(?:BIN)?(\d{1,3})(?:\s*[,\s]\s*(.*))?$',
        re.IGNORECASE
    )
    
    def __init__(self, config_file='config.json', device_path=None, 
                 station_code=None, station_display_name=None):
        # Load base config
        self.config = QRScannerConfig(config_file)
        
        # Override station code if provided
        if station_code:
            self.config.config['station_code'] = station_code
            self.config.config['station_id'] = station_code
        
        # Initialize with overridden config
        self.parser = QRDataParser(station_code or self.config.get('station_code'))
        self.duplicate_detector = DuplicateDetector(
            self.config.get('scanning.duplicate_timeout', 30.0)
        )
        self.hardware = HardwareController(self.config)
        
        # Set up barcode listener with specific device
        self.input_mode = 'barcode_scanner'
        self.barcode_listener = None
        if device_path:
            try:
                self.barcode_listener = BarcodeScannerListener(device_path)
                logging.info(f"📷 Using barcode scanner device: {device_path}")
            except Exception as e:
                logging.error(f"❌ Failed to initialize scanner {device_path}: {e}")
                raise
        
        self.current_operator = ""
        self.current_operator_date = ""
        try:
            # Persist operator per-station for the day (shared DB settings)
            self._load_operator_state()
        except Exception as e:
            logging.debug(f"Operator state init skipped: {e}")
        self.running = False
        self.camera = None
        # Match QRScanner behavior: keep queues bounded to protect RAM.
        self.scan_queue = Queue(maxsize=200)
        self.pending_bin = None
        self.bin_context_timeout = float(
            self.config.get('scanning.bin_context_timeout', 20.0)
        )

        # Recut marker context (shared implementation lives in QRScanner.process_scan)
        self.pending_recut = None
        self.recut_context_timeout = float(
            self.config.get('scanning.recut_context_timeout', 30.0)
        )
        # Default remake bin for recut/remake parts
        self.remake_bin_number = 99
        try:
            rb = self.config.get('scanning.remake_bin_number', 99)
            self.remake_bin_number = int(str(rb).strip())
        except Exception:
            self.remake_bin_number = 99
        
        # Store station info
        self.station_code = station_code or self.config.get('station_code')
        # Human-friendly identity (e.g. "Assembly 1") used for logging/search/timing.
        self.station_display_name = (station_display_name or '').strip() or self.station_code
        self.device_path = device_path

        # Thin/local: always keep a local raw scan archive that includes station_code
        # (independent of cloud forwarding). This prevents "Unknown station" in local views
        # even when scan prefixes are stripped before logging.
        self._local_archive_file = None
        try:
            cfg = (self.config.config or {})
            thin_cfg = (cfg.get('thin') or {}) if isinstance(cfg.get('thin'), dict) else {}
            archive_path = (thin_cfg.get('local_archive_path') or cfg.get('local_archive_path') or 'local_backup/raw_scans.jsonl')
            ap = Path(str(archive_path)).expanduser()
            if not ap.is_absolute():
                ap = (Path(__file__).resolve().parent / ap).resolve()
            ap.parent.mkdir(parents=True, exist_ok=True)
            self._local_archive_file = ap
        except Exception:
            self._local_archive_file = None

        # Optional Cloud v2 forwarder (multi-scanner uses per-station station_code)
        # QRScannerForStation bypasses QRScanner.__init__, so initialize forwarder here.
        self._cloud_sink = None
        self._cloud_send_operator = False
        try:
            self._init_cloud_v2_forwarder(self.station_code)
        except Exception as e:
            logging.debug("Cloud v2 forward init skipped: %s", e)
        
        # Station prefixes to strip (since station is determined by device path)
        self.station_prefixes = ["H08", "H10", "QC", "Edge", "Dowel", "Sort", "Pull", "Assembly"]
        
        # Initialize bin manager for Sort/Pull operations
        self.bin_manager = None
        if BIN_MANAGER_AVAILABLE:
            try:
                self.bin_manager = BinManager()
                logging.info(f"✅ BinManager initialized for {station_code}")
            except Exception as e:
                logging.warning(f"⚠️ Could not initialize BinManager: {e}")
        
        # Station routing map
        self.routing = {
            "Sort": "Station_5_Sorting",
            "Pull": "Station_6_Pulling"
        }
    
    def process_scan(self, scan_data):
        """Process scan with Sort/Pull routing detection (thread-safe)"""
        if not scan_data:
            return False
        
        # Use global lock to prevent data jumbling when multiple scanners scan simultaneously
        with SCAN_PROCESS_LOCK:
            logging.debug(f"🔍 [{self.station_code}] Processing scan: {scan_data[:50]}...")
            
            # In thin mode, skip local Sort/Pull routing (cloud will handle).
            if not bool(self.config.get("cloud_v2.thin_mode", False)):
                # Check for Sort/Pull routing first (combined format like "Sort,15,Part,Cabinet")
                if self._try_handle_sort_pull_routing(scan_data):
                    return True
            
            # Strip station prefix since we know station from device mapping
            cleaned_scan = self._strip_station_prefix(scan_data)
            
            # Call parent process_scan with cleaned data
            # This handles simple bin labels like "Sort Bin 30" via _try_handle_bin_scan
            ok = super().process_scan(cleaned_scan)
            if ok:
                self._archive_local_scan(original_scan=scan_data, cleaned_scan=cleaned_scan)
            return ok

    def _archive_local_scan(self, original_scan: str, cleaned_scan: str) -> None:
        """Append a JSONL record for local raw scan history (best-effort)."""
        if not self._local_archive_file:
            return
        try:
            payload = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "station_code": self.station_code,
                "station_display_name": getattr(self, "station_display_name", None),
                "device_path": self.device_path,
                "raw_data_original": original_scan,
                "raw_data_cleaned": cleaned_scan,
                # For convenience in dashboards that expect raw_data
                "raw_data": cleaned_scan,
            }
            line = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
            with self._local_archive_file.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass
    
    def _try_handle_sort_pull_routing(self, scan_data):
        """
        Handle Sort/Pull routing from any station.
        
        Expected formats:
        - "Sort,BIN01,PartNumber,CabinetName,JobName"
        - "Pull,BIN05,PartNumber,CabinetName"
        - "Sort,15,DOOR_001,Upper_Cabinet_A,Kitchen_2024"
        
        Returns True if handled, False to continue normal processing.
        """
        # Try full pattern first: Sort/Pull,Bin,Part,Cabinet[,Job]
        match = self.SORT_PULL_PATTERN.match(scan_data.strip())
        
        if match:
            action = match.group(1).capitalize()  # "Sort" or "Pull"
            bin_number = int(match.group(2))
            part_number = match.group(3).strip()
            cabinet_name = match.group(4).strip()
            job_name = match.group(5).strip() if match.group(5) else ""
            
            return self._execute_sort_pull(
                action=action,
                bin_number=bin_number,
                part_number=part_number,
                cabinet_name=cabinet_name,
                job_name=job_name,
                raw_scan=scan_data
            )
        
        # Try simple pattern: Sort/Pull,Bin[,remaining data]
        simple_match = self.SIMPLE_SORT_PULL_PATTERN.match(scan_data.strip())
        if simple_match:
            action = simple_match.group(1).capitalize()
            bin_number = int(simple_match.group(2))
            remaining = simple_match.group(3) or ""
            
            # Parse remaining data if available
            remaining_parts = [p.strip() for p in remaining.split(',') if p.strip()]
            part_number = remaining_parts[0] if len(remaining_parts) > 0 else ""
            cabinet_name = remaining_parts[1] if len(remaining_parts) > 1 else ""
            job_name = remaining_parts[2] if len(remaining_parts) > 2 else ""
            
            return self._execute_sort_pull(
                action=action,
                bin_number=bin_number,
                part_number=part_number,
                cabinet_name=cabinet_name,
                job_name=job_name,
                raw_scan=scan_data
            )
        
        return False
    
    def _execute_sort_pull(self, action, bin_number, part_number, cabinet_name, 
                          job_name, raw_scan):
        """Execute Sort or Pull operation with bin management and Google Sheets logging"""
        try:
            logging.info(f"🔄 {action} routing detected: Bin {bin_number}, Part {part_number}, Cabinet {cabinet_name}")
            
            # Validate bin number
            max_bins = 40
            try:
                if self.bin_manager and getattr(self.bin_manager, 'num_bins', None):
                    max_bins = int(self.bin_manager.num_bins)
            except Exception:
                max_bins = 40
            if bin_number < 1 or bin_number > max_bins:
                logging.error(f"❌ Invalid bin number: {bin_number}")
                self.hardware.beep_error()
                return True  # Handled but failed
            
            # Check for duplicates
            if self.duplicate_detector.is_duplicate(raw_scan):
                logging.warning(f"⚠️ Duplicate {action} scan ignored: {raw_scan}")
                self.hardware.beep_error()
                return True
            
            # Execute bin operation
            bin_success = False
            bin_message = ""
            
            if self.bin_manager:
                if action == "Sort":
                    # Add part to bin
                    bin_success, bin_message = self.bin_manager.add_part_to_bin(
                        bin_number=bin_number,
                        part_number=part_number,
                        cabinet_name=cabinet_name,
                        job_name=job_name,
                        quantity=1,
                        operator_id=self.current_operator,
                        station_code=self.station_code  # Track which station initiated
                    )
                    logging.info(f"📥 SORT to Bin {bin_number}: {bin_message}")
                    
                elif action == "Pull":
                    # Remove part from bin
                    bin_success, bin_message = self.bin_manager.pull_part_from_bin(
                        bin_number=bin_number,
                        part_number=part_number,
                        cabinet_name=cabinet_name,
                        operator_id=self.current_operator,
                        station_code=self.station_code
                    )
                    logging.info(f"📤 PULL from Bin {bin_number}: {bin_message}")
            else:
                logging.warning("⚠️ BinManager not available - skipping bin update")
                bin_success = True  # Continue with logging even without bin manager
            
            # Persist to local DB (source of truth)
            try:
                from database_schema import log_scan
                log_scan(
                    station_code=action,
                    raw_data=raw_scan,
                    parsed_fields={
                        "bin_number": f"BIN{str(bin_number).zfill(2)}",
                        "job_name": job_name,
                        "cabinet_name": cabinet_name,
                        "part_num": part_number,
                        "action": action,
                    },
                    operator_id=self.current_operator if self.current_operator else None
                )
            except Exception as e:
                logging.error(f"❌ Failed to log {action} to DB: {e}")
            
            # Feedback
            if bin_success:
                self.hardware.beep_success()
                self.hardware.led_on()
                try:
                    import threading
                    if hasattr(self, '_led_off_timer') and self._led_off_timer is not None:
                        try:
                            self._led_off_timer.cancel()
                        except Exception:
                            pass
                    self._led_off_timer = threading.Timer(1.0, self.hardware.led_off)
                    self._led_off_timer.daemon = True
                    self._led_off_timer.start()
                except Exception:
                    pass
            else:
                self.hardware.beep_error()
                logging.error(f"❌ {action} failed: {bin_message}")
            
            return True
            
        except Exception as e:
            logging.error(f"❌ Error executing {action}: {e}")
            self.hardware.beep_error()
            return True  # Handled but with error
    
    def _strip_station_prefix(self, scan_data):
        """Remove station prefix from scan data if present"""
        if not scan_data:
            return scan_data

        def _detect_delim(t: str) -> str:
            tt = t or ""
            if tt.count("|") >= 2:
                return "|"
            if tt.count("^") >= 2:
                return "^"
            return ","
        
        # Check if scan starts with a known station prefix
        delim = _detect_delim(scan_data)
        parts = scan_data.split(delim)
        if len(parts) > 1:
            first_part = parts[0].strip()
            if first_part in self.station_prefixes:
                # Remove the station prefix, keep the rest
                cleaned = delim.join(parts[1:]).strip()
                logging.debug(f"📝 Stripped station prefix '{first_part}' from scan: {scan_data} → {cleaned}")
                return cleaned
        
        # No prefix found, return as-is
        return scan_data

