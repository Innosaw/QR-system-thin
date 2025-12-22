#!/usr/bin/env python3
"""
Detect all connected Tera USB dongles
Run this to identify device paths for configuration
"""

import sys
from pathlib import Path

try:
    import evdev
    from evdev import InputDevice
    EVDEV_AVAILABLE = True
except ImportError:
    EVDEV_AVAILABLE = False
    print("❌ evdev not available. Install with: pip install evdev")

def detect_scanners():
    """Detect all keyboard-like input devices (scanners)"""
    if not EVDEV_AVAILABLE:
        return []
    
    devices = evdev.list_devices()
    scanners = []
    
    def _build_symlink_targets(dir_path: Path):
        """Return {resolved_target: [symlink_paths...]} for a /dev/input/by-* directory."""
        mapping = {}
        if not dir_path.exists():
            return mapping
        for symlink in dir_path.iterdir():
            try:
                if not symlink.is_symlink():
                    continue
                target = symlink.resolve()
                mapping.setdefault(str(target), []).append(str(symlink))
            except Exception:
                continue
        return mapping

    def _pick_best_symlink(paths):
        if not paths:
            return None
        # Prefer the keyboard event node; keep ordering stable.
        def score(p: str):
            s = 0
            if 'event-kbd' in p:
                s += 100
            if 'kbd' in p:
                s += 10
            return -s, p
        return sorted(paths, key=score)[0]

    by_path_dir = Path('/dev/input/by-path')
    by_id_dir = Path('/dev/input/by-id')

    # Map device nodes to stable symlinks (prefer by-path to preserve physical port mapping)
    by_path_targets = {}
    by_id_targets = {}
    try:
        by_path_targets = _build_symlink_targets(by_path_dir)
        by_id_targets = _build_symlink_targets(by_id_dir)
    except Exception as e:
        print(f"⚠️  Could not read /dev/input/by-path/by-id: {e}")
    
    for device_path in devices:
        try:
            dev = InputDevice(device_path)
            name = dev.name.lower()
            caps = dev.capabilities().get(evdev.ecodes.EV_KEY, [])
            has_keyboard = bool(caps) and evdev.ecodes.KEY_ENTER in caps
            
            if has_keyboard:
                # Filter out HDMI CEC devices (not scanners)
                is_hdmi = "hdmi" in name or "vc4" in name
                if is_hdmi:
                    continue
                
                # Check if it's likely a scanner (not a regular keyboard)
                is_scanner = (
                    any(keyword in name for keyword in ["scanner", "barcode", "honeywell", "tera", "symbol", "datalogic", "hid"]) or
                    ("hid" in name and "0581" in name) or  # Tera devices
                    ("event" in device_path and not is_hdmi)  # Most scanners appear as event devices
                )
                
                # Prefer by-path (stable physical port mapping), then by-id, else event path
                stable_path = device_path
                stable_kind = 'event'
                try:
                    device_path_obj = Path(device_path)
                    if device_path_obj.exists():
                        by_path_link = _pick_best_symlink(by_path_targets.get(device_path, []))
                        if by_path_link:
                            stable_path = by_path_link
                            stable_kind = 'by-path'
                        else:
                            by_id_link = _pick_best_symlink(by_id_targets.get(device_path, []))
                            if by_id_link:
                                stable_path = by_id_link
                                stable_kind = 'by-id'
                except Exception:
                    pass
                
                scanners.append({
                    'path': device_path,
                    'stable_path': stable_path,
                    'stable_kind': stable_kind,
                    'name': dev.name,
                    'phys': dev.phys,
                    'is_scanner': is_scanner,
                    'has_keyboard': has_keyboard,
                    'vendor_id': hex(dev.info.vendor) if hasattr(dev.info, 'vendor') else 'unknown',
                    'product_id': hex(dev.info.product) if hasattr(dev.info, 'product') else 'unknown'
                })
        except Exception as e:
            print(f"⚠️  Error reading {device_path}: {e}")
    
    return scanners

def main():
    print("🔍 Detecting USB dongles/scanners...\n")
    
    scanners = detect_scanners()
    
    if not scanners:
        print("❌ No scanner devices found")
        print("\nMake sure:")
        print("  1. USB dongles are connected to USB hub")
        print("  2. USB hub is connected to Raspberry Pi")
        print("  3. Scanners are paired with their dongles")
        return
    
    print(f"✅ Found {len(scanners)} device(s):\n")
    
    for i, scanner in enumerate(scanners, 1):
        marker = "⭐" if scanner['is_scanner'] else "⚠️"
        print(f"{marker} Device {i}: {scanner['name']}")
        stable_kind = scanner.get('stable_kind', 'unknown')
        print(f"   Stable Path ({stable_kind}): {scanner['stable_path']}")
        print(f"   Event Path: {scanner['path']}")
        print(f"   Physical: {scanner['phys']}")
        print(f"   VID/PID: {scanner['vendor_id']}/{scanner['product_id']}")
        print()
    
    print("\n📋 Configuration template:")
    print("Add this to your config.json:\n")
    print('"scanners": {')
    
    station_codes = ["QC", "H08", "H10", "Edge", "Dowel", "Sort", "Pull"]
    station_sheets = [
        "Station_8_QC", "Station_1_H08", "Station_2_H10",
        "Station_3_Edge", "Station_4_Dowel", "Station_5_Sorting", "Station_6_Pulling"
    ]
    
    for i, scanner in enumerate(scanners[:7]):  # Limit to 7 scanners
        station_code = station_codes[i] if i < len(station_codes) else f"Station{i+1}"
        station_sheet = station_sheets[i] if i < len(station_sheets) else f"Station_{i+1}"
        
        # Use preferred stable path if available, otherwise use event path
        config_path = scanner['stable_path'] if scanner['stable_path'] != scanner['path'] else scanner['path']
        
        print(f'  "{config_path}": {{')
        print(f'    "station_code": "{station_code}",')
        print(f'    "station_sheet": "{station_sheet}"')
        print('  }' + (',' if i < len(scanners) - 1 else ''))
    
    print('}')
    print("\n💡 Tip: Test each device with: sudo evtest <device_path>")

if __name__ == "__main__":
    main()

