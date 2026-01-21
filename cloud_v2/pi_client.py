from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import requests


@dataclass
class CloudV2Config:
    base_url: str
    station_token: str
    timeout_seconds: int = 8
    queue_path: Optional[str] = None
    # Optional append-only archive of every scan payload (JSONL). Never deleted by the flusher.
    archive_path: Optional[str] = None
    flush_batch_size: int = 200


class CloudV2ScanSink:
    """
    Best-effort scan forwarder to Cloud v2.
    - Sends scan payloads to {base_url}/api/scans with Bearer token.
    - On failure, appends payload to a local JSONL queue and retries later.
    """

    def __init__(self, cfg: CloudV2Config):
        self.cfg = cfg
        self.base_url = (cfg.base_url or "").rstrip("/")
        self.session = requests.Session()
        self.timeout = max(1, int(cfg.timeout_seconds or 8))
        self.queue_file = Path(cfg.queue_path).expanduser() if cfg.queue_path else None
        if self.queue_file:
            try:
                self.queue_file.parent.mkdir(parents=True, exist_ok=True)
            except Exception:
                # Don't block startup if queue dir can't be made.
                self.queue_file = None

        self.archive_file = Path(cfg.archive_path).expanduser() if cfg.archive_path else None
        if self.archive_file:
            try:
                self.archive_file.parent.mkdir(parents=True, exist_ok=True)
            except Exception:
                self.archive_file = None

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.cfg.station_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _post_payload(self, payload: Dict[str, Any]) -> bool:
        url = f"{self.base_url}/api/scans"
        resp = self.session.post(url, headers=self._headers(), json=payload, timeout=self.timeout)
        if resp.status_code >= 200 and resp.status_code < 300:
            return True
            logging.warning("Cloud v2 rejected scan: HTTP %s (body truncated)", resp.status_code)
        return False

    def _enqueue(self, payload: Dict[str, Any]) -> None:
        if not self.queue_file:
            return
        try:
            line = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
            with self.queue_file.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception as e:
            logging.warning("Failed to enqueue scan for retry: %s", e)

    def _archive(self, payload: Dict[str, Any]) -> None:
        if not self.archive_file:
            return
        try:
            line = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
            with self.archive_file.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception as e:
            logging.debug("Failed to archive scan payload: %s", e)

    def flush_queue(self) -> None:
        if not self.queue_file or not self.queue_file.exists():
            return

        tmp = self.queue_file.with_suffix(self.queue_file.suffix + ".tmp")
        sent = 0
        kept = 0
        try:
            with self.queue_file.open("r", encoding="utf-8") as src, tmp.open("w", encoding="utf-8") as dst:
                for line in src:
                    if not line.strip():
                        continue
                    if sent >= self.cfg.flush_batch_size:
                        dst.write(line)
                        kept += 1
                        continue
                    try:
                        payload = json.loads(line)
                    except Exception:
                        # Keep malformed lines to avoid accidental loss.
                        dst.write(line)
                        kept += 1
                        continue
                    try:
                        if self._post_payload(payload):
                            sent += 1
                            continue
                    except Exception:
                        # Network error: keep for later.
                        pass
                    dst.write(line)
                    kept += 1

            tmp.replace(self.queue_file)
            if sent:
                logging.info("Cloud v2 queue flush: sent=%s kept=%s file=%s", sent, kept, self.queue_file)
        except Exception as e:
            try:
                if tmp.exists():
                    tmp.unlink()
            except Exception:
                pass
            logging.debug("Cloud v2 queue flush skipped: %s", e)

    def submit_scan(self, payload: Dict[str, Any]) -> bool:
        """
        Submit a single scan. Returns True if delivered immediately.
        On delivery failure, it is queued (if queue enabled).
        """
        # Always archive first (best-effort). This supports "local backup history" for thin images.
        self._archive(payload)

        # Opportunistic flush first (keeps latency low when back online).
        try:
            self.flush_queue()
        except Exception:
            pass

        try:
            ok = self._post_payload(payload)
            if ok:
                return True
        except Exception as e:
            logging.info("Cloud v2 submit failed (will queue if enabled): %s", e)

        self._enqueue(payload)
        return False


