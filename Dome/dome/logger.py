"""
Structured JSON logger for Dome WAF.
Writes to rotating file + stdout (colour).
Compatible with Wazuh / Filebeat log ingestion.
"""
from __future__ import annotations
import json
import logging
import logging.handlers
import sys
import time
from pathlib import Path


# ── ANSI colour helpers ───────────────────────────────────────────────────────
_COLOURS = {
    "BLOCK":  "\033[91m",   # red
    "LOG":    "\033[93m",   # yellow
    "ALLOW":  "\033[92m",   # green
    "RESET":  "\033[0m",
}


class _ColourFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        colour = _COLOURS.get(getattr(record, "action", ""), "")
        reset = _COLOURS["RESET"] if colour else ""
        return f"{colour}{msg}{reset}"


class WafLogger:
    def __init__(self, log_path: str, max_bytes: int = 10_485_760, backup_count: int = 5):
        self._log_path = Path(log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

        # File handler (JSON, no colour)
        file_handler = logging.handlers.RotatingFileHandler(
            str(self._log_path),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(logging.Formatter("%(message)s"))

        # Stdout handler (colour)
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setFormatter(_ColourFormatter(
            "[%(asctime)s] %(levelname)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        ))

        self._logger = logging.getLogger("dome")
        self._logger.setLevel(logging.DEBUG)
        self._logger.addHandler(file_handler)
        self._logger.addHandler(stdout_handler)

    def log_request(
        self,
        action: str,
        client_ip: str,
        method: str,
        path: str,
        status_code: int,
        hits: list[dict],
        duration_ms: float,
    ) -> dict:
        """Log the request and return the event dict (used by notifiers)."""
        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "product": "dome-waf",
            "action": action,
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "status_code": status_code,
            "duration_ms": round(duration_ms, 2),
            "hits": hits,
            "hit_count": len(hits),
            "categories": list({h["category"] for h in hits}),
        }
        level = logging.WARNING if action in ("BLOCK", "LOG") else logging.INFO
        extra = {"action": action}
        self._logger.log(level, json.dumps(record), extra=extra)
        return record
