"""Signed audit logging for accountability and monitoring."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import AUDIT_LOG_FILE
from crypto.signing import SigningManager


class AuditLogger:
    """Writes append-only style audit entries and signs each entry with ECDSA P-256."""

    def __init__(self, log_file: Path | None = None):
        self.log_file = log_file or AUDIT_LOG_FILE
        self.signing = SigningManager()
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_file.exists():
            self._write_all([])

    def _read_all(self) -> list[dict[str, Any]]:
        if not self.log_file.exists():
            return []
        return json.loads(self.log_file.read_text(encoding="utf-8"))

    def _write_all(self, entries: list[dict[str, Any]]) -> None:
        self.log_file.write_text(json.dumps(entries, indent=2), encoding="utf-8")

    def log(self, actor: str, action: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create an audit log entry and attach a digital signature."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "action": action,
            "details": details or {},
        }
        entry["signature"] = self.signing.sign_json(entry)
        entries = self._read_all()
        entries.append(entry)
        self._write_all(entries)
        return entry

    def read_verified_logs(self) -> list[dict[str, Any]]:
        """Return logs only if each ECDSA signature verifies correctly."""
        verified: list[dict[str, Any]] = []
        for entry in self._read_all():
            signature = entry.get("signature", "")
            signed_portion = {k: v for k, v in entry.items() if k != "signature"}
            if self.signing.verify_json(signed_portion, signature):
                verified.append(entry)
            else:
                verified.append({**entry, "verification_error": "Invalid signature"})
        return verified
