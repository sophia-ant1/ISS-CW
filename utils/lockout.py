"""Account lockout tracker.

Implements a persistent lockout policy aligned with NIST SP 800-63B §5.2.2:
after MAX_FAILURES consecutive failed login attempts the account is locked for
LOCKOUT_SECONDS.  The lockout is lifted automatically when the window expires,
or immediately by an administrator via AdminService.unlock_account().

State is kept in a JSON sidecar file so lockouts survive restarts — important
for a coursework demo.  In production this would be a database row with an index
on (username, locked_until).
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config import DATA_DIR

LOCKOUT_FILE = DATA_DIR / "account_lockouts.json"
MAX_FAILURES = 5          # consecutive failures before lockout
LOCKOUT_SECONDS = 300   # 5-minute lockout window                 #####CHANGE TO 300


class AccountLockoutManager:
    """Read/write lockout records for usernames."""

    def __init__(self, lockout_file: Path | None = None) -> None:
        self.lockout_file = lockout_file or LOCKOUT_FILE
        self.lockout_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.lockout_file.exists():
            self._write({})

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _read(self) -> dict:
        return json.loads(self.lockout_file.read_text(encoding="utf-8"))

    def _write(self, data: dict) -> None:
        self.lockout_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def is_locked(self, username: str) -> bool:
        """Return True if the account is currently locked out."""
        data = self._read()
        record = data.get(username)
        if not record:
            return False
        locked_until_str = record.get("locked_until")
        if not locked_until_str:
            return False
        locked_until = datetime.fromisoformat(locked_until_str)
        if datetime.now(timezone.utc) < locked_until:
            return True
        # Lock has expired — clear it
        self.clear_failures(username)
        return False

    def locked_until(self, username: str) -> datetime | None:
        """Return the lockout expiry time, or None if not locked."""
        data = self._read()
        record = data.get(username, {})
        ts = record.get("locked_until")
        if ts:
            return datetime.fromisoformat(ts)
        return None

    def record_failure(self, username: str) -> int:
        """Increment failure counter; lock the account if threshold is reached.

        Returns the current failure count after increment.
        """
        data = self._read()
        record = data.setdefault(username, {"failures": 0, "locked_until": None})
        record["failures"] = record.get("failures", 0) + 1
        if record["failures"] >= MAX_FAILURES:
            record["locked_until"] = (
                datetime.now(timezone.utc) + timedelta(seconds=LOCKOUT_SECONDS)
            ).isoformat()
        self._write(data)
        return record["failures"]

    def clear_failures(self, username: str) -> None:
        """Reset failure count after a successful login or admin unlock."""
        data = self._read()
        data.pop(username, None)
        self._write(data)

    def failure_count(self, username: str) -> int:
        """Return the current failure count without modifying state."""
        data = self._read()
        return data.get(username, {}).get("failures", 0)