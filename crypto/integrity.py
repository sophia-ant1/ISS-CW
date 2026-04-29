"""Integrity protection using HMAC-SHA256."""
from __future__ import annotations

import base64
import hashlib
import hmac


class IntegrityManager:
    """Provides HMAC generation and constant-time verification."""

    def generate_hmac(self, key: bytes, data: bytes) -> str:
        """Generate a base64-encoded HMAC-SHA256 for the supplied data."""
        mac = hmac.new(key, data, hashlib.sha256).digest()
        return base64.b64encode(mac).decode("utf-8")

    def verify_hmac(self, key: bytes, data: bytes, expected_hmac: str) -> bool:
        """Verify an HMAC using constant-time comparison."""
        actual = self.generate_hmac(key, data)
        return hmac.compare_digest(actual, expected_hmac)
