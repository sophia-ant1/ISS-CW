"""Data access layer for encrypted coursework records."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from config import MESSAGES_FILE, SYSTEM_DATA_FILE
from crypto.encryption import EncryptionManager
from crypto.key_management import KeyManager


class SecureDataStore:
    """Persists encrypted application data using envelope encryption."""

    def __init__(self) -> None:
        self.encryption = EncryptionManager()
        self.key_manager = KeyManager()
        SYSTEM_DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        if not SYSTEM_DATA_FILE.exists():
            self.save_system_data({"grades": {}, "assignments": {}, "feedback": {}})
        if not MESSAGES_FILE.exists():
            self.save_messages([])

    def save_system_data(self, payload: dict[str, Any]) -> None:
        """Encrypt and write core academic data to disk."""
        envelope = self.encryption.envelope_encrypt(payload, self.key_manager.server_ecdh_public_pem())
        SYSTEM_DATA_FILE.write_text(json.dumps(envelope, indent=2), encoding="utf-8")

    def load_system_data(self) -> dict[str, Any]:
        """Read and decrypt the main system data file."""
        envelope = json.loads(SYSTEM_DATA_FILE.read_text(encoding="utf-8"))
        return self.encryption.envelope_decrypt(envelope)

    def save_messages(self, messages: list[dict[str, Any]]) -> None:
        """Encrypt and write stored messages to disk."""
        envelope = self.encryption.envelope_encrypt({"messages": messages}, self.key_manager.server_ecdh_public_pem())
        MESSAGES_FILE.write_text(json.dumps(envelope, indent=2), encoding="utf-8")

    def load_messages(self) -> list[dict[str, Any]]:
        """Read and decrypt stored messages."""
        envelope = json.loads(MESSAGES_FILE.read_text(encoding="utf-8"))
        return self.encryption.envelope_decrypt(envelope)["messages"]
