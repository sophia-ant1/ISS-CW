"""Digital signatures using ECDSA over the P-256 curve."""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

from config import KEYS_DIR


class SigningManager:
    """Signs and verifies records using ECDSA(P-256).

    Also exposes PEM accessors so the session layer can use the same ECDSA key
    pair for ES256 JWT signing — removing the need for a separate RSA key and
    keeping the system's cryptographic material entirely ECC-based.
    """

    def __init__(self) -> None:
        KEYS_DIR.mkdir(parents=True, exist_ok=True)
        self.private_key_path = KEYS_DIR / "ecdsa_private.pem"
        self.public_key_path = KEYS_DIR / "ecdsa_public.pem"
        self._private_key, self._public_key = self._load_or_create_keys()

    def _load_or_create_keys(self):
        if self.private_key_path.exists() and self.public_key_path.exists():
            private_key = serialization.load_pem_private_key(
                self.private_key_path.read_bytes(), password=None
            )
            public_key = serialization.load_pem_public_key(self.public_key_path.read_bytes())
            return private_key, public_key

        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        self.private_key_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.public_key_path.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        return private_key, public_key

    @staticmethod
    def _normalise_json(payload: dict[str, Any]) -> bytes:
        """Serialise JSON deterministically so signatures are stable."""
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign_bytes(self, data: bytes) -> str:
        """Sign raw bytes and return a base64-encoded DER signature."""
        signature = self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(signature).decode("utf-8")

    def verify_bytes(self, data: bytes, signature_b64: str) -> bool:
        """Verify a base64 ECDSA signature against raw bytes."""
        try:
            self._public_key.verify(
                base64.b64decode(signature_b64), data, ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False

    def sign_json(self, payload: dict[str, Any]) -> str:
        """Sign a JSON object."""
        return self.sign_bytes(self._normalise_json(payload))

    def verify_json(self, payload: dict[str, Any], signature_b64: str) -> bool:
        """Verify a signed JSON object."""
        return self.verify_bytes(self._normalise_json(payload), signature_b64)

    def public_key_pem(self) -> str:
        """Export the ECDSA public key as PEM text.

        Used by SessionManager for ES256 JWT verification — the ECDSA key
        pair serves double duty: audit log signing and JWT session tokens.
        """
        return self.public_key_path.read_text(encoding="utf-8")

    def private_key_pem(self) -> str:
        """Export the ECDSA private key as PEM text for ES256 JWT signing.

        NOTE: In production this key would be protected at rest (HSM or
        encrypted PEM). For this coursework it is stored unencrypted on disk
        as a pragmatic simplification — documented as a known limitation.
        """
        return self.private_key_path.read_text(encoding="utf-8")