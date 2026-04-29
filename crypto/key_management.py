"""Key management primitives for AES and ECDH keys.

JWT signing uses system's ECDSA P-256 key via SigningManager
keeping all asymmetric cryptography on a single ECC curve (P-256) 
consistent with NIST SP 800-131A guidance.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import secrets

from config import KEYS_DIR


class KeyManager:
    """Loads, creates, and derives keys used by the coursework system."""

    def __init__(self) -> None:
        KEYS_DIR.mkdir(parents=True, exist_ok=True)
        self.ecdh_private_path = KEYS_DIR / "ecdh_private.pem"
        self.ecdh_public_path = KEYS_DIR / "ecdh_public.pem"
        self.hkdf_salt_path = KEYS_DIR / "hkdf_salt.bin"
        self._server_ecdh_private, self._server_ecdh_public = self._load_or_create_ecdh_keys()

    def _load_or_create_hkdf_salt(self) -> bytes:
        if not self.hkdf_salt_path.exists():
            self.hkdf_salt_path.write_bytes(secrets.token_bytes(32))
        return self.hkdf_salt_path.read_bytes()

    def _load_or_create_ecdh_keys(self):
        if self.ecdh_private_path.exists() and self.ecdh_public_path.exists():
            private_key = serialization.load_pem_private_key(
                self.ecdh_private_path.read_bytes(), password=None
            )
            public_key = serialization.load_pem_public_key(self.ecdh_public_path.read_bytes())
            return private_key, public_key

        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        self.ecdh_private_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.ecdh_public_path.write_bytes(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        return private_key, public_key

    def server_ecdh_private_key(self):
        """Return the system's long-term ECDH private key."""
        return self._server_ecdh_private

    def server_ecdh_public_pem(self) -> str:
        """Return the system's ECDH public key in PEM format."""
        return self.ecdh_public_path.read_text(encoding="utf-8")

    def generate_ephemeral_ecdh_keypair(self) -> tuple[Any, str]:
        """Create a fresh ECDH key pair for a simulated secure session or envelope exchange."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        return private_key, public_pem

    def derive_shared_key(
        self, private_key: Any, peer_public_pem: str, info: bytes = b"sls-ecdh"
    ) -> bytes:
        """Derive a 256-bit symmetric key from an ECDH shared secret using HKDF-SHA256."""
        peer_public_key = serialization.load_pem_public_key(peer_public_pem.encode("utf-8"))
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        hkdf_salt = self._load_or_create_hkdf_salt()
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=hkdf_salt, info=info)
        return hkdf.derive(shared_secret)