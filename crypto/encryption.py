"""Symmetric encryption and envelope encryption built on AES-256-GCM."""
from __future__ import annotations

import base64
import json
import secrets
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto.integrity import IntegrityManager
from crypto.key_management import KeyManager


class EncryptionManager:
    """Handles AES-256-GCM encryption, HMAC integrity, and ECDH-based envelope encryption."""

    def __init__(self) -> None:
        self.key_manager = KeyManager()
        self.integrity = IntegrityManager()

    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.b64encode(data).decode("utf-8")

    @staticmethod
    def _unb64(data: str) -> bytes:
        return base64.b64decode(data.encode("utf-8"))

    def encrypt_with_aes_gcm(self, plaintext: bytes, key: bytes, aad: bytes | None = None) -> dict[str, str]:
        """Encrypt bytes with AES-256-GCM using a fresh nonce from Python's secrets module."""
        if len(key) != 32:
            raise ValueError("AES-256-GCM requires a 32-byte key.")
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        return {"nonce": self._b64(nonce), "ciphertext": self._b64(ciphertext)}

    def decrypt_with_aes_gcm(self, encrypted: dict[str, str], key: bytes, aad: bytes | None = None) -> bytes:
        """Decrypt AES-256-GCM ciphertext."""
        nonce = self._unb64(encrypted["nonce"])
        ciphertext = self._unb64(encrypted["ciphertext"])
        return AESGCM(key).decrypt(nonce, ciphertext, aad)

    def envelope_encrypt(self, payload: dict[str, Any], recipient_public_pem: str) -> dict[str, Any]:
        """Encrypt JSON using a random DEK protected by an ECDH-derived KEK.

        Steps:
        1. Generate a random data encryption key (DEK) with the secrets module.
        2. Encrypt the payload using AES-256-GCM with the DEK.
        3. Generate an ephemeral ECDH key pair.
        4. Derive a key-encryption key (KEK) from ECDH + HKDF.
        5. Wrap the DEK using AES-256-GCM under the derived KEK.
        6. Add an HMAC-SHA256 over the payload ciphertext for explicit integrity evidence.
        """
        dek = secrets.token_bytes(32)
        plaintext = json.dumps(payload, sort_keys=True).encode("utf-8")
        encrypted_payload = self.encrypt_with_aes_gcm(plaintext, dek)

        eph_private, eph_public_pem = self.key_manager.generate_ephemeral_ecdh_keypair()
        kek = self.key_manager.derive_shared_key(eph_private, recipient_public_pem, info=b"envelope-kek")
        wrapped_dek = self.encrypt_with_aes_gcm(dek, kek)

        ciphertext_bytes = self._unb64(encrypted_payload["ciphertext"])
        hmac_tag = self.integrity.generate_hmac(dek, ciphertext_bytes)

        return {
            "algorithm": "AES-256-GCM + ECDH envelope encryption + HMAC-SHA256",
            "ephemeral_public_key": eph_public_pem,
            "wrapped_dek": wrapped_dek,
            "encrypted_payload": encrypted_payload,
            "hmac": hmac_tag,
        }

    def envelope_decrypt(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Decrypt an envelope-encrypted payload using the server's ECDH private key."""
        kek = self.key_manager.derive_shared_key(
            self.key_manager.server_ecdh_private_key(),
            envelope["ephemeral_public_key"],
            info=b"envelope-kek",
        )
        dek = self.decrypt_with_aes_gcm(envelope["wrapped_dek"], kek)
        ciphertext_bytes = self._unb64(envelope["encrypted_payload"]["ciphertext"])
        if not self.integrity.verify_hmac(dek, ciphertext_bytes, envelope["hmac"]):
            raise ValueError("Integrity verification failed: invalid HMAC.")
        plaintext = self.decrypt_with_aes_gcm(envelope["encrypted_payload"], dek)
        return json.loads(plaintext.decode("utf-8"))
