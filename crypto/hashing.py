"""Password hashing and verification using Argon2id."""
from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import Type


class PasswordManager:
    """Centralises password hashing so parameters remain consistent across the system."""

    def __init__(self) -> None:
        # Argon2id is resistant to GPU, side-channel attacks 
        # Is appropriate for password storage.
        self._hasher = PasswordHasher(
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )

    def hash_password(self, password: str) -> str:
        """Hash a plaintext password using Argon2id."""
        return self._hasher.hash(password)

    def verify_password(self, password_hash: str, password: str) -> bool:
        """Verify a password against a stored Argon2id hash."""
        try:
            valid = self._hasher.verify(password_hash, password)
            if valid and self._hasher.check_needs_rehash(password_hash):
                # Caller can rehash after successful authentication if desired.
                return True
            return valid
        except VerifyMismatchError:
            return False
