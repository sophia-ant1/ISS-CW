"""User registration and persistent user repository."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from config import USERS_FILE
from models.user import User
from utils.validators import (
    ensure_non_empty,
    validate_role,
    validate_username,
    validate_password_strength,
    validate_email,
)
from auth.password_utils import password_manager


class UserRepository:
    """Stores users in JSON for a simple coursework-friendly deployment model."""

    def __init__(self, users_file: Path | None = None) -> None:
        self.users_file = users_file or USERS_FILE
        self.users_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.users_file.exists():
            self._write_all([])

    def _read_all(self) -> list[dict[str, Any]]:
        if not self.users_file.exists():
            return []
        return json.loads(self.users_file.read_text(encoding="utf-8"))

    def _write_all(self, users: list[dict[str, Any]]) -> None:
        self.users_file.write_text(json.dumps(users, indent=2), encoding="utf-8")

    def list_users(self) -> list[User]:
        """Return all users as model objects."""
        return [User.from_dict(item) for item in self._read_all()]

    def find_user(self, username: str) -> User | None:
        """Find a user by username."""
        for user in self.list_users():
            if user.username == username:
                return user
        return None

    def get_role(self, username: str) -> str:
        """Return a user's role or raise if the user does not exist."""
        user = self.find_user(username)
        if not user:
            raise ValueError(f"Unknown user: {username}")
        return user.role

    def create_user(
        self,
        username: str,
        password: str,
        role: str,
        profile: dict[str, Any] | None = None,
    ) -> User:
        """Create a user with an Argon2id password hash.

        Password is validated against the system complexity policy before hashing.
        Email in profile is validated against RFC 5321-aligned format if present.
        Aligned with NIST SP 800-63B §5.1.1 and UK GDPR Article 5(1)(d) accuracy.
        """
        username = validate_username(username)
        ensure_non_empty(password, "Password")
        validate_password_strength(password)
        role = validate_role(role)

        # Validate email in profile if provided
        profile = profile or {}
        if "email" in profile and profile["email"]:
            profile["email"] = validate_email(profile["email"])

        if self.find_user(username):
            raise ValueError("User already exists.")
        user = User(
            username=username,
            role=role,
            password_hash=password_manager.hash_password(password),
            profile=profile,
        )
        users = self._read_all()
        users.append(user.to_dict())
        self._write_all(users)
        return user

    def update_user(self, updated_user: User) -> None:
        """Persist changes for a single user."""
        users = self._read_all()
        for index, item in enumerate(users):
            if item["username"] == updated_user.username:
                users[index] = updated_user.to_dict()
                self._write_all(users)
                return
        raise ValueError("User not found.")

    def set_active_state(self, username: str, active: bool) -> None:
        """Activate or deactivate a user account."""
        user = self.find_user(username)
        if not user:
            raise ValueError("User not found.")
        user.active = active
        self.update_user(user)