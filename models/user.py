"""User model definitions."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class User:
    """Represents a system user with role, password hash, and protected profile data."""

    username: str
    role: str
    password_hash: str
    active: bool = True
    profile: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert the dataclass to a JSON-serialisable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "User":
        """Reconstruct a user from stored JSON."""
        return cls(**payload)
