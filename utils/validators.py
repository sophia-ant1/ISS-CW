"""Input validation helpers used across the system."""
from __future__ import annotations

import re
from typing import Any

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

# Password policy: minimum 10 characters, at least one uppercase, one lowercase,
# one digit, and one special character — consistent with NIST SP 800-63B (§5.1.1)
PASSWORD_MIN_LENGTH = 10
PASSWORD_RE = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{}|;:',.<>?/`~]).{10,}$"
)


def validate_username(username: str) -> str:
    """Validate usernames so storage and audit logs remain predictable."""
    if not USERNAME_RE.fullmatch(username):
        raise ValueError(
            "Username must be 3-32 characters and contain only letters, digits, underscores, dots, or hyphens."
        )
    return username


def validate_email(email: str) -> str:
    """Validate email address format using RFC 5321-aligned pattern."""
    email = email.strip()
    if not email:
        raise ValueError("Email address cannot be blank.")
    if len(email) > 254:
        raise ValueError("Email address is too long (max 254 characters).")
    if not EMAIL_RE.fullmatch(email):
        raise ValueError("Email address format is invalid.")
    return email.lower()


def validate_role(role: str) -> str:
    """Allow only the three authorised coursework roles."""
    if role not in {"student", "lecturer", "admin"}:
        raise ValueError("Role must be student, lecturer, or admin.")
    return role


def ensure_non_empty(value: str, field_name: str) -> str:
    """Reject blank values for security-sensitive records."""
    if not value or not value.strip():
        raise ValueError(f"{field_name} cannot be blank.")
    return value.strip()


def validate_password_strength(password: str) -> str:
    """Enforce password complexity policy aligned with NIST SP 800-63B.

    Requires:
    - Minimum 10 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if not password or len(password) < PASSWORD_MIN_LENGTH:
        raise ValueError(
            f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."
        )
    if not PASSWORD_RE.match(password):
        raise ValueError(
            "Password must contain at least one uppercase letter, one lowercase letter, "
            "one digit, and one special character."
        )
    return password


def validate_grade(grade: str) -> str:
    """Validate coursework grades as whole numbers from 0 to 100 inclusive."""
    grade = ensure_non_empty(grade, "Grade")
    if not grade.isdigit():
        raise ValueError("Grade must be a whole number between 0 and 100.")
    numeric_grade = int(grade)
    if numeric_grade < 0 or numeric_grade > 100:
        raise ValueError("Grade must be between 0 and 100.")
    return str(numeric_grade)


def require_fields(payload: dict[str, Any], required: list[str]) -> None:
    """Check that a dictionary contains every required key."""
    missing = [key for key in required if key not in payload]
    if missing:
        raise ValueError(f"Missing required fields: {', '.join(missing)}")