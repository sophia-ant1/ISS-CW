"""Secure session token creation and verification using PyJWT with ES256.

Changed from RS256 (RSA-2048) to ES256 (ECDSA P-256) to maintain consistency
with the system's ECC-first cryptographic posture and reduce key material
footprint. ES256 produces smaller signatures and is aligned with NIST SP 800-131A.
"""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jwt

from config import JWT_AUDIENCE, JWT_ISSUER, SESSION_FILE, TOKEN_TTL_SECONDS
from crypto.signing import SigningManager


class SessionManager:
    """Issues ES256-signed JWT access tokens and tracks active session IDs.

    Uses ECDSA P-256 (ES256) rather than RSA RS256 so the session layer is
    consistent with the rest of the system's ECC cryptographic stack.
    Expired sessions are pruned from the store on every verify call to
    prevent unbounded growth of the session file.
    """

    def __init__(self, session_file: Path | None = None) -> None:
        self.signing = SigningManager()
        self.session_file = session_file or SESSION_FILE
        self.session_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.session_file.exists():
            self.session_file.write_text(
                json.dumps({"active_sessions": []}, indent=2), encoding="utf-8"
            )

    def _read_store(self) -> dict[str, Any]:
        return json.loads(self.session_file.read_text(encoding="utf-8"))

    def _write_store(self, payload: dict[str, Any]) -> None:
        self.session_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _prune_expired_sessions(self, store: dict[str, Any]) -> dict[str, Any]:
        """Remove sessions whose expiry timestamp has passed.

        This prevents the active_sessions store from growing unbounded and
        ensures stale session IDs cannot linger in the store after token expiry.
        Pruning on every verify is a lightweight mitigation — a production system
        would use a background task or a database TTL index.
        """
        now = datetime.now(timezone.utc)
        store["active_sessions"] = [
            entry
            for entry in store["active_sessions"]
            if datetime.fromisoformat(entry["expires_at"]) > now
        ]
        return store

    def issue_token(self, username: str, role: str) -> str:
        """Create a signed JWT containing the subject's role and a random session ID.

        Tokens are signed with ECDSA P-256 (ES256). Claims include iss, aud,
        iat, nbf, exp, and a random sid for server-side revocation support.
        """
        now = datetime.now(timezone.utc)
        session_id = secrets.token_urlsafe(32)
        claims = {
            "sub": username,
            "role": role,
            "sid": session_id,
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(seconds=TOKEN_TTL_SECONDS),
        }
        # Sign with ECDSA P-256 private key (ES256) — consistent with system ECC posture.
        token = jwt.encode(
            claims,
            self.signing.private_key_pem(),
            algorithm="ES256",
        )
        store = self._read_store()
        store = self._prune_expired_sessions(store)
        store["active_sessions"].append(
            {
                "sid": session_id,
                "username": username,
                "expires_at": (now + timedelta(seconds=TOKEN_TTL_SECONDS)).isoformat(),
            }
        )
        self._write_store(store)
        return token

    def verify_token(self, token: str) -> dict[str, Any]:
        """Verify the JWT signature, claims, and server-side session ID state.

        Expired sessions are pruned from the store on every call so the
        active_sessions file does not grow without bound.
        """
        claims = jwt.decode(
            token,
            self.signing.public_key_pem(),
            algorithms=["ES256"],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
        )
        store = self._read_store()
        store = self._prune_expired_sessions(store)
        self._write_store(store)

        valid_sids = {entry["sid"] for entry in store["active_sessions"]}
        if claims["sid"] not in valid_sids:
            raise ValueError("Session has been revoked or is unknown.")
        return claims

    def revoke_token(self, token: str) -> None:
        """Remove a session from the active store."""
        claims = self.verify_token(token)
        store = self._read_store()
        store["active_sessions"] = [
            entry
            for entry in store["active_sessions"]
            if entry["sid"] != claims["sid"]
        ]
        self._write_store(store)