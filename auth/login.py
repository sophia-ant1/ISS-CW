"""Authentication service including secure login and session issuance."""
from __future__ import annotations

from typing import Any

from auth.password_utils import password_manager
from auth.register import UserRepository
from crypto.key_management import KeyManager
from crypto.session import SessionManager
from utils.logger import AuditLogger
from utils.lockout import AccountLockoutManager
from utils.rate_limiter import check_login_rate_limit, RateLimitError, login_limiter


class AuthenticationService:
    """Handles login, token issuance, and secure-channel setup using ECDH.

    JWT tokens are issued using ES256 (ECDSA P-256) via SessionManager,
    which reuses the system's ECDSA signing key — no RSA material required.

    Login protection uses a two-layer defence aligned with NIST SP 800-63B §5.2.2:
      1. Sliding-window rate limiter: throttles rapid successive attempts.
      2. Account lockout: locks the account after MAX_FAILURES consecutive
         failures regardless of inter-attempt timing.

    NOTE — Simulated ECDH channel: the ephemeral ECDH key exchange in login()
    is performed entirely server-side to demonstrate the protocol. In a real
    deployment the client would generate its own ephemeral key pair, send the
    public key to the server, and the shared secret would never leave either
    endpoint. The 8-byte preview in the return dict is for demonstration only
    and would be removed in production.
    """

    def __init__(self) -> None:
        self.user_repository = UserRepository()
        self.session_manager = SessionManager()
        self.key_manager = KeyManager()
        self.audit_logger = AuditLogger()
        self.lockout_manager = AccountLockoutManager()

    def login(self, username: str, password: str) -> dict[str, Any]:
        """Authenticate a user and return an ES256 JWT plus ECDH session material.

        Checks rate limit and account lockout before verifying credentials.
        Clears lockout state on successful authentication.
        """
        # Layer 1: sliding-window rate limit (raises RateLimitError if exceeded)
        try:
            check_login_rate_limit(username)
        except RateLimitError as exc:
            self.audit_logger.log(
                "system", "login_rate_limited", {"username": username}
            )
            raise PermissionError(str(exc)) from exc

        # Layer 2: persistent account lockout
        if self.lockout_manager.is_locked(username):
            locked_until = self.lockout_manager.locked_until(username)
            self.audit_logger.log(
                "system", "login_blocked_lockout", {"username": username}
            )
            raise PermissionError(
                f"Account is locked due to repeated failed login attempts. "
                f"Try again after {locked_until.strftime('%H:%M:%S UTC')}."
            )

        user = self.user_repository.find_user(username)
        if not user:
            self.lockout_manager.record_failure(username)
            self.audit_logger.log(
                "system", "login_failed", {"username": username, "reason": "unknown_user"}
            )
            raise ValueError("Invalid credentials.")

        if not user.active:
            self.audit_logger.log(
                "system", "login_failed", {"username": username, "reason": "inactive_user"}
            )
            raise PermissionError("Account is inactive.")

        if not password_manager.verify_password(user.password_hash, password):
            count = self.lockout_manager.record_failure(username)
            remaining = max(0, 5 - count)
            self.audit_logger.log(
                "system", "login_failed", {
                    "username": username,
                    "reason": "bad_password",
                    "failures": count,
                    "attempts_remaining": remaining,
                }
            )
            msg = "Invalid credentials."
            if count >= 3:
                msg += f" {remaining} attempt(s) remaining before lockout."
            raise ValueError(msg)

        # Successful login — clear lockout state
        self.lockout_manager.clear_failures(username)
        login_limiter.reset(username)
        # Simulate secure communication channel setup using ephemeral ECDH.
        client_private, client_public_pem = self.key_manager.generate_ephemeral_ecdh_keypair()
        shared_key = self.key_manager.derive_shared_key(
            client_private,
            self.key_manager.server_ecdh_public_pem(),
            info=b"login-secure-channel",
        )
        token = self.session_manager.issue_token(user.username, user.role)
        self.audit_logger.log(user.username, "login_success", {"role": user.role})
        return {
            "token": token,
            "role": user.role,
            "username": user.username,
            "client_public_key": client_public_pem,
            "server_public_key": self.key_manager.server_ecdh_public_pem(),
            "derived_secure_channel_key_b64_preview": shared_key[:8].hex(),
        }

    def verify_session(self, token: str) -> dict[str, Any]:
        """Validate a session token and return its claims."""
        return self.session_manager.verify_token(token)

    def logout(self, token: str) -> None:
        """Revoke the caller's session token."""
        claims = self.session_manager.verify_token(token)
        self.session_manager.revoke_token(token)
        self.audit_logger.log(claims["sub"], "logout", {"sid": claims["sid"]})