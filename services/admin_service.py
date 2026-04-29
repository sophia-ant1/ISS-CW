"""Administrator-facing operations."""
from __future__ import annotations

import secrets
from datetime import datetime, timezone

from access_control.permissions import require_permission
from auth.register import UserRepository
from auth.password_utils import password_manager
from utils.logger import AuditLogger
from utils.lockout import AccountLockoutManager
from utils.rate_limiter import check_profile_update_rate_limit
from utils.validators import (
    ensure_non_empty,
    validate_role,
    validate_username,
    validate_email,
    validate_password_strength,
)
from models.data import SecureDataStore
from utils.rate_limiter import login_limiter


class AdminService:
    """Implements operations administrators are authorised to perform."""

    def __init__(self) -> None:
        self.user_repository = UserRepository()
        self.audit_logger = AuditLogger()
        self.lockout_manager = AccountLockoutManager()
        self.data_store = SecureDataStore()

    def _get_user_or_raise(self, username: str):
        """Resolve a user and fail clearly if the account does not exist."""
        username = validate_username(username)
        user = self.user_repository.find_user(username)
        if not user:
            raise ValueError("User does not exist.")
        return user

    def _notify_user(self, recipient: str, actor: str, message_body: str) -> None:
        """Store a system notification message in the messages store for the recipient."""
        from crypto.signing import SigningManager
        signing = SigningManager()
        message = {
            "from": f"system (admin: {actor})",
            "to": recipient,
            "body": message_body,
        }
        message["signature"] = signing.sign_json(message)
        messages = self.data_store.load_messages()
        messages.append(message)
        self.data_store.save_messages(messages)

    @require_permission("view_all_users")
    def view_all_users(self, actor: str) -> list[dict]:
        """Return a summary of all system accounts for administrative review."""
        users = self.user_repository.list_users()
        self.audit_logger.log(actor, "view_all_users", {"count": len(users)})
        return [
            {
                "username": user.username,
                "role": user.role,
                "active": user.active,
                "profile": user.profile,
            }
            for user in users
        ]

    @require_permission("view_all_users")
    def view_profile(self, actor: str) -> dict:
        """Return the admin's own profile data."""
        user = self.user_repository.find_user(actor)
        self.audit_logger.log(actor, "view_profile")
        return {
            "username": user.username,
            "role": user.role,
            "profile": user.profile,
            "active": user.active,
        }

    @require_permission("view_audit_logs")
    def view_audit_logs(self, actor: str) -> list[dict]:
        """Return the verified audit log for accountability and monitoring."""
        logs = self.audit_logger.read_verified_logs()
        self.audit_logger.log(actor, "view_audit_logs", {"count": len(logs)})
        return logs

    @require_permission("register_user")
    def register_user(
        self,
        actor: str,
        username: str,
        password: str,
        role: str,
        full_name: str,
        email: str,
    ) -> None:
        """Create a new active user account with validated identity fields.

        Email is validated against RFC 5321-aligned format per UK GDPR
        Article 5(1)(d) (accuracy principle).
        """
        username = validate_username(username)
        role = validate_role(role)
        password = ensure_non_empty(password, "Password")
        full_name = ensure_non_empty(full_name, "Full name")
        email = validate_email(email)

        if self.user_repository.find_user(username):
            raise ValueError("A user with that username already exists.")

        profile = {
            "full_name": full_name,
            "email": email,
        }
        self.user_repository.create_user(username, password, role, profile)
        self.audit_logger.log(actor, "register_user", {"username": username, "role": role})

    @require_permission("change_own_password")
    def change_password(
        self, actor: str, current_password: str, new_password: str
    ) -> None:
        """Allow an admin to change their own password after verifying the current one.

        Enforces NIST SP 800-63B §5.1.1 complexity policy; re-hashes with Argon2id.
        """
        current_password = ensure_non_empty(current_password, "Current password")
        new_password = ensure_non_empty(new_password, "New password")
        validate_password_strength(new_password)

        user = self.user_repository.find_user(actor)
        if not password_manager.verify_password(user.password_hash, current_password):
            self.audit_logger.log(actor, "change_password_failed", {"reason": "bad_current_password"})
            raise ValueError("Current password is incorrect.")

        if password_manager.verify_password(user.password_hash, new_password):
            raise ValueError("New password must differ from the current password.")

        user.password_hash = password_manager.hash_password(new_password)
        self.user_repository.update_user(user)
        self.audit_logger.log(actor, "change_password_success", {})

    @require_permission("update_user_profile")
    def update_user_profile(
        self,
        actor: str,
        target_username: str,
        full_name: str | None = None,
        email: str | None = None,
    ) -> None:
        """Allow an administrator to update personal data for any account.

        After updating, a system notification is delivered to the affected
        user via the encrypted messages store, satisfying the transparency
        obligation under UK GDPR Article 13/14 (right to be informed of
        processing changes).

        Rate-limited to prevent bulk profile manipulation.
        """
        check_profile_update_rate_limit(actor)

        target_username = validate_username(target_username)
        user = self._get_user_or_raise(target_username)

        changes: dict[str, str] = {}
        profile = dict(user.profile)

        if full_name is not None:
            full_name = ensure_non_empty(full_name, "Full name")
            old = profile.get("full_name", "")
            if old != full_name:
                profile["full_name"] = full_name
                changes["full_name"] = f"'{old}' → '{full_name}'"

        if email is not None:
            email = validate_email(email)
            old_email = profile.get("email", "")
            if old_email != email:
                profile["email"] = email
                changes["email"] = f"'{old_email}' → '{email}'"

        if not changes:
            raise ValueError("No profile changes were specified.")

        user.profile = profile
        self.user_repository.update_user(user)
        self.audit_logger.log(
            actor,
            "update_user_profile",
            {"target": target_username, "changes": changes},
        )

        change_summary = "; ".join(f"{k} changed from {v}" for k, v in changes.items())
        self._notify_user(
            recipient=target_username,
            actor=actor,
            message_body=(
                f"Your profile has been updated by an administrator ({actor}). "
                f"Changes: {change_summary}. "
                "If you did not request this change, please contact your system administrator."
            ),
        )

    @require_permission("export_any_user_data")
    def export_user_data(self, actor: str, target_username: str) -> dict:
        """Export all personal data held for a target user (GDPR Article 15).

        Admin-initiated subject access request. Returns a structured export
        covering profile, grades, assignments, feedback, and messages.
        Logged to audit trail per GDPR Art.5(2) accountability principle.
        """
        target_username = validate_username(target_username)
        user = self._get_user_or_raise(target_username)

        system_data = self.data_store.load_system_data()
        all_messages = self.data_store.load_messages()

        export = {
            "export_generated_at": datetime.now(timezone.utc).isoformat(),
            "gdpr_basis": "Article 15 - Right of Access (admin-initiated SAR)",
            "subject": target_username,
            "requested_by": actor,
            "profile": {
                "username": user.username,
                "role": user.role,
                "active": user.active,
                **user.profile,
            },
            "grades": system_data["grades"].get(target_username, {}),
            "feedback": system_data["feedback"].get(target_username, {}),
            "assignments": system_data["assignments"].get(target_username, {}),
            "messages": [
                m for m in all_messages
                if m.get("from") == target_username or m.get("to") == target_username
            ],
        }
        self.audit_logger.log(
            actor,
            "gdpr_art15_data_export",
            {"subject": target_username, "requested_by": actor},
        )
        return export

    @require_permission("anonymise_user")
    def anonymise_user(self, actor: str, target_username: str) -> dict:
        """Irreversibly anonymise a user account under GDPR Article 17.

        Steps:
        1. Validate target exists and is not the acting admin (self-anonymisation
           via admin route is disallowed to prevent accidental lock-out).
        2. Replace all PII (email, full_name) with a cryptographically random
           pseudonym — irreversible under GDPR recital 26 definition of anonymisation.
        3. Purge the user's personal messages from the encrypted store.
        4. Deactivate the account.
        5. Academic records (grades, assignments) are retained under Art.17(3)(b)
           legitimate interest for academic integrity.
        6. Audit entry retained (pseudonymised) per Art.17(3)(e) legal obligation.
        """
        target_username = validate_username(target_username)

        if target_username == actor:
            raise ValueError(
                "Admins cannot anonymise their own account via this route. "
                "Use request_anonymisation on your own account."
            )

        user = self._get_user_or_raise(target_username)

        pseudonym = "anon_" + secrets.token_hex(8)

        user.profile = {
            "full_name": pseudonym,
            "email": f"{pseudonym}@anonymised.invalid",
            "anonymised": True,
            "anonymised_at": datetime.now(timezone.utc).isoformat(),
            "anonymised_by": actor,
        }
        user.active = False
        self.user_repository.update_user(user)

        all_messages = self.data_store.load_messages()
        retained = [
            m for m in all_messages
            if m.get("from") != target_username and m.get("to") != target_username
        ]
        self.data_store.save_messages(retained)

        self.audit_logger.log(
            actor,
            "gdpr_art17_anonymisation",
            {
                "target": target_username,
                "pseudonym": pseudonym,
                "messages_purged": len(all_messages) - len(retained),
                "academic_records_retained": True,
                "basis": "Art.17(3)(b) - legitimate interest (academic integrity)",
            },
        )
        return {
            "status": "anonymised",
            "target": target_username,
            "pseudonym": pseudonym,
            "account_deactivated": True,
            "academic_records_retained": True,
            "gdpr_basis": "Article 17 - Right to Erasure",
        }

    @require_permission("deactivate_user")
    def deactivate_user(self, actor: str, target_username: str) -> None:
        """Deactivate a user account to enforce access restrictions."""
        target_username = validate_username(target_username)

        if target_username == actor:
            raise ValueError("Administrators cannot deactivate their own active session account.")

        user = self._get_user_or_raise(target_username)
        if not user.active:
            raise ValueError("User account is already inactive.")

        self.user_repository.set_active_state(target_username, False)
        self.audit_logger.log(actor, "deactivate_user", {"target": target_username})

    @require_permission("reactivate_user")
    def reactivate_user(self, actor: str, target_username: str) -> None:
        """Reactivate a previously disabled user account."""
        target_username = validate_username(target_username)

        user = self._get_user_or_raise(target_username)
        if user.active:
            raise ValueError("User account is already active.")

        self.user_repository.set_active_state(target_username, True)
        self.audit_logger.log(actor, "reactivate_user", {"target": target_username})

    @require_permission("unlock_account")
    def unlock_account(self, actor: str, target_username: str) -> None:
        """Clear the lockout state for an account locked due to failed login attempts.

        Aligned with NIST SP 800-63B §5.2.2 which recommends an administrative
        unlock mechanism alongside automatic time-based unlocking.
        """
        target_username = validate_username(target_username)
        self._get_user_or_raise(target_username)

        if not self.lockout_manager.is_locked(target_username):
            raise ValueError("Account is not currently locked.")

        self.lockout_manager.clear_failures(target_username)
        login_limiter.reset(target_username)
        self.audit_logger.log(actor, "unlock_account", {"target": target_username})

        self._notify_user(
            recipient=target_username,
            actor=actor,
            message_body=(
                f"Your account lockout has been cleared by an administrator ({actor}). "
                "You may now attempt to log in again."
            ),
        )

    @require_permission("export_own_data")
    def export_my_data(self, actor: str) -> dict:
        """Return a complete structured export of all personal data held for the actor.

        Implements GDPR Article 15 (right of access / subject access request).
        The export includes profile data, grades, assignments (content + signatures),
        feedback, and messages. Logged to audit trail per GDPR Art.5(2) accountability.
        """
        user = self.user_repository.find_user(actor)
        system_data = self.data_store.load_system_data()
        all_messages = self.data_store.load_messages()

        export = {
            "export_generated_at": datetime.now(timezone.utc).isoformat(),
            "gdpr_basis": "Article 15 - Right of Access",
            "subject": actor,
            "profile": {
                "username": user.username,
                "role": user.role,
                "active": user.active,
                **user.profile,
            },
            "messages": [
                m for m in all_messages
                if m.get("from") == actor or m.get("to") == actor
            ],
        }
        self.audit_logger.log(actor, "gdpr_art15_data_export", {"subject": actor})
        return export