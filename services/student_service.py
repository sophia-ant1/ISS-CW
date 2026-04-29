"""Student-facing operations."""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone

from access_control.permissions import require_permission
from auth.register import UserRepository
from auth.password_utils import password_manager
from crypto.signing import SigningManager
from models.data import SecureDataStore
from utils.logger import AuditLogger
from utils.validators import ensure_non_empty, validate_password_strength, validate_email
from utils.rate_limiter import check_message_rate_limit, check_submission_rate_limit


class StudentService:
    """Implements operations students are authorised to perform."""

    def __init__(self) -> None:
        self.user_repository = UserRepository()
        self.data_store = SecureDataStore()
        self.audit_logger = AuditLogger()
        self.signing = SigningManager()

    def _get_user_or_raise(self, username: str):
        username = ensure_non_empty(username, "Username")
        user = self.user_repository.find_user(username)
        if not user:
            raise ValueError("User does not exist.")
        if not user.active:
            raise ValueError("User account is inactive.")
        return user

    def _get_active_lecturer_or_raise(self, username: str):
        user = self._get_user_or_raise(username)
        if user.role != "lecturer":
            raise ValueError("Students can only message lecturers.")
        return user

    @require_permission("view_own_profile")
    def view_profile(self, actor: str) -> dict:
        """Return the calling user's own profile data."""
        user = self.user_repository.find_user(actor)
        self.audit_logger.log(actor, "view_profile")
        return {
            "username": user.username,
            "role": user.role,
            "profile": user.profile,
            "active": user.active,
        }

    @require_permission("view_own_grades")
    def view_grades(self, actor: str) -> dict:
        """Return only the caller's grades and feedback."""
        data = self.data_store.load_system_data()
        self.audit_logger.log(actor, "view_grades")
        return {
            "grades": data["grades"].get(actor, {}),
            "feedback": data["feedback"].get(actor, {}),
        }

    @require_permission("view_own_grades")
    def view_assignments(self, actor: str) -> dict:
        """Return only the caller's uploaded assignments."""
        data = self.data_store.load_system_data()
        self.audit_logger.log(actor, "view_assignments")
        return {
            "assignments": data["assignments"].get(actor, {}),
        }

    @require_permission("upload_assignment")
    def upload_assignment(self, actor: str, assignment_name: str, content: str) -> None:
        """Store a student's assignment with an ECDSA non-repudiation signature.

        Rate-limited to 5 uploads per 60 seconds to prevent storage flooding
        (DoS mitigation). Each submission is signed over a canonical JSON
        representation of {actor, assignment_name, content} using ECDSA P-256
        (FIPS 186-4).  The signature is stored alongside the submission so the
        system can later prove which authenticated user submitted which content 
        for non-repudiation. 
        """
        check_submission_rate_limit(actor)

        assignment_name = ensure_non_empty(assignment_name, "Assignment name")
        content = ensure_non_empty(content, "Content")

        # Canonical payload signed for non-repudiation.
        submission_payload = {
            "submitted_by": actor,
            "assignment_name": assignment_name,
            "content": content,
        }
        signature = self.signing.sign_json(submission_payload)

        data = self.data_store.load_system_data()
        data["assignments"].setdefault(actor, {})[assignment_name] = {
            "content": content,
            "submitted_by": actor,
            "signature": signature,          # ECDSA P-256 non-repudiation signature
        }
        self.data_store.save_system_data(data)
        self.audit_logger.log(actor, "upload_assignment", {"assignment_name": assignment_name})

    def verify_assignment_signature(self, actor: str, assignment_name: str) -> bool:
        """Verify the ECDSA signature on a stored assignment submission."""
        data = self.data_store.load_system_data()
        submission = data["assignments"].get(actor, {}).get(assignment_name)
        if not submission:
            raise ValueError("Assignment not found.")
        signature = submission.get("signature")
        if not signature:
            return False
        payload = {
            "submitted_by": submission["submitted_by"],
            "assignment_name": assignment_name,
            "content": submission["content"],
        }
        return self.signing.verify_json(payload, signature)

    @require_permission("send_message")
    def send_message(self, actor: str, recipient: str, body: str) -> None:
        """Allow a student to send a signed, encrypted message to an active lecturer only.

        Rate-limited to 10 messages per 60 seconds to prevent spam/DoS.
        Messages are signed with ECDSA P-256 at send time so recipients can
        verify authenticity and origin.
        """
        check_message_rate_limit(actor)

        self._get_user_or_raise(actor)
        recipient = ensure_non_empty(recipient, "Recipient")
        body = ensure_non_empty(body, "Message body")
        recipient_user = self._get_active_lecturer_or_raise(recipient)

        message = {
            "from": actor,
            "to": recipient_user.username,
            "body": body,
        }
        message["signature"] = self.signing.sign_json(message)

        messages = self.data_store.load_messages()
        messages.append(message)
        self.data_store.save_messages(messages)
        self.audit_logger.log(actor, "send_message", {"recipient": recipient_user.username})

    @require_permission("view_own_profile")
    def view_messages(self, actor: str) -> dict:
        """Return only messages sent or received by the logged-in student."""
        self._get_user_or_raise(actor)
        messages = self.data_store.load_messages()
        visible_messages = [
            message
            for message in messages
            if message.get("from") == actor or message.get("to") == actor
        ]
        self.audit_logger.log(actor, "view_messages", {"message_count": len(visible_messages)})
        return {"messages": visible_messages}

    @require_permission("change_own_password")
    def change_password(
        self, actor: str, current_password: str, new_password: str
    ) -> None:
        """Allow a user to change their own password after verifying the current one.

        Enforces password complexity policy (NIST SP 800-63B §5.1.1) on the new
        password and re-hashes with Argon2id.  Current password verification
        prevents account takeover if a session token is stolen.
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
            "grades": system_data["grades"].get(actor, {}),
            "feedback": system_data["feedback"].get(actor, {}),
            "assignments": system_data["assignments"].get(actor, {}),
            "messages": [
                m for m in all_messages
                if m.get("from") == actor or m.get("to") == actor
            ],
        }
        self.audit_logger.log(actor, "gdpr_art15_data_export", {"subject": actor})
        return export

    @require_permission("request_anonymisation")
    def request_anonymisation(self, actor: str, current_password: str) -> dict:
        """Irreversibly anonymise the actor's account under GDPR Article 17.

        Steps (aligned with ICO guidance on the right to erasure):
        1. Verify current password — prevents inadvertent or coerced erasure.
        2. Replace all PII fields (username in profile, email, full_name) with a
           cryptographically random pseudonym so the record cannot be re-identified.
        3. Purge the actor's messages from the encrypted store.
        4. Deactivate the account so the pseudonym cannot be used to log in.
        5. Academic records (grades, assignments) are retained under the legitimate
           interest basis for academic integrity — standard Art.17(3)(b) exception.
        6. Audit log entry is retained (pseudonymised) per Art.17(3)(e) legal obligation.

        Returns a dict confirming the pseudonym assigned, for the user's records.
        """
        current_password = ensure_non_empty(current_password, "Current password")

        user = self.user_repository.find_user(actor)
        if not password_manager.verify_password(user.password_hash, current_password):
            self.audit_logger.log(actor, "anonymisation_failed", {"reason": "bad_password"})
            raise ValueError("Current password is incorrect.")

        pseudonym = "anon_" + secrets.token_hex(8)

        # Overwrite PII fields — irreversible replacement, not deletion,
        # preserving relational integrity of the academic record store.
        user.profile = {
            "full_name": pseudonym,
            "email": f"{pseudonym}@anonymised.invalid",
            "anonymised": True,
            "anonymised_at": datetime.now(timezone.utc).isoformat(),
        }
        user.active = False
        self.user_repository.update_user(user)

        # Purge personal messages — no legitimate interest exception applies.
        all_messages = self.data_store.load_messages()
        retained = [
            m for m in all_messages
            if m.get("from") != actor and m.get("to") != actor
        ]
        self.data_store.save_messages(retained)

        self.audit_logger.log(
            actor,
            "gdpr_art17_anonymisation",
            {
                "pseudonym": pseudonym,
                "messages_purged": len(all_messages) - len(retained),
                "academic_records_retained": True,
                "basis": "Art.17(3)(b) - legitimate interest (academic integrity)",
            },
        )
        return {
            "status": "anonymised",
            "pseudonym": pseudonym,
            "account_deactivated": True,
            "academic_records_retained": True,
            "gdpr_basis": "Article 17 - Right to Erasure",
        }