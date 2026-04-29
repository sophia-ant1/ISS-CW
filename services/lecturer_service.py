"""Lecturer-facing operations."""
from __future__ import annotations
from datetime import datetime, timezone
from access_control.permissions import require_permission
from auth.register import UserRepository
from auth.password_utils import password_manager
from crypto.signing import SigningManager
from models.data import SecureDataStore
from utils.logger import AuditLogger
from utils.validators import ensure_non_empty, validate_grade, validate_password_strength
from utils.rate_limiter import check_message_rate_limit


class LecturerService:
    """Implements operations lecturers are authorised to perform."""

    def __init__(self) -> None:
        self.user_repository = UserRepository()
        self.data_store = SecureDataStore()
        self.audit_logger = AuditLogger()
        self.signing = SigningManager()

    def _get_student_or_raise(self, student_username: str):
        """Resolve and validate that the supplied username belongs to an existing student."""
        student_username = ensure_non_empty(student_username, "Student username")
        user = self.user_repository.find_user(student_username)
        if not user:
            raise ValueError("Student user does not exist.")
        if user.role != "student":
            raise ValueError("Selected user is not a student.")
        if not user.active:
            raise ValueError("Selected student account is inactive.")
        return user

    def _get_user_or_raise(self, username: str):
        username = ensure_non_empty(username, "Username")
        user = self.user_repository.find_user(username)
        if not user:
            raise ValueError("User does not exist.")
        if not user.active:
            raise ValueError("User account is inactive.")
        return user

    def _ensure_assignment_exists(self, student_username: str, assignment_name: str) -> dict:
        """Validate that a named assignment exists for the selected student."""
        assignment_name = ensure_non_empty(assignment_name, "Assignment name")
        data = self.data_store.load_system_data()
        submissions = data["assignments"].get(student_username, {})
        if assignment_name not in submissions:
            raise ValueError("Assignment does not exist for the selected student.")
        return data

    @require_permission("view_student_submissions")
    def view_profile(self, actor: str) -> dict:
        """Return the lecturer's own profile data."""
        user = self.user_repository.find_user(actor)
        self.audit_logger.log(actor, "view_profile")
        return {
            "username": user.username,
            "role": user.role,
            "profile": user.profile,
            "active": user.active,
        }

    @require_permission("change_own_password")
    def change_password(
        self, actor: str, current_password: str, new_password: str
    ) -> None:
        """Allow a lecturer to change their own password after verifying the current one.

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

    @require_permission("view_student_submissions")
    def list_students_with_submissions(self, actor: str) -> list[str]:
        """Return all student usernames that currently have at least one submission."""
        data = self.data_store.load_system_data()
        students = []
        for username, submissions in data["assignments"].items():
            user = self.user_repository.find_user(username)
            if user and user.role == "student" and submissions:
                students.append(username)

        students = sorted(students)
        self.audit_logger.log(actor, "list_students_with_submissions", {"count": len(students)})
        return students

    @require_permission("view_student_submissions")
    def view_student_submissions(self, actor: str, student_username: str) -> dict:
        """Return assignment submissions for a given student."""
        self._get_student_or_raise(student_username)
        data = self.data_store.load_system_data()
        submissions = data["assignments"].get(student_username, {})
        self.audit_logger.log(actor, "view_student_submissions", {"student": student_username})
        return submissions

    @require_permission("view_student_submissions")
    def verify_submission_signature(
        self, actor: str, student_username: str, assignment_name: str
    ) -> bool:
        """Verify the ECDSA non-repudiation signature on a student's submission."""
        self._get_student_or_raise(student_username)
        data = self.data_store.load_system_data()
        submission = data["assignments"].get(student_username, {}).get(assignment_name)
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

    @require_permission("set_grade")
    def set_grade(self, actor: str, student_username: str, assignment_name: str, grade: str) -> None:
        """Record a validated grade for a student's assignment."""
        self._get_student_or_raise(student_username)
        grade = validate_grade(grade)
        data = self._ensure_assignment_exists(student_username, assignment_name)

        data["grades"].setdefault(student_username, {})[assignment_name] = grade
        self.data_store.save_system_data(data)
        self.audit_logger.log(
            actor,
            "set_grade",
            {"student": student_username, "assignment": assignment_name, "grade": grade},
        )

    @require_permission("give_feedback")
    def give_feedback(
        self, actor: str, student_username: str, assignment_name: str, feedback: str
    ) -> None:
        """Attach feedback to an existing student assignment."""
        self._get_student_or_raise(student_username)
        feedback = ensure_non_empty(feedback, "Feedback")
        data = self._ensure_assignment_exists(student_username, assignment_name)

        data["feedback"].setdefault(student_username, {})[assignment_name] = feedback
        self.data_store.save_system_data(data)
        self.audit_logger.log(
            actor, "give_feedback", {"student": student_username, "assignment": assignment_name}
        )

    @require_permission("send_message")
    def send_message(self, actor: str, recipient: str, body: str) -> None:
        """Allow a lecturer to send a signed, encrypted message to an active student only.

        Rate-limited to 10 messages per 60 seconds to prevent spam/DoS.
        Messages are signed with ECDSA P-256 at send time to provide sender
        authenticity and non-repudiation.
        """
        check_message_rate_limit(actor)

        self._get_user_or_raise(actor)
        recipient = ensure_non_empty(recipient, "Recipient")
        body = ensure_non_empty(body, "Message body")
        recipient_user = self._get_student_or_raise(recipient)

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

    @require_permission("view_student_submissions")
    def list_students_with_message_threads(self, actor: str) -> list[str]:
        """Return student usernames that have at least one message exchanged with the lecturer."""
        self._get_user_or_raise(actor)
        messages = self.data_store.load_messages()
        students = set()

        for message in messages:
            sender = message.get("from")
            recipient = message.get("to")

            if sender == actor:
                try:
                    user = self._get_student_or_raise(recipient)
                    students.add(user.username)
                except ValueError:
                    continue
            elif recipient == actor:
                try:
                    user = self._get_student_or_raise(sender)
                    students.add(user.username)
                except ValueError:
                    continue

        result = sorted(students)
        self.audit_logger.log(
            actor, "list_students_with_message_threads", {"count": len(result)}
        )
        return result

    @require_permission("view_student_submissions")
    def view_messages_with_student(self, actor: str, student_username: str) -> dict:
        """Return only the message thread between the lecturer and one selected student."""
        self._get_user_or_raise(actor)
        student = self._get_student_or_raise(student_username)
        messages = self.data_store.load_messages()

        thread = [
            message
            for message in messages
            if (
                message.get("from") == actor and message.get("to") == student.username
            )
            or (
                message.get("from") == student.username and message.get("to") == actor
            )
        ]

        self.audit_logger.log(
            actor,
            "view_messages_with_student",
            {"student": student.username, "message_count": len(thread)},
        )
        return {"student": student.username, "messages": thread}
    
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