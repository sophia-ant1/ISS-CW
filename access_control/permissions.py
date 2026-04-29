"""RBAC permissions and enforcement helpers."""
from __future__ import annotations

from functools import wraps
from typing import Callable
from auth.register import UserRepository


ROLE_PERMISSIONS = {
    "student": {
        "view_own_profile",
        "view_own_grades",
        "upload_assignment",
        "view_feedback",
        "send_message",
        "change_own_password",       # GDPR Art.5 - data accuracy; NIST SP 800-63B §5.1.1
        "export_own_data",           # GDPR Art.15 - right of access
        "request_anonymisation",     # GDPR Art.17 - right to erasure
    },
    "lecturer": {
        "review_assignments",
        "set_grade",
        "give_feedback",
        "send_message",
        "view_student_submissions",
        "change_own_password",
        "export_own_data",
    },
    "admin": {
        "register_user",
        "deactivate_user",
        "reactivate_user",
        "view_audit_logs",
        "view_all_users",
        "update_user_profile",
        "unlock_account",
        "change_own_password",
        "export_own_data",
        "export_any_user_data",      # GDPR Art.15 - admin-initiated subject access
        "anonymise_user",            # GDPR Art.17 - admin-initiated erasure
    },
}

def require_permission(permission: str):
    """Decorator that enforces role-based permissions for service methods."""

    def decorator(func):
        @wraps(func)
        def wrapper(self, actor: str, *args, **kwargs):
            user_repo = UserRepository()
            user = user_repo.find_user(actor)

            if not user:
                raise PermissionError("User does not exist.")
            if not user.active:
                raise PermissionError("Account is inactive.")

            allowed = ROLE_PERMISSIONS.get(user.role, set())
            if permission not in allowed:
                raise PermissionError(f"User '{actor}' is not permitted to perform '{permission}'.")

            return func(self, actor, *args, **kwargs)

        return wrapper

    return decorator