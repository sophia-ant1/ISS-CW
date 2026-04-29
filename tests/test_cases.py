"""Unit tests covering the core security requirements."""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from models.data import SecureDataStore


class TestSecureLearningSystem(unittest.TestCase):
    """Test authentication, RBAC, encryption, signatures, integrity, and sessions."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.project_root = Path(__file__).resolve().parents[1]
        self._old_cwd = Path.cwd()
        self.test_project = Path(self.temp_dir.name) / "secure_learning_system"
        shutil.copytree(self.project_root, self.test_project, dirs_exist_ok=True)
        import os
        os.chdir(self.test_project)

        lockout_file = self.test_project / "data" / "account_lockouts.json"
        lockout_file.parent.mkdir(parents=True, exist_ok=True)
        lockout_file.write_text("{}", encoding="utf-8")

        users_file = self.test_project / "data" / "users.json"
        if users_file.exists():
            _users = json.loads(users_file.read_text(encoding="utf-8"))
            _users = [
                u for u in _users
                if u["username"] not in ("newstudent", "validemailuser", "new_user", "new_lecturer")
            ]
            users_file.write_text(json.dumps(_users, indent=2), encoding="utf-8")

        from auth.register import UserRepository
        from auth.login import AuthenticationService
        from services.student_service import StudentService
        from services.lecturer_service import LecturerService
        from services.admin_service import AdminService
        from crypto.encryption import EncryptionManager
        from crypto.signing import SigningManager
        from crypto.integrity import IntegrityManager
        from crypto.key_management import KeyManager

        self.UserRepository = UserRepository
        self.AuthenticationService = AuthenticationService
        self.StudentService = StudentService
        self.LecturerService = LecturerService
        self.AdminService = AdminService
        self.EncryptionManager = EncryptionManager
        self.SigningManager = SigningManager
        self.IntegrityManager = IntegrityManager
        self.KeyManager = KeyManager
        self.SecureDataStore = SecureDataStore

        repo = self.UserRepository()
        data_store = self.SecureDataStore()

        from auth.password_utils import password_manager as _pm

        for username, password, role, profile in [
            ("student1", "StrongPass!234", "student", {"email": "student1@test.com"}),
            ("student2", "StrongPass!234", "student", {"email": "student2@test.com"}),
            ("lecturer1", "StrongPass!234", "lecturer", {"email": "lecturer1@test.com"}),
            ("admin1",   "StrongPass!234", "admin",   {"email": "admin1@test.com"}),
        ]:
            user = repo.find_user(username)
            if not user:
                repo.create_user(username, password, role, profile)
            else:
                # Always reset hash and state so tests are not affected by
                # stale hashes copied from the project's data/users.json.
                user.password_hash = _pm.hash_password(password)
                user.active = True
                repo.update_user(user)

        data_store.save_system_data({"grades": {}, "assignments": {}, "feedback": {}})
        data_store.save_messages([])

        from utils.rate_limiter import login_limiter, message_limiter, submission_limiter, profile_update_limiter
        for limiter in (login_limiter, message_limiter, submission_limiter, profile_update_limiter):
            for key in ("student1", "student2", "lecturer1", "admin1"):
                limiter.reset(key)

    def tearDown(self):
        import os
        os.chdir(self._old_cwd)
        self.temp_dir.cleanup()

    # ------------------------------------------------------------------ #
    # Authentication & sessions                                            #
    # ------------------------------------------------------------------ #

    def test_logout_revokes_session(self):
        auth = self.AuthenticationService()
        session = auth.login("student1", "StrongPass!234")
        auth.logout(session["token"])
        with self.assertRaises(ValueError):
            auth.verify_session(session["token"])

    def test_inactive_user_cannot_login(self):
        repo = self.UserRepository()
        repo.set_active_state("student1", False)
        auth = self.AuthenticationService()
        with self.assertRaises(PermissionError):
            auth.login("student1", "StrongPass!234")

    # ------------------------------------------------------------------ #
    # Account lockout                                                       #
    # ------------------------------------------------------------------ #

    def test_account_locked_after_repeated_failures(self):
        from utils.lockout import AccountLockoutManager
        auth = self.AuthenticationService()
        lockout = AccountLockoutManager()

        for _ in range(5):
            try:
                auth.login("student1", "WRONG_PASSWORD")
            except (ValueError, PermissionError):
                pass

        self.assertTrue(lockout.is_locked("student1"))

    def test_locked_account_cannot_login(self):
        from utils.lockout import AccountLockoutManager
        auth = self.AuthenticationService()
        lockout = AccountLockoutManager()
        for _ in range(5):
            lockout.record_failure("student1")

        with self.assertRaises(PermissionError):
            auth.login("student1", "StrongPass!234")

    def test_admin_can_unlock_account(self):
        from utils.lockout import AccountLockoutManager
        admin = self.AdminService()
        auth = self.AuthenticationService()
        lockout = AccountLockoutManager()

        for _ in range(5):
            lockout.record_failure("student1")

        self.assertTrue(lockout.is_locked("student1"))
        admin.unlock_account("admin1", "student1")
        self.assertFalse(lockout.is_locked("student1"))

        session = auth.login("student1", "StrongPass!234")
        self.assertEqual(session["username"], "student1")

    def test_successful_login_clears_failure_count(self):
        from utils.lockout import AccountLockoutManager
        auth = self.AuthenticationService()
        lockout = AccountLockoutManager()

        try:
            auth.login("student1", "WRONG")
        except (ValueError, PermissionError):
            pass

        self.assertGreater(lockout.failure_count("student1"), 0)
        auth.login("student1", "StrongPass!234")
        self.assertEqual(lockout.failure_count("student1"), 0)

    # ------------------------------------------------------------------ #
    # Password policy                                                       #
    # ------------------------------------------------------------------ #

    def test_weak_password_rejected_too_short(self):
        from utils.validators import validate_password_strength
        with self.assertRaises(ValueError):
            validate_password_strength("Short1!")

    def test_weak_password_rejected_no_special_char(self):
        from utils.validators import validate_password_strength
        with self.assertRaises(ValueError):
            validate_password_strength("NoSpecial123")

    def test_weak_password_rejected_no_uppercase(self):
        from utils.validators import validate_password_strength
        with self.assertRaises(ValueError):
            validate_password_strength("nouppercase1!")

    def test_strong_password_accepted(self):
        from utils.validators import validate_password_strength
        result = validate_password_strength("Str0ng!Pass#99")
        self.assertEqual(result, "Str0ng!Pass#99")

    def test_create_user_rejects_weak_password(self):
        repo = self.UserRepository()
        with self.assertRaises(ValueError):
            repo.create_user("weakpwduser", "password", "student", {})

    # ------------------------------------------------------------------ #
    # Password change                                                       #
    # ------------------------------------------------------------------ #

    def test_student_can_change_own_password(self):
        """Successful password change rehashes with Argon2id; new credentials work at login."""
        student = self.StudentService()
        auth = self.AuthenticationService()
        student.change_password("student1", "StrongPass!234", "NewSecure!Pass99")
        session = auth.login("student1", "NewSecure!Pass99")
        self.assertEqual(session["username"], "student1")

    def test_change_password_wrong_current_rejected(self):
        """Wrong current password must raise ValueError, not change the hash."""
        student = self.StudentService()
        with self.assertRaises(ValueError):
            student.change_password("student1", "WRONG_CURRENT", "NewSecure!Pass99")

    def test_change_password_weak_new_rejected(self):
        """New password failing complexity policy must be rejected before hashing."""
        student = self.StudentService()
        with self.assertRaises(ValueError):
            student.change_password("student1", "StrongPass!234", "weak")

    def test_change_password_same_as_current_rejected(self):
        """New password identical to current must be rejected."""
        student = self.StudentService()
        with self.assertRaises(ValueError):
            student.change_password("student1", "StrongPass!234", "StrongPass!234")

    def test_lecturer_can_change_own_password(self):
        lecturer = self.LecturerService()
        auth = self.AuthenticationService()
        lecturer.change_password("lecturer1", "StrongPass!234", "NewLecPass!99")
        session = auth.login("lecturer1", "NewLecPass!99")
        self.assertEqual(session["username"], "lecturer1")

    def test_admin_can_change_own_password(self):
        admin = self.AdminService()
        auth = self.AuthenticationService()
        admin.change_password("admin1", "StrongPass!234", "NewAdminPass!99")
        session = auth.login("admin1", "NewAdminPass!99")
        self.assertEqual(session["username"], "admin1")

    def test_change_password_is_audited(self):
        """Password change success must appear in the audit log."""
        student = self.StudentService()
        admin = self.AdminService()
        student.change_password("student1", "StrongPass!234", "NewSecure!Pass99")
        logs = admin.view_audit_logs("admin1")
        actions = [e["action"] for e in logs]
        self.assertIn("change_password_success", actions)

    # ------------------------------------------------------------------ #
    # Profile view — all roles                                              #
    # ------------------------------------------------------------------ #

    def test_student_can_view_own_profile(self):
        student = self.StudentService()
        profile = student.view_profile("student1")
        self.assertEqual(profile["username"], "student1")
        self.assertEqual(profile["role"], "student")

    def test_lecturer_can_view_own_profile(self):
        lecturer = self.LecturerService()
        profile = lecturer.view_profile("lecturer1")
        self.assertEqual(profile["username"], "lecturer1")
        self.assertEqual(profile["role"], "lecturer")

    def test_admin_can_view_own_profile(self):
        admin = self.AdminService()
        profile = admin.view_profile("admin1")
        self.assertEqual(profile["username"], "admin1")
        self.assertEqual(profile["role"], "admin")

    # ------------------------------------------------------------------ #
    # GDPR Article 15 — data export                                         #
    # ------------------------------------------------------------------ #

    def test_student_can_export_own_data(self):
        """Export must include profile, grades, assignments, feedback, and messages."""
        student = self.StudentService()
        student.upload_assignment("student1", "CW1", "my work")
        export = student.export_my_data("student1")
        self.assertEqual(export["subject"], "student1")
        self.assertIn("profile", export)
        self.assertIn("grades", export)
        self.assertIn("assignments", export)
        self.assertIn("feedback", export)
        self.assertIn("messages", export)
        self.assertIn("CW1", export["assignments"])

    def test_data_export_includes_messages(self):
        student = self.StudentService()
        student.send_message("student1", "lecturer1", "Hello")
        export = student.export_my_data("student1")
        self.assertEqual(len(export["messages"]), 1)
        self.assertEqual(export["messages"][0]["from"], "student1")

    def test_admin_can_export_any_user_data(self):
        admin = self.AdminService()
        student = self.StudentService()
        student.upload_assignment("student1", "CW1", "my work")
        export = admin.export_user_data("admin1", "student1")
        self.assertEqual(export["subject"], "student1")
        self.assertEqual(export["requested_by"], "admin1")
        self.assertIn("CW1", export["assignments"])

    def test_student_cannot_export_another_users_data(self):
        """Students only have export_own_data, not export_any_user_data."""
        admin_svc = self.AdminService()
        with self.assertRaises(PermissionError):
            admin_svc.export_user_data("student1", "student2")

    def test_data_export_is_audited(self):
        student = self.StudentService()
        admin = self.AdminService()
        student.export_my_data("student1")
        logs = admin.view_audit_logs("admin1")
        actions = [e["action"] for e in logs]
        self.assertIn("gdpr_art15_data_export", actions)

    # ------------------------------------------------------------------ #
    # GDPR Article 17 — anonymisation                                       #
    # ------------------------------------------------------------------ #

    def test_student_can_request_own_anonymisation(self):
        """Self-service anonymisation must deactivate account and replace PII."""
        student = self.StudentService()
        repo = self.UserRepository()
        result = student.request_anonymisation("student1", "StrongPass!234")
        self.assertEqual(result["status"], "anonymised")
        self.assertTrue(result["account_deactivated"])
        user = repo.find_user("student1")
        self.assertFalse(user.active)
        self.assertTrue(user.profile.get("anonymised"))
        self.assertNotIn("student1", user.profile.get("email", ""))

    def test_anonymisation_purges_messages(self):
        """After anonymisation the user's messages must be removed from the store."""
        student = self.StudentService()
        student.send_message("student1", "lecturer1", "Hello")
        data_store = self.SecureDataStore()
        self.assertEqual(len(data_store.load_messages()), 1)
        student.request_anonymisation("student1", "StrongPass!234")
        self.assertEqual(len(data_store.load_messages()), 0)

    def test_anonymisation_retains_academic_records(self):
        """Grades and assignments must be retained under Art.17(3)(b)."""
        student = self.StudentService()
        lecturer = self.LecturerService()
        student.upload_assignment("student1", "CW1", "work")
        lecturer.set_grade("lecturer1", "student1", "CW1", "75")
        student.request_anonymisation("student1", "StrongPass!234")
        data = self.SecureDataStore().load_system_data()
        self.assertIn("CW1", data["assignments"].get("student1", {}))
        self.assertIn("CW1", data["grades"].get("student1", {}))

    def test_anonymisation_wrong_password_rejected(self):
        student = self.StudentService()
        with self.assertRaises(ValueError):
            student.request_anonymisation("student1", "WRONG")

    def test_anonymised_account_cannot_login(self):
        student = self.StudentService()
        auth = self.AuthenticationService()
        student.request_anonymisation("student1", "StrongPass!234")
        with self.assertRaises(PermissionError):
            auth.login("student1", "StrongPass!234")

    def test_admin_can_anonymise_user(self):
        """Admin-initiated anonymisation must deactivate and pseudonymise the target."""
        admin = self.AdminService()
        repo = self.UserRepository()
        result = admin.anonymise_user("admin1", "student1")
        self.assertEqual(result["status"], "anonymised")
        user = repo.find_user("student1")
        self.assertFalse(user.active)
        self.assertTrue(user.profile.get("anonymised"))

    def test_admin_cannot_anonymise_self(self):
        admin = self.AdminService()
        with self.assertRaises(ValueError):
            admin.anonymise_user("admin1", "admin1")

    def test_student_cannot_anonymise_another_user(self):
        admin_svc = self.AdminService()
        with self.assertRaises(PermissionError):
            admin_svc.anonymise_user("student1", "student2")

    def test_anonymisation_is_audited(self):
        student = self.StudentService()
        admin = self.AdminService()
        student.request_anonymisation("student1", "StrongPass!234")
        logs = admin.view_audit_logs("admin1")
        actions = [e["action"] for e in logs]
        self.assertIn("gdpr_art17_anonymisation", actions)

    # ------------------------------------------------------------------ #
    # Email validation                                                      #
    # ------------------------------------------------------------------ #

    def test_valid_email_accepted(self):
        from utils.validators import validate_email
        self.assertEqual(validate_email("user@example.com"), "user@example.com")
        self.assertEqual(validate_email("USER@EXAMPLE.COM"), "user@example.com")
        self.assertEqual(validate_email("  user+tag@sub.domain.org  "), "user+tag@sub.domain.org")

    def test_invalid_email_no_at_rejected(self):
        from utils.validators import validate_email
        with self.assertRaises(ValueError):
            validate_email("notanemail")

    def test_invalid_email_no_tld_rejected(self):
        from utils.validators import validate_email
        with self.assertRaises(ValueError):
            validate_email("user@domain")

    def test_invalid_email_double_at_rejected(self):
        from utils.validators import validate_email
        with self.assertRaises(ValueError):
            validate_email("user@@domain.com")

    def test_blank_email_rejected(self):
        from utils.validators import validate_email
        with self.assertRaises(ValueError):
            validate_email("")

    def test_register_user_rejects_invalid_email(self):
        admin = self.AdminService()
        with self.assertRaises(ValueError):
            admin.register_user(
                "admin1", "newuser99", "StrongPass!8", "student", "New User", "not-an-email"
            )

    def test_register_user_accepts_valid_email(self):
        admin = self.AdminService()
        repo = self.UserRepository()
        admin.register_user(
            "admin1", "validemailuser", "StrongPass!8", "student", "Valid User", "valid@example.com"
        )
        user = repo.find_user("validemailuser")
        self.assertIsNotNone(user)
        self.assertEqual(user.profile["email"], "valid@example.com")

    # ------------------------------------------------------------------ #
    # Admin profile update                                                  #
    # ------------------------------------------------------------------ #

    def test_admin_can_update_user_full_name(self):
        admin = self.AdminService()
        repo = self.UserRepository()
        admin.update_user_profile("admin1", "student1", full_name="Updated Name")
        user = repo.find_user("student1")
        self.assertEqual(user.profile["full_name"], "Updated Name")

    def test_admin_can_update_user_email(self):
        admin = self.AdminService()
        repo = self.UserRepository()
        admin.update_user_profile("admin1", "student1", email="New@Email.COM")
        user = repo.find_user("student1")
        self.assertEqual(user.profile["email"], "new@email.com")

    def test_profile_update_notifies_user(self):
        admin = self.AdminService()
        data_store = self.SecureDataStore()
        admin.update_user_profile("admin1", "student1", full_name="Notified Student")
        messages = data_store.load_messages()
        notifications = [m for m in messages if m.get("to") == "student1"]
        self.assertGreater(len(notifications), 0)
        self.assertIn("profile has been updated", notifications[-1]["body"])

    def test_profile_update_rejects_invalid_email(self):
        admin = self.AdminService()
        with self.assertRaises(ValueError):
            admin.update_user_profile("admin1", "student1", email="bademail")

    def test_profile_update_with_no_changes_raises(self):
        admin = self.AdminService()
        admin.update_user_profile("admin1", "student1", full_name="Alice")
        with self.assertRaises(ValueError):
            admin.update_user_profile("admin1", "student1", full_name="Alice")

    def test_student_cannot_update_profile(self):
        admin_svc = self.AdminService()
        with self.assertRaises(PermissionError):
            admin_svc.update_user_profile("student1", "student2", full_name="Hacked")

    # ------------------------------------------------------------------ #
    # Rate limiting                                                         #
    # ------------------------------------------------------------------ #

    def test_message_rate_limit_enforced(self):
        from utils.rate_limiter import message_limiter, RateLimitError
        message_limiter.reset("ratelimit_test_sender")
        for _ in range(10):
            message_limiter.is_allowed("ratelimit_test_sender")
        self.assertFalse(message_limiter.is_allowed("ratelimit_test_sender"))

    def test_submission_rate_limit_enforced(self):
        from utils.rate_limiter import submission_limiter
        submission_limiter.reset("ratelimit_student")
        for _ in range(5):
            submission_limiter.is_allowed("ratelimit_student")
        self.assertFalse(submission_limiter.is_allowed("ratelimit_student"))

    def test_login_rate_limit_enforced(self):
        from utils.rate_limiter import login_limiter
        login_limiter.reset("rate_limited_user")
        for _ in range(5):
            login_limiter.is_allowed("rate_limited_user")
        self.assertFalse(login_limiter.is_allowed("rate_limited_user"))

    # ------------------------------------------------------------------ #
    # RBAC                                                                  #
    # ------------------------------------------------------------------ #

    def test_rbac_blocks_student_from_admin_operation(self):
        admin = self.AdminService()
        with self.assertRaises(PermissionError):
            admin.view_all_users("student1")

    def test_student_cannot_message_admin(self):
        student = self.StudentService()
        with self.assertRaises(ValueError):
            student.send_message("student1", "admin1", "Hello admin")

    def test_lecturer_cannot_message_admin(self):
        lecturer = self.LecturerService()
        with self.assertRaises(ValueError):
            lecturer.send_message("lecturer1", "admin1", "Hello admin")

    # ------------------------------------------------------------------ #
    # Assignment workflow                                                   #
    # ------------------------------------------------------------------ #

    def test_assignment_grade_and_feedback_flow(self):
        student = self.StudentService()
        lecturer = self.LecturerService()
        student.upload_assignment("student1", "CW1", "submission")
        lecturer.set_grade("lecturer1", "student1", "CW1", "82")
        lecturer.give_feedback("lecturer1", "student1", "CW1", "Well done")
        grades = student.view_grades("student1")
        self.assertEqual(grades["grades"]["CW1"], "82")
        self.assertEqual(grades["feedback"]["CW1"], "Well done")

    def test_student_can_view_uploaded_assignments(self):
        student = self.StudentService()
        student.upload_assignment("student1", "CW1", "submission")
        assignments = student.view_assignments("student1")
        self.assertIn("CW1", assignments["assignments"])
        self.assertEqual(assignments["assignments"]["CW1"]["submitted_by"], "student1")

    def test_lecturer_can_list_students_with_submissions(self):
        student = self.StudentService()
        lecturer = self.LecturerService()
        student.upload_assignment("student1", "CW1", "submission")
        student.upload_assignment("student2", "CW2", "submission")
        students = lecturer.list_students_with_submissions("lecturer1")
        self.assertIn("student1", students)
        self.assertIn("student2", students)

    def test_invalid_student_name_is_rejected(self):
        lecturer = self.LecturerService()
        with self.assertRaises(ValueError):
            lecturer.view_student_submissions("lecturer1", "missing_student")

    def test_invalid_grade_is_rejected(self):
        student = self.StudentService()
        lecturer = self.LecturerService()
        student.upload_assignment("student1", "CW1", "submission")
        with self.assertRaises(ValueError):
            lecturer.set_grade("lecturer1", "student1", "CW1", "abc")
        with self.assertRaises(ValueError):
            lecturer.set_grade("lecturer1", "student1", "CW1", "120")

    def test_grading_missing_assignment_is_rejected(self):
        lecturer = self.LecturerService()
        with self.assertRaises(ValueError):
            lecturer.set_grade("lecturer1", "student1", "MISSING", "80")

    # ------------------------------------------------------------------ #
    # Non-repudiation: assignment signatures                               #
    # ------------------------------------------------------------------ #

    def test_assignment_signature_is_stored_on_upload(self):
        student = self.StudentService()
        student.upload_assignment("student1", "CW1", "my submission content")
        data = self.SecureDataStore().load_system_data()
        submission = data["assignments"]["student1"]["CW1"]
        self.assertIn("signature", submission)
        self.assertGreater(len(submission["signature"]), 0)

    def test_assignment_signature_verifies_correctly(self):
        student = self.StudentService()
        student.upload_assignment("student1", "CW1", "my submission content")
        self.assertTrue(student.verify_assignment_signature("student1", "CW1"))

    def test_tampered_assignment_fails_signature_check(self):
        student = self.StudentService()
        student.upload_assignment("student1", "CW1", "original content")
        data_store = self.SecureDataStore()
        data = data_store.load_system_data()
        data["assignments"]["student1"]["CW1"]["content"] = "tampered content"
        data_store.save_system_data(data)
        self.assertFalse(student.verify_assignment_signature("student1", "CW1"))

    def test_lecturer_can_verify_submission_signature(self):
        student = self.StudentService()
        lecturer = self.LecturerService()
        student.upload_assignment("student1", "CW1", "authentic submission")
        result = lecturer.verify_submission_signature("lecturer1", "student1", "CW1")
        self.assertTrue(result)

    # ------------------------------------------------------------------ #
    # Non-repudiation: message signatures                                  #
    # ------------------------------------------------------------------ #

    def test_message_signature_stored_on_send(self):
        student = self.StudentService()
        student.send_message("student1", "lecturer1", "Hello lecturer")
        messages = self.SecureDataStore().load_messages()
        self.assertIn("signature", messages[0])

    def test_message_signature_is_valid(self):
        from crypto.signing import SigningManager
        student = self.StudentService()
        student.send_message("student1", "lecturer1", "Hello lecturer")
        messages = self.SecureDataStore().load_messages()
        msg = messages[0]
        signature = msg["signature"]
        payload = {"from": msg["from"], "to": msg["to"], "body": msg["body"]}
        signing = SigningManager()
        self.assertTrue(signing.verify_json(payload, signature))

    # ------------------------------------------------------------------ #
    # Messaging                                                             #
    # ------------------------------------------------------------------ #

    def test_student_can_send_and_view_messages(self):
        student = self.StudentService()
        lecturer = self.LecturerService()
        student.send_message("student1", "lecturer1", "Hello lecturer")
        lecturer.send_message("lecturer1", "student1", "Hello student")
        result = student.view_messages("student1")
        self.assertEqual(len(result["messages"]), 2)

    def test_lecturer_can_view_thread_with_student(self):
        student = self.StudentService()
        lecturer = self.LecturerService()
        student.send_message("student1", "lecturer1", "Question about feedback")
        lecturer.send_message("lecturer1", "student1", "Please check the rubric")
        thread = lecturer.view_messages_with_student("lecturer1", "student1")
        self.assertEqual(thread["student"], "student1")
        self.assertEqual(len(thread["messages"]), 2)

    # ------------------------------------------------------------------ #
    # Admin operations                                                      #
    # ------------------------------------------------------------------ #

    def test_admin_can_register_new_user(self):
        admin = self.AdminService()
        repo = self.UserRepository()
        admin.register_user("admin1", "newstudent", "StrongPass!8", "student", "New Student", "ns@example.com")
        user = repo.find_user("newstudent")
        self.assertIsNotNone(user)
        self.assertEqual(user.role, "student")
        self.assertTrue(user.active)

    def test_admin_can_deactivate_and_reactivate_user(self):
        admin = self.AdminService()
        repo = self.UserRepository()
        admin.deactivate_user("admin1", "student1")
        self.assertFalse(repo.find_user("student1").active)
        admin.reactivate_user("admin1", "student1")
        self.assertTrue(repo.find_user("student1").active)

    def test_deactivated_user_cannot_login_until_reactivated(self):
        admin = self.AdminService()
        auth = self.AuthenticationService()
        admin.deactivate_user("admin1", "student1")
        with self.assertRaises(PermissionError):
            auth.login("student1", "StrongPass!234")
        admin.reactivate_user("admin1", "student1")
        session = auth.login("student1", "StrongPass!234")
        self.assertEqual(session["username"], "student1")

    def test_admin_cannot_register_duplicate_username(self):
        admin = self.AdminService()
        with self.assertRaises(ValueError):
            admin.register_user("admin1", "student1", "StrongPass!8", "student", "Dup", "d@t.com")

    def test_admin_cannot_deactivate_self(self):
        admin = self.AdminService()
        with self.assertRaises(ValueError):
            admin.deactivate_user("admin1", "admin1")

    # ------------------------------------------------------------------ #
    # Cryptographic primitives                                             #
    # ------------------------------------------------------------------ #

    def test_envelope_encryption_round_trip(self):
        encryption = self.EncryptionManager()
        key_manager = self.KeyManager()
        payload = {"secret": "top secret", "value": 123}
        envelope = encryption.envelope_encrypt(payload, key_manager.server_ecdh_public_pem())
        recovered = encryption.envelope_decrypt(envelope)
        self.assertEqual(recovered, payload)

    def test_ecdsa_signature_verification(self):
        signing = self.SigningManager()
        payload = {"event": "test", "status": "ok"}
        signature = signing.sign_json(payload)
        self.assertTrue(signing.verify_json(payload, signature))

    def test_ecdsa_detects_tampered_payload(self):
        signing = self.SigningManager()
        payload = {"event": "test", "status": "ok"}
        signature = signing.sign_json(payload)
        tampered = {"event": "test", "status": "tampered"}
        self.assertFalse(signing.verify_json(tampered, signature))

    def test_hmac_integrity(self):
        integrity = self.IntegrityManager()
        key = b"k" * 32
        data = b"important"
        mac = integrity.generate_hmac(key, data)
        self.assertTrue(integrity.verify_hmac(key, data, mac))
        self.assertFalse(integrity.verify_hmac(key, b"tampered", mac))

    def test_expired_sessions_are_pruned_on_verify(self):
        import json
        from datetime import datetime, timedelta, timezone
        from config import SESSION_FILE
        from crypto.session import SessionManager

        sm = SessionManager()
        token = sm.issue_token("student1", "student")

        store = json.loads(SESSION_FILE.read_text(encoding="utf-8"))
        store["active_sessions"].append({
            "sid": "fake-expired-sid",
            "username": "nobody",
            "expires_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        })
        SESSION_FILE.write_text(json.dumps(store, indent=2), encoding="utf-8")

        sm.verify_token(token)

        store_after = json.loads(SESSION_FILE.read_text(encoding="utf-8"))
        sids = [e["sid"] for e in store_after["active_sessions"]]
        self.assertNotIn("fake-expired-sid", sids)

    # ------------------------------------------------------------------ #
    # Salting
    # ------------------------------------------------------------------ #

    def test_hkdf_salt_is_created_and_reused(self):
        key_manager = self.KeyManager()
        if key_manager.hkdf_salt_path.exists():
            key_manager.hkdf_salt_path.unlink()
        salt1 = key_manager._load_or_create_hkdf_salt()
        salt2 = key_manager._load_or_create_hkdf_salt()
        self.assertTrue(key_manager.hkdf_salt_path.exists())
        self.assertIsInstance(salt1, bytes)
        self.assertEqual(len(salt1), 32)
        self.assertEqual(salt1, salt2)

    def test_derive_shared_key_is_repeatable_for_same_inputs(self):
        key_manager = self.KeyManager()
        private_key = key_manager.server_ecdh_private_key()
        public_pem = key_manager.server_ecdh_public_pem()
        key1 = key_manager.derive_shared_key(private_key, public_pem, info=b"test-channel")
        key2 = key_manager.derive_shared_key(private_key, public_pem, info=b"test-channel")
        self.assertIsInstance(key1, bytes)
        self.assertEqual(len(key1), 32)
        self.assertEqual(key1, key2)

    def test_different_salt_produces_different_key(self):
        key_manager = self.KeyManager()
        private_key = key_manager.server_ecdh_private_key()
        public_pem = key_manager.server_ecdh_public_pem()
        key_manager.hkdf_salt_path.write_bytes(b"A" * 32)
        key1 = key_manager.derive_shared_key(private_key, public_pem, info=b"test-channel")
        key_manager.hkdf_salt_path.write_bytes(b"B" * 32)
        key2 = key_manager.derive_shared_key(private_key, public_pem, info=b"test-channel")
        self.assertNotEqual(key1, key2)


if __name__ == "__main__":
    unittest.main()