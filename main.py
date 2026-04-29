"""Entry point for the secure learning system.

Default behaviour runs a deterministic demo so the project can be tested quickly.
Use --interactive to explore menu-driven flows manually.
"""
from __future__ import annotations

import argparse
import json
import jwt
from auth.login import AuthenticationService
from services.admin_service import AdminService
from services.lecturer_service import LecturerService
from services.student_service import StudentService


DEMO_USERS = [
    ("alice_student", "StudentPass!234", "student", {"full_name": "Alice Student", "email": "alice@example.local"}),
    ("leo_lecturer", "LecturerPass!234", "lecturer", {"full_name": "Leo Lecturer", "email": "leo@example.local"}),
    ("amy_admin", "AdminPass!234", "admin", {"full_name": "Amy Admin", "email": "amy@example.local"}),
]


def seed_demo_data() -> None:
    """Create a clean demo dataset if the expected users do not already exist."""
    from auth.register import UserRepository
    from models.data import SecureDataStore

    user_repo = UserRepository()
    data_store = SecureDataStore()

    for username, password, role, profile in DEMO_USERS:
        if not user_repo.find_user(username):
            user_repo.create_user(username, password, role, profile)

    data = data_store.load_system_data()
    data.setdefault("grades", {}).setdefault("alice_student", {})
    data.setdefault("assignments", {}).setdefault("alice_student", {})
    data.setdefault("feedback", {}).setdefault("alice_student", {})
    data_store.save_system_data(data)


def run_demo() -> None:
    """Execute an end-to-end scenario covering the three coursework roles."""
    seed_demo_data()
    auth = AuthenticationService()
    student_service = StudentService()
    lecturer_service = LecturerService()
    admin_service = AdminService()

    student_session = auth.login("alice_student", "StudentPass!234")
    token = student_session["token"]
    lecturer_session = auth.login("leo_lecturer", "LecturerPass!234")
    admin_session = auth.login("amy_admin", "AdminPass!234")

    # Token verification
    from crypto.session import SessionManager
    sm = SessionManager()
    claims = sm.verify_token(token)

    # Core workflow
    student_service.upload_assignment("alice_student", "CW1", "My secure coursework submission.")
    student_service.send_message("alice_student", "leo_lecturer", "Hello, I have uploaded my assignment.")
    lecturer_service.set_grade("leo_lecturer", "alice_student", "CW1", "78")
    lecturer_service.give_feedback(
        "leo_lecturer", "alice_student", "CW1", "Strong security architecture and clear code structure."
    )
    lecturer_service.send_message("leo_lecturer", "alice_student", "Your assignment has been marked.")

    # Profile view (all three roles)
    student_profile = student_service.view_profile("alice_student")
    lecturer_profile = lecturer_service.view_profile("leo_lecturer")
    admin_profile = admin_service.view_profile("amy_admin")

    # GDPR Art.15 — data export
    student_export = student_service.export_my_data("alice_student")
    admin_export = admin_service.export_user_data("amy_admin", "alice_student")

    # Standard read operations
    assignments = student_service.view_assignments("alice_student")
    grades = student_service.view_grades("alice_student")
    messages = student_service.view_messages("alice_student")
    all_users = admin_service.view_all_users("amy_admin")
    logs = admin_service.view_audit_logs("amy_admin")

    # GDPR Art.17 — admin anonymises a separate test user
    # (alice_student not anonymised here so the rest of the demo output remains readable)
    from auth.register import UserRepository
    repo = UserRepository()
    if not repo.find_user("demo_erasure"):
        repo.create_user("demo_erasure", "EraseMe!Pass99", "student", {"email": "erase@example.local"})
    erasure_result = admin_service.anonymise_user("amy_admin", "demo_erasure")

    output = {
        "student_session": {"username": student_session["username"], "role": student_session["role"]},
        "TOKEN:":student_session["token"],
        "Decoded_token:":jwt.get_unverified_header(token),
        "Claim:": claims,
        "lecturer_session": {"username": lecturer_session["username"], "role": lecturer_session["role"]},
        "admin_session": {"username": admin_session["username"], "role": admin_session["role"]},
        "student_profile": student_profile,
        "lecturer_profile": lecturer_profile,
        "admin_profile": admin_profile,
        "gdpr_art15_student_export_keys": list(student_export.keys()),
        "gdpr_art15_admin_export_subject": admin_export["subject"],
        "gdpr_art17_erasure": erasure_result,
        "student_assignments": assignments,
        "student_grades": grades,
        "student_messages": messages,
        "all_users_count": len(all_users),
        "verified_log_entries": len(logs),
    }
    print(json.dumps(output, indent=2))


def prompt_choice(valid_choices: set[str], prompt: str = "Choice: ") -> str:
    while True:
        choice = input(prompt).strip()
        if choice in valid_choices:
            return choice
        print(f"Invalid choice. Please enter one of: {', '.join(sorted(valid_choices))}")


def prompt_non_empty(label: str) -> str:
    while True:
        value = input(label).strip()
        if value:
            return value
        print("Input cannot be blank.")


def choose_from_numbered_list(options: list[str], heading: str) -> str | None:
    while True:
        print(f"\n{heading}")
        print("1. Back")
        for index, option in enumerate(options, start=2):
            print(f"{index}. {option}")
        valid_choices = {str(i) for i in range(1, len(options) + 2)}
        choice = prompt_choice(valid_choices, "Choice: ")
        if choice == "1":
            return None
        return options[int(choice) - 2]


# ------------------------------------------------------------------ #
# Shared flows (used by all roles)                                    #
# ------------------------------------------------------------------ #

def change_password_flow(service, username: str) -> None:
    """Shared password-change flow for any role's service object."""
    print("\nChange password")
    print("1. Back")
    print("2. Proceed")
    if prompt_choice({"1", "2"}) == "1":
        return
    current = prompt_non_empty("Current password: ")
    new_pw = prompt_non_empty("New password: ")
    confirm = prompt_non_empty("Confirm new password: ")
    if new_pw != confirm:
        print("Passwords do not match.")
        return
    try:
        service.change_password(username, current, new_pw)
        print("Password changed successfully.")
    except (ValueError, PermissionError) as exc:
        print(f"Password change failed: {exc}")


def export_own_data_flow(service, username: str) -> None:
    """GDPR Art.15 self-service data export for any role."""
    try:
        export = service.export_my_data(username)
        print(json.dumps(export, indent=2))
    except (ValueError, PermissionError) as exc:
        print(f"Export failed: {exc}")


# ------------------------------------------------------------------ #
# Student flows                                                        #
# ------------------------------------------------------------------ #

def student_upload_assignment_flow(student_service: StudentService, username: str) -> None:
    while True:
        print("\nUpload assignment")
        print("1. Back")
        print("2. Enter assignment name")
        if prompt_choice({"1", "2"}) == "1":
            return
        assignment_name = prompt_non_empty("Assignment name: ")
        while True:
            print("\nUpload assignment content")
            print("1. Back")
            print("2. Enter content")
            if prompt_choice({"1", "2"}) == "1":
                break
            content = prompt_non_empty("Content: ")
            try:
                student_service.upload_assignment(username, assignment_name, content)
                print("Assignment uploaded successfully.")
            except PermissionError as exc:
                print(f"Upload blocked: {exc}")
            return


def student_send_message_flow(student_service: StudentService, username: str) -> None:
    while True:
        print("\nSend message to lecturer")
        print("1. Back")
        print("2. Enter lecturer username")
        if prompt_choice({"1", "2"}) == "1":
            return
        recipient = prompt_non_empty("Lecturer username: ")
        while True:
            print("\nEnter message")
            print("1. Back")
            print("2. Enter message body")
            if prompt_choice({"1", "2"}) == "1":
                break
            body = prompt_non_empty("Message: ")
            try:
                student_service.send_message(username, recipient, body)
                print("Message sent successfully.")
            except PermissionError as exc:
                print(f"Message blocked: {exc}")
            return


def student_anonymisation_flow(student_service: StudentService, username: str) -> None:
    """GDPR Art.17 self-service anonymisation for students."""
    print("\n⚠  GDPR Article 17 — Right to Erasure")
    print("This will irreversibly anonymise your account.")
    print("Academic records (grades, assignments) are retained under Art.17(3)(b).")
    print("Your account will be deactivated. This cannot be undone.")
    print("1. Back")
    print("2. Proceed with anonymisation")
    if prompt_choice({"1", "2"}) == "1":
        return
    current = prompt_non_empty("Confirm current password: ")
    try:
        result = student_service.request_anonymisation(username, current)
        print(json.dumps(result, indent=2))
        print("You have been logged out.")
        return "logout"
    except (ValueError, PermissionError) as exc:
        print(f"Anonymisation failed: {exc}")


def student_menu(auth: AuthenticationService, session: dict, student_service: StudentService) -> None:
    username = session["username"]
    token = session["token"]

    while True:
        print("\nStudent menu")
        print("1. View profile")
        print("2. View grades")
        print("3. View uploaded assignments")
        print("4. Upload assignment")
        print("5. Send message to lecturer")
        print("6. View my messages")
        print("7. Change password")
        print("8. Export my data (GDPR Art.15)")
        print("9. Request account anonymisation (GDPR Art.17)")
        print("10. Logout")

        choice = prompt_choice({"1","2","3","4","5","6","7","8","9","10"})

        try:
            if choice == "1":
                print(json.dumps(student_service.view_profile(username), indent=2))
            elif choice == "2":
                print(json.dumps(student_service.view_grades(username), indent=2))
            elif choice == "3":
                print(json.dumps(student_service.view_assignments(username), indent=2))
            elif choice == "4":
                student_upload_assignment_flow(student_service, username)
            elif choice == "5":
                student_send_message_flow(student_service, username)
            elif choice == "6":
                print(json.dumps(student_service.view_messages(username), indent=2))
            elif choice == "7":
                change_password_flow(student_service, username)
            elif choice == "8":
                export_own_data_flow(student_service, username)
            elif choice == "9":
                result = student_anonymisation_flow(student_service, username)
                if result == "logout":
                    auth.logout(token)
                    return
            elif choice == "10":
                auth.logout(token)
                print("Logged out successfully.")
                return
        except Exception as exc:
            print(f"Error: {exc}")


# ------------------------------------------------------------------ #
# Lecturer flows                                                       #
# ------------------------------------------------------------------ #

def choose_student_with_submissions(lecturer_service: LecturerService, lecturer_username: str) -> str | None:
    students = lecturer_service.list_students_with_submissions(lecturer_username)
    if not students:
        print("There are no student submissions available.")
        return None
    return choose_from_numbered_list(students, "Students with submissions")


def choose_assignment_for_student(
    lecturer_service: LecturerService, lecturer_username: str, student_username: str
) -> str | None:
    submissions = lecturer_service.view_student_submissions(lecturer_username, student_username)
    assignment_names = list(submissions.keys())
    if not assignment_names:
        print("That student has no assignments.")
        return None
    return choose_from_numbered_list(assignment_names, f"Assignments for {student_username}")


def lecturer_view_submission_flow(lecturer_service: LecturerService, lecturer_username: str) -> None:
    while True:
        student_username = choose_student_with_submissions(lecturer_service, lecturer_username)
        if student_username is None:
            return
        while True:
            assignment_name = choose_assignment_for_student(lecturer_service, lecturer_username, student_username)
            if assignment_name is None:
                break
            submissions = lecturer_service.view_student_submissions(lecturer_username, student_username)
            print(json.dumps({assignment_name: submissions[assignment_name]}, indent=2))
            return


def lecturer_set_grade_flow(lecturer_service: LecturerService, lecturer_username: str) -> None:
    while True:
        student_username = choose_student_with_submissions(lecturer_service, lecturer_username)
        if student_username is None:
            return
        while True:
            assignment_name = choose_assignment_for_student(lecturer_service, lecturer_username, student_username)
            if assignment_name is None:
                break
            while True:
                print("\nSet grade")
                print("1. Back")
                print("2. Enter grade")
                if prompt_choice({"1", "2"}) == "1":
                    break
                grade = prompt_non_empty("Grade (0-100): ")
                lecturer_service.set_grade(lecturer_username, student_username, assignment_name, grade)
                print("Grade saved successfully.")
                return


def lecturer_feedback_flow(lecturer_service: LecturerService, lecturer_username: str) -> None:
    while True:
        student_username = choose_student_with_submissions(lecturer_service, lecturer_username)
        if student_username is None:
            return
        while True:
            assignment_name = choose_assignment_for_student(lecturer_service, lecturer_username, student_username)
            if assignment_name is None:
                break
            while True:
                print("\nGive feedback")
                print("1. Back")
                print("2. Enter feedback")
                if prompt_choice({"1", "2"}) == "1":
                    break
                feedback = prompt_non_empty("Feedback: ")
                lecturer_service.give_feedback(lecturer_username, student_username, assignment_name, feedback)
                print("Feedback saved successfully.")
                return


def lecturer_send_message_flow(lecturer_service: LecturerService, lecturer_username: str) -> None:
    while True:
        students = lecturer_service.list_students_with_submissions(lecturer_username)
        if not students:
            print("There are no students available for messaging.")
            return
        recipient = choose_from_numbered_list(students, "Students available for messaging")
        if recipient is None:
            return
        while True:
            print("\nSend message to student")
            print("1. Back")
            print("2. Enter message body")
            if prompt_choice({"1", "2"}) == "1":
                break
            body = prompt_non_empty("Message: ")
            try:
                lecturer_service.send_message(lecturer_username, recipient, body)
                print("Message sent successfully.")
            except PermissionError as exc:
                print(f"Message blocked: {exc}")
            return


def lecturer_view_thread_flow(lecturer_service: LecturerService, lecturer_username: str) -> None:
    while True:
        students = lecturer_service.list_students_with_message_threads(lecturer_username)
        if not students:
            print("There are no message threads available.")
            return
        recipient = choose_from_numbered_list(students, "Students with message threads")
        if recipient is None:
            return
        print(json.dumps(lecturer_service.view_messages_with_student(lecturer_username, recipient), indent=2))
        return


def lecturer_menu(auth: AuthenticationService, session: dict, lecturer_service: LecturerService) -> None:
    username = session["username"]
    token = session["token"]

    while True:
        print("\nLecturer menu")
        print("1. View profile")
        print("2. View student submissions")
        print("3. Set grade")
        print("4. Give feedback")
        print("5. Send message to student")
        print("6. View messages with student")
        print("7. Change password")
        print("8. Export my data (GDPR Art.15)")
        print("9. Logout")

        choice = prompt_choice({"1","2","3","4","5","6","7","8","9"})

        try:
            if choice == "1":
                print(json.dumps(lecturer_service.view_profile(username), indent=2))
            elif choice == "2":
                lecturer_view_submission_flow(lecturer_service, username)
            elif choice == "3":
                lecturer_set_grade_flow(lecturer_service, username)
            elif choice == "4":
                lecturer_feedback_flow(lecturer_service, username)
            elif choice == "5":
                lecturer_send_message_flow(lecturer_service, username)
            elif choice == "6":
                lecturer_view_thread_flow(lecturer_service, username)
            elif choice == "7":
                change_password_flow(lecturer_service, username)
            elif choice == "8":
                export_own_data_flow(lecturer_service, username)
            elif choice == "9":
                auth.logout(token)
                print("Logged out successfully.")
                return
        except Exception as exc:
            print(f"Error: {exc}")


# ------------------------------------------------------------------ #
# Admin flows                                                          #
# ------------------------------------------------------------------ #

def admin_register_user_flow(admin_service: AdminService, admin_username: str) -> None:
    while True:
        print("\nRegister new user")
        print("1. Back")
        print("2. Enter username")
        if prompt_choice({"1", "2"}) == "1":
            return
        username = prompt_non_empty("Username: ")
        while True:
            print("\nRegister new user")
            print("1. Back")
            print("2. Enter password")
            if prompt_choice({"1", "2"}) == "1":
                break
            password = prompt_non_empty("Password: ")
            while True:
                print("\nSelect role")
                print("1. Back")
                print("2. Student")
                print("3. Lecturer")
                print("4. Admin")
                role_choice = prompt_choice({"1", "2", "3", "4"})
                if role_choice == "1":
                    break
                role = {"2": "student", "3": "lecturer", "4": "admin"}[role_choice]
                while True:
                    print("\nRegister new user")
                    print("1. Back")
                    print("2. Enter full name")
                    if prompt_choice({"1", "2"}) == "1":
                        break
                    full_name = prompt_non_empty("Full name: ")
                    while True:
                        print("\nRegister new user")
                        print("1. Back")
                        print("2. Enter email")
                        if prompt_choice({"1", "2"}) == "1":
                            break
                        email = prompt_non_empty("Email: ")
                        try:
                            admin_service.register_user(admin_username, username, password, role, full_name, email)
                            print("User registered successfully.")
                        except (ValueError, PermissionError) as exc:
                            print(f"Registration failed: {exc}")
                        return


def admin_update_profile_flow(admin_service: AdminService, admin_username: str) -> None:
    while True:
        print("\nUpdate user profile")
        print("1. Back")
        print("2. Enter target username")
        if prompt_choice({"1", "2"}) == "1":
            return
        target = prompt_non_empty("Target username: ")

        new_full_name: str | None = None
        new_email: str | None = None

        print("\nUpdate full name? (leave blank to skip)")
        raw = input("New full name: ").strip()
        if raw:
            new_full_name = raw

        print("Update email? (leave blank to skip)")
        raw = input("New email: ").strip()
        if raw:
            new_email = raw

        if new_full_name is None and new_email is None:
            print("No fields entered — returning to menu.")
            return

        try:
            admin_service.update_user_profile(admin_username, target, full_name=new_full_name, email=new_email)
            print(f"Profile updated. {target} will see a notification message on next login.")
        except (ValueError, PermissionError) as exc:
            print(f"Update failed: {exc}")
        return


def admin_deactivate_user_flow(admin_service: AdminService, admin_username: str) -> None:
    while True:
        print("\nDeactivate user")
        print("1. Back")
        print("2. Enter username to deactivate")
        if prompt_choice({"1", "2"}) == "1":
            return
        target = prompt_non_empty("Username to deactivate: ")
        if target == admin_username:
            print("You cannot deactivate the account you are currently using.")
            continue
        admin_service.deactivate_user(admin_username, target)
        print("User deactivated successfully.")
        return


def admin_reactivate_user_flow(admin_service: AdminService, admin_username: str) -> None:
    while True:
        print("\nReactivate user")
        print("1. Back")
        print("2. Enter username to reactivate")
        if prompt_choice({"1", "2"}) == "1":
            return
        target = prompt_non_empty("Username to reactivate: ")
        admin_service.reactivate_user(admin_username, target)
        print("User reactivated successfully.")
        return


def admin_export_user_data_flow(admin_service: AdminService, admin_username: str) -> None:
    """GDPR Art.15 admin-initiated subject access request."""
    while True:
        print("\nExport user data (GDPR Art.15)")
        print("1. Back")
        print("2. Enter target username")
        if prompt_choice({"1", "2"}) == "1":
            return
        target = prompt_non_empty("Target username: ")
        try:
            export = admin_service.export_user_data(admin_username, target)
            print(json.dumps(export, indent=2))
        except (ValueError, PermissionError) as exc:
            print(f"Export failed: {exc}")
        return


def admin_anonymise_user_flow(admin_service: AdminService, admin_username: str) -> None:
    """GDPR Art.17 admin-initiated erasure."""
    while True:
        print("\n⚠  GDPR Article 17 — Admin-Initiated Erasure")
        print("This will irreversibly anonymise the target account.")
        print("1. Back")
        print("2. Enter target username")
        if prompt_choice({"1", "2"}) == "1":
            return
        target = prompt_non_empty("Target username: ")
        try:
            result = admin_service.anonymise_user(admin_username, target)
            print(json.dumps(result, indent=2))
        except (ValueError, PermissionError) as exc:
            print(f"Anonymisation failed: {exc}")
        return


def admin_menu(auth: AuthenticationService, session: dict, admin_service: AdminService) -> None:
    username = session["username"]
    token = session["token"]

    while True:
        print("\nAdmin menu")
        print("1. View profile")
        print("2. View users")
        print("3. View audit logs")
        print("4. Register new user")
        print("5. Deactivate user")
        print("6. Reactivate user")
        print("7. Update user profile")
        print("8. Change password")
        print("9. Export my data (GDPR Art.15)")
        print("10. Export user data (GDPR Art.15 SAR)")
        print("11. Anonymise user (GDPR Art.17)")
        print("12. Logout")

        choice = prompt_choice({"1","2","3","4","5","6","7","8","9","10","11","12"})

        try:
            if choice == "1":
                print(json.dumps(admin_service.view_profile(username), indent=2))
            elif choice == "2":
                print(json.dumps(admin_service.view_all_users(username), indent=2))
            elif choice == "3":
                print(json.dumps(admin_service.view_audit_logs(username), indent=2))
            elif choice == "4":
                admin_register_user_flow(admin_service, username)
            elif choice == "5":
                admin_deactivate_user_flow(admin_service, username)
            elif choice == "6":
                admin_reactivate_user_flow(admin_service, username)
            elif choice == "7":
                admin_update_profile_flow(admin_service, username)
            elif choice == "8":
                change_password_flow(admin_service, username)
            elif choice == "9":
                export_own_data_flow(admin_service, username)
            elif choice == "10":
                admin_export_user_data_flow(admin_service, username)
            elif choice == "11":
                admin_anonymise_user_flow(admin_service, username)
            elif choice == "12":
                auth.logout(token)
                print("Logged out successfully.")
                return
        except Exception as exc:
            print(f"Error: {exc}")


def run_interactive() -> None:
    """Interactive mode for manual testing and screenshots."""
    seed_demo_data()
    auth = AuthenticationService()
    student_service = StudentService()
    lecturer_service = LecturerService()
    admin_service = AdminService()

    print("Secure Learning System")
    print("Demo accounts:")
    print("  alice_student / StudentPass!234")
    print("  leo_lecturer  / LecturerPass!234")
    print("  amy_admin     / AdminPass!234")

    while True:
        print("\nLogin")
        print("1. Exit")
        print("2. Enter username and password")
        if prompt_choice({"1", "2"}) == "1":
            print("Exiting system.")
            return

        try:
            username = prompt_non_empty("Username: ")
            password = prompt_non_empty("Password: ")
            session = auth.login(username, password)
            role = session["role"]
            print(f"Logged in as {session['username']} ({role})")

            if role == "student":
                student_menu(auth, session, student_service)
            elif role == "lecturer":
                lecturer_menu(auth, session, lecturer_service)
            elif role == "admin":
                admin_menu(auth, session, admin_service)
            else:
                print("Unknown role.")
                auth.logout(session["token"])

        except Exception as exc:
            print(f"Login failed: {exc}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Secure learning system demo")
    parser.add_argument("--interactive", action="store_true", help="run the interactive console mode")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.interactive:
        run_interactive()
    else:
        run_demo()