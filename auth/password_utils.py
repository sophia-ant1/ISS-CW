"""Thin wrapper exposing password hashing utilities to the auth package."""
from crypto.hashing import PasswordManager

password_manager = PasswordManager()
