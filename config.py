""" Global configuration values across the system"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
USERS_FILE = DATA_DIR / "users.json"
SYSTEM_DATA_FILE = DATA_DIR / "system_data.enc"
KEYS_DIR = DATA_DIR / "keys"
AUDIT_LOG_FILE = DATA_DIR / "audit_log.json"
MESSAGES_FILE = DATA_DIR / "messages.enc"
SESSION_FILE = DATA_DIR / "active_sessions.json"

TOKEN_TTL_SECONDS = 3600
JWT_ISSUER = "secure-learning-system"
JWT_AUDIENCE = "secure-learning-system-users"
