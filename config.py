import os

SECRET_KEY = os.environ.get(
    "SECRET_KEY",
    "dev-only-change-me-in-production-9f3a2c1b8e7d4f5a",
)

JWT_ALGORITHM = "HS256"
JWT_EXP_MINUTES = int(os.environ.get("JWT_EXP_MINUTES", "30"))

DB_PATH = os.environ.get("DB_PATH", "users.db")
LOG_PATH = os.environ.get("LOG_PATH", "security.log")

SEED_ADMIN_USERNAME = "admin"
SEED_ADMIN_PASSWORD = "Admin123!"
