# ─────────────────────────────────────────────
#  scripts/seed_admin.py
#  Creates the default admin/analyst account.
#
#  HOW TO RUN (from the backend/ folder):
#    python scripts/seed_admin.py
#
#  This only needs to be run ONCE when setting
#  up the project for the first time.
# ─────────────────────────────────────────────
import sys
import os

# Add parent directory to path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pathlib import Path
from datetime import datetime, timezone
from passlib.context import CryptContext
from dotenv import load_dotenv
from database.connection import get_db, ping_db

# Always load .env from the backend/ folder
_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_ENV_PATH)

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin123"   # Change this after first login!
DEFAULT_FULLNAME = "Platform Administrator"


def seed():
    print("─" * 50)
    print("  Email Threat Platform — Database Seeder")
    print("─" * 50)

    # Check DB connection
    if not ping_db():
        print("✗ ERROR: Cannot connect to MongoDB.")
        print("  Make sure MongoDB is running and MONGO_URI in .env is correct.")
        sys.exit(1)

    db = get_db()

    # Check if admin already exists
    existing = db.users.find_one({"username": DEFAULT_USERNAME})
    if existing:
        print(f"ℹ  User '{DEFAULT_USERNAME}' already exists. Skipping.")
    else:
        db.users.insert_one({
            "username":   DEFAULT_USERNAME,
            "password":   pwd_ctx.hash(DEFAULT_PASSWORD),
            "full_name":  DEFAULT_FULLNAME,
            "role":       "admin",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        print(f"✓  Created user: {DEFAULT_USERNAME} / {DEFAULT_PASSWORD}")
        print("   ⚠  Please change this password after first login!")

    # Create MongoDB indexes for fast lookups
    db.analyses.create_index("case_id", unique=True)
    db.analyses.create_index("created_at")
    db.users.create_index("username", unique=True)
    print("✓  Database indexes created.")

    print("─" * 50)
    print("  Setup complete. Start the server with:")
    print("  uvicorn main:app --reload --port 8000")
    print("─" * 50)


if __name__ == "__main__":
    seed()
