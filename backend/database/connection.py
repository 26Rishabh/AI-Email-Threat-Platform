# ─────────────────────────────────────────────
#  database/connection.py
#  Manages the MongoDB connection.
#
#  WHY: We use a single shared client so the app
#  doesn't open a new database connection on every
#  request — that would be very slow.
# ─────────────────────────────────────────────
import os
from pathlib import Path
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from dotenv import load_dotenv

# Explicitly find the .env file in the backend/ folder regardless of
# which directory the script is run from.
_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_ENV_PATH)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "email_threat_platform")

# Create one global client instance (reused across all requests)
_client: MongoClient = None


def get_db():
    """
    Returns the MongoDB database object.
    Creates the client on first call (lazy initialization).
    """
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    return _client[MONGO_DB_NAME]


def ping_db() -> bool:
    """
    Returns True if MongoDB is reachable, False otherwise.
    Called at startup to give an early warning if the DB is down.
    """
    try:
        db = get_db()
        db.command("ping")
        return True
    except ConnectionFailure:
        return False
