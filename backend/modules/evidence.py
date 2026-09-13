# ─────────────────────────────────────────────
#  modules/evidence.py  —  MODULE 12
#  Evidence Preservation
#
#  WHY THIS EXISTS:
#  In a real investigation, you need to prove that
#  the evidence hasn't been tampered with. We do
#  this by calculating a SHA-256 hash of the original
#  .eml file the moment it is uploaded.
#
#  If anyone modifies the file later, its hash will
#  be different — proving tampering. This is called
#  "chain of custody" in digital forensics.
# ─────────────────────────────────────────────
import hashlib
import uuid
from datetime import datetime, timezone


def generate_case_id() -> str:
    """
    Generates a unique Case ID for each email investigation.
    Format: CASE-YYYYMMDD-XXXXXXXX
    Example: CASE-20240615-A3F2B1C9

    WHY: Every investigation needs a unique reference number
    so analysts can look it up, reference it in reports, and
    track it over time.
    """
    date_part = datetime.now(timezone.utc).strftime("%Y%m%d")
    unique_part = uuid.uuid4().hex[:8].upper()
    return f"CASE-{date_part}-{unique_part}"


def compute_sha256(data: bytes) -> str:
    """
    Computes the SHA-256 hash of the raw file bytes.

    WHY SHA-256:
    SHA-256 is a cryptographic hash function that produces
    a unique 64-character hex string for any input. Even
    changing a single byte in the file produces a completely
    different hash. It is the standard for evidence integrity
    in digital forensics.
    """
    return hashlib.sha256(data).hexdigest()


def build_evidence_record(
    case_id: str,
    filename: str,
    sha256: str,
    file_size_bytes: int,
) -> dict:
    """
    Builds the evidence preservation record.

    This is stored in MongoDB alongside the analysis result.
    It records:
      - The case ID (unique investigation reference)
      - The original filename
      - The SHA-256 hash of the file (integrity proof)
      - The file size
      - When it was uploaded (timestamp)

    This is the digital equivalent of an evidence bag tag.
    """
    now = datetime.now(timezone.utc)
    return {
        "case_id":          case_id,
        "filename":         filename,
        "sha256":           sha256,
        "file_size_bytes":  file_size_bytes,
        "upload_timestamp": now.isoformat(),
        "upload_timestamp_readable": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
