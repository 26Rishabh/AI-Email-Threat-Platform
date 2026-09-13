# ─────────────────────────────────────────────
#  modules/email_parser.py  —  MODULE 1
#  Email Ingestion & Parsing
#
#  WHY THIS EXISTS:
#  A raw .eml file is just a big block of text
#  with a specific format (called MIME). Python's
#  built-in `email` library knows how to read that
#  format and split it into its parts — headers,
#  body text, HTML body, attachments, URLs, etc.
#
#  This is the FIRST step in the pipeline. Every
#  other module receives the output of this one.
# ─────────────────────────────────────────────
import email
import email.policy
import hashlib
import re
import quopri
import base64
from email.header import decode_header
from typing import Any


# ── Helpers ──────────────────────────────────

def _decode_mime_words(raw: str) -> str:
    """
    Email subjects and sender names can be encoded like:
      =?utf-8?b?SGVsbG8gV29ybGQ=?=
    This function decodes them back to readable text.
    """
    if not raw:
        return ""
    parts = decode_header(raw)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            try:
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            except (LookupError, UnicodeDecodeError):
                decoded.append(part.decode("utf-8", errors="replace"))
        else:
            decoded.append(str(part))
    return " ".join(decoded)


def _extract_email_address(raw: str) -> str:
    """
    From a string like 'John Doe <john@example.com>',
    extracts only 'john@example.com'.
    """
    if not raw:
        return ""
    match = re.search(r"<([^>]+)>", raw)
    if match:
        return match.group(1).strip().lower()
    return raw.strip().lower()


def _extract_urls(text: str) -> list[str]:
    """
    Finds all URLs inside a block of text using a regular expression.
    Returns a deduplicated list.
    """
    if not text:
        return []
    pattern = r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+'
    urls = re.findall(pattern, text)
    # Remove trailing punctuation that got captured
    cleaned = [u.rstrip(".,;:!?)>") for u in urls]
    return list(dict.fromkeys(cleaned))  # deduplicate while preserving order


def _get_body(msg: email.message.Message) -> dict[str, str]:
    """
    Extracts plain-text and HTML body from the email message.
    Emails can be 'multipart' (multiple sections) or simple.
    We walk every part and collect the text/plain and text/html sections.
    """
    plain = ""
    html = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            # Skip attachments
            if "attachment" in disposition:
                continue
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                decoded = payload.decode(charset, errors="replace")
            except (LookupError, UnicodeDecodeError):
                decoded = payload.decode("utf-8", errors="replace")

            if content_type == "text/plain" and not plain:
                plain = decoded
            elif content_type == "text/html" and not html:
                html = decoded
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            try:
                plain = payload.decode(charset, errors="replace")
            except (LookupError, UnicodeDecodeError):
                plain = payload.decode("utf-8", errors="replace")

    return {"plain": plain, "html": html}


def _get_attachments(msg: email.message.Message) -> list[dict]:
    """
    Finds all file attachments in the email.
    Returns their filename, MIME type, and size in bytes.
    We do NOT store the actual file content — only metadata.
    """
    attachments = []
    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        disposition = str(part.get("Content-Disposition", ""))
        if "attachment" in disposition:
            filename_raw = part.get_filename()
            filename = _decode_mime_words(filename_raw) if filename_raw else "unknown"
            payload = part.get_payload(decode=True)
            size = len(payload) if payload else 0
            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size_bytes": size,
            })
    return attachments


def _get_received_headers(msg: email.message.Message) -> list[str]:
    """
    The 'Received' headers form the routing trail of an email.
    Each mail server that relayed the email adds one.
    The FIRST one in the list is the MOST RECENT hop (read bottom-up).
    """
    return msg.get_all("Received") or []


# ── Main Parser Function ──────────────────────

def parse_email(raw_bytes: bytes) -> dict[str, Any]:
    """
    Main entry point for Module 1.

    INPUT : raw bytes of the .eml file
    OUTPUT: a dictionary with every extracted component

    This output is passed to all other modules for analysis.
    """
    # Parse the raw bytes using Python's email library with a modern policy
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)

    # ── Basic fields ──────────────────────────
    from_raw    = msg.get("From", "")
    to_raw      = msg.get("To", "")
    reply_to    = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    subject_raw = msg.get("Subject", "")
    date        = msg.get("Date", "")
    message_id  = msg.get("Message-ID", "")
    x_mailer    = msg.get("X-Mailer", "")
    x_originating_ip = msg.get("X-Originating-IP", "")

    # ── Authentication headers ─────────────────
    auth_results = msg.get("Authentication-Results", "")
    dkim_sig     = msg.get("DKIM-Signature", "")
    arc_auth     = msg.get("ARC-Authentication-Results", "")

    # ── Body extraction ───────────────────────
    body = _get_body(msg)

    # Combine plain + HTML for URL extraction
    combined_text = body["plain"] + " " + body["html"]

    # ── URL extraction ────────────────────────
    urls = _extract_urls(combined_text)

    # ── Routing headers ───────────────────────
    received_headers = _get_received_headers(msg)

    # ── Attachments ───────────────────────────
    attachments = _get_attachments(msg)

    # ── SHA-256 hash (evidence integrity) ─────
    # This is the unique fingerprint of the original file.
    # If anyone modifies the file later, this hash will no longer match.
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

    return {
        # Decoded display fields
        "from_raw":          from_raw,
        "from_address":      _extract_email_address(from_raw),
        "from_display_name": from_raw.split("<")[0].strip().strip('"') if "<" in from_raw else "",
        "to":                to_raw,
        "reply_to":          reply_to,
        "reply_to_address":  _extract_email_address(reply_to),
        "return_path":       return_path,
        "return_path_address": _extract_email_address(return_path),
        "subject":           _decode_mime_words(subject_raw),
        "date":              date,
        "message_id":        message_id,
        "x_mailer":          x_mailer,
        "x_originating_ip":  x_originating_ip,
        # Auth
        "auth_results":      auth_results,
        "dkim_signature":    dkim_sig,
        "arc_auth_results":  arc_auth,
        # Body
        "body_plain":        body["plain"],
        "body_html":         body["html"],
        # Extracted data
        "urls":              urls,
        "received_headers":  received_headers,
        "attachments":       attachments,
        # Evidence
        "sha256":            sha256_hash,
        "file_size_bytes":   len(raw_bytes),
    }
