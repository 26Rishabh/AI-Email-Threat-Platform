# ─────────────────────────────────────────────
#  modules/header_forensics.py  —  MODULE 2
#  Email Header Forensics
#
#  WHY THIS EXISTS:
#  Email headers contain invisible metadata that
#  attackers often manipulate to disguise who
#  really sent an email. This module inspects
#  those headers for known red flags and anomalies.
#
#  Think of it like examining the postmarks and
#  routing stamps on an envelope to check if the
#  return address matches the actual sender.
# ─────────────────────────────────────────────
import re
from typing import Any


# ── IP extraction from Received headers ──────

_IP_PATTERN = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

# Private / reserved IP ranges that belong to internal networks.
# We skip these when building the list of "external" IPs to investigate.
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "0.", "169.254.",
)


def _is_private_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def extract_ips_from_received(received_headers: list[str]) -> list[str]:
    """
    Parses all Received headers and pulls out every public IP address.

    The Received headers form a routing chain. Each server that relayed
    the email adds one. Reading them bottom-up gives the original path.
    We extract IPs so Module 7 can look up their geolocation/ISP info.
    """
    seen = set()
    ips = []
    for header in received_headers:
        for match in _IP_PATTERN.finditer(header):
            ip = match.group(1)
            if not _is_private_ip(ip) and ip not in seen:
                seen.add(ip)
                ips.append(ip)
    return ips


# ── Anomaly detection helpers ─────────────────

def _check_reply_to_mismatch(parsed: dict) -> dict | None:
    """
    Flag: The From domain and Reply-To domain differ.

    WHY THIS MATTERS:
    Attackers set a legitimate-looking From address but put their
    own address in Reply-To so that when the victim clicks Reply,
    the response goes to the attacker — not the real sender.

    Example:
      From:     support@yourbank.com
      Reply-To: attacker@gmail.com   ← YOU REPLY TO THIS
    """
    from_addr    = parsed.get("from_address", "").lower()
    reply_to_addr = parsed.get("reply_to_address", "").lower()

    if not reply_to_addr:
        return None  # No Reply-To set — not suspicious by itself

    from_domain    = from_addr.split("@")[-1]    if "@" in from_addr    else ""
    reply_domain   = reply_to_addr.split("@")[-1] if "@" in reply_to_addr else ""

    if from_domain and reply_domain and from_domain != reply_domain:
        return {
            "flag":        "REPLY_TO_MISMATCH",
            "severity":    "HIGH",
            "description": (
                f"From domain '{from_domain}' does not match "
                f"Reply-To domain '{reply_domain}'. "
                "This is a common phishing technique."
            ),
            "from_address":    from_addr,
            "reply_to_address": reply_to_addr,
        }
    return None


def _check_return_path_mismatch(parsed: dict) -> dict | None:
    """
    Flag: The From domain and Return-Path domain differ.

    WHY THIS MATTERS:
    Return-Path is where bounce messages go. If it's on a different
    domain than the From address, this can indicate spoofing or
    a misconfigured third-party sender.
    """
    from_addr       = parsed.get("from_address", "").lower()
    return_path_addr = parsed.get("return_path_address", "").lower()

    if not return_path_addr:
        return None

    from_domain   = from_addr.split("@")[-1]        if "@" in from_addr        else ""
    return_domain = return_path_addr.split("@")[-1] if "@" in return_path_addr else ""

    if from_domain and return_domain and from_domain != return_domain:
        return {
            "flag":        "RETURN_PATH_MISMATCH",
            "severity":    "MEDIUM",
            "description": (
                f"From domain '{from_domain}' does not match "
                f"Return-Path domain '{return_domain}'."
            ),
            "from_address":        from_addr,
            "return_path_address": return_path_addr,
        }
    return None


def _check_missing_message_id(parsed: dict) -> dict | None:
    """
    Flag: No Message-ID header present.

    WHY THIS MATTERS:
    Every legitimate email client adds a Message-ID. Its absence
    is unusual and may indicate a manually crafted/forged email.
    """
    if not parsed.get("message_id", "").strip():
        return {
            "flag":        "MISSING_MESSAGE_ID",
            "severity":    "LOW",
            "description": "No Message-ID header found. Legitimate mail servers always add one.",
        }
    return None


def _check_suspicious_message_id(parsed: dict) -> dict | None:
    """
    Flag: Message-ID domain does not match the From domain.

    WHY THIS MATTERS:
    Message-ID is typically formatted as <random@sending-domain.com>.
    If the domain in the Message-ID doesn't match the From domain,
    the email may have been sent through a different, unauthorized system.
    """
    msg_id    = parsed.get("message_id", "")
    from_addr = parsed.get("from_address", "")

    if not msg_id or not from_addr or "@" not in from_addr:
        return None

    from_domain = from_addr.split("@")[-1].lower()
    mid_match   = re.search(r"@([^>]+)>?$", msg_id)
    if not mid_match:
        return None

    mid_domain = mid_match.group(1).lower().strip(">")

    if from_domain not in mid_domain and mid_domain not in from_domain:
        return {
            "flag":        "MESSAGE_ID_DOMAIN_MISMATCH",
            "severity":    "MEDIUM",
            "description": (
                f"Message-ID domain '{mid_domain}' does not match "
                f"From domain '{from_domain}'."
            ),
        }
    return None


def _check_x_originating_ip(parsed: dict) -> dict | None:
    """
    Flag: X-Originating-IP header is present.

    WHY THIS MATTERS:
    Some mail servers add the originating client IP. This is useful
    intelligence — we log it for the IP module to investigate.
    Not suspicious by itself, but informational.
    """
    ip = parsed.get("x_originating_ip", "").strip()
    if ip and not _is_private_ip(ip):
        return {
            "flag":        "X_ORIGINATING_IP_FOUND",
            "severity":    "INFO",
            "description": f"X-Originating-IP header found: {ip}. Added to IP investigation list.",
            "ip":          ip,
        }
    return None


def _check_received_spoof_indicators(received_headers: list[str]) -> list[dict]:
    """
    Scans Received headers for signs of spoofing or unusual routing.

    Checks for:
    - Forged/suspicious localhost claims
    - Unusually short routing chains (could be direct injection)
    """
    flags = []

    for i, header in enumerate(received_headers):
        lower = header.lower()

        # A legitimate external email rarely says it came from 'localhost' or '127.0.0.1'
        if "localhost" in lower or "127.0.0.1" in lower:
            flags.append({
                "flag":        "RECEIVED_LOCALHOST_CLAIM",
                "severity":    "MEDIUM",
                "description": f"Received header #{i+1} references localhost. This may indicate header forgery.",
                "header_index": i,
            })

    # A real email through the internet typically has 2+ Received hops.
    # Only 1 hop suggests the email was injected directly or headers were stripped.
    if len(received_headers) == 1:
        flags.append({
            "flag":        "SINGLE_HOP_ROUTING",
            "severity":    "LOW",
            "description": "Only one Received header found. Unusual for external email — headers may have been stripped.",
        })

    return flags


# ── Main Header Forensics Function ───────────

def analyze_headers(parsed: dict[str, Any]) -> dict[str, Any]:
    """
    Main entry point for Module 2.

    INPUT : the parsed email dictionary from Module 1
    OUTPUT: a dictionary with:
              - flags     : list of detected anomalies
              - ips       : list of public IPs found in routing
              - summary   : human-readable summary
              - score_contribution : points to add to the risk score
    """
    flags = []

    # Run all individual checks
    checks = [
        _check_reply_to_mismatch(parsed),
        _check_return_path_mismatch(parsed),
        _check_missing_message_id(parsed),
        _check_suspicious_message_id(parsed),
        _check_x_originating_ip(parsed),
    ]
    for result in checks:
        if result:
            flags.append(result)

    # Check Received headers
    received = parsed.get("received_headers", [])
    flags.extend(_check_received_spoof_indicators(received))

    # Extract public IPs from routing chain
    routing_ips = extract_ips_from_received(received)

    # Also include X-Originating-IP if present and not private
    x_ip = parsed.get("x_originating_ip", "").strip()
    if x_ip and not _is_private_ip(x_ip) and x_ip not in routing_ips:
        routing_ips.insert(0, x_ip)

    # ── Score contribution ────────────────────
    # Each flag type adds a different number of points to the risk score.
    SEVERITY_POINTS = {
        "HIGH":   15,
        "MEDIUM":  8,
        "LOW":     3,
        "INFO":    0,
    }
    score = sum(SEVERITY_POINTS.get(f.get("severity", "LOW"), 0) for f in flags)
    score = min(score, 25)  # Cap module contribution at 25 points

    # ── Build summary ─────────────────────────
    high_flags   = [f for f in flags if f.get("severity") == "HIGH"]
    medium_flags = [f for f in flags if f.get("severity") == "MEDIUM"]

    if high_flags:
        summary = f"⚠ {len(high_flags)} HIGH severity header anomaly/anomalies detected."
    elif medium_flags:
        summary = f"⚠ {len(medium_flags)} MEDIUM severity header anomaly/anomalies detected."
    elif flags:
        summary = f"ℹ {len(flags)} minor header observation(s)."
    else:
        summary = "✓ No significant header anomalies detected."

    return {
        "flags":             flags,
        "routing_ips":       routing_ips,
        "received_count":    len(received),
        "summary":           summary,
        "score_contribution": score,
    }
