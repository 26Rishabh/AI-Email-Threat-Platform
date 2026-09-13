# ─────────────────────────────────────────────
#  modules/url_analysis.py  —  MODULE 5
#  URL Analysis
#
#  WHY THIS EXISTS:
#  Phishing emails almost always contain a malicious
#  URL — a link designed to trick the victim into
#  entering credentials, downloading malware, or
#  revealing personal information.
#
#  This module examines every URL extracted from
#  the email body and scores it based on known
#  suspicious characteristics:
#    - Lookalike / typosquatted domains
#    - IP address used instead of domain name
#    - Suspicious keywords in the URL path
#    - No HTTPS
#    - Extremely long URLs (used to hide the real domain)
#    - Suspicious TLDs (.xyz, .top, .ru etc.)
#    - Encoded characters used to obfuscate
#    - Multiple subdomains (e.g. paypal.evil.com)
# ─────────────────────────────────────────────
import re
from urllib.parse import urlparse, unquote
from typing import Any


# ── Known legitimate domains (short whitelist) ─
# These are well-known brands. If a URL uses a
# SIMILAR but not exact domain, it's flagged as
# a lookalike (typosquatting).
_KNOWN_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon",
    "facebook", "instagram", "twitter", "netflix", "spotify",
    "dropbox", "linkedin", "yahoo", "outlook", "office365",
    "chase", "bankofamerica", "wellsfargo", "citibank",
    "github", "gitlab", "stackoverflow", "adobe",
]

# Suspicious TLDs frequently abused in phishing
_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".online", ".site", ".website",
    ".info", ".biz", ".ru", ".cn", ".tk", ".ml", ".ga", ".cf",
    ".gq", ".pw", ".cc", ".icu", ".vip", ".work", ".loan",
    ".download", ".stream", ".racing", ".win", ".party",
}

# URL path keywords that strongly suggest credential harvesting
_SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "logon", "log-in",
    "verify", "verification", "validate", "confirm",
    "secure", "security", "account", "update", "restore",
    "recover", "password", "passwd", "credential",
    "banking", "payment", "checkout", "invoice",
    "unlock", "suspended", "limited", "alert",
    "webscr", "cmd=_login",
]

# Regex for IP address in URL host
_IP_HOST_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Regex for hex/percent encoding used to hide characters
_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")


# ── Individual URL check functions ───────────

def _check_ip_based_url(parsed_url) -> dict | None:
    """
    Flag: URL uses a raw IP address instead of a domain name.

    WHY SUSPICIOUS:
    Legitimate companies use domain names (paypal.com).
    Attackers often use IP addresses directly to avoid
    domain registration scrutiny:
      http://192.168.1.1/login  ← suspicious
    """
    host = parsed_url.hostname or ""
    if _IP_HOST_RE.match(host):
        return {
            "flag":        "IP_BASED_URL",
            "severity":    "HIGH",
            "description": f"URL uses a raw IP address ({host}) instead of a domain name.",
        }
    return None


def _check_no_https(parsed_url, url: str) -> dict | None:
    """
    Flag: URL uses HTTP instead of HTTPS.

    WHY SUSPICIOUS:
    Legitimate login/banking pages always use HTTPS
    (encrypted connection). HTTP means no encryption —
    anything typed is sent in plain text.
    """
    if parsed_url.scheme == "http":
        path = (parsed_url.path or "").lower()
        # Only flag if it also contains login/verify keywords
        if any(kw in path for kw in ["login", "verify", "secure", "account", "password"]):
            return {
                "flag":        "HTTP_LOGIN_PAGE",
                "severity":    "HIGH",
                "description": "Login/verification page served over unencrypted HTTP.",
            }
        return {
            "flag":        "NO_HTTPS",
            "severity":    "LOW",
            "description": "URL uses HTTP instead of HTTPS (unencrypted).",
        }
    return None


def _check_suspicious_keywords(parsed_url) -> dict | None:
    """
    Flag: URL path contains credential-harvesting keywords.
    """
    path  = (parsed_url.path or "").lower()
    query = (parsed_url.query or "").lower()
    combined = path + " " + query

    found = [kw for kw in _SUSPICIOUS_PATH_KEYWORDS if kw in combined]
    if found:
        return {
            "flag":        "SUSPICIOUS_PATH_KEYWORDS",
            "severity":    "MEDIUM",
            "description": f"URL path contains suspicious keywords: {', '.join(found[:4])}.",
            "keywords":    found,
        }
    return None


def _check_url_length(url: str) -> dict | None:
    """
    Flag: URL is unusually long.

    WHY SUSPICIOUS:
    Attackers use very long URLs to hide the real domain
    in the middle, hoping victims only see the beginning:
      https://www.paypal.com.evil-phish.com/very/long/path...
    The real domain here is evil-phish.com, not paypal.com.
    """
    if len(url) > 100:
        return {
            "flag":        "LONG_URL",
            "severity":    "LOW",
            "description": f"URL is unusually long ({len(url)} chars). May be hiding the real domain.",
        }
    return None


def _check_suspicious_tld(parsed_url) -> dict | None:
    """
    Flag: URL uses a TLD (top-level domain) commonly abused in phishing.
    """
    host = (parsed_url.hostname or "").lower()
    for tld in _SUSPICIOUS_TLDS:
        if host.endswith(tld):
            return {
                "flag":        "SUSPICIOUS_TLD",
                "severity":    "MEDIUM",
                "description": f"Domain uses TLD '{tld}' which is frequently abused in phishing campaigns.",
            }
    return None


def _check_lookalike_domain(parsed_url) -> dict | None:
    """
    Flag: Domain looks like a well-known brand but isn't exact.

    WHY SUSPICIOUS:
    Attackers register domains that look like trusted brands:
      paypa1.com   (1 instead of l)
      paypal-secure.com
      secure-paypal.com
      paypal.verify-now.com

    We check if a known brand name appears in the domain
    but the domain is NOT the official brand domain.
    """
    host = (parsed_url.hostname or "").lower()
    # Remove www.
    host = re.sub(r"^www\.", "", host)

    for brand in _KNOWN_BRANDS:
        if brand in host:
            # Check if it's the exact official domain
            # e.g. paypal.com is fine, paypal-login.com is not
            parts = host.split(".")
            # Official: brand.com or brand.co.in etc.
            if parts[0] == brand and len(parts) <= 3:
                return None  # Looks legitimate
            # Otherwise it's a lookalike
            return {
                "flag":        "LOOKALIKE_DOMAIN",
                "severity":    "HIGH",
                "description": (
                    f"Domain '{host}' contains brand name '{brand}' "
                    "but is not the official domain. Possible typosquatting or impersonation."
                ),
                "brand":  brand,
                "domain": host,
            }
    return None


def _check_multiple_subdomains(parsed_url) -> dict | None:
    """
    Flag: Excessive subdomains used to hide the real domain.

    Example:
      paypal.com.verify.evil-phish.net
    The registered domain is evil-phish.net, but
    'paypal.com' appears as a subdomain to look legitimate.
    """
    host = (parsed_url.hostname or "").lower()
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 4:
        return {
            "flag":        "EXCESSIVE_SUBDOMAINS",
            "severity":    "MEDIUM",
            "description": (
                f"Domain has {len(parts)} levels ({host}). "
                "Attackers use deep subdomains to disguise the real registered domain."
            ),
        }
    return None


def _check_encoded_characters(url: str) -> dict | None:
    """
    Flag: URL contains percent-encoded characters.

    WHY SUSPICIOUS:
    Encoding characters like %2F (/) or %40 (@) is sometimes
    used to obfuscate the true destination or confuse URL parsers.
    """
    matches = _ENCODED_RE.findall(url)
    if len(matches) >= 3:
        return {
            "flag":        "ENCODED_CHARACTERS",
            "severity":    "LOW",
            "description": f"URL contains {len(matches)} percent-encoded characters, possibly to obfuscate destination.",
        }
    return None


def _extract_domain(parsed_url) -> str:
    """Returns just the hostname from a parsed URL."""
    host = (parsed_url.hostname or "").lower()
    return re.sub(r"^www\.", "", host)


# ── Score map ─────────────────────────────────
_FLAG_SCORES = {
    "IP_BASED_URL":           15,
    "HTTP_LOGIN_PAGE":        12,
    "LOOKALIKE_DOMAIN":       15,
    "SUSPICIOUS_PATH_KEYWORDS": 8,
    "EXCESSIVE_SUBDOMAINS":    8,
    "SUSPICIOUS_TLD":          6,
    "LONG_URL":                3,
    "NO_HTTPS":                2,
    "ENCODED_CHARACTERS":      3,
}


# ── Per-URL analysis ──────────────────────────

def analyze_single_url(url: str) -> dict[str, Any]:
    """
    Analyses one URL and returns all flags, a risk level, and a score.
    """
    flags = []

    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
    except Exception:
        return {"url": url, "flags": [], "risk": "UNKNOWN", "score": 0, "domain": ""}

    # Run all checks
    checks = [
        _check_ip_based_url(parsed),
        _check_no_https(parsed, url),
        _check_suspicious_keywords(parsed),
        _check_url_length(url),
        _check_suspicious_tld(parsed),
        _check_lookalike_domain(parsed),
        _check_multiple_subdomains(parsed),
        _check_encoded_characters(url),
    ]
    for result in checks:
        if result:
            flags.append(result)

    # Score this URL
    score = sum(_FLAG_SCORES.get(f["flag"], 0) for f in flags)
    score = min(score, 30)

    # Risk level
    high_flags = [f for f in flags if f["severity"] == "HIGH"]
    if high_flags or score >= 20:
        risk = "HIGH"
    elif score >= 8:
        risk = "MEDIUM"
    elif score > 0:
        risk = "LOW"
    else:
        risk = "CLEAN"

    return {
        "url":    url,
        "domain": _extract_domain(parsed),
        "scheme": parsed.scheme,
        "flags":  flags,
        "risk":   risk,
        "score":  score,
    }


# ── Main URL Analysis Function ────────────────

def analyze_urls(parsed_email: dict[str, Any]) -> dict[str, Any]:
    """
    Main entry point for Module 5.

    INPUT : parsed email dict from Module 1
    OUTPUT: analysis of all URLs found in the email
    """
    urls = parsed_email.get("urls", [])

    if not urls:
        return {
            "urls_found":         0,
            "url_results":        [],
            "high_risk_urls":     [],
            "suspicious_domains": [],
            "score_contribution": 0,
            "summary":            "No URLs found in email.",
        }

    url_results = [analyze_single_url(u) for u in urls[:20]]  # analyse up to 20 URLs

    high_risk  = [r for r in url_results if r["risk"] == "HIGH"]
    medium_risk = [r for r in url_results if r["risk"] == "MEDIUM"]

    # Collect unique suspicious domains
    suspicious_domains = list({
        r["domain"] for r in url_results
        if r["risk"] in ("HIGH", "MEDIUM") and r["domain"]
    })

    # Overall score = highest single URL score (worst offender drives the risk)
    max_url_score = max((r["score"] for r in url_results), default=0)
    score = min(max_url_score, 20)  # Module cap: 20 points

    # Summary
    if high_risk:
        summary = f"⚠ {len(high_risk)} HIGH risk URL(s) detected."
    elif medium_risk:
        summary = f"⚠ {len(medium_risk)} MEDIUM risk URL(s) detected."
    else:
        summary = f"✓ {len(urls)} URL(s) found — no high-risk indicators."

    return {
        "urls_found":         len(urls),
        "url_results":        url_results,
        "high_risk_urls":     [r["url"] for r in high_risk],
        "suspicious_domains": suspicious_domains,
        "score_contribution": score,
        "summary":            summary,
    }
