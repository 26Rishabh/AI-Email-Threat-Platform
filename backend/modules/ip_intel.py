# ─────────────────────────────────────────────
#  modules/ip_intel.py  —  MODULE 7
#  IP & Infrastructure Intelligence
#
#  WHY THIS EXISTS:
#  Every email travels through mail servers, each
#  identified by an IP address. By looking up these
#  IPs we can find:
#    - Approximate country/region of the server
#    - Which ISP or hosting company owns it
#    - The ASN (Autonomous System Number — the network
#      block that IP belongs to)
#
#  We use ip-api.com which is FREE for non-commercial
#  use (up to 45 requests/minute) — no API key needed.
#
#  IMPORTANT DISCLAIMER (built into every result):
#  IP geolocation shows where the MAIL SERVER is,
#  NOT where the attacker is physically sitting.
#  Attackers use VPNs, cloud servers, and compromised
#  machines. We always label this as "approximate
#  infrastructure geolocation" not attacker location.
# ─────────────────────────────────────────────
import os
import time
import logging
import requests
from typing import Any
from dotenv import load_dotenv
from pathlib import Path

_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_ENV_PATH)

logger = logging.getLogger(__name__)

_IP_API_URL  = os.getenv("IP_API_URL", "http://ip-api.com/json")
_TIMEOUT     = 5    # seconds per request
_RATE_LIMIT_DELAY = 0.5  # seconds between requests (respect free tier limit)

# Private IP ranges — no point looking these up
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "0.",
    "169.254.", "::1", "fc", "fd",
)


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def lookup_ip(ip: str) -> dict[str, Any]:
    """
    Looks up a single IP address using ip-api.com.

    ip-api.com returns JSON like:
    {
      "status": "success",
      "country": "India",
      "regionName": "Maharashtra",
      "city": "Mumbai",
      "isp": "Jio Reliance",
      "org": "AS55836 Reliance Jio Infocomm Limited",
      "as": "AS55836 ...",
      "query": "49.36.x.x"
    }

    We request specific fields to keep the response small.
    """
    if not ip or _is_private(ip):
        return _empty_ip_result(ip, "private_or_reserved")

    fields = "status,message,country,countryCode,regionName,city,isp,org,as,query,hosting"
    url    = f"{_IP_API_URL}/{ip}?fields={fields}"

    try:
        resp = requests.get(url, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") != "success":
            return _empty_ip_result(ip, data.get("message", "lookup_failed"))

        return {
            "ip":           ip,
            "country":      data.get("country", "Unknown"),
            "country_code": data.get("countryCode", ""),
            "region":       data.get("regionName", "Unknown"),
            "city":         data.get("city", "Unknown"),
            "isp":          data.get("isp", "Unknown"),
            "org":          data.get("org", ""),
            "asn":          data.get("as", ""),
            "is_hosting":   data.get("hosting", False),
            "lookup_status": "success",
            # Legal / accuracy disclaimer always included
            "disclaimer":   (
                "IP geolocation represents the approximate location of the "
                "observed mail infrastructure, NOT the physical location or "
                "identity of the sender."
            ),
        }

    except requests.Timeout:
        logger.warning("IP lookup timeout for %s", ip)
        return _empty_ip_result(ip, "timeout")
    except requests.RequestException as e:
        logger.warning("IP lookup failed for %s: %s", ip, e)
        return _empty_ip_result(ip, "request_error")
    except Exception as e:
        logger.error("Unexpected error in IP lookup for %s: %s", ip, e)
        return _empty_ip_result(ip, "error")


def _empty_ip_result(ip: str, reason: str) -> dict:
    return {
        "ip":           ip,
        "country":      "Unknown",
        "country_code": "",
        "region":       "Unknown",
        "city":         "Unknown",
        "isp":          "Unknown",
        "org":          "",
        "asn":          "",
        "is_hosting":   False,
        "lookup_status": reason,
        "disclaimer":   (
            "IP geolocation represents the approximate location of the "
            "observed mail infrastructure, NOT the physical location or "
            "identity of the sender."
        ),
    }


# ── Main IP Intelligence Function ────────────

def analyze_ips(ip_list: list[str]) -> dict[str, Any]:
    """
    Main entry point for Module 7.

    INPUT : list of IP addresses from routing headers + domain lookups
    OUTPUT:
      - ip_results   : geolocation/ISP data per IP
      - countries    : unique countries found
      - isps         : unique ISPs found
      - hosting_ips  : IPs identified as hosting/datacenter
      - score_contribution
      - summary
    """
    if not ip_list:
        return {
            "ips_investigated": 0,
            "ip_results":       [],
            "countries":        [],
            "isps":             [],
            "hosting_ips":      [],
            "score_contribution": 0,
            "summary":          "No public IP addresses found for investigation.",
        }

    # Filter private IPs, deduplicate, limit to 5
    public_ips = []
    seen = set()
    for ip in ip_list:
        if ip and not _is_private(ip) and ip not in seen:
            seen.add(ip)
            public_ips.append(ip)
        if len(public_ips) >= 5:
            break

    if not public_ips:
        return {
            "ips_investigated": 0,
            "ip_results":       [],
            "countries":        [],
            "isps":             [],
            "hosting_ips":      [],
            "score_contribution": 0,
            "summary":          "All IPs are private/reserved — no public infrastructure found.",
        }

    # Look up each IP (with small delay to respect free tier)
    ip_results = []
    for i, ip in enumerate(public_ips):
        if i > 0:
            time.sleep(_RATE_LIMIT_DELAY)
        result = lookup_ip(ip)
        ip_results.append(result)

    # Aggregate intelligence
    successful = [r for r in ip_results if r["lookup_status"] == "success"]
    countries  = list({r["country"] for r in successful if r["country"] != "Unknown"})
    isps       = list({r["isp"]     for r in successful if r["isp"]     != "Unknown"})
    hosting    = [r["ip"] for r in successful if r.get("is_hosting")]

    # Score: hosting IPs add suspicion (attackers use cloud/VPS servers)
    score = min(len(hosting) * 3, 10)

    # Summary
    if successful:
        country_str = ", ".join(countries[:3]) if countries else "Unknown"
        summary = (
            f"Investigated {len(public_ips)} IP(s). "
            f"Infrastructure approximately located in: {country_str}. "
            f"Note: This is server infrastructure location, not attacker location."
        )
    else:
        summary = f"Attempted {len(public_ips)} IP lookups — results unavailable."

    return {
        "ips_investigated":   len(public_ips),
        "ip_results":         ip_results,
        "countries":          countries,
        "isps":               isps,
        "hosting_ips":        hosting,
        "score_contribution": score,
        "summary":            summary,
    }
