# ─────────────────────────────────────────────
#  modules/domain_intel.py  —  MODULE 6
#  Domain Intelligence
#
#  WHY THIS EXISTS:
#  A domain name is like an address in the
#  internet. Phishers register fake domains
#  that look like real ones. By looking up
#  DNS records we can find:
#    - What IP addresses the domain points to
#    - What mail servers (MX) it uses
#    - Who registered it (nameservers/registrar)
#    - Whether it has a valid SPF record
#
#  This gives investigators a technical picture
#  of the infrastructure behind a suspicious email.
#
#  WHY dnspython:
#  Python's built-in socket only does basic lookups.
#  dnspython can query any record type (A, MX, NS,
#  TXT, CNAME) and handles errors gracefully.
# ─────────────────────────────────────────────
import logging
from typing import Any

try:
    import dns.resolver
    import dns.exception
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False
    logging.warning("dnspython not installed. Domain intelligence will be limited.")

logger = logging.getLogger(__name__)

# Timeout for each DNS query in seconds
_DNS_TIMEOUT = 3.0


def _safe_dns_query(domain: str, record_type: str) -> list[str]:
    """
    Performs a DNS query and returns results as a list of strings.
    Returns an empty list on any error (timeout, NXDOMAIN, etc.)

    WHY SAFE: DNS queries can fail for many reasons — the domain
    doesn't exist, the DNS server is slow, or the record type
    doesn't exist for this domain. We never let a DNS failure
    crash the whole analysis.
    """
    if not _DNS_AVAILABLE:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = _DNS_TIMEOUT
        answers = resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.resolver.LifetimeTimeout):
        return []
    except Exception as e:
        logger.debug("DNS query %s/%s failed: %s", domain, record_type, e)
        return []


def lookup_domain(domain: str) -> dict[str, Any]:
    """
    Performs DNS lookups for a single domain.

    Returns:
      - a_records   : IP addresses the domain resolves to
      - mx_records  : mail server hostnames
      - ns_records  : nameservers (who hosts this domain's DNS)
      - txt_records : TXT records (includes SPF, DKIM, DMARC policies)
      - has_spf     : whether an SPF record was found
      - has_dmarc   : whether a DMARC record was found
      - ips         : all IP addresses found (from A records)
      - exists      : whether the domain resolves at all
    """
    if not domain or len(domain) < 3:
        return _empty_domain_result(domain)

    # Remove any path or port that got included
    domain = domain.split("/")[0].split(":")[0].strip().lower()

    a_records  = _safe_dns_query(domain, "A")
    mx_records = _safe_dns_query(domain, "MX")
    ns_records = _safe_dns_query(domain, "NS")
    txt_records = _safe_dns_query(domain, "TXT")

    # Check for SPF and DMARC in TXT records
    has_spf   = any("v=spf1" in t.lower() for t in txt_records)
    has_dmarc = any("v=dmarc1" in t.lower() for t in txt_records)

    # Also check _dmarc subdomain (standard location for DMARC)
    if not has_dmarc:
        dmarc_records = _safe_dns_query(f"_dmarc.{domain}", "TXT")
        has_dmarc = any("v=dmarc1" in t.lower() for t in dmarc_records)

    # Clean up MX records (strip priority numbers like "10 mail.example.com")
    mx_hosts = []
    for mx in mx_records:
        parts = mx.strip().split()
        if parts:
            mx_hosts.append(parts[-1].rstrip("."))

    # Clean up NS records
    ns_hosts = [ns.rstrip(".") for ns in ns_records]

    exists = bool(a_records or mx_records or ns_records)

    return {
        "domain":      domain,
        "exists":      exists,
        "a_records":   a_records,
        "mx_records":  mx_hosts,
        "ns_records":  ns_hosts[:4],   # limit to 4
        "txt_records": txt_records[:5],  # limit to 5
        "has_spf":     has_spf,
        "has_dmarc":   has_dmarc,
        "ips":         a_records,       # IPs resolved from A records
    }


def _empty_domain_result(domain: str) -> dict:
    return {
        "domain": domain, "exists": False,
        "a_records": [], "mx_records": [], "ns_records": [],
        "txt_records": [], "has_spf": False, "has_dmarc": False, "ips": [],
    }


# ── Main Domain Intelligence Function ────────

def analyze_domains(
    suspicious_domains: list[str],
    from_domain: str = "",
) -> dict[str, Any]:
    """
    Main entry point for Module 6.

    INPUT:
      suspicious_domains : list of domains from URL analysis
      from_domain        : the sender's domain (From header)

    OUTPUT:
      - domain_results   : DNS lookup result per domain
      - all_ips          : all IPs found across all domains
      - missing_spf      : domains with no SPF record
      - missing_dmarc    : domains with no DMARC record
      - score_contribution
      - summary
    """
    # Build the set of domains to investigate
    domains_to_check = set()

    for d in suspicious_domains:
        if d and len(d) > 3:
            domains_to_check.add(d.lower())

    if from_domain and len(from_domain) > 3:
        domains_to_check.add(from_domain.lower())

    if not domains_to_check:
        return {
            "domains_checked":   0,
            "domain_results":    {},
            "all_ips":           [],
            "missing_spf":       [],
            "missing_dmarc":     [],
            "score_contribution": 0,
            "summary":           "No domains to investigate.",
        }

    # Lookup each domain (max 5 to keep response fast)
    domain_results = {}
    all_ips = []

    for domain in list(domains_to_check)[:5]:
        result = lookup_domain(domain)
        domain_results[domain] = result
        all_ips.extend(result["ips"])

    # Deduplicate IPs
    all_ips = list(dict.fromkeys(all_ips))

    # Find missing security records
    missing_spf   = [d for d, r in domain_results.items() if r["exists"] and not r["has_spf"]]
    missing_dmarc = [d for d, r in domain_results.items() if r["exists"] and not r["has_dmarc"]]

    # Score: missing SPF/DMARC on suspicious domains is a red flag
    score = 0
    score += len(missing_spf)   * 2
    score += len(missing_dmarc) * 3
    score = min(score, 10)

    # Summary
    checked = len(domain_results)
    if missing_spf or missing_dmarc:
        summary = (
            f"Checked {checked} domain(s). "
            f"{len(missing_spf)} missing SPF, "
            f"{len(missing_dmarc)} missing DMARC."
        )
    else:
        summary = f"Checked {checked} domain(s). All have SPF/DMARC records."

    return {
        "domains_checked":    checked,
        "domain_results":     domain_results,
        "all_ips":            all_ips,
        "missing_spf":        missing_spf,
        "missing_dmarc":      missing_dmarc,
        "score_contribution": score,
        "summary":            summary,
    }
