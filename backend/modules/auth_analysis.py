# ─────────────────────────────────────────────
#  modules/auth_analysis.py  —  MODULE 3
#  SPF, DKIM & DMARC Analysis
#
#  WHY THIS EXISTS:
#  SPF, DKIM, and DMARC are email authentication
#  standards that help verify that an email actually
#  came from the domain it claims to be from.
#
#  SPF  — Did this email come from an authorized
#          server for this domain?
#  DKIM — Was this email digitally signed by the
#          domain, and hasn't been tampered with?
#  DMARC— Does this domain have a policy, and did
#          the email pass that policy?
#
#  A FAIL on any of these is a red flag, but not
#  definitive proof of malice by itself. We combine
#  auth results with all other signals.
# ─────────────────────────────────────────────
import re
from typing import Any


# ── Result constants ──────────────────────────
PASS    = "PASS"
FAIL    = "FAIL"
SOFTFAIL = "SOFTFAIL"
NEUTRAL = "NEUTRAL"
NONE    = "NONE"
UNKNOWN = "UNKNOWN"


def _normalize(value: str) -> str:
    """Map raw strings to standard result constants."""
    v = value.strip().lower()
    if v in ("pass", "passwith"):
        return PASS
    if v in ("fail", "hardfail"):
        return FAIL
    if v == "softfail":
        return SOFTFAIL
    if v == "neutral":
        return NEUTRAL
    if v in ("none", "not_checked", ""):
        return NONE
    return UNKNOWN


def _parse_auth_results_header(auth_header: str) -> dict[str, str]:
    """
    Parses the Authentication-Results header.

    A real Authentication-Results header looks like:
      mx.google.com;
         spf=pass (google.com: domain of sender@example.com designates ...)
         dkim=fail header.i=@example.com;
         dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=example.com

    We extract the result keyword after each protocol name.
    """
    results = {"spf": NONE, "dkim": NONE, "dmarc": NONE}
    if not auth_header:
        return results

    for protocol in ("spf", "dkim", "dmarc"):
        # Match 'protocol=result' pattern
        pattern = rf"\b{protocol}=([a-zA-Z]+)"
        match = re.search(pattern, auth_header, re.IGNORECASE)
        if match:
            results[protocol] = _normalize(match.group(1))

    return results


def _parse_received_spf(msg_headers: dict) -> str:
    """
    Some servers add a dedicated 'Received-SPF' header.
    Parse it as a fallback if Authentication-Results doesn't contain SPF.
    """
    received_spf = msg_headers.get("received_spf", "")
    if not received_spf:
        return NONE
    match = re.match(r"^\s*([a-zA-Z]+)", received_spf)
    if match:
        return _normalize(match.group(1))
    return NONE


def _check_dkim_signature_present(parsed: dict) -> bool:
    """Check if a DKIM-Signature header exists in the email."""
    return bool(parsed.get("dkim_signature", "").strip())


# ── Risk contribution by result ───────────────
# FAIL contributes the most. SOFTFAIL is partial.
# PASS reduces risk (negative contribution).
_SPF_SCORE = {
    PASS:    -2,
    FAIL:     8,
    SOFTFAIL: 5,
    NEUTRAL:  2,
    NONE:     3,
    UNKNOWN:  1,
}
_DKIM_SCORE = {
    PASS:    -2,
    FAIL:    10,
    SOFTFAIL: 5,
    NEUTRAL:  2,
    NONE:     4,
    UNKNOWN:  1,
}
_DMARC_SCORE = {
    PASS:    -2,
    FAIL:    12,
    SOFTFAIL: 6,
    NEUTRAL:  2,
    NONE:     5,
    UNKNOWN:  1,
}


# ── Main Auth Analysis Function ───────────────

def analyze_authentication(parsed: dict[str, Any]) -> dict[str, Any]:
    """
    Main entry point for Module 3.

    INPUT : the parsed email dictionary from Module 1
    OUTPUT: a dictionary with:
              - spf / dkim / dmarc : result strings
              - dkim_signature_present
              - flags  : list of authentication failures
              - score_contribution
              - summary
    """
    auth_header = parsed.get("auth_results", "")
    auth_results = _parse_auth_results_header(auth_header)

    spf   = auth_results["spf"]
    dkim  = auth_results["dkim"]
    dmarc = auth_results["dmarc"]

    # Fallback: if SPF still NONE, try dedicated Received-SPF header
    if spf == NONE:
        spf = _parse_received_spf(parsed)

    dkim_sig_present = _check_dkim_signature_present(parsed)

    # If DKIM result is NONE but the signature header exists, mark as UNKNOWN
    # (signature is there but we couldn't verify — header may be incomplete)
    if dkim == NONE and dkim_sig_present:
        dkim = UNKNOWN

    # ── Build flags ───────────────────────────
    flags = []

    if spf == FAIL:
        flags.append({
            "flag":        "SPF_FAIL",
            "severity":    "HIGH",
            "description": (
                "SPF check FAILED. The sending mail server is NOT authorized "
                "to send email on behalf of this domain."
            ),
        })
    elif spf == SOFTFAIL:
        flags.append({
            "flag":        "SPF_SOFTFAIL",
            "severity":    "MEDIUM",
            "description": (
                "SPF returned SOFTFAIL. The sending server is not explicitly "
                "authorized, but the domain has not hard-blocked it."
            ),
        })

    if dkim == FAIL:
        flags.append({
            "flag":        "DKIM_FAIL",
            "severity":    "HIGH",
            "description": (
                "DKIM signature verification FAILED. The email may have been "
                "tampered with in transit, or was not signed by the claimed domain."
            ),
        })
    elif dkim in (NONE, UNKNOWN) and not dkim_sig_present:
        flags.append({
            "flag":        "DKIM_MISSING",
            "severity":    "LOW",
            "description": "No DKIM signature found. Legitimate senders typically sign their emails.",
        })

    if dmarc == FAIL:
        flags.append({
            "flag":        "DMARC_FAIL",
            "severity":    "HIGH",
            "description": (
                "DMARC policy check FAILED. This email does not align with "
                "the domain's published DMARC policy."
            ),
        })
    elif dmarc == NONE:
        flags.append({
            "flag":        "DMARC_NONE",
            "severity":    "LOW",
            "description": (
                "No DMARC result found. Either the domain has no DMARC policy "
                "or it was not evaluated."
            ),
        })

    # ── Score contribution ────────────────────
    raw_score = (
        _SPF_SCORE.get(spf, 0)
        + _DKIM_SCORE.get(dkim, 0)
        + _DMARC_SCORE.get(dmarc, 0)
    )
    score = max(0, min(raw_score, 30))  # Clamp to [0, 30]

    # ── Summary ───────────────────────────────
    failures = [f for f in flags if f["severity"] in ("HIGH", "MEDIUM")]
    if not failures:
        summary = f"✓ Authentication: SPF={spf}, DKIM={dkim}, DMARC={dmarc}"
    else:
        fail_names = [f["flag"] for f in failures]
        summary = f"⚠ Authentication failures: {', '.join(fail_names)}"

    return {
        "spf":                  spf,
        "dkim":                 dkim,
        "dmarc":                dmarc,
        "dkim_signature_present": dkim_sig_present,
        "flags":                flags,
        "summary":              summary,
        "score_contribution":   score,
    }
