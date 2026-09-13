# ─────────────────────────────────────────────
#  modules/risk_scoring.py  —  MODULE 9
#  Threat Risk Scoring & Correlation
#
#  WHY THIS EXISTS:
#  Every module produces a partial score and a list
#  of indicators. This module combines them all into
#  a single, explainable risk score from 0 to 100.
#
#  WHY EXPLAINABLE:
#  In cybersecurity investigations, analysts need to
#  know WHY a system flagged something — not just that
#  it did. The score breakdown shows exactly which
#  module contributed how many points.
#
#  SCORE BREAKDOWN (max 100):
#    Header Forensics    →  0–25 pts
#    Authentication      →  0–30 pts
#    AI/ML Detection     →  0–30 pts
#    URL Analysis        →  0–20 pts
#    Domain Intelligence →  0–10 pts
#    IP Intelligence     →  0–10 pts
#    ─────────────────────────────
#    Total               →  0–100 pts  (capped)
#
#  RISK LEVELS:
#    0–29   → LOW
#    30–59  → MEDIUM
#    60–79  → HIGH
#    80–100 → CRITICAL
# ─────────────────────────────────────────────
from typing import Any


# ── Risk level thresholds ─────────────────────
def _score_to_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"


def _score_to_color(level: str) -> str:
    return {
        "CRITICAL": "#dc2626",   # red
        "HIGH":     "#ea580c",   # orange
        "MEDIUM":   "#ca8a04",   # yellow
        "LOW":      "#16a34a",   # green
    }.get(level, "#6b7280")


# ── Main Risk Scoring Function ────────────────

def calculate_risk_score(
    header_result:   dict[str, Any],
    auth_result:     dict[str, Any],
    ai_result:       dict[str, Any],
    url_result:      dict[str, Any],
    domain_result:   dict[str, Any],
    ip_result:       dict[str, Any],
    correlation:     dict[str, Any],
) -> dict[str, Any]:
    """
    Main entry point for Module 9.

    Combines all module scores into a final risk assessment.
    Returns a complete risk report with breakdown and explanation.
    """

    # ── Module score contributions ────────────
    header_score = min(header_result.get("score_contribution", 0), 25)
    auth_score   = min(auth_result.get("score_contribution", 0),   30)
    ai_score     = min(ai_result.get("score_contribution", 0),     30)
    url_score    = min(url_result.get("score_contribution", 0),    20)
    domain_score = min(domain_result.get("score_contribution", 0), 10)
    ip_score     = min(ip_result.get("score_contribution", 0),     10)

    # Raw total
    raw_total = (
        header_score + auth_score + ai_score +
        url_score + domain_score + ip_score
    )

    # Hard cap at 100
    final_score = min(raw_total, 100)

    # Risk level
    risk_level = _score_to_level(final_score)
    risk_color = _score_to_color(risk_level)

    # ── Build breakdown ───────────────────────
    breakdown = {
        "header_forensics": {
            "score": header_score,
            "max":   25,
            "label": "Header Forensics",
        },
        "authentication": {
            "score": auth_score,
            "max":   30,
            "label": "Authentication (SPF/DKIM/DMARC)",
        },
        "ai_detection": {
            "score": ai_score,
            "max":   30,
            "label": "AI/ML Content Analysis",
        },
        "url_analysis": {
            "score": url_score,
            "max":   20,
            "label": "URL Analysis",
        },
        "domain_intel": {
            "score": domain_score,
            "max":   10,
            "label": "Domain Intelligence",
        },
        "ip_intel": {
            "score": ip_score,
            "max":   10,
            "label": "IP Infrastructure",
        },
    }

    # ── Build major reasons list ──────────────
    major_reasons = _extract_major_reasons(
        header_result, auth_result, ai_result,
        url_result, domain_result, ip_result, correlation,
    )

    # ── Final classification ──────────────────
    # AI classification takes priority; risk level can upgrade it
    ai_classification = ai_result.get("classification", "UNKNOWN")
    final_classification = _determine_final_classification(
        ai_classification, final_score, correlation
    )

    # ── Conclusion text ───────────────────────
    conclusion = _build_conclusion(
        final_classification, final_score, risk_level, major_reasons
    )

    return {
        "score":                final_score,
        "risk_level":           risk_level,
        "risk_color":           risk_color,
        "classification":       final_classification,
        "ai_confidence":        ai_result.get("confidence", 0),
        "breakdown":            breakdown,
        "major_reasons":        major_reasons,
        "total_indicators":     correlation.get("total_indicator_count", 0),
        "high_indicators":      correlation.get("high_indicator_count", 0),
        "infrastructure_overlap": correlation.get("infrastructure_overlap", False),
        "conclusion":           conclusion,
    }


def _determine_final_classification(
    ai_classification: str,
    score: int,
    correlation: dict,
) -> str:
    """
    Determines the final classification combining AI result with risk score.
    The risk score can upgrade but not downgrade the AI classification.
    """
    if score >= 80:
        # Very high score overrides to PHISHING regardless
        if ai_classification in ("PHISHING", "SUSPICIOUS", "UNKNOWN"):
            return "PHISHING"
    if score >= 60:
        if ai_classification in ("SUSPICIOUS", "UNKNOWN"):
            return "PHISHING"
        return ai_classification
    if score >= 30:
        if ai_classification == "LEGITIMATE":
            return "SUSPICIOUS"
        return ai_classification

    # Low score
    return ai_classification


def _extract_major_reasons(
    header_result:  dict,
    auth_result:    dict,
    ai_result:      dict,
    url_result:     dict,
    domain_result:  dict,
    ip_result:      dict,
    correlation:    dict,
) -> list[str]:
    """
    Extracts the top reasons why this email was flagged.
    These are shown prominently on the dashboard.
    """
    reasons = []

    # Header flags
    for flag in header_result.get("flags", []):
        if flag["severity"] in ("HIGH", "MEDIUM"):
            reasons.append(flag["description"])

    # Auth failures
    for flag in auth_result.get("flags", []):
        if flag["severity"] in ("HIGH", "MEDIUM"):
            reasons.append(flag["description"])

    # AI patterns (top 3)
    for ind in ai_result.get("indicators", [])[:3]:
        reasons.append(ind["description"])

    # High risk URLs
    high_urls = url_result.get("high_risk_urls", [])
    if high_urls:
        reasons.append(f"High-risk URL detected: {high_urls[0][:60]}")

    # Domain issues
    if domain_result.get("missing_spf"):
        reasons.append(
            f"Domain(s) missing SPF record: {', '.join(domain_result['missing_spf'][:2])}"
        )
    if domain_result.get("missing_dmarc"):
        reasons.append(
            f"Domain(s) missing DMARC policy: {', '.join(domain_result['missing_dmarc'][:2])}"
        )

    # Infrastructure
    if ip_result.get("hosting_ips"):
        reasons.append(
            f"Email routed through hosting/datacenter infrastructure: "
            f"{', '.join(ip_result['hosting_ips'][:2])}"
        )
    if correlation.get("infrastructure_overlap"):
        reasons.append("Shared infrastructure detected between routing IPs and suspicious domains.")

    return reasons[:10]  # Return top 10 reasons


def _build_conclusion(
    classification: str,
    score: int,
    risk_level: str,
    major_reasons: list[str],
) -> str:
    """
    Builds the written conclusion paragraph for the forensic report.
    This is the text that appears at the bottom of the PDF report.
    """
    if classification == "PHISHING":
        opening = (
            "The analyzed email exhibits multiple characteristics consistent "
            "with a phishing attempt."
        )
    elif classification == "SUSPICIOUS":
        opening = (
            "The analyzed email exhibits several suspicious characteristics "
            "that warrant further investigation."
        )
    elif classification == "LEGITIMATE":
        opening = (
            "The analyzed email does not exhibit significant threat indicators "
            "and appears consistent with legitimate communication."
        )
    else:
        opening = "The analyzed email could not be definitively classified."

    middle = (
        f"The overall risk score is {score}/100 ({risk_level}). "
    )

    if major_reasons:
        reasons_text = "; ".join(major_reasons[:4])
        middle += f"Key findings include: {reasons_text}."

    disclaimer = (
        " Any IP geolocation data represents the approximate location of the "
        "observed mail infrastructure and should NOT be interpreted as the "
        "physical location or identity of the sender."
    )

    return opening + " " + middle + disclaimer
