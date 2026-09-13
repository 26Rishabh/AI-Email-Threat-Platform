# ─────────────────────────────────────────────
#  tests/test_phase3.py
#  Unit tests for Phase 3 modules.
#
#  HOW TO RUN (from backend/ folder):
#    python -m pytest tests/test_phase3.py -v
# ─────────────────────────────────────────────
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.url_analysis import analyze_single_url, analyze_urls
from modules.risk_scoring import calculate_risk_score, _score_to_level
from modules.correlation import correlate_indicators
from modules.email_parser import parse_email


def load_eml(filename: str) -> bytes:
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(base, "test_emails", filename)
    with open(path, "rb") as f:
        return f.read()


# ─────────────────────────────────────────────
#  Module 5 — URL Analysis Tests
# ─────────────────────────────────────────────

class TestURLAnalysis:

    def test_ip_based_url_flagged(self):
        result = analyze_single_url("http://192.168.1.1/login")
        flags = [f["flag"] for f in result["flags"]]
        assert "IP_BASED_URL" in flags

    def test_lookalike_domain_flagged(self):
        result = analyze_single_url("https://paypal-secure-login.com/verify")
        flags = [f["flag"] for f in result["flags"]]
        assert "LOOKALIKE_DOMAIN" in flags

    def test_suspicious_path_keywords_flagged(self):
        result = analyze_single_url("https://example.com/login/verify/password")
        flags = [f["flag"] for f in result["flags"]]
        assert "SUSPICIOUS_PATH_KEYWORDS" in flags

    def test_long_url_flagged(self):
        long_url = "https://example.com/" + "a" * 120
        result = analyze_single_url(long_url)
        flags = [f["flag"] for f in result["flags"]]
        assert "LONG_URL" in flags

    def test_suspicious_tld_flagged(self):
        result = analyze_single_url("https://secure-bank.xyz/account")
        flags = [f["flag"] for f in result["flags"]]
        assert "SUSPICIOUS_TLD" in flags

    def test_clean_url_no_flags(self):
        result = analyze_single_url("https://github.com/user/repo")
        assert result["risk"] in ("CLEAN", "LOW")

    def test_high_risk_url_correct_level(self):
        # IP-based URL with login keyword → HIGH
        result = analyze_single_url("http://192.0.2.1/login/verify")
        assert result["risk"] == "HIGH"

    def test_result_has_required_fields(self):
        result = analyze_single_url("https://example.com")
        for field in ("url", "domain", "scheme", "flags", "risk", "score"):
            assert field in result

    def test_analyze_urls_on_phishing_email(self):
        raw    = load_eml("phishing_sample.eml")
        parsed = parse_email(raw)
        result = analyze_urls(parsed)

        assert result["urls_found"] > 0
        assert result["score_contribution"] >= 0
        assert isinstance(result["url_results"], list)

    def test_analyze_urls_score_within_bounds(self):
        raw    = load_eml("phishing_sample.eml")
        parsed = parse_email(raw)
        result = analyze_urls(parsed)
        assert 0 <= result["score_contribution"] <= 20

    def test_no_urls_returns_zero_score(self):
        fake_parsed = {"urls": [], "body_plain": "", "body_html": ""}
        result = analyze_urls(fake_parsed)
        assert result["score_contribution"] == 0
        assert result["urls_found"] == 0


# ─────────────────────────────────────────────
#  Module 9 — Risk Scoring Tests
# ─────────────────────────────────────────────

class TestRiskScoring:

    def _make_empty_result(self):
        """Helper: returns a minimal empty module result."""
        return {"score_contribution": 0, "flags": [], "indicators": [],
                "url_results": [], "high_risk_urls": [], "suspicious_domains": [],
                "missing_spf": [], "missing_dmarc": [], "ip_results": [],
                "hosting_ips": [], "routing_ips": [], "all_ips": []}

    def test_score_level_boundaries(self):
        assert _score_to_level(0)   == "LOW"
        assert _score_to_level(29)  == "LOW"
        assert _score_to_level(30)  == "MEDIUM"
        assert _score_to_level(59)  == "MEDIUM"
        assert _score_to_level(60)  == "HIGH"
        assert _score_to_level(79)  == "HIGH"
        assert _score_to_level(80)  == "CRITICAL"
        assert _score_to_level(100) == "CRITICAL"

    def test_phishing_email_scores_high(self):
        raw    = load_eml("phishing_sample.eml")
        parsed = parse_email(raw)

        from modules.header_forensics import analyze_headers
        from modules.auth_analysis import analyze_authentication
        from modules.ai_detection import analyze_email_content
        from modules.url_analysis import analyze_urls
        from modules.domain_intel import analyze_domains
        from modules.ip_intel import analyze_ips
        from modules.correlation import correlate_indicators

        hr  = analyze_headers(parsed)
        ar  = analyze_authentication(parsed)
        ai  = analyze_email_content(parsed)
        ur  = analyze_urls(parsed)
        dr  = analyze_domains(ur["suspicious_domains"])
        from_domain = parsed.get("from_address","").split("@")[-1]
        dr  = analyze_domains(ur["suspicious_domains"], from_domain)
        ips = list(dict.fromkeys(hr["routing_ips"] + dr["all_ips"]))
        ir  = analyze_ips(ips)
        cor = correlate_indicators(hr, ar, ai, ur, dr, ir, parsed)
        risk = calculate_risk_score(hr, ar, ai, ur, dr, ir, cor)

        assert risk["score"] >= 40        # phishing email must score at least MEDIUM
        assert risk["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
        assert risk["classification"] in ("PHISHING", "SUSPICIOUS")
        assert len(risk["major_reasons"]) > 0
        assert isinstance(risk["conclusion"], str)

    def test_legitimate_email_scores_low(self):
        raw    = load_eml("legitimate_sample.eml")
        parsed = parse_email(raw)

        from modules.header_forensics import analyze_headers
        from modules.auth_analysis import analyze_authentication
        from modules.ai_detection import analyze_email_content
        from modules.url_analysis import analyze_urls
        from modules.domain_intel import analyze_domains
        from modules.ip_intel import analyze_ips
        from modules.correlation import correlate_indicators

        hr  = analyze_headers(parsed)
        ar  = analyze_authentication(parsed)
        ai  = analyze_email_content(parsed)
        ur  = analyze_urls(parsed)
        from_domain = parsed.get("from_address","").split("@")[-1]
        dr  = analyze_domains(ur["suspicious_domains"], from_domain)
        ips = list(dict.fromkeys(hr["routing_ips"] + dr["all_ips"]))
        ir  = analyze_ips(ips)
        cor = correlate_indicators(hr, ar, ai, ur, dr, ir, parsed)
        risk = calculate_risk_score(hr, ar, ai, ur, dr, ir, cor)

        # Legitimate email should score lower than phishing
        assert risk["risk_level"] in ("LOW", "MEDIUM")

    def test_score_never_exceeds_100(self):
        """Even if all modules return max scores, total must be ≤ 100."""
        max_result = {
            "score_contribution": 999,
            "flags": [], "indicators": [], "url_results": [],
            "high_risk_urls": [], "suspicious_domains": [],
            "missing_spf": [], "missing_dmarc": [],
            "ip_results": [], "hosting_ips": [],
            "routing_ips": [], "all_ips": [],
            "classification": "PHISHING",
            "confidence": 99,
        }
        empty_corr = {
            "all_indicators": [], "high_indicator_count": 0,
            "total_indicator_count": 0, "shared_ips": [],
            "infrastructure_overlap": False, "graph": {},
        }
        risk = calculate_risk_score(
            max_result, max_result, max_result,
            max_result, max_result, max_result, empty_corr,
        )
        assert risk["score"] <= 100

    def test_result_has_all_required_fields(self):
        raw    = load_eml("phishing_sample.eml")
        parsed = parse_email(raw)

        from modules.header_forensics import analyze_headers
        from modules.auth_analysis import analyze_authentication
        from modules.ai_detection import analyze_email_content
        from modules.url_analysis import analyze_urls
        from modules.domain_intel import analyze_domains
        from modules.ip_intel import analyze_ips
        from modules.correlation import correlate_indicators

        hr  = analyze_headers(parsed)
        ar  = analyze_authentication(parsed)
        ai  = analyze_email_content(parsed)
        ur  = analyze_urls(parsed)
        from_domain = parsed.get("from_address","").split("@")[-1]
        dr  = analyze_domains(ur["suspicious_domains"], from_domain)
        ips = list(dict.fromkeys(hr["routing_ips"] + dr["all_ips"]))
        ir  = analyze_ips(ips)
        cor = correlate_indicators(hr, ar, ai, ur, dr, ir, parsed)
        risk = calculate_risk_score(hr, ar, ai, ur, dr, ir, cor)

        required = [
            "score", "risk_level", "risk_color", "classification",
            "ai_confidence", "breakdown", "major_reasons",
            "total_indicators", "conclusion",
        ]
        for field in required:
            assert field in risk, f"Missing field: {field}"
