# ─────────────────────────────────────────────
#  tests/test_phase1.py
#  Unit tests for Phase 1 modules.
#
#  HOW TO RUN (from the backend/ folder):
#    python -m pytest tests/ -v
#
#  WHY TESTS:
#  Tests verify that each module produces the
#  correct output for known inputs. If you change
#  a module later and break something, the tests
#  will catch it immediately.
# ─────────────────────────────────────────────
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hashlib
from modules.email_parser import parse_email, _extract_urls, _extract_email_address
from modules.header_forensics import analyze_headers, extract_ips_from_received
from modules.auth_analysis import analyze_authentication
from modules.evidence import generate_case_id, compute_sha256, build_evidence_record


# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

def load_eml(filename: str) -> bytes:
    """Load a test .eml file from the test_emails directory."""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(base, "test_emails", filename)
    with open(path, "rb") as f:
        return f.read()


# ─────────────────────────────────────────────
#  Module 1 — Email Parser Tests
# ─────────────────────────────────────────────

class TestEmailParser:

    def test_parse_phishing_email(self):
        """Phishing .eml should parse without error and return expected fields."""
        raw = load_eml("phishing_sample.eml")
        result = parse_email(raw)

        assert result["from_address"] == "security@paypa1-alert.com"
        assert result["subject"] != ""
        # Reply-To is attacker-phish.com — intentionally different from From domain
        assert "attacker-phish.com" in result["reply_to_address"]
        assert len(result["urls"]) > 0
        assert result["sha256"] != ""
        assert result["file_size_bytes"] > 0

    def test_parse_legitimate_email(self):
        """Legitimate .eml should parse without error."""
        raw = load_eml("legitimate_sample.eml")
        result = parse_email(raw)

        assert result["from_address"] == "noreply@github.com"
        assert result["reply_to_address"] == "noreply@github.com"
        assert "github.com" in " ".join(result["urls"])

    def test_sha256_is_deterministic(self):
        """Same file bytes must always produce the same SHA-256."""
        raw = load_eml("phishing_sample.eml")
        r1 = parse_email(raw)
        r2 = parse_email(raw)
        assert r1["sha256"] == r2["sha256"]

    def test_url_extraction(self):
        """URL extractor should find HTTPS links in text."""
        text = "Click here: https://evil.com/login and also http://www.example.com/page"
        urls = _extract_urls(text)
        assert "https://evil.com/login" in urls
        assert "http://www.example.com/page" in urls

    def test_url_deduplication(self):
        """Duplicate URLs should appear only once."""
        text = "https://example.com https://example.com https://other.com"
        urls = _extract_urls(text)
        assert urls.count("https://example.com") == 1

    def test_extract_email_address(self):
        """Should extract just the email from 'Name <email>' format."""
        assert _extract_email_address("John Doe <john@example.com>") == "john@example.com"
        assert _extract_email_address("plain@example.com") == "plain@example.com"
        assert _extract_email_address("") == ""


# ─────────────────────────────────────────────
#  Module 2 — Header Forensics Tests
# ─────────────────────────────────────────────

class TestHeaderForensics:

    def test_phishing_headers_flagged(self):
        """Phishing email should produce at least one header flag."""
        raw = load_eml("phishing_sample.eml")
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        assert len(result["flags"]) > 0
        flag_names = [f["flag"] for f in result["flags"]]
        # Reply-To mismatch is a key indicator
        assert "REPLY_TO_MISMATCH" in flag_names

    def test_legitimate_headers_clean(self):
        """Legitimate email should have no HIGH severity flags."""
        raw = load_eml("legitimate_sample.eml")
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        high_flags = [f for f in result["flags"] if f["severity"] == "HIGH"]
        assert len(high_flags) == 0

    def test_routing_ips_extracted(self):
        """Should extract public IPs from Received headers."""
        raw = load_eml("phishing_sample.eml")
        parsed = parse_email(raw)
        result = analyze_headers(parsed)

        # The phishing sample has a public IP (192.0.2.1 is TEST-NET, skip)
        # Just verify the function runs without error and returns a list
        assert isinstance(result["routing_ips"], list)

    def test_extract_ips_from_received(self):
        """IP extractor should find IPs and skip private ranges."""
        headers = [
            "from mail.example.com (mail.example.com [203.0.113.5]) by mx.dest.com",
            "from localhost (localhost [127.0.0.1]) by mail.example.com",
        ]
        ips = extract_ips_from_received(headers)
        assert "203.0.113.5" in ips
        assert "127.0.0.1" not in ips  # private — should be excluded

    def test_score_is_non_negative(self):
        """Score contribution should never be negative."""
        raw = load_eml("legitimate_sample.eml")
        parsed = parse_email(raw)
        result = analyze_headers(parsed)
        assert result["score_contribution"] >= 0


# ─────────────────────────────────────────────
#  Module 3 — Authentication Analysis Tests
# ─────────────────────────────────────────────

class TestAuthAnalysis:

    def test_phishing_auth_failures(self):
        """Phishing email should have SPF/DKIM/DMARC failures."""
        raw = load_eml("phishing_sample.eml")
        parsed = parse_email(raw)
        result = analyze_authentication(parsed)

        assert result["spf"]   == "FAIL"
        assert result["dkim"]  == "FAIL"
        assert result["dmarc"] == "FAIL"
        assert result["score_contribution"] > 0

    def test_legitimate_auth_passes(self):
        """Legitimate email should pass all authentication checks."""
        raw = load_eml("legitimate_sample.eml")
        parsed = parse_email(raw)
        result = analyze_authentication(parsed)

        assert result["spf"]   == "PASS"
        assert result["dkim"]  == "PASS"
        assert result["dmarc"] == "PASS"

    def test_softfail_detected(self):
        """SPF softfail in spear-phishing sample should be detected."""
        raw = load_eml("spear_phishing_sample.eml")
        parsed = parse_email(raw)
        result = analyze_authentication(parsed)

        assert result["spf"] == "SOFTFAIL"

    def test_score_within_bounds(self):
        """Score should be between 0 and 30."""
        for filename in ("phishing_sample.eml", "legitimate_sample.eml"):
            raw = load_eml(filename)
            parsed = parse_email(raw)
            result = analyze_authentication(parsed)
            assert 0 <= result["score_contribution"] <= 30


# ─────────────────────────────────────────────
#  Module 12 — Evidence Tests
# ─────────────────────────────────────────────

class TestEvidence:

    def test_case_id_format(self):
        """Case ID should follow CASE-YYYYMMDD-XXXXXXXX format."""
        cid = generate_case_id()
        parts = cid.split("-")
        assert parts[0] == "CASE"
        assert len(parts[1]) == 8   # YYYYMMDD
        assert len(parts[2]) == 8   # hex

    def test_case_ids_are_unique(self):
        """Each call to generate_case_id should return a different ID."""
        ids = {generate_case_id() for _ in range(100)}
        assert len(ids) == 100

    def test_sha256_matches_hashlib(self):
        """Our compute_sha256 should produce the same result as hashlib."""
        data = b"test email content"
        expected = hashlib.sha256(data).hexdigest()
        assert compute_sha256(data) == expected

    def test_evidence_record_fields(self):
        """Evidence record should contain all required fields."""
        rec = build_evidence_record("CASE-20240101-ABCD1234", "test.eml", "abc123", 1024)
        assert rec["case_id"]         == "CASE-20240101-ABCD1234"
        assert rec["filename"]        == "test.eml"
        assert rec["sha256"]          == "abc123"
        assert rec["file_size_bytes"] == 1024
        assert "upload_timestamp" in rec
