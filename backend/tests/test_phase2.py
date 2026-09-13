# ─────────────────────────────────────────────
#  tests/test_phase2.py
#  Unit tests for Phase 2 — AI/ML Detection
#
#  HOW TO RUN (from the backend/ folder):
#    python -m pytest tests/test_phase2.py -v
# ─────────────────────────────────────────────
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.ai_detection import (
    preprocess_text,
    extract_keyword_features,
    analyze_email_content,
    LABEL_PHISHING,
    LABEL_LEGITIMATE,
    LABEL_SUSPICIOUS,
)
from modules.email_parser import parse_email


def load_eml(filename: str) -> bytes:
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(base, "test_emails", filename)
    with open(path, "rb") as f:
        return f.read()


# ─────────────────────────────────────────────
#  Text Preprocessing Tests
# ─────────────────────────────────────────────

class TestPreprocessText:

    def test_lowercases_text(self):
        result = preprocess_text("URGENT ACT NOW")
        assert result == result.lower()

    def test_removes_html_tags(self):
        result = preprocess_text("<b>Click here</b> to <a href='x'>verify</a>")
        assert "<b>" not in result
        assert "<a" not in result
        assert "click" in result
        assert "verify" in result

    def test_removes_urls(self):
        result = preprocess_text("Visit https://evil.com/login to verify your account")
        assert "evil.com" not in result
        assert "url" in result  # replaced with 'url' token

    def test_removes_stop_words(self):
        result = preprocess_text("this is a test and the result")
        tokens = result.split()
        stop_words = {"this", "is", "a", "and", "the"}
        for token in tokens:
            assert token not in stop_words

    def test_empty_text_returns_empty(self):
        assert preprocess_text("") == ""
        assert preprocess_text(None) == ""

    def test_preserves_meaningful_words(self):
        result = preprocess_text("verify your password immediately before account suspended")
        assert "verify" in result
        assert "password" in result
        assert "immediately" in result


# ─────────────────────────────────────────────
#  Keyword Feature Extraction Tests
# ─────────────────────────────────────────────

class TestKeywordFeatures:

    def test_detects_urgency_language(self):
        result = extract_keyword_features("Act now! Your account will expire in 24 hours.")
        assert "urgency_language" in result["detected_patterns"]
        assert result["keyword_score"] > 0

    def test_detects_credential_request(self):
        result = extract_keyword_features("Please verify your password and confirm your account details.")
        assert "credential_request" in result["detected_patterns"]

    def test_detects_financial_request(self):
        result = extract_keyword_features("Please provide your credit card number and Social Security Number.")
        assert "financial_request" in result["detected_patterns"]
        assert result["keyword_score"] >= 7  # credit card (3) + SSN (4)

    def test_detects_account_threat(self):
        result = extract_keyword_features("Your account has been suspended due to unusual activity.")
        assert "account_threat" in result["detected_patterns"]

    def test_clean_text_has_low_score(self):
        result = extract_keyword_features(
            "Hi team, please find the meeting agenda attached for tomorrow's standup. "
            "We will discuss the Q3 roadmap and sprint retrospective."
        )
        assert result["keyword_score"] < 5

    def test_returns_indicators_list(self):
        result = extract_keyword_features("Urgent: verify your password immediately.")
        assert isinstance(result["indicators"], list)
        assert len(result["indicators"]) > 0

    def test_keyword_score_capped_at_40(self):
        # Very phishy text with many patterns — score should not exceed 40
        text = ("urgent act now verify password credit card social security number "
                "suspended terminated click here dear customer unusual activity "
                "do not share bank account routing number confirm immediately")
        result = extract_keyword_features(text)
        assert result["keyword_score"] <= 40


# ─────────────────────────────────────────────
#  Full AI Detection Pipeline Tests
# ─────────────────────────────────────────────

class TestAIDetection:

    def test_phishing_email_classified_correctly(self):
        """Phishing email should be classified as PHISHING or SUSPICIOUS."""
        raw    = load_eml("phishing_sample.eml")
        parsed = parse_email(raw)
        result = analyze_email_content(parsed)

        assert result["classification"] in (LABEL_PHISHING, LABEL_SUSPICIOUS)
        assert result["confidence"] > 0
        assert result["score_contribution"] > 0

    def test_legitimate_email_not_phishing(self):
        """Legitimate email should NOT be classified as PHISHING."""
        raw    = load_eml("legitimate_sample.eml")
        parsed = parse_email(raw)
        result = analyze_email_content(parsed)

        assert result["classification"] != LABEL_PHISHING

    def test_spear_phishing_flagged(self):
        """Spear phishing email should be flagged as PHISHING or SUSPICIOUS."""
        raw    = load_eml("spear_phishing_sample.eml")
        parsed = parse_email(raw)
        result = analyze_email_content(parsed)

        assert result["classification"] in (LABEL_PHISHING, LABEL_SUSPICIOUS)

    def test_result_has_all_required_fields(self):
        """Result must contain all fields used by the dashboard."""
        raw    = load_eml("phishing_sample.eml")
        parsed = parse_email(raw)
        result = analyze_email_content(parsed)

        required_fields = [
            "classification", "confidence", "model_used",
            "detected_patterns", "indicators", "keyword_score",
            "explanation", "score_contribution",
        ]
        for field in required_fields:
            assert field in result, f"Missing field: {field}"

    def test_confidence_is_percentage(self):
        """Confidence should be between 0 and 100."""
        raw    = load_eml("phishing_sample.eml")
        parsed = parse_email(raw)
        result = analyze_email_content(parsed)

        assert 0 <= result["confidence"] <= 100

    def test_score_contribution_within_bounds(self):
        """Score contribution should be between 0 and 30."""
        for filename in ("phishing_sample.eml", "legitimate_sample.eml"):
            raw    = load_eml(filename)
            parsed = parse_email(raw)
            result = analyze_email_content(parsed)
            assert 0 <= result["score_contribution"] <= 30

    def test_model_used_field_is_valid(self):
        """model_used should be either 'ml_model' or 'rule_based'."""
        raw    = load_eml("phishing_sample.eml")
        parsed = parse_email(raw)
        result = analyze_email_content(parsed)

        assert result["model_used"] in ("ml_model", "rule_based")

    def test_explanation_is_non_empty_string(self):
        """Explanation should always be a non-empty string."""
        raw    = load_eml("phishing_sample.eml")
        parsed = parse_email(raw)
        result = analyze_email_content(parsed)

        assert isinstance(result["explanation"], str)
        assert len(result["explanation"]) > 10
