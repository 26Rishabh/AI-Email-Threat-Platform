# ─────────────────────────────────────────────
#  modules/ai_detection.py  —  MODULE 4
#  AI / ML Email Threat Detection
#
#  WHY THIS EXISTS:
#  Rule-based checks (header mismatches, auth failures)
#  catch known patterns but miss novel attacks.
#  A machine-learning model trained on thousands of
#  real phishing and legitimate emails can detect
#  subtle language patterns that rules never could —
#  urgency, credential requests, social engineering,
#  impersonation language, financial threats, etc.
#
#  HOW IT WORKS:
#  1. The email body text is cleaned (lowercased,
#     punctuation removed, stop-words stripped).
#  2. TF-IDF converts the text into a numeric vector
#     (each word gets a weight based on how unique
#     it is to phishing vs. legitimate emails).
#  3. A Random Forest classifier votes on the vector
#     and produces a label + confidence score.
#
#  The trained model is saved to disk as a .pkl file
#  so it loads instantly on server startup without
#  retraining every time.
# ─────────────────────────────────────────────
import os
import re
import pickle
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Path to saved model files ─────────────────
_MODEL_DIR  = Path(__file__).resolve().parent.parent / "ml_models"
_MODEL_PATH = _MODEL_DIR / "phishing_classifier.pkl"
_VECT_PATH  = _MODEL_DIR / "tfidf_vectorizer.pkl"

# ── Classification labels ─────────────────────
LABEL_LEGITIMATE  = "LEGITIMATE"
LABEL_SUSPICIOUS  = "SUSPICIOUS"
LABEL_PHISHING    = "PHISHING"
LABEL_UNKNOWN     = "UNKNOWN"

# Confidence threshold below which we call something SUSPICIOUS
# rather than definitively PHISHING or LEGITIMATE
_SUSPICIOUS_THRESHOLD = 0.65

# ── Cached model objects (loaded once) ────────
_classifier  = None
_vectorizer  = None
_model_ready = False


# ── Text preprocessing ────────────────────────

# Common English stop-words to remove (they add noise, not signal)
_STOP_WORDS = {
    "a","an","the","and","or","but","in","on","at","to","for","of","with",
    "is","are","was","were","be","been","being","have","has","had","do",
    "does","did","will","would","shall","should","may","might","must","can",
    "could","i","you","he","she","it","we","they","me","him","her","us",
    "them","my","your","his","its","our","their","this","that","these",
    "those","what","which","who","how","when","where","from","by","as","if",
    "not","no","so","up","out","about","into","through","during","before",
    "after","between","each","all","both","few","more","most","other","some",
    "such","than","too","very","just","because","while","although","however",
}


def preprocess_text(text: str) -> str:
    """
    Cleans and normalises email body text for the ML model.

    Steps:
      1. Lowercase everything
      2. Remove HTML tags (emails often contain HTML)
      3. Remove URLs (handled separately by Module 5)
      4. Remove special characters, keep only letters/spaces
      5. Remove stop-words
      6. Collapse extra whitespace

    WHY: Raw email text is noisy. The model learns better
    from clean, normalised tokens.
    """
    if not text:
        return ""

    text = text.lower()

    # Remove HTML tags
    text = re.sub(r"<[^>]+>", " ", text)

    # Remove URLs
    text = re.sub(r"https?://\S+|www\.\S+", " url ", text)

    # Remove email addresses
    text = re.sub(r"\S+@\S+", " email ", text)

    # Keep only letters and spaces
    text = re.sub(r"[^a-z\s]", " ", text)

    # Tokenise and remove stop-words
    tokens = [w for w in text.split() if w not in _STOP_WORDS and len(w) > 2]

    return " ".join(tokens)


# ── Phishing keyword signals ──────────────────
# These weighted keywords are used both as features
# for the rule-based fallback AND to enrich the
# explanation of why an email was flagged.

_PHISHING_PATTERNS = [
    # Urgency / threat language
    (r"\burgent\b",           "urgency_language",        2),
    (r"\bimmediately\b",      "urgency_language",        2),
    (r"\bact now\b",          "urgency_language",        3),
    (r"\b24 hours?\b",        "urgency_language",        2),
    (r"\bexpire[sd]?\b",      "urgency_language",        1),
    (r"\bsuspend(ed)?\b",     "account_threat",          2),
    (r"\bterminate[sd]?\b",   "account_threat",          2),
    (r"\blimited\b",          "account_threat",          1),
    (r"\blocked\b",           "account_threat",          1),
    (r"\bclosed\b",           "account_threat",          1),
    # Credential / financial requests
    (r"\bpassword\b",         "credential_request",      3),
    (r"\bverif(y|ication)\b", "credential_request",      2),
    (r"\bconfirm\b",          "credential_request",      1),
    (r"\bcredit card\b",      "financial_request",       3),
    (r"\bbank account\b",     "financial_request",       3),
    (r"\bssn\b",              "financial_request",       4),
    (r"\bsocial security\b",  "financial_request",       4),
    (r"\brouting number\b",   "financial_request",       3),
    # Social engineering
    (r"\bdear (customer|user|member|client)\b", "impersonation", 2),
    (r"\bwe noticed\b",       "social_engineering",      2),
    (r"\bunusual activity\b", "social_engineering",      3),
    (r"\bclick (here|below|the link)\b", "suspicious_cta", 2),
    (r"\bclick (the link|here) to (verify|confirm|restore|update)\b", "suspicious_cta", 3),
    (r"\bdo not (share|ignore|delete)\b", "manipulation",  2),
    (r"\bconfidential\b",     "manipulation",            1),
    # Impersonation language
    (r"\bpaypal\b",           "brand_impersonation",     1),
    (r"\bamazon\b",           "brand_impersonation",     1),
    (r"\bmicrosoft\b",        "brand_impersonation",     1),
    (r"\bapple\b",            "brand_impersonation",     1),
    (r"\bnetflix\b",          "brand_impersonation",     1),
    (r"\bchase\b",            "brand_impersonation",     1),
]


def extract_keyword_features(text: str) -> dict[str, Any]:
    """
    Scans the email body for phishing keyword patterns.

    Returns:
      - detected_patterns : list of triggered pattern categories
      - keyword_score     : weighted score from keyword matches
      - indicators        : human-readable list of what was found
    """
    if not text:
        return {"detected_patterns": [], "keyword_score": 0, "indicators": []}

    lower = text.lower()
    detected = {}   # category → total weight
    indicators = []

    for pattern, category, weight in _PHISHING_PATTERNS:
        if re.search(pattern, lower):
            detected[category] = detected.get(category, 0) + weight
            if category not in [i["category"] for i in indicators]:
                indicators.append({
                    "category":    category,
                    "description": _CATEGORY_DESCRIPTIONS.get(category, category),
                })

    keyword_score = min(sum(detected.values()), 40)  # cap at 40

    return {
        "detected_patterns": list(detected.keys()),
        "keyword_score":     keyword_score,
        "indicators":        indicators,
    }


_CATEGORY_DESCRIPTIONS = {
    "urgency_language":    "Urgent / time-pressure language detected",
    "account_threat":      "Account suspension or closure threat",
    "credential_request":  "Request for password or credentials",
    "financial_request":   "Request for financial / banking information",
    "impersonation":       "Generic impersonation greeting (Dear Customer)",
    "social_engineering":  "Social engineering language pattern",
    "suspicious_cta":      "Suspicious call-to-action (click link to verify)",
    "manipulation":        "Manipulation / secrecy instruction",
    "brand_impersonation": "Known brand name referenced (possible impersonation)",
}


# ── Model loading ─────────────────────────────

def load_model() -> bool:
    """
    Loads the trained classifier and TF-IDF vectorizer from disk.
    Called once at server startup.

    Returns True if model loaded successfully, False otherwise.
    (If False, the system falls back to rule-based scoring only.)
    """
    global _classifier, _vectorizer, _model_ready

    if not _MODEL_PATH.exists() or not _VECT_PATH.exists():
        logger.warning(
            "ML model files not found at %s. "
            "Run 'python scripts/train_model.py' to train the model. "
            "Falling back to rule-based detection.",
            _MODEL_DIR,
        )
        _model_ready = False
        return False

    try:
        with open(_MODEL_PATH, "rb") as f:
            _classifier = pickle.load(f)
        with open(_VECT_PATH, "rb") as f:
            _vectorizer = pickle.load(f)
        _model_ready = True
        logger.info("✓ ML phishing detection model loaded successfully.")
        return True
    except Exception as e:
        logger.error("Failed to load ML model: %s", e)
        _model_ready = False
        return False


def is_model_ready() -> bool:
    return _model_ready


# ── ML-based prediction ───────────────────────

def _predict_with_model(clean_text: str) -> tuple[str, float]:
    """
    Runs the trained model on preprocessed text.

    Returns (label, confidence) where confidence is 0.0–1.0.
    """
    if not _model_ready or not clean_text.strip():
        return LABEL_UNKNOWN, 0.0

    try:
        vec = _vectorizer.transform([clean_text])
        proba = _classifier.predict_proba(vec)[0]
        classes = _classifier.classes_

        # Find the index of the PHISHING class
        phishing_idx = list(classes).index(1) if 1 in classes else -1
        legit_idx    = list(classes).index(0) if 0 in classes else -1

        if phishing_idx == -1:
            return LABEL_UNKNOWN, 0.0

        phishing_conf = float(proba[phishing_idx])
        legit_conf    = float(proba[legit_idx]) if legit_idx != -1 else 1 - phishing_conf

        if phishing_conf >= _SUSPICIOUS_THRESHOLD:
            return LABEL_PHISHING, phishing_conf
        elif legit_conf >= _SUSPICIOUS_THRESHOLD:
            return LABEL_LEGITIMATE, legit_conf
        else:
            return LABEL_SUSPICIOUS, max(phishing_conf, legit_conf)

    except Exception as e:
        logger.error("Model prediction error: %s", e)
        return LABEL_UNKNOWN, 0.0


# ── Rule-based fallback ───────────────────────

def _classify_by_rules(keyword_score: int, patterns: list[str]) -> tuple[str, float]:
    """
    When the ML model is not available, classify purely by keyword score.
    This ensures the system always produces a result.
    """
    if keyword_score >= 20:
        confidence = min(0.60 + (keyword_score - 20) * 0.01, 0.89)
        return LABEL_PHISHING, round(confidence, 2)
    elif keyword_score >= 8:
        return LABEL_SUSPICIOUS, round(0.50 + keyword_score * 0.005, 2)
    else:
        return LABEL_LEGITIMATE, round(0.70 - keyword_score * 0.01, 2)


# ── Main AI Detection Function ────────────────

def analyze_email_content(parsed: dict[str, Any]) -> dict[str, Any]:
    """
    Main entry point for Module 4.

    INPUT : the parsed email dictionary from Module 1
    OUTPUT: a dictionary with:
              - classification   : PHISHING / SUSPICIOUS / LEGITIMATE / UNKNOWN
              - confidence       : 0–100 (percentage)
              - model_used       : 'ml_model' or 'rule_based'
              - detected_patterns: list of triggered pattern categories
              - indicators       : human-readable explanation list
              - score_contribution: points added to the overall risk score
    """
    # Combine plain text and HTML body for analysis
    body = (parsed.get("body_plain", "") or "") + " " + (parsed.get("body_html", "") or "")
    subject = parsed.get("subject", "") or ""

    # Include subject in analysis — phishing subjects are often highly indicative
    full_text = subject + " " + body

    # ── Step 1: Extract keyword features ──────
    keyword_result = extract_keyword_features(full_text)
    keyword_score  = keyword_result["keyword_score"]
    patterns       = keyword_result["detected_patterns"]
    indicators     = keyword_result["indicators"]

    # ── Step 2: Classify ──────────────────────
    if _model_ready:
        clean_text = preprocess_text(full_text)
        label, confidence = _predict_with_model(clean_text)
        model_used = "ml_model"

        # Blend: if keyword score is very high but model says legitimate,
        # bump to SUSPICIOUS — keyword signals override low-confidence ML
        if label == LABEL_LEGITIMATE and keyword_score >= 15:
            label      = LABEL_SUSPICIOUS
            confidence = max(confidence, 0.55)
    else:
        label, confidence = _classify_by_rules(keyword_score, patterns)
        model_used = "rule_based"

    # ── Step 3: Refine label ──────────────────
    # Emails with very high keyword scores and high ML confidence
    # get labelled more specifically
    if label == LABEL_PHISHING and "financial_request" in patterns:
        label = "PHISHING"   # keep — financial data theft is phishing
    elif label == LABEL_PHISHING and "brand_impersonation" in patterns:
        label = "PHISHING"   # brand impersonation is phishing

    # ── Step 4: Score contribution ────────────
    # The AI module contributes up to 30 points to the risk score
    if label == LABEL_PHISHING:
        score = int(20 + (confidence * 10))
    elif label == LABEL_SUSPICIOUS:
        score = int(10 + (confidence * 5))
    elif label == LABEL_LEGITIMATE:
        score = max(0, int(5 - (confidence * 5)))
    else:
        score = 5

    # Also add keyword contribution (up to 10 extra points)
    score += min(keyword_score // 4, 10)
    score  = min(score, 30)

    # ── Step 5: Build explanation ─────────────
    explanation = _build_explanation(label, confidence, indicators, model_used)

    return {
        "classification":    label,
        "confidence":        round(confidence * 100, 1),   # as percentage
        "confidence_raw":    round(confidence, 4),
        "model_used":        model_used,
        "detected_patterns": patterns,
        "indicators":        indicators,
        "keyword_score":     keyword_score,
        "explanation":       explanation,
        "score_contribution": score,
    }


def _build_explanation(
    label: str,
    confidence: float,
    indicators: list[dict],
    model_used: str,
) -> str:
    """Builds a human-readable explanation of the classification result."""
    conf_pct = round(confidence * 100)
    source   = "AI/ML model" if model_used == "ml_model" else "rule-based analysis"

    if label == LABEL_PHISHING:
        base = f"Email classified as PHISHING ({conf_pct}% confidence) by {source}."
    elif label == LABEL_SUSPICIOUS:
        base = f"Email classified as SUSPICIOUS ({conf_pct}% confidence) by {source}."
    elif label == LABEL_LEGITIMATE:
        base = f"Email classified as LEGITIMATE ({conf_pct}% confidence) by {source}."
    else:
        base = f"Classification inconclusive. Manual review recommended."

    if indicators:
        pattern_list = "; ".join(i["description"] for i in indicators[:5])
        base += f" Key patterns: {pattern_list}."

    return base
