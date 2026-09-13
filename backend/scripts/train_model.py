# ─────────────────────────────────────────────
#  scripts/train_model.py
#  Downloads phishing email datasets, trains the
#  ML classifier, and saves it to disk.
#
#  HOW TO RUN (from the backend/ folder):
#    python scripts/train_model.py
#
#  WHY A SEPARATE SCRIPT:
#  Training takes time and only needs to happen
#  once (or when you want to retrain with new data).
#  The server loads the pre-trained model from disk,
#  which is instant.
#
#  DATASET USED:
#  We build a training set from two sources:
#    1. Built-in curated phishing/legitimate samples
#       (always available, no download needed)
#    2. The CSDMC2010 spam dataset structure or
#       any CSV with 'text' and 'label' columns
#       placed in backend/data/
#
#  The model: Random Forest with TF-IDF features.
#  WHY RANDOM FOREST:
#    - Works well on text classification
#    - Produces probability scores (needed for confidence %)
#    - Resistant to overfitting
#    - Fast to train and predict
# ─────────────────────────────────────────────
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pickle
import json
import re
from pathlib import Path
from datetime import datetime

# ML libraries
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report, accuracy_score,
    precision_score, recall_score, f1_score,
)
from sklearn.pipeline import Pipeline
import numpy as np

from modules.ai_detection import preprocess_text

# ── Paths ─────────────────────────────────────
_BASE       = Path(__file__).resolve().parent.parent
_MODEL_DIR  = _BASE / "ml_models"
_DATA_DIR   = _BASE / "data"
_MODEL_PATH = _MODEL_DIR / "phishing_classifier.pkl"
_VECT_PATH  = _MODEL_DIR / "tfidf_vectorizer.pkl"
_META_PATH  = _MODEL_DIR / "model_metadata.json"

_MODEL_DIR.mkdir(exist_ok=True)
_DATA_DIR.mkdir(exist_ok=True)


# ─────────────────────────────────────────────
#  TRAINING DATA
#  A curated set of phishing and legitimate email
#  samples. These are representative examples
#  of real patterns — not real personal data.
#
#  Label: 1 = phishing/spam,  0 = legitimate
# ─────────────────────────────────────────────

PHISHING_SAMPLES = [
    # Payment / account suspension threats
    "Your PayPal account has been limited. Please verify your information immediately to restore access. Click here to confirm your details within 24 hours or your account will be permanently suspended.",
    "URGENT: Your bank account has been compromised. Unusual activity detected. Verify your identity now by clicking the secure link below. Failure to respond within 24 hours will result in account closure.",
    "Dear Customer, We have detected suspicious transactions on your account. Your account will be suspended unless you verify your credit card details and billing address immediately.",
    "Your Apple ID has been locked due to security reasons. To unlock your account please verify your information at the link provided. Act now to prevent permanent loss of access.",
    "IMPORTANT NOTICE: Your Netflix account payment failed. Update your billing information immediately to avoid service interruption. Click here to update your payment method now.",
    "We noticed unusual sign-in activity on your Microsoft account. Please verify your account immediately by clicking the link below and entering your username and password.",
    "Your Amazon account has been suspended due to suspicious activity. Confirm your identity by clicking here and providing your account credentials and payment information.",
    "Dear valued customer, Your online banking access will be disabled unless you verify your details. Please click the secure link and enter your account number and PIN immediately.",
    "FINAL WARNING: Your email account will be deactivated in 24 hours. Verify your account details now to prevent deletion. Click the link and enter your password to continue.",
    "Congratulations! You have won a prize. To claim your reward, verify your identity by providing your credit card number, expiry date, and CVV code at the secure link below.",

    # HR / corporate impersonation
    "Dear Employee, All staff are required to submit their banking information for the annual salary review. Please provide your bank account number and routing number by end of day.",
    "Important HR Notice: Due to a payroll system update, all employees must re-enter their direct deposit information. Click the link below and enter your bank details immediately.",
    "This is a confidential notice from the HR department. Please do not discuss this with your colleagues. Submit your updated tax information including your Social Security Number by today.",
    "Management has approved salary increments. To receive your updated payment, please verify your bank account details by filling out the attached secure form immediately.",

    # Credential harvesting
    "Your password will expire in 24 hours. Click here to reset your password immediately. Enter your current password and choose a new one to maintain account access.",
    "Security Alert: Someone tried to access your account from an unknown device. Verify your identity now by entering your username and password at the secure portal.",
    "Your account requires immediate verification. Please log in using the link below and confirm your username, password, and date of birth to secure your account.",
    "We have updated our security policy. All users must verify their login credentials within 24 hours. Failure to do so will result in account suspension. Click here to verify now.",
    "NOTICE: Your webmail account storage is full. To continue receiving emails, please verify your account by clicking the link and entering your email address and password.",
    "Dear account holder, your session has expired. Please click here to re-authenticate by providing your username, password and the one-time verification code sent to your phone.",

    # Financial fraud
    "You have a pending transfer of $5,000 awaiting your confirmation. To release the funds, provide your bank account number and Social Security Number for identity verification.",
    "Congratulations! Your loan application has been approved. To receive the funds, you must first pay a processing fee of $200. Send payment immediately to release your loan amount.",
    "URGENT: IRS Tax Refund Notification. You are entitled to a tax refund of $1,250. Provide your Social Security Number and bank details to process your refund immediately.",
    "A large international transfer has been held for your account. To claim the $10,000 wire transfer, verify your identity by providing your bank account details and routing number.",
    "Your insurance claim has been approved. To receive your payout, please provide your bank account number, sort code, and date of birth for verification purposes.",

    # Lottery / prize scams
    "You have been selected as a winner in our online lottery. To claim your prize of $50,000, you must verify your identity and pay a small processing fee. Contact us immediately.",
    "WINNER NOTIFICATION: Your email address was randomly selected for a cash prize. To receive your winnings, provide your full name, address, and banking details for transfer.",
    "Congratulations! Your phone number has won in our weekly draw. Claim your prize by clicking the link and entering your personal and banking information for immediate payment.",

    # Package delivery scams
    "Your package delivery failed because no one was home. To reschedule delivery, click the link and confirm your address and payment card details to cover the redelivery fee.",
    "USPS: Your parcel is on hold due to incomplete address information. Update your delivery address and pay the $2.99 redelivery fee by clicking the secure link below immediately.",
    "DHL NOTICE: Your international shipment requires customs clearance. Pay the $15 customs fee immediately by clicking the link to avoid your package being returned to sender.",

    # Tech support scams
    "VIRUS ALERT: Your computer has been infected with a dangerous virus. Call our toll-free number immediately or click the link to remove the virus and protect your data now.",
    "Microsoft Security Warning: Your Windows license has expired. Call support immediately or your computer will be blocked. Click here to renew your license and remove the threat.",
    "Your computer has been blocked for suspicious activity. Do not restart your computer. Call our security team immediately at the number provided to unlock your system.",

    # Generic phishing patterns
    "Click here to verify your account and claim your exclusive reward. This offer expires in 24 hours. Enter your details on the secure page to avoid losing your benefits.",
    "We need to verify your personal information. Please click the secure link and confirm your date of birth, mother's maiden name, and last four digits of your Social Security Number.",
    "Dear user, your account has been flagged for suspicious activity. Immediate action required. Log in through our secure portal and verify your identity to restore full access.",
    "Warning: Unauthorized login attempt detected. Your account will be locked in 30 minutes unless you verify your identity immediately by clicking the link and entering your password.",
    "You have received a secure document. To view your document, click the link and enter your email credentials. This document will expire in 24 hours.",
    "Final notice: Your subscription payment of $199 is due. Update your payment information immediately to avoid service disruption. Click here to update your billing details.",
]

LEGITIMATE_SAMPLES = [
    # Professional/work emails
    "Hi team, please find the meeting agenda attached for tomorrow's standup. We will be discussing the Q3 roadmap, sprint retrospective, and upcoming product launch timeline. See you at 10am.",
    "Dear John, thank you for your application to our engineering position. We were impressed with your background and would like to invite you for a technical interview next week.",
    "Hi Sarah, just following up on the proposal I sent last Tuesday. Please let me know if you have any questions or need any additional information. Looking forward to your feedback.",
    "The weekly engineering report is attached. Key highlights include the completion of the authentication module, three bug fixes in the payment service, and upcoming database migration.",
    "Hello everyone, the quarterly company all-hands meeting is scheduled for next Friday at 2pm in the main conference room. Lunch will be provided. Please RSVP by Wednesday.",
    "Hi, I wanted to share the project status update. The development team completed the API integration on schedule. Testing is underway and we expect to go live next Monday.",
    "Please find attached the invoice for the consulting services provided in October. Payment is due within 30 days. Contact me if you have any questions about the billing.",

    # Transactional / service emails
    "Your order #12345 has been shipped. Your package is on its way and should arrive within 3-5 business days. Track your shipment using the tracking number in the subject.",
    "Thank you for your purchase. Your subscription to the Premium plan has been activated. Your receipt for $9.99 is attached. You can manage your account in the settings.",
    "Your GitHub pull request has been merged into the main branch. The CI/CD pipeline has been triggered and deployment will complete within the next 15 minutes.",
    "Your flight confirmation for tomorrow morning. Flight AA1234 departs at 8:30am. Please arrive at the airport at least 2 hours before departure. Check-in is now open.",
    "Your appointment with Dr. Johnson is confirmed for Tuesday at 3pm at the downtown medical center. Please bring your insurance card and arrive 15 minutes early.",
    "Your monthly bank statement is now available. Log in to your account to view your statement. Your current balance and recent transactions are available in the portal.",
    "Thank you for contacting support. Your ticket #98765 has been created and assigned to a technician. Expected response time is within 24 hours during business days.",

    # Educational / informational
    "This week in our newsletter: best practices for code review, introduction to Docker containers, and a roundup of the most interesting open source projects launched this month.",
    "The library's new arrivals list is now available. We have added 50 new titles to our collection including fiction, non-fiction, and technical books. Members can reserve online.",
    "Your course completion certificate for Python for Data Science is ready. You can download it from your profile page. Congratulations on completing all 12 modules.",
    "Meeting reminder: The board of directors meeting is scheduled for Monday at 9am. The agenda and supporting documents have been distributed via the document management system.",
    "Your software license renewal is coming up in 30 days. You can renew directly in the admin portal under Settings > Billing. No action is required if you want to continue.",

    # Personal / casual professional
    "Hi, just wanted to check in on how the onboarding is going. Let me know if you need access to any additional resources or if you have questions about the codebase.",
    "Thanks for the great presentation yesterday. The team really appreciated the depth of analysis. We will incorporate your recommendations into the next planning cycle.",
    "Reminder that the office will be closed on Monday for the national holiday. Normal operations will resume on Tuesday. Enjoy the long weekend.",
    "The updated employee handbook is now available on the intranet. Please review the changes to the remote work policy and expense reimbursement procedures by end of month.",
    "Your password was recently changed. If you made this change, no further action is needed. If you did not make this change, please contact the IT help desk immediately.",
    "The server maintenance window is scheduled for Sunday night from 11pm to 3am. During this time the application will be unavailable. Please plan your work accordingly.",
    "Your annual performance review is scheduled for next week. Please complete the self-assessment form in the HR portal before your meeting with your manager.",
    "Hi, the code review for your pull request is complete. I left a few minor comments but nothing blocking. Feel free to merge once you have addressed the feedback.",
    "This is a reminder that expense reports for October must be submitted by the 15th of this month. Late submissions may not be processed until the following payment cycle.",
    "Good news — the database migration completed successfully last night with no data loss. All services are operating normally. The post-migration report is attached.",
]


def build_training_data() -> tuple[list[str], list[int]]:
    """
    Assembles the training corpus.

    Returns:
      texts  : list of raw email body strings
      labels : list of 0 (legitimate) or 1 (phishing)
    """
    texts  = []
    labels = []

    # Add built-in samples
    for sample in PHISHING_SAMPLES:
        texts.append(sample)
        labels.append(1)

    for sample in LEGITIMATE_SAMPLES:
        texts.append(sample)
        labels.append(0)

    # Try to load additional data from backend/data/ folder
    # Supports CSV files with columns: text, label (0 or 1)
    for csv_file in _DATA_DIR.glob("*.csv"):
        try:
            import csv
            with open(csv_file, encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                added = 0
                for row in reader:
                    text  = row.get("text", row.get("body", row.get("message", "")))
                    label = row.get("label", row.get("spam", ""))
                    if text and label in ("0", "1", 0, 1):
                        texts.append(str(text))
                        labels.append(int(label))
                        added += 1
            print(f"  ✓ Loaded {added} samples from {csv_file.name}")
        except Exception as e:
            print(f"  ✗ Could not load {csv_file.name}: {e}")

    return texts, labels


def train_and_save():
    """
    Main training function.
    Preprocesses data, trains the model, evaluates it, saves to disk.
    """
    print("-" * 55)
    print("  AI Email Threat Detection - Model Training")
    print("-" * 55)

    # ── Step 1: Load data ─────────────────────
    print("\n[1/5] Loading training data...")
    texts, labels = build_training_data()
    print(f"  Total samples : {len(texts)}")
    print(f"  Phishing (1)  : {sum(labels)}")
    print(f"  Legitimate (0): {len(labels) - sum(labels)}")

    if len(texts) < 20:
        print("✗ Not enough training samples. Add more data to backend/data/")
        sys.exit(1)

    # ── Step 2: Preprocess ────────────────────
    print("\n[2/5] Preprocessing text...")
    clean_texts = [preprocess_text(t) for t in texts]

    # ── Step 3: Vectorize ─────────────────────
    print("\n[3/5] Building TF-IDF features...")
    vectorizer = TfidfVectorizer(
        max_features=3000,     # top 3000 words by TF-IDF score
        ngram_range=(1, 2),    # single words AND two-word phrases
        min_df=2,              # word must appear in at least 2 documents
        sublinear_tf=True,     # use log(1+tf) instead of raw tf
    )
    X = vectorizer.fit_transform(clean_texts)
    y = np.array(labels)

    # ── Step 4: Train ─────────────────────────
    print("\n[4/5] Training Random Forest classifier...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=200,      # 200 decision trees
        max_depth=None,        # trees grow until pure
        min_samples_split=2,
        random_state=42,
        class_weight="balanced",  # handles imbalanced datasets
        n_jobs=-1,             # use all CPU cores
    )
    clf.fit(X_train, y_train)

    # ── Step 5: Evaluate ──────────────────────
    print("\n[5/5] Evaluating model...")
    y_pred = clf.predict(X_test)
    acc    = accuracy_score(y_test, y_pred)
    prec   = precision_score(y_test, y_pred, zero_division=0)
    rec    = recall_score(y_test, y_pred, zero_division=0)
    f1     = f1_score(y_test, y_pred, zero_division=0)

    print(f"\n  Accuracy  : {acc:.2%}")
    print(f"  Precision : {prec:.2%}")
    print(f"  Recall    : {rec:.2%}")
    print(f"  F1 Score  : {f1:.2%}")
    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    # ── Save model and vectorizer ─────────────
    with open(_MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    with open(_VECT_PATH, "wb") as f:
        pickle.dump(vectorizer, f)

    # Save metadata for reference
    metadata = {
        "trained_at":       datetime.now().isoformat(),
        "total_samples":    len(texts),
        "phishing_samples": int(sum(labels)),
        "legit_samples":    int(len(labels) - sum(labels)),
        "accuracy":         round(acc, 4),
        "precision":        round(prec, 4),
        "recall":           round(rec, 4),
        "f1_score":         round(f1, 4),
        "model_type":       "RandomForestClassifier",
        "vectorizer":       "TfidfVectorizer",
        "max_features":     3000,
        "n_estimators":     200,
    }
    with open(_META_PATH, "w") as f:
        json.dump(metadata, f, indent=2)

    print("\n" + "-" * 55)
    print(f"  Model saved  : {_MODEL_PATH}")
    print(f"  Vectorizer   : {_VECT_PATH}")
    print(f"  Metadata     : {_META_PATH}")
    print("-" * 55)
    print("  Training complete! Restart the server to use the model.")
    print("-" * 55)


if __name__ == "__main__":
    # Check scikit-learn is installed
    try:
        import sklearn
        print(f"  scikit-learn version: {sklearn.__version__}")
    except ImportError:
        print("✗ scikit-learn not installed. Run: pip install scikit-learn")
        sys.exit(1)

    train_and_save()
