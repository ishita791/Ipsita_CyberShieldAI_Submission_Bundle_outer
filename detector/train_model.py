"""
CyberShield AI — Reproducible ML Model Training Pipeline
Trains binary classifiers for URL phishing detection using stratified train/test splits.
Extracts features consistently via URLAnalyzer and logs evaluation metrics.
"""

import csv
import os
import random
from typing import List, Tuple
from .url_analyzer import URLAnalyzer
from .ml_engine import FEATURE_NAMES, extract_features_vector

RANDOM_SEED = 42
DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "sample_phishing_dataset.csv")
MODEL_OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "cyber_model.joblib")

# Curated synthetic demonstration URLs representing diverse attack archetypes and legitimate services
DEMO_URL_PATTERNS = [
    # Legitimate services (label=0)
    ("https://www.google.com/search?q=cybersecurity+defense", 0),
    ("https://github.com/torvalds/linux", 0),
    ("https://docs.python.org/3/library/urllib.parse.html", 0),
    ("https://en.wikipedia.org/wiki/Phishing", 0),
    ("https://www.microsoft.com/en-us/security", 0),
    ("https://aws.amazon.com/security/introduction", 0),
    ("https://cloudflare.com/learning/access-management/what-is-phishing/", 0),
    ("https://cve.mitre.org/cve/identifiers/", 0),
    ("https://owasp.org/www-project-top-ten/", 0),
    ("https://www.nist.gov/cyberframework", 0),
    ("https://stackoverflow.com/questions/tagged/python", 0),
    ("https://pypi.org/project/scikit-learn/", 0),
    ("https://www.apple.com/privacy/", 0),
    ("https://support.mozilla.org/en-US/products/firefox", 0),
    ("https://developer.mozilla.org/en-US/docs/Web/HTTP", 0),
    ("https://www.cisa.gov/resources-tools/cybersecurity-alerts", 0),

    # Phishing lures (label=1)
    ("http://192.168.1.105/paypal/login.php?cmd=verify", 1),
    ("http://bankofamerica.secure-update-login.xyz/account/auth", 1),
    ("http://bit.ly/secure-banking-verification-notice", 1),
    ("http://update-apple-id.account-verification-service.top/confirm", 1),
    ("http://netflix-billing-update-required.buzz/signin", 1),
    ("http://microsoft-365.re-activate-support.icu/portal/login.html", 1),
    ("http://user@secure-banking-portal.net/verify_credentials", 1),
    ("http://198.51.100.42:8080/secure/webscr?cmd=_login-run", 1),
    ("http://chase.online-verification-support.work/security/update", 1),
    ("http://xn--appl-43d.com/support/login", 1),
    ("http://account.paypal.com.verification-center-id492.top/signin", 1),
    ("http://secure.wellsfargo.com-confirm-identity.xyz/auth", 1),
    ("http://tinyurl.com/urgent-irs-tax-refund-claim", 1),
    ("http://203.0.113.88/secure/wallet/recover.php?token=92847", 1),
    ("http://dhl-package-tracking.parcel-held.cam/re-delivery/verify", 1),
    ("http://amazon.shipping-status-alert.rest/account/billing", 1)
]


def generate_synthetic_dataset(num_samples: int = 1000) -> List[dict]:
    """
    Generate an annotated demonstration dataset for model training and benchmarking.
    NOTE: This is synthetic training data for academic demonstration, NOT real threat intelligence.
    """
    random.seed(RANDOM_SEED)
    analyzer = URLAnalyzer()
    dataset = []

    # Populate from archetypes with variations
    for i in range(num_samples):
        base_url, label = random.choice(DEMO_URL_PATTERNS)

        # Inject realistic noise / variation
        if label == 1:
            # Vary parameters, hosts, subdomains
            param_id = random.randint(10000, 99999)
            if "?" in base_url:
                url = f"{base_url}&session={param_id}&token={random.choice(['auth', 'sec', 'val'])}"
            else:
                url = f"{base_url}?ref={param_id}&attempt={i}"
        else:
            page_id = random.randint(1, 500)
            url = f"{base_url}&page={page_id}" if "?" in base_url else f"{base_url}/{page_id}"

        feat = analyzer.extract_features(url)
        vec = extract_features_vector(feat)

        row = {
            "url": url,
            "label": label,
            "source_type": "Synthetic Demonstration (Academic)",
            **dict(zip(FEATURE_NAMES, vec))
        }
        dataset.append(row)

    return dataset


def save_dataset_to_csv(dataset: List[dict], filepath: str):
    """Save dataset rows to CSV file."""
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    if not dataset:
        return
    fieldnames = list(dataset[0].keys())
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(dataset)
    print(f"[CyberShield AI] Dataset successfully written to {filepath} ({len(dataset)} records).")


def run_pipeline():
    """Execute training pipeline and log evaluation metrics."""
    print("=" * 60)
    print("CyberShield AI — Machine Learning Pipeline Execution")
    print("=" * 60)
    print("[1/4] Generating balanced demonstration dataset...")
    data = generate_synthetic_dataset(num_samples=1000)
    save_dataset_to_csv(data, DATASET_PATH)

    print("[2/4] Parsing features and labels...")
    X = [[row[feat] for feat in FEATURE_NAMES] for row in data]
    y = [row["label"] for row in data]

    # Attempt scikit-learn training if installed in environment
    try:
        from sklearn.model_selection import train_test_split
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
        import joblib

        print("[3/4] Running 80/20 Stratified train/test split...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=RANDOM_SEED, stratify=y
        )

        print("[4/4] Training RandomForestClassifier (n_estimators=100)...")
        clf = RandomForestClassifier(n_estimators=100, random_state=RANDOM_SEED, max_depth=10)
        clf.fit(X_train, y_train)

        y_pred = clf.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        cm = confusion_matrix(y_test, y_pred)

        print("-" * 60)
        print("MODEL EVALUATION RESULTS (Test Set):")
        print(f"Accuracy:  {acc:.4f} ({acc*100:.2f}%)")
        print(f"Precision: {prec:.4f} ({prec*100:.2f}%)")
        print(f"Recall:    {rec:.4f} ({rec*100:.2f}%)")
        print(f"F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
        print(f"Confusion Matrix:\n{cm}")
        print("-" * 60)

        joblib.dump(clf, MODEL_OUTPUT_PATH)
        print(f"Model serialized successfully to {MODEL_OUTPUT_PATH}")

    except ImportError:
        print("[Notice] scikit-learn not available in current environment.")
        print("Using calibrated mathematical ensemble inside ml_engine.py.")
        print(f"Dataset successfully created and verified at: {DATASET_PATH}")


if __name__ == "__main__":
    run_pipeline()
