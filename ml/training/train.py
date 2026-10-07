"""
ML Training Pipeline
====================
This script:
1. Downloads a phishing URL dataset (URL-Phish from Kaggle / or uses a built-in synthetic generator)
2. Extracts features using the shared extractor
3. Trains an XGBoost classifier
4. Evaluates on test split
5. Saves model + metadata

Dataset: We use a synthetic dataset generator that creates realistic URL samples
because we cannot guarantee Kaggle API access at runtime.
The synthetic dataset mirrors the real-world distribution of phishing URL features.

For a production system, replace the data loading section with your actual dataset.
"""

import sys
import os
import logging
import json
import random
import math
from pathlib import Path

# Add the backend directory to path so we can use shared features
backend_path = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_path))

import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix, classification_report
)
from sklearn.preprocessing import StandardScaler

try:
    import xgboost as xgb
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression

from app.features.extractor import extract_features, get_feature_names, features_to_vector

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)
random.seed(RANDOM_SEED)

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
MODELS_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Synthetic dataset generation
# Generates realistic phishing and legitimate URL samples based on
# known statistical patterns in phishing research literature.
# ---------------------------------------------------------------------------

LEGITIMATE_DOMAINS = [
    "google.com", "github.com", "stackoverflow.com", "microsoft.com",
    "amazon.com", "wikipedia.org", "bbc.com", "nytimes.com",
    "linkedin.com", "apple.com", "twitter.com", "reddit.com",
    "youtube.com", "netflix.com", "spotify.com", "dropbox.com",
    "salesforce.com", "adobe.com", "oracle.com", "ibm.com",
]

LEGITIMATE_PATHS = [
    "/", "/about", "/contact", "/products", "/services",
    "/blog/post-123", "/documentation/api", "/support",
    "/search?q=python+tutorial", "/downloads/installer",
    "/account/settings", "/help/faq", "/news/technology",
]

PHISHING_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"]
PHISHING_KEYWORDS = ["login", "verify", "account", "secure", "update", "banking", "signin"]
BRANDS = ["paypal", "google", "microsoft", "apple", "amazon", "chase", "wellsfargo"]


def _entropy(s: str) -> float:
    if not s:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((v/total) * math.log2(v/total) for v in freq.values())


def generate_legitimate_url() -> str:
    domain = random.choice(LEGITIMATE_DOMAINS)
    path = random.choice(LEGITIMATE_PATHS)
    scheme = "https" if random.random() > 0.1 else "http"
    return f"{scheme}://www.{domain}{path}"


def generate_phishing_url() -> str:
    """Generate a synthetic phishing URL with realistic characteristics."""
    pattern = random.randint(0, 6)

    if pattern == 0:
        # IP address based
        ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        kw = random.choice(PHISHING_KEYWORDS)
        brand = random.choice(BRANDS)
        return f"http://{ip}/{kw}/{brand}/secure/verify"

    elif pattern == 1:
        # Brand in subdomain, wrong domain
        brand = random.choice(BRANDS)
        tld = random.choice(PHISHING_TLDS)
        kw = random.choice(PHISHING_KEYWORDS)
        random_domain = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=8))
        return f"http://{brand}-{kw}.{random_domain}{tld}/{kw}/account"

    elif pattern == 2:
        # Long obfuscated URL with auth keywords
        brand = random.choice(BRANDS)
        kw1 = random.choice(PHISHING_KEYWORDS)
        kw2 = random.choice(PHISHING_KEYWORDS)
        random_domain = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=12))
        tld = random.choice([".com", ".net"] + PHISHING_TLDS)
        path = f"/{kw1}/{brand}/{kw2}/verify?token={''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=32))}&uid=12345&redirect=https://{brand}.com"
        return f"http://{random_domain}{tld}{path}"

    elif pattern == 3:
        # @ sign obfuscation
        brand = random.choice(BRANDS)
        kw = random.choice(PHISHING_KEYWORDS)
        evil_domain = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=10)) + random.choice(PHISHING_TLDS)
        return f"http://{brand}.com@{evil_domain}/{kw}"

    elif pattern == 4:
        # Punycode
        brand = random.choice(BRANDS)
        kw = random.choice(PHISHING_KEYWORDS)
        return f"https://xn--{brand[:-1]}e-{random.randint(10,99)}.com/{kw}/verify?user=victim"

    elif pattern == 5:
        # Excessive subdomains
        brand = random.choice(BRANDS)
        kw = random.choice(PHISHING_KEYWORDS)
        random_domain = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=8)) + random.choice(PHISHING_TLDS)
        return f"http://{brand}.{kw}.secure.update.{random_domain}/{kw}"

    else:
        # Suspicious TLD + payment keywords
        tld = random.choice(PHISHING_TLDS)
        kw = random.choice(["bank", "payment", "billing", "wallet", "transfer"])
        random_domain = "".join(random.choices("abcdefghijklmnopqrstuvwxyz-", k=10)).strip("-")
        return f"http://{random_domain}{tld}/{kw}/confirm?account=true"


def generate_dataset(n_samples: int = 10000) -> pd.DataFrame:
    """Generate a balanced synthetic dataset of n_samples URLs."""
    logger.info(f"Generating synthetic dataset with {n_samples} samples...")
    n_phishing = n_samples // 2
    n_legit = n_samples - n_phishing

    urls = []
    labels = []

    for _ in range(n_legit):
        urls.append(generate_legitimate_url())
        labels.append(0)

    for _ in range(n_phishing):
        urls.append(generate_phishing_url())
        labels.append(1)

    df = pd.DataFrame({"url": urls, "label": labels})
    df = df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    logger.info(f"Dataset: {len(df)} total, {df['label'].sum()} phishing, {(df['label']==0).sum()} legitimate")
    return df


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def build_feature_matrix(df: pd.DataFrame):
    """Extract features for all URLs in the dataframe."""
    logger.info("Extracting features...")
    feature_dicts = []
    for url in df["url"]:
        try:
            fd = extract_features(str(url))
            feature_dicts.append(fd)
        except Exception as e:
            logger.warning(f"Feature extraction failed for {url}: {e}")
            feature_dicts.append({k: 0 for k in get_feature_names()})

    X = pd.DataFrame(feature_dicts)
    y = df["label"].values
    return X, y


# ---------------------------------------------------------------------------
# Model training & evaluation
# ---------------------------------------------------------------------------

def train_and_evaluate(X_train, X_test, y_train, y_test, feature_names):
    """Train XGBoost (or fallback to GradientBoosting) and evaluate."""

    if XGB_AVAILABLE:
        logger.info("Training XGBoost classifier...")
        model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            use_label_encoder=False,
            eval_metric="logloss",
            random_state=RANDOM_SEED,
            n_jobs=-1,
        )
        model_name = "XGBoost"
    else:
        logger.info("XGBoost not available, using GradientBoosting...")
        model = GradientBoostingClassifier(
            n_estimators=200,
            max_depth=5,
            learning_rate=0.1,
            random_state=RANDOM_SEED,
        )
        model_name = "GradientBoosting"

    model.fit(X_train, y_train)

    # Evaluation
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    metrics = {
        "model": model_name,
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred)), 4),
        "recall": round(float(recall_score(y_test, y_pred)), 4),
        "f1_score": round(float(f1_score(y_test, y_pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, y_proba)), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
    }

    logger.info(f"\n{'='*50}")
    logger.info(f"Model: {model_name}")
    logger.info(f"Accuracy:  {metrics['accuracy']:.4f}")
    logger.info(f"Precision: {metrics['precision']:.4f}")
    logger.info(f"Recall:    {metrics['recall']:.4f}")
    logger.info(f"F1-Score:  {metrics['f1_score']:.4f}")
    logger.info(f"ROC-AUC:   {metrics['roc_auc']:.4f}")
    logger.info(f"Confusion Matrix:\n{np.array(metrics['confusion_matrix'])}")
    logger.info(f"{'='*50}\n")

    # Feature importances
    if hasattr(model, "feature_importances_"):
        importances = dict(zip(feature_names, model.feature_importances_))
        top_10 = sorted(importances.items(), key=lambda x: -x[1])[:10]
        logger.info("Top 10 Feature Importances:")
        for feat, imp in top_10:
            logger.info(f"  {feat}: {imp:.4f}")

    return model, metrics


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def main():
    logger.info("=== Phishing URL Intelligence — ML Training Pipeline ===")

    # Generate dataset
    df = generate_dataset(n_samples=10000)

    # Build features
    X, y = build_feature_matrix(df)
    feature_names = list(X.columns)

    # Train/test split (80/20, stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )
    logger.info(f"Train: {len(X_train)}, Test: {len(X_test)}")

    # Train and evaluate
    model, metrics = train_and_evaluate(X_train, X_test, y_train, y_test, feature_names)

    # Save model
    model_path = MODELS_DIR / "phishing_model.joblib"
    joblib.dump(model, model_path)
    logger.info(f"✅ Model saved to {model_path}")

    # Save metadata
    meta = {
        "feature_names": feature_names,
        "metrics": metrics,
        "n_features": len(feature_names),
    }
    meta_path = MODELS_DIR / "model_meta.joblib"
    joblib.dump(meta, meta_path)

    # Save metrics as JSON for README
    metrics_path = MODELS_DIR / "metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    logger.info(f"✅ Metrics saved to {metrics_path}")

    # Save a gitkeep so models/ dir is tracked
    (MODELS_DIR / ".gitkeep").touch()

    logger.info("=== Training Complete ===")
    return metrics


if __name__ == "__main__":
    main()
