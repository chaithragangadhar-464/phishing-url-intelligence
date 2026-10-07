"""
Self-contained training script for Railway/Render deployment.
Runs from the backend/ directory.
Saves model to backend/models/ which is where the loader expects it.
"""
import sys
import os
import logging
import json
import random
import math
from pathlib import Path

# Ensure backend/ is on path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix
)

try:
    import xgboost as xgb
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False
    from sklearn.ensemble import GradientBoostingClassifier

from app.features.extractor import extract_features, get_feature_names

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)
random.seed(RANDOM_SEED)

# Save inside backend/models/ — this is what the loader looks for
MODELS_DIR = Path(__file__).resolve().parent / "models"
MODELS_DIR.mkdir(exist_ok=True)

LEGITIMATE_DOMAINS = [
    "google.com", "github.com", "stackoverflow.com", "microsoft.com",
    "amazon.com", "wikipedia.org", "bbc.com", "nytimes.com",
    "linkedin.com", "apple.com", "twitter.com", "reddit.com",
    "youtube.com", "netflix.com", "spotify.com", "dropbox.com",
]
LEGITIMATE_PATHS = [
    "/", "/about", "/contact", "/products", "/services",
    "/blog/post-123", "/documentation/api", "/support",
    "/search?q=python+tutorial", "/downloads/installer",
    "/account/settings", "/help/faq",
]
PHISHING_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"]
PHISHING_KEYWORDS = ["login", "verify", "account", "secure", "update", "banking", "signin"]
BRANDS = ["paypal", "google", "microsoft", "apple", "amazon", "chase", "wellsfargo"]


def _entropy(s):
    if not s:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((v/total) * math.log2(v/total) for v in freq.values())


def generate_legitimate_url():
    domain = random.choice(LEGITIMATE_DOMAINS)
    path = random.choice(LEGITIMATE_PATHS)
    scheme = "https" if random.random() > 0.1 else "http"
    return f"{scheme}://www.{domain}{path}"


def generate_phishing_url():
    pattern = random.randint(0, 6)
    if pattern == 0:
        ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        kw = random.choice(PHISHING_KEYWORDS)
        brand = random.choice(BRANDS)
        return f"http://{ip}/{kw}/{brand}/secure/verify"
    elif pattern == 1:
        brand = random.choice(BRANDS)
        tld = random.choice(PHISHING_TLDS)
        kw = random.choice(PHISHING_KEYWORDS)
        rd = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=8))
        return f"http://{brand}-{kw}.{rd}{tld}/{kw}/account"
    elif pattern == 2:
        brand = random.choice(BRANDS)
        kw1 = random.choice(PHISHING_KEYWORDS)
        kw2 = random.choice(PHISHING_KEYWORDS)
        rd = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=12))
        tld = random.choice([".com", ".net"] + PHISHING_TLDS)
        token = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=32))
        return f"http://{rd}{tld}/{kw1}/{brand}/{kw2}/verify?token={token}&uid=12345"
    elif pattern == 3:
        brand = random.choice(BRANDS)
        kw = random.choice(PHISHING_KEYWORDS)
        evil = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=10)) + random.choice(PHISHING_TLDS)
        return f"http://{brand}.com@{evil}/{kw}"
    elif pattern == 4:
        brand = random.choice(BRANDS)
        kw = random.choice(PHISHING_KEYWORDS)
        return f"https://xn--{brand[:-1]}e-{random.randint(10,99)}.com/{kw}/verify?user=victim"
    elif pattern == 5:
        brand = random.choice(BRANDS)
        kw = random.choice(PHISHING_KEYWORDS)
        rd = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=8)) + random.choice(PHISHING_TLDS)
        return f"http://{brand}.{kw}.secure.update.{rd}/{kw}"
    else:
        tld = random.choice(PHISHING_TLDS)
        kw = random.choice(["bank", "payment", "billing", "wallet", "transfer"])
        rd = "".join(random.choices("abcdefghijklmnopqrstuvwxyz-", k=10)).strip("-")
        return f"http://{rd}{tld}/{kw}/confirm?account=true"


def main():
    logger.info("=== Deployment Training Pipeline ===")
    logger.info("Generating synthetic dataset (10000 samples)...")
    n = 10000
    urls, labels = [], []
    for _ in range(n // 2):
        urls.append(generate_legitimate_url())
        labels.append(0)
    for _ in range(n // 2):
        urls.append(generate_phishing_url())
        labels.append(1)

    df = pd.DataFrame({"url": urls, "label": labels}).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    logger.info(f"Dataset: {len(df)} samples")

    logger.info("Extracting features...")
    feature_dicts = []
    for url in df["url"]:
        try:
            feature_dicts.append(extract_features(str(url)))
        except Exception:
            feature_dicts.append({k: 0 for k in get_feature_names()})

    X = pd.DataFrame(feature_dicts)
    y = df["label"].values
    feature_names = list(X.columns)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y)
    logger.info(f"Train: {len(X_train)}, Test: {len(X_test)}")

    if XGB_AVAILABLE:
        logger.info("Training XGBoost...")
        model = xgb.XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            subsample=0.8, colsample_bytree=0.8,
            eval_metric="logloss", random_state=RANDOM_SEED, n_jobs=-1,
        )
        model_name = "XGBoost"
    else:
        logger.info("Training GradientBoosting (XGBoost not available)...")
        model = GradientBoostingClassifier(n_estimators=200, max_depth=5, learning_rate=0.1, random_state=RANDOM_SEED)
        model_name = "GradientBoosting"

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    metrics = {
        "model": model_name,
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred)), 4),
        "recall": round(float(recall_score(y_test, y_pred)), 4),
        "f1_score": round(float(f1_score(y_test, y_pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, y_proba)), 4),
    }
    logger.info(f"Accuracy: {metrics['accuracy']} | F1: {metrics['f1_score']} | ROC-AUC: {metrics['roc_auc']}")

    # Save model
    model_path = MODELS_DIR / "phishing_model.joblib"
    joblib.dump(model, model_path)
    logger.info(f"Model saved: {model_path}")

    # Save metadata
    meta = {"feature_names": feature_names, "metrics": metrics, "n_features": len(feature_names)}
    joblib.dump(meta, MODELS_DIR / "model_meta.joblib")

    with open(MODELS_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    logger.info("=== Training Complete ===")
    return metrics


if __name__ == "__main__":
    main()
